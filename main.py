"""
================================================================================
Luma Shield - Cloud Proxy Scraper & Quality Node Validator
================================================================================

Created by Alperen Burak Yeşil

Purpose:
Fetches VPN/Xray node configs from public repositories, deduplicates them,
filters weak/zombie-prone configs, performs multi-attempt TLS-level probing,
assigns a quality score, and exports the best nodes per country.

Important:
This version does NOT run Xray subprocess. It is a strong pre-filter, not a
full end-to-end VPN egress validator. Flutter should still perform final
SOCKS/generate_204 verification at connection time.
================================================================================
"""

import asyncio
import aiohttp
import base64
import time
import json
import re
import urllib.parse
import ssl
from typing import Optional, Dict, Any, List


# =============================================================================
# CONFIG
# =============================================================================

SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/hysteria2_configs.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no5.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/vless.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/hy2.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
]

OUTPUT_FILE = "luma_premium_nodes.json"

CONNECTION_TIMEOUT = 5.0
READ_TIMEOUT = 2.0
SOURCE_TIMEOUT = 10.0

CONCURRENCY_LIMIT = 60
LATENCY_ATTEMPTS = 3
TOP_NODES_PER_COUNTRY = 15

MIN_QUALITY_SCORE = 75.0
MAX_ACCEPTED_PING = 1200
MAX_ACCEPTED_JITTER = 800
MIN_PROBE_SUCCESS_RATE = 0.67

STRICT_VLESS_ONLY = True

ALLOWED_VLESS_PORTS = {
    443,
    8443,
    2053,
    2083,
    2087,
    2096,
}

ALLOWED_SECURITY = {
    "reality",
    "tls",
}

BLOCKED_TRANSPORTS = {
    "ws",
    "websocket",
    "httpupgrade",
    "splithttp",
}

PREFERRED_TRANSPORTS = {
    "tcp",
    "grpc",
    "h2",
    "http",
}

PREFERRED_FINGERPRINTS = {
    "",
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "random",
    "randomized",
}


COUNTRY_MAPPINGS = {
    "TR": ["🇹🇷", r"\bTR\b", r"\bTURKIYE\b", r"\.tr$"],
    "US": ["🇺🇸", r"\bUS\b", r"\bUSA\b", r"\bUNITED STATES\b", r"\.us$"],
    "DE": ["🇩🇪", r"\bDE\b", r"\bGERMANY\b", r"\bDEUTSCHLAND\b", r"\.de$"],
    "FR": ["🇫🇷", r"\bFR\b", r"\bFRANCE\b", r"\.fr$"],
    "GB": ["🇬🇧", r"\bGB\b", r"\bUK\b", r"\bENGLAND\b", r"\bUNITED KINGDOM\b", r"\.uk$"],
    "NL": ["🇳🇱", r"\bNL\b", r"\bNETHERLANDS\b", r"\bHOLLAND\b", r"\.nl$"],
    "SG": ["🇸🇬", r"\bSG\b", r"\bSINGAPORE\b", r"\.sg$"],
    "JP": ["🇯🇵", r"\bJP\b", r"\bJAPAN\b", r"\.jp$"],
    "CA": ["🇨🇦", r"\bCA\b", r"\bCANADA\b", r"\.ca$"],
    "AU": ["🇦🇺", r"\bAU\b", r"\bAUSTRALIA\b", r"\.au$"],
    "IT": ["🇮🇹", r"\bIT\b", r"\bITALY\b", r"\.it$"],
    "ES": ["🇪🇸", r"\bES\b", r"\bSPAIN\b", r"\.es$"],
}


# =============================================================================
# BASIC HELPERS
# =============================================================================

def decode_base64(data: str) -> str:
    try:
        clean = data.strip()
        clean = clean.replace("\n", "").replace("\r", "")
        missing_padding = len(clean) % 4
        if missing_padding:
            clean += "=" * (4 - missing_padding)
        return base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return data


def is_ipv4(value: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value or "") is not None


def is_valid_hostname(value: str) -> bool:
    if not value:
        return False

    if is_ipv4(value):
        return False

    if len(value) > 253:
        return False

    try:
        value.encode("idna")
    except Exception:
        return False

    return re.match(r"^[a-zA-Z0-9.-]+$", value) is not None


def safe_unquote(value: str) -> str:
    try:
        return urllib.parse.unquote(value or "")
    except Exception:
        return value or ""


def extract_query_value(link: str, key: str, default: str = "") -> str:
    try:
        uri = urllib.parse.urlparse(link)
        q = urllib.parse.parse_qs(uri.query)
        return q.get(key, [default])[0] or default
    except Exception:
        return default


def get_transport(link: str) -> str:
    value = extract_query_value(link, "type", "tcp").lower()
    if not value:
        value = "tcp"
    return value


def get_security(link: str) -> str:
    return extract_query_value(link, "security", "").lower()


def get_uuid_from_link(link: str) -> str:
    try:
        uri = urllib.parse.urlparse(link)
        return uri.username or ""
    except Exception:
        return ""


def predict_true_egress(remark: str, sni: str, host: str, ip: str) -> Optional[str]:
    space = f"{remark} {sni} {host} {ip}".upper()

    for code, patterns in COUNTRY_MAPPINGS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, space):
                    return code
            except Exception:
                pass

    return None


def normalize_vless_link(link: str) -> str:
    """
    Adds safe defaults without aggressively rewriting the protocol.
    """
    lower = link.lower()

    if "fragment=" not in lower:
        separator = "&" if "?" in link else "?"
        link += f"{separator}fragment=10-20,10-20,tlshello"

    return link


def node_fingerprint(node: Dict[str, Any]) -> str:
    link = node["link"]
    proto = node.get("proto", "")
    ip = node.get("ip", "")
    port = node.get("port", "")

    uuid = get_uuid_from_link(link)
    sni = extract_query_value(link, "sni")
    host = extract_query_value(link, "host")
    pbk = extract_query_value(link, "pbk")
    sid = extract_query_value(link, "sid")
    flow = extract_query_value(link, "flow")
    security = extract_query_value(link, "security")
    transport = extract_query_value(link, "type", "tcp")

    return f"{proto}|{ip}|{port}|{uuid}|{sni}|{host}|{pbk}|{sid}|{flow}|{security}|{transport}"


# =============================================================================
# PARSER
# =============================================================================

def parse_config(link: str) -> Optional[Dict[str, Any]]:
    try:
        link = link.strip()
        if not link or "://" not in link:
            return None

        proto = link.split("://", 1)[0].lower()

        if STRICT_VLESS_ONLY and proto != "vless":
            return None

        if proto not in ["vless", "hysteria2", "hy2"]:
            return None

        if proto in ["hysteria2", "hy2"]:
            # HY2 needs separate UDP-based validation. Do not trust it here.
            return None

        match = re.search(r"@([^:/?#]+):(\d+)", link)
        if not match:
            return None

        ip = match.group(1).strip()
        port = int(match.group(2))

        if port not in ALLOWED_VLESS_PORTS:
            return None

        security = get_security(link)
        transport = get_transport(link)
        flow = extract_query_value(link, "flow").lower()
        fp = extract_query_value(link, "fp").lower()
        pbk = extract_query_value(link, "pbk")
        sid = extract_query_value(link, "sid")
        sni = extract_query_value(link, "sni")
        host = extract_query_value(link, "host")
        remark = safe_unquote(urllib.parse.urlparse(link).fragment)

        if not sni:
            sni = host

        if security not in ALLOWED_SECURITY:
            return None

        if transport in BLOCKED_TRANSPORTS:
            return None

        if transport not in PREFERRED_TRANSPORTS:
            return None

        if fp not in PREFERRED_FINGERPRINTS:
            return None

        if security == "reality":
            if not pbk:
                return None

        if security in ["reality", "tls"]:
            if not sni and not host:
                # Some configs can still work without SNI, but quality is usually worse.
                return None

        link = normalize_vless_link(link)

        country = predict_true_egress(remark, sni, host, ip)

        return {
            "link": link,
            "ip": ip,
            "port": port,
            "sni": sni,
            "host": host,
            "proto": proto,
            "security": security,
            "transport": transport,
            "flow": flow,
            "fp": fp,
            "pbk": pbk,
            "sid": sid,
            "country": country,
            "remark": remark,
        }

    except Exception:
        return None


# =============================================================================
# QUALITY SCORE
# =============================================================================

def compute_quality_score(node: Dict[str, Any]) -> float:
    ping = int(node.get("ping", 9999))
    jitter = int(node.get("jitter", 9999))
    success_rate = float(node.get("probeSuccessRate", 0.0))

    link = node.get("link", "").lower()
    port = int(node.get("port", 0))
    security = node.get("security", "")
    transport = node.get("transport", "")
    flow = node.get("flow", "")
    fp = node.get("fp", "")
    sni = node.get("sni", "")

    score = 100.0

    # Ping penalty
    if ping > 1500:
        score -= 50
    elif ping > 1200:
        score -= 38
    elif ping > 900:
        score -= 26
    elif ping > 700:
        score -= 18
    elif ping > 450:
        score -= 9
    elif ping < 250:
        score += 5

    # Jitter penalty
    if jitter > 1000:
        score -= 35
    elif jitter > 800:
        score -= 26
    elif jitter > 500:
        score -= 18
    elif jitter > 250:
        score -= 9
    elif jitter < 120:
        score += 5

    # Probe stability
    if success_rate >= 1.0:
        score += 12
    elif success_rate >= 0.67:
        score += 4
    else:
        score -= 35

    # Security
    if security == "reality":
        score += 14
    elif security == "tls":
        score += 8
    else:
        score -= 45

    # Transport
    if transport == "tcp":
        score += 6
    elif transport == "grpc":
        score += 7
    elif transport in ["h2", "http"]:
        score += 4
    elif transport in BLOCKED_TRANSPORTS:
        score -= 45

    # XTLS Vision
    if flow == "xtls-rprx-vision":
        score += 8

    # Port quality
    if port == 443:
        score += 8
    elif port in [8443, 2053, 2083, 2087, 2096]:
        score += 3
    else:
        score -= 25

    # Fingerprint
    if fp in ["chrome", "firefox", "safari", "ios", "android", "randomized"]:
        score += 4

    # SNI
    if sni and is_valid_hostname(sni):
        score += 5
    else:
        score -= 18

    # Bad markers
    bad_markers = [
        "test",
        "expire",
        "expired",
        "limit",
        "traffic",
        "trial",
        "slow",
        "fake",
        "demo",
    ]

    remark = node.get("remark", "").lower()
    for marker in bad_markers:
        if marker in remark:
            score -= 5

    return max(0.0, min(100.0, round(score, 2)))


# =============================================================================
# PROBING
# =============================================================================

async def single_tls_probe(node: Dict[str, Any]) -> Optional[int]:
    ip = node["ip"]
    port = int(node["port"])
    sni = node.get("sni") or node.get("host") or ip

    start = time.time()
    writer = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server_hostname = sni if is_valid_hostname(sni) else None

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=context,
                server_hostname=server_hostname,
            ),
            timeout=CONNECTION_TIMEOUT,
        )

        host_header = sni if server_hostname else ip

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8", errors="ignore")

        writer.write(request)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(512), timeout=READ_TIMEOUT)

        if not response:
            return None

        elapsed_ms = int((time.time() - start) * 1000)

        # Do not require 200. Any coherent TLS-level response is enough for stage-1.
        if (
            b"HTTP/" in response
            or b"400" in response
            or b"403" in response
            or b"404" in response
            or b"301" in response
            or b"302" in response
            or b"bad request" in response.lower()
            or b"<html" in response.lower()
        ):
            return elapsed_ms

        return elapsed_ms

    except Exception:
        return None

    finally:
        if writer:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass


async def validate_node(node: Dict[str, Any], semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    async with semaphore:
        values: List[int] = []

        try:
            for _ in range(LATENCY_ATTEMPTS):
                ms = await single_tls_probe(node)
                if ms is not None:
                    values.append(ms)
                await asyncio.sleep(0.12)

            if not values:
                return None

            values.sort()

            avg_ping = int(sum(values) / len(values))
            jitter = values[-1] - values[0]
            success_rate = len(values) / LATENCY_ATTEMPTS

            node["ping"] = avg_ping
            node["jitter"] = jitter
            node["probeSuccessRate"] = round(success_rate, 2)
            node["verifiedAt"] = int(time.time())
            node["qualityScore"] = compute_quality_score(node)

            if node["ping"] > MAX_ACCEPTED_PING:
                return None

            if node["jitter"] > MAX_ACCEPTED_JITTER:
                return None

            if node["probeSuccessRate"] < MIN_PROBE_SUCCESS_RATE:
                return None

            if node["qualityScore"] < MIN_QUALITY_SCORE:
                return None

            return node

        except Exception:
            return None


# =============================================================================
# COUNTRY FALLBACK
# =============================================================================

async def resolve_fallback_countries(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unknown = [n for n in nodes if n.get("country") is None]
    if not unknown:
        return nodes

    ips = list(set([n["ip"] for n in unknown if n.get("ip")]))
    ip_to_country: Dict[str, str] = {}

    timeout = aiohttp.ClientTimeout(total=8)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for i in range(0, len(ips), 100):
            batch = ips[i:i + 100]

            try:
                async with session.post(
                    "http://ip-api.com/batch?fields=query,countryCode,status",
                    json=batch,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for item in data:
                            if item.get("status") == "success":
                                ip_to_country[item["query"]] = item.get("countryCode", "UN")
            except Exception:
                pass

            await asyncio.sleep(0.25)

    for node in nodes:
        if node.get("country") is None:
            node["country"] = ip_to_country.get(node.get("ip"), "UN")

    return nodes


# =============================================================================
# SCRAPING
# =============================================================================

async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    try:
        async with session.get(url) as response:
            if response.status != 200:
                return []

            text = await response.text(errors="ignore")

            if "://" not in text:
                text = decode_base64(text)

            lines = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                if "://" not in line:
                    maybe = decode_base64(line)
                    if "://" in maybe:
                        lines.extend(maybe.splitlines())
                    continue

                lines.append(line)

            return lines

    except Exception:
        return []


async def fetch_all_links() -> List[str]:
    timeout = aiohttp.ClientTimeout(total=SOURCE_TIMEOUT)

    headers = {
        "User-Agent": "Mozilla/5.0 LumaShieldNodeScanner/1.0",
        "Accept": "*/*",
    }

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [fetch_source(session, url) for url in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    raw_links: List[str] = []

    for result in results:
        if isinstance(result, list):
            raw_links.extend(result)

    return raw_links


# =============================================================================
# MAIN
# =============================================================================

async def main():
    started_at = time.time()

    print("===============================================================")
    print("[LUMA] Fetching sources...")
    print("===============================================================")

    raw_links = await fetch_all_links()
    print(f"[LUMA] Raw links collected: {len(raw_links)}")

    unique_fingerprints = set()
    parsed_nodes: List[Dict[str, Any]] = []

    for link in raw_links:
        node = parse_config(link)
        if not node:
            continue

        fingerprint = node_fingerprint(node)

        if fingerprint in unique_fingerprints:
            continue

        unique_fingerprints.add(fingerprint)
        parsed_nodes.append(node)

    print(f"[LUMA] Parsed strong candidates: {len(parsed_nodes)}")

    if not parsed_nodes:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)
        print("[LUMA] No candidates found. Empty JSON exported.")
        return

    print("===============================================================")
    print("[LUMA] Running multi-probe quality validation...")
    print("===============================================================")

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [validate_node(node, semaphore) for node in parsed_nodes]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive = [
        result for result in results
        if isinstance(result, dict)
    ]

    print(f"[LUMA] Alive high-quality candidates: {len(alive)}")

    alive = await resolve_fallback_countries(alive)

    pools: Dict[str, List[Dict[str, Any]]] = {}

    for node in alive:
        country = node.get("country")

        if not country or country not in COUNTRY_MAPPINGS:
            continue

        pools.setdefault(country, []).append(node)

    out: Dict[str, List[Dict[str, Any]]] = {}

    for country, nodes in pools.items():
        filtered = [
            n for n in nodes
            if n.get("qualityScore", 0) >= MIN_QUALITY_SCORE
            and n.get("ping", 9999) <= MAX_ACCEPTED_PING
            and n.get("jitter", 9999) <= MAX_ACCEPTED_JITTER
            and n.get("probeSuccessRate", 0) >= MIN_PROBE_SUCCESS_RATE
        ]

        filtered.sort(
            key=lambda x: (
                -float(x.get("qualityScore", 0)),
                int(x.get("ping", 9999)),
                int(x.get("jitter", 9999)),
            )
        )

        selected = filtered[:TOP_NODES_PER_COUNTRY]

        if not selected:
            continue

        out[country] = [
            {
                "config": n["link"],
                "countryCode": country,
                "countryName": country,
                "pingMs": int(n["ping"]),

                # Extra quality metadata for Flutter AI / ranking
                "qualityScore": float(n.get("qualityScore", 0)),
                "jitterMs": int(n.get("jitter", 9999)),
                "probeSuccessRate": float(n.get("probeSuccessRate", 0)),
                "proto": n.get("proto", ""),
                "security": n.get("security", ""),
                "transport": n.get("transport", ""),
                "flow": n.get("flow", ""),
                "fp": n.get("fp", ""),
                "verifiedAt": int(n.get("verifiedAt", int(time.time()))),
            }
            for n in selected
        ]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    total_selected = sum(len(v) for v in out.values())

    print("===============================================================")
    print("[LUMA] Export completed.")
    print("===============================================================")
    print(f"[LUMA] Countries exported: {len(out)}")
    print(f"[LUMA] Total selected nodes: {total_selected}")
    print(f"[LUMA] Output file: {OUTPUT_FILE}")
    print(f"[LUMA] Duration: {round(time.time() - started_at, 2)} sec")

    for country, items in sorted(out.items()):
        best = items[0]
        print(
            f"[LUMA] {country}: {len(items)} nodes | "
            f"best ping={best['pingMs']}ms | "
            f"quality={best['qualityScore']}"
        )


if __name__ == "__main__":
    asyncio.run(main())
