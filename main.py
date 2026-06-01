"""
================================================================================
Luma Shield - Cloud Proxy Scraper & Quality Node Validator
================================================================================

Developed by Alperen Burak Yeşil

Purpose:
Fetches VPN/Xray node configs from public repositories, deduplicates them,
filters weak/zombie-prone configs, performs multi-attempt TLS-level probing,
verifies country metadata with multiple GeoIP providers, assigns a quality score,
and exports the best nodes per country.

Important:
This script does NOT run Xray subprocess. It is a strong pre-filter, not a full
end-to-end VPN egress validator. Flutter should still perform final SOCKS /
generate_204 / real egress verification at connection time.
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
import socket
from typing import Optional, Dict, Any, List, Tuple


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
GEO_TIMEOUT = 8.0

CONCURRENCY_LIMIT = 60
GEO_CONCURRENCY_LIMIT = 24
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

MIN_GEO_CONFIDENCE = 0.60
MIN_GEO_SOURCES_FOR_EXPORT = 2
DROP_GEO_CONFLICT_NODES = False

GEO_BATCH_SIZE = 80
GEO_REQUEST_DELAY = 0.35

GEO_PROVIDER_WEIGHTS = {
    "ip_api": 1.0,
    "ipinfo": 1.15,
    "ipwhois": 1.0,
}


COUNTRY_MAPPINGS = {
    "TR": ["🇹🇷", r"\bTR\b", r"\bTURKIYE\b", r"\bTÜRKİYE\b", r"\bTURKEY\b", r"\.tr$"],
    "US": ["🇺🇸", r"\bUS\b", r"\bUSA\b", r"\bUNITED STATES\b", r"\bAMERICA\b", r"\.us$"],
    "DE": ["🇩🇪", r"\bDE\b", r"\bGERMANY\b", r"\bDEUTSCHLAND\b", r"\.de$"],
    "FR": ["🇫🇷", r"\bFR\b", r"\bFRANCE\b", r"\.fr$"],
    "GB": ["🇬🇧", r"\bGB\b", r"\bUK\b", r"\bENGLAND\b", r"\bUNITED KINGDOM\b", r"\bBRITAIN\b", r"\.uk$"],
    "NL": ["🇳🇱", r"\bNL\b", r"\bNETHERLANDS\b", r"\bHOLLAND\b", r"\.nl$"],
    "SG": ["🇸🇬", r"\bSG\b", r"\bSINGAPORE\b", r"\.sg$"],
    "JP": ["🇯🇵", r"\bJP\b", r"\bJAPAN\b", r"\.jp$"],
    "CA": ["🇨🇦", r"\bCA\b", r"\bCANADA\b", r"\.ca$"],
    "AU": ["🇦🇺", r"\bAU\b", r"\bAUSTRALIA\b", r"\.au$"],
    "IT": ["🇮🇹", r"\bIT\b", r"\bITALY\b", r"\.it$"],
    "ES": ["🇪🇸", r"\bES\b", r"\bSPAIN\b", r"\.es$"],
    "PL": ["🇵🇱", r"\bPL\b", r"\bPOLAND\b", r"\.pl$"],
    "CZ": ["🇨🇿", r"\bCZ\b", r"\bCZECH\b", r"\bCZECHIA\b", r"\.cz$"],
    "AT": ["🇦🇹", r"\bAT\b", r"\bAUSTRIA\b", r"\.at$"],
    "CH": ["🇨🇭", r"\bCH\b", r"\bSWITZERLAND\b", r"\.ch$"],
    "SE": ["🇸🇪", r"\bSE\b", r"\bSWEDEN\b", r"\.se$"],
    "NO": ["🇳🇴", r"\bNO\b", r"\bNORWAY\b", r"\.no$"],
    "FI": ["🇫🇮", r"\bFI\b", r"\bFINLAND\b", r"\.fi$"],
    "DK": ["🇩🇰", r"\bDK\b", r"\bDENMARK\b", r"\.dk$"],
    "BE": ["🇧🇪", r"\bBE\b", r"\bBELGIUM\b", r"\.be$"],
    "IE": ["🇮🇪", r"\bIE\b", r"\bIRELAND\b", r"\.ie$"],
    "RO": ["🇷🇴", r"\bRO\b", r"\bROMANIA\b", r"\.ro$"],
    "BG": ["🇧🇬", r"\bBG\b", r"\bBULGARIA\b", r"\.bg$"],
    "HU": ["🇭🇺", r"\bHU\b", r"\bHUNGARY\b", r"\.hu$"],
    "RU": ["🇷🇺", r"\bRU\b", r"\bRUSSIA\b", r"\.ru$"],
    "UA": ["🇺🇦", r"\bUA\b", r"\bUKRAINE\b", r"\.ua$"],
}


COUNTRY_NAMES = {
    "TR": "Türkiye",
    "US": "Amerika",
    "DE": "Almanya",
    "FR": "Fransa",
    "GB": "İngiltere",
    "NL": "Hollanda",
    "SG": "Singapur",
    "JP": "Japonya",
    "CA": "Kanada",
    "AU": "Avustralya",
    "IT": "İtalya",
    "ES": "İspanya",
    "PL": "Polonya",
    "CZ": "Çekya",
    "AT": "Avusturya",
    "CH": "İsviçre",
    "SE": "İsveç",
    "NO": "Norveç",
    "FI": "Finlandiya",
    "DK": "Danimarka",
    "BE": "Belçika",
    "IE": "İrlanda",
    "RO": "Romanya",
    "BG": "Bulgaristan",
    "HU": "Macaristan",
    "RU": "Rusya",
    "UA": "Ukrayna",
    "BR": "Brezilya",
    "AR": "Arjantin",
    "MX": "Meksika",
    "ZA": "Güney Afrika",
    "AE": "B.A.E.",
    "IN": "Hindistan",
    "KR": "Güney Kore",
    "HK": "Hong Kong",
    "TW": "Tayvan",
}


# =============================================================================
# BASIC HELPERS
# =============================================================================

def decode_base64(data: str) -> str:
    try:
        clean = data.strip()
        clean = clean.replace("\n", "").replace("\r", "")
        clean = clean.replace("-", "+").replace("_", "/")
        missing_padding = len(clean) % 4
        if missing_padding:
            clean += "=" * (4 - missing_padding)
        return base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return data


def normalize_country_code(value: str) -> str:
    code = (value or "").strip().upper()

    if code == "UK":
        return "GB"

    if len(code) != 2:
        return ""

    if not re.match(r"^[A-Z]{2}$", code):
        return ""

    return code


def country_name(code: str) -> str:
    normalized = normalize_country_code(code)
    return COUNTRY_NAMES.get(normalized, normalized or "UN")


def is_ipv4(value: str) -> bool:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value or ""):
        return False

    try:
        parts = [int(part) for part in value.split(".")]
        return all(0 <= part <= 255 for part in parts)
    except Exception:
        return False


def is_private_ip(value: str) -> bool:
    if not is_ipv4(value):
        return False

    try:
        parts = [int(part) for part in value.split(".")]
        a, b = parts[0], parts[1]

        if a == 10:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 100 and 64 <= b <= 127:
            return True

        return False
    except Exception:
        return True


def is_valid_hostname(value: str) -> bool:
    if not value:
        return False

    value = value.strip().strip("[]")

    if is_ipv4(value):
        return False

    if len(value) > 253:
        return False

    try:
        value.encode("idna")
    except Exception:
        return False

    if "." not in value:
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
        q = urllib.parse.parse_qs(uri.query, keep_blank_values=True)
        return q.get(key, [default])[0] or default
    except Exception:
        return default


def get_transport(link: str) -> str:
    value = extract_query_value(link, "type", "").lower()

    if not value:
        value = extract_query_value(link, "transport", "").lower()

    if not value:
        value = extract_query_value(link, "net", "").lower()

    if not value:
        value = "tcp"

    if value == "websocket":
        return "ws"

    return value


def get_security(link: str) -> str:
    return extract_query_value(link, "security", "").lower()


def get_uuid_from_link(link: str) -> str:
    try:
        uri = urllib.parse.urlparse(link)
        return uri.username or ""
    except Exception:
        return ""


def safe_host_from_link(link: str) -> str:
    try:
        uri = urllib.parse.urlparse(link)
        return (uri.hostname or "").strip()
    except Exception:
        match = re.search(r"@([^:/?#]+):", link)
        return match.group(1).strip() if match else ""


def safe_port_from_link(link: str) -> int:
    try:
        uri = urllib.parse.urlparse(link)
        return int(uri.port or 443)
    except Exception:
        match = re.search(r"@[^:/?#]+:(\d{2,5})", link)
        return int(match.group(1)) if match else 443


def predict_country_from_metadata(remark: str, sni: str, host: str, ip: str) -> Optional[str]:
    space = f"{remark} {sni} {host} {ip}".upper()

    for code, patterns in COUNTRY_MAPPINGS.items():
        for pattern in patterns:
            try:
                if pattern.startswith("🇦") or pattern.startswith("🇧") or pattern.startswith("🇨") or pattern.startswith("🇩") or pattern.startswith("🇪") or pattern.startswith("🇫") or pattern.startswith("🇬") or pattern.startswith("🇭") or pattern.startswith("🇮") or pattern.startswith("🇯") or pattern.startswith("🇳") or pattern.startswith("🇵") or pattern.startswith("🇷") or pattern.startswith("🇸") or pattern.startswith("🇹") or pattern.startswith("🇺"):
                    if pattern in f"{remark} {sni} {host} {ip}":
                        return code
                elif re.search(pattern, space):
                    return code
            except Exception:
                pass

    return None


def normalize_vless_link(link: str) -> str:
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
    transport = get_transport(link)
    fp = extract_query_value(link, "fp")

    return f"{proto}|{ip}|{port}|{uuid}|{sni}|{host}|{pbk}|{sid}|{flow}|{security}|{transport}|{fp}"


def extract_links_from_text(text: str) -> List[str]:
    lines: List[str] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if "://" in line:
            lines.append(line)
            continue

        decoded = decode_base64(line)
        if decoded != line and "://" in decoded:
            for decoded_line in decoded.splitlines():
                decoded_line = decoded_line.strip()
                if "://" in decoded_line:
                    lines.append(decoded_line)

    if not lines and "://" in text:
        pattern = re.compile(r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s]+", re.IGNORECASE)
        lines.extend(match.group(0).strip() for match in pattern.finditer(text))

    return lines


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
            return None

        ip = safe_host_from_link(link)
        port = safe_port_from_link(link)

        if not ip:
            return None

        if is_private_ip(ip):
            return None

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
                return None

        if sni and not is_valid_hostname(sni):
            if security == "reality":
                return None

        link = normalize_vless_link(link)

        predicted_country = predict_country_from_metadata(remark, sni, host, ip)

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
            "country": predicted_country,
            "predictedCountry": predicted_country,
            "remark": remark,
        }

    except Exception:
        return None


# =============================================================================
# GEO CONSENSUS
# =============================================================================

def weighted_country_consensus(results: Dict[str, str]) -> Dict[str, Any]:
    votes: Dict[str, float] = {}
    sources: Dict[str, List[str]] = {}

    for provider, country in results.items():
        code = normalize_country_code(country)
        if not code:
            continue

        weight = float(GEO_PROVIDER_WEIGHTS.get(provider, 1.0))
        votes[code] = votes.get(code, 0.0) + weight
        sources.setdefault(code, []).append(provider)

    if not votes:
        return {
            "country": "UN",
            "confidence": 0.0,
            "sources": [],
            "raw": results,
            "conflict": False,
        }

    total = sum(votes.values())
    country, score = sorted(votes.items(), key=lambda item: item[1], reverse=True)[0]

    confidence = score / total if total > 0 else 0.0

    return {
        "country": country,
        "confidence": round(confidence, 3),
        "sources": sources.get(country, []),
        "raw": results,
        "conflict": len(votes) > 1,
    }


async def fetch_ip_api_batch(
    session: aiohttp.ClientSession,
    ips: List[str],
) -> Dict[str, str]:
    result: Dict[str, str] = {}

    try:
        async with session.post(
            "http://ip-api.com/batch?fields=query,countryCode,status",
            json=ips,
        ) as resp:
            if resp.status != 200:
                return result

            data = await resp.json(content_type=None)

            if not isinstance(data, list):
                return result

            for item in data:
                if not isinstance(item, dict):
                    continue

                if item.get("status") != "success":
                    continue

                ip = item.get("query")
                country = normalize_country_code(item.get("countryCode", ""))

                if ip and country:
                    result[ip] = country

    except Exception:
        pass

    return result


async def fetch_ipinfo_country(
    session: aiohttp.ClientSession,
    ip: str,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, Optional[str]]:
    async with semaphore:
        try:
            async with session.get(f"https://ipinfo.io/{ip}/json") as resp:
                if resp.status != 200:
                    return ip, None

                data = await resp.json(content_type=None)
                return ip, normalize_country_code(data.get("country", ""))

        except Exception:
            return ip, None


async def fetch_ipwhois_country(
    session: aiohttp.ClientSession,
    ip: str,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, Optional[str]]:
    async with semaphore:
        try:
            async with session.get(f"https://ipwho.is/{ip}") as resp:
                if resp.status != 200:
                    return ip, None

                data = await resp.json(content_type=None)

                if isinstance(data, dict) and data.get("success") is False:
                    return ip, None

                return ip, normalize_country_code(data.get("country_code", ""))

        except Exception:
            return ip, None


async def resolve_geo_consensus(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not nodes:
        return nodes

    ips = sorted(set(n["ip"] for n in nodes if n.get("ip")))

    print("===============================================================")
    print("[LUMA] Running multi-provider GeoIP consensus...")
    print("===============================================================")
    print(f"[LUMA] Unique IPs for GeoIP: {len(ips)}")

    timeout = aiohttp.ClientTimeout(total=GEO_TIMEOUT)
    headers = {
        "User-Agent": "Mozilla/5.0 LumaShieldGeoValidator/2.1",
        "Accept": "application/json,*/*",
    }

    ip_api_map: Dict[str, str] = {}
    ipinfo_map: Dict[str, str] = {}
    ipwhois_map: Dict[str, str] = {}

    geo_semaphore = asyncio.Semaphore(GEO_CONCURRENCY_LIMIT)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for i in range(0, len(ips), GEO_BATCH_SIZE):
            batch = ips[i:i + GEO_BATCH_SIZE]
            batch_result = await fetch_ip_api_batch(session, batch)
            ip_api_map.update(batch_result)
            await asyncio.sleep(GEO_REQUEST_DELAY)

        ipinfo_tasks = [fetch_ipinfo_country(session, ip, geo_semaphore) for ip in ips]
        ipwhois_tasks = [fetch_ipwhois_country(session, ip, geo_semaphore) for ip in ips]

        ipinfo_results = await asyncio.gather(*ipinfo_tasks, return_exceptions=True)
        ipwhois_results = await asyncio.gather(*ipwhois_tasks, return_exceptions=True)

    for item in ipinfo_results:
        if isinstance(item, tuple):
            ip, country = item
            if country:
                ipinfo_map[ip] = country

    for item in ipwhois_results:
        if isinstance(item, tuple):
            ip, country = item
            if country:
                ipwhois_map[ip] = country

    consensus_by_ip: Dict[str, Dict[str, Any]] = {}

    for ip in ips:
        raw = {
            "ip_api": ip_api_map.get(ip, ""),
            "ipinfo": ipinfo_map.get(ip, ""),
            "ipwhois": ipwhois_map.get(ip, ""),
        }

        consensus_by_ip[ip] = weighted_country_consensus(raw)

    patched: List[Dict[str, Any]] = []

    mismatch_count = 0
    conflict_count = 0
    weak_geo_count = 0

    for node in nodes:
        ip = node.get("ip", "")
        geo = consensus_by_ip.get(ip, {
            "country": "UN",
            "confidence": 0.0,
            "sources": [],
            "raw": {},
            "conflict": False,
        })

        predicted = normalize_country_code(node.get("predictedCountry") or node.get("country") or "")
        observed = normalize_country_code(geo.get("country", "")) or "UN"

        sources = geo.get("sources", [])
        confidence = float(geo.get("confidence", 0.0))
        conflict = bool(geo.get("conflict", False))

        country_mismatch = (
            bool(predicted)
            and observed != "UN"
            and predicted != observed
        )

        if country_mismatch:
            mismatch_count += 1

        if conflict:
            conflict_count += 1

        if confidence < MIN_GEO_CONFIDENCE or len(sources) < MIN_GEO_SOURCES_FOR_EXPORT:
            weak_geo_count += 1

        node["predictedCountryCode"] = predicted or ""
        node["observedCountryCode"] = observed
        node["observedIp"] = ip
        node["geoConfidence"] = round(confidence, 3)
        node["geoSources"] = sources
        node["geoRaw"] = geo.get("raw", {})
        node["geoConflict"] = conflict
        node["countryMismatch"] = country_mismatch

        if observed != "UN":
            node["country"] = observed
        elif predicted:
            node["country"] = predicted
        else:
            node["country"] = "UN"

        patched.append(node)

    print(f"[LUMA] Geo conflicts: {conflict_count}")
    print(f"[LUMA] Predicted/observed mismatches: {mismatch_count}")
    print(f"[LUMA] Weak GeoIP confidence nodes: {weak_geo_count}")

    return patched


# =============================================================================
# QUALITY SCORE
# =============================================================================

def compute_quality_score(node: Dict[str, Any]) -> float:
    ping = int(node.get("ping", 9999))
    jitter = int(node.get("jitter", 9999))
    success_rate = float(node.get("probeSuccessRate", 0.0))

    port = int(node.get("port", 0))
    security = node.get("security", "")
    transport = node.get("transport", "")
    flow = node.get("flow", "")
    fp = node.get("fp", "")
    sni = node.get("sni", "")

    geo_confidence = float(node.get("geoConfidence", 0.0))
    geo_sources = node.get("geoSources", [])
    geo_conflict = bool(node.get("geoConflict", False))
    country_mismatch = bool(node.get("countryMismatch", False))

    score = 100.0

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

    if success_rate >= 1.0:
        score += 12
    elif success_rate >= 0.67:
        score += 4
    else:
        score -= 35

    if security == "reality":
        score += 14
    elif security == "tls":
        score += 8
    else:
        score -= 45

    if transport == "tcp":
        score += 6
    elif transport == "grpc":
        score += 7
    elif transport in ["h2", "http"]:
        score += 4
    elif transport in BLOCKED_TRANSPORTS:
        score -= 45

    if flow == "xtls-rprx-vision":
        score += 8

    if port == 443:
        score += 8
    elif port in [8443, 2053, 2083, 2087, 2096]:
        score += 3
    else:
        score -= 25

    if fp in ["chrome", "firefox", "safari", "ios", "android", "randomized"]:
        score += 4

    if sni and is_valid_hostname(sni):
        score += 5
    else:
        score -= 18

    if geo_confidence >= 0.95 and len(geo_sources) >= 2:
        score += 8
    elif geo_confidence >= 0.60 and len(geo_sources) >= 2:
        score += 3
    elif geo_confidence > 0:
        score -= 6
    else:
        score -= 16

    if geo_conflict:
        score -= 8

    if country_mismatch:
        score -= 10

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
# TLS PROBING
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
            "User-Agent: Mozilla/5.0 LumaShieldScanner/2.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8", errors="ignore")

        writer.write(request)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(512), timeout=READ_TIMEOUT)

        if not response:
            return None

        elapsed_ms = int((time.time() - start) * 1000)

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

            if node["ping"] > MAX_ACCEPTED_PING:
                return None

            if node["jitter"] > MAX_ACCEPTED_JITTER:
                return None

            if node["probeSuccessRate"] < MIN_PROBE_SUCCESS_RATE:
                return None

            return node

        except Exception:
            return None


# =============================================================================
# SCRAPING
# =============================================================================

async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    try:
        async with session.get(url) as response:
            if response.status != 200:
                print(f"[LUMA] Source skipped status={response.status}: {url}")
                return []

            text = await response.text(errors="ignore")

            if "://" not in text:
                decoded = decode_base64(text)
                if "://" in decoded:
                    text = decoded

            return extract_links_from_text(text)

    except Exception as e:
        print(f"[LUMA] Source error: {url} | {e}")
        return []


async def fetch_all_links() -> List[str]:
    timeout = aiohttp.ClientTimeout(total=SOURCE_TIMEOUT)

    headers = {
        "User-Agent": "Mozilla/5.0 LumaShieldNodeScanner/2.1",
        "Accept": "*/*",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
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
# EXPORT FILTERING
# =============================================================================

def should_export_node(node: Dict[str, Any]) -> bool:
    if node.get("country") in ["", None, "UN"]:
        return False

    if float(node.get("qualityScore", 0.0)) < MIN_QUALITY_SCORE:
        return False

    if int(node.get("ping", 9999)) > MAX_ACCEPTED_PING:
        return False

    if int(node.get("jitter", 9999)) > MAX_ACCEPTED_JITTER:
        return False

    if float(node.get("probeSuccessRate", 0.0)) < MIN_PROBE_SUCCESS_RATE:
        return False

    geo_confidence = float(node.get("geoConfidence", 0.0))
    geo_sources = node.get("geoSources", [])

    if geo_confidence < MIN_GEO_CONFIDENCE:
        return False

    if len(geo_sources) < MIN_GEO_SOURCES_FOR_EXPORT:
        return False

    if DROP_GEO_CONFLICT_NODES and node.get("countryMismatch") is True:
        return False

    return True


def export_node_payload(node: Dict[str, Any], country: str) -> Dict[str, Any]:
    return {
        "config": node["link"],
        "countryCode": country,
        "countryName": country_name(country),
        "pingMs": int(node["ping"]),
        "qualityScore": float(node.get("qualityScore", 0)),
        "jitterMs": int(node.get("jitter", 9999)),
        "probeSuccessRate": float(node.get("probeSuccessRate", 0)),
        "proto": node.get("proto", ""),
        "security": node.get("security", ""),
        "transport": node.get("transport", ""),
        "flow": node.get("flow", ""),
        "fp": node.get("fp", ""),
        "verifiedAt": int(node.get("verifiedAt", int(time.time()))),
        "host": node.get("ip", ""),
        "port": int(node.get("port", 443)),
        "observedIp": node.get("observedIp", node.get("ip", "")),
        "observedCountryCode": node.get("observedCountryCode", country),
        "predictedCountryCode": node.get("predictedCountryCode", ""),
        "geoConfidence": float(node.get("geoConfidence", 0.0)),
        "geoSources": node.get("geoSources", []),
        "geoConflict": bool(node.get("geoConflict", False)),
        "countryMismatch": bool(node.get("countryMismatch", False)),
    }


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
    print("[LUMA] Running multi-probe TLS quality validation...")
    print("===============================================================")

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [validate_node(node, semaphore) for node in parsed_nodes]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive = [
        result for result in results
        if isinstance(result, dict)
    ]

    print(f"[LUMA] Alive high-quality pre-geo candidates: {len(alive)}")

    if not alive:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)

        print("[LUMA] No alive candidates found. Empty JSON exported.")
        return

    alive = await resolve_geo_consensus(alive)

    for node in alive:
        node["qualityScore"] = compute_quality_score(node)

    filtered_alive = [node for node in alive if should_export_node(node)]

    print(f"[LUMA] Exportable nodes after geo consensus: {len(filtered_alive)}")

    pools: Dict[str, List[Dict[str, Any]]] = {}

    for node in filtered_alive:
        country = normalize_country_code(node.get("country", ""))

        if not country or country == "UN":
            continue

        pools.setdefault(country, []).append(node)

    out: Dict[str, List[Dict[str, Any]]] = {}

    for country, nodes in pools.items():
        nodes.sort(
            key=lambda x: (
                -float(x.get("qualityScore", 0)),
                int(x.get("ping", 9999)),
                int(x.get("jitter", 9999)),
                -float(x.get("geoConfidence", 0)),
            )
        )

        selected = nodes[:TOP_NODES_PER_COUNTRY]

        if not selected:
            continue

        out[country] = [export_node_payload(node, country) for node in selected]

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
            f"best={best['host']}:{best['port']} | "
            f"ping={best['pingMs']}ms | "
            f"quality={best['qualityScore']} | "
            f"geo={best['observedCountryCode']} "
            f"conf={best['geoConfidence']} "
            f"sources={','.join(best['geoSources'])}"
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[LUMA] Interrupted by user.")
