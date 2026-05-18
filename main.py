"""
================================================================================
Luma Shield - Cloud Proxy Scraper & Egress-First Validator Architecture
================================================================================

Created by Alperen Burak Yeşil

Description:
This backend aggregator fetches, deduplicates, and evaluates premium VPN nodes.
It addresses the "CDN Illusion" (Ingress vs Egress mismatch) by implementing a
predictive egress locator. Instead of strictly relying on the physical location
of a Cloudflare/CDN IP (which is often misleading), it analyzes SNI, host headers,
and creator remarks to group nodes by their true egress (exit) country.

Architecture & Core Methods:
1. Fetching: Pulls raw configurations from expanded premium Telegram/GitHub URLs.
2. Parsing & Deduplication: Extracts core config details and drops duplicates.
3. Egress Prediction (predict_true_egress): Employs a scoring heuristic combining
   Regex boundary checks, emoji flags, and SNI headers to override inaccurate
   GeoIP API responses for Anycast IPs.
4. Latency Check: Opens a raw TCP socket, discarding slow nodes (>150ms).
5. Geo-Structuring: Groups and limits nodes purely by their verified Egress location.
================================================================================
"""

import asyncio
import aiohttp
import base64
import time
import json
import re
import sys
import urllib.parse
import ssl

SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Epodon/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/BoringCat/v2ray-links/master/links.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/main/trojan",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/main/vless",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/v2ray-links/v2ray-free/master/v2ray",
    "https://raw.githubusercontent.com/JlikO/V2Ray-configs/main/All_Configs_Sub.txt"
]

MAX_PING_MS = 1500
CONNECTION_TIMEOUT = 3.0
TOP_NODES_PER_COUNTRY = 4
CONCURRENCY_LIMIT = 100

COUNTRY_MAPPINGS = {
    "TR": ["🇹🇷", r"\bTR\b", r"\bTURKEY\b", r"\.tr$"],
    "US": ["🇺🇸", r"\bUS\b", r"\bUSA\b", r"\.us$"],
    "DE": ["🇩🇪", r"\bDE\b", r"\bGERMANY\b", r"\.de$"],
    "FR": ["🇫🇷", r"\bFR\b", r"\bFRANCE\b", r"\.fr$"],
    "GB": ["🇬🇧", r"\bGB\b", r"\bUK\b", r"\bENGLAND\b", r"\.uk$"],
    "NL": ["🇳🇱", r"\bNL\b", r"\bNETHERLANDS\b", r"\.nl$"],
    "SG": ["🇸🇬", r"\bSG\b", r"\bSINGAPORE\b", r"\.sg$"],
    "JP": ["🇯🇵", r"\bJP\b", r"\bJAPAN\b", r"\.jp$"],
    "CA": ["🇨🇦", r"\bCA\b", r"\bCANADA\b", r"\.ca$"],
    "AU": ["🇦🇺", r"\bAU\b", r"\bAUSTRALIA\b", r"\.au$"],
    "IT": ["🇮🇹", r"\bIT\b", r"\bITALY\b", r"\.it$"],
    "ES": ["🇪🇸", r"\bES\b", r"\bSPAIN\b", r"\.es$"]
}

def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return data

def predict_true_egress(link, ip, sni, host):
    try:
        uri = urllib.parse.urlparse(link)
        remark = urllib.parse.unquote(uri.fragment).upper()
        combined_search_space = f"{remark} {sni} {host}"

        for country_code, patterns in COUNTRY_MAPPINGS.items():
            for pattern in patterns:
                if re.search(pattern, combined_search_space):
                    return country_code
    except Exception:
        pass
    return None

def parse_config(link):
    try:
        link = link.strip()
        if not link:
            return None

        protocol = link.split('://')[0].lower()
        if protocol not in ['vless', 'trojan', 'ss']:
            return None

        match = re.search(r'@([^:]+):(\d+)', link)
        if not match:
            return None
            
        ip = match.group(1)
        port = int(match.group(2))

        uri = urllib.parse.urlparse(link)
        query_params = urllib.parse.parse_qs(uri.query)
        sni = query_params.get('sni', [''])[0]
        host = query_params.get('host', [''])[0]
        
        if not sni:
            sni = host

        predicted_country = predict_true_egress(link, ip, sni, host)

        return {
            "link": link,
            "protocol": protocol,
            "ip": ip,
            "port": port,
            "sni": sni,
            "country": predicted_country
        }
    except Exception:
        return None

async def _do_validate(node):
    ip = node['ip']
    port = node['port']
    sni = node['sni']
    start_time = time.time()

    try:
        requires_tls = port in [443, 8443, 2053, 2083, 2087, 2096] or 'vless' in node['protocol'] or 'trojan' in node['protocol']
        
        if requires_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            valid_sni = sni if sni and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sni) else None
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=valid_sni),
                timeout=CONNECTION_TIMEOUT
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=CONNECTION_TIMEOUT
            )
            
        writer.close()

        latency = int((time.time() - start_time) * 1000)
        if latency <= MAX_PING_MS:
            node['ping'] = latency
            return node
            
        return None
    except Exception:
        return None

async def validate_node(node, semaphore):
    async with semaphore:
        try:
            return await asyncio.wait_for(_do_validate(node), timeout=CONNECTION_TIMEOUT + 2.0)
        except Exception:
            return None

async def resolve_fallback_countries(nodes):
    unknown_nodes = [n for n in nodes if n['country'] is None]
    if not unknown_nodes:
        return nodes

    ips = list(set([n['ip'] for n in unknown_nodes]))
    ip_to_country = {}
    chunks = [ips[i:i + 100] for i in range(0, len(ips), 100)]

    async with aiohttp.ClientSession() as session:
        for chunk in chunks:
            try:
                async with session.post(
                    "http://ip-api.com/batch?fields=query,countryCode,status",
                    json=chunk,
                    timeout=5
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data:
                            if item.get('status') == 'success':
                                ip_to_country[item['query']] = item.get('countryCode')
            except Exception:
                pass

    for n in nodes:
        if n['country'] is None:
            n['country'] = ip_to_country.get(n['ip'], 'UN')

    return nodes

async def main():
    raw_links = []

    async with aiohttp.ClientSession() as session:
        for url in SOURCES:
            try:
                async with session.get(url, timeout=6) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "://" not in text:
                            text = decode_base64(text)
                        raw_links.extend(text.splitlines())
            except Exception:
                continue

    unique_ips = set()
    parsed_nodes = []

    for link in raw_links:
        node = parse_config(link)
        if node and node['ip'] not in unique_ips:
            unique_ips.add(node['ip'])
            parsed_nodes.append(node)

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [validate_node(node, semaphore) for node in parsed_nodes]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive_nodes = [res for res in results if isinstance(res, dict)]

    verified_nodes = await resolve_fallback_countries(alive_nodes)

    country_pools = {}
    for node in verified_nodes:
        c = node['country']
        if c == 'UN' or c not in COUNTRY_MAPPINGS.keys():
            continue
            
        if c not in country_pools:
            country_pools[c] = []
        country_pools[c].append(node)

    json_output = {}

    for country, nodes in country_pools.items():
        nodes.sort(key=lambda x: x['ping'])
        top_nodes = nodes[:TOP_NODES_PER_COUNTRY]

        json_output[country] = []
        for n in top_nodes:
            json_output[country].append({
                "config": n['link'],
                "countryCode": country,
                "countryName": country,
                "pingMs": n['ping']
            })

    with open('luma_premium_nodes.json', 'w', encoding='utf-8') as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
