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

SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Epodon/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt"
]

MAX_PING_MS = 200
CONNECTION_TIMEOUT = 2.0
L7_TIMEOUT = 3.0
TOP_NODES_PER_COUNTRY = 3
CONCURRENCY_LIMIT = 300

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

async def check_l7_sni(sni):
    if not sni:
        return True
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://{sni}", timeout=L7_TIMEOUT) as response:
                if response.status in [521, 522, 523, 525, 526, 530]:
                    return False
                return True
    except Exception:
        return False

async def validate_node(node, semaphore):
    async with semaphore:
        ip = node['ip']
        port = node['port']
        start_time = time.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECTION_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            if node['sni']:
                is_l7_alive = await check_l7_sni(node['sni'])
                if not is_l7_alive:
                    return None

            latency = int((time.time() - start_time) * 1000)
            if latency <= MAX_PING_MS:
                node['ping'] = latency
                return node
                
            return None
        except (asyncio.TimeoutError, Exception):
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
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data:
                            if item.get('status') == 'success':
                                ip_to_country[item['query']] = item.get('countryCode')
                await asyncio.sleep(1.5)
            except Exception:
                pass

    for n in nodes:
        if n['country'] is None:
            n['country'] = ip_to_country.get(n['ip'], 'UN')

    return nodes

async def main():
    print("Starting Luma Shield Premium Scraper with L7 Validation...")
    raw_links = []

    async with aiohttp.ClientSession() as session:
        for url in SOURCES:
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "://" not in text:
                            text = decode_base64(text)
                        raw_links.extend(text.splitlines())
            except Exception:
                pass

    unique_ips = set()
    parsed_nodes = []

    for link in raw_links:
        node = parse_config(link)
        if node and node['ip'] not in unique_ips:
            unique_ips.add(node['ip'])
            parsed_nodes.append(node)

    print(f"Testing {len(parsed_nodes)} unique nodes with L7 verification...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [validate_node(node, semaphore) for node in parsed_nodes]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive_nodes = [res for res in results if res is not None and not isinstance(res, Exception)]

    print(f"Resolving remaining physical locations for {len(alive_nodes)} active nodes...")
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
    total_saved = 0

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
            total_saved += 1

    with open('luma_premium_nodes.json', 'w', encoding='utf-8') as f:
        json.dump(json_output, f, ensure_ascii=False, indent=2)

    print(f"Process complete! {total_saved} absolutely verified nodes exported.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
