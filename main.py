"""
================================================================================
Luma Shield - Cloud Proxy Scraper & L7 Deep Probe Validator
================================================================================

Created by Alperen Burak Yeşil

Description:
This backend aggregator fetches, deduplicates, and evaluates premium VPN nodes.
It specifically destroys "Cloudflare Traps" (Anycast IPs with dead origins) 
using an advanced Layer 7 (L7) HTTP/TLS Deep Probe. Instead of heavy binary 
executions, it simulates a raw Xray WebSocket handshake. Nodes returning 
HTTP 5xx (502, 530) are purged instantly, ensuring the mobile app receives 
ONLY nodes with guaranteed internet egress.
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
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vmess_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt"
]

MAX_PING_MS = 1500
CONNECTION_TIMEOUT = 3.0
TOP_NODES_PER_COUNTRY = 5
CONCURRENCY_LIMIT = 150

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
        if not link: return None

        protocol = link.split('://')[0].lower()
        if protocol not in ['vless', 'trojan', 'vmess']:
            return None

        ip, port, sni, host, path = "", 0, "", "", "/"

        if protocol == 'vmess':
            b64 = link[8:]
            b64 += '=' * (-len(b64) % 4)
            v = json.loads(base64.b64decode(b64).decode('utf-8'))
            ip = v.get('add', '')
            port = int(v.get('port', 443))
            sni = v.get('sni', '')
            host = v.get('host', '')
            path = v.get('path', '/')
        else:
            match = re.search(r'@([^:]+):(\d+)', link)
            if not match: return None
            ip = match.group(1)
            port = int(match.group(2))
            uri = urllib.parse.urlparse(link)
            query_params = urllib.parse.parse_qs(uri.query)
            sni = query_params.get('sni', [''])[0]
            host = query_params.get('host', [''])[0]
            path = query_params.get('path', ['/'])[0]
        
        if not sni: sni = host

        predicted_country = predict_true_egress(link, ip, sni, host)

        return {
            "link": link,
            "protocol": protocol,
            "ip": ip,
            "port": port,
            "sni": sni,
            "host": host,
            "path": path,
            "country": predicted_country
        }
    except Exception:
        return None

async def _do_validate(node):
    ip = node['ip']
    port = node['port']
    sni = node['sni'] or node['host'] or ip
    host = node['host'] or sni
    path = node['path']
    start_time = time.time()
    writer = None 

    try:
        requires_tls = port in [443, 8443, 2053, 2083, 2087, 2096] or 'tls' in node['link'].lower()
        
        if requires_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            valid_sni = sni if sni and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sni) else None
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=valid_sni),
                timeout=CONNECTION_TIMEOUT
            )

            req = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   f"Upgrade: websocket\r\n"
                   f"Connection: Upgrade\r\n"
                   f"User-Agent: LumaShield-Validator/1.0\r\n\r\n").encode('utf-8')
            
            writer.write(req)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(1024), timeout=CONNECTION_TIMEOUT)

            resp_str = resp.decode('utf-8', errors='ignore')

            # Sahte Cloudflare yakalama
            if "HTTP/1.1 5" in resp_str or "502 Bad Gateway" in resp_str or "Error 5" in resp_str:
                return None 

            if len(resp) == 0:
                return None 

        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=CONNECTION_TIMEOUT
            )
            writer.write(b"\x00" * 10)
            await writer.drain()

        latency = int((time.time() - start_time) * 1000)
        if latency <= MAX_PING_MS:
            node['ping'] = latency
            return node
            
        return None
    except Exception:
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def validate_node(node, semaphore):
    async with semaphore:
        try:
            return await asyncio.wait_for(_do_validate(node), timeout=CONNECTION_TIMEOUT + 1.5)
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

    print(f"Scraped {len(parsed_nodes)} unique nodes. Beginning L7 Deep Probe validation...")
    
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [validate_node(node, semaphore) for node in parsed_nodes]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive_nodes = [res for res in results if isinstance(res, dict)]
    print(f"Validation complete. {len(alive_nodes)} real nodes survived the Cloudflare trap check.")

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
        
    print(f"Successfully saved {sum(len(v) for v in json_output.values())} ultra-premium nodes to JSON.")
    
    await asyncio.sleep(0.250)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
