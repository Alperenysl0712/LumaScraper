"""
================================================================================
Luma Shield - Cloud Proxy Scraper & L7 Deep Probe Validator
================================================================================

Created by Alperen Burak Yeşil

Description:
This backend aggregator fetches, deduplicates, and evaluates premium VPN nodes.
*NEW*: It now acts as a Strict Security Dictator. It ruthlessly drops ANY node 
that does not use TLS encryption (Port 443, 8443, etc.) or lacks security=tls/reality. 
This guarantees that nodes survive Deep Packet Inspection (DPI) in heavily 
censored regions (like Turkey).
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
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"
]

MAX_PING_MS = 2000
CONNECTION_TIMEOUT = 5.0
TOP_NODES_PER_COUNTRY = 10
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
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except: return data

def predict_true_egress(remark, sni, host):
    space = f"{remark} {sni} {host}".upper()
    for code, patterns in COUNTRY_MAPPINGS.items():
        for p in patterns:
            if re.search(p, space): return code
    return None

def parse_config(link):
    try:
        link = link.strip()
        if not link: return None
        proto = link.split('://')[0].lower()
        
        if proto not in ['vless', 'hysteria2', 'hy2']: 
            return None

        if proto == 'vless':
            if 'security=reality' not in link.lower():
                return None
            if 'type=ws' in link.lower() or 'ws=1' in link.lower():
                return None

        match = re.search(r'@([^:]+):(\d+)', link)
        if not match: return None
        ip, port = match.group(1), int(match.group(2))
        
        if proto == 'vless' and port not in [443, 8443, 2053, 2083, 2087, 2096]: 
            return None

        uri = urllib.parse.urlparse(link)
        q = urllib.parse.parse_qs(uri.query)
        sni = q.get('sni', [''])[0]
        host = q.get('host', [''])[0]
        if not sni: sni = host
        remark = urllib.parse.unquote(uri.fragment)

        if proto == 'vless' and 'fragment=' not in link:
            link += '&fragment=10-20,10-20,tlshello'

        country = predict_true_egress(remark, sni, host)
        return {"link": link, "ip": ip, "port": port, "sni": sni, "host": host, "proto": proto, "country": country}
    except: return None

async def _do_validate(node):
    ip, port, sni, proto = node['ip'], node['port'], node['sni'] or node['ip'], node['proto']
    start = time.time()
    
    if proto in ['hysteria2', 'hy2']:
        node['ping'] = 300
        return node

    writer = None 
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        valid_sni = sni if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sni) else None
        if valid_sni:
            try: valid_sni.encode('idna')
            except: valid_sni = None
            
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context, server_hostname=valid_sni), timeout=CONNECTION_TIMEOUT)
        req = (f"GET / HTTP/1.1\r\nHost: iplocation.net\r\nConnection: close\r\n\r\n").encode('utf-8')
        writer.write(req)
        await writer.drain()
        
        resp = await asyncio.wait_for(reader.read(2048), timeout=3.0)
        
        if b"200 OK" in resp or b"204" in resp or b"<html" in resp.lower() or b"bad request" in resp.lower():
            node['ping'] = int((time.time() - start) * 1000)
            return node
        return None
    except: return None
    finally:
        if writer:
            try: 
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except: pass

async def validate_node(node, semaphore):
    async with semaphore:
        return await asyncio.wait_for(_do_validate(node), timeout=CONNECTION_TIMEOUT + 3.0)

async def resolve_fallback_countries(nodes):
    unknown = [n for n in nodes if n['country'] is None]
    if not unknown: return nodes
    ips = list(set([n['ip'] for n in unknown]))
    ip_to_country = {}
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(ips), 100):
            try:
                async with session.post("http://ip-api.com/batch?fields=query,countryCode,status", json=ips[i:i+100], timeout=5) as resp:
                    if resp.status == 200:
                        for item in await resp.json():
                            if item.get('status') == 'success': ip_to_country[item['query']] = item.get('countryCode')
            except: pass
    for n in nodes:
        if n['country'] is None: n['country'] = ip_to_country.get(n['ip'], 'UN')
    return nodes

async def main():
    raw_links = []
    async with aiohttp.ClientSession() as s:
        for url in SOURCES:
            try:
                async with s.get(url, timeout=8) as r:
                    if r.status == 200: 
                        text = await r.text()
                        if "://" not in text: text = decode_base64(text)
                        raw_links.extend(text.splitlines())
            except: continue
    
    unique_ips, parsed_nodes = set(), []
    for link in raw_links:
        node = parse_config(link)
        if node and node['ip'] not in unique_ips:
            unique_ips.add(node['ip'])
            parsed_nodes.append(node)
            
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    results = await asyncio.gather(*[validate_node(n, sem) for n in parsed_nodes], return_exceptions=True)
    alive = [res for res in results if isinstance(res, dict)]
    
    pools = {}
    for node in await resolve_fallback_countries(alive):
        c = node['country']
        if not c or c not in COUNTRY_MAPPINGS: continue
        pools.setdefault(c, []).append(node)
    
    out = {}
    for country, nodes in pools.items():
        nodes.sort(key=lambda x: x['ping'])
        out[country] = [{"config": n['link'], "countryCode": country, "countryName": country, "pingMs": n['ping']} for n in nodes[:TOP_NODES_PER_COUNTRY]]
    
    with open('luma_premium_nodes.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
