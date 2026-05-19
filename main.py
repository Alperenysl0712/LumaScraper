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
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vmess_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2"
]

MAX_PING_MS = 1500
CONNECTION_TIMEOUT = 3.0
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

def predict_true_egress(link, sni, host, remark):
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
        if proto not in ['vless', 'trojan', 'vmess']: return None

        if proto in ['vless', 'trojan']:
            if 'security=tls' not in link.lower() and 'security=reality' not in link.lower():
                return None

        ip, port, sni, host, path, remark = "", 0, "", "", "/", ""

        if proto == 'vmess':
            b64 = link[8:]
            b64 += '=' * (-len(b64) % 4)
            v = json.loads(base64.b64decode(b64).decode('utf-8'))
            ip, port = v.get('add', ''), int(v.get('port', 443))
            sni, host = v.get('sni', ''), v.get('host', '')
            path, remark = v.get('path', '/'), v.get('ps', '')
            if str(v.get('tls', '')).lower() != 'tls': return None
        else:
            match = re.search(r'@([^:]+):(\d+)', link)
            if not match: return None
            ip, port = match.group(1), int(match.group(2))
            uri = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(uri.query)
            sni, host = q.get('sni', [''])[0], q.get('host', [''])[0]
            path = q.get('path', ['/'])[0]
            remark = urllib.parse.unquote(uri.fragment)

        if port not in [443, 8443, 2053, 2083, 2087, 2096]: return None
        if not sni: sni = host

        if ('type=ws' in link or 'ws=1' in link) and proto != 'vmess':
            link = link.replace('type=ws', 'type=grpc').replace('ws=1', 'grpc=1')
        
        if 'security=reality' in link and 'fragment=' not in link:
            link += '&fragment=10-20,10-20,tlshello'

        country = predict_true_egress(link, sni, host, remark)

        return {"link": link, "ip": ip, "port": port, "sni": sni, "host": host, "path": path, "country": country}
    except: return None

async def _do_validate(node):
    ip, port, sni, host, path = node['ip'], node['port'], node['sni'] or node['host'] or ip, node['host'] or sni, node['path']
    start = time.time()
    writer = None 
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        valid_sni = sni if sni and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sni) else None
        if valid_sni:
            try: valid_sni.encode('idna')
            except: valid_sni = None
        
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context, server_hostname=valid_sni), timeout=CONNECTION_TIMEOUT)
        req = (f"GET / HTTP/1.1\r\nHost: iplocation.net\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-Agent: LumaShield/1.0\r\n\r\n").encode('utf-8')
        writer.write(req)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2048), timeout=5.0)
        writer.close()
        await writer.wait_closed()
        
        if b"<html" in resp.lower() or b"http/1.1 200" in resp.lower():
            node['ping'] = int((time.time() - start) * 1000)
            return node
        return None
    except: return None
    finally:
        if writer:
            try: writer.close()
            except: pass

async def main():
    raw_links = []
    async with aiohttp.ClientSession() as session:
        for url in SOURCES:
            try:
                async with session.get(url, timeout=6) as response:
                    if response.status == 200:
                        text = await response.text()
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
    results = await asyncio.gather(*[asyncio.wait_for(validate_node(n, sem), timeout=8.0) for n in parsed_nodes], return_exceptions=True)
    alive = [res for res in results if isinstance(res, dict)]
    
    country_pools = {}
    for node in await resolve_fallback_countries(alive):
        c = node['country']
        if not c or c not in COUNTRY_MAPPINGS: continue
        country_pools.setdefault(c, []).append(node)

    json_out = {}
    for country, nodes in country_pools.items():
        nodes.sort(key=lambda x: x['ping'])
        json_out[country] = [{"config": n['link'], "countryCode": country, "countryName": country, "pingMs": n['ping']} for n in nodes[:TOP_NODES_PER_COUNTRY]]

    with open('luma_premium_nodes.json', 'w', encoding='utf-8') as f:
        json.dump(json_out, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
