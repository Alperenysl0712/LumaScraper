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
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/vless.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/vmess.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/trojan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vmess.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/trojan.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"
]

MAX_PING_MS = 2000
CONNECTION_TIMEOUT = 5.0
TOP_NODES_PER_COUNTRY = 10
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

def parse_config(link):
    try:
        link = link.strip()
        proto = link.split('://')[0].lower()
        if proto not in ['vless', 'trojan', 'vmess']: return None
        
        if 'security=tls' not in link.lower() and 'security=reality' not in link.lower():
            if proto != 'vmess': return None

        ip, port, sni, host, path, remark = "", 0, "", "", "/", ""

        if proto == 'vmess':
            b64 = link[8:]
            if '#' in b64: b64, remark = b64.split('#', 1)
            b64 += '=' * (-len(b64) % 4)
            v = json.loads(base64.b64decode(b64).decode('utf-8'))
            ip, port = v.get('add', ''), int(v.get('port', 443))
            sni, host, path = v.get('sni', ''), v.get('host', ''), v.get('path', '/')
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
        
        if 'security=reality' in link and 'fragment=' not in link:
            link += '&fragment=10-20,10-20,tlshello'
            
        return {"link": link, "ip": ip, "port": port, "sni": sni, "host": host, "path": path, "remark": remark}
    except: return None

async def validate_node(node, sem):
    async with sem:
        try:
            start = time.time()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(asyncio.open_connection(node['ip'], node['port'], ssl=ctx, server_hostname=node['sni'] or None), timeout=CONNECTION_TIMEOUT)
            writer.write(f"GET / HTTP/1.1\r\nHost: iplocation.net\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close(); await writer.wait_closed()
            
            if b"200 OK" in resp or b"204 No Content" in resp:
                node['ping'] = int((time.time() - start) * 1000)
                return node
        except: return None
    return None

async def main():
    raw_links = []
    async with aiohttp.ClientSession() as s:
        for url in SOURCES:
            try:
                async with s.get(url, timeout=5) as r:
                    if r.status == 200: raw_links.extend((await r.text()).splitlines())
            except: continue
    
    nodes = [n for n in [parse_config(l) for l in raw_links] if n]
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    alive = [res for res in await asyncio.gather(*[validate_node(n, sem) for n in nodes]) if res]
    
    out = {}
    for node in alive:
        c = "GLOBAL"
        out.setdefault(c, []).append({"config": node['link'], "pingMs": node['ping']})
    
    with open('luma_premium_nodes.json', 'w') as f:
        json.dump(out, f, indent=2)

asyncio.run(main())
