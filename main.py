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
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/hysteria2_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/ss_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/tuic_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Leon406/Sub/master/sub/configs.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no5.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no6.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no9.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no10.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/vless.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/vmess.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/trojan.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/shadowsocks.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/hy2.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/tuic.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Germany.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Spain.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Netherlands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Türkiye.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Italy.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Canada.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Singapore.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/France.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/United_Kingdom.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/United_States.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Australia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Countrys/Japan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vmess.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/trojan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/shadowsocks.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ssr.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/shadowsocks.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/skywrt/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/skywrt/v2ray-Collector/master/v2ray",
    "https://raw.githubusercontent.com/10ium/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/10ium/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/10ium/V2rayCollectorLite/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/10ium/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged",
    "https://raw.githubusercontent.com/10ium/multi-proxy-config-fetcher/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Abdulhossein/Autov2rayLeecher/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/ShadowSocks.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/ShadowSocksR.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Trojan.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Tuic.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Vless.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Vmess.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/M-Mashreghi/Free-V2ray-Collector/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/M-Mashreghi/Free-V2ray-Collector/main/Splitted-By-Protocol/ssr.txt",
    "https://raw.githubusercontent.com/M-Mashreghi/Free-V2ray-Collector/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/M-Mashreghi/Free-V2ray-Collector/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/M-Mashreghi/Free-V2ray-Collector/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Reality",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/SS",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/T,H",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Vless",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links2.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/ss.html",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/trojan.html",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/vless.html",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/vmess.html",
    "https://raw.githubusercontent.com/azadiazinjamigzare/Service/main/Sub",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/hysteria2.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/tuic.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/darknessm427/Sub/main/Ss",
    "https://raw.githubusercontent.com/darknessm427/Sub/main/V2mix",
    "https://raw.githubusercontent.com/darknessm427/Sub/main/V2ss",
    "https://raw.githubusercontent.com/darknessm427/Sub/main/Warp/Nikav4",
    "https://raw.githubusercontent.com/darknessm427/Sub/main/Warp/Nikav6",
    "https://raw.githubusercontent.com/hamedp-71/Trojan/main/hp.txt",
    "https://raw.githubusercontent.com/hamedp-71/openproxylist/main/V2RAY.txt",
    "https://raw.githubusercontent.com/hamedp-71/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt"
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
        if proto not in ['vless', 'trojan', 'vmess']: return None

        if proto in ['vless', 'trojan']:
            if 'security=tls' not in link.lower() and 'security=reality' not in link.lower():
                return None

        ip, port, sni, host, path, remark = "", 0, "", "", "/", ""

        if proto == 'vmess':
            b64 = link[8:]
            if '#' in b64:
                b64, rem = b64.split('#', 1)
                remark = urllib.parse.unquote(rem)
            b64 += '=' * (-len(b64) % 4)
            v = json.loads(base64.b64decode(b64).decode('utf-8'))
            ip, port = v.get('add', ''), int(v.get('port', 443))
            sni, host = v.get('sni', ''), v.get('host', '')
            path = v.get('path', '/')
            if not remark: remark = v.get('ps', '')
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
            link += '&fragment=1-5,1-5,tlshello'

        country = predict_true_egress(remark, sni, host)

        return {"link": link, "ip": ip, "port": port, "sni": sni, "host": host, "path": path, "country": country}
    except: return None

async def _do_validate(node):
    ip, port, sni, host, path = node['ip'], node['port'], node['sni'] or node['host'] or node['ip'], node['host'] or node['sni'], node['path']
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
        if b"<html" in resp.lower() or b"http/1.1 200" in resp.lower() or b"connection established" in resp.lower():
            node['ping'] = int((time.time() - start) * 1000)
            return node
        return None
    except: return None
    finally:
        if writer:
            try: writer.close()
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
    async with aiohttp.ClientSession() as session:
        for url in SOURCES:
            try:
                async with session.get(url, timeout=8) as resp:
                    if resp.status == 200:
                        text = await resp.text()
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
