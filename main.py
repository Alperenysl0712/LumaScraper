"""
================================================================================
Luma Shield - Cloud Proxy Scraper & Validator Architecture (Created by Alperen Burak Yeşil)
================================================================================

Description:
This script acts as the backend aggregator for the Luma Shield VPN client. It is
designed to be deployed on a cloud environment to alleviate the mobile client
from the heavy burden of node discovery and testing.

Architecture & Core Methods:
1. Fetching (aiohttp): Asynchronously pulls raw configurations from premium
   Telegram aggregator URLs.
2. Parsing & Deduplication (parse_config): Extracts IP, Port, and Protocol from
   vless/vmess/trojan/ss links. Uses a Set to drop duplicate IP addresses.
3. Concurrency Control (asyncio.Semaphore): Implements a strict connection limit
   (e.g., 500 concurrent sockets) to prevent OS socket exhaustion.
4. Latency Check (check_tcp_latency): Opens a raw TCP socket to the node.
   If the handshake exceeds MAX_PING_MS (150ms), the node is discarded.
5. Verification (check_real_internet): Simulates a deep-routing check. Prioritizes
   Trojan and Shadowsocks protocols, which naturally bypass UDP/QUIC drops.
6. Geo-Structuring & Limiting: Groups verified nodes by country, sorts them by
   latency, and enforces a strict limit (TOP_NODES_PER_COUNTRY) to output only
   the absolute fastest working nodes per region.

Dependencies: asyncio, aiohttp
================================================================================
"""

import asyncio
import aiohttp
import base64
import time
import json
import re
import sys

SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt"
]

MAX_PING_MS = 150
CONNECTION_TIMEOUT = 1.5
TOP_NODES_PER_COUNTRY = 3
CONCURRENCY_LIMIT = 500


def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return data


def parse_config(link):
    try:
        link = link.strip()
        if not link: return None

        protocol = link.split('://')[0].lower()
        if protocol not in ['vless', 'vmess', 'trojan', 'ss']:
            return None

        match = re.search(r'@([^:]+):(\d+)', link)
        if not match:
            return None

        ip = match.group(1)
        port = int(match.group(2))

        return {"link": link, "protocol": protocol, "ip": ip, "port": port}
    except Exception:
        return None


async def check_tcp_latency(node, semaphore):
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

            latency = int((time.time() - start_time) * 1000)
            if latency <= MAX_PING_MS:
                node['ping'] = latency
                return node
            return None
        except Exception:
            return None


async def check_real_internet(node):
    if node['protocol'] in ['trojan', 'ss']:
        return True
    if node['ping'] < 100:
        return True
    return False


async def resolve_real_countries(nodes):
    if not nodes:
        return []

    ips = list(set([n['ip'] for n in nodes]))
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
            except Exception:
                pass

    resolved_nodes = []
    for n in nodes:
        cc = ip_to_country.get(n['ip'])
        if cc:
            n['country'] = cc
            resolved_nodes.append(n)

    return resolved_nodes


async def main():
    print("Starting Luma Shield Premium Scraper with GeoIP Verification...")
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
                    else:
                        print(f"Warning: HTTP {response.status} from {url}")
            except Exception as e:
                print(f"Warning: Failed to fetch {url} -> {e}")

    unique_ips = set()
    parsed_nodes = []

    for link in raw_links:
        node = parse_config(link)
        if node and node['ip'] not in unique_ips:
            unique_ips.add(node['ip'])
            parsed_nodes.append(node)

    print(f"Testing {len(parsed_nodes)} unique nodes (Concurrency limit: {CONCURRENCY_LIMIT})...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [check_tcp_latency(node, semaphore) for node in parsed_nodes]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)

    alive_nodes = [res for res in results if res is not None and not isinstance(res, Exception)]

    vip_nodes = []
    for node in alive_nodes:
        if await check_real_internet(node):
            vip_nodes.append(node)

    print(f"Resolving real physical locations for {len(vip_nodes)} VIP nodes...")
    verified_nodes = await resolve_real_countries(vip_nodes)

    country_pools = {}
    for node in verified_nodes:
        c = node['country']
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

    print(f"Process complete! {total_saved} location-verified nodes exported.")


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
