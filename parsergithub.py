import urllib.parse
import socket
import ssl
import time
import requests
import concurrent.futures
from collections import defaultdict
import os
import sys
import re
import json
import subprocess
import base64

LINKS_FILE = "links.txt"
XRAY_BIN = "./xray"

# ==========================================
# 1. ПАРСИНГ И РАБОТА С ССЫЛКАМИ
# ==========================================

def fix_github_url(url):
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

def fetch_keys_from_url(url):
    url = fix_github_url(url)
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        with requests.get(url, headers=headers, timeout=10) as response:
            response.raise_for_status()
            keys = re.findall(r"(?:vless|hysteria2|hy2|trojan)://[^\s\"'<>]+", response.text)
            return keys
    except Exception as e:
        print(f" ❌ Ошибка скачивания {url}: {e}")
        return []

def parse_proxy_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        proto = parsed.scheme.lower()
        
        if proto not in ['vless', 'hysteria2', 'hy2', 'trojan']:
            return None

        host = parsed.hostname
        port = parsed.port or (443 if proto in ['hysteria2', 'hy2', 'trojan'] else 80)
        qs = urllib.parse.parse_qs(parsed.query)

        item = {
            'key': url,
            'proto': 'hysteria2' if proto in ['hysteria2', 'hy2'] else proto,
            'host': host,
            'port': port,
            'sni': qs.get('sni', [host])[0],
            'insecure': qs.get('insecure', ['0'])[0] in ['1', 'true'],
            'raw_parsed': parsed,
            'qs': qs
        }

        if item['proto'] == 'vless':
            item['security'] = qs.get('security', ['none'])[0]
            item['type'] = qs.get('type', ['tcp'])[0]
        elif item['proto'] == 'trojan':
            item['type'] = qs.get('type', ['tcp'])[0]
            item['security'] = 'tls' 

        return item
    except Exception:
        return None

# ==========================================
# 2. ПЕРВИЧНАЯ ПРОВЕРКА (FAST CHECK)
# ==========================================

def verify_proxy(item):
    host, port = item['host'], item['port']
    
    try:
        socket.setdefaulttimeout(2.5) 
        ip = socket.gethostbyname(host)
    except (socket.gaierror, Exception):
        return None

    item['ip'] = ip
    start_time = time.time()

    if item['proto'] == 'hysteria2':
        item['tcp_ping'] = 0
        return item

    security = item.get('security', 'none')
    sni = item.get('sni') or host 

    try:
        with socket.create_connection((ip, port), timeout=2.5) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if security == 'tls':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    pass 

        item['tcp_ping'] = round((time.time() - start_time) * 1000)
        return item

    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError, Exception):
        return None

# ==========================================
# 3. ГЕНЕРАЦИЯ XRAY КОНФИГА И ТЕСТИРОВАНИЕ
# ==========================================

def build_xray_config(item, local_port):
    parsed = item['raw_parsed']
    qs = item['qs']
    host = item['host']
    port = int(item['port'])

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": []
    }

    if item['proto'] == 'vless':
        uuid = parsed.username
        security = qs.get('security', ['none'])[0]
        network = qs.get('type', ['tcp'])[0]
        sni = item['sni']

        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "encryption": "none"}]}]},
            "streamSettings": {"network": network, "security": security}
        }
        stream = outbound["streamSettings"]

        if security == "tls":
            stream["tlsSettings"] = {"serverName": sni, "fingerprint": qs.get('fp', ['chrome'])[0]}
        elif security == "reality":
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": qs.get('fp', ['chrome'])[0],
                "publicKey": qs.get('pbk', [''])[0],
                "shortId": qs.get('sid', [''])[0],
                "spiderX": qs.get('spx', ['/'])[0]
            }

        if network == "ws":
            stream["wsSettings"] = {"path": qs.get('path', ['/'])[0], "headers": {"Host": qs.get('host', [sni])[0]}}
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": qs.get('serviceName', [''])[0]}

        config["outbounds"].append(outbound)

    elif item['proto'] == 'trojan':
        password = urllib.parse.unquote(parsed.username or '')
        network = qs.get('type', ['tcp'])[0]
        sni = item['sni']

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": network,
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "allowInsecure": item['insecure']
                }
            }
        }
        
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": qs.get('path', ['/'])[0],
                "headers": {"Host": qs.get('host', [sni])[0]}
            }
        elif network == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": qs.get('serviceName', [''])[0]
            }

        config["outbounds"].append(outbound)

    elif item['proto'] == 'hysteria2':
        password = urllib.parse.unquote(parsed.username or '')
        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": item['sni'],
                    "allowInsecure": item['insecure']
                }
            }
        }
        config["outbounds"].append(outbound)

    return config

def wait_for_socks_port(port, timeout=2.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False

def test_xray_traffic(item, local_port):
    config_data = build_xray_config(item, local_port)
    if not config_data:
        return None

    config_filename = f"temp_cfg_{local_port}.json"
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    xray_proc = None
    try:
        xray_proc = subprocess.Popen([XRAY_BIN, "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if not wait_for_socks_port(local_port, timeout=2.5):
            return None

        proxies = {
            "http": f"socks5://127.0.0.1:{local_port}",
            "https": f"socks5://127.0.0.1:{local_port}"
        }

        ping_start = time.time()
        with requests.get("http://gstatic.com/generate_204", proxies=proxies, timeout=6) as ping_res:
            if ping_res.status_code != 204:
                return None
        http_ping = round((time.time() - ping_start) * 1000)

        speed_url = "https://speed.cloudflare.com/__down?bytes=2097152"
        download_start = time.time()
        
        with requests.get(speed_url, proxies=proxies, stream=True, timeout=6) as speed_res:
            speed_res.raise_for_status()
            downloaded_bytes = 0
            
            for chunk in speed_res.iter_content(chunk_size=16384):
                if chunk:
                    downloaded_bytes += len(chunk)
                if (time.time() - download_start) > 3.5:
                    break

        elapsed = time.time() - download_start
        mbps = (downloaded_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0.0

        with requests.get("http://ip-api.com/json/?fields=country,countryCode,isp,org,query", proxies=proxies, timeout=5) as geo_res:
            geo_data = geo_res.json()
            item['real_ip'] = geo_data.get('query', '')
            item['country'] = geo_data.get('country', 'Unknown')
            item['code'] = geo_data.get('countryCode', '')
            
            org_isp = (geo_data.get('isp', '') + " " + geo_data.get('org', '')).lower()
            cdn_keywords = ['cloudflare', 'fastly', 'akamai', 'cloudfront', 'cdn']
            item['is_cdn'] = any(cdn in org_isp for cdn in cdn_keywords)

        item['http_ping'] = http_ping
        item['speed'] = round(mbps, 2)
        return item

    except Exception:
        return None
    finally:
        if xray_proc:
            xray_proc.terminate()
            xray_proc.wait()
        if os.path.exists(config_filename):
            try: os.remove(config_filename)
            except OSError: pass

def get_flag(country_code):
    if not country_code or len(country_code) != 2:
        return "🏳️"
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

# ==========================================
# 4. ГЕНЕРАЦИЯ CLASH КОНФИГА
# ==========================================

def generate_clash_config(proxies_list, output_file="clash.yaml"):
    if not proxies_list:
        return
    
    sorted_proxies = sorted(proxies_list, key=lambda x: x['speed'], reverse=True)
    clash_proxies = []
    proxy_groups = defaultdict(list)
    
    for proxy in sorted_proxies:
        if proxy.get('speed', 0) < 1.5:
            continue
            
        name = f"{proxy['proto'].upper()}-{proxy['country']}-{proxy['speed']}Mbps"
        name = re.sub(r'[^a-zA-Z0-9\-_]', '_', name)
        
        if proxy['proto'] == 'vless':
            clash_proxy = {
                'name': name,
                'type': 'vless',
                'server': proxy['host'],
                'port': proxy['port'],
                'uuid': proxy['raw_parsed'].username,
                'network': proxy['qs'].get('type', ['tcp'])[0],
                'tls': proxy.get('security') == 'tls' or proxy.get('security') == 'reality',
                'udp': True,
                'sni': proxy.get('sni'),
                'skip-cert-verify': proxy.get('insecure', False)
            }
            if proxy.get('security') == 'reality':
                clash_proxy['reality-opts'] = {
                    'public-key': proxy['qs'].get('pbk', [''])[0],
                    'short-id': proxy['qs'].get('sid', [''])[0]
                }
                clash_proxy['tls'] = True
            
            if clash_proxy['network'] == 'ws':
                clash_proxy['ws-opts'] = {
                    'path': proxy['qs'].get('path', ['/'])[0],
                    'headers': {'Host': proxy['qs'].get('host', [proxy.get('sni', proxy['host'])])[0]}
                }
            if clash_proxy['network'] == 'grpc':
                clash_proxy['grpc-opts'] = {
                    'grpc-service-name': proxy['qs'].get('serviceName', [''])[0]
                }
                
        elif proxy['proto'] == 'trojan':
            clash_proxy = {
                'name': name,
                'type': 'trojan',
                'server': proxy['host'],
                'port': proxy['port'],
                'password': urllib.parse.unquote(proxy['raw_parsed'].username or ''),
                'network': proxy['qs'].get('type', ['tcp'])[0],
                'udp': True,
                'sni': proxy.get('sni'),
                'skip-cert-verify': proxy.get('insecure', False)
            }
            if clash_proxy['network'] == 'ws':
                clash_proxy['ws-opts'] = {
                    'path': proxy['qs'].get('path', ['/'])[0],
                    'headers': {'Host': proxy['qs'].get('host', [proxy.get('sni', proxy['host'])])[0]}
                }
            if clash_proxy['network'] == 'grpc':
                clash_proxy['grpc-opts'] = {
                    'grpc-service-name': proxy['qs'].get('serviceName', [''])[0]
                }
                
        elif proxy['proto'] == 'hysteria2':
            clash_proxy = {
                'name': name,
                'type': 'hysteria2',
                'server': proxy['host'],
                'port': proxy['port'],
                'password': urllib.parse.unquote(proxy['raw_parsed'].username or ''),
                'udp': True,
                'sni': proxy.get('sni'),
                'skip-cert-verify': proxy.get('insecure', False)
            }
        else:
            continue
            
        clash_proxies.append(clash_proxy)
        proxy_groups[proxy['country']].append(name)
    
    if not clash_proxies:
        return
    
    proxy_group_list = [{
        'name': 'Proxy',
        'type': 'select',
        'proxies': ['DIRECT'] + [p['name'] for p in clash_proxies]
    }]
    
    for country, proxies in proxy_groups.items():
        if proxies:
            proxy_group_list.append({
                'name': country,
                'type': 'url-test',
                'proxies': proxies,
                'url': 'http://gstatic.com/generate_204',
                'interval': 300
            })
    
    try:
        import yaml
        clash_config = {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': False,
            'mode': 'rule',
            'log-level': 'info',
            'proxies': clash_proxies,
            'proxy-groups': proxy_group_list,
            'rules': [
                'DOMAIN-SUFFIX,local,DIRECT',
                'GEOIP,private,DIRECT',
                'GEOIP,CN,DIRECT',
                'MATCH,Proxy'
            ]
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"✅ Clash конфиг сохранен в '{output_file}'")
    except ImportError:
        pass

# ==========================================
# 5. ОСНОВНОЙ ПАЙПЛАЙН
# ==========================================

def main():
    if not os.path.exists(XRAY_BIN):
        print(f"❌ Файл ядра '{XRAY_BIN}' не найден!")
        sys.exit(1)

    os.chmod(XRAY_BIN, 0o755)

    if not os.path.exists(LINKS_FILE):
        print(f"❌ Файл '{LINKS_FILE}' не найден.")
        sys.exit(1)

    with open(LINKS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"📥 Загрузка конфигураций из источников ({len(urls)} шт.)...")
    raw_keys = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for batch in executor.map(fetch_keys_from_url, urls):
            raw_keys.extend(batch)

    raw_keys = list(set(raw_keys))
    if not raw_keys:
        print("❌ Ссылки на прокси не найдены.")
        return

    parsed_items_raw = [p for k in raw_keys if (p := parse_proxy_url(k))]
    
    host_port_groups = defaultdict(list)
    for p in parsed_items_raw:
        ident = f"{p['host']}:{p['port']}"
        host_port_groups[ident].append(p)
            
    parsed_items = [group[0] for group in host_port_groups.values()]
    print(f"🔍 Собрано уникальных ключей: {len(parsed_items_raw)}. Серверов: {len(parsed_items)}")

    print("\n⚡ ЭТАП 1: Предварительная фильтрация серверов (TCP/TLS)...")
    alive_first_proxies = []
    total_fast = len(parsed_items)
    completed_fast = 0
    last_log_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(verify_proxy, item): item for item in parsed_items}
        for future in concurrent.futures.as_completed(futures):
            completed_fast += 1
            res = future.result()
            if res:
                alive_first_proxies.append(res)
            
            now = time.time()
            if now - last_log_time >= 5.0 or completed_fast == total_fast:
                percent = round((completed_fast / total_fast) * 100)
                print(f"  📊 [Этап 1] Проверено {completed_fast}/{total_fast} ({percent}%) | Найдено живых TCP: {len(alive_first_proxies)}")
                last_log_time = now

    tcp_alive_hosts = set(f"{p['host']}:{p['port']}" for p in alive_first_proxies if p)
    alive_proxies = []
    for ident in tcp_alive_hosts:
        alive_proxies.extend(host_port_groups[ident])

    print(f"✅ Допущены к глубокому тестированию: {len(alive_proxies)} ключей")
    if not alive_proxies:
        return

    print("\n🚀 ЭТАП 2: Полное тестирование скорости и стран через Xray...")
    final_working_proxies = []
    xray_tasks = [(p, 10800 + (i % 5000)) for i, p in enumerate(alive_proxies)]
    total_tasks = len(xray_tasks)
    completed = 0
    last_log_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(test_xray_traffic, arg[0], arg[1]): arg for arg in xray_tasks}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            res = future.result()
            if res:
                final_working_proxies.append(res)

            now = time.time()
            if now - last_log_time >= 5.0 or completed == total_tasks:
                percent = round((completed / total_tasks) * 100)
                print(f"  📊 [Этап 2] Проверено {completed}/{total_tasks} ({percent}%) | Рабочих прокси: {len(final_working_proxies)}")
                last_log_time = now

    if not final_working_proxies:
        print("❌ Нет рабочих прокси после глубокого тестирования.")
        return

    # СОХРАНЕНИЕ И АВТОМАТИЧЕСКАЯ ГЕНЕРАЦИЯ
    grouped = defaultdict(list)
    for p in final_working_proxies:
        grouped[p['country']].append(p)

    out_file = "good_proxies.txt"
    MIN_SPEED = 2.5  
    saved_count = 0  

    with open(out_file, "w", encoding="utf-8") as f:
        for country in sorted(grouped.keys()):
            sorted_proxies = sorted(grouped[country], key=lambda x: x['speed'], reverse=True)
            if not any(p.get('speed', 0) >= MIN_SPEED for p in sorted_proxies):
                continue

            flag = get_flag(grouped[country][0]['code'])
            f.write(f"\n# {flag} {country}\n")

            for proxy in sorted_proxies:
                if proxy.get('speed', 0) < MIN_SPEED:
                    continue

                safe_country = proxy['country'].replace(" ", "_")
                cdn_suffix = "-CDN" if proxy.get('is_cdn') else ""
                new_name = f"{flag}_{proxy['proto'].upper()}_{safe_country}{cdn_suffix}-{proxy['http_ping']}ms-{proxy['speed']}Mbps"
                base_key = proxy['key'].split('#')[0]
                renamed_key = f"{base_key}#{urllib.parse.quote(new_name)}"
                
                f.write(f"{renamed_key}\n")
                saved_count += 1

    print(f"\n💾 Успешно сохранено {saved_count} прокси (>= {MIN_SPEED} Мбит/с) в '{out_file}'")

    # Автоматическая подписка
    try:
        with open(out_file, "r", encoding="utf-8") as f:
            valid_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if valid_links:
            encoded_bytes = base64.b64encode("\n".join(valid_links).encode("utf-8"))
            with open("sub.txt", "w", encoding="utf-8") as f:
                f.write(encoded_bytes.decode("utf-8"))
            print("✅ Подписка автоматически сохранена в 'sub.txt'")
    except Exception as e:
        print(f"❌ Ошибка при создании подписки: {e}")

    # Автоматический Clash
    clash_proxies = [p for p in final_working_proxies if p.get('speed', 0) >= MIN_SPEED]
    if clash_proxies:
        generate_clash_config(clash_proxies, "clash.yaml")

if __name__ == "__main__":
    main()
