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
            
            text = response.text
            if "<html" in text.lower() or "<!doctype" in text.lower():
                print(f" ⚠️ Источник {url} вернул HTML-страницу ошибки вместо ключей (пропущен)")
                return []

            keys = re.findall(r"(?:vless|hysteria2|hy2|trojan)://[^\s\"'<>]+", text)
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
# 2. ПЕРВИЧНАЯ ПРОВЕРКА (FAST TCP/TLS)
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
# 3. ГЕНЕРАЦИЯ XRAY КОНФИГА И ТЕСТЫ
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
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": {
                "network": network,
                "security": "tls",
                "tlsSettings": {"serverName": sni, "allowInsecure": item['insecure']}
            }
        }
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {"path": qs.get('path', ['/'])[0], "headers": {"Host": qs.get('host', [sni])[0]}}
        elif network == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {"serviceName": qs.get('serviceName', [''])[0]}

        config["outbounds"].append(outbound)

    elif item['proto'] == 'hysteria2':
        password = urllib.parse.unquote(parsed.username or '')
        outbound = {
            "protocol": "hysteria2",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {"serverName": item['sni'], "allowInsecure": item['insecure']}
            }
        }
        config["outbounds"].append(outbound)

    return config

def wait_for_socks_port(port, timeout=1.5):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.03)
    return False

def check_xray_alive(item, local_port):
    config_data = build_xray_config(item, local_port)
    if not config_data:
        return None

    config_filename = f"temp_cfg_{local_port}.json"
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    xray_proc = None
    try:
        xray_proc = subprocess.Popen([XRAY_BIN, "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_for_socks_port(local_port, timeout=1.5):
            return None

        proxies = {"http": f"socks5://127.0.0.1:{local_port}", "https": f"socks5://127.0.0.1:{local_port}"}

        ping_start = time.time()
        # ЖЕСТКИЙ ТАЙМАУТ: 1.8 секунды вместо 3.0
        with requests.get("http://gstatic.com/generate_204", proxies=proxies, timeout=1.8) as ping_res:
            if ping_res.status_code != 204:
                return None
        
        item['http_ping'] = round((time.time() - ping_start) * 1000)
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

def test_xray_speed(item, local_port):
    config_data = build_xray_config(item, local_port)
    if not config_data:
        return None

    config_filename = f"temp_cfg_{local_port}.json"
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    xray_proc = None
    try:
        xray_proc = subprocess.Popen([XRAY_BIN, "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_for_socks_port(local_port, timeout=1.5):
            return None

        proxies = {"http": f"socks5://127.0.0.1:{local_port}", "https": f"socks5://127.0.0.1:{local_port}"}

        # 1. Замер скорости
        speed_url = "https://speed.cloudflare.com/__down?bytes=2097152"
        download_start = time.time()
        
        with requests.get(speed_url, proxies=proxies, stream=True, timeout=5) as speed_res:
            speed_res.raise_for_status()
            downloaded_bytes = 0
            for chunk in speed_res.iter_content(chunk_size=16384):
                if chunk:
                    downloaded_bytes += len(chunk)
                if (time.time() - download_start) > 3.0:
                    break

        elapsed = time.time() - download_start
        mbps = (downloaded_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0.0

        # 2. GeoIP инфо
        with requests.get("http://ip-api.com/json/?fields=country,countryCode,isp,org,query", proxies=proxies, timeout=4) as geo_res:
            geo_data = geo_res.json()
            item['real_ip'] = geo_data.get('query', '')
            item['country'] = geo_data.get('country', 'Unknown')
            item['code'] = geo_data.get('countryCode', '')
            
            org_isp = (geo_data.get('isp', '') + " " + geo_data.get('org', '')).lower()
            cdn_keywords = ['cloudflare', 'fastly', 'akamai', 'cloudfront', 'cdn']
            item['is_cdn'] = any(cdn in org_isp for cdn in cdn_keywords)

        # 3. ТЕСТ TELEGRAM
        try:
            with requests.get("https://api.telegram.org", proxies=proxies, timeout=2.5) as tg_res:
                item['telegram_ok'] = tg_res.status_code in [200, 400, 404]
        except Exception:
            item['telegram_ok'] = False

        # 4. ТЕСТ GOOGLE SEARCH
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            }
            with requests.get("https://www.google.com/search?q=test", proxies=proxies, headers=headers, timeout=3.0) as g_res:
                has_captcha = (
                    "sorry/index" in g_res.url 
                    or "unusual traffic" in g_res.text.lower() 
                    or "recaptcha" in g_res.text.lower()
                )
                item['google_ok'] = (g_res.status_code == 200) and not has_captcha
        except Exception:
            item['google_ok'] = False

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

def build_emoji_tags(proxy_item):
    icons = ""
    if proxy_item.get('telegram_ok'):
        icons += "✈️"
    if proxy_item.get('google_ok'):
        icons += "🔍"
    return f"{icons} " if icons else ""

# ==========================================
# 4. ВАЛИДНАЯ СБОРКА CLASH META
# ==========================================

def generate_clash_config(proxies_list, output_file="clash.yaml"):
    if not proxies_list:
        return

    sorted_proxies = sorted(proxies_list, key=lambda x: x.get('speed', 0), reverse=True)
    clash_proxies = []
    proxy_groups_map = defaultdict(list)
    seen_names = set()

    for i, proxy in enumerate(sorted_proxies, 1):
        flag = get_flag(proxy.get('code', ''))
        country = proxy.get('country', 'Unknown').replace(" ", "_")
        emoji_tags = build_emoji_tags(proxy)
        cdn_suffix = "-CDN" if proxy.get('is_cdn') else ""

        raw_name = f"{flag} #{i} {emoji_tags}{country}{cdn_suffix} {proxy['speed']}Mbps"
        name = raw_name
        dup_counter = 1
        while name in seen_names:
            name = f"{raw_name}_{dup_counter}"
            dup_counter += 1
        seen_names.add(name)

        proto = proxy['proto']
        host = proxy['host']
        port = int(proxy['port'])
        sni = proxy.get('sni') or host
        qs = proxy.get('qs', {})

        p_dict = {
            'name': name,
            'type': proto,
            'server': host,
            'port': port,
            'udp': True,
            'skip-cert-verify': proxy.get('insecure', False)
        }

        if proto == 'vless':
            p_dict['uuid'] = proxy['raw_parsed'].username
            net = qs.get('type', ['tcp'])[0]
            p_dict['network'] = net
            sec = proxy.get('security', 'none')

            if sec in ['tls', 'reality']:
                p_dict['tls'] = True
                p_dict['servername'] = sni
                p_dict['client-fingerprint'] = qs.get('fp', ['chrome'])[0]

                if sec == 'reality':
                    pbk = qs.get('pbk', [''])[0]
                    sid = qs.get('sid', [''])[0]
                    p_dict['reality-opts'] = {'public-key': pbk}
                    if sid:
                        p_dict['reality-opts']['short-id'] = sid

            if net == 'ws':
                p_dict['ws-opts'] = {
                    'path': qs.get('path', ['/'])[0],
                    'headers': {'Host': qs.get('host', [sni])[0]}
                }
            elif net == 'grpc':
                p_dict['grpc-opts'] = {
                    'grpc-service-name': qs.get('serviceName', [''])[0]
                }

        elif proto == 'trojan':
            p_dict['password'] = urllib.parse.unquote(proxy['raw_parsed'].username or '')
            net = qs.get('type', ['tcp'])[0]
            p_dict['network'] = net
            p_dict['sni'] = sni

            if net == 'ws':
                p_dict['ws-opts'] = {
                    'path': qs.get('path', ['/'])[0],
                    'headers': {'Host': qs.get('host', [sni])[0]}
                }
            elif net == 'grpc':
                p_dict['grpc-opts'] = {
                    'grpc-service-name': qs.get('serviceName', [''])[0]
                }

        elif proto == 'hysteria2':
            p_dict['password'] = urllib.parse.unquote(proxy['raw_parsed'].username or '')
            p_dict['sni'] = sni

        else:
            continue

        clash_proxies.append(p_dict)
        proxy_groups_map[country].append(name)

    if not clash_proxies:
        return

    def esc(val):
        return json.dumps(str(val), ensure_ascii=False)

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "",
        "proxies:"
    ]

    for p in clash_proxies:
        lines.append(f"  - name: {esc(p['name'])}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {esc(p['server'])}")
        lines.append(f"    port: {p['port']}")
        lines.append(f"    udp: {'true' if p.get('udp') else 'false'}")
        lines.append(f"    skip-cert-verify: {'true' if p.get('skip-cert-verify') else 'false'}")

        if 'uuid' in p:
            lines.append(f"    uuid: {esc(p['uuid'])}")
        if 'password' in p:
            lines.append(f"    password: {esc(p['password'])}")
        if p.get('tls'):
            lines.append("    tls: true")
        if 'servername' in p:
            lines.append(f"    servername: {esc(p['servername'])}")
        if 'sni' in p:
            lines.append(f"    sni: {esc(p['sni'])}")
        if 'client-fingerprint' in p:
            lines.append(f"    client-fingerprint: {esc(p['client-fingerprint'])}")
        if 'network' in p:
            lines.append(f"    network: {esc(p['network'])}")

        if 'reality-opts' in p:
            lines.append("    reality-opts:")
            lines.append(f"      public-key: {esc(p['reality-opts']['public-key'])}")
            if 'short-id' in p['reality-opts']:
                lines.append(f"      short-id: {esc(p['reality-opts']['short-id'])}")

        if 'ws-opts' in p:
            lines.append("    ws-opts:")
            lines.append(f"      path: {esc(p['ws-opts']['path'])}")
            lines.append("      headers:")
            lines.append(f"        Host: {esc(p['ws-opts']['headers']['Host'])}")

        if 'grpc-opts' in p:
            lines.append("    grpc-opts:")
            lines.append(f"      grpc-service-name: {esc(p['grpc-opts']['grpc-service-name'])}")

    lines.append("")
    lines.append("proxy-groups:")
    all_names = [p['name'] for p in clash_proxies]

    lines.append('  - name: "🚀 PROXY"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "⚡ AUTO"')
    for n in all_names:
        lines.append(f"      - {esc(n)}")

    lines.append('  - name: "⚡ AUTO"')
    lines.append("    type: url-test")
    lines.append('    url: "http://gstatic.com/generate_204"')
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for n in all_names:
        lines.append(f"      - {esc(n)}")

    for country_name, p_names in proxy_groups_map.items():
        if p_names:
            lines.append(f'  - name: {esc("📍 " + country_name)}')
            lines.append("    type: url-test")
            lines.append('    url: "http://gstatic.com/generate_204"')
            lines.append("    interval: 300")
            lines.append("    proxies:")
            for n in p_names:
                lines.append(f"      - {esc(n)}")

    lines.append("")
    lines.append("rules:")
    lines.append("  - DOMAIN-SUFFIX,local,DIRECT")
    lines.append("  - GEOIP,private,DIRECT")
    lines.append("  - MATCH,🚀 PROXY")

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
        print(f"✅ Валидный Clash Meta конфиг сохранен в '{output_file}'")
    except Exception as e:
        print(f"❌ Ошибка записи YAML ({output_file}): {e}")

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

    # ЭТАП 1: Быстрая TCP/TLS проверка
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
            if now - last_log_time >= 10.0 or completed_fast == total_fast:
                percent = round((completed_fast / total_fast) * 100)
                print(f"  📊 [Этап 1] Проверено {completed_fast}/{total_fast} ({percent}%) | Найдено живых TCP: {len(alive_first_proxies)}")
                last_log_time = now

    tcp_alive_hosts = set(f"{p['host']}:{p['port']}" for p in alive_first_proxies if p)
    alive_proxies = []
    for ident in tcp_alive_hosts:
        alive_proxies.extend(host_port_groups[ident])

    print(f"✅ Допущены к Xray-тесту: {len(alive_proxies)} ключей")
    if not alive_proxies:
        return

    # ЭТАП 2: Быстрая проверка 204
    print("\n🚀 ЭТАП 2: Быстрая проверка прокси через Xray (HTTP 204)...")
    alive_xray_proxies = []
    xray_tasks = [(p, 10800 + (i % 5000)) for i, p in enumerate(alive_proxies)]
    total_tasks = len(xray_tasks)
    completed = 0
    last_log_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_xray_alive, arg[0], arg[1]): arg for arg in xray_tasks}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            res = future.result()
            if res:
                alive_xray_proxies.append(res)

            now = time.time()
            if now - last_log_time >= 10.0 or completed == total_tasks:
                percent = round((completed / total_tasks) * 100)
                print(f"  📊 [Этап 2] Проверено {completed}/{total_tasks} ({percent}%) | Рабочих Xray: {len(alive_xray_proxies)}")
                last_log_time = now

    print(f"✅ Успешно ответили на 204 запрос: {len(alive_xray_proxies)} из {total_tasks}")
    if not alive_xray_proxies:
        print("❌ Нет рабочих прокси после Этапа 2.")
        return

    # ЭТАП 3: Скорость, GeoIP, TG и Google
    print(f"\n💨 ЭТАП 3: Замер скорости и проверка сервисов для {len(alive_xray_proxies)} прокси...")
    final_working_proxies = []
    speed_tasks = [(p, 16000 + (i % 5000)) for i, p in enumerate(alive_xray_proxies)]
    total_speed_tasks = len(speed_tasks)
    completed_speed = 0
    last_log_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(test_xray_speed, arg[0], arg[1]): arg for arg in speed_tasks}
        for future in concurrent.futures.as_completed(futures):
            completed_speed += 1
            res = future.result()
            if res:
                final_working_proxies.append(res)

            now = time.time()
            if now - last_log_time >= 10.0 or completed_speed == total_speed_tasks:
                percent = round((completed_speed / total_speed_tasks) * 100)
                print(f"  📊 [Этап 3] Проверено {completed_speed}/{total_speed_tasks} ({percent}%) | Успешно с замером: {len(final_working_proxies)}")
                last_log_time = now

    if not final_working_proxies:
        print("❌ Не удалось получить данные по скорости.")
        return

    # ----------------------------------------------------
    # 6.1. ТОП-100 (ЖЕСТКИЙ СНАЙПЕРСКИЙ ОТБОР)
    # ----------------------------------------------------
    MIN_SPEED_TOP = 5.0  # Было 3.0
    MAX_PING_TOP = 300   # Было 500

    prime_candidates = [
        p for p in final_working_proxies 
        if p.get('speed', 0) >= MIN_SPEED_TOP and p.get('http_ping', 9999) <= MAX_PING_TOP
    ]

    prime_candidates.sort(
        key=lambda x: (x['speed'] * 1000 / max(x['http_ping'], 1)), 
        reverse=True
    )

    top_100_list = []
    seen_servers_top = defaultdict(int)

    for p in prime_candidates:
        server_id = p.get('real_ip') or p.get('host')
        # СТРОГО 1 ключ на один IP
        if seen_servers_top[server_id] < 1:
            top_100_list.append(p)
            seen_servers_top[server_id] += 1
        if len(top_100_list) == 100:
            break

    if top_100_list:
        top_links = []
        for i, p in enumerate(top_100_list, 1):
            flag = get_flag(p.get('code', ''))
            safe_country = p['country'].replace(" ", "_")
            cdn_suffix = "-CDN" if p.get('is_cdn') else ""
            emoji_tags = build_emoji_tags(p)
            
            name = f"🔥{flag} #{i} {emoji_tags}{safe_country}{cdn_suffix} {p['speed']}Mbps"
            base_key = p['key'].split('#')[0]
            top_links.append(f"{base_key}#{urllib.parse.quote(name)}")

        with open("top100.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(top_links))

        encoded_top = base64.b64encode("\n".join(top_links).encode("utf-8")).decode("utf-8")
        with open("top100_sub.txt", "w", encoding="utf-8") as f:
            f.write(encoded_top)

        generate_clash_config(top_100_list, "clash_top100.yaml")
        print(f"\n💎 Отобрано {len(top_100_list)} ЭЛИТНЫХ прокси в 'top100_sub.txt' и 'clash_top100.yaml'")

    # ----------------------------------------------------
    # 6.2. ТОП-500 (УЖЕСТОЧЕННЫЙ ТОП)
    # ----------------------------------------------------
    MIN_SPEED_500 = 3.5  # Было 2.5
    MAX_PING_500 = 450   # Было 700

    candidates_500 = [
        p for p in final_working_proxies 
        if p.get('speed', 0) >= MIN_SPEED_500 and p.get('http_ping', 9999) <= MAX_PING_500
    ]

    candidates_500.sort(
        key=lambda x: (x['speed'] * 1000 / max(x['http_ping'], 1)), 
        reverse=True
    )

    top_500_list = []
    seen_servers_500 = defaultdict(int)

    for p in candidates_500:
        server_id = p.get('real_ip') or p.get('host')
        # Максимум 2 ключа на IP
        if seen_servers_500[server_id] < 2:
            top_500_list.append(p)
            seen_servers_500[server_id] += 1
        if len(top_500_list) == 500:
            break

    if top_500_list:
        top500_links = []
        for i, p in enumerate(top_500_list, 1):
            flag = get_flag(p.get('code', ''))
            safe_country = p['country'].replace(" ", "_")
            cdn_suffix = "-CDN" if p.get('is_cdn') else ""
            emoji_tags = build_emoji_tags(p)
            
            name = f"⚡{flag} #{i} {emoji_tags}{safe_country}{cdn_suffix} {p['speed']}Mbps"
            base_key = p['key'].split('#')[0]
            top500_links.append(f"{base_key}#{urllib.parse.quote(name)}")

        with open("top500.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(top500_links))

        encoded_top500 = base64.b64encode("\n".join(top500_links).encode("utf-8")).decode("utf-8")
        with open("top500_sub.txt", "w", encoding="utf-8") as f:
            f.write(encoded_top500)

        generate_clash_config(top_500_list, "clash_top500.yaml")
        print(f"🚀 Отобрано {len(top_500_list)} прокси в 'top500_sub.txt' и 'clash_top500.yaml'")

    # ----------------------------------------------------
    # 7. ОСНОВНАЯ ЧИСТАЯ БАЗА
    # ----------------------------------------------------
    MIN_SPEED_ALL = 2.5  # Было 2.0
    sorted_all = sorted(final_working_proxies, key=lambda x: x.get('speed', 0), reverse=True)
    
    unique_links = set()
    server_ip_count = defaultdict(int)
    clean_final_proxies = []

    for p in sorted_all:
        if p.get('speed', 0) < MIN_SPEED_ALL:
            continue
            
        clean_url = p['key'].split('#')[0]
        server_id = p.get('real_ip') or p.get('host')
        
        # Максимум 2 ключа на один IP
        if clean_url not in unique_links and server_ip_count[server_id] < 2:
            unique_links.add(clean_url)
            server_ip_count[server_id] += 1
            clean_final_proxies.append(p)

    out_file = "good_proxies.txt"
    grouped = defaultdict(list)
    for p in clean_final_proxies:
        grouped[p['country']].append(p)

    saved_count = 0  
    with open(out_file, "w", encoding="utf-8") as f:
        for country in sorted(grouped.keys()):
            sorted_proxies = sorted(grouped[country], key=lambda x: x['speed'], reverse=True)
            flag = get_flag(grouped[country][0]['code'])
            f.write(f"\n# {flag} {country}\n")

            for proxy in sorted_proxies:
                safe_country = proxy['country'].replace(" ", "_")
                cdn_suffix = "-CDN" if proxy.get('is_cdn') else ""
                emoji_tags = build_emoji_tags(proxy)
                
                new_name = f"{flag} {emoji_tags}{safe_country}{cdn_suffix} {proxy['speed']}Mbps"
                base_key = proxy['key'].split('#')[0]
                renamed_key = f"{base_key}#{urllib.parse.quote(new_name)}"
                
                f.write(f"{renamed_key}\n")
                saved_count += 1

    print(f"📦 Очищенная база ({saved_count} уникальных ключей) сохранена в '{out_file}'")

    try:
        with open(out_file, "r", encoding="utf-8") as f:
            valid_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if valid_links:
            encoded_bytes = base64.b64encode("\n".join(valid_links).encode("utf-8"))
            with open("sub.txt", "w", encoding="utf-8") as f:
                f.write(encoded_bytes.decode("utf-8"))
            print("✅ Полная подписка сохранена в 'sub.txt'")
    except Exception as e:
        print(f"❌ Ошибка при создании подписки: {e}")

    if clean_final_proxies:
        generate_clash_config(clean_final_proxies, "clash.yaml")

if __name__ == "__main__":
    main()
