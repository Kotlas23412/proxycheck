import os
import re
import json
import urllib.parse
import urllib.request
import geoip2.database
from geoip2.errors import AddressNotFoundError

# Папки
CONFIGS_DIR = 'configs'
OUTPUT_DIR = 'proxy'

# Файлы-источники (по приоритету, сначала самые проверенные и быстрые)
INPUT_FILES = [
    'white-list_available_st',
    'ru_st',
    'available_st',
    'white-list_available',
    'ru'
]

MMDB_PATH = os.path.join(CONFIGS_DIR, 'dbip-country-lite.mmdb')

def get_geoip_country(ip):
    if not os.path.exists(MMDB_PATH):
        return None, None
    try:
        with geoip2.database.Reader(MMDB_PATH) as reader:
            response = reader.country(ip)
            iso_code = response.country.iso_code
            if not iso_code: return None, None
            # Конвертация ISO в эмодзи флага
            c1 = chr(ord(iso_code[0].upper()) - ord('A') + 0x1F1E6)
            c2 = chr(ord(iso_code[1].upper()) - ord('A') + 0x1F1E6)
            flag = c1 + c2
            # Перевод базовых стран на русский, для остальных английское название
            names_ru = {
                'RU': 'Россия', 'DE': 'Германия', 'NL': 'Нидерланды', 'FI': 'Финляндия',
                'US': 'США', 'GB': 'Великобритания', 'FR': 'Франция', 'SE': 'Швеция',
                'PL': 'Польша', 'TR': 'Турция', 'HU': 'Венгрия', 'AD': 'Андорра'
            }
            country = names_ru.get(iso_code, response.country.name)
            return flag, country
    except Exception:
        return None, None

def normalize_name(original_name, address, sni, index):
    upper_name = original_name.upper()
    flag = ""
    country_name = ""
    resolved = False

    # 1. Защита от цикла смерти
    is_corrupted = any(bad in upper_name for bad in ["НЕИЗВЕСТНО", "ЛОКАЦИЯ", "GLOBAL"])

    # 2. Ищем флаг и название в оригинальном имени
    if not is_corrupted:
        explicit_regex = r'([\U0001F1E6-\U0001F1FF]{2})\s*([A-Za-zА-Яа-яЁё\-\s]+?)(?:\s*\[|\s*\||\s*#|\s*\*|$)'
        match = re.search(explicit_regex, original_name)
        if match:
            found_flag = match.group(1)
            raw_name = match.group(2).strip()
            if raw_name and "ANYCAST" not in raw_name.upper():
                flag = found_flag
                mapping = {
                    "FRANCE": "Франция", "GERMANY": "Германия", "NORWAY": "Норвегия",
                    "THE NETHERLANDS": "Нидерланды", "NETHERLANDS": "Нидерланды",
                    "RUSSIA": "Россия", "РОССИЯ": "Россия", "UNITED STATES": "США", "USA": "США",
                    "UNITED KINGDOM": "Великобритания", "UK": "Великобритания",
                    "FINLAND": "Финляндия", "SWEDEN": "Швеция", "POLAND": "Польша",
                    "TURKEY": "Турция", "HUNGARY": "Венгрия", "ANDORRA": "Андорра"
                }
                country_name = mapping.get(raw_name.upper(), raw_name)
                resolved = True

    # 3. GeoIP fallback
    if not resolved and address:
        ip_to_detect = address
        # Если это домен, пытаемся резолвить (упрощенно)
        if not re.match(r'^[0-9a-fA-F\.:]+$', ip_to_detect):
            try:
                import socket
                ip_to_detect = socket.gethostbyname(ip_to_detect)
            except Exception:
                pass
        
        f, c = get_geoip_country(ip_to_detect)
        if f and c:
            flag, country_name = f, c
            resolved = True

    # 4. План Б: по SNI
    if not resolved and sni:
        sni_lower = sni.lower()
        if sni_lower.endswith('.ru') or sni_lower.endswith('.su') or sni_lower.endswith('.рф') or 'yandex' in sni_lower or 'vk.com' in sni_lower or 'x5.ru' in sni_lower:
            flag, country_name = "🇷🇺", "Россия"; resolved = True
        elif sni_lower.endswith('.de'): flag, country_name = "🇩🇪", "Германия"; resolved = True
        elif sni_lower.endswith('.nl'): flag, country_name = "🇳🇱", "Нидерланды"; resolved = True
        elif sni_lower.endswith('.fi'): flag, country_name = "🇫🇮", "Финляндия"; resolved = True
        elif sni_lower.endswith('.us'): flag, country_name = "🇺🇸", "США"; resolved = True
        elif sni_lower.endswith('.uk') or sni_lower.endswith('.co.uk'): flag, country_name = "🇬🇧", "Великобритания"; resolved = True
        elif sni_lower.endswith('.fr'): flag, country_name = "🇫🇷", "Франция"; resolved = True
        elif sni_lower.endswith('.se'): flag, country_name = "🇸🇪", "Швеция"; resolved = True

    # 5. Заглушка
    if not resolved or not country_name:
        flag = "🏴"
        country_name = "Неизвестно"

    is_lte = "/" in address or "CIDR" in upper_name or "LTE" in upper_name
    lte_suffix = " | LTE" if is_lte else ""

    return f"{flag} {country_name}{lte_suffix} #{index + 1}"

def parse_vless_to_happ(link, index):
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.lower() not in ['vless', 'vmess']: return None, None
        
        params = dict(urllib.parse.parse_qsl(parsed.query))
        original_name = urllib.parse.unquote(parsed.fragment)
        address = parsed.hostname or ""
        port = parsed.port or 443
        uuid = parsed.username or ""
        sni = params.get('sni', '')

        nice_name = normalize_name(original_name, address, sni, index)
        
        # Собираем новую ссылку (txt)
        new_fragment = urllib.parse.quote(nice_name)
        new_link = link.split('#')[0] + '#' + new_fragment

        # Собираем JSON для Happ
        node = {
            "log": {"loglevel": "warning"},
            "remarks": nice_name,
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                },
                {
                    "port": 10809,
                    "protocol": "http",
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }
            ]
        }

        # Outbounds
        proxy_out = {
            "tag": "proxy",
            "protocol": parsed.scheme.lower(),
            "settings": {},
            "streamSettings": {}
        }

        user = {"id": uuid}
        if proxy_out["protocol"] == "vless":
            user["encryption"] = params.get("encryption", "none")
            if params.get("flow"): user["flow"] = params.get("flow")
        else:
            user["alterId"] = int(params.get("alterId", 0))
            user["security"] = params.get("security", "auto")

        proxy_out["settings"]["vnext"] = [{"address": address, "port": port, "users": [user]}]

        network = params.get("type", "tcp")
        proxy_out["streamSettings"]["network"] = network

        if network == "ws":
            ws_settings = {}
            if "path" in params: ws_settings["path"] = params["path"]
            if "host" in params: ws_settings["headers"] = {"Host": params["host"]}
            proxy_out["streamSettings"]["wsSettings"] = ws_settings
        elif network == "grpc":
            grpc_settings = {}
            if "serviceName" in params: grpc_settings["serviceName"] = params["serviceName"]
            proxy_out["streamSettings"]["grpcSettings"] = grpc_settings

        sec = params.get("security", "")
        if sec in ["tls", "reality"]:
            proxy_out["streamSettings"]["security"] = sec
            sec_obj = {}
            if "sni" in params: sec_obj["serverName"] = params["sni"]
            if "fp" in params: sec_obj["fingerprint"] = params["fp"]
            
            if sec == "reality":
                if "pbk" in params: sec_obj["publicKey"] = params["pbk"]
                if "sid" in params: sec_obj["shortId"] = params["sid"]
                if "spx" in params: sec_obj["spiderX"] = params["spx"]
                proxy_out["streamSettings"]["realitySettings"] = sec_obj
            else:
                proxy_out["streamSettings"]["tlsSettings"] = sec_obj

        node["outbounds"] = [
            proxy_out,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ]

        # Маршрутизация (Жёстко для РФ из Kotlin)
        node["routing"] = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"type": "field", "domain": [
                    "domain:ru", "domain:su", "domain:xn--p1ai",
                    "domain:vk.com", "domain:vk.ru", "domain:userapi.com", "domain:vk-cdn.net",
                    "domain:vkuser.net", "domain:mvk.com",
                    "domain:yandex.ru", "domain:yandex.net", "domain:ya.ru", "domain:kinopoisk.ru",
                    "domain:mail.ru", "domain:ok.ru", "domain:avito.ru", "domain:avito.st",
                    "keyword:yandex", "keyword:vkontakte", "keyword:userapi", "keyword:mail",
                    "keyword:rutube", "keyword:sber", "keyword:tinkoff", "keyword:alfabank",
                    "keyword:vtb", "keyword:gosuslugi"
                ], "outboundTag": "direct"},
                {"type": "field", "ip": [
                    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
                    "127.0.0.0/8", "fc00::/7", "fe80::/10"
                ], "outboundTag": "direct"},
                {"type": "field", "ip": [
                    "87.240.128.0/18", "93.186.224.0/20", "95.213.0.0/18"
                ], "outboundTag": "direct"}
            ]
        }

        return new_link, node
    except Exception as e:
        return None, None

def main():
    top_10_links = []
    seen_addresses = set()

    # Собираем топ-10 vless конфигов
    for file_name in INPUT_FILES:
        path = os.path.join(CONFIGS_DIR, file_name)
        if not os.path.exists(path): continue
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if not (line.startswith('vless://') or line.startswith('vmess://')): continue
                
                # Извлекаем IP/хост для дедупликации
                try:
                    host = urllib.parse.urlsplit(line).hostname
                except:
                    continue
                
                if host not in seen_addresses:
                    seen_addresses.add(host)
                    top_10_links.append(line)
                
                if len(top_10_links) >= 10:
                    break
        if len(top_10_links) >= 10:
            break

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    txt_output = []
    json_output = []

    txt_output.append("# === BEGIN Top 10 Fast & Stable ===")
    
    for i, link in enumerate(top_10_links):
        new_link, happ_node = parse_vless_to_happ(link, i)
        if new_link and happ_node:
            txt_output.append(new_link)
            json_output.append(happ_node)

    txt_output.append("# === END Top 10 Fast & Stable ===")

    # Запись txt
    with open(os.path.join(OUTPUT_DIR, 'top10_proxies.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(txt_output) + '\n')

    # Запись JSON
    with open(os.path.join(OUTPUT_DIR, 'top10_happ.json'), 'w', encoding='utf-8') as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)

    print(f"Успешно сгенерировано {len(json_output)} прокси в папку {OUTPUT_DIR}/")

if __name__ == "__main__":
    main()
