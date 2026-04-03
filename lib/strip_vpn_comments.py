#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Убирает комментарии (фрагмент после #) в VPN-конфигах построчно и добавляет новый:
  # <флаг_страны>[ | LTE] <AUTO_COMMENT>
Страна определяется по IP хоста прокси (локальный MMDB -> fallback ip-api.com).
Пометка "| LTE" добавляется, если IP endpoint попадает в подсети из cidrlist.
AUTO_COMMENT задаётся переменной окружения (см. .env и workflow).
"""

import argparse
import ipaddress
import os
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Загружаем .env при локальном запуске
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Парсинг ссылки для извлечения хоста (address)
try:
    from lib.parsing import parse_proxy_url
except ImportError:
    parse_proxy_url = None

GEO_API = "http://ip-api.com/json/{ip}?fields=countryCode"
GEO_TIMEOUT = 3
GEO_DELAY = 0.2  # пауза перед запросом в каждом потоке (лимит ip-api.com ~45/мин без ключа)
# Потоки: DNS можно поднять до 24-32; geo - не выше 10-12, иначе легко 429 от ip-api
DNS_MAX_WORKERS = 32
GEO_MAX_WORKERS = 10

DEFAULT_AUTO_COMMENT = " verified · XRayCheck"

# Быстрый режим: не делать DNS/HTTP-запросы, использовать фиксированный или глобальный флаг.
STRIP_FAST = (os.environ.get("STRIP_VPN_COMMENTS_FAST") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
# Код страны по умолчанию для быстрого режима (например, RU), пусто = глобус.
STRIP_CC_DEFAULT = (os.environ.get("STRIP_VPN_COMMENTS_CC") or "").strip().upper()
STRIP_GEO_MMDB = (
    (os.environ.get("GEOIP_MMDB") or "").strip()
    or (os.environ.get("STRIP_VPN_COMMENTS_GEO_MMDB") or "").strip()
    or os.path.join("configs", "dbip-country-lite.mmdb")
)
STRIP_CIDR_FILE = (os.environ.get("STRIP_VPN_COMMENTS_CIDR_FILE") or "").strip() or "cidrlist"
STRIP_ADD_LTE_MARK = (os.environ.get("STRIP_VPN_COMMENTS_LTE_MARK") or "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def get_auto_comment() -> str:
    """Текст комментария из переменной окружения AUTO_COMMENT."""
    return os.environ.get("AUTO_COMMENT", DEFAULT_AUTO_COMMENT).strip() or DEFAULT_AUTO_COMMENT


def strip_comment_from_line(line: str) -> str:
    """Убирает из строки фрагмент (комментарий) после первого '#'."""
    line = line.strip()
    if not line or line.startswith("#"):
        return line
    return line.split("#", 1)[0].strip()


def country_code_to_flag(cc: str) -> str:
    """Двухбуквенный код страны (ISO 3166-1 alpha-2) -> эмодзи флаг (региональные индикаторы)."""
    if not cc or len(cc) != 2:
        return "\U0001f310"  # globe
    a = 0x1F1E6  # regional indicator A
    return "".join(chr(a + ord(c) - ord("A")) for c in cc.upper() if "A" <= c <= "Z")


def get_host_from_link(link: str) -> str | None:
    """Извлекает хост (address) из прокси-ссылки."""
    if parse_proxy_url:
        parsed = parse_proxy_url(link)
        if parsed and isinstance(parsed.get("address"), str):
            return parsed["address"].strip()
    # Fallback: ищем @host:port в типичных схемах
    for prefix in ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://", "hysteria://"):
        if link.startswith(prefix):
            rest = link[len(prefix) :].strip()
            if "?" in rest:
                rest = rest.split("?")[0]
            if "@" in rest:
                _, host_port = rest.rsplit("@", 1)
                if ":" in host_port:
                    return host_port.rpartition(":")[0].strip()
                return host_port.strip()
            if "://" in rest:
                return rest.split("/")[0].strip()
            break
    return None


def resolve_to_ip(host: str) -> str | None:
    """Возвращает IP для хоста или None при ошибке."""
    if not host:
        return None
    if host.replace(".", "").isdigit():
        return host
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def fetch_country_for_ip(ip: str, cache: dict) -> str:
    """Получает countryCode для IP через ip-api.com; использует cache."""
    if ip in cache:
        return cache[ip]
    time.sleep(GEO_DELAY)
    try:
        req = urllib.request.Request(GEO_API.format(ip=ip), headers={"User-Agent": "XRayCheck/1.0"})
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as r:
            import json
            data = json.loads(r.read().decode())
            cc = data.get("countryCode") or ""
            cache[ip] = cc
            return cc
    except Exception:
        cache[ip] = ""
        return ""


def _load_cidr_networks(path: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if not path or not os.path.isfile(path):
        return nets
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    return nets


def _ip_in_cidr(ip_text: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not ip_text or not networks:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(ip_obj in net for net in networks)


def _cc_from_mmdb(ip: str, mmdb_path: str, mmdb_cache: dict[str, str], reader_holder: dict) -> str:
    if not ip or not mmdb_path or not os.path.isfile(mmdb_path):
        return ""
    if ip in mmdb_cache:
        return mmdb_cache[ip]

    reader = reader_holder.get("reader")
    if reader is None:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(mmdb_path)
            reader_holder["reader"] = reader
        except Exception:
            mmdb_cache[ip] = ""
            return ""
    try:
        rec = reader.country(ip)
        cc = (rec.country.iso_code or "").strip().upper()
        mmdb_cache[ip] = cc
        return cc
    except Exception:
        mmdb_cache[ip] = ""
        return ""


def process_file(
    input_path: str,
    output_path: str | None,
    add_comment: bool = True,
) -> int:
    """Читает файл, убирает комментарии, опционально добавляет новый с флагом страны, пишет результат."""
    path = Path(input_path)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 0
    out = Path(output_path) if output_path else path.parent / (path.stem + "_new" + path.suffix)
    lines_in = path.read_text(encoding="utf-8").splitlines()

    # Предварительно разбираем строки в чистые ссылки и хосты
    links: list[str] = []
    hosts: list[str | None] = []
    for line in lines_in:
        link = strip_comment_from_line(line)
        if not link:
            continue
        links.append(link)
        hosts.append(get_host_from_link(link) if add_comment and not STRIP_FAST else None)

    geo_cache: dict[str, str] = {}
    mmdb_cache: dict[str, str] = {}
    reader_holder: dict[str, object] = {}
    host_to_ip: dict[str, str] = {}
    cidr_networks = _load_cidr_networks(STRIP_CIDR_FILE) if add_comment else []

    if add_comment and not STRIP_FAST:
        # 1) Разрешаем все уникальные хосты в IP параллельно
        unique_hosts = sorted({h for h in hosts if h})

        def _resolve_host(h: str) -> None:
            ip = resolve_to_ip(h) or ""
            host_to_ip[h] = ip

        if unique_hosts:
            with ThreadPoolExecutor(max_workers=min(DNS_MAX_WORKERS, len(unique_hosts))) as executor:
                list(executor.map(_resolve_host, unique_hosts))

        # 2) Для всех уникальных IP получаем countryCode (с кэшем) тоже параллельно
        unique_ips = sorted({ip for ip in host_to_ip.values() if ip})

        def _fetch_cc(ip: str) -> None:
            fetch_country_for_ip(ip, geo_cache)

        if unique_ips:
            with ThreadPoolExecutor(max_workers=min(GEO_MAX_WORKERS, len(unique_ips))) as executor:
                list(executor.map(_fetch_cc, unique_ips))

    # 3) Собираем итоговые строки
    result: list[str] = []
    for link, host in zip(links, hosts):
        if add_comment:
            if STRIP_FAST:
                cc = STRIP_CC_DEFAULT or ""
                is_lte = False
            else:
                ip = host_to_ip.get(host, "") if host else ""
                # Максимально точное определение страны: сначала локальный MMDB, затем ip-api.
                cc = _cc_from_mmdb(ip, STRIP_GEO_MMDB, mmdb_cache, reader_holder) or geo_cache.get(ip, "")
                if not cc and ip:
                    cc = fetch_country_for_ip(ip, geo_cache)
                is_lte = _ip_in_cidr(ip, cidr_networks)
            flag = country_code_to_flag(cc)
            lte_mark = " | LTE" if (STRIP_ADD_LTE_MARK and is_lte) else ""
            link = f"{link}#{flag}{lte_mark} {get_auto_comment().strip()}"
        result.append(link)
    reader = reader_holder.get("reader")
    if reader is not None:
        try:
            reader.close()
        except Exception:
            pass
    out.write_text("\n".join(result) + ("\n" if result else ""), encoding="utf-8")
    print(f"Processed: {len(lines_in)} lines -> {len(result)} with new comment. Output: {out}")
    return len(result)


def main():
    parser = argparse.ArgumentParser(
        description="Strip comments from VPN configs and add: # <flag> verified · XRayCheck"
    )
    parser.add_argument("input", help="Input file (one link per line)")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: <name>_new.<ext>)")
    parser.add_argument("--no-comment", action="store_true", help="Only strip comments, do not add new one")
    args = parser.parse_args()
    n = process_file(args.input, args.output, add_comment=not args.no_comment)
    sys.exit(0 if n > 0 else 1)


if __name__ == "__main__":
    main()
