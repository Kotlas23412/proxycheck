#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль проверки прокси-ключей - основная логика проверки.
Поддерживает протоколы: VLESS, VMess, Trojan, Shadowsocks, Hysteria, Hysteria2.
"""

import json
import logging
import os
import socket
import subprocess
import tempfile
import time
import threading
import requests  # Добавлен импорт requests для точной проверки
from dataclasses import dataclass
from typing import Optional, Tuple

from .cache import check_cache, get_key_hash
from .config import (
    ALLOWED_COUNTRIES,
    CHECK_GEOLOCATION,
    CONNECT_TIMEOUT,
    CONNECT_TIMEOUT_SLOW,
    ENABLE_CACHE,
    MAX_RESPONSE_TIME,
    MAX_RETRIES,
    MIN_AVG_RESPONSE_TIME,
    MIN_RESPONSE_SIZE,
    MIN_SUCCESSFUL_REQUESTS,
    MIN_SUCCESSFUL_URLS,
    REQUEST_DELAY,
    REQUESTS_PER_URL,
    REQUIRE_HTTPS,
    RETRY_DELAY_BASE,
    RETRY_DELAY_MULTIPLIER,
    STABILITY_CHECK_DELAY,
    STABILITY_CHECKS,
    STRICT_MODE,
    STRICT_MODE_REQUIRE_ALL,
    STRONG_ATTEMPTS,
    STRONG_STYLE_CONNECT_T_MIN,
    STRONG_MAX_RESPONSE_TIME,
    STRONG_STYLE_READ_T_MIN,
    STRONG_STYLE_TEST,
    STRONG_STYLE_TIMEOUT,
    XRAY_CHECKER_MAX_CONCURRENCY,
    TEST_POST_REQUESTS,
    TEST_URL,
    TEST_URLS,
    TEST_URLS_HTTPS,
    USE_ADAPTIVE_TIMEOUT,
    XRAY_REUSE_WORKER,
    XRAY_STARTUP_POLL_INTERVAL,
    XRAY_STARTUP_WAIT,
    XRAY_PORT_WAIT,
    _CLIENT_TEST_HTTPS,
)
from .logger_config import should_debug as should_debug_func

logger = logging.getLogger(__name__)
from .parsing import parse_proxy_url, parse_vless_url
from .port_pool import return_port, take_port

from .signals import register_process, unregister_process
from .utils import (
    check_geolocation_allowed,
    check_response_valid,
    get_geolocation,
    is_connection_error,
    make_request,
)
from .xray_manager import build_xray_config, kill_xray_process, reload_xray_config, run_xray

_xray_checker_semaphore = threading.Semaphore(max(1, int(XRAY_CHECKER_MAX_CONCURRENCY)))

_tls_xray_worker = threading.local()


@dataclass
class _XrayThreadWorker:
    """Один выделенный порт и процесс xray на поток исполнителя (амортизация cold start)."""
    port: Optional[int] = None
    config_path: Optional[str] = None
    proc: Optional[subprocess.Popen] = None


def _get_xray_thread_worker() -> _XrayThreadWorker:
    if not hasattr(_tls_xray_worker, "w"):
        _tls_xray_worker.w = _XrayThreadWorker()
    return _tls_xray_worker.w


def _wait_for_port(host: str, port: int, max_wait: float, poll_interval: float = 0.1) -> bool:
    """Ждёт, пока SOCKS-порт на localhost начнёт принимать соединения."""
    deadline = time.perf_counter() + max_wait
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (socket.error, socket.gaierror, OSError):
            time.sleep(poll_interval)
    return False


def _check_hysteria_reachable(address: str, port: int, timeout: float) -> tuple[bool, float]:
    """
    Проверка доступности сервера Hysteria/Hysteria2 по TCP (порт открыт).
    """
    try:
        start_time = time.perf_counter()
        with socket.create_connection((address, port), timeout=timeout):
            elapsed = time.perf_counter() - start_time
            return (True, elapsed)
    except (socket.error, socket.gaierror, OSError):
        return (False, timeout)


def exact_url_test(port: int, url: str, timeout: float = 10.0) -> Tuple[bool, float, Optional[str]]:
    """
    Точный аналог Libcore.urlTest из Android (NekoBox/Matsuri). 
    Использует socks5h (DNS через прокси) и замеряет чистый пинг.
    """
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }

    # ============ ДИАГНОСТИКА: ПРОВЕРЯЕМ IP (ТОЛЬКО ОДИН РАЗ) ============
    import os
    if os.environ.get("DEBUG_PROXY_IP") == "true":
        try:
            ip_check = requests.get("https://ifconfig.me", proxies=proxies, timeout=5)
            detected_ip = ip_check.text.strip()
            console.print(f"[yellow]DEBUG: Трафик через Xray выходит с IP:[/yellow] {detected_ip}")
        except Exception as e:
            console.print(f"[red]DEBUG: Не удалось определить выходной IP:[/red] {e}")
    
    start_time = time.perf_counter()
    try:
        # allow_redirects=False для скорости. verify=True обязательно для защиты от подмены DPI!
        r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False, verify=True)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # 301/302 редирект (например, Инстаграм на страницу логина) считается успехом
        if 200 <= r.status_code < 400:
            return True, elapsed_ms, None
        else:
            return False, elapsed_ms, f"Bad HTTP status: {r.status_code}"
            
    except requests.exceptions.Timeout:
        return False, timeout * 1000, "Timeout"
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return False, elapsed_ms, f"Connection error: {str(e)}"


def check_key_e2e(vless_line: str, debug: bool = False, cache: Optional[dict] = None) -> tuple[str, bool, Optional[dict]]:
    """
    End-to-end проверка с расширенными возможностями.
    """
    should_debug_flag = should_debug_func(debug)
    
    # Проверка кэша
    if cache is not None and ENABLE_CACHE:
        key_hash = get_key_hash(vless_line)
        cached_result = check_cache(key_hash, cache)
        if cached_result is not None:
            if should_debug_flag:
                logger.debug(f"Результат из кэша для ключа: {key_hash[:8]}...")
            metrics = {
                "response_times": [],
                "geolocation": None,
                "successful_urls": 0,
                "failed_urls": 0,
                "total_requests": 0,
                "successful_requests": 0,
                "cached": True,
                "transient_failure": False,
                "transient_exhausted": False,
                "failure_type": None,
            }
            return (vless_line, cached_result, metrics)
    
    metrics = {
        "response_times": [],
        "geolocation": None,
        "successful_urls": 0,
        "failed_urls": 0,
        "total_requests": 0,
        "successful_requests": 0,
        "cached": False,
        "transient_failure": False,
        "transient_exhausted": False,
        "failure_type": None,
    }
    
    parsed = parse_proxy_url(vless_line)
    if not parsed:
        metrics["failure_type"] = "PARSE_ERROR"
        if should_debug_flag:
            logger.debug("Не удалось разобрать прокси-ссылку.")
        return (vless_line, False, metrics)

    # Hysteria
    if parsed.get("protocol") in ("hysteria", "hysteria2"):
        timeout = CONNECT_TIMEOUT_SLOW if USE_ADAPTIVE_TIMEOUT else CONNECT_TIMEOUT
        ok, latency = _check_hysteria_reachable(parsed["address"], parsed["port"], float(timeout))
        if ok:
            metrics["response_times"] = [latency]
        else:
            metrics["failure_type"] = "TIMEOUT_REQUEST_ERROR"
        if cache is not None and ENABLE_CACHE:
            key_hash = get_key_hash(vless_line)
            cache[key_hash] = {"result": ok, "timestamp": time.time()}
        metrics["successful_urls"] = 1 if ok else 0
        metrics["failed_urls"] = 0 if ok else 1
        return (vless_line, ok, metrics)

    semaphore_acquired = False
    _xray_checker_semaphore.acquire()
    semaphore_acquired = True

    tw = _get_xray_thread_worker()
    proc: Optional[subprocess.Popen] = None
    config_path: Optional[str] = None
    _preserve_xray_process = False

    if XRAY_REUSE_WORKER:
        if tw.port is None:
            tw.port = take_port()
        if tw.port is None:
            metrics["transient_failure"] = True
            metrics["failure_type"] = "NO_FREE_PORT"
            if semaphore_acquired:
                _xray_checker_semaphore.release()
            return (vless_line, False, metrics)
        port = tw.port
    else:
        port = take_port()
        if port is None:
            metrics["transient_failure"] = True
            metrics["failure_type"] = "NO_FREE_PORT"
            if semaphore_acquired:
                _xray_checker_semaphore.release()
            return (vless_line, False, metrics)

    try:
        config = build_xray_config(parsed, port)
    except Exception as e:
        metrics["failure_type"] = "BUILD_CONFIG_ERROR"
        if semaphore_acquired:
            _xray_checker_semaphore.release()
        return (vless_line, False, metrics)

    if XRAY_REUSE_WORKER:
        if tw.config_path is None:
            try:
                fd, tw.config_path = tempfile.mkstemp(suffix=".json", prefix="xray_tw_")
                os.close(fd)
            except OSError:
                metrics["failure_type"] = "BUILD_CONFIG_ERROR"
                if semaphore_acquired:
                    _xray_checker_semaphore.release()
                return (vless_line, False, metrics)
        config_path = tw.config_path
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False)
        except Exception:
            metrics["failure_type"] = "BUILD_CONFIG_ERROR"
            if semaphore_acquired:
                _xray_checker_semaphore.release()
            return (vless_line, False, metrics)
    else:
        try:
            fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        except OSError:
            metrics["failure_type"] = "BUILD_CONFIG_ERROR"
            if semaphore_acquired:
                _xray_checker_semaphore.release()
            return_port(port)
            return (vless_line, False, metrics)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            return_port(port)
            metrics["failure_type"] = "BUILD_CONFIG_ERROR"
            if semaphore_acquired:
                _xray_checker_semaphore.release()
            return (vless_line, False, metrics)

    try:
        started_via_reload = False
        if (
            XRAY_REUSE_WORKER
            and tw.proc is not None
            and tw.proc.poll() is None
            and reload_xray_config(tw.proc)
            and _wait_for_port("127.0.0.1", port, XRAY_PORT_WAIT, XRAY_STARTUP_POLL_INTERVAL)
        ):
            proc = tw.proc
            started_via_reload = True
            
        if not started_via_reload:
            if XRAY_REUSE_WORKER and tw.proc is not None:
                unregister_process(tw.proc, port)
                kill_xray_process(tw.proc, drain_stderr=True)
                tw.proc = None
            proc = run_xray(config_path, stderr_pipe=should_debug_flag)
            if XRAY_REUSE_WORKER:
                tw.proc = proc
            register_process(proc, port)
            
            waited = 0.0
            while waited < XRAY_STARTUP_WAIT:
                if proc.poll() is not None:
                    break
                time.sleep(XRAY_STARTUP_POLL_INTERVAL)
                waited += XRAY_STARTUP_POLL_INTERVAL
                
            if proc.poll() is not None:
                unregister_process(proc, port)
                metrics["transient_failure"] = True
                metrics["failure_type"] = "XRAY_STARTUP_EARLY_EXIT"
                if XRAY_REUSE_WORKER:
                    tw.proc = None
                return (vless_line, False, metrics)

            if not _wait_for_port("127.0.0.1", port, XRAY_PORT_WAIT, XRAY_STARTUP_POLL_INTERVAL):
                unregister_process(proc, port)
                metrics["transient_failure"] = True
                metrics["failure_type"] = "SOCKS_PORT_TIMEOUT"
                if XRAY_REUSE_WORKER:
                    tw.proc = None
                return (vless_line, False, metrics)

        # =====================================================================
        # НОВАЯ ANDROID-ПОДОБНАЯ E2E ПРОВЕРКА ЧЕРЕЗ TAILSCALE
        # =====================================================================

        # 1. МАГИЯ ИЗ ANDROID: ждем 500мс после открытия порта.
        time.sleep(0.5)

        # 2. БЫСТРЫЙ ТЕСТ (Проверка живости сервера, timeout 10s)
        metrics["total_requests"] = 1
        is_alive, ping_ms, err = exact_url_test(port, "https://cp.cloudflare.com/generate_204", timeout=10.0)
        
        if not is_alive:
            metrics["failure_type"] = "DEAD_PROXY_OR_TIMEOUT"
            metrics["failed_urls"] = 1
            if should_debug_flag:
                logger.debug(f"Прокси мертв или недоступен: {err}")
            unregister_process(proc, port)
            return (vless_line, False, metrics)

        metrics["successful_requests"] = 1
        metrics["total_requests"] = 2
        
        # 3. ТЕСТ НА ПРОБИВАНИЕ ТСПУ (Tailscale -> Телефон -> Прокси -> Инстаграм)
        is_bypassing, bypass_ping, dpi_err = exact_url_test(port, "https://www.instagram.com/", timeout=15.0)

        if not is_bypassing:
            metrics["failure_type"] = "BLOCKED_BY_DPI_RU"
            metrics["failed_urls"] = 1
            metrics["successful_urls"] = 1
            if should_debug_flag:
                logger.debug(f"Жив, но ЗАБЛОКИРОВАН В РФ (DPI): {dpi_err}")
            unregister_process(proc, port)
            return (vless_line, False, metrics)

        # 4. Проверка геолокации (если нужно по конфигу)
        if CHECK_GEOLOCATION:
            proxies_geo = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
            geolocation = get_geolocation(proxies_geo)
            if geolocation:
                metrics["geolocation"] = geolocation
                if not check_geolocation_allowed(geolocation, ALLOWED_COUNTRIES):
                    metrics["failure_type"] = "GEO_NOT_ALLOWED"
                    unregister_process(proc, port)
                    return (vless_line, False, metrics)

        # ЕСЛИ ДОШЛИ СЮДА - ПРОКСИ ИДЕАЛЬНЫЙ
        metrics["successful_urls"] = 2
        metrics["successful_requests"] = 2
        metrics["failed_urls"] = 0
        metrics["response_times"] = [ping_ms / 1000.0, bypass_ping / 1000.0]
        metrics["avg_response_time"] = (ping_ms + bypass_ping) / 2000.0
        
        # Сохранение в кэш
        if cache is not None and ENABLE_CACHE:
            key_hash = get_key_hash(vless_line)
            cache[key_hash] = {'result': True, 'timestamp': time.time()}

        if XRAY_REUSE_WORKER:
            _preserve_xray_process = True
        else:
            unregister_process(proc, port)
            
        return (vless_line, True, metrics)

    except FileNotFoundError:
        metrics["failure_type"] = "START_XRAY_NOT_FOUND"
        _ep = proc or (tw.proc if XRAY_REUSE_WORKER else None)
        if _ep:
            unregister_process(_ep, port)
        return (vless_line, False, metrics)
    except Exception as e:
        metrics["failure_type"] = "EXCEPTION"
        _ep = proc or (tw.proc if XRAY_REUSE_WORKER else None)
        if _ep:
            unregister_process(_ep, port)
        return (vless_line, False, metrics)
    finally:
        _keep_alive = (
            XRAY_REUSE_WORKER
            and _preserve_xray_process
            and tw.proc is not None
            and tw.proc.poll() is None
        )
        if _keep_alive:
            if semaphore_acquired:
                _xray_checker_semaphore.release()
        else:
            _cleanup_proc = tw.proc if XRAY_REUSE_WORKER and tw.proc is not None else proc
            if _cleanup_proc is not None:
                unregister_process(_cleanup_proc, port)
                kill_xray_process(_cleanup_proc, drain_stderr=True)
            if XRAY_REUSE_WORKER:
                tw.proc = None
            if config_path is not None and not XRAY_REUSE_WORKER:
                try:
                    os.unlink(config_path)
                except FileNotFoundError:
                    pass
            if not XRAY_REUSE_WORKER:
                return_port(port)
            if semaphore_acquired:
                _xray_checker_semaphore.release()
