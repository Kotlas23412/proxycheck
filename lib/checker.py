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


def _run_strong_style_test(port: int, urls: list, should_debug_flag: bool) -> tuple[bool, list, int, int]:
    """
    STRONG_STYLE_TEST: несколько попыток через SOCKS-прокси к TEST_URLS/TEST_URLS_HTTPS.
    Возвращает (passed, response_times, successful_urls, failed_urls).
    Логика полностью берётся из конфига (STRONG_ATTEMPTS, STRONG_STYLE_TIMEOUT, и т.д.).
    """
    import requests as _requests

    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }

    response_times = []
    successful_urls = 0
    failed_urls = 0

    connect_t = max(float(STRONG_STYLE_CONNECT_T_MIN), float(STRONG_STYLE_TIMEOUT) * 0.4)
    read_t = max(float(STRONG_STYLE_READ_T_MIN), float(STRONG_STYLE_TIMEOUT) * 0.7)
    timeout_tuple = (connect_t, read_t)

    for url in urls:
        url_ok = False
        for attempt in range(int(STRONG_ATTEMPTS)):
            try:
                start = time.perf_counter()
                verify_ssl = (
                    url.startswith("https://")
                    and not (os.environ.get("VERIFY_HTTPS_SSL", "false").lower() in ("false", "0", "no"))
                )
                r = _requests.get(
                    url,
                    proxies=proxies,
                    timeout=timeout_tuple,
                    allow_redirects=True,
                    verify=verify_ssl,
                )
                elapsed = time.perf_counter() - start
                if check_response_valid(r, elapsed, MIN_RESPONSE_SIZE, float(STRONG_MAX_RESPONSE_TIME)):
                    response_times.append(elapsed)
                    url_ok = True
                    break
                else:
                    if should_debug_flag:
                        logger.debug(f"Strong test attempt {attempt+1}: bad response {r.status_code} / {elapsed:.2f}s for {url}")
            except Exception as e:
                if should_debug_flag:
                    logger.debug(f"Strong test attempt {attempt+1} exception for {url}: {e}")
                continue

        if url_ok:
            successful_urls += 1
        else:
            failed_urls += 1

    if STRICT_MODE_REQUIRE_ALL:
        passed = successful_urls >= len(urls) and failed_urls == 0
    else:
        passed = successful_urls >= int(MIN_SUCCESSFUL_URLS)

    return passed, response_times, successful_urls, failed_urls


def check_key_e2e(vless_line: str, debug: bool = False, cache: Optional[dict] = None) -> tuple[str, bool, Optional[dict]]:
    """
    End-to-end проверка прокси-ключа через локальный xray SOCKS-прокси.
    Использует TEST_URLS / TEST_URLS_HTTPS из конфига (настраивается через env).
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

    # Hysteria: простая TCP-проверка достижимости сервера
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
        # ОСНОВНАЯ ПРОВЕРКА: TEST_URLS из конфига (env-переменные)
        # TEST_URLS:       http://www.google.com/generate_204,...
        # TEST_URLS_HTTPS: https://www.gstatic.com/generate_204
        # Управляется через STRONG_STYLE_TEST, STRONG_ATTEMPTS, STRONG_STYLE_TIMEOUT,
        # MIN_SUCCESSFUL_URLS, STRICT_MODE_REQUIRE_ALL и т.д.
        # =====================================================================

        # Собираем список URL для проверки
        urls_to_test: list[str] = []
        if REQUIRE_HTTPS and TEST_URLS_HTTPS:
            for u in str(TEST_URLS_HTTPS).split(","):
                u = u.strip()
                if u:
                    urls_to_test.append(u)
        if TEST_URLS:
            for u in str(TEST_URLS).split(","):
                u = u.strip()
                if u and u not in urls_to_test:
                    urls_to_test.append(u)
        # Фоллбэк если ничего не задано
        if not urls_to_test:
            urls_to_test = ["http://www.google.com/generate_204"]

        proxies_dict = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        if STRONG_STYLE_TEST:
            passed, response_times, successful_urls, failed_urls = _run_strong_style_test(
                port, urls_to_test, should_debug_flag
            )
            metrics["response_times"] = response_times
            metrics["successful_urls"] = successful_urls
            metrics["failed_urls"] = failed_urls
            metrics["total_requests"] = successful_urls + failed_urls
            metrics["successful_requests"] = successful_urls

            if not passed:
                metrics["failure_type"] = "URL_TEST_FAILED"
                unregister_process(proc, port)
                return (vless_line, False, metrics)
        else:
            # Упрощённая проверка: make_request по каждому URL
            response_times = []
            successful_urls = 0
            failed_urls = 0
            total_requests = 0

            connect_timeout = CONNECT_TIMEOUT_SLOW if USE_ADAPTIVE_TIMEOUT else CONNECT_TIMEOUT

            for url in urls_to_test:
                url_ok = False
                for attempt in range(int(MAX_RETRIES) + 1):
                    total_requests += 1
                    try:
                        ok, elapsed, resp = make_request(
                            url,
                            proxies=proxies_dict,
                            connect_timeout=float(connect_timeout),
                            read_timeout=float(MAX_RESPONSE_TIME),
                            verify_https=(url.startswith("https://") and REQUIRE_HTTPS),
                            debug=should_debug_flag,
                        )
                        if ok:
                            response_times.append(elapsed)
                            url_ok = True
                            break
                    except Exception as e:
                        if should_debug_flag:
                            logger.debug(f"make_request attempt {attempt+1} exception: {e}")
                        if attempt < int(MAX_RETRIES):
                            time.sleep(float(RETRY_DELAY_BASE) * (float(RETRY_DELAY_MULTIPLIER) ** attempt))
                        continue

                if url_ok:
                    successful_urls += 1
                else:
                    failed_urls += 1

            metrics["response_times"] = response_times
            metrics["successful_urls"] = successful_urls
            metrics["failed_urls"] = failed_urls
            metrics["total_requests"] = total_requests
            metrics["successful_requests"] = successful_urls

            if STRICT_MODE_REQUIRE_ALL:
                passed = successful_urls >= len(urls_to_test) and failed_urls == 0
            else:
                passed = successful_urls >= int(MIN_SUCCESSFUL_URLS)

            if not passed:
                metrics["failure_type"] = "URL_TEST_FAILED"
                unregister_process(proc, port)
                return (vless_line, False, metrics)

        # Проверка задержки
        if metrics["response_times"]:
            avg_rt = sum(metrics["response_times"]) / len(metrics["response_times"])
            metrics["avg_response_time"] = avg_rt
            from .config import MAX_LATENCY_MS
            if avg_rt * 1000 > float(MAX_LATENCY_MS):
                metrics["failure_type"] = "HIGH_LATENCY"
                unregister_process(proc, port)
                return (vless_line, False, metrics)

        # Stability checks (дополнительные прогоны с паузой)
        if int(STABILITY_CHECKS) > 0:
            for sc in range(int(STABILITY_CHECKS)):
                time.sleep(float(STABILITY_CHECK_DELAY))
                sc_passed, sc_times, sc_ok, sc_fail = _run_strong_style_test(
                    port, urls_to_test[:1], should_debug_flag  # проверяем только первый URL
                )
                if not sc_passed:
                    metrics["failure_type"] = "STABILITY_CHECK_FAILED"
                    unregister_process(proc, port)
                    return (vless_line, False, metrics)
                metrics["response_times"].extend(sc_times)

        # Проверка геолокации
        if CHECK_GEOLOCATION:
            geolocation = get_geolocation(proxies_dict)
            if geolocation:
                metrics["geolocation"] = geolocation
                if not check_geolocation_allowed(geolocation, ALLOWED_COUNTRIES):
                    metrics["failure_type"] = "GEO_NOT_ALLOWED"
                    unregister_process(proc, port)
                    return (vless_line, False, metrics)

        # Сохранение в кэш
        if cache is not None and ENABLE_CACHE:
            key_hash = get_key_hash(vless_line)
            cache[key_hash] = {"result": True, "timestamp": time.time()}

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
        if should_debug_flag:
            logger.debug(f"check_key_e2e exception: {e}", exc_info=True)
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
