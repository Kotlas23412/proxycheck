<div align="center">

# XRayCheck

> **Технический анализ конфигураций VLESS, VMess, Trojan, Shadowsocks, Hysteria и MTProto с возможностью эмуляции сетевых ограничений**

---

> ⚠️ **Данные предоставляются исключительно в информационных целях.**
>
> ⚠️ **Любое использование конфигураций возможно только с согласия их владельцев**
> 
> ⚠️ **Настоящий инструмент выполняет только техническую валидацию доступности сетевых endpoint**
> 
> ⚠️ **Инструмент не создаёт VPN-соединений и не маршрутизирует пользовательский трафик через третьи лица**


---

| [**Исходный код**](https://github.com/WhitePrime/xraycheck/tree/main) | | [**Локальный запуск**](#локальный-запуск) | 

| [**Техническая информация**](#техническая-информация) |



| [**DMCA Takedown**](#-dmca-takedown) | 


> [**Telegram**](https://t.me/XRayCheck)

</div>

---

<div align="center">

## 📊 Статистика репозитория

| Показатель                             | Значение |
| ------------------------------------------------ | ---------------- |
| Просмотры (14Д)                        | 4 668|
| Уникальные посетители (14Д) | 1 426|
| Клоны (14Д)                                | 17 238|
| Уникальные клоны (14Д)           | 3 441|
| Звёзды                                     | 90|
| Форки                                       | 9|

</div>

---
---

## 📮 DMCA Takedown

Если вы являетесь владельцем сервера, чьи конфигурации были обнаружены в данном репозитории, и вы хотите их удалить:

<div align="center">

| Способ | Действие |
|--------|----------|
| **GitHub Issue** | Создайте [Issue](https://github.com/WhitePrime/xraycheck/issues/new) с тегом `[Takedown]` в заголовке |
| **Telegram** | Напишите в [Telegram-бот для обратной связи](https://t.me/XRayCheckSupportBot) |

</div>

### Что нужно указать в запросе

Обязательно:
- [ ] Домен или IP-адрес сервера для удаления
- [ ] Доказательство владения (одно из):
  - Запись WHOIS домена
  - Счёт от хостинг-провайдера (реквизиты и персональные данные можно скрыть)
  - DNS TXT-запись: `v=removal-request-xraycheck`
  - Письмо с корпоративного email на домене сервера

Опционально:
- Причина удаления (утечка, устаревшие данные, ошибочное добавление)
- Предпочтительный способ связи для подтверждения

### Сроки обработки

- **Первичный ответ**: в течение 48 часов
- **Удаление из репозитория**: в течение 72 часов после подтверждения владения
- **Обновление GitHub Pages**: до 24 часов после удаления из репозитория

---
---

<div align="center">


# Техническая информация

</div>

---

Поддерживаемые протоколы: **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **Hysteria**, **MTProto**


## Требования

- **Python 3.8+**
- **Xray-core** - при первом запуске, если xray не найден в PATH и не задан`XRAY_PATH`, скрипт **автоматически скачает** нужную сборку с [GitHub Releases](https://github.com/XTLS/Xray-core/releases) в папку`xray_dist` рядом со скриптом. Ручная установка не обязательна.

## Установка

```bash
pip install -r requirements.txt
```

## Режимы работы

- **single** - Валидация ключей из одной ссылки (аргумент командной строки или`DEFAULT_LIST_URL`).
- **merge** - Объединение ключей из нескольких ссылок и валидация одной группы. Ссылки задаются в файле`links.txt` (по одной URL на строку). Имя файла задаётся в`.env` переменной`LINKS_FILE`.

## Режимы проверки ключей

- **Обычный** (`STRONG_STYLE_TEST=false`) - несколько тестовых URL (HTTP и/или HTTPS), повторные запросы, проверки стабильности. Настраивается через`TEST_URLS`,`TEST_URLS_HTTPS`,`MIN_SUCCESSFUL_URLS`,`REQUIRE_HTTPS`,`STABILITY_CHECKS` и др.
- **Строгий** (`STRONG_STYLE_TEST=true`) - один тестовый URL`https://www.gstatic.com/generate_204`, один или два запроса подряд, без повторов. Ключ считается рабочим только при ответе 204, пустом теле и времени ответа не более`STRONG_MAX_RESPONSE_TIME` секунд. Результаты ближе к поведению мобильных клиентов.

Полный список переменных - в `.env.example`.

---

---

<div align="center">

# Локальный запуск

</div>

## Запуск

Список по умолчанию (режим single):

```bash
python -m lib.vless_checker
```

Свой URL списка (режим single):

```bash
python -m lib.vless_checker "https://example.com/my-vless-list.txt"
```

Режим merge: положите ссылки в `links.txt`, в `.env` задайте `MODE=merge`:

```bash
# В links.txt по одной URL на строку, например:
# https://example.com/list1.txt
# https://example.com/list2.txt
python -m lib.vless_checker
```

Проверка доступа к сайтам (в т.ч. заблокированным в РФ): в коде уже есть встроенные HTTPS URL (`twitter.com`, `x.com`, `instagram.com`, `facebook.com`, `threads.net`), которые используются по умолчанию, если `TEST_URLS_HTTPS` не задан.

```bash
MODE=single
python -m lib.vless_checker "https://example.com/my-vless-list.txt"
```

## Запуск через Docker

Для запуска проверки в изолированном окружении доступен режим через Docker.  
Рекомендуемый способ - использовать `docker-compose` из репозитория (учитывает `.env`, CIDR whitelist и публикацию результатов в `configs/`).

### Быстрый старт с docker-compose

1. Скопируйте `.env.example` в `.env` и при необходимости скорректируйте настройки (режим, `LINKS_FILE`, whitelist: файл `cidrlist` в корне при `docker-compose` или `CIDR_WHITELIST_URL` и т.д.).
2. Убедитесь, что установлен Docker и Docker Compose.
3. Запустите:

```bash
docker compose up --build
```

Результаты проверки (файлы `available`, `available(top100)` и отчёты speedtest при включённом `SPEED_TEST_ENABLED`) будут в каталоге `configs/` на хосте согласно настройкам в `.env`.

### Пример запуска одиночного контейнера

При необходимости можно запустить контейнер вручную (например, для одноразовой проверки), используя локально собранный образ:

```bash
docker build -t xraycheck:latest .
```

А затем:

```bash
docker run --rm \
  --env-file .env \
  -v "$(pwd)/configs:/app/configs" \
  xraycheck:latest
```

Где:
- `--env-file .env` передаёт все настройки проверки в контейнер;
- `-v "$(pwd)/configs:/app/configs"` монтирует локальную папку `configs` для сохранения результатов.

### Передача URL списка конфигов в Docker

В качестве первого аргумента контейнер принимает URL списка конфигов (аналог `python -m lib.vless_checker "https://..."` при локальном запуске).  
Это работает как для `docker run`, так и для `docker compose run`:

```bash
docker run --rm \
  --env-file .env \
  -v "$(pwd)/configs:/app/configs" \
  xraycheck:latest \
  "https://example.com/my-vless-list.txt"
```

Или через docker-compose (использует сервис `vless-checker` из `docker-compose.yml`):

```bash
docker compose run --rm vless-checker "https://example.com/my-vless-list.txt"
```

В этом случае список ключей загружается по переданному URL, а все остальные параметры берутся из `.env`.

## Запуск через скрипты

Для удобства запуска доступны интерактивные скрипты, которые предлагают выбор между обычной проверкой и проверкой в Docker, а также автоматически проверяют и устанавливают зависимости.

### Windows: bat-скрипт

Для Windows доступен нативный bat-скрипт `run_check.bat` с интерактивным меню:

1. Дважды кликните на`run_check.bat` в проводнике Windows, или
2. Запустите из командной строки или PowerShell:
   ```cmd
   run_check.bat
   ```

**Использование:**

- Используйте стрелки ↑↓ для навигации по меню
- Нажмите Enter для выбора пункта
- Нажмите Escape для выхода

С передачей аргументов (например, URL списка):

```cmd
run_check.bat "https://example.com/my-list.txt"
```

> **Примечание:** Скрипт использует встроенный PowerShell для интерактивного меню. Убедитесь, что PowerShell доступен в вашей системе (обычно установлен по умолчанию в Windows 10/11).

### Linux/macOS: bash скрипт

Для Linux и macOS используйте bash скрипт `run_check.sh` с интерактивным меню:

```bash
chmod +x run_check.sh
./run_check.sh
```

**Использование:**

- Используйте стрелки ↑↓ для навигации по меню
- Нажмите Enter для выбора пункта
- Нажмите Escape или 'q' для выхода

С передачей аргументов (например, URL списка):

```bash
./run_check.sh "https://example.com/my-list.txt"
```

## Настройки (файл `.env`)

Параметры задаются в **`.env`** в каталоге проекта (или через переменные окружения). Полный шаблон со значениями по умолчанию - **`.env.example`**.

<details>
<summary><strong>Основные, вывод и комментарии</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MODE` | Режим: `single` (одна ссылка) или `merge` (объединение списков из файла) |
| `DEFAULT_LIST_URL` | URL списка по умолчанию при `MODE=single` |
| `LINKS_FILE` | Файл со ссылками при `MODE=merge` (по одной URL на строку) |
| `OUTPUT_FILE` | Имя файла для рабочих ключей без расширения; локально часто `available`, в `docker-compose` задаётся `white-list_available` |
| `OUTPUT_DIR` | Директория для результатов (`configs`), включая `notworkers` |
| `OUTPUT_ADD_DATE` | Добавлять дату и источник к имени файла (`true`/`false`) |
| `NOTWORKERS_UPDATE_ENABLED` | Обновлять файл нерабочих ключей `notworkers` в `OUTPUT_DIR` после проверки (`false` - только чтение для фильтра) |
| `AUTO_COMMENT` | Legacy-переменная для старого формата комментариев (текущий `strip_vpn_comments.py` формирует `# <flag> <country>[ | LTE]`) |
| `STRIP_VPN_COMMENTS_LTE_MARK` | Добавлять `\| LTE` в комментарий, если endpoint IP попал в `cidrlist` (`true`/`false`) |
| `STRIP_VPN_COMMENTS_CIDR_FILE` | Путь к файлу CIDR для `\| LTE` (по умолчанию `cidrlist`) |
| `STRIP_VPN_COMMENTS_GEO_MMDB` / `GEOIP_MMDB` | Путь к MMDB для более точного определения страны (fallback - ip-api) |
| `CIDR_WHITELIST_URL` | URL списка CIDR для Docker, если файл whitelist не задан или пуст |
| `CIDR_WHITELIST_FILE` | Путь к локальному файлу CIDR (в контейнере с монтированием репозитория обычно `/app/cidrlist`); имеет приоритет над URL |
| `SNI_FILE_URL` | URL списка доменов для whitelist SNI (workflow «Update tools»; см. комментарий в `.env.example`) |
| `FILTER_DOCKER_CONFIGS_ENABLED` | Локальный флаг вызова `filter_docker_configs` перед Docker (в GitHub Actions задаётся в workflow, не из `.env` раннера) |

</details>

<details>
<summary><strong>Тестовые URL и валидация</strong></summary>

| Переменная | Описание |
|------------|----------|
| `TEST_URL` | Один HTTP URL, если `TEST_URLS` пустой |
| `TEST_URLS` | Несколько HTTP URL через запятую или `;` |
| `TEST_URLS_HTTPS` | HTTPS URL (напр. `https://www.gstatic.com/generate_204`) |
| `REQUIRE_HTTPS` | Требовать успешный HTTPS для признания ключа рабочим |
| `STRONG_STYLE_TEST` | Строгий режим как в мобильных клиентах (`true`/`false`) |
| `STRONG_STYLE_TIMEOUT` | Таймаут одного запроса в строгом режиме, сек. |
| `STRONG_MAX_RESPONSE_TIME` | В строгом режиме макс. время ответа, сек. |
| `STRONG_DOUBLE_CHECK` | В строгом режиме два запроса подряд, оба должны пройти |
| `STRONG_ATTEMPTS` | Число подряд успешных запросов к generate_204 (3 = строже) |
| `STRONG_STYLE_CONNECT_T_MIN`, `STRONG_STYLE_READ_T_MIN` | Нижние границы connect/read таймаутов (сек.) в строгом режиме |

</details>

<details>
<summary><strong>Запросы и таймауты</strong></summary>

| Переменная | Описание |
|------------|----------|
| `REQUESTS_PER_URL` | Число запросов к каждому URL |
| `MIN_SUCCESSFUL_REQUESTS` | Минимум успешных запросов к одному URL |
| `MIN_SUCCESSFUL_URLS` | Минимум успешных URL для признания ключа рабочим |
| `REQUEST_DELAY` | Задержка между запросами к одному URL, сек. |
| `CONNECT_TIMEOUT` | Таймаут HTTP-запроса через прокси, сек. |
| `CONNECT_TIMEOUT_SLOW` | Таймаут для медленных соединений, сек. |
| `USE_ADAPTIVE_TIMEOUT` | Адаптивные таймауты (`true`/`false`) |
| `MAX_RETRIES` | Макс. повторов при ошибке соединения |
| `RETRY_DELAY_BASE`, `RETRY_DELAY_MULTIPLIER` | Задержка между повторами (экспоненциальная) |

</details>

<details>
<summary><strong>Ответы и фильтры</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MAX_RESPONSE_TIME` | Макс. допустимое время ответа, сек. (0 = не ограничивать) |
| `MIN_RESPONSE_SIZE` | Минимальный размер ответа в байтах (0 = не проверять) |
| `MAX_LATENCY_MS` | Макс. задержка в мс; ключи выше не попадают в результат |
| `VERIFY_HTTPS_SSL` | Проверять SSL при HTTPS через прокси (`false` типично для SOCKS) |

</details>

<details>
<summary><strong>Транзиентные сбои (xray / сокет)</strong></summary>

| Переменная | Описание |
|------------|----------|
| `TRANSIENT_RETRY_COUNT` | Сколько раз повторить проверку при типовых транзиентных ошибках |
| `TRANSIENT_RETRY_BACKOFF_BASE_SEC`, `TRANSIENT_RETRY_BACKOFF_MULT` | Пауза между повторами (база в секундах и множитель) |
| `EXCLUDE_TRANSIENT_FROM_NOTWORKERS` | Не записывать такие сбои в `notworkers` |

</details>

<details>
<summary><strong>Геолокация и стабильность</strong></summary>

| Переменная | Описание |
|------------|----------|
| `CHECK_GEOLOCATION` | Проверять геолокацию прокси |
| `GEOLOCATION_SERVICE` | URL сервиса геолокации |
| `ALLOWED_COUNTRIES` | Разрешённые страны (пусто = все) |
| `STABILITY_CHECKS` | Число проверок стабильности |
| `STABILITY_CHECK_DELAY` | Задержка между валидациями стабильности, сек. |
| `STRICT_MODE`, `STRICT_MODE_REQUIRE_ALL` | Строгий режим: требовать все проверки |

</details>

<details>
<summary><strong>Исключения endpoint</strong></summary>

| Переменная | Описание |
|------------|----------|
| `EXCLUDE_ENDPOINTS` | Список endpoint для отсева (см. `filter_excluded_endpoints`) |
| `EXCLUDE_ENDPOINTS_FILE` | Файл с исключениями (по умолчанию `configs/exclude_endpoints`) |
| `EXCLUDE_ENDPOINTS_LOG_DETAILS` | Подробный лог исключений (`true` / `1` / `yes` / `on`) |

</details>

<details>
<summary><strong>Производительность и xray</strong></summary>

| Переменная | Описание |
|------------|----------|
| `MAX_WORKERS` | Число потоков (параллельных проверок) |
| `BASE_PORT` | Начальный порт для SOCKS (диапазон BASE_PORT … BASE_PORT+MAX_WORKERS-1) |
| `XRAY_CHECKER_MAX_CONCURRENCY` | Лимит одновременных процессов xray в чекере (`0` = как `MAX_WORKERS`) |
| `XRAY_STARTUP_WAIT` | Ожидание старта xray, сек. |
| `XRAY_STARTUP_POLL_INTERVAL` | Интервал опроса процесса xray, сек. |
| `XRAY_PORT_WAIT` | Секунд ждать открытия SOCKS после старта процесса |
| `XRAY_REUSE_WORKER` | Переиспользование одного процесса xray на поток (Unix: SIGHUP; Windows: перезапуск) |
| `XRAY_PATH` | Путь к xray (пусто = поиск в PATH и автоустановка в `xray_dist`) |
| `XRAY_DIR_NAME` | Папка для скачанного xray |

</details>

<details>
<summary><strong>Отладка, логи, метрики, кэш и дополнительные проверки</strong></summary>

| Переменная | Описание |
|------------|----------|
| `DEBUG_FIRST_FAIL` | Вывод отладки при первой неудаче |
| `LOG_LEVEL` | Уровень логирования (DEBUG, INFO, WARNING, ERROR) |
| `LOG_FILE`, `LOG_MAX_SIZE`, `LOG_BACKUP_COUNT` | Файл логов и ротация |
| `LOG_RESPONSE_TIME` | Писать время ответа в результаты |
| `LOG_METRICS` | Логировать метрики производительности |
| `METRICS_FILE` | Файл для метрик |
| `MIN_AVG_RESPONSE_TIME` | Мин. среднее время ответа, сек. (0 = не ограничивать) |
| `TEST_POST_REQUESTS` | Проверять POST-запросы |
| `ENABLE_CACHE` | Кэширование результатов проверки |
| `CACHE_TTL`, `CACHE_FILE` | Время жизни кэша и файл кэша |

</details>

<details>
<summary><strong>Speedtest (speedtest_checker.py)</strong></summary>

| Переменная | Описание |
|------------|----------|
| `SPEED_TEST_ENABLED` | Включить speedtest (`true`/`false`) |
| `SPEED_TEST_TIMEOUT` | Макс. секунд на конфиг для фазы задержки |
| `SPEED_TEST_MODE` | Режим: `latency`, `quick` (250KB), `full` (1MB) |
| `SPEED_TEST_METRIC` | Метрика при latency: `latency`, `throughput`, `hybrid` |
| `SPEED_TEST_OUTPUT` | Куда писать: `separate_file` (_st, _st(top100)) |
| `SPEED_TEST_REQUESTS` | Число запросов для фазы задержки |
| `SPEED_TEST_URL` | URL для проверки задержки (generate_204) |
| `SPEED_TEST_WORKERS` | Число потоков для speedtest |
| `SPEED_TEST_DOWNLOAD_TIMEOUT` | Макс. секунд на загрузку тестового файла |
| `SPEED_TEST_DOWNLOAD_URL_SMALL`, `SPEED_TEST_DOWNLOAD_URL_MEDIUM` | URL для загрузки (quick/full) |
| `SPEED_TEST_MIN_SUCCESS_RATIO` | Мин. доля успешных запросов в latency-фазе (0..1) |
| `SPEED_TEST_MIN_SUCCESS_COUNT` | Мин. число успешных запросов в latency-фазе (оба порога должны выполняться) |
| `MIN_SPEED_THRESHOLD_MBPS` | Отсев по скорости, Mbps (0 = не фильтровать) |
| `SPEED_TEST_DEBUG` | Печать причины сбоя speedtest по каждому ключу |

</details>

<details>
<summary><strong>Docker entrypoint и вспомогательные скрипты</strong></summary>

| Переменная | Описание |
|------------|----------|
| `DOCKER_MTPROTO_ONLY` | Только проверка MTProto (и SOCKS из того же входа): список через stdin `-` или путь к файлу |
| `MTPROTO_OUTPUT_BASENAME` | Базовое имя итоговых файлов (по умолчанию `white-list_mtproto`) |
| `MTPROTO_TOP_N` | Размер top при слиянии результатов |
| `DOCKER_TG_SOCKS_ONLY` | Только `tg_socks_checker`, вход как у MTProto-режима |
| `TG_SOCKS_OUTPUT_BASENAME` | Имя выхода для Telegram SOCKS |
| `DOCKER_SPEEDTEST_ONLY` | Пропустить основную проверку, только speedtest по переданному списку (нужны `SPEED_TEST_ENABLED` и CIDR) |
| `MTPROTO_CHANNEL_TAG`, `TG_SOCKS_CHANNEL_TAG` | Метки канала для отчётов MTProto / SOCKS (см. соответствующие чекеры) |
| `GITHUB_TOKEN` | Для скриптов, обращающихся к GitHub API (`check_links`, `build_links_actual` и др.) |
| `GEOIP_MMDB` | Путь к GeoIP2 `.mmdb` для `filter_configs_by_cidr_and_geo` |
| `DOCKER_LOCATION_FILTER` | Код страны для `filter_mtproto_by_country` (по умолчанию `RU`) |
| `FILTER_DOCKER_VERBOSE`, `FILTER_DOCKER_CIDR_ONLY` | Отладка и режим только CIDR в `filter_docker_configs` |
| `CHECKER_DIAG_FAILURE_TYPES`, `CHECKER_DIAG_FAILURE_TOP_N` | Диагностика типов отказов в `vless_checker` |

</details>

<details>
<summary><strong>Экспорт</strong></summary>

| Переменная | Описание |
|------------|----------|
| `EXPORT_FORMAT` | Формат экспорта: txt, json, csv, html, all |
| `EXPORT_DIR` | Директория для экспорта |

</details>
