# wiretracer — Руководство пользователя

## Оглавление
- [1. Что это](#1-что-это)
- [2. Ключевые возможности](#2-ключевые-возможности)
- [3. Как работает прокси](#3-как-работает-прокси)
- [4. Быстрый старт](#4-быстрый-старт)
- [5. Конфигурация (YAML)](#5-конфигурация-yaml)
- [6. PROXY protocol: как использовать](#6-proxy-protocol-как-использовать)
- [7. Диагностика HTTP/2 и gRPC](#7-диагностика-http2-и-grpc)
- [8. Типовые сценарии использования](#8-типовые-сценарии-использования)
- [9. Рекомендации для эксплуатации](#9-рекомендации-для-эксплуатации)
- [10. Новые сценарии (актуально для текущей версии)](#10-новые-сценарии-актуально-для-текущей-версии)
- [11. Полезные команды](#11-полезные-команды)
- [12. Связанные документы](#12-связанные-документы)

## 1. Что это
`wiretracer` — TLS-терминирующий диагностический L7-прокси для HTTP/1.1, HTTP/2 и gRPC.

Основные задачи:
- наблюдение и разбор трафика на уровне запросов/ответов;
- диагностика TLS/ALPN/mTLS проблем;
- анализ HTTP/2 control-событий (`SETTINGS`, `RST_STREAM`, `GOAWAY`, `WINDOW_UPDATE`);
- headless-режим с JSONL для автоматических проверок.

## 2. Ключевые возможности
- Поддержка протоколов: `http1`, `http2`, `grpc`.
- Режимы запуска:
  - `TUI` (интерактивный интерфейс);
  - `headless` (логирование в JSONL).
- Входящий и исходящий TLS/mTLS.
- Автоопределение PROXY protocol на входе:
  - PROXY отсутствует;
  - PROXY v1;
  - PROXY v2;
  - malformed header (диагностика с явной причиной).
- Проброс PROXY protocol в upstream:
  - при наличии входящего PROXY заголовка соединение к upstream выполняется с той же версией PROXY protocol.
- Расширенная телеметрия соединения:
  - `proxy_version`, `proxy_src`, `proxy_dst` в `conn open/close`, Details и JSONL.
- HTTP/2 fingerprint телеметрия:
  - значения `h2fp` по направлениям и общий профиль в Connections/Details.
- Inbound TLS fingerprint телеметрия (до TLS upgrade):
  - `JA3`, `JA4`, наличие/длина `ECH`, наличие legacy `ESNI`.

## 3. Как работает прокси
1. Принимает входящее TCP/TLS соединение на listener.
2. До TLS handshake на входе пытается определить PROXY protocol (v1/v2/none).
3. Если PROXY найден — применяет source/destination endpoint к данным соединения.
4. Терминирует входящий TLS (L7-режим сохраняется).
5. Открывает upstream-соединение:
   - plain или TLS/mTLS по конфигу listener;
   - при входящем PROXY отправляет upstream тот же PROXY header.
6. Проксирует HTTP/1.1 или HTTP/2/gRPC, логируя handshake/control/events.

Важно: поддержка PROXY protocol не переводит прокси в L4 pass-through. Прокси остаётся L7 MITM-диагностическим узлом.

## 4. Быстрый старт
### 4.1 Зависимости
Минимум:
- Python 3.11+;
- `urwid`, `PyYAML`, `h2`.

Опционально для нативных gRPC тестов:
- `grpcio`.

### 4.2 Генерация примера конфигурации
```bash
python3 wiretracer.py --gen-config > config.yaml
```

### 4.3 Проверка конфига
```bash
python3 wiretracer.py --config config.yaml --check
```

### 4.4 Запуск
TUI:
```bash
python3 wiretracer.py --config config.yaml
```

Headless:
```bash
python3 wiretracer.py --config config.yaml --headless
```

## 5. Конфигурация (YAML)
Структура listener:
```yaml
- name: my-listener
  listen: 0.0.0.0:9101
  tls:
    cert: /path/server.crt
    key: /path/server.key
    require_client_cert: false
    client_ca: null
    alpn: [h2, http/1.1]
    min_version: TLS1.2
  upstream:
    addr: 127.0.0.1:50052
    tls: true
    server_name: localhost
    verify: false
    alpn: [h2]
    ca: /path/ca.crt
    client_cert: null
    client_key: null
  policy:
    allowlist: [127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16]
    max_connections: 200
    upstream_connect_timeout: 5.0
    upstream_handshake_timeout: 10.0
    maxconn_wait_warn_ms: 500
  logging:
    log_headers: true
    log_body: true
    body_max_bytes: 8192
    redact_headers: [authorization, cookie, x-api-key]
    sample_rate: 1.0
    jsonl_path: /tmp/headless.jsonl
```

## 6. PROXY protocol: как использовать
### 6.1 Что поддерживается
- Вход: автодетект `none/v1/v2` на любом listener.
- Выход: если на входе был PROXY, в upstream отправляется тот же `raw` header.
- Ошибки парсинга malformed PROXY header:
  - соединение закрывается с `close_reason=proxy_protocol_error`.

### 6.2 Что видно в логах и UI
В `conn` событиях:
- `proxy_version` (`none`, `v1`, `v2`, `invalid`),
- `proxy_src` (`ip:port`),
- `proxy_dst` (`ip:port`).

В TUI:
- Traffic/Connections: `pp=... src=... dst=...`;
- Details: отдельные строки `PROXY(in)`, `PROXY src`, `PROXY dst`.

### 6.3 Полезные фильтры
- `proxy=v1`
- `proxy=v2`
- `proxy=none`
- `proxy_src=203.0.113.10`
- `listener=grpc-exporter proto=grpc`

## 7. Диагностика HTTP/2 и gRPC
### 7.1 Типы событий
- `proto=tls` — входящие/исходящие handshake и причины fail; для входа дополнительно ClientHello fingerprints (`JA3/JA4/ECH/ESNI`), если доступны;
- `proto=h2ctl` — control frames, flow-control диагностика и `FINGERPRINT`-события H2-профиля;
- `proto=grpc|http2|http1` — события запрос/ответ.

### 7.1.1 Визуальная индикация ошибок в TUI
- `Traffic view`:
  - error-строки подсвечиваются цветом (например, `tls fail`, `conn close` с `*_fail/*_error/*_timeout/*_rst`, `event` с `error`/`5xx`);
  - warn-строки подсвечиваются отдельно для части `h2ctl` событий (`GOAWAY`, `RST_STREAM`, `FLOW_BLOCK`).
- `Connections view`:
  - error-строки подсвечиваются цветом по состоянию соединения;
  - добавлена колонка `Errs` — счетчик ошибок по соединению (`last_error`/проблемные close-reason/flags).
  - для закрытых соединений `Idle` фиксируется на момент `closed_ts` и дальше не увеличивается.

### 7.2 Важные практические моменты
- `event.duration_ms` — длительность конкретного RPC/HTTP запроса.
- `conn.duration_ms` — длительность жизни TCP/TLS соединения.

Поэтому нормальна ситуация: gRPC ответ получен мгновенно, а `conn.duration_ms` ~30s (клиент держит h2 connection keep-alive и закрывает позже).

## 8. Типовые сценарии использования
- Troubleshooting `grpcurl` (`EOF`, `Unavailable`, `deadline exceeded`).
- Проверка ALPN/h2 (`no_application_protocol`, `wrong version`).
- Проверка mTLS (клиент->прокси и прокси->upstream).
- Анализ причин `RST_STREAM`/`GOAWAY`.
- Диагностика реального client IP при цепочке L4/L7 через PROXY protocol.

## 9. Рекомендации для эксплуатации
- В production включать `upstream.verify=true` и корректный `ca`.
- Ограничивать `body_max_bytes` для высоконагруженных систем.
- Для быстрых сервисов использовать `sample_rate < 1.0`.
- Для проблемных клиентов начинать с фильтра:
  - `proto=tls outcome=fail`
  - `proto=h2ctl`
  - `proto=grpc error=1`
  - `ja3=<md5>`
  - `ja4=t13d...`
  - `ech=1`
  - `h2fp=h2fp1:...`

## 10. Новые сценарии (актуально для текущей версии)
- Единый listener может принимать mixed-трафик: клиенты с PROXY и без PROXY.
- `PROXY + TLS + HTTP/2` и `PROXY + TLS + gRPC` поддержаны и покрыты тестами.
- Для gRPC доступны два подхода тестирования:
  - h2-эмуляция с grpc headers (`fault_client --proto grpc`), включая PROXY v1/v2;
  - нативный grpcio клиент/сервер (`--proto grpc_native`) для «честного» RPC.

## 11. Полезные команды
Проверка gRPC upstream напрямую:
```bash
grpcurl -insecure -import-path ./test -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:50052 helloworld.Greeter/SayHello
```

Проверка через listener `grpc-exporter`:
```bash
grpcurl -insecure -import-path ./test -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:9101 helloworld.Greeter/SayHello
```

## 12. Связанные документы
- `README.md` — краткий англоязычный обзор для GitHub.
- `README-rus.md` — краткий русскоязычный обзор для GitHub.
- `test-suite/TEST_SUITE_GUIDE_RUS.md` — подробная инструкция по тестовому набору.

