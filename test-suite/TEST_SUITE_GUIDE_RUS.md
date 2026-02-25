# Тестовый набор wiretracer (подробная инструкция)

## Оглавление
- [1. Назначение](#1-назначение)
- [2. Компоненты](#2-компоненты)
- [3. Подготовка](#3-подготовка)
- [4. Базовый запуск suite](#4-базовый-запуск-suite)
- [5. PROXY protocol тесты](#5-proxy-protocol-тесты)
- [6. gRPC тесты](#6-grpc-тесты)
- [7. Ручная проверка grpcurl](#7-ручная-проверка-grpcurl)
- [8. Как читать результаты](#8-как-читать-результаты)
- [9. Частые проблемы](#9-частые-проблемы)
- [10. Рекомендуемый порядок отладки](#10-рекомендуемый-порядок-отладки)

## 1. Назначение
Этот набор проверяет:
- HTTP/1.1 и HTTP/2 проксирование;
- gRPC сценарии;
- TLS/mTLS негативные и позитивные кейсы;
- PROXY protocol (`none`, `v1`, `v2`, malformed);
- корректность телеметрии в JSONL.

## 2. Компоненты
- `fault_client.py` — генерирует тестовые запросы (http1/h2/grpc/grpc_native).
- `fault_server.py` — upstream для тестов:
  - TLS server (`:19443`),
  - mTLS server (`:29443`),
  - plain server (`:18480`) с optional PROXY parse,
  - native gRPC TLS server (`:50052`, при наличии `grpcio`).
- `verify_headless.py` — валидирует JSONL события после прогона.
- `run_proxy_test_suite.sh` — orchestrator полного набора тестов.
- `config.yaml` и `test-suite/config.yaml` — тестовые listener-конфиги прокси.
- `helloworld.proto` — proto для ручных grpcurl проверок.

## 3. Подготовка
Из каталога `test-suite/`:

1. Убедитесь, что сертификаты есть в `./certs`.
2. Убедитесь, что `wiretracer.py` запускается с корректным `config.yaml`.
3. Если нужны `grpc_native` тесты, установите `grpcio`.

## 4. Базовый запуск suite
Запуск с автостартом прокси:
```bash
cd <repo>/test
bash ./run_proxy_test_suite.sh
```

Запуск при уже работающем прокси (TUI/ручной старт):
```bash
bash ./run_proxy_test_suite.sh --no-proxy
```

Что делает suite:
- проверяет readiness нужных listener портов;
- гоняет позитивные/негативные кейсы;
- останавливает прокси (если сам запускал);
- запускает `verify_headless.py` и печатает PASS/FAIL по проверкам.

## 5. PROXY protocol тесты
В suite есть кейсы:
- HTTP/1.1: `proxy_none_h1`, `proxy_v1_h1`, `proxy_v2_h1`, `proxy_malformed_h1`;
- HTTP/2: `proxy_none_h2`, `proxy_v1_h2`, `proxy_v2_h2`;
- gRPC (h2 mode): `proxy_none_grpc`, `proxy_v1_grpc`, `proxy_v2_grpc`.

Проверяется:
- успешные status=200 для корректных кейсов;
- применение client IP из PROXY header;
- `proxy_protocol_error` для malformed кейса.

## 6. gRPC тесты
### 6.1 h2-эмуляция gRPC
`fault_client --proto grpc` формирует h2 запросы с grpc-заголовками.

Плюсы:
- поддерживает injection PROXY header перед TLS;
- хорошо подходит для теста PROXY+gRPC.

### 6.2 Нативный gRPC
`fault_client --proto grpc_native` использует `grpcio`.

Плюсы:
- «честный» RPC вызов.

Ограничение:
- grpcio клиент не поддерживает отправку PROXY header до TLS, поэтому для `grpc_native` используется только `--proxy-header none`.

## 7. Ручная проверка grpcurl
Из каталога `test-suite/`:

Upstream напрямую (`fault_server`):
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:50052 helloworld.Greeter/SayHello
```

Через proxy listener `grpc-exporter`:
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:9101 helloworld.Greeter/SayHello
```

## 8. Как читать результаты
### 8.1 verify_headless.py
В конце выдаёт список `PASS/FAIL` с деталями:
- `presence` — найдены ли записи по test TID;
- статусы/протоколы (`grpc/http2/http1`);
- причины закрытия соединений;
- tls outcomes/reasons.

### 8.2 event vs conn duration
- `event.duration_ms` — latency конкретного запроса/RPC.
- `conn.duration_ms` — lifetime всего соединения.

Если RPC быстрый, а `conn.duration_ms` ~30s (например с grpcurl), это обычно keep-alive поведение клиента и не ошибка.

## 9. Частые проблемы
1. `helloworld.proto does not reside in any import path`
- Вы запускаете из `test-suite/`, значит должен быть `-import-path .`, а не `-import-path ./test`.

2. `EOF while waiting h2 response`
- Проверьте, что `test-http2` направлен на корректный upstream (h2/h2c по тестовому сценарию).
- Проверьте актуальный `config.yaml` и перезапуск прокси после правок.

3. `upstream_protocol_error` сразу после старта h2
- Часто mismatch по ALPN/TLS режиму upstream.
- Для TLS upstream нужен ALPN `h2`; для cleartext h2c ALPN отсутствует.

## 10. Рекомендуемый порядок отладки
1. Запустить `fault_server.py`.
2. Запустить прокси с `test-suite/config.yaml`.
3. Выполнить один проблемный кейс вручную через `fault_client.py`.
4. Проверить JSONL события по `tid`.
5. После фикса прогнать полный `run_proxy_test_suite.sh`.


