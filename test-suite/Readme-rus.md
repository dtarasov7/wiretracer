# Тестовый набор wiretracer (RU)

## Оглавление
- [Обзор](#обзор)
- [Компоненты](#компоненты)
- [Что покрывается](#что-покрывается)
- [Быстрый старт](#быстрый-старт)
- [Ручные проверки](#ручные-проверки)
- [Интерпретация результатов](#интерпретация-результатов)
- [Ссылки](#ссылки)

## Обзор
Тестовый набор проверяет `wiretracer` end-to-end:
- HTTP/1.1, HTTP/2 и gRPC;
- TLS/mTLS сценарии;
- PROXY protocol (`none`, `v1`, `v2`, malformed);
- корректность телеметрии в JSONL.

## Компоненты
- `fault_client.py` — генератор трафика (`http1`, `h2`, `grpc`, `grpc_native`).
- `fault_server.py` — upstream-эмулятор:
  - TLS server (`:19443`),
  - mTLS server (`:29443`),
  - plain server (`:18480`) с optional PROXY parse,
  - native gRPC TLS server (`:50052`, если установлен `grpcio`).
- `run_proxy_test_suite.sh` — оркестратор полного прогона.
- `verify_headless.py` — верификация JSONL после тестов.
- `helloworld.proto` — proto для grpcurl/native gRPC проверок.

## Что покрывается
- Happy-path:
  - `h1_chat5`, `h2_chat5`, `grpc_chat3`.
- PROXY protocol:
  - `proxy_none_*`, `proxy_v1_*`, `proxy_v2_*`, malformed кейс.
- Негативные upstream сценарии:
  - `hang`, `close_early`, `truncate`, `rst`, `sleep_headers`.
- Негативные client сценарии:
  - `client_close_early`, `client_rst`, `client_half_close`.
- mTLS:
  - клиентский сертификат: OK/отсутствует/невалиден;
  - проблемы handshake к upstream.
- Опционально native grpcio кейсы через listener `grpc-exporter` (`:9101`).

## Быстрый старт
Из каталога `test-suite/`:

1. Запуск upstream:
```bash
python3 ./fault_server.py --certs ./certs
```

2. Запуск прокси (в отдельном терминале):
```bash
python3 ../wiretracer.py --config ../config.yaml --headless
```

3. Запуск suite:
```bash
bash ./run_proxy_test_suite.sh
```

Если прокси уже запущен:
```bash
bash ./run_proxy_test_suite.sh --no-proxy
```

## Ручные проверки
grpcurl напрямую в native upstream (`:50052`) из `test-suite/`:
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:50052 helloworld.Greeter/SayHello
```

grpcurl через proxy listener (`grpc-exporter`, `:9101`):
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:9101 helloworld.Greeter/SayHello
```

## Интерпретация результатов
- `event.duration_ms`: latency конкретного запроса/RPC.
- `conn.duration_ms`: время жизни TCP/TLS соединения.

Ситуация «быстрый gRPC ответ + `conn.duration_ms` около 30 секунд» обычно нормальна: клиент держит keep-alive соединение.

## Ссылки
- Полная инструкция по test kit: `test-suite/TEST_SUITE_GUIDE_RUS.md`
- Полное пользовательское руководство: `UserGuide.md`
- README репозитория:
  - `README.md`
  - `README-rus.md`


