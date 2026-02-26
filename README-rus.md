# wiretracer

TLS-терминирующий диагностический L7-прокси для HTTP/1.1, HTTP/2 и gRPC.

## Оглавление
- [Ключевые возможности](#ключевые-возможности)
- [Быстрый старт](#быстрый-старт)
- [Где полезен](#где-полезен)
- [Важный нюанс по длительностям](#важный-нюанс-по-длительностям)
- [Тестовый набор](#тестовый-набор)
- [Документация](#документация)

## Ключевые возможности
- Наблюдение трафика: `http1`, `http2`, `grpc`.
- Диагностика TLS/mTLS на входе и на выходе.
- HTTP/2 control-события (`SETTINGS`, `RST_STREAM`, `GOAWAY`, flow-control) при `logging.h2_control_events: true`.
- HTTP/2 fingerprint (`h2fp`) по ранним H2-признакам (`SETTINGS` + `WINDOW_UPDATE`).
- Inbound TLS ClientHello fingerprint: `JA3`, `JA4`, `ECH`, legacy `ESNI` (best-effort).
- Режимы запуска:
  - TUI (интерактивный интерфейс);
  - headless (JSONL).
- Улучшения диагностики в TUI:
  - цветовая подсветка error/warn строк в Traffic и Connections;
  - колонка `Errs` в Connections (счетчик ошибок по соединению).
- Поддержка PROXY protocol:
  - автодетект на входе (`none`, `v1`, `v2`, malformed);
  - отправка в upstream с той же версией PROXY;
  - расширенные поля в логах/UI: `proxy_version`, `proxy_src`, `proxy_dst`.

## Быстрый старт
```bash
python3 wiretracer.py --gen-config > config.yaml
python3 wiretracer.py --config config.yaml --check
python3 wiretracer.py --config config.yaml
```

Headless режим:
```bash
python3 wiretracer.py --config config.yaml --headless
```

## Где полезен
- `grpcurl` возвращает `EOF`/`Unavailable`/`deadline exceeded`.
- Не договариваются ALPN/h2.
- mTLS ошибки доверия/сертификатов.
- Нужно понять, проблема в TLS, H2 control или в самом RPC.
- Нужно сохранить исходный client IP через PROXY protocol.

## Важный нюанс по длительностям
- `event.duration_ms` — время конкретного RPC/HTTP запроса.
- `conn.duration_ms` — время жизни TCP/TLS соединения.

Поэтому «быстрый ответ + conn=30s» для `grpcurl` — обычно нормально: клиент держит h2 keep-alive канал.

## Тестовый набор
- Основная инструкция: `test-suite/TEST_SUITE_GUIDE_RUS.md`
- Ключевые скрипты:
  - `test-suite/fault_client.py`
  - `test-suite/fault_server.py`
  - `test-suite/verify_headless.py`
  - `test-suite/run_proxy_test_suite.sh`

## Документация
- Полное руководство пользователя: `UserGuide-rus.md`
- Англоязычный README: `README.md`
- Документация тестового набора:
  - `test-suite/Readme-eng.md`
  - `test-suite/Readme-rus.md`
  - `test-suite/TEST_SUITE_GUIDE_RUS.md`
- Расширенная историческая документация: `ug-qwen.md`

