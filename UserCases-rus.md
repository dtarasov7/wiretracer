## Примеры применения wiretracer

### Пример A: Javaagent OpenTelemetry не отправляет трейсы

**Симптом:**
- агент пишет `export failed`, `deadline exceeded`, `UNAVAILABLE`;
- сервер «живой», но трейсы не доходят.

**Что делаем:**
1. Ставим `wiretracer` перед collector/ingest endpoint.
2. В listener включаем:
   - `tls.alpn: [h2, http/1.1]`
   - для upstream gRPC: `upstream.alpn: [h2]`
3. В Traffic проверяем:
   - `tls out fail no_application_protocol` (нет согласованного h2),
   - `h2ctl GOAWAY` / `RST_STREAM`,
   - `grpc-status` в response headers.

**Типовые причины:**
- upstream реально принимает только `http/1.1`;
- mismatch `SNI/CA/verify`;
- upstream ждёт mTLS client cert, а прокси его не предъявляет.

---

### Пример B: Redis Sentinel под TLS не собирает кворум

**Ситуация:**
Sentinel видят Redis, но peer-to-peer взаимодействие Sentinel ломается.

**Что даёт wiretracer:**
- видно, что TLS в обе стороны успешен (`tls in ok`, `tls out ok`);
- значит проблема выше TLS, например аутентификация (`NOAUTH`) или ACL;
- можно быстро отделить сетевую/криптографическую проблему от логики приложения.

---

### Пример C: Nginx пишет `"PRI * HTTP/2.0" 400`

**Смысл ошибки:**
На endpoint, где ожидался HTTP/1.1, пришёл HTTP/2 preface.

**Как помогает wiretracer:**
- видно, был ли `ALPN=h2`;
- видно, дошли ли `SETTINGS/ACK` (`h2ctl`);
- можно понять, это проблема маршрутизации, ALPN или конфигурации Nginx.

---

### Пример D: `grpcurl list` через wiretracer даёт `context deadline exceeded`

**Порядок проверки:**
1. Есть ли `tls in ok`?
2. Есть ли `tls out ok`?
3. Есть ли `h2ctl SETTINGS` в обе стороны?
4. Есть ли `GOAWAY/RST_STREAM`?
5. Появляются ли `event proto=grpc`?

Если `event proto=grpc` нет, запрос не дошёл до уровня gRPC.

---

### Пример E: Непонятно, кто и что отправляет

**Сценарий:**
Много клиентов/агентов, трудно связать источник, listener и upstream.

**Полезные поля:**
- `client_ip:client_port`,
- `listener`,
- `upstream_addr`,
- `conn_id`,
- `alpn_in/alpn_out`,
- `tls in/out`.

Это позволяет быстро построить «цепочку» соединения.

---

### Пример F: Клиенты приходят через L4 балансировщики (PROXY protocol)

**Симптом:**
В логах виден IP балансировщика, а не реального клиента.

**Что делаем:**
- оставляем listener как есть, без отдельного порта под PROXY;
- `wiretracer` сам определяет `none/v1/v2`;
- в событиях `conn` смотрим:
  - `proxy_version`,
  - `proxy_src`,
  - `proxy_dst`.

**Результат:**
Реальный source endpoint становится виден в диагностике.

---

### Пример G: Нужно убедиться, что PROXY пробрасывается в upstream

**Задача:**
Проверить, что при входящем PROXY v1/v2 в upstream уходит та же версия.

**Как проверяем:**
1. Запускаем кейсы `proxy_v1_*` / `proxy_v2_*` из test-suite.
2. На `fault_server` видим детект:
   - `PROXY=v1|v2`
   - `src=... dst=...`
3. В JSONL видим корректный `client_ip` и `proxy_*` поля.

---

### Пример H: gRPC быстрый, но `conn.duration_ms` около 30 секунд

**Симптом:**
`grpcurl` уже вывел ответ, но `conn close` приходит позже.

**Разбор:**
- `event.duration_ms` — latency RPC;
- `conn.duration_ms` — lifetime TCP/TLS соединения.

Для h2 keep-alive это нормально: клиент закрывает канал не сразу.

---

### Пример I: Ошибки только на части клиентов

**Сценарий:**
Некоторые клиенты работают, некоторые падают по TLS.

**Что фильтровать:**
- `proto=tls outcome=fail`
- `client=<ip>`
- `listener=<name>`
- `reason` / `category` в `tls` событиях.

**Результат:**
Быстро видно сегмент клиентов с неправильными сертификатами/CA/SNI.

---

### Пример J: Нужна проверка новых релизных изменений без ручного клика в TUI

**Сценарий:**
Проверить регрессию после изменения конфигов/логики.

**Что делаем:**
1. Запускаем `test-suite/run_proxy_test_suite.sh`.
2. Анализируем `verify_headless.py` итог.
3. Смотрим только упавшие TID.

**Плюс:**
Можно встроить в CI как smoke/regression набор.

---

### Пример K: Проверка «честного» gRPC (не только h2-эмуляции)

**Сценарий:**
Есть сомнение, что h2-эмуляция не отражает реальный grpcio клиент.

**Что делаем:**
- используем `fault_client.py --proto grpc_native`;
- либо вручную вызываем `grpcurl` с `helloworld.proto`;
- сравниваем события `proto=grpc`, заголовки и статусы.

---

### Пример L: Mixed traffic на одном listener

**Сценарий:**
На одном и том же listener приходят клиенты:
- без PROXY,
- с PROXY v1,
- с PROXY v2.

**Что даёт wiretracer:**
- не нужно делить трафик по разным listener;
- для каждого соединения видно фактический режим (`proxy_version`), endpoint и причины закрытия;
- удобно для плавной миграции инфраструктуры.

