## FAQ

### Q1: Почему в Traffic появляются строки “tls” и “h2ctl”? Это “лишнее”?

Нет — это главная ценность для troubleshooting gRPC/HTTP2/TLS. Большая часть реальных проблем — не в “самом запросе”, а в рукопожатии/ALPN/GOAWAY/RST/flow-control.

---

### Q2: Почему gRPC body выглядит как бинарь?

Потому что gRPC payload — protobuf. Читабельный UTF-8 там редкость. Поэтому:

* показывается **gRPC frame structure**
* `hexdump+ascii`
* “strings” для быстрого поиска человеческих фрагментов (например `NOAUTH`).

---

### Q3: wiretracer хранит “полное тело”?

Он проксирует полный поток, но **захват в UI ограничен** `body_max_bytes` и hard-limit. Это специально, чтобы не съесть память на больших телах.

---

### Q4: Как включить входящий mTLS?

В listener:

```yaml
tls:
  require_client_cert: true
  client_ca: /path/to/client-ca.crt
```

И следить в Traffic за `tls in fail bad_certificate` / `unknown_ca`.

---

### Q5: Как включить исходящий mTLS (proxy→upstream)?

В upstream:

```yaml
upstream:
  tls: true
  client_cert: /path/to/proxy-client.crt
  client_key: /path/to/proxy-client.key
```

---

### Q6: Почему upstream verify выключен (`verify: false`), и это “плохо”?

Для troubleshooting это часто удобно, чтобы быстро исключить ошибки цепочки CA. Но в бою — лучше `verify: true` и `ca: ...`.

---

### Q7: В headless режиме что происходит?

wiretracer запускается, принимает соединения, пишет записи в store (и optionally JSONL), но **без UI**. Это режим для сервисов/демонов.

---

## Практические советы для реальной эксплуатации

1. Для gRPC почти всегда:

* listener `tls.alpn: ["h2","http/1.1"]`
* upstream `alpn: ["h2"]`

2. Для первичной диагностики можно временно поставить:

* upstream `verify: false`
  а затем включить обратно и настроить `ca`.

3. На больших телах:

* держи `body_max_bytes` 8–64KB, иначе UI станет тяжелее.

4. Включай `jsonl_path`, если нужна история “после факта”:

* можно потом грепать `GOAWAY`, `RST_STREAM`, `tls fail`.

---

Дополнение к инструкции: **карта типовых ошибок gRPC** (grpc-status ↔ причины ↔ какие H2/TLS события искать) + **набор готовых шаблонов конфигов** 
под распространённые кейсы (otel-collector, grpc server/reflection, nginx/h2, inbound/outbound mTLS, “двойной TLS”).

---

## Карта типовых ошибок gRPC и что искать в Traffic

### С чего начинать (быстрый чек-лист)

Если клиент видит `EOF`, `Unavailable`, `deadline exceeded`:

1. Найди в Traffic **tls(in)** событие рядом по времени.

   * Если `tls in fail` → проблема на входе (клиент→proxy): CA, mTLS, ALPN, версия TLS.
2. Найди **tls(out)** событие.

   * Если `tls out fail` → проблема на выходе (proxy→upstream): verify/SNI/CA/mTLS.
3. Если оба TLS ok — проверь наличие **h2ctl SETTINGS**:

   * Если нет SETTINGS от одной из сторон → с HTTP/2 что-то не так (ALPN/h2 не поднялся).
4. Потом смотри **h2ctl GOAWAY / RST_STREAM / FLOW_BLOCK** вокруг момента ошибки.

---

### Таблица grpc-status → причины → что искать

> Важно: grpc-status может быть в **trailers** (в конце), а не в headers. Поэтому полезно видеть и **h2ctl**, и сами **gRPC события**.

#### grpc-status = 0 (OK), но клиент всё равно ругается

**Симптомы:**

* Клиент пишет `error reading from server: EOF`, но ответ вроде “успел”.

**Частые причины:**

* upstream закрыл соединение сразу после response, клиент ожидал ещё (редко),
* проблема не на RPC уровне, а на transport (H2) уровне.

**Ищи:**

* `h2ctl GOAWAY` сразу после ответа,
* `RST_STREAM` на другом стриме в том же соединении.

---

#### grpc-status = 2 (UNKNOWN)

**Чаще всего:**

* исключение на сервере, не обёрнутое корректно,
* сбой в прокси/балансировщике.

**Ищи:**

* `h2ctl RST_STREAM` (особенно INTERNAL_ERROR),
* `h2ctl GOAWAY` с debug data,
* в response headers иногда есть `grpc-message` (часто пусто).

---

#### grpc-status = 3 (INVALID_ARGUMENT)

**Причина:**

* неверный запрос / protobuf / параметры.

**Ищи:**

* в Details request body (gRPC frames + strings) — часто видно “какой аргумент”,
* `grpc-message`.

---

#### grpc-status = 7 (PERMISSION_DENIED)

**Причина:**

* отказ авторизации/ACL.

**Ищи:**

* request metadata (authorization/token) — но у тебя редактирование может скрыть,
* `grpc-message`.

---

#### grpc-status = 13 (INTERNAL)

**Причины:**

* ошибка приложения,
* падение обработчика,
* иногда проблемы сериализации/десериализации protobuf.

**Ищи:**

* `grpc-message`,
* рядом могут быть `RST_STREAM` или `GOAWAY`.

---

#### grpc-status = 14 (UNAVAILABLE) — самый частый в troubleshooting

**Причины:**

* сеть/балансировщик/апстрим недоступен,
* TLS/ALPN не сходится,
* апстрим рвёт h2 соединение,
* timeouts.

**Ищи прежде всего:**

* `tls out fail` (cert_verify_failed, unknown_ca, bad_certificate, handshake_failure),
* `h2ctl GOAWAY` (часто code=ENHANCE_YOUR_CALM, PROTOCOL_ERROR, INTERNAL_ERROR),
* `h2ctl RST_STREAM` (CANCEL/INTERNAL_ERROR),
* `FLOW_BLOCK`/window==0 (иногда выглядит как таймаут/дедлайн).

---

#### grpc-status = 16 (UNAUTHENTICATED)

**Причины:**

* неправильные креды/токен,
* сервер требует auth metadata.

**Ищи:**

* `grpc-message` (иногда там “missing auth token”),
* request headers/metadata.

---

#### grpc-status отсутствует, а клиент получает EOF/RESET

**Причины:**

* не дошли до trailers (соединение порвали),
* транспортная ошибка.

**Ищи:**

* `h2ctl RST_STREAM` (особенно если случилось на этом stream_id),
* `h2ctl GOAWAY`,
* `tls` события/ошибки.

---

### Что означают ключевые H2 control события (практически)

#### SETTINGS / SETTINGS_ACK

**Зачем:** понять, “поняли ли стороны друг друга”.

* Если клиент предлагал h2 (ALPN), но нет SETTINGS → значит HTTP/2 не стартовал.
* Если upstream прислал странные настройки (например гигантские/маленькие окна), может быть источник проблем с flow-control.

#### GOAWAY

Почти всегда объясняет “почему внезапно всё умерло”.

* Смотри `code`, `last_stream_id`, `debug data`.
* Если GOAWAY приходит сразу после соединения — часто ALPN/протокол/политики.

#### RST_STREAM

Сброс конкретного стрима:

* `CANCEL` — отмена, часто из-за deadline/клиент отменил,
* `INTERNAL_ERROR`/`PROTOCOL_ERROR` — почти всегда bug/несовместимость.

#### WINDOW_UPDATE / FLOW_BLOCK

Если окно становится 0, прокси/сторона не может отправлять данные:

* на клиенте это может выглядеть как **подвисание** и затем `deadline exceeded`.

---

## Диагностические “шпаргалки” по симптомам

### `grpcurl ... list` → `context deadline exceeded`

1. Проверь `tls(in)` ok.
2. Проверь `tls(out)` ok.
3. Должен быть `h2ctl SETTINGS` (и туда, и обратно).
4. Если SETTINGS есть, но нет ответа:

   * ищи `FLOW_BLOCK` / отсутствие WINDOW_UPDATE,
   * ищи `GOAWAY`/`RST_STREAM`.

---

### Клиент пишет `Unavailable: error reading from server: EOF`

Чаще всего это:

* upstream отправил `GOAWAY` и закрыл,
* либо `RST_STREAM` на стрим.

**Смотри:**

* `h2ctl GOAWAY`,
* `h2ctl RST_STREAM`,
* `tls out ok/fail` — если fail, это TLS.

---

### Nginx логирует `"PRI * HTTP/2.0" 400`

Это значит: к Nginx пришёл HTTP/2 preface, но он не ожидал h2 на этом endpoint.
**Смотри:**

* ALPN negotiated? (tls events)
* `h2ctl SETTINGS` вообще есть?

---

## Готовые шаблоны конфигов (копируй-вставляй)

Ниже примеры **мульти-листенеров**. Можно держать один proxy для нескольких сервисов.

---

### OTEL Collector (gRPC OTLP) “двойной TLS”, upstream с verify=false (быстро исключить CA)

```yaml
listeners:
  - name: otel-otlp-grpc
    listen: "0.0.0.0:4317"
    tls:
      cert: "/opt/certs/proxy.crt"
      key:  "/opt/certs/proxy.key"
      require_client_cert: false
      client_ca: null
      alpn: ["h2", "http/1.1"]
      min_version: "TLS1.2"

    upstream:
      addr: "127.0.0.1:4318"
      tls: true
      alpn: ["h2"]
      server_name: "localhost"
      verify: false
      ca: null
      client_cert: null
      client_key: null
      client_key_password: null

    policy:
      allowlist: ["10.0.0.0/8", "192.168.0.0/16"]
      max_connections: 500

    logging:
      log_headers: true
      log_body: false
      body_max_bytes: 8192
      redact_headers: ["authorization", "cookie", "x-api-key"]
      sample_rate: 1.0
      jsonl_path: "/var/log/packet-monitor/otel.jsonl"
```

---

### gRPC сервер (reflection) “двойной TLS”, upstream verify=true + CA

```yaml
listeners:
  - name: grpc-reflection
    listen: "0.0.0.0:9100"
    tls:
      cert: "/opt/nginc/certs/nginx_cert.crt"
      key:  "/opt/nginc/certs/nginx_cert.key"
      require_client_cert: false
      client_ca: null
      alpn: ["h2", "http/1.1"]
      min_version: "TLS1.2"

    upstream:
      addr: "127.0.0.1:50052"
      tls: true
      alpn: ["h2"]
      server_name: "localhost"
      verify: true
      ca: "/opt/nginc/certs/ca.crt"

    policy:
      allowlist: ["0.0.0.0/0"]
      max_connections: 200

    logging:
      log_headers: true
      log_body: true
      body_max_bytes: 65536
      redact_headers: ["authorization", "cookie", "x-api-key"]
      sample_rate: 1.0
      jsonl_path: null
```

---

### Inbound mTLS (клиент должен предъявить сертификат)

```yaml
listeners:
  - name: inbound-mtls-grpc
    listen: "0.0.0.0:9444"
    tls:
      cert: "/opt/certs/proxy-server.crt"
      key:  "/opt/certs/proxy-server.key"
      require_client_cert: true
      client_ca: "/opt/certs/client-ca.crt"
      alpn: ["h2", "http/1.1"]
      min_version: "TLS1.2"

    upstream:
      addr: "127.0.0.1:50052"
      tls: false
      alpn: ["h2"]

    policy:
      allowlist: ["10.0.0.0/8"]
      max_connections: 200

    logging:
      log_headers: true
      log_body: false
      body_max_bytes: 8192
      redact_headers: ["authorization", "cookie", "x-api-key"]
      sample_rate: 1.0
      jsonl_path: null
```

---

### Outbound mTLS (proxy предъявляет client cert upstream)

```yaml
listeners:
  - name: outbound-mtls-to-upstream
    listen: "0.0.0.0:9101"
    tls:
      cert: "/opt/certs/proxy.crt"
      key:  "/opt/certs/proxy.key"
      require_client_cert: false
      client_ca: null
      alpn: ["h2", "http/1.1"]
      min_version: "TLS1.2"

    upstream:
      addr: "127.0.0.1:50052"
      tls: true
      alpn: ["h2"]
      server_name: "upstream.local"
      verify: true
      ca: "/opt/certs/upstream-ca.crt"
      client_cert: "/opt/certs/proxy-client.crt"
      client_key:  "/opt/certs/proxy-client.key"
      client_key_password: null

    policy:
      allowlist: ["0.0.0.0/0"]
      max_connections: 200

    logging:
      log_headers: true
      log_body: true
      body_max_bytes: 16384
      redact_headers: ["authorization", "cookie", "x-api-key"]
      sample_rate: 1.0
      jsonl_path: "/var/log/packet-monitor/mtls.jsonl"
```

---

### Nginx HTTPS health endpoint (h2/http1) — просто наблюдать, upstream TLS

```yaml
listeners:
  - name: nginx-health
    listen: "0.0.0.0:9102"
    tls:
      cert: "/opt/nginc/certs/nginx_cert.crt"
      key:  "/opt/nginc/certs/nginx_cert.key"
      require_client_cert: false
      client_ca: null
      alpn: ["h2", "http/1.1"]
      min_version: "TLS1.2"

    upstream:
      addr: "127.0.0.1:9443"
      tls: true
      alpn: ["h2", "http/1.1"]
      server_name: "localhost"
      verify: false
      ca: "/opt/nginc/certs/ca.crt"

    policy:
      allowlist: ["192.168.0.0/16"]
      max_connections: 200

    logging:
      log_headers: true
      log_body: true
      body_max_bytes: 8192
      redact_headers: ["authorization", "cookie", "x-api-key"]
      sample_rate: 1.0
      jsonl_path: null
```

---

## Рекомендации по “правильному” режиму для gRPC/otel

**Для OTLP/gRPC:**

* Везде старайся явно держать `alpn: ["h2"]` на upstream (чтобы не было случайного downgrade).
* На входе: `["h2","http/1.1"]` (потому что curl и другие любят “предложить оба”).

**Если подозрение на CA/SNI:**

* сначала временно `verify: false`,
* убедись, что проксирование вообще работает,
* потом включай verify и подбирай `ca`/`server_name`.

---

## HTTP/2 error_code: расшифровка и практические причины

### Для GOAWAY и RST_STREAM используются коды ошибок HTTP/2

На практике в troubleshooting важно не “официальное определение”, а что это обычно значит в проде.

> Примечание: в UI лучше смотреть рядом **что происходило до** (SETTINGS/headers/data) и **есть ли TLS/ALPN проблемы**.

### Таблица кодов (наиболее полезные)

| Код | Имя                 | Где        | Что обычно означает в реальности                                      | Что искать в Traffic                                                          |
| --: | ------------------- | ---------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| 0x0 | NO_ERROR            | GOAWAY/RST | “Нормальное завершение” (в GOAWAY часто graceful shutdown)            | `GOAWAY` после ответа, балансер/сервер завершает conn                         |
| 0x1 | PROTOCOL_ERROR      | GOAWAY/RST | Несовместимость/ошибка протокола: неожиданные кадры, плохие заголовки | перед этим: странные HEADERS/пересылка hop-by-hop, нарушение состояния стрима |
| 0x2 | INTERNAL_ERROR      | GOAWAY/RST | Серверная ошибка/исключение в реализации                              | `grpc-status` может отсутствовать; часто `EOF` на клиенте                     |
| 0x3 | FLOW_CONTROL_ERROR  | GOAWAY/RST | Проблемы с окнами: отправили больше чем можно/окно рассинхронено      | `FLOW_BLOCK`, нет `WINDOW_UPDATE`, большие DATA                               |
| 0x4 | SETTINGS_TIMEOUT    | GOAWAY     | Не дождались SETTINGS ACK                                             | есть SETTINGS, но нет ACK; или задержки/потери                                |
| 0x5 | STREAM_CLOSED       | RST        | Кадр пришёл на закрытый стрим                                         | ретраи/гонки, повторная отправка DATA после END_STREAM                        |
| 0x6 | FRAME_SIZE_ERROR    | GOAWAY/RST | Размер фрейма невалиден                                               | upstream/клиент баг или middlebox                                             |
| 0x7 | REFUSED_STREAM      | RST        | Сервер отказался обслуживать стрим (часто из-за нагрузки)             | много параллельных стримов, сервер лимитирует                                 |
| 0x8 | CANCEL              | RST        | Отмена (часто клиент отменил или дедлайн)                             | коррелирует с deadline/cancel на клиенте                                      |
| 0x9 | COMPRESSION_ERROR   | GOAWAY/RST | Ошибка HPACK (сжатие заголовков)                                      | редкий, но бывает при несовместимости/баге                                    |
| 0xA | CONNECT_ERROR       | GOAWAY/RST | Ошибка на CONNECT (прокси-режим), редко в gRPC                        | чаще в специфичных прокси сценариях                                           |
| 0xB | ENHANCE_YOUR_CALM   | GOAWAY/RST | “Слишком много” (rate-limit/защита)                                   | всплеск запросов, балансер режет                                              |
| 0xC | INADEQUATE_SECURITY | GOAWAY     | Неприемлемая безопасность (ciphers/TLS)                               | смотри `tls out`/`tls in` и минимальные версии                                |
| 0xD | HTTP_1_1_REQUIRED   | GOAWAY     | Требуют HTTP/1.1 (не хотят h2)                                        | часто ALPN/h2 конфликт, upstream не поддерживает h2                           |

### Типовые “связки” симптом → control-событие

* Клиент: `Unavailable: EOF` → часто `GOAWAY(INTERNAL_ERROR)` или `RST_STREAM(INTERNAL_ERROR)`
* Клиент: `deadline exceeded` → часто `FLOW_BLOCK` + отсутствие `WINDOW_UPDATE`, либо server “подвис”
* Nginx: `"PRI * HTTP/2.0" 400` → вообще не поднялся h2; ALPN/порт/конфиг

---

## ALPN/h2 чек-лист: как быстро понять, где “сломалось”

### Минимальные признаки “h2 реально включился”

На **входе** (client→proxy):

* В `tls(in)` событии: `alpn=h2`
* В `h2ctl`: есть `SETTINGS` от клиента и `SETTINGS` от прокси + `ACK`

На **выходе** (proxy→upstream), если upstream тоже h2:

* В `tls(out)` событии: `alpn=h2`
* В `h2ctl`: `SETTINGS` от upstream

Если ты видишь `tls ok`, но ALPN `http/1.1`, а потом “вдруг” приходят байты `PRI * HTTP/2.0` — это почти всегда:

* клиент пытался говорить h2 “вручную” не через ALPN, или
* middlebox неправильно маршрутизирует, или
* порт upstream не тот (h2 не там).

### Частые ALPN грабли

1. **Upstream не объявляет h2** (или объявляет только http/1.1)
   → `tls(out) alpn=http/1.1`, а потом gRPC ломается.

2. **SNI не тот** (upstream выбирает не тот сертификат/виртхост)
   → `tls(out) fail cert_verify_failed` или `handshake_failure`.

3. **verify=true и не задан ca** (self-signed/частная CA)
   → `tls(out) fail unknown_ca`.

4. **mTLS**: upstream ждёт client cert, proxy не отправляет
   → `tls(out) fail bad_certificate/handshake_failure`.

###  “Быстрая диагностика одним взглядом”

* Включи фильтр: `proto=tls` → сразу видно in/out ok/fail
* Затем фильтр: `proto=h2ctl` → SETTINGS/GOAWAY/RST/FLOW_BLOCK
* Затем фильтр: `proto=grpc` → grpc-status, grpc-message

---

## Вставить wiretracer “в разрыв”, когда порт уже занят (iptables)

очень типичный кейс: **порт занят самим сервисом**, но нельзя его просто перенести, потому что соседи узнают/переконфигурируются (как у sentinel).

### Базовая идея 

* **Входящие** подключения на `:26379` перенаправить на порт wiretracer (например `:16379`)
* wiretracer слушает `:16379`, а **upstream** у него `127.0.0.1:26379` (тот самый локальный sentinel)
* Клиенты по-прежнему стучатся в `:26379` и ничего не знают

Это работает именно потому, что на машине с sentinel ты можешь перехватить входящий трафик локально.

---

### Вариант 1: REDIRECT (самый простой, для локального порта)

Подходит, если wiretracer и сервис на **одной машине**, и тебе нужно перехватить трафик, приходящий на локальный порт.

Пример: сервис слушает `26379`, wiretracer будет слушать `16379`.

1. wiretracer слушает `16379`, upstream → `127.0.0.1:26379`
2. Перехват входящих на `26379` и редирект на `16379`:

```bash
# Входящие TCP на 26379 перенаправить на 16379
iptables -t nat -A PREROUTING -p tcp --dport 26379 -j REDIRECT --to-ports 16379
```

**Проверка правил:**

```bash
iptables -t nat -L PREROUTING -n -v --line-numbers
```

**Откат (удаление по номеру строки):**

```bash
iptables -t nat -D PREROUTING <N>
```

> Примечание: PREROUTING работает для пакетов, входящих извне. Если тебе нужно также перехватывать локальные подключения с этой же машины на `localhost:26379`, нужен OUTPUT (см. ниже).

---

### Вариант 2: Перехват локальных клиентов (OUTPUT REDIRECT)

Если какие-то клиенты на той же машине подключаются к `127.0.0.1:26379` или `localhost:26379`.

```bash
iptables -t nat -A OUTPUT -p tcp -o lo --dport 26379 -j REDIRECT --to-ports 16379
```

---

### Вариант 3: DNAT на конкретный адрес (когда нужен точный контроль)

Если нужно перенаправить не на “локальный” REDIRECT, а на конкретный IP:port (например, в docker namespace или другой интерфейс).

```bash
iptables -t nat -A PREROUTING -p tcp --dport 26379 -j DNAT --to-destination 127.0.0.1:16379
```

(Здесь тоже фактически на локалхост, но можно указать и другой адрес.)

---

### Docker / контейнеры (важное замечание)

Если sentinel/redis в контейнере:

* iptables может применяться на хосте, но трафик может “уходить” через docker bridge правила.
* Иногда проще:

  * запускать wiretracer в том же network namespace,
  * или делать DNAT на IP контейнера,
  * или использовать docker-proxy / publish ports аккуратно.


