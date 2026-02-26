## FAQ

### Q1: Why do `tls` and `h2ctl` lines appear in Traffic? Is that “extra noise”?

No. This is the main value for gRPC/HTTP2/TLS troubleshooting. Most real incidents are not in the “request itself”, but in handshake/ALPN/GOAWAY/RST/flow-control.

---

### Q2: Why does the gRPC body look binary?

Because gRPC payload is protobuf. Human-readable UTF-8 is uncommon there. That is why wiretracer shows:

* **gRPC frame structure**
* `hexdump+ascii`
* `strings` for quick search of readable fragments (for example `NOAUTH`).

---

### Q3: Does wiretracer store the “full body”?

It proxies the full stream, but **UI capture is limited** by `body_max_bytes` and a hard limit. This is intentional, to avoid memory blowups on large payloads.

---

### Q4: How do I enable inbound mTLS?

In the listener:

```yaml
tls:
  require_client_cert: true
  client_ca: /path/to/client-ca.crt
```

Then watch Traffic for `tls in fail bad_certificate` / `unknown_ca`.

---

### Q5: How do I enable outbound mTLS (proxy -> upstream)?

In `upstream`:

```yaml
upstream:
  tls: true
  client_cert: /path/to/proxy-client.crt
  client_key: /path/to/proxy-client.key
```

---

### Q6: Why is upstream verification disabled (`verify: false`), and is that “bad”?

For troubleshooting it is often useful because it quickly eliminates CA-chain issues. In production, prefer `verify: true` and `ca: ...`.

---

### Q7: What happens in headless mode?

wiretracer runs, accepts connections, writes entries to the store (and optionally JSONL), but **without UI**. This mode is for services/daemons.

---

## Practical advice for real operations

1. For gRPC, almost always:

* listener `tls.alpn: ["h2","http/1.1"]`
* upstream `alpn: ["h2"]`

2. For initial diagnostics, you can temporarily set:

* upstream `verify: false`
  then switch back and configure `ca`.

3. For large bodies:

* keep `body_max_bytes` in the 8–64KB range; otherwise UI becomes heavier.

4. Enable `jsonl_path` if you need after-the-fact history:

* then you can grep for `GOAWAY`, `RST_STREAM`, `tls fail`.

---

Guide addendum: **gRPC common error map** (grpc-status <-> causes <-> which H2/TLS events to look for) + **ready config templates**
for common cases (otel-collector, grpc server/reflection, nginx/h2, inbound/outbound mTLS, “double TLS”).

---

## Common gRPC error map and what to look for in Traffic

### Where to start (quick checklist)

If the client sees `EOF`, `Unavailable`, `deadline exceeded`:

1. Find a nearby **tls(in)** event in Traffic.

   * If `tls in fail` -> problem on inbound side (client->proxy): CA, mTLS, ALPN, TLS version.
2. Find **tls(out)**.

   * If `tls out fail` -> problem on outbound side (proxy->upstream): verify/SNI/CA/mTLS.
3. If both TLS sides are ok, check for **h2ctl SETTINGS**:

   * If SETTINGS are missing from one side -> HTTP/2 setup failed (ALPN/h2 did not come up).
4. Then inspect **h2ctl GOAWAY / RST_STREAM / FLOW_BLOCK** around the failure time.

---

### grpc-status -> causes -> what to inspect

> Important: grpc-status can be in **trailers** (at the end), not headers. So it is useful to see both **h2ctl** and **gRPC events**.

#### grpc-status = 0 (OK), but the client still complains

**Symptoms:**

* Client shows `error reading from server: EOF`, even though a response seemed to arrive.

**Common causes:**

* upstream closed the connection right after response, client expected more (rare),
* issue is not RPC-level, but transport-level (H2).

**Look for:**

* `h2ctl GOAWAY` right after response,
* `RST_STREAM` on another stream in the same connection.

---

#### grpc-status = 2 (UNKNOWN)

**Most often:**

* server-side exception not mapped correctly,
* proxy/load balancer failure.

**Look for:**

* `h2ctl RST_STREAM` (especially INTERNAL_ERROR),
* `h2ctl GOAWAY` with debug data,
* `grpc-message` in response headers (often empty).

---

#### grpc-status = 3 (INVALID_ARGUMENT)

**Cause:**

* invalid request / protobuf / arguments.

**Look for:**

* request body details (gRPC frames + strings) often show which argument is wrong,
* `grpc-message`.

---

#### grpc-status = 7 (PERMISSION_DENIED)

**Cause:**

* authorization/ACL denial.

**Look for:**

* request metadata (authorization/token) - redaction may hide it,
* `grpc-message`.

---

#### grpc-status = 13 (INTERNAL)

**Causes:**

* application error,
* handler crash,
* sometimes protobuf serialization/deserialization issues.

**Look for:**

* `grpc-message`,
* nearby `RST_STREAM` or `GOAWAY`.

---

#### grpc-status = 14 (UNAVAILABLE) - the most common in troubleshooting

**Causes:**

* network/load-balancer/upstream unavailable,
* TLS/ALPN mismatch,
* upstream drops h2 connection,
* timeouts.

**First things to inspect:**

* `tls out fail` (`cert_verify_failed`, `unknown_ca`, `bad_certificate`, `handshake_failure`),
* `h2ctl GOAWAY` (often `ENHANCE_YOUR_CALM`, `PROTOCOL_ERROR`, `INTERNAL_ERROR`),
* `h2ctl RST_STREAM` (`CANCEL`/`INTERNAL_ERROR`),
* `FLOW_BLOCK`/window==0 (can look like timeout/deadline).

---

#### grpc-status = 16 (UNAUTHENTICATED)

**Causes:**

* wrong credentials/token,
* server requires auth metadata.

**Look for:**

* `grpc-message` (sometimes “missing auth token”),
* request headers/metadata.

---

#### grpc-status is absent, and client gets EOF/RESET

**Causes:**

* trailers were never delivered (connection dropped),
* transport error.

**Look for:**

* `h2ctl RST_STREAM` (especially if it happened on this stream_id),
* `h2ctl GOAWAY`,
* TLS events/errors.

---

### What key H2 control events mean (practically)

#### SETTINGS / SETTINGS_ACK

**Why:** verify both sides actually understood each other.

* If client offered h2 (ALPN) but SETTINGS are absent -> HTTP/2 never started.
* If upstream sends odd settings (very large/small windows), this can indicate flow-control trouble.

#### GOAWAY

It often explains why everything suddenly died.

* Check `code`, `last_stream_id`, `debug data`.
* If GOAWAY appears right after connect, suspect ALPN/protocol/policy mismatch.

#### RST_STREAM

Reset of a specific stream:

* `CANCEL` - cancellation, often due to deadline/client cancel,
* `INTERNAL_ERROR`/`PROTOCOL_ERROR` - usually bug/incompatibility.

#### WINDOW_UPDATE / FLOW_BLOCK

If window becomes 0, one side cannot send more data:

* client side can look like a hang followed by `deadline exceeded`.

---

## Diagnostic cheatsheets by symptom

### `grpcurl ... list` -> `context deadline exceeded`

1. Check `tls(in)` is ok.
2. Check `tls(out)` is ok.
3. There should be `h2ctl SETTINGS` in both directions.
4. If SETTINGS exist but no response:

   * look for `FLOW_BLOCK` / missing `WINDOW_UPDATE`,
   * look for `GOAWAY`/`RST_STREAM`.

---

### Client shows `Unavailable: error reading from server: EOF`

Most often:

* upstream sent `GOAWAY` and closed,
* or `RST_STREAM` on the stream.

**Inspect:**

* `h2ctl GOAWAY`,
* `h2ctl RST_STREAM`,
* `tls out ok/fail` - if fail, it is TLS.

---

### Nginx logs `"PRI * HTTP/2.0" 400`

Meaning: Nginx received HTTP/2 preface but did not expect h2 on that endpoint.
**Inspect:**

* was ALPN negotiated? (TLS events)
* are there any `h2ctl SETTINGS` at all?

---

## Ready config templates (copy-paste)

Examples below are **multi-listener** configs. One proxy can serve multiple services.

---

### OTEL Collector (gRPC OTLP) “double TLS”, upstream with verify=false (quick CA elimination)

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

### gRPC server (reflection) “double TLS”, upstream verify=true + CA

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

### Inbound mTLS (client must present a certificate)

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

### Outbound mTLS (proxy presents client cert to upstream)

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

### Nginx HTTPS health endpoint (h2/http1) - observe only, upstream TLS

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

## Recommended “correct” mode for gRPC/OTel

**For OTLP/gRPC:**

* Keep `alpn: ["h2"]` explicitly on upstream whenever possible (to avoid accidental downgrade).
* On inbound side use `["h2","http/1.1"]` (many clients offer both).

**If you suspect CA/SNI issues:**

* first temporarily set `verify: false`,
* confirm proxying works at all,
* then enable verify and tune `ca`/`server_name`.

---

## HTTP/2 error_code: decoding and practical causes

### GOAWAY and RST_STREAM use HTTP/2 error codes

For troubleshooting, practical meaning matters more than formal spec wording.

> Note: in UI, inspect what happened **right before** (SETTINGS/headers/data) and whether there are TLS/ALPN issues.

### Code table (most useful)

| Code | Name                | Where      | Typical practical meaning                                          | What to inspect in Traffic                                                   |
| ---: | ------------------- | ---------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| 0x0  | NO_ERROR            | GOAWAY/RST | “Normal shutdown” (in GOAWAY often graceful shutdown)              | `GOAWAY` after response, balancer/server closes conn                         |
| 0x1  | PROTOCOL_ERROR      | GOAWAY/RST | Protocol mismatch/error: unexpected frames, invalid headers        | before that: odd HEADERS/hop-by-hop forwarding/state violations             |
| 0x2  | INTERNAL_ERROR      | GOAWAY/RST | Server-side failure/exception in implementation                    | `grpc-status` may be absent; client often sees `EOF`                        |
| 0x3  | FLOW_CONTROL_ERROR  | GOAWAY/RST | Window issues: sent more than allowed / window desync              | `FLOW_BLOCK`, no `WINDOW_UPDATE`, large DATA                                |
| 0x4  | SETTINGS_TIMEOUT    | GOAWAY     | SETTINGS ACK not received                                          | SETTINGS exists but no ACK; or latency/loss                                 |
| 0x5  | STREAM_CLOSED       | RST        | Frame received on closed stream                                    | retries/races, DATA resent after END_STREAM                                 |
| 0x6  | FRAME_SIZE_ERROR    | GOAWAY/RST | Invalid frame size                                                 | upstream/client bug or middlebox                                             |
| 0x7  | REFUSED_STREAM      | RST        | Server refused to serve stream (often load related)                | many concurrent streams, server limits                                       |
| 0x8  | CANCEL              | RST        | Cancellation (often client cancel or deadline)                     | correlates with client deadline/cancel                                       |
| 0x9  | COMPRESSION_ERROR   | GOAWAY/RST | HPACK compression error                                             | rare, but possible with incompatibility/bug                                 |
| 0xA  | CONNECT_ERROR       | GOAWAY/RST | CONNECT-mode error, uncommon in gRPC                               | more common in specific proxy scenarios                                      |
| 0xB  | ENHANCE_YOUR_CALM   | GOAWAY/RST | “Too much” (rate-limit/protection)                                 | request spike, balancer throttles                                            |
| 0xC  | INADEQUATE_SECURITY | GOAWAY     | Unacceptable security (ciphers/TLS)                                | inspect `tls out`/`tls in` and minimum versions                              |
| 0xD  | HTTP_1_1_REQUIRED   | GOAWAY     | Peer requires HTTP/1.1 (does not accept h2)                        | often ALPN/h2 conflict, upstream does not support h2                         |

### Typical symptom -> control-event pairs

* Client: `Unavailable: EOF` -> often `GOAWAY(INTERNAL_ERROR)` or `RST_STREAM(INTERNAL_ERROR)`
* Client: `deadline exceeded` -> often `FLOW_BLOCK` + missing `WINDOW_UPDATE`, or server stall
* Nginx: `"PRI * HTTP/2.0" 400` -> h2 never established; ALPN/port/config issue

---

## ALPN/h2 checklist: quickly locate where it failed

### Minimum signs that h2 is actually enabled

On **inbound** (client->proxy):

* In `tls(in)` event: `alpn=h2`
* In `h2ctl`: client `SETTINGS` and proxy `SETTINGS` + `ACK`

On **outbound** (proxy->upstream), when upstream is h2:

* In `tls(out)` event: `alpn=h2`
* In `h2ctl`: `SETTINGS` from upstream

If TLS is ok but ALPN is `http/1.1`, and then you suddenly see bytes like `PRI * HTTP/2.0`, it usually means:

* client tried to force h2 without ALPN, or
* middlebox routed incorrectly, or
* wrong upstream port (h2 is not there).

### Common ALPN pitfalls

1. **Upstream does not advertise h2** (or advertises only http/1.1)
   -> `tls(out) alpn=http/1.1`, then gRPC fails.

2. **Wrong SNI** (upstream picks wrong cert/vhost)
   -> `tls(out) fail cert_verify_failed` or `handshake_failure`.

3. **verify=true without `ca`** (self-signed/private CA)
   -> `tls(out) fail unknown_ca`.

4. **mTLS**: upstream expects client cert, proxy does not send one
   -> `tls(out) fail bad_certificate/handshake_failure`.

### “One-glance” quick diagnostics

* Filter by `proto=tls` -> immediately see in/out ok/fail
* Then filter by `proto=h2ctl` -> SETTINGS/GOAWAY/RST/FLOW_BLOCK
* Then filter by `proto=grpc` -> grpc-status, grpc-message

---

## Insert wiretracer inline when the port is already occupied (iptables)

Very common case: **port is already occupied by the service**, but you cannot move it because neighboring systems depend on it.

### Basic idea

* Redirect inbound connections to `:26379` to wiretracer port (for example `:16379`)
* wiretracer listens on `:16379`, and uses `127.0.0.1:26379` as upstream (the local service)
* Clients still connect to `:26379` and do not need changes

This works because on the service host you can intercept inbound traffic locally.

---

### Option 1: REDIRECT (simplest, for local port)

Use when wiretracer and service are on the **same machine**, and you need to intercept traffic coming to a local port.

Example: service listens on `26379`, wiretracer will listen on `16379`.

1. wiretracer listens on `16379`, upstream -> `127.0.0.1:26379`
2. Intercept inbound `26379` and redirect to `16379`:

```bash
# Redirect inbound TCP on 26379 to 16379
iptables -t nat -A PREROUTING -p tcp --dport 26379 -j REDIRECT --to-ports 16379
```

**Check rules:**

```bash
iptables -t nat -L PREROUTING -n -v --line-numbers
```

**Rollback (delete by rule number):**

```bash
iptables -t nat -D PREROUTING <N>
```

> Note: PREROUTING handles packets arriving from outside. If you also need to intercept local connections from the same host to `localhost:26379`, use OUTPUT (see below).

---

### Option 2: Intercept local clients (OUTPUT REDIRECT)

If some clients on the same host connect to `127.0.0.1:26379` or `localhost:26379`.

```bash
iptables -t nat -A OUTPUT -p tcp -o lo --dport 26379 -j REDIRECT --to-ports 16379
```

---

### Option 3: DNAT to a specific address (for precise control)

Use when you need to redirect to an explicit IP:port (for example, docker namespace or another interface).

```bash
iptables -t nat -A PREROUTING -p tcp --dport 26379 -j DNAT --to-destination 127.0.0.1:16379
```

(Here it still targets localhost, but any other address can be used.)

---

### Docker / containers (important note)

If sentinel/redis is in a container:

* iptables may be applied on host, but traffic can pass through docker bridge rules.
* Sometimes it is easier to:

  * run wiretracer in the same network namespace,
  * or DNAT to container IP,
  * or use docker-proxy / published ports carefully.
