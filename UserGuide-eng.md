# wiretracer - User Guide

## Table of Contents
- [1. What It Is](#1-what-it-is)
- [2. Key Features](#2-key-features)
- [3. How the Proxy Works](#3-how-the-proxy-works)
- [4. Quick Start](#4-quick-start)
- [5. Configuration (YAML)](#5-configuration-yaml)
- [6. PROXY Protocol: How to Use](#6-proxy-protocol-how-to-use)
- [7. HTTP/2 and gRPC Diagnostics](#7-http2-and-grpc-diagnostics)
- [8. Typical Usage Scenarios](#8-typical-usage-scenarios)
- [9. Operational Recommendations](#9-operational-recommendations)
- [10. New Scenarios (Current Version)](#10-new-scenarios-current-version)
- [11. Useful Commands](#11-useful-commands)
- [12. Related Documents](#12-related-documents)

## 1. What It Is
`wiretracer` is a TLS-terminating diagnostic L7 proxy for HTTP/1.1, HTTP/2, and gRPC.

Main goals:
- observe and inspect request/response traffic;
- diagnose TLS/ALPN/mTLS issues;
- analyze HTTP/2 control events (`SETTINGS`, `RST_STREAM`, `GOAWAY`, `WINDOW_UPDATE`);
- support headless JSONL mode for automated validation.

## 2. Key Features
- Supported protocols: `http1`, `http2`, `grpc`.
- Run modes:
  - `TUI` (interactive UI);
  - `headless` (JSONL logging).
- Incoming and outgoing TLS/mTLS.
- Incoming PROXY protocol auto-detection:
  - no PROXY;
  - PROXY v1;
  - PROXY v2;
  - malformed header (diagnostic with explicit reason).
- PROXY protocol forwarding to upstream:
  - if incoming PROXY is present, upstream connection uses the same PROXY protocol version.
- Extended connection telemetry:
  - `proxy_version`, `proxy_src`, `proxy_dst` in `conn open/close`, Details, and JSONL.
- HTTP/2 fingerprint telemetry:
  - per-side and combined `h2fp` values in Connections/Details.
- Inbound TLS fingerprint telemetry (before TLS upgrade):
  - `JA3`, `JA4`, `ECH` presence/length, legacy `ESNI` presence.

## 3. How the Proxy Works
1. Accepts incoming TCP/TLS connection on listener.
2. Before inbound TLS handshake, attempts to detect PROXY protocol (v1/v2/none).
3. If PROXY is found, applies source/destination endpoint to connection data.
4. Terminates inbound TLS (L7 mode is preserved).
5. Opens upstream connection:
   - plain or TLS/mTLS based on listener config;
   - if incoming PROXY exists, sends the same PROXY header upstream.
6. Proxies HTTP/1.1 or HTTP/2/gRPC and logs handshake/control/events.

Important: PROXY protocol support does not switch proxy to L4 pass-through. It remains an L7 MITM diagnostic node.

## 4. Quick Start
### 4.1 Dependencies
Minimum:
- Python 3.11+;
- `urwid`, `PyYAML`, `h2`.

Optional for native gRPC tests:
- `grpcio`.

### 4.2 Generate Example Config
```bash
python3 wiretracer.py --gen-config > config.yaml
```

### 4.3 Validate Config
```bash
python3 wiretracer.py --config config.yaml --check
```

### 4.4 Run
TUI:
```bash
python3 wiretracer.py --config config.yaml
```

Headless:
```bash
python3 wiretracer.py --config config.yaml --headless
```

## 5. Configuration (YAML)
Listener structure:
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

## 6. PROXY Protocol: How to Use
### 6.1 What Is Supported
- Input: auto-detect `none/v1/v2` on any listener.
- Output: if PROXY was present on input, the same `raw` header is sent upstream.
- Malformed PROXY parsing errors:
  - connection closes with `close_reason=proxy_protocol_error`.

### 6.2 What You See in Logs and UI
In `conn` events:
- `proxy_version` (`none`, `v1`, `v2`, `invalid`),
- `proxy_src` (`ip:port`),
- `proxy_dst` (`ip:port`).

In TUI:
- Traffic/Connections: `pp=... src=... dst=...`;
- Details: separate lines `PROXY(in)`, `PROXY src`, `PROXY dst`.

### 6.3 Useful Filters
- `proxy=v1`
- `proxy=v2`
- `proxy=none`
- `proxy_src=203.0.113.10`
- `listener=grpc-exporter proto=grpc`

## 7. HTTP/2 and gRPC Diagnostics
### 7.1 Event Types
- `proto=tls` - inbound/outbound handshake and fail reasons; inbound side includes ClientHello fingerprints (`JA3/JA4/ECH/ESNI`) when available;
- `proto=h2ctl` - control frames, flow-control diagnostics, and `FINGERPRINT` markers for H2 profile;
- `proto=grpc|http2|http1` - request/response events.

### 7.1.1 Visual Error Indication in TUI
- `Traffic view`:
  - error rows are highlighted (e.g. `tls fail`, `conn close` with `*_fail/*_error/*_timeout/*_rst`, `event` with `error`/`5xx`);
  - warn rows are highlighted separately for selected `h2ctl` events (`GOAWAY`, `RST_STREAM`, `FLOW_BLOCK`).
- `Connections view`:
  - error rows are highlighted based on connection state;
  - `Errs` column shows per-connection error counter (`last_error` / problematic close-reason/flags);
  - for closed connections, `Idle` is frozen at `closed_ts` and does not continue increasing.

### 7.2 Important Practical Notes
- `event.duration_ms` = duration of a specific RPC/HTTP request.
- `conn.duration_ms` = full TCP/TLS connection lifetime.

So this is normal: gRPC response is fast, while `conn.duration_ms` is ~30s (client keeps h2 keep-alive and closes later).

## 8. Typical Usage Scenarios
- Troubleshooting `grpcurl` (`EOF`, `Unavailable`, `deadline exceeded`).
- ALPN/h2 validation (`no_application_protocol`, `wrong version`).
- mTLS validation (client->proxy and proxy->upstream).
- Root cause analysis for `RST_STREAM`/`GOAWAY`.
- Real client IP diagnostics in L4/L7 chains via PROXY protocol.

## 9. Operational Recommendations
- In production, use `upstream.verify=true` and proper `ca`.
- Limit `body_max_bytes` for high-load systems.
- For high-throughput services, use `sample_rate < 1.0`.
- For problematic clients, start with filters:
  - `proto=tls outcome=fail`
  - `proto=h2ctl`
  - `proto=grpc error=1`
  - `ja3=<md5>`
  - `ja4=t13d...`
  - `ech=1`
  - `h2fp=h2fp1:...`

## 10. New Scenarios (Current Version)
- One listener can accept mixed traffic: clients with PROXY and without PROXY.
- `PROXY + TLS + HTTP/2` and `PROXY + TLS + gRPC` are supported and covered by tests.
- Two gRPC test approaches are available:
  - h2 emulation with gRPC headers (`fault_client --proto grpc`), including PROXY v1/v2;
  - native grpcio client/server (`--proto grpc_native`) for "real" RPC.

## 11. Useful Commands
Check gRPC upstream directly:
```bash
grpcurl -insecure -import-path ./test-suite -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:50052 helloworld.Greeter/SayHello
```

Check through `grpc-exporter` listener:
```bash
grpcurl -insecure -import-path ./test-suite -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:9101 helloworld.Greeter/SayHello
```

## 12. Related Documents
- `README.md` - short English overview for GitHub.
- `README-rus.md` - short Russian overview for GitHub.
- `test-suite/TEST_SUITE_GUIDE_RUS.md` - detailed test-suite guide.
