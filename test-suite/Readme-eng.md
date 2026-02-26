# wiretracer Test Kit (EN)

## Table of Contents
- [Overview](#overview)
- [Components](#components)
- [What Is Covered](#what-is-covered)
- [Quick Start](#quick-start)
- [Manual Checks](#manual-checks)
- [Result Interpretation](#result-interpretation)
- [References](#references)

## Overview
This test kit validates `wiretracer` end-to-end behavior for:
- HTTP/1.1, HTTP/2, and gRPC traffic;
- TLS and mTLS scenarios;
- PROXY protocol (`none`, `v1`, `v2`, malformed);
- JSONL observability correctness.

## Components
- `fault_client.py` — traffic generator (`http1`, `h2`, `grpc`, `grpc_native`).
- `fault_server.py` — upstream simulator:
  - TLS server (`:19443`),
  - mTLS server (`:29443`),
  - plain server (`:18480`) with optional PROXY header parsing,
  - native gRPC TLS server (`:50052`, when `grpcio` is installed).
- `run_proxy_test_suite.sh` — full orchestrator.
- `verify_headless.py` — post-run JSONL verifier.
- `helloworld.proto` — proto file for grpcurl/native gRPC checks.

## What Is Covered
- Happy-path:
  - `h1_chat5`, `h2_chat5`, `grpc_chat3`.
- PROXY protocol:
  - `proxy_none_*`, `proxy_v1_*`, `proxy_v2_*`, malformed header handling.
- Negative upstream behavior:
  - `hang`, `close_early`, `truncate`, `rst`, `sleep_headers`.
- Negative client behavior:
  - `client_close_early`, `client_rst`, `client_half_close`.
- mTLS:
  - client cert required/absent/invalid;
  - upstream handshake failures.
- Optional native grpcio checks via `grpc-exporter` listener (`:9101`).

## Quick Start
From `test-suite/`:

1. Start upstream:
```bash
python3 ./fault_server.py --certs ./certs
```

2. Start proxy (separate terminal):
```bash
python3 ../wiretracer.py --config ../config.yaml --headless
```

3. Run suite:
```bash
bash ./run_proxy_test_suite.sh
```

If proxy is already running:
```bash
bash ./run_proxy_test_suite.sh --no-proxy
```

## Manual Checks
grpcurl direct to native upstream (`:50052`) from `test-suite/`:
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:50052 helloworld.Greeter/SayHello
```

grpcurl through proxy listener (`grpc-exporter`, `:9101`):
```bash
grpcurl -insecure -import-path . -proto helloworld.proto \
  -d '{"name":"proxy"}' 127.0.0.1:9101 helloworld.Greeter/SayHello
```

## Result Interpretation
- `event.duration_ms`: request/RPC latency.
- `conn.duration_ms`: full connection lifetime.

A fast gRPC response plus `conn.duration_ms ~ 30s` is usually normal keep-alive behavior.

## References
- Full Russian test guide: `test-suite/TEST_SUITE_GUIDE_RUS.md`
- Main user guide (RU): `UserGuide.md`
- Repo-level READMEs:
  - `README.md`
  - `README-rus.md`


