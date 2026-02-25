## wiretracer Use Cases

### Case A: Javaagent OpenTelemetry Does Not Export Traces

**Symptom:**
- the agent logs `export failed`, `deadline exceeded`, `UNAVAILABLE`;
- the server is "alive", but traces do not reach the collector.

**What we do:**
1. Put `wiretracer` in front of the collector/ingest endpoint.
2. Enable in listener:
   - `tls.alpn: [h2, http/1.1]`
   - for gRPC upstream: `upstream.alpn: [h2]`
3. In Traffic, check:
   - `tls out fail no_application_protocol` (no negotiated h2),
   - `h2ctl GOAWAY` / `RST_STREAM`,
   - `grpc-status` in response headers.

**Typical root causes:**
- upstream actually accepts only `http/1.1`;
- `SNI/CA/verify` mismatch;
- upstream expects an mTLS client cert, but proxy does not present one.

---

### Case B: Redis Sentinel Over TLS Cannot Reach Quorum

**Situation:**
Sentinels can see Redis, but Sentinel peer-to-peer interaction breaks.

**What wiretracer gives you:**
- TLS is successful on both sides (`tls in ok`, `tls out ok`);
- this means the issue is above TLS, e.g. auth (`NOAUTH`) or ACL;
- you can quickly separate network/crypto problems from application logic.

---

### Case C: Nginx Logs `"PRI * HTTP/2.0" 400`

**Meaning of this error:**
An endpoint expecting HTTP/1.1 received an HTTP/2 preface.

**How wiretracer helps:**
- shows whether `ALPN=h2` was negotiated;
- shows whether `SETTINGS/ACK` appeared (`h2ctl`);
- helps identify whether this is routing, ALPN, or Nginx config.

---

### Case D: `grpcurl list` via wiretracer Returns `context deadline exceeded`

**Checklist:**
1. Is there `tls in ok`?
2. Is there `tls out ok`?
3. Is there `h2ctl SETTINGS` on both sides?
4. Is there `GOAWAY/RST_STREAM`?
5. Are there `event proto=grpc` entries?

If there is no `event proto=grpc`, the request did not reach gRPC level.

---

### Case E: It Is Unclear Who Sends What

**Scenario:**
Many clients/agents, hard to correlate source, listener, and upstream.

**Useful fields:**
- `client_ip:client_port`,
- `listener`,
- `upstream_addr`,
- `conn_id`,
- `alpn_in/alpn_out`,
- `tls in/out`.

This quickly gives you an end-to-end connection chain.

---

### Case F: Clients Arrive Through L4 Load Balancers (PROXY protocol)

**Symptom:**
Logs show load balancer IP, not real client IP.

**What we do:**
- keep listener as-is (no dedicated PROXY-only port);
- `wiretracer` auto-detects `none/v1/v2`;
- inspect `conn` events:
  - `proxy_version`,
  - `proxy_src`,
  - `proxy_dst`.

**Result:**
Real source endpoint is visible in diagnostics.

---

### Case G: Need to Verify PROXY Is Forwarded to Upstream

**Task:**
Confirm that incoming PROXY v1/v2 is forwarded to upstream with the same version.

**How to verify:**
1. Run `proxy_v1_*` / `proxy_v2_*` cases from test-suite.
2. On `fault_server`, observe:
   - `PROXY=v1|v2`
   - `src=... dst=...`
3. In JSONL, verify correct `client_ip` and `proxy_*` fields.

---

### Case H: gRPC Is Fast, but `conn.duration_ms` Is About 30 Seconds

**Symptom:**
`grpcurl` already printed response, but `conn close` appears later.

**Interpretation:**
- `event.duration_ms` = RPC latency;
- `conn.duration_ms` = TCP/TLS connection lifetime.

With h2 keep-alive this is normal: client closes channel later.

---

### Case I: Failures Affect Only a Subset of Clients

**Scenario:**
Some clients work, some fail on TLS.

**What to filter:**
- `proto=tls outcome=fail`
- `client=<ip>`
- `listener=<name>`
- `reason` / `category` in `tls` events.

**Result:**
You quickly isolate client groups with bad certs/CA/SNI.

---

### Case J: Need Regression Checks After Release Changes Without Manual TUI Work

**Scenario:**
Validate regressions after config/logic changes.

**What we do:**
1. Run `test-suite/run_proxy_test_suite.sh`.
2. Review `verify_headless.py` results.
3. Focus only on failed TIDs.

**Benefit:**
Can be integrated into CI as smoke/regression suite.

---

### Case K: Validate "Real" gRPC (Not Only h2 Emulation)

**Scenario:**
Doubt that h2 emulation reflects a real grpcio client.

**What we do:**
- use `fault_client.py --proto grpc_native`;
- or call `grpcurl` manually with `helloworld.proto`;
- compare `proto=grpc` events, headers, and statuses.

---

### Case L: Mixed Traffic on One Listener

**Scenario:**
One listener receives clients:
- without PROXY,
- with PROXY v1,
- with PROXY v2.

**What wiretracer gives you:**
- no need to split traffic across separate listeners;
- per-connection visibility of actual mode (`proxy_version`), endpoints, and close reasons;
- convenient for gradual infrastructure migration.

