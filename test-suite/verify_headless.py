#!/usr/bin/env python3
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Set


# ----------------------------
# Helpers
# ----------------------------
def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _safe_str(x: Any, default: str = "") -> str:
    try:
        return str(x)
    except Exception:
        return default


def record_ts(r: Dict[str, Any]) -> float:
    """
    В JSONL разные kinds могут иметь разные поля времени:
      - conn/tls: ts
      - event: ts_start / ts_end
    """
    if "ts" in r:
        return _safe_float(r.get("ts"), 0.0)
    if "ts_start" in r:
        return _safe_float(r.get("ts_start"), 0.0)
    if "ts_end" in r:
        return _safe_float(r.get("ts_end"), 0.0)
    return 0.0


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
    return out


def filter_since(recs: List[Dict[str, Any]], since_ts: float) -> List[Dict[str, Any]]:
    return [r for r in recs if record_ts(r) >= since_ts]


def event_path(r: Dict[str, Any]) -> str:
    if r.get("kind") != "event":
        return ""
    req = r.get("request") or {}
    return _safe_str(req.get("path"), "")


def filter_by_tid(recs: List[Dict[str, Any]], tid: str) -> List[Dict[str, Any]]:
    """
    tid может находиться:
      - в r["tid"] (conn close у вас так пишет)
      - в event.request.path как query ?tid=... (часто именно так)
    """
    out: List[Dict[str, Any]] = []
    needle1 = f"tid={tid}"
    needle2 = tid  # иногда удобнее просто подстрокой
    for r in recs:
        if r.get("tid") == tid:
            out.append(r)
            continue

        p = event_path(r)
        if p and (needle1 in p or needle2 in p):
            out.append(r)
            continue
        if r.get("kind") == "event":
            req = r.get("request") or {}
            hdrs = req.get("headers") or {}
            if isinstance(hdrs, dict):
                for hk, hv in hdrs.items():
                    hs = f"{_safe_str(hk)}={_safe_str(hv)}"
                    if needle1 in hs or needle2 in hs:
                        out.append(r)
                        break
    return out


def kinds(recs: List[Dict[str, Any]]) -> Dict[str, int]:
    k: Dict[str, int] = {}
    for r in recs:
        kk = r.get("kind")
        k[kk] = k.get(kk, 0) + 1
    return k


def extract_conn_ids(recs: List[Dict[str, Any]]) -> List[str]:
    ids: Set[str] = set()
    for r in recs:
        cid = r.get("conn_id")
        if cid:
            ids.add(str(cid))
    return sorted(ids)


def extract_conn_close(recs: List[Dict[str, Any]]) -> Tuple[List[str], List[str], List[List[str]]]:
    reasons: List[str] = []
    closed_by: List[str] = []
    flags: List[List[str]] = []
    for r in recs:
        if r.get("kind") == "conn" and r.get("event") == "close":
            reasons.append(_safe_str(r.get("close_reason")))
            closed_by.append(_safe_str(r.get("closed_by")))
            flags.append(list(r.get("flags") or []))
    return reasons, closed_by, flags


def extract_statuses(recs: List[Dict[str, Any]]) -> List[int]:
    st: List[int] = []
    for r in recs:
        if r.get("kind") == "event":
            try:
                s = r.get("response", {}).get("status")
                if s is not None:
                    st.append(int(s))
            except Exception:
                pass
    return st


def extract_event_protocols(recs: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for r in recs:
        if r.get("kind") == "event":
            p = r.get("protocol")
            if p:
                out.append(_safe_str(p).lower())
    return out


def extract_tls_in(recs: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    outcomes: List[str] = []
    reasons: List[str] = []
    for r in recs:
        if r.get("kind") == "tls" and r.get("side") == "in":
            outcomes.append(_safe_str(r.get("outcome")))
            reasons.append(_safe_str(r.get("reason")))
    return outcomes, reasons


def extract_tls_out(recs: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    outcomes: List[str] = []
    reasons: List[str] = []
    for r in recs:
        if r.get("kind") == "tls" and r.get("side") == "out":
            outcomes.append(_safe_str(r.get("outcome")))
            reasons.append(_safe_str(r.get("reason")))
    return outcomes, reasons


def extract_last_errors(recs: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for r in recs:
        if r.get("kind") == "event":
            e = r.get("error")
            if e:
                out.append(_safe_str(e))
    return out


def extract_client_ips(recs: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for r in recs:
        ip = r.get("client_ip")
        if ip:
            out.append(_safe_str(ip))
    return out


def is_timeoutish(reasons: List[str], errors: List[str]) -> bool:
    s = " ".join([x.lower() for x in reasons + errors])
    return ("read_timeout" in s) or ("idle_timeout" in s) or ("timeout" in s)


@dataclass
class CheckResult:
    ok: bool
    name: str
    tid: str
    detail: str


def must(cond: bool, name: str, tid: str, detail_ok: str, detail_fail: str) -> CheckResult:
    return CheckResult(ok=bool(cond), name=name, tid=tid, detail=(detail_ok if cond else detail_fail))


# ----------------------------
# TLS-fail-before-HTTP fallback
# ----------------------------
def find_by_listener_window(
    recs_since: List[Dict[str, Any]],
    listener: str,
    since_ts: float,
    window_s: float,
) -> List[Dict[str, Any]]:
    hi = since_ts + window_s
    out: List[Dict[str, Any]] = []
    for r in recs_since:
        ts = record_ts(r)
        if ts < since_ts or ts > hi:
            continue
        if _safe_str(r.get("listener")) != listener:
            continue
        out.append(r)
    return out


def print_found(tid: str, recs: List[Dict[str, Any]]) -> None:
    ks = kinds(recs)
    cids = extract_conn_ids(recs)
    sts = extract_statuses(recs)
    cr, cb, cf = extract_conn_close(recs)
    print(f"[verify] FOUND: records={len(recs)} kinds={ks}")
    print(f"[verify]        conn_ids={cids}")
    if sts:
        print(f"[verify]        statuses={sts}")
    if cr:
        print(f"[verify]        conn_close_reasons={cr}")
    if cb:
        print(f"[verify]        conn_closed_by={cb}")
    if cf:
        print(f"[verify]        conn_close_flags={cf}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--tid-base", required=True)
    ap.add_argument("--since", type=float, required=True)
    ap.add_argument("--mtls-fail-window", type=float, default=120.0)
    ap.add_argument("--with-grpc-native", action="store_true")
    args = ap.parse_args()

    all_recs = load_jsonl(args.jsonl)
    recs_since = filter_since(all_recs, args.since)

    print("[verify] -------------------------------------------------------------------")
    print("[verify] Headless JSONL verification (verbose)")
    print(f"[verify] jsonl filter: record_ts >= {int(args.since)} (epoch seconds)")
    print(f"[verify] records considered: {len(recs_since)} (out of total {len(all_recs)})")
    print("[verify] -------------------------------------------------------------------")

    # tid_base already includes "tid..." in your invocation
    tid_base = args.tid_base

    tests = [
        ("h1_chat5", "HAPPY: HTTP/1.1 keep-alive; 5 запросов", f"{tid_base}_h1_chat5"),
        ("h2_chat5", "HAPPY: HTTP/2; 5 запросов", f"{tid_base}_h2_chat5"),
        ("grpc_chat3", "HAPPY: gRPC over HTTP/2; 3 запроса", f"{tid_base}_grpc_chat3"),
        ("proxy_none_h1", "PROXY: none (HTTP/1.1)", f"{tid_base}_proxy_none_h1"),
        ("proxy_v1_h1", "PROXY: v1 (HTTP/1.1)", f"{tid_base}_proxy_v1_h1"),
        ("proxy_v2_h1", "PROXY: v2 (HTTP/1.1)", f"{tid_base}_proxy_v2_h1"),
        ("proxy_malformed_h1", "PROXY: malformed header (HTTP/1.1)", f"{tid_base}_proxy_malformed_h1"),
        ("proxy_none_h2", "PROXY: none (HTTP/2)", f"{tid_base}_proxy_none_h2"),
        ("proxy_v1_h2", "PROXY: v1 (HTTP/2)", f"{tid_base}_proxy_v1_h2"),
        ("proxy_v2_h2", "PROXY: v2 (HTTP/2)", f"{tid_base}_proxy_v2_h2"),
        ("proxy_none_grpc", "PROXY: none (gRPC)", f"{tid_base}_proxy_none_grpc"),
        ("proxy_v1_grpc", "PROXY: v1 (gRPC)", f"{tid_base}_proxy_v1_grpc"),
        ("proxy_v2_grpc", "PROXY: v2 (gRPC)", f"{tid_base}_proxy_v2_grpc"),

        ("neg_h1_hang", "NEGATIVE: server hang (HTTP/1.1)", f"{tid_base}_neg_h1_hang"),
        ("neg_h1_close_early", "NEGATIVE: close_early (HTTP/1.1)", f"{tid_base}_neg_h1_close_early"),
        ("neg_h1_truncate", "NEGATIVE: truncate (HTTP/1.1)", f"{tid_base}_neg_h1_truncate"),
        ("neg_h1_rst", "NEGATIVE: rst (HTTP/1.1)", f"{tid_base}_neg_h1_rst"),
        ("neg_h1_sleep_headers", "NEGATIVE-ish: sleep_headers (HTTP/1.1)", f"{tid_base}_neg_h1_sleep_headers"),

        ("neg_h2_hang", "NEGATIVE: server hang (HTTP/2)", f"{tid_base}_neg_h2_hang"),
        ("neg_h2_close_early", "NEGATIVE: close_early (HTTP/2)", f"{tid_base}_neg_h2_close_early"),
        ("neg_h2_truncate", "NEGATIVE: truncate (HTTP/2)", f"{tid_base}_neg_h2_truncate"),
        ("neg_h2_rst", "NEGATIVE: rst (HTTP/2)", f"{tid_base}_neg_h2_rst"),

        ("neg_client_close_early", "NEGATIVE: client close early", f"{tid_base}_neg_client_close_early"),
        ("neg_client_rst", "NEGATIVE: client rst", f"{tid_base}_neg_client_rst"),
        ("neg_client_half_close", "NEGATIVE: client half-close", f"{tid_base}_neg_client_half_close"),

        ("mtls_h1_ok", "mTLS OK (http1)", f"{tid_base}_mtls_h1_ok"),
        ("mtls_h2_ok", "mTLS OK (h2)", f"{tid_base}_mtls_h2_ok"),

        ("mtls_h1_client_no_cert", "mTLS NEG: client NO cert (http1)", f"{tid_base}_mtls_h1_client_no_cert"),
        ("mtls_h2_client_no_cert", "mTLS NEG: client NO cert (h2)", f"{tid_base}_mtls_h2_client_no_cert"),
        ("mtls_h1_client_bad_cert", "mTLS NEG: client BAD cert (http1)", f"{tid_base}_mtls_h1_client_bad_cert"),
        ("mtls_h2_client_bad_cert", "mTLS NEG: client BAD cert (h2)", f"{tid_base}_mtls_h2_client_bad_cert"),

        ("mtls_h1_upstream_fail", "mTLS NEG: upstream FAIL (http1)", f"{tid_base}_mtls_h1_upstream_fail"),
        ("mtls_h2_upstream_fail", "mTLS NEG: upstream FAIL (h2)", f"{tid_base}_mtls_h2_upstream_fail"),
    ]
    if args.with_grpc_native:
        tests.extend([
            ("grpc_native_chat2", "HAPPY: native grpcio client/server; 2 unary calls", f"{tid_base}_grpc_native_chat2"),
            ("grpc_native_client_cert_ok", "native grpcio with client cert provided", f"{tid_base}_grpc_native_client_cert_ok"),
        ])

    mtls_listener_map = {
        "mtls_h1_client_no_cert": "test-mtls-http1",
        "mtls_h2_client_no_cert": "test-mtls-http2",
        "mtls_h1_client_bad_cert": "test-mtls-http1",
        "mtls_h2_client_bad_cert": "test-mtls-http2",
    }
    proxy_listener_map = {
        "proxy_malformed_h1": "test-http1",
    }

    results: List[CheckResult] = []

    for short, scenario, tid in tests:
        print("\n" + "=" * 80)
        print(f"[verify] TEST: {tid}")
        print(f"[verify] SCENARIO: {scenario}")

        recs_tid = filter_by_tid(recs_since, tid)

        # TLS fail before HTTP => no tid in records; use listener fallback
        if short in mtls_listener_map and len(recs_tid) == 0:
            listener = mtls_listener_map[short]
            recs_fb = find_by_listener_window(recs_since, listener, args.since, args.mtls_fail_window)
            print("[verify] NOTE: tid может отсутствовать (TLS упал до HTTP). Используем fallback по listener+time_window.")
            print_found(tid, recs_fb)

            tls_in_out, tls_in_reason = extract_tls_in(recs_fb)
            cr, _, _ = extract_conn_close(recs_fb)

            results.append(must(
                len(recs_fb) > 0,
                "presence(fallback_listener_window)",
                tid,
                detail_ok=f"records={len(recs_fb)} listener={listener}",
                detail_fail=f"records=0 listener={listener}",
            ))

            cond = ("fail" in [x.lower() for x in tls_in_out]) or any("tls_in_fail" in (x or "").lower() for x in cr)
            results.append(must(
                cond,
                "mtls_tls_in_fail_hint",
                tid,
                detail_ok=f"tls_in_outcomes={tls_in_out} tls_in_reasons={tls_in_reason} close_reasons={cr}",
                detail_fail=f"tls_in_outcomes={tls_in_out} tls_in_reasons={tls_in_reason} close_reasons={cr}",
            ))
            continue

        if short in proxy_listener_map and len(recs_tid) == 0:
            listener = proxy_listener_map[short]
            recs_fb = find_by_listener_window(recs_since, listener, args.since, args.mtls_fail_window)
            print("[verify] NOTE: malformed PROXY может упасть до HTTP. Используем fallback по listener+time_window.")
            print_found(tid, recs_fb)
            cr, _, _ = extract_conn_close(recs_fb)
            results.append(must(
                len(recs_fb) > 0,
                "presence(fallback_listener_window)",
                tid,
                detail_ok=f"records={len(recs_fb)} listener={listener}",
                detail_fail=f"records=0 listener={listener}",
            ))
            results.append(must(
                any((x or "").lower() == "proxy_protocol_error" for x in cr),
                "proxy_malformed_close_reason",
                tid,
                detail_ok=f"close_reasons={cr}",
                detail_fail=f"close_reasons={cr}",
            ))
            continue

        # Normal: by tid
        print_found(tid, recs_tid)

        ks = kinds(recs_tid)
        cids = extract_conn_ids(recs_tid)
        statuses = extract_statuses(recs_tid)
        protocols = extract_event_protocols(recs_tid)
        close_reasons, closed_by, close_flags = extract_conn_close(recs_tid)
        tls_out_outcomes, tls_out_reasons = extract_tls_out(recs_tid)
        last_errs = extract_last_errors(recs_tid)
        client_ips = extract_client_ips(recs_tid)

        results.append(must(
            len(recs_tid) > 0,
            "presence",
            tid,
            detail_ok=f"records={len(recs_tid)} kinds={ks} conn_ids={cids}",
            detail_fail=f"records=0 kinds={ks} conn_ids={cids}",
        ))

        if short in ("h1_chat5", "h2_chat5"):
            results.append(must(
                ks.get("event", 0) >= 5,
                "happy_events_5",
                tid,
                detail_ok=f"event_count={ks.get('event',0)} (want >= 5)",
                detail_fail=f"event_count={ks.get('event',0)} (want >= 5)",
            ))
            results.append(must(
                len(statuses) >= 5 and all(s == 200 for s in statuses[:5]),
                "happy_status_200",
                tid,
                detail_ok=f"statuses(first5)={statuses[:5]} full={statuses}",
                detail_fail=f"statuses(first5)={statuses[:5]} full={statuses}",
            ))

        if short == "grpc_chat3":
            results.append(must(
                ks.get("event", 0) >= 3,
                "grpc_events_3",
                tid,
                detail_ok=f"event_count={ks.get('event',0)} (want >= 3)",
                detail_fail=f"event_count={ks.get('event',0)} (want >= 3)",
            ))
            results.append(must(
                len(statuses) >= 3 and all(s == 200 for s in statuses[:3]),
                "grpc_status_200",
                tid,
                detail_ok=f"statuses(first3)={statuses[:3]} full={statuses}",
                detail_fail=f"statuses(first3)={statuses[:3]} full={statuses}",
            ))
            results.append(must(
                "grpc" in protocols,
                "grpc_protocol_detected",
                tid,
                detail_ok=f"protocols={protocols}",
                detail_fail=f"protocols={protocols}",
            ))

        if short == "grpc_native_chat2":
            results.append(must(
                ks.get("event", 0) >= 2,
                "grpc_native_events_2",
                tid,
                detail_ok=f"event_count={ks.get('event',0)} (want >= 2)",
                detail_fail=f"event_count={ks.get('event',0)} (want >= 2)",
            ))
            results.append(must(
                all(s == 200 for s in statuses[:2]) if len(statuses) >= 2 else False,
                "grpc_native_status_200",
                tid,
                detail_ok=f"statuses(first2)={statuses[:2]} full={statuses}",
                detail_fail=f"statuses(first2)={statuses[:2]} full={statuses}",
            ))
            results.append(must(
                "grpc" in protocols,
                "grpc_native_protocol_detected",
                tid,
                detail_ok=f"protocols={protocols}",
                detail_fail=f"protocols={protocols}",
            ))

        if short == "grpc_native_client_cert_ok":
            results.append(must(
                any(s == 200 for s in statuses),
                "grpc_native_client_cert_status_200",
                tid,
                detail_ok=f"statuses={statuses} protocols={protocols}",
                detail_fail=f"statuses={statuses} protocols={protocols}",
            ))
            results.append(must(
                "grpc" in protocols,
                "grpc_native_client_cert_protocol_detected",
                tid,
                detail_ok=f"protocols={protocols}",
                detail_fail=f"protocols={protocols}",
            ))

        if short in ("proxy_none_h1", "proxy_v1_h1", "proxy_v2_h1", "proxy_none_h2", "proxy_v1_h2", "proxy_v2_h2"):
            results.append(must(
                any(s == 200 for s in statuses),
                "proxy_status_200",
                tid,
                detail_ok=f"statuses={statuses} client_ips={client_ips}",
                detail_fail=f"statuses={statuses} client_ips={client_ips}",
            ))

        if short in ("proxy_none_grpc", "proxy_v1_grpc", "proxy_v2_grpc"):
            results.append(must(
                any(s == 200 for s in statuses),
                "proxy_grpc_status_200",
                tid,
                detail_ok=f"statuses={statuses} protocols={protocols} client_ips={client_ips}",
                detail_fail=f"statuses={statuses} protocols={protocols} client_ips={client_ips}",
            ))
            results.append(must(
                "grpc" in protocols,
                "proxy_grpc_protocol_detected",
                tid,
                detail_ok=f"protocols={protocols}",
                detail_fail=f"protocols={protocols}",
            ))

        if short in ("proxy_v1_h1", "proxy_v1_h2"):
            results.append(must(
                "203.0.113.10" in client_ips,
                "proxy_v1_client_ip_applied",
                tid,
                detail_ok=f"client_ips={client_ips}",
                detail_fail=f"client_ips={client_ips}",
            ))

        if short == "proxy_v1_grpc":
            results.append(must(
                "203.0.113.10" in client_ips,
                "proxy_v1_grpc_client_ip_applied",
                tid,
                detail_ok=f"client_ips={client_ips}",
                detail_fail=f"client_ips={client_ips}",
            ))

        if short in ("proxy_v2_h1", "proxy_v2_h2"):
            results.append(must(
                "198.51.100.20" in client_ips,
                "proxy_v2_client_ip_applied",
                tid,
                detail_ok=f"client_ips={client_ips}",
                detail_fail=f"client_ips={client_ips}",
            ))

        if short == "proxy_v2_grpc":
            results.append(must(
                "198.51.100.20" in client_ips,
                "proxy_v2_grpc_client_ip_applied",
                tid,
                detail_ok=f"client_ips={client_ips}",
                detail_fail=f"client_ips={client_ips}",
            ))

        if short in ("neg_h1_hang", "neg_h2_hang"):
            results.append(must(
                is_timeoutish(close_reasons, last_errs),
                "hang_timeout_hint",
                tid,
                detail_ok=f"close_reasons={close_reasons} errors={last_errs}",
                detail_fail=f"close_reasons={close_reasons} errors={last_errs}",
            ))

        if short in (
            "neg_h1_close_early", "neg_h1_truncate", "neg_h1_rst",
            "neg_h2_close_early", "neg_h2_truncate", "neg_h2_rst",
            "neg_client_close_early", "neg_client_rst", "neg_client_half_close",
        ):
            results.append(must(
                ks.get("conn", 0) >= 1 and len(close_reasons) >= 1,
                "close_hint",
                tid,
                detail_ok=f"kinds={ks} close_reasons={close_reasons} close_flags={close_flags} closed_by={closed_by}",
                detail_fail=f"kinds={ks} close_reasons={close_reasons} close_flags={close_flags} closed_by={closed_by}",
            ))

        if short == "neg_h1_sleep_headers":
            results.append(must(
                ks.get("event", 0) >= 1,
                "sleep_headers_event_present",
                tid,
                detail_ok=f"event_count={ks.get('event',0)}",
                detail_fail=f"event_count={ks.get('event',0)}",
            ))

        if short in ("mtls_h1_ok", "mtls_h2_ok"):
            results.append(must(
                any(s == 200 for s in statuses),
                "mtls_ok_status_200",
                tid,
                detail_ok=f"statuses={statuses}",
                detail_fail=f"statuses={statuses}",
            ))

        if short in ("mtls_h1_upstream_fail", "mtls_h2_upstream_fail"):
            s = " ".join([x.lower() for x in tls_out_outcomes + tls_out_reasons + close_reasons + last_errs])
            cond = (
                ("fail" in [x.lower() for x in tls_out_outcomes]) or
                ("upstream" in s and ("tls" in s or "handshake" in s or "cert" in s)) or
                any("upstream_" in (x or "").lower() for x in close_reasons)
            )
            results.append(must(
                cond,
                "mtls_upstream_fail_hint",
                tid,
                detail_ok=f"tls_out_outcomes={tls_out_outcomes} tls_out_reasons={tls_out_reasons} close_reasons={close_reasons} last_errors={last_errs}",
                detail_fail=f"tls_out_outcomes={tls_out_outcomes} tls_out_reasons={tls_out_reasons} close_reasons={close_reasons} last_errors={last_errs}",
            ))

    fails = [r for r in results if not r.ok]
    print("[verify] -------------------------------------------------------------------")
    print("[verify] RESULTS")
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        print(f"  - {status} {r.name}[{r.tid}]: {r.detail}")
    print("[verify] -------------------------------------------------------------------")
    if fails:
        print(f"[verify] FAILED: {len(fails)} checks failed")
        return 2
    print("[verify] ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
