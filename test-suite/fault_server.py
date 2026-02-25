#!/usr/bin/env python3
"""
fault_server.py (unified TLS + mTLS)

Одна программа поднимает два TLS-сервера:
  - TLS-only  : 127.0.0.1:19443  (client cert НЕ требуется)
  - mTLS      : 127.0.0.1:29443  (client cert ОБЯЗАТЕЛЕН и проверяется по CA)

Оба поддерживают ALPN: http/1.1 и h2
И реализуют одинаковые fault-сценарии:
  /mode/ok
  /mode/hang?t=...
  /mode/close_early
  /mode/truncate
  /mode/rst
  /mode/sleep_headers?t=...

Ключевое отличие (фикс относительно предыдущей версии):
  - HTTP/1.1 теперь корректно поддерживает keep-alive:
      клиент в chat-режиме может сделать 5 запросов по одному соединению,
      а сервер не будет принудительно закрывать сокет после первого ответа.

Зависимости:
  pip install h2
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import os
import ssl
import time
import ipaddress
from typing import Optional, Tuple, Dict, List

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived, StreamEnded
from h2.exceptions import ProtocolError

try:
    import grpc
    import grpc.aio
except Exception:
    grpc = None  # type: ignore[assignment]

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PROXY_V1_MAX_LINE = 108
H2C_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ----------------------------
# logging / misc helpers
# ----------------------------

def ts() -> str:
    return time.strftime("%H:%M:%S")


def say(server_tag: str, *a: object) -> None:
    print(f"[{ts()}][{server_tag}]", *a, flush=True)


def parse_qs(path: str) -> Tuple[str, Dict[str, str]]:
    if "?" not in path:
        return path, {}
    base, qs = path.split("?", 1)
    out: Dict[str, str] = {}
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        out[k] = v
    return base, out


def abort_transport(writer: asyncio.StreamWriter) -> None:
    tr = writer.transport  # type: ignore[attr-defined]
    tr.abort()


def tls_peer_summary(sslobj: Optional[ssl.SSLObject]) -> str:
    if sslobj is None:
        return "ssl_object=None"
    try:
        cert = sslobj.getpeercert()
    except Exception as e:
        return f"peercert=<error {type(e).__name__}: {e}>"
    if not cert:
        return "peercert=None (client did not provide certificate)"
    subj = cert.get("subject")
    iss = cert.get("issuer")
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    return f"peercert=present subject={subj} issuer={iss} notBefore={not_before} notAfter={not_after}"


def _prepend_to_stream_reader(reader: asyncio.StreamReader, data: bytes) -> None:
    if not data:
        return
    buf = getattr(reader, "_buffer", None)
    if isinstance(buf, bytearray):
        buf[:0] = data


def _pb_encode_varint(v: int) -> bytes:
    if v < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_decode_varint(data: bytes, off: int = 0) -> Tuple[int, int]:
    shift = 0
    value = 0
    i = off
    while i < len(data):
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def decode_hello_request(raw: bytes) -> str:
    off = 0
    while off < len(raw):
        key, off = _pb_decode_varint(raw, off)
        field_no = key >> 3
        wire = key & 0x07
        if wire == 2:  # length-delimited
            ln, off = _pb_decode_varint(raw, off)
            if off + ln > len(raw):
                raise ValueError("bad protobuf length")
            val = raw[off:off + ln]
            off += ln
            if field_no == 1:
                return val.decode("utf-8", errors="replace")
        elif wire == 0:  # varint
            _, off = _pb_decode_varint(raw, off)
        elif wire == 1:  # 64-bit
            off += 8
        elif wire == 5:  # 32-bit
            off += 4
        else:
            raise ValueError(f"unsupported wire type: {wire}")
        if off > len(raw):
            raise ValueError("bad protobuf payload")
    return ""


def encode_hello_reply(message: str) -> bytes:
    b = message.encode("utf-8")
    return b"\x0a" + _pb_encode_varint(len(b)) + b


def build_grpc_server_creds(certs_dir: str):
    if grpc is None:
        return None
    server_crt = os.path.join(certs_dir, "server.crt")
    server_key = os.path.join(certs_dir, "server.key")
    with open(server_crt, "rb") as f:
        crt = f.read()
    with open(server_key, "rb") as f:
        key = f.read()
    return grpc.ssl_server_credentials(((key, crt),))


async def start_native_grpc_server(host: str, port: int, certs_dir: str, server_tag: str):
    if grpc is None:
        say(server_tag, "grpcio not installed; native gRPC server disabled")
        return None

    async def _say_hello(raw_req: bytes, ctx) -> bytes:
        try:
            name = decode_hello_request(raw_req)
        except Exception as e:
            await ctx.abort(grpc.StatusCode.INVALID_ARGUMENT, f"bad protobuf request: {e}")
            raise
        peer = ""
        try:
            peer = ctx.peer() or ""
        except Exception:
            peer = ""
        say(server_tag, f"[grpc] SayHello name={name!r} peer={peer}")
        return encode_hello_reply(f"Hello, {name}")

    handler = grpc.method_handlers_generic_handler(
        "helloworld.Greeter",
        {
            "SayHello": grpc.unary_unary_rpc_method_handler(
                _say_hello,
                request_deserializer=lambda b: b,
                response_serializer=lambda b: b,
            )
        },
    )

    srv = grpc.aio.server()
    srv.add_generic_rpc_handlers((handler,))
    creds = build_grpc_server_creds(certs_dir)
    if creds is None:
        say(server_tag, "native gRPC creds unavailable; server not started")
        return None
    bound = srv.add_secure_port(f"{host}:{port}", creds)
    if bound <= 0:
        raise RuntimeError(f"failed to bind native gRPC server on {host}:{port}")
    await srv.start()
    say(server_tag, f"Listening native gRPC TLS on {host}:{port} service=helloworld.Greeter/SayHello")
    return srv


@dataclasses.dataclass
class ProxyHeaderInfo:
    version: str = "none"            # none|v1|v2
    src: Optional[str] = None        # ip:port
    dst: Optional[str] = None        # ip:port


def _parse_proxy_v1_line(line: bytes) -> ProxyHeaderInfo:
    t = line.decode("ascii", errors="strict").rstrip("\r\n")
    p = t.split()
    if len(p) < 2 or p[0] != "PROXY":
        raise ValueError("invalid v1")
    if p[1] == "UNKNOWN":
        return ProxyHeaderInfo(version="v1")
    if p[1] not in ("TCP4", "TCP6") or len(p) != 6:
        raise ValueError("invalid v1 proto")
    src_ip, dst_ip = p[2], p[3]
    src_port, dst_port = int(p[4]), int(p[5])
    _ = ipaddress.ip_address(src_ip)
    _ = ipaddress.ip_address(dst_ip)
    return ProxyHeaderInfo(version="v1", src=f"{src_ip}:{src_port}", dst=f"{dst_ip}:{dst_port}")


def _parse_proxy_v2_raw(raw: bytes) -> ProxyHeaderInfo:
    if len(raw) < 16 or raw[:12] != PROXY_V2_SIGNATURE:
        raise ValueError("invalid v2 signature")
    ver_cmd = raw[12]
    fam_proto = raw[13]
    if (ver_cmd >> 4) != 0x2:
        raise ValueError("invalid v2 version")
    plen = int.from_bytes(raw[14:16], "big")
    if len(raw) != 16 + plen:
        raise ValueError("invalid v2 length")
    cmd = ver_cmd & 0x0F
    fam = (fam_proto >> 4) & 0x0F
    if cmd != 0x01:  # LOCAL
        return ProxyHeaderInfo(version="v2")
    payload = raw[16:]
    if fam == 0x1 and len(payload) >= 12:
        src_ip = str(ipaddress.IPv4Address(payload[0:4]))
        dst_ip = str(ipaddress.IPv4Address(payload[4:8]))
        src_port = int.from_bytes(payload[8:10], "big")
        dst_port = int.from_bytes(payload[10:12], "big")
        return ProxyHeaderInfo(version="v2", src=f"{src_ip}:{src_port}", dst=f"{dst_ip}:{dst_port}")
    if fam == 0x2 and len(payload) >= 36:
        src_ip = str(ipaddress.IPv6Address(payload[0:16]))
        dst_ip = str(ipaddress.IPv6Address(payload[16:32]))
        src_port = int.from_bytes(payload[32:34], "big")
        dst_port = int.from_bytes(payload[34:36], "big")
        return ProxyHeaderInfo(version="v2", src=f"{src_ip}:{src_port}", dst=f"{dst_ip}:{dst_port}")
    return ProxyHeaderInfo(version="v2")


async def consume_optional_proxy_header(reader: asyncio.StreamReader, *, timeout_s: float = 3.0) -> ProxyHeaderInfo:
    """
    Consume optional PROXY protocol header (v1/v2) from plain TCP stream.
    Returns one of: "none" | "v1" | "v2".
    """
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=timeout_s)
    except Exception:
        return ProxyHeaderInfo(version="none")

    if first == b"P":
        consumed = bytearray(first)
        try:
            tail = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout_s)
            consumed.extend(tail)
            line = bytes(consumed)
            if line.startswith(b"PROXY "):
                if len(line) > PROXY_V1_MAX_LINE:
                    raise ValueError("v1 too long")
                return _parse_proxy_v1_line(line)
            _prepend_to_stream_reader(reader, line)
            return ProxyHeaderInfo(version="none")
        except Exception:
            _prepend_to_stream_reader(reader, bytes(consumed))
            return ProxyHeaderInfo(version="none")

    if first == b"\r":
        consumed = bytearray(first)
        try:
            head_tail = await asyncio.wait_for(reader.readexactly(15), timeout=timeout_s)
            consumed.extend(head_tail)
            head = bytes(consumed)
            if head[:12] != PROXY_V2_SIGNATURE:
                _prepend_to_stream_reader(reader, head)
                return ProxyHeaderInfo(version="none")
            plen = int.from_bytes(head[14:16], "big")
            if 16 + plen > (16 + 65535):
                raise ValueError("v2 too long")
            body = b""
            if plen > 0:
                body = await asyncio.wait_for(reader.readexactly(plen), timeout=timeout_s)
            return _parse_proxy_v2_raw(head + body)
        except Exception:
            _prepend_to_stream_reader(reader, bytes(consumed))
            return ProxyHeaderInfo(version="none")

    _prepend_to_stream_reader(reader, first)
    return ProxyHeaderInfo(version="none")


async def detect_h2c_prior_knowledge(reader: asyncio.StreamReader, *, timeout_s: float = 2.0) -> bool:
    """
    Detect HTTP/2 prior-knowledge preface on plain TCP and keep stream intact.
    """
    try:
        head = await asyncio.wait_for(reader.readexactly(len(H2C_PREFACE)), timeout=timeout_s)
    except asyncio.IncompleteReadError as e:
        _prepend_to_stream_reader(reader, e.partial)
        return False
    except Exception:
        return False
    _prepend_to_stream_reader(reader, head)
    return head == H2C_PREFACE


# ----------------------------
# HTTP/1.1 parsing helpers
# ----------------------------

async def read_http1_request(reader: asyncio.StreamReader, *, header_timeout: float = 30.0) -> Tuple[str, Dict[str, str]]:
    """
    Читаем только заголовки HTTP/1.1 (GET без body).
    Возвращаем (path, headers_lowercase).
    """
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=header_timeout)
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    req_line = lines[0].strip()
    parts = req_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"bad request line: {req_line!r}")

    method = parts[0].upper()
    path = parts[1]
    if method != "GET":
        raise ValueError(f"unsupported method: {method}")

    hdrs: Dict[str, str] = {}
    for ln in lines[1:]:
        if not ln:
            continue
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        hdrs[k.strip().lower()] = v.strip()

    return path, hdrs


def http1_build_response(
    status: int,
    body: bytes,
    *,
    keep_alive: bool,
    extra_headers: Optional[List[Tuple[str, str]]] = None,
) -> bytes:
    """
    Строим HTTP/1.1 ответ.
    Важно: Connection зависит от keep_alive.
    """
    reason = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}.get(status, "OK")

    headers = [
        ("Server", "fault_server"),
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Connection", "keep-alive" if keep_alive else "close"),
    ]
    if extra_headers:
        headers.extend(extra_headers)

    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return head.encode("iso-8859-1") + body


# ----------------------------
# Scenario handlers (HTTP/1.1)
# ----------------------------

async def handle_one_http1_request(
    server_tag: str,
    path: str,
    hdrs: Dict[str, str],
    writer: asyncio.StreamWriter,
    proxy_version: str = "none",
) -> Tuple[bool, bool]:
    """
    Обрабатывает ОДИН HTTP/1.1 запрос.

    Возвращает:
      (keep_alive_after_response, connection_already_terminated)

    connection_already_terminated=True означает:
      - мы сами закрыли/abort соединение в рамках fault-сценария
      - caller должен прекратить цикл
    """
    base, qs = parse_qs(path)
    tid = qs.get("tid")
    want_keep_alive = (hdrs.get("connection", "").lower() == "keep-alive")

    say(server_tag, f"[http1] SCENARIO: base={base} tid={tid!r} keep_alive_req={want_keep_alive}")

    # --- HANG ---
    if base == "/mode/hang":
        t = float(qs.get("t", "999") or "999")
        say(server_tag, f"[http1] emulate HANG: {t}s no response (client/proxy likely kills connection)")
        await asyncio.sleep(t)
        return False, True

    # --- CLOSE EARLY ---
    if base == "/mode/close_early":
        say(server_tag, "[http1] emulate CLOSE_EARLY: close socket immediately, no response")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return False, True

    # --- TRUNCATE ---
    if base == "/mode/truncate":
        body = b"partial-body\n"
        pretend_len = len(body) + 50
        say(server_tag, f"[http1] emulate TRUNCATE: send Content-Length={pretend_len}, but only {len(body)} bytes, then close")
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Server: fault_server\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {pretend_len}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        try:
            writer.write(head + body)
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return False, True

    # --- RST / ABORT ---
    if base == "/mode/rst":
        say(server_tag, "[http1] emulate RST: abort transport (RST-like)")
        try:
            abort_transport(writer)
        except Exception:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return False, True

    # --- SLEEP HEADERS ---
    if base == "/mode/sleep_headers":
        t = float(qs.get("t", "1") or "1")
        say(server_tag, f"[http1] emulate SLEEP_HEADERS: delay {t}s then reply 200; keep_alive={want_keep_alive}")
        await asyncio.sleep(t)
        body = f"sleep_headers ok t={t} tid={tid}\n".encode("utf-8")
        resp = http1_build_response(200, body, keep_alive=want_keep_alive)
        writer.write(resp)
        await writer.drain()
        return want_keep_alive, False

    # --- OK ---
    if base == "/mode/ok":
        want_proxy = (qs.get("expect_proxy") or "").strip().lower()
        if want_proxy:
            actual = (proxy_version or "none").lower()
            if actual != want_proxy:
                say(server_tag, f"[http1] PROXY EXPECT mismatch: want={want_proxy} got={actual}")
                body = f"proxy mismatch: want={want_proxy} got={actual}\n".encode("utf-8")
                resp = http1_build_response(500, body, keep_alive=False)
                writer.write(resp)
                await writer.drain()
                return False, False
        say(server_tag, f"[http1] emulate OK: 200; keep_alive={want_keep_alive}")
        body = f"ok tid={tid}\n".encode("utf-8")
        resp = http1_build_response(200, body, keep_alive=want_keep_alive)
        writer.write(resp)
        await writer.drain()
        return want_keep_alive, False

    # --- unknown ---
    say(server_tag, f"[http1] unknown path -> 404; keep_alive={want_keep_alive}")
    resp = http1_build_response(404, b"not found\n", keep_alive=want_keep_alive)
    writer.write(resp)
    await writer.drain()
    return want_keep_alive, False


async def scenario_http1_connection(
    server_tag: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy_version: str = "none",
) -> None:
    """
    Главный цикл HTTP/1.1 на одном TCP/TLS соединении.

    Важная задача: поддержать chat (keep-alive) и позволить выполнить N запросов подряд,
    пока клиент не закроет соединение или пока сценарий не “сломает” его намеренно.
    """
    req_num = 0
    while True:
        req_num += 1
        try:
            path, hdrs = await read_http1_request(reader, header_timeout=30.0)
        except asyncio.TimeoutError:
            say(server_tag, f"[http1] timeout waiting headers (req#{req_num}) -> close")
            break
        except asyncio.IncompleteReadError:
            say(server_tag, f"[http1] client EOF while reading headers (req#{req_num})")
            break
        except (ConnectionResetError, BrokenPipeError):
            say(server_tag, f"[http1] connection reset by peer (req#{req_num})")
            break
        except Exception as e:
            say(server_tag, f"[http1] bad request/read error (req#{req_num}): {type(e).__name__}: {e}")
            break

        say(
            server_tag,
            f"[http1] got request#{req_num}: path={path!r} host={hdrs.get('host')!r} x-msg={hdrs.get('x-msg')!r} conn={hdrs.get('connection')!r}",
        )

        try:
            keep_alive, terminated = await handle_one_http1_request(
                server_tag, path, hdrs, writer, proxy_version=proxy_version
            )
        except (ConnectionResetError, BrokenPipeError):
            say(server_tag, f"[http1] client disconnected during response (req#{req_num})")
            break
        except Exception as e:
            say(server_tag, f"[http1] handler error (req#{req_num}): {type(e).__name__}: {e}")
            break

        if terminated:
            # мы сами закрыли/abort соединение внутри сценария
            break

        if not keep_alive:
            # корректное "Connection: close" => закрываем соединение со своей стороны
            say(server_tag, f"[http1] keep_alive is False -> closing after req#{req_num}")
            break

        # иначе продолжаем цикл, ждём следующий запрос


# ----------------------------
# Scenario handlers (HTTP/2)
# ----------------------------

async def scenario_h2(server_tag: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    say(server_tag, "[h2] init H2Connection(server_side=True)")

    conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()

    async def h2_send_ok(sid: int, body: bytes) -> None:
        conn.send_headers(sid, [(":status", "200"), ("content-length", str(len(body))), ("content-type", "text/plain")])
        conn.send_data(sid, body, end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()

    async def h2_send_404(sid: int) -> None:
        body = b"not found\n"
        conn.send_headers(sid, [(":status", "404"), ("content-length", str(len(body)))], end_stream=False)
        conn.send_data(sid, body, end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()

    async def handle_stream(sid: int, path: str) -> None:
        base, qs = parse_qs(path)
        tid = qs.get("tid")
        say(server_tag, f"[h2] SCENARIO stream={sid} base={base} tid={tid!r}")

        if base == "/mode/hang":
            t = float(qs.get("t", "999") or "999")
            say(server_tag, f"[h2] emulate HANG(stream={sid}): no response for {t}s")
            await asyncio.sleep(t)
            return

        if base == "/mode/close_early":
            say(server_tag, f"[h2] emulate CLOSE_EARLY(stream={sid}): close TCP now")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        if base == "/mode/truncate":
            body = b"partial-body\n"
            say(server_tag, f"[h2] emulate TRUNCATE(stream={sid}): send some data then close TCP")
            conn.send_headers(sid, [(":status", "200"), ("content-type", "text/plain")], end_stream=False)
            conn.send_data(sid, body, end_stream=False)
            writer.write(conn.data_to_send())
            await writer.drain()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        if base == "/mode/rst":
            say(server_tag, f"[h2] emulate RST(stream={sid}): send RST_STREAM")
            try:
                conn.reset_stream(sid, error_code=0x2)  # INTERNAL_ERROR
                writer.write(conn.data_to_send())
                await writer.drain()
            except Exception:
                pass
            return

        if base == "/mode/sleep_headers":
            t = float(qs.get("t", "1") or "1")
            say(server_tag, f"[h2] emulate SLEEP_HEADERS(stream={sid}): delay {t}s then 200")
            await asyncio.sleep(t)
            body = f"sleep_headers ok t={t} tid={tid}\n".encode("utf-8")
            await h2_send_ok(sid, body)
            return

        if base == "/mode/ok":
            say(server_tag, f"[h2] emulate OK(stream={sid}): immediate 200")
            body = f"ok tid={tid}\n".encode("utf-8")
            await h2_send_ok(sid, body)
            return

        say(server_tag, f"[h2] unknown path -> 404 stream={sid}")
        await h2_send_404(sid)

    try:
        while True:
            data = await reader.read(65536)
            if not data:
                say(server_tag, "[h2] EOF -> connection closed")
                break

            try:
                events = conn.receive_data(data)
            except ProtocolError as e:
                say(server_tag, f"[h2] ProtocolError: {e} -> closing")
                break

            for ev in events:
                if isinstance(ev, RequestReceived):
                    sid = ev.stream_id
                    hdrs = dict(ev.headers)
                    path = hdrs.get(":path", "/")
                    asyncio.create_task(handle_stream(sid, path))
                elif isinstance(ev, DataReceived):
                    try:
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    except Exception:
                        pass
                elif isinstance(ev, StreamEnded):
                    pass

            out = conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()

    finally:
        try:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ----------------------------
# Connection handler (ALPN switch)
# ----------------------------

async def handle_client(server_tag: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    sslobj: Optional[ssl.SSLObject] = writer.get_extra_info("ssl_object")
    try:
        alpn = sslobj.selected_alpn_protocol() if sslobj else None
    except Exception:
        alpn = None

    say(server_tag, "--------------------------------------------------------------------------------")
    say(server_tag, f"NEW TLS CONNECTION from {peer[0]}:{peer[1]} alpn={alpn!r}")
    say(server_tag, f"TLS peer cert summary: {tls_peer_summary(sslobj)}")
    say(server_tag, "--------------------------------------------------------------------------------")

    try:
        if (alpn or "").lower() == "h2":
            await scenario_h2(server_tag, reader, writer)
        else:
            await scenario_http1_connection(server_tag, reader, writer)

    finally:
        try:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        say(server_tag, "connection closed")


async def handle_plain_http1(server_tag: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    say(server_tag, "--------------------------------------------------------------------------------")
    say(server_tag, f"NEW PLAIN CONNECTION from {peer[0]}:{peer[1]}")
    pinfo = await consume_optional_proxy_header(reader, timeout_s=3.0)
    say(server_tag, f"[plain] detected PROXY={pinfo.version} src={pinfo.src or '-'} dst={pinfo.dst or '-'}")
    say(server_tag, "--------------------------------------------------------------------------------")
    try:
        if await detect_h2c_prior_knowledge(reader, timeout_s=2.0):
            say(server_tag, "[plain] detected HTTP/2 prior-knowledge preface -> h2 scenario")
            await scenario_h2(server_tag, reader, writer)
        else:
            await scenario_http1_connection(server_tag, reader, writer, proxy_version=pinfo.version)
    finally:
        try:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        say(server_tag, "plain connection closed")


# ----------------------------
# SSL contexts: TLS and mTLS
# ----------------------------

def build_ssl_contexts(certs_dir: str) -> Tuple[ssl.SSLContext, ssl.SSLContext]:
    server_crt = os.path.join(certs_dir, "server.crt")
    server_key = os.path.join(certs_dir, "server.key")
    ca_crt = os.path.join(certs_dir, "ca.crt")

    for p in (server_crt, server_key, ca_crt):
        if not os.path.isfile(p):
            raise SystemExit(f"Missing file: {p}")

    def _base_ctx() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=server_crt, keyfile=server_key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        return ctx

    tls_ctx = _base_ctx()
    tls_ctx.verify_mode = ssl.CERT_NONE

    mtls_ctx = _base_ctx()
    mtls_ctx.verify_mode = ssl.CERT_REQUIRED
    mtls_ctx.load_verify_locations(cafile=ca_crt)

    return tls_ctx, mtls_ctx


# ----------------------------
# main: start two servers
# ----------------------------

async def amain() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tls-port", type=int, default=19443)
    ap.add_argument("--mtls-port", type=int, default=29443)
    ap.add_argument("--plain-port", type=int, default=18480)
    ap.add_argument("--grpc-port", type=int, default=50052)
    ap.add_argument("--certs", default="./certs")
    args = ap.parse_args()

    tls_ctx, mtls_ctx = build_ssl_contexts(args.certs)

    tls_tag = f"fault_server_tls:{args.tls_port}"
    mtls_tag = f"fault_server_mtls:{args.mtls_port}"
    plain_tag = f"fault_server_plain:{args.plain_port}"
    grpc_tag = f"fault_server_grpc:{args.grpc_port}"

    say(tls_tag, "====================================================================")
    say(tls_tag, "Starting TLS-only fault server (client cert NOT required)")
    say(tls_tag, f"Listen: {args.host}:{args.tls_port}  ALPN=['h2','http/1.1']")
    say(tls_tag, f"Certs : {os.path.abspath(args.certs)}")
    say(tls_tag, "====================================================================")

    say(mtls_tag, "====================================================================")
    say(mtls_tag, "Starting mTLS fault server (client cert REQUIRED)")
    say(mtls_tag, f"Listen: {args.host}:{args.mtls_port}  ALPN=['h2','http/1.1']")
    say(mtls_tag, f"Certs : {os.path.abspath(args.certs)}  (trust=ca.crt)")
    say(mtls_tag, "====================================================================")

    say(plain_tag, "====================================================================")
    say(plain_tag, "Starting PLAIN fault server (HTTP/1.1 + optional PROXY v1/v2)")
    say(plain_tag, f"Listen: {args.host}:{args.plain_port}")
    say(plain_tag, "====================================================================")

    srv_tls = await asyncio.start_server(
        lambda r, w: handle_client(tls_tag, r, w),
        host=args.host,
        port=args.tls_port,
        ssl=tls_ctx,
    )

    srv_mtls = await asyncio.start_server(
        lambda r, w: handle_client(mtls_tag, r, w),
        host=args.host,
        port=args.mtls_port,
        ssl=mtls_ctx,
    )
    srv_plain = await asyncio.start_server(
        lambda r, w: handle_plain_http1(plain_tag, r, w),
        host=args.host,
        port=args.plain_port,
        ssl=None,
    )
    grpc_srv = await start_native_grpc_server(args.host, args.grpc_port, args.certs, grpc_tag)

    say(tls_tag, f"Listening on: {', '.join(str(s.getsockname()) for s in (srv_tls.sockets or []))}")
    say(mtls_tag, f"Listening on: {', '.join(str(s.getsockname()) for s in (srv_mtls.sockets or []))}")
    say(plain_tag, f"Listening on: {', '.join(str(s.getsockname()) for s in (srv_plain.sockets or []))}")

    tasks = [
        asyncio.create_task(srv_tls.serve_forever()),
        asyncio.create_task(srv_mtls.serve_forever()),
        asyncio.create_task(srv_plain.serve_forever()),
    ]
    if grpc_srv is not None:
        tasks.append(asyncio.create_task(grpc_srv.wait_for_termination()))

    try:
        async with srv_tls, srv_mtls, srv_plain:
            await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if grpc_srv is not None:
            await grpc_srv.stop(grace=0)


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\n[fault_server] Interrupted, exiting.", flush=True)


if __name__ == "__main__":
    main()
