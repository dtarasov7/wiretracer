#!/usr/bin/env python3
import argparse
import asyncio
import os
import socket
import ssl
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived, DataReceived, StreamEnded
from h2.exceptions import ProtocolError

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def build_client_ssl(
    certs_dir: str,
    *,
    alpn: list[str],
    client_cert: Optional[str],
    client_key: Optional[str],
    no_client_cert: bool,
) -> ssl.SSLContext:
    """
    Собираем SSLContext для подключения клиента к proxy.

    - Доверяем CA из certs_dir/ca.crt
    - check_hostname выключен (лабораторный режим)
    - ALPN задаём явно
    - Для mTLS:
        * если no_client_cert=True -> НЕ отправляем клиентский сертификат
        * если client_cert/client_key заданы -> используем их
        * иначе -> по умолчанию без клиентского сертификата (как было раньше)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(certs_dir, "ca.crt"))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_alpn_protocols(alpn)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if not no_client_cert:
        # Если явно задали client_cert/key — используем их.
        # Иначе — ведем себя как раньше (без mTLS с клиентской стороны).
        if client_cert or client_key:
            if not (client_cert and client_key):
                raise SystemExit("[client] ERROR: --client-cert requires --client-key (and vice versa)")
            ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)

    return ctx


async def http1_one_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, path: str, xmsg: str) -> bytes:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"User-Agent: fault_client\r\n"
        f"Accept: */*\r\n"
        f"X-Msg: {xmsg}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("iso-8859-1")
    writer.write(req)
    await writer.drain()

    line = await reader.readline()
    if not line:
        raise EOFError("no response (EOF)")

    clen = None
    while True:
        h = await reader.readline()
        if not h:
            break
        if h in (b"\r\n", b"\n"):
            break
        hs = h.decode("iso-8859-1", errors="replace")
        if ":" in hs:
            k, v = hs.split(":", 1)
            if k.strip().lower() == "content-length":
                try:
                    clen = int(v.strip())
                except Exception:
                    clen = None

    if clen is None:
        return await reader.read(65536)
    return await reader.readexactly(clen)


def build_proxy_header(
    mode: str,
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    if mode == "none":
        return b""
    if mode == "malformed":
        return b"PROXY TCP4 203.0.113.10 192.0.2.10 BADPORT 443\r\n"
    if mode == "v1":
        return f"PROXY TCP4 {src_ip} {dst_ip} {int(src_port)} {int(dst_port)}\r\n".encode("ascii")
    if mode == "v2":
        payload = (
            socket.inet_aton(src_ip)
            + socket.inet_aton(dst_ip)
            + int(src_port).to_bytes(2, "big")
            + int(dst_port).to_bytes(2, "big")
        )
        return (
            PROXY_V2_SIGNATURE
            + bytes([0x21, 0x11])  # version=2, cmd=PROXY, fam=INET, proto=STREAM
            + len(payload).to_bytes(2, "big")
            + payload
        )
    raise ValueError(f"unsupported proxy header mode: {mode}")


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


def encode_hello_request(name: str) -> bytes:
    b = name.encode("utf-8")
    return b"\x0a" + _pb_encode_varint(len(b)) + b


def decode_hello_reply(raw: bytes) -> str:
    off = 0
    while off < len(raw):
        key, off = _pb_decode_varint(raw, off)
        field_no = key >> 3
        wire = key & 0x07
        if wire == 2:
            ln, off = _pb_decode_varint(raw, off)
            if off + ln > len(raw):
                raise ValueError("bad protobuf length")
            val = raw[off:off + ln]
            off += ln
            if field_no == 1:
                return val.decode("utf-8", errors="replace")
        elif wire == 0:
            _, off = _pb_decode_varint(raw, off)
        elif wire == 1:
            off += 8
        elif wire == 5:
            off += 4
        else:
            raise ValueError(f"unsupported wire type: {wire}")
        if off > len(raw):
            raise ValueError("bad protobuf payload")
    return ""


def extract_tid_from_path(path: str) -> Optional[str]:
    try:
        qs = parse_qs(urlsplit(path).query)
    except Exception:
        return None
    vals = qs.get("tid") or []
    if vals:
        v = vals[0].strip()
        return v or None
    return None


async def open_tls_with_optional_proxy_header(
    *,
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext,
    sni: str,
    proxy_header_mode: str,
    proxy_src_ip: str,
    proxy_dst_ip: str,
    proxy_src_port: int,
    proxy_dst_port: int,
    proxy_pre_tls_delay_s: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if proxy_header_mode == "none":
        return await asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=sni)

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.create_connection(lambda: protocol, host=host, port=port)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)

    hdr = build_proxy_header(
        proxy_header_mode,
        src_ip=proxy_src_ip,
        dst_ip=proxy_dst_ip,
        src_port=proxy_src_port,
        dst_port=proxy_dst_port,
    )
    if hdr:
        writer.write(hdr)
        await writer.drain()
        # Give server side a short window to parse/consume PROXY header before TLS ClientHello.
        if proxy_pre_tls_delay_s > 0:
            await asyncio.sleep(float(proxy_pre_tls_delay_s))

    tls_transport = await loop.start_tls(
        transport,
        protocol,
        ssl_ctx,
        server_side=False,
        server_hostname=sni,
        ssl_handshake_timeout=10.0,
    )
    writer._transport = tls_transport  # type: ignore[attr-defined]
    reader._transport = tls_transport  # type: ignore[attr-defined]
    return reader, writer


async def http1_via_proxy(
    host: str,
    port: int,
    path: str,
    ssl_ctx: ssl.SSLContext,
    sni: str,
    mode: str,
    cycles: int,
    interval: float,
    proxy_header_mode: str,
    proxy_src_ip: str,
    proxy_dst_ip: str,
    proxy_src_port: int,
    proxy_dst_port: int,
    proxy_pre_tls_delay_s: float,
) -> None:
    r, w = await open_tls_with_optional_proxy_header(
        host=host,
        port=port,
        ssl_ctx=ssl_ctx,
        sni=sni,
        proxy_header_mode=proxy_header_mode,
        proxy_src_ip=proxy_src_ip,
        proxy_dst_ip=proxy_dst_ip,
        proxy_src_port=proxy_src_port,
        proxy_dst_port=proxy_dst_port,
        proxy_pre_tls_delay_s=proxy_pre_tls_delay_s,
    )
    try:
        if mode == "idle":
            await asyncio.sleep(interval * max(1, cycles))
            return

        if mode == "client_rst":
            await http1_one_request(r, w, path, "client_rst")
            tr = w.transport  # type: ignore
            tr.abort()
            return

        if mode == "client_close_early":
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"X-Msg: client_close_early\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode("iso-8859-1")
            w.write(req)
            await w.drain()
            w.close()
            await w.wait_closed()
            return

        if mode == "client_half_close":
            body = await http1_one_request(r, w, path, "client_half_close")
            try:
                sock = w.get_extra_info("socket")
                if sock:
                    sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            _ = body
            return

        async def one(i: int) -> bytes:
            xmsg = f"cycle={i}"
            body = await http1_one_request(r, w, path, xmsg)
            print(f"h1 ok path={path} xmsg={xmsg} body_len={len(body)}")
            return body

        for i in range(1, cycles + 1):
            await one(i)
            if i != cycles:
                await asyncio.sleep(interval)

    finally:
        try:
            if not w.is_closing():
                w.close()
            await w.wait_closed()
        except Exception:
            pass


async def h2_via_proxy(
    host: str,
    port: int,
    path: str,
    ssl_ctx: ssl.SSLContext,
    sni: str,
    mode: str,
    cycles: int,
    interval: float,
    proxy_header_mode: str,
    proxy_src_ip: str,
    proxy_dst_ip: str,
    proxy_src_port: int,
    proxy_dst_port: int,
    proxy_pre_tls_delay_s: float,
    grpc_mode: bool = False,
) -> None:
    r, w = await open_tls_with_optional_proxy_header(
        host=host,
        port=port,
        ssl_ctx=ssl_ctx,
        sni=sni,
        proxy_header_mode=proxy_header_mode,
        proxy_src_ip=proxy_src_ip,
        proxy_dst_ip=proxy_dst_ip,
        proxy_src_port=proxy_src_port,
        proxy_dst_port=proxy_dst_port,
        proxy_pre_tls_delay_s=proxy_pre_tls_delay_s,
    )
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    w.write(conn.data_to_send())
    await w.drain()

    stream_id = 1

    async def send_req(xmsg: str) -> int:
        nonlocal stream_id
        sid = stream_id
        stream_id += 2
        req_method = "POST" if grpc_mode else "GET"
        req_headers = [
            (":method", req_method),
            (":scheme", "https"),
            (":authority", sni),
            (":path", path),
            ("x-msg", xmsg),
        ]
        if grpc_mode:
            req_headers.extend([
                ("content-type", "application/grpc"),
                ("te", "trailers"),
            ])
        conn.send_headers(
            sid,
            req_headers,
            end_stream=True,
        )
        w.write(conn.data_to_send())
        await w.drain()
        return sid

    async def read_one(sid: int) -> Tuple[Optional[int], bytes]:
        status = None
        body = bytearray()
        while True:
            data = await r.read(65536)
            if not data:
                raise EOFError("EOF while waiting h2 response")
            try:
                events = conn.receive_data(data)
            except ProtocolError as e:
                raise RuntimeError(f"h2 protocol error: {e}") from e

            for ev in events:
                if isinstance(ev, ResponseReceived) and ev.stream_id == sid:
                    hdrs = dict(ev.headers)
                    st = hdrs.get(":status")
                    try:
                        status = int(st) if st else None
                    except Exception:
                        status = None
                elif isinstance(ev, DataReceived) and ev.stream_id == sid:
                    body.extend(ev.data)
                    try:
                        conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                    except Exception:
                        pass
                elif isinstance(ev, StreamEnded) and ev.stream_id == sid:
                    w.write(conn.data_to_send())
                    await w.drain()
                    return status, bytes(body)

            out = conn.data_to_send()
            if out:
                w.write(out)
                await w.drain()

    try:
        if mode == "idle":
            await asyncio.sleep(interval * max(1, cycles))
            return

        if mode == "client_rst":
            _ = await send_req("client_rst")
            tr = w.transport  # type: ignore
            tr.abort()
            return

        if mode == "client_close_early":
            _ = await send_req("client_close_early")
            w.close()
            await w.wait_closed()
            return

        for i in range(1, cycles + 1):
            xmsg = f"cycle={i}"
            sid = await send_req(xmsg)
            st, body = await read_one(sid)
            proto = "grpc" if grpc_mode else "h2"
            print(f"{proto} ok path={path} xmsg={xmsg} status={st} body_len={len(body)}")
            if i != cycles:
                await asyncio.sleep(interval)

    finally:
        try:
            if not w.is_closing():
                w.close()
            await w.wait_closed()
        except Exception:
            pass


async def grpc_native_via_proxy(
    host: str,
    port: int,
    path: str,
    sni: str,
    mode: str,
    cycles: int,
    interval: float,
    certs_dir: str,
    client_cert: Optional[str],
    client_key: Optional[str],
    no_client_cert: bool,
    proxy_header_mode: str,
) -> None:
    if proxy_header_mode != "none":
        raise SystemExit("[client] grpc_native does not support PROXY pre-header injection; use --proxy-header none")
    try:
        import grpc
        import grpc.aio
    except Exception as e:
        raise SystemExit(f"[client] grpcio is required for --proto grpc_native: {e}")

    root_ca = open(os.path.join(certs_dir, "ca.crt"), "rb").read()
    key_bytes = None
    cert_bytes = None
    if not no_client_cert and (client_cert or client_key):
        if not (client_cert and client_key):
            raise SystemExit("[client] ERROR: --client-cert requires --client-key (and vice versa)")
        key_bytes = open(client_key, "rb").read()
        cert_bytes = open(client_cert, "rb").read()

    creds = grpc.ssl_channel_credentials(
        root_certificates=root_ca,
        private_key=key_bytes,
        certificate_chain=cert_bytes,
    )
    opts = [
        ("grpc.ssl_target_name_override", sni),
        ("grpc.default_authority", sni),
    ]
    target = f"{host}:{port}"

    tid = extract_tid_from_path(path)
    md_base = []
    if tid:
        md_base.append(("x-tid", tid))

    async with grpc.aio.secure_channel(target, creds, options=opts) as ch:
        await ch.channel_ready()
        call = ch.unary_unary(
            "/helloworld.Greeter/SayHello",
            request_serializer=lambda b: b,
            response_deserializer=lambda b: b,
        )

        if mode == "idle":
            await asyncio.sleep(interval * max(1, cycles))
            return

        for i in range(1, cycles + 1):
            xmsg = f"cycle={i}"
            req = encode_hello_request(xmsg)
            md = tuple(md_base + [("x-msg", xmsg)])
            raw = await call(req, timeout=10.0, metadata=md)
            reply = decode_hello_reply(raw)
            print(f"grpc_native ok method=/helloworld.Greeter/SayHello xmsg={xmsg} reply={reply!r}")
            if i != cycles:
                await asyncio.sleep(interval)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", required=True)
    ap.add_argument("--proxy-port", type=int, required=True)
    ap.add_argument("--certs", required=True)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--proto", choices=["http1", "h2", "grpc", "grpc_native"], required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--interval", type=float, default=0.0)
    ap.add_argument("--path", required=True)
    ap.add_argument(
        "--proxy-header",
        choices=["none", "v1", "v2", "malformed"],
        default="none",
        help="Optional PROXY protocol header to prepend before TLS handshake.",
    )
    ap.add_argument("--proxy-src-ip", default="203.0.113.10")
    ap.add_argument("--proxy-dst-ip", default="192.0.2.10")
    ap.add_argument("--proxy-src-port", type=int, default=54321)
    ap.add_argument("--proxy-dst-port", type=int, default=443)
    ap.add_argument(
        "--proxy-pre-tls-delay",
        type=float,
        default=0.0,
        help="Delay (seconds) between sending PROXY header and starting TLS handshake.",
    )

    # mTLS knobs (client -> proxy)
    ap.add_argument("--client-cert", default=None, help="Client cert PEM for mTLS (client->proxy).")
    ap.add_argument("--client-key", default=None, help="Client key PEM for mTLS (client->proxy).")
    ap.add_argument("--no-client-cert", action="store_true", help="Force: do NOT send client cert (even if proxy requires it).")

    # quiet mode for negative tests
    ap.add_argument(
        "--quiet-expected",
        action="store_true",
        help="Suppress traceback for expected negative-test exceptions (EOF/reset/timeout/SSL handshake).",
    )

    args = ap.parse_args()

    def _is_expected_negative_exc(e: BaseException) -> bool:
        # network-ish expected
        if isinstance(e, (EOFError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError)):
            return True
        if isinstance(e, OSError) and getattr(e, "errno", None) in (104, 32, 110):
            return True
        if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
            return True
        # mTLS / TLS handshake expected failures
        if isinstance(e, ssl.SSLError):
            return True
        return False

    if args.proto == "http1":
        alpn = ["http/1.1"]
    else:
        alpn = ["h2"]

    ssl_ctx = build_client_ssl(
        args.certs,
        alpn=alpn,
        client_cert=args.client_cert,
        client_key=args.client_key,
        no_client_cert=args.no_client_cert,
    )

    try:
        if args.proto == "http1":
            await http1_via_proxy(
                host=args.proxy_host,
                port=args.proxy_port,
                path=args.path,
                ssl_ctx=ssl_ctx,
                sni=args.sni,
                mode=args.mode,
                cycles=args.cycles,
                interval=args.interval,
                proxy_header_mode=args.proxy_header,
                proxy_src_ip=args.proxy_src_ip,
                proxy_dst_ip=args.proxy_dst_ip,
                proxy_src_port=args.proxy_src_port,
                proxy_dst_port=args.proxy_dst_port,
                proxy_pre_tls_delay_s=args.proxy_pre_tls_delay,
            )
        elif args.proto in ("h2", "grpc"):
            await h2_via_proxy(
                host=args.proxy_host,
                port=args.proxy_port,
                path=args.path,
                ssl_ctx=ssl_ctx,
                sni=args.sni,
                mode=args.mode,
                cycles=args.cycles,
                interval=args.interval,
                proxy_header_mode=args.proxy_header,
                proxy_src_ip=args.proxy_src_ip,
                proxy_dst_ip=args.proxy_dst_ip,
                proxy_src_port=args.proxy_src_port,
                proxy_dst_port=args.proxy_dst_port,
                proxy_pre_tls_delay_s=args.proxy_pre_tls_delay,
                grpc_mode=(args.proto == "grpc"),
            )
        else:
            await grpc_native_via_proxy(
                host=args.proxy_host,
                port=args.proxy_port,
                path=args.path,
                sni=args.sni,
                mode=args.mode,
                cycles=args.cycles,
                interval=args.interval,
                certs_dir=args.certs,
                client_cert=args.client_cert,
                client_key=args.client_key,
                no_client_cert=args.no_client_cert,
                proxy_header_mode=args.proxy_header,
            )

    except BaseException as e:
        if args.quiet_expected and _is_expected_negative_exc(e):
            et = type(e).__name__
            msg = str(e) if str(e) else "<no message>"
            print(f"[client] expected negative-test exception: {et}: {msg}")
            raise SystemExit(1)
        raise


if __name__ == "__main__":
    asyncio.run(main())
