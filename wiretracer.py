#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wiretracer (single-file)

- Multi-listener TLS-terminating proxy for HTTP/2 + gRPC (h2<->h2) + raw tunnel fallback.
- TUI (urwid): Traffic + Connections + Metrics
- Traffic shows:
  - request/response events (grpc/http2)
  - TLS handshake events (ok/fail) in/out
  - HTTP/2 control events (SETTINGS/ACK/GOAWAY/RST/WINDOW_UPDATE/flow-control block)

"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid
import weakref
from collections import deque
import dataclasses
from dataclasses import dataclass, field
from typing import Callable, Any, Deque, Dict, List, Optional, Set, Tuple, Union
import urwid
import yaml

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    RequestReceived,
    ResponseReceived,
    DataReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
    RemoteSettingsChanged,
    SettingsAcknowledged,
    WindowUpdated,
    ConnectionTerminated,
)
from h2.exceptions import ProtocolError, FlowControlError

from contextvars import ContextVar

import logging
from logging.handlers import RotatingFileHandler
import warnings

HEADER_MAX = 64 * 1024
HARD_BODY_LIMIT = 10 * 1024 * 1024  # 10MB hard cap
CURRENT_CONN_ID: ContextVar[Optional[str]] = ContextVar("CURRENT_CONN_ID", default=None)

__version__ = "1.40.0"
__AUTHOR__ = "Tarasov Dmitry"


# прибрать asyncio noisy warnings
warnings.filterwarnings(
    "ignore",
    message=r"returning true from eof_received\(\) has no effect when using ssl",
)

# прибрать шум asyncio logger (опционально)
logging.getLogger("asyncio").setLevel(logging.ERROR)

# Module logger (configured in main())
LOG = logging.getLogger("wiretracer")

# Throttled logging (best-effort; designed for single-threaded asyncio loop)
_LOG_THROTTLE_STATE: dict[str, tuple[float, int]] = {}
# key -> (last_ts, suppressed_count)


def log_throttled(
    level: int,
    key: str,
    msg: str,
    *args,
    interval_s: float = 2.0,
    exc_info: bool = False,
    **kwargs,
) -> None:
    """
    Log a message at most once per interval for a given key.

    Keeps a suppressed counter; when it logs again it appends:
      " (suppressed N similar messages)"
    """
    try:
        now = time.time()
        last_ts, suppressed = _LOG_THROTTLE_STATE.get(key, (0.0, 0))

        if (now - last_ts) < float(interval_s):
            _LOG_THROTTLE_STATE[key] = (last_ts, suppressed + 1)
            return

        # time to log
        _LOG_THROTTLE_STATE[key] = (now, 0)

        if suppressed:
            msg = f"{msg} (suppressed {suppressed} similar messages)"
        LOG.log(level, msg, *args, exc_info=exc_info, **kwargs)

    except Exception:
        # never let logging break the app
        try:
            LOG.log(level, msg, *args, exc_info=exc_info, **kwargs)
        except Exception:
            pass


def setup_logging(log_path: str, level: str = "INFO") -> None:
    """Configure application logging.

    Defaults:
      - log file in the current working directory
      - rotating file handler (to avoid unbounded growth)

    Args:
        log_path: Path to the log file.
        level: Logging level name (e.g. INFO, DEBUG).
    """
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)

    # Ensure parent directory exists (if any)
    try:
        d = os.path.dirname(log_path)
        if d:
            os.makedirs(d, exist_ok=True)
    except Exception:
        # Best-effort; fall back to current directory
        log_path = os.path.basename(log_path) or "wiretracer.log"

    root = logging.getLogger()
    root.setLevel(lvl)

    # Avoid duplicate handlers (e.g. reload/tests)
    for h in list(root.handlers):
        try:
            root.removeHandler(h)
        except Exception:
            pass

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        fh = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(lvl)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except Exception:
        # Last resort: stderr
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(lvl)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    LOG.info("Logging initialized: %s level=%s", log_path, logging.getLevelName(lvl))


def _extract_tid(path: str) -> Optional[str]:
    if not path:
        return None
    # fast parse, no urllib dependency
    qpos = path.find("?")
    if qpos < 0:
        return None
    qs = path[qpos+1:]
    for part in qs.split("&"):
        if not part:
            continue
        if part.startswith("tid="):
            return part[4:] or ""
    return None


# Config model
@dataclass
class TlsConfig:
    # Incoming TLS (client -> proxy)
    cert: str
    key: str
    require_client_cert: bool = False
    client_ca: Optional[str] = None
    alpn: List[str] = field(default_factory=lambda: ["h2", "http/1.1"])
    min_version: str = "TLS1.2"


@dataclass
class UpstreamConfig:
    # Outgoing (proxy -> upstream)
    addr: str
    tls: bool = False
    server_name: Optional[str] = None
    verify: bool = True
    ca: Optional[str] = None
    alpn: List[str] = field(default_factory=lambda: ["h2", "http/1.1"])

    # Outgoing mTLS (client cert for proxy->upstream)
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    client_key_password: Optional[str] = None


@dataclass
class PolicyConfig:
    allowlist: List[str] = field(default_factory=list)
    max_connections: int = 200

    # upstream timeouts (seconds)
    upstream_connect_timeout: float = 5.0
    upstream_handshake_timeout: float = 10.0

    # if semaphore wait exceeds this threshold, log "maxconn_wait" (milliseconds)
    maxconn_wait_warn_ms: float = 200.0


@dataclass
class LoggingConfig:
    log_headers: bool = True
    log_body: bool = False
    body_max_bytes: int = 0  # 0 => unlimited (hard-capped)
    redact_headers: List[str] = field(default_factory=lambda: ["authorization", "cookie", "x-api-key"])
    sample_rate: float = 1.0
    h2_control_events: bool = False
    jsonl_path: Optional[str] = None


@dataclass
class ListenerConfig:
    name: str
    listen: str
    tls: TlsConfig
    upstream: UpstreamConfig
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


@dataclass
class AppConfig:
    listeners: List[ListenerConfig]


def dump_example_config() -> str:
    example = {
        "listeners": [
            {
                "name": "grpc-mitm",
                "listen": "0.0.0.0:9100",
                "tls": {
                    "cert": "/opt/nginc/certs/nginx_cert.crt",
                    "key": "/opt/nginc/certs/nginx_cert.key",
                    "require_client_cert": False,
                    "client_ca": None,
                    "alpn": ["h2", "http/1.1"],
                    "min_version": "TLS1.2",
                },
                "upstream": {
                    "addr": "127.0.0.1:50052",
                    "tls": True,
                    "server_name": "localhost",
                    "verify": False,
                    "ca": None,
                    "alpn": ["h2"],
                    "client_cert": None,
                    "client_key": None,
                    "client_key_password": None,
                },
                "policy": {"allowlist": ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"], "max_connections": 200},
                "logging": {
                    "log_headers": True,
                    "log_body": True,
                    "body_max_bytes": 8192,
                    "redact_headers": ["authorization", "cookie", "x-api-key"],
                    "sample_rate": 1.0,
                    "h2_control_events": False,
                    "jsonl_path": None,
                },
            }
        ]
    }
    return yaml.safe_dump(example, sort_keys=False)


def _parse_hostport(addr: str) -> Tuple[str, int]:
    host, port_s = addr.rsplit(":", 1)
    return host, int(port_s)


PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PROXY_V1_MAX_LINE = 108
PROXY_V2_MAX_HEADER = 16 + 65535


@dataclass
class ProxyProtocolHeader:
    present: bool = False
    version: Optional[int] = None  # 1 | 2
    raw: bytes = b""
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None


def _parse_proxy_v1_line(line: bytes) -> ProxyProtocolHeader:
    text = line.decode("ascii", errors="strict").rstrip("\r\n")
    parts = text.split()
    if len(parts) < 2 or parts[0] != "PROXY":
        raise ValueError("invalid PROXY v1 header")

    proto = parts[1]
    if proto == "UNKNOWN":
        return ProxyProtocolHeader(present=True, version=1, raw=line)

    if proto not in ("TCP4", "TCP6") or len(parts) != 6:
        raise ValueError("unsupported PROXY v1 protocol")

    src_ip, dst_ip = parts[2], parts[3]
    try:
        src_port = int(parts[4], 10)
        dst_port = int(parts[5], 10)
    except Exception as e:
        raise ValueError("invalid PROXY v1 port") from e

    if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
        raise ValueError("PROXY v1 port out of range")

    try:
        src_ver = ipaddress.ip_address(src_ip).version
        dst_ver = ipaddress.ip_address(dst_ip).version
    except Exception as e:
        raise ValueError("invalid PROXY v1 address") from e

    if proto == "TCP4" and (src_ver != 4 or dst_ver != 4):
        raise ValueError("PROXY v1 family mismatch for TCP4")
    if proto == "TCP6" and (src_ver != 6 or dst_ver != 6):
        raise ValueError("PROXY v1 family mismatch for TCP6")

    return ProxyProtocolHeader(
        present=True,
        version=1,
        raw=line,
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=dst_ip,
        dest_port=dst_port,
    )


def _parse_proxy_v2_raw(raw: bytes) -> ProxyProtocolHeader:
    if len(raw) < 16:
        raise ValueError("short PROXY v2 header")
    if raw[:12] != PROXY_V2_SIGNATURE:
        raise ValueError("invalid PROXY v2 signature")

    ver_cmd = raw[12]
    fam_proto = raw[13]
    if (ver_cmd >> 4) != 0x2:
        raise ValueError("invalid PROXY v2 version")

    plen = int.from_bytes(raw[14:16], "big")
    if len(raw) != 16 + plen:
        raise ValueError("invalid PROXY v2 length")

    cmd = ver_cmd & 0x0F
    fam = (fam_proto >> 4) & 0x0F

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    if cmd == 0x01:  # PROXY
        payload = raw[16:]
        if fam == 0x1 and len(payload) >= 12:  # INET
            src_ip = str(ipaddress.IPv4Address(payload[0:4]))
            dst_ip = str(ipaddress.IPv4Address(payload[4:8]))
            src_port = int.from_bytes(payload[8:10], "big")
            dst_port = int.from_bytes(payload[10:12], "big")
        elif fam == 0x2 and len(payload) >= 36:  # INET6
            src_ip = str(ipaddress.IPv6Address(payload[0:16]))
            dst_ip = str(ipaddress.IPv6Address(payload[16:32]))
            src_port = int.from_bytes(payload[32:34], "big")
            dst_port = int.from_bytes(payload[34:36], "big")

    return ProxyProtocolHeader(
        present=True,
        version=2,
        raw=raw,
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=dst_ip,
        dest_port=dst_port,
    )


def _unwrap_raw_socket(sock_obj: Any) -> Optional[socket.socket]:
    if sock_obj is None:
        return None
    if isinstance(sock_obj, socket.socket):
        return sock_obj
    raw = getattr(sock_obj, "_sock", None)
    if isinstance(raw, socket.socket):
        return raw
    return None


async def _sock_peek(raw_sock: socket.socket, n: int, deadline: float) -> bytes:
    while True:
        if time.time() >= deadline:
            raise asyncio.TimeoutError("socket peek timeout")
        try:
            return raw_sock.recv(n, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            await asyncio.sleep(0.005)


async def _sock_recv_exact(raw_sock: socket.socket, n: int, deadline: float) -> bytes:
    out = bytearray()
    while len(out) < n:
        if time.time() >= deadline:
            raise asyncio.TimeoutError("socket recv timeout")
        try:
            b = raw_sock.recv(n - len(out))
        except (BlockingIOError, InterruptedError):
            await asyncio.sleep(0.005)
            continue
        if not b:
            raise ConnectionError("socket closed while reading")
        out.extend(b)
    return bytes(out)


def _prepend_to_stream_reader(reader: asyncio.StreamReader, data: bytes) -> None:
    if not data:
        return
    buf = getattr(reader, "_buffer", None)
    if isinstance(buf, bytearray):
        buf[:0] = data


async def _detect_proxy_protocol_header_stream_reader(
    reader: asyncio.StreamReader,
    *,
    timeout_s: float,
) -> ProxyProtocolHeader:
    """
    Compatibility path for tests/tools that pass StreamReader instead of socket.
    """
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=timeout_s)
    except Exception:
        return ProxyProtocolHeader()

    if first == b"P":
        consumed = bytearray(first)
        try:
            tail = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout_s)
            consumed.extend(tail)
            line = bytes(consumed)
            if len(line) > (PROXY_V1_MAX_LINE + 2):
                if line.startswith(b"PROXY "):
                    raise ValueError("PROXY v1 header too long")
                _prepend_to_stream_reader(reader, line)
                return ProxyProtocolHeader()
            if not line.startswith(b"PROXY "):
                _prepend_to_stream_reader(reader, line)
                return ProxyProtocolHeader()
            return _parse_proxy_v1_line(line)
        except asyncio.TimeoutError:
            _prepend_to_stream_reader(reader, bytes(consumed))
            return ProxyProtocolHeader()

    if first == b"\r":
        consumed = bytearray(first)
        try:
            head_tail = await asyncio.wait_for(reader.readexactly(15), timeout=timeout_s)
            consumed.extend(head_tail)
            head = bytes(consumed)
            if head[:12] != PROXY_V2_SIGNATURE:
                _prepend_to_stream_reader(reader, head)
                return ProxyProtocolHeader()
            plen = int.from_bytes(head[14:16], "big")
            total = 16 + plen
            if total > PROXY_V2_MAX_HEADER:
                raise ValueError("PROXY v2 header too long")
            body = b""
            if plen > 0:
                body = await asyncio.wait_for(reader.readexactly(plen), timeout=timeout_s)
            return _parse_proxy_v2_raw(head + body)
        except asyncio.IncompleteReadError as e:
            _prepend_to_stream_reader(reader, bytes(consumed) + e.partial)
            return ProxyProtocolHeader()
        except asyncio.TimeoutError:
            _prepend_to_stream_reader(reader, bytes(consumed))
            return ProxyProtocolHeader()

    _prepend_to_stream_reader(reader, first)
    return ProxyProtocolHeader()


async def detect_proxy_protocol_header(
    sock_obj: Any,
    *,
    timeout_s: float = 1.0,
) -> ProxyProtocolHeader:
    """
    Auto-detect PROXY protocol header (v1/v2) or absence using raw socket.

    Must be used while transport reading is paused; consumes bytes only when PROXY
    header is present, leaving TLS ClientHello intact in socket receive queue.
    """
    if isinstance(sock_obj, asyncio.StreamReader):
        return await _detect_proxy_protocol_header_stream_reader(sock_obj, timeout_s=timeout_s)

    raw_sock = _unwrap_raw_socket(sock_obj)
    if raw_sock is None:
        return ProxyProtocolHeader()

    deadline = time.time() + max(0.05, float(timeout_s))

    try:
        first = await _sock_peek(raw_sock, 1, deadline)
    except asyncio.TimeoutError:
        return ProxyProtocolHeader()
    if not first:
        return ProxyProtocolHeader()

    b0 = first[:1]

    if b0 == b"P":
        while True:
            peek = await _sock_peek(raw_sock, PROXY_V1_MAX_LINE + 2, deadline)
            if not peek:
                return ProxyProtocolHeader()
            eol = peek.find(b"\r\n")
            if eol < 0:
                if len(peek) >= (PROXY_V1_MAX_LINE + 2):
                    if peek.startswith(b"PROXY "):
                        raise ValueError("PROXY v1 header too long")
                    return ProxyProtocolHeader()
                await asyncio.sleep(0.005)
                continue
            line = peek[: eol + 2]
            if not line.startswith(b"PROXY "):
                return ProxyProtocolHeader()
            parsed = _parse_proxy_v1_line(line)
            _ = await _sock_recv_exact(raw_sock, len(line), deadline)
            return parsed

    if b0 == b"\r":
        head = await _sock_peek(raw_sock, 16, deadline)
        if len(head) < 16:
            return ProxyProtocolHeader()
        if head[:12] != PROXY_V2_SIGNATURE:
            return ProxyProtocolHeader()
        plen = int.from_bytes(head[14:16], "big")
        total = 16 + plen
        if total > PROXY_V2_MAX_HEADER:
            raise ValueError("PROXY v2 header too long")
        while True:
            peek = await _sock_peek(raw_sock, total, deadline)
            if len(peek) < total:
                await asyncio.sleep(0.005)
                continue
            raw = peek[:total]
            parsed = _parse_proxy_v2_raw(raw)
            _ = await _sock_recv_exact(raw_sock, total, deadline)
            return parsed

    return ProxyProtocolHeader()


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict) or "listeners" not in raw:
        raise ValueError("Config must be a dict with 'listeners' list")

    listeners: List[ListenerConfig] = []
    for item in raw["listeners"]:
        tls_raw = item.get("tls") or {}
        up_raw = item.get("upstream") or {}
        pol_raw = item.get("policy") or {}
        log_raw = item.get("logging") or {}

        _parse_hostport(str(item["listen"]))
        _parse_hostport(str(up_raw["addr"]))

        tls = TlsConfig(
            cert=str(tls_raw["cert"]),
            key=str(tls_raw["key"]),
            require_client_cert=bool(tls_raw.get("require_client_cert", False)),
            client_ca=tls_raw.get("client_ca"),
            alpn=list(tls_raw.get("alpn", ["h2", "http/1.1"])),
            min_version=str(tls_raw.get("min_version", "TLS1.2")),
        )
        upstream = UpstreamConfig(
            addr=str(up_raw["addr"]),
            tls=bool(up_raw.get("tls", False)),
            server_name=up_raw.get("server_name"),
            verify=bool(up_raw.get("verify", True)),
            ca=up_raw.get("ca"),
            alpn=list(up_raw.get("alpn", ["h2", "http/1.1"])),
            client_cert=up_raw.get("client_cert"),
            client_key=up_raw.get("client_key"),
            client_key_password=up_raw.get("client_key_password"),
        )
        policy = PolicyConfig(
            allowlist=list(pol_raw.get("allowlist", [])),
            max_connections=int(pol_raw.get("max_connections", 200)),
            upstream_connect_timeout=float(pol_raw.get("upstream_connect_timeout", 5.0)),
            upstream_handshake_timeout=float(pol_raw.get("upstream_handshake_timeout", 10.0)),
            maxconn_wait_warn_ms=float(pol_raw.get("maxconn_wait_warn_ms", 200.0)),
        )
        logging_cfg = LoggingConfig(
            log_headers=bool(log_raw.get("log_headers", True)),
            log_body=bool(log_raw.get("log_body", False)),
            body_max_bytes=int(log_raw.get("body_max_bytes", 0)),
            redact_headers=[str(x).lower() for x in list(log_raw.get("redact_headers", ["authorization", "cookie", "x-api-key"]))],
            sample_rate=float(log_raw.get("sample_rate", 1.0)),
            h2_control_events=bool(log_raw.get("h2_control_events", False)),
            jsonl_path=log_raw.get("jsonl_path"),
        )

        listeners.append(
            ListenerConfig(
                name=str(item["name"]),
                listen=str(item["listen"]),
                tls=tls,
                upstream=upstream,
                policy=policy,
                logging=logging_cfg,
            )
        )
    return AppConfig(listeners=listeners)


# Security policy
class SecurityPolicy:
    def __init__(self, allowlist: List[str], redact_headers: List[str]):
        self.allowlist = allowlist or []
        self.redact_headers = set([h.lower() for h in (redact_headers or [])])

        self._nets: List[ipaddress._BaseNetwork] = []
        for c in self.allowlist:
            try:
                self._nets.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                LOG.error("Invalid CIDR in allowlist ignored: %r", c, exc_info=True)

    def allow(self, ip: str) -> bool:
        """Return True if client IP is allowed by allowlist. Empty allowlist = allow all."""
        if not self._nets:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        for n in self._nets:
            if addr in n:
                return True
        return False

    def allow_client(self, ip: str) -> bool:
        # Backward-compatible alias (older code used allow_client()).
        return self.allow(ip)

    def redact(self, headers: Dict[str, str]) -> Dict[str, str]:
        if not headers:
            return {}
        out: Dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() in self.redact_headers:
                out[k] = "***"
            else:
                out[k] = v
        return out


# Records (Traffic rows)
@dataclass
class TlsInfo:
    sni: Optional[str] = None
    alpn: Optional[str] = None
    version: Optional[str] = None
    cipher: Optional[str] = None


@dataclass
class HttpMessage:
    headers: Dict[str, str] = field(default_factory=dict)
    body_b64: Optional[str] = None
    body_truncated: bool = False
    content_length: Optional[int] = None


@dataclass
class RequestInfo(HttpMessage):
    method: Optional[str] = None
    path: Optional[str] = None
    authority: Optional[str] = None
    stream_id: Optional[int] = None
    grpc_service: Optional[str] = None
    grpc_method: Optional[str] = None


@dataclass
class ResponseInfo(HttpMessage):
    status: Optional[int] = None


@dataclass
class Event:
    """
    Request-level record shown in Traffic view.

    Created when a request completes (HTTP/2 stream or HTTP/1.1 request).

    Holds:
      - request/response metadata and optional bodies (base64) with policy + size limits
      - protocol: http1/http2/grpc
      - bytes_in/out and duration_ms
      - conn_id: linkage to ConnInfo for filtering and jump navigation.
    """
    kind: str  # "event"
    id: str
    ts_start: float
    ts_end: float
    listener: str
    client_ip: str
    client_port: int
    upstream_addr: str
    protocol: str  # http2/grpc/raw
    tls: TlsInfo
    request: RequestInfo
    response: ResponseInfo
    bytes_in: int
    bytes_out: int
    duration_ms: int
    flags: List[str] = field(default_factory=list)
    error: Optional[str] = None

    # link to connection
    conn_id: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class H2ControlRecord:
    kind: str  # "h2ctl"
    id: str
    ts: float
    listener: str
    client_ip: str
    client_port: int
    direction: str  # downstream|upstream
    h2_event: str   # SETTINGS|SETTINGS_ACK|GOAWAY|RST_STREAM|WINDOW_UPDATE|FLOW_BLOCK
    stream_id: Optional[int]
    details: Dict[str, Any] = field(default_factory=dict)

    # link to connection
    conn_id: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ConnLifecycleRecord:
    """
    Connection lifecycle marker for Traffic view.

    event:
      - "wait"  — delayed accept due to max_connections pressure (maxconn_wait)
      - "open"  — accepted connection
      - "close" — closed connection with outcome

    close fields:
      - closed_by: client/upstream/proxy
      - close_reason: completed / timeouts / resets / tls_in_fail / ...
      - duration_ms: connection lifetime
      - flags: extra markers (e.g. client_tls_fail)
      - conn_id: linkage to ConnInfo.
    """
    kind: str  # "conn"
    id: str
    ts: float
    listener: str
    client_ip: str
    client_port: int
    upstream_addr: str

    event: str  # "open" | "close" | "wait"
    proxy_version: Optional[str] = None   # none|v1|v2|invalid
    proxy_src: Optional[str] = None       # ip:port
    proxy_dst: Optional[str] = None       # ip:port
    closed_by: Optional[str] = None
    close_reason: Optional[str] = None
    duration_ms: Optional[int] = None
    flags: List[str] = field(default_factory=list)

    conn_id: Optional[str] = None       # link to connection

    tid: Optional[str] = None
    path: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class TlsHandshakeRecord:
    """
    TLS handshake record for Traffic view.

    side:
      - "in"  — TLS between client and proxy (downstream)
      - "out" — TLS between proxy and upstream
    outcome:
      - ok / fail
    reason:
      - coarse classified root cause (unknown_ca, cert_verify_failed, handshake_timeout, ...)
    category:
      - finer bucket for cert_verify_failed (expired / wrong_eku / unknown_ca / signature_failure / ...)
    detail:
      - raw-ish exception/detail string (shortened) for operator visibility
    tls:
      - version/cipher/alpn/sni (when available)
    conn_id:
      - linkage to the owning connection for drill-down and filtering.
    """
    kind: str  # "tls"
    id: str
    ts: float
    listener: str
    client_ip: str
    client_port: int
    side: str      # in|out
    outcome: str   # ok|fail

    reason: Optional[str] = None

    category: Optional[str] = None
    detail: Optional[str] = None

    tls: "TlsInfo" = field(default_factory=lambda: TlsInfo())
    upstream: Dict[str, Any] = field(default_factory=dict)

    # link to connection (auto-attached by store via contextvar in your code)
    conn_id: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


Record = Union[Event, H2ControlRecord, TlsHandshakeRecord, ConnLifecycleRecord]


class JsonlWriter:
    def __init__(self, path: str):
        self.path = path
        self._fh = open(self.path, "a", encoding="utf-8")

    def write(self, obj: Dict[str, Any]) -> None:
        self._fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class RecordStore:
    """
    Storage for Traffic view records (ring buffer).

    Holds mixed record types:
      - Event (http1/http2/grpc)
      - TlsHandshakeRecord (in/out)
      - ConnLifecycleRecord (open/wait/close)
      - H2ControlRecord (optional)

    Important:
      - add(rec) may auto-attach rec.conn_id from ContextVar CURRENT_CONN_ID,
        enabling conn=<uuid> filtering and Traffic <-> Connections navigation.
      - snapshot(limit=...) returns the newest records for UI rendering.
    """
    def __init__(self, max_events: int = 50_000, jsonl_path: Optional[str] = None):
        self._events: Deque[Record] = deque(maxlen=max_events)
        self._lock = asyncio.Lock()
        self._writer = JsonlWriter(jsonl_path) if jsonl_path else None

    async def add(self, rec: Record) -> None:
        """
        Append a record to the ring buffer, optionally writing JSONL.

        Best-effort:
          - attaches conn_id from CURRENT_CONN_ID if record supports it
          - does not raise on JSONL write errors (logs them)
        """
        # Attach conn_id automatically (if record supports it) from current task context.
        try:
            cid = CURRENT_CONN_ID.get()
            if cid and hasattr(rec, "conn_id"):
                if getattr(rec, "conn_id", None) in (None, ""):
                    setattr(rec, "conn_id", cid)
        except Exception:
            LOG.debug("RecordStore.add: failed to attach conn_id", exc_info=True)

        async with self._lock:
            self._events.append(rec)
            if self._writer:
                try:
                    self._writer.write(rec.to_json())
                except Exception:
                    # JSONL failure is important for offline analysis, but should not break proxy
                    log_throttled(
                        logging.WARNING,
                        "recordstore.jsonl_write",
                        "RecordStore.add: JSONL write failed",
                        interval_s=5.0,
                        exc_info=True,
                    )

    async def snapshot(self, limit: int = 4000) -> List[Record]:
        async with self._lock:
            return list(self._events)[-limit:]

    def close(self) -> None:
        """Close underlying JSONL writer (best-effort)."""
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                LOG.debug("RecordStore.close: writer.close failed", exc_info=True)


# Metrics
class Metrics:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._g: Dict[str, int] = {}
        self._by_listener: Dict[str, Dict[str, int]] = {}

    async def inc(self, key: str, n: int = 1, listener: Optional[str] = None) -> None:
        async with self._lock:
            self._g[key] = self._g.get(key, 0) + n
            if listener:
                d = self._by_listener.setdefault(listener, {})
                d[key] = d.get(key, 0) + n

    async def set(self, key: str, value: int, listener: Optional[str] = None) -> None:
        async with self._lock:
            self._g[key] = int(value)
            if listener:
                d = self._by_listener.setdefault(listener, {})
                d[key] = int(value)

    async def snapshot(self) -> Tuple[Dict[str, int], Dict[str, Dict[str, int]]]:
        async with self._lock:
            return dict(self._g), {k: dict(v) for k, v in self._by_listener.items()}


# Connection model + store (Connections view)
@dataclass
class ConnInfo:
    """
    Summary of a single TCP/TLS connection for Connections view.

    Contains:
      - client_* / upstream_* endpoints
      - opened_ts / last_activity_ts for age/idle diagnostics
      - tls_in/tls_out + alpn_in/out + sni_out
      - h2_open_streams / h2_total_streams for h2/grpc
      - closed_ts/close_reason/closed_by/last_error for final outcome and blame

    close_reason should be explicit when possible:
      - client_idle_timeout / upstream_idle_timeout
      - client_read_timeout / upstream_read_timeout
      - upstream_connect_timeout / upstream_handshake_timeout
      - protocol_error, proxy:completed, etc.
    """
    id: str
    listener: str
    client_ip: str
    client_port: int
    upstream_addr: str
    upstream_tls: bool

    opened_ts: float
    last_activity_ts: float

    # lifecycle (optional)
    closed_ts: Optional[float] = None
    close_reason: Optional[str] = None
    closed_by: Optional[str] = None  # "client" | "upstream" | "proxy"

    # TLS/ALPN
    tls_in: TlsInfo = field(default_factory=TlsInfo)
    tls_out: TlsInfo = field(default_factory=TlsInfo)

    alpn_in: Optional[str] = None
    alpn_out: Optional[str] = None
    sni_out: Optional[str] = None

    # HTTP/2 stream counters
    h2_open_streams: int = 0
    h2_total_streams: int = 0

    # misc
    last_error: Optional[str] = None
    error_count: int = 0
    proxy_version: Optional[str] = None   # none|v1|v2|invalid
    proxy_src: Optional[str] = None       # ip:port
    proxy_dst: Optional[str] = None       # ip:port

    # transport-level forensic flags: client_fin/upstream_fin/client_rst/upstream_rst/...
    close_flags: List[str] = field(default_factory=list)

    def age_s(self) -> int:
        return max(0, int(time.time() - self.opened_ts))

    def idle_s(self) -> int:
        ref_ts = self.closed_ts if self.closed_ts is not None else time.time()
        return max(0, int(ref_ts - self.last_activity_ts))


class ConnectionStore:
    """
    Storage for ConnInfo shown in Connections view.

    Usually maintains:
      - active connections (opened_ts..)
      - closed history (ring buffer) so short-lived connections remain visible in All/Closed modes

    Typical methods:
      - add(ConnInfo): register on accept (ASAP)
      - touch(conn_id): update last_activity_ts
      - set_tls_in / set_upstream / set_error: enrich diagnostics progressively
      - remove(conn_id,...): finalize and move to closed history
      - snapshot(include_closed=...): feed the UI modes active/all/closed
    """
    def __init__(self, closed_max: int = 2000):
        self._lock = asyncio.Lock()
        self._active: Dict[str, ConnInfo] = {}
        self._closed: Deque[ConnInfo] = deque(maxlen=int(closed_max))

    async def add(self, ci: "ConnInfo") -> None:
        """Register a connection as active."""
        try:
            async with self._lock:
                self._active[ci.id] = ci
        except Exception:
            LOG.warning("ConnectionStore.add failed conn_id=%s", getattr(ci, "id", None), exc_info=True)

    async def remove(
            self,
            conn_id: str,
            *,
            close_reason: Optional[str] = None,
            closed_by: Optional[str] = None,
            close_flags: Optional[List[str]] = None,
    ) -> Optional[ConnInfo]:
        """Finalize an active connection and move it into the closed history ring."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if not ci:
                    return None

                if close_reason is not None:
                    ci.close_reason = close_reason
                if closed_by is not None:
                    ci.closed_by = closed_by
                if close_flags is not None:
                    ci.close_flags = list(close_flags)

                # Ensure a visible error counter for failed/problematic closes even
                # if last_error was not set explicitly.
                cr_l = (ci.close_reason or "").lower()
                has_problem_close = any(x in cr_l for x in ("fail", "error", "timeout", "rst", "protocol"))
                if not has_problem_close and ci.close_flags:
                    for f in ci.close_flags:
                        ff = (f or "").lower()
                        if any(x in ff for x in ("fail", "error", "timeout", "rst", "protocol")):
                            has_problem_close = True
                            break
                if has_problem_close and ci.error_count <= 0:
                    ci.error_count = 1

                ci.closed_ts = time.time()

                self._active.pop(conn_id, None)
                self._closed.append(ci)
                return ci
        except Exception:
            LOG.warning("ConnectionStore.remove failed conn_id=%s", conn_id, exc_info=True)
            return None

    async def touch(self, conn_id: str) -> None:
        """Update last_activity_ts for an active connection (best-effort)."""
        try:
            async with self._lock:
                c = self._active.get(conn_id)
                if c:
                    c.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.touch failed conn_id=%s", conn_id, exc_info=True)

    async def set_last_path(self, conn_id: str, path: str) -> None:
        """Remember last observed request path/tid for this connection (best-effort)."""
        try:
            tid = _extract_tid(path)
        except Exception:
            tid = None
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.last_path = path
                    if tid is not None:
                        ci.last_tid = tid
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_last_path failed conn_id=%s path=%r", conn_id, path, exc_info=True)

    async def set_tls_in(self, conn_id: str, tls: TlsInfo, alpn: Optional[str]) -> None:
        """Persist downstream TLS info for the connection."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.tls_in = tls
                    ci.alpn_in = alpn
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_tls_in failed conn_id=%s", conn_id, exc_info=True)

    async def set_client_endpoint(self, conn_id: str, client_ip: str, client_port: int) -> None:
        """Update client endpoint (e.g. from PROXY protocol header)."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.client_ip = str(client_ip)
                    ci.client_port = int(client_port)
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_client_endpoint failed conn_id=%s", conn_id, exc_info=True)

    async def set_proxy_info(
            self,
            conn_id: str,
            *,
            proxy_version: Optional[str],
            proxy_src: Optional[str],
            proxy_dst: Optional[str],
    ) -> None:
        """Persist detected inbound PROXY protocol metadata for connection."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.proxy_version = proxy_version
                    ci.proxy_src = proxy_src
                    ci.proxy_dst = proxy_dst
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_proxy_info failed conn_id=%s", conn_id, exc_info=True)

    async def set_upstream(
            self,
            conn_id: str,
            tls_out: TlsInfo,
            alpn_out: Optional[str],
            sni_out: Optional[str],
    ) -> None:
        """Persist upstream TLS/ALPN/SNI info for the connection."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.tls_out = tls_out
                    ci.alpn_out = alpn_out
                    ci.sni_out = sni_out
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_upstream failed conn_id=%s", conn_id, exc_info=True)

    async def set_error(self, conn_id: str, err: str) -> None:
        """Set last_error for active connection (truncated)."""
        try:
            async with self._lock:
                c = self._active.get(conn_id)
                if c:
                    c.last_error = (err or "")[:500]
                    c.error_count = int(getattr(c, "error_count", 0) or 0) + 1
                    c.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.set_error failed conn_id=%s err=%r", conn_id, (err or "")[:120], exc_info=True)

    async def h2_stream_open(self, conn_id: str) -> None:
        """Increment stream counters for HTTP/2 connection."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.h2_total_streams += 1
                    ci.h2_open_streams += 1
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.h2_stream_open failed conn_id=%s", conn_id, exc_info=True)

    async def h2_stream_close(self, conn_id: str) -> None:
        """Decrement open stream counters for HTTP/2 connection."""
        try:
            async with self._lock:
                ci = self._active.get(conn_id)
                if ci:
                    ci.h2_open_streams = max(0, ci.h2_open_streams - 1)
                    ci.last_activity_ts = time.time()
        except Exception:
            LOG.debug("ConnectionStore.h2_stream_close failed conn_id=%s", conn_id, exc_info=True)

    async def snapshot(self, *, include_closed: bool = False) -> List[ConnInfo]:
        """Return a snapshot for UI: active only or active+closed history."""
        try:
            async with self._lock:
                if not include_closed:
                    return list(self._active.values())
                active = list(self._active.values())
                active.sort(key=lambda c: c.opened_ts)
                return active + list(self._closed)
        except Exception:
            LOG.warning("ConnectionStore.snapshot failed include_closed=%s", include_closed, exc_info=True)
            return []



# gRPC helpers
def grpc_parse_path(path: str) -> Tuple[Optional[str], Optional[str]]:
    if not path or not path.startswith("/"):
        return None, None
    try:
        p = path[1:]
        if "/" not in p:
            return None, None
        svc, m = p.split("/", 1)
        return svc or None, m or None
    except Exception:
        return None, None


def is_grpc(headers: Dict[str, str]) -> bool:
    ct = None
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v
            break
    if not ct:
        return False
    return "application/grpc" in ct.lower()


class UpstreamConnectTimeout(Exception):
    pass


class UpstreamHandshakeTimeout(Exception):
    pass


def classify_close_reason(exc: Optional[BaseException], eof: bool = False) -> str:
    """
    Classify an exception/state into a concise connection close_reason.

    Goal: an actionable reason that helps assign blame quickly.
    Examples:
      - client_read_timeout / upstream_read_timeout
      - client_idle_timeout / upstream_idle_timeout
      - upstream_connect_timeout / upstream_handshake_timeout
      - protocol_error / proxy_error:<...> / completed
    """
    if eof:
        return "eof"
    if exc is None:
        return "normal"

    # upstream stage-specific timeouts
    if isinstance(exc, UpstreamConnectTimeout):
        return "upstream_connect_timeout"
    if isinstance(exc, UpstreamHandshakeTimeout):
        return "upstream_handshake_timeout"

    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "rst"
    if isinstance(exc, BrokenPipeError):
        return "broken_pipe"

    msg = str(exc).lower()
    if "incomplete read" in msg:
        return "eof"
    if "ssl" in msg and ("alert" in msg or "handshake" in msg or "tls" in msg):
        return "tls_error"
    if "protocol error" in msg:
        return "protocol_error"
    return "error"


def _one_line(s: str, limit: int = 300) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ").strip()
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def _ssl_detail_from_exc(e: BaseException) -> str:
    """
    Best-effort extraction of the most informative text from SSL exceptions.
    """
    # The most useful case on many platforms:
    # ssl.SSLCertVerificationError has verify_message / verify_code
    vm = getattr(e, "verify_message", None)
    if isinstance(vm, str) and vm.strip():
        return vm.strip()

    # Often contains OpenSSL message text:
    s = str(e) or ""
    s = s.strip()
    if s:
        return s

    # Fallback: join args
    try:
        if getattr(e, "args", None):
            j = " ".join(str(x) for x in e.args if x is not None).strip()
            if j:
                return j
    except Exception:
        pass

    return ""

def classify_cert_verify_failure(e: BaseException) -> Tuple[str, str, str]:
    """
    Returns (reason, category, detail)

    reason:
      - always 'cert_verify_failed' for verification failures
    category:
      - expired | wrong_eku | unknown_ca | signature_failure | cert_verify_failed (fallback)
    detail:
      - raw-ish text
    """
    detail_raw = _ssl_detail_from_exc(e)
    detail = _one_line(detail_raw, limit=400)
    d = detail.lower()

    # ---- expired ----
    if ("has expired" in d) or ("expired certificate" in d) or ("certificate expired" in d):
        return "cert_verify_failed", "expired", detail

    # ---- wrong EKU / purpose ----
    # OpenSSL typical: "unsuitable certificate purpose" / "unsupported certificate purpose" / "invalid purpose"
    if ("unsuitable certificate purpose" in d) or ("unsupported certificate purpose" in d) or ("invalid purpose" in d):
        return "cert_verify_failed", "wrong_eku", detail

    # ---- unknown CA / chain issues ----
    # Typical: "unable to get local issuer certificate", "unable to verify the first certificate",
    # "self signed certificate", "self-signed certificate in certificate chain", "unknown ca"
    if (
        ("unable to get local issuer certificate" in d) or
        ("unable to get issuer certificate" in d) or
        ("unable to verify the first certificate" in d) or
        ("self signed certificate" in d) or
        ("self-signed certificate" in d) or
        ("certificate chain" in d and "self" in d and "signed" in d) or
        ("unknown ca" in d)
    ):
        return "cert_verify_failed", "unknown_ca", detail

    # ---- signature failure ----
    # Typical: "certificate signature failure", "signature failure", "bad signature"
    if ("certificate signature failure" in d) or ("signature failure" in d) or ("bad signature" in d):
        return "cert_verify_failed", "signature_failure", detail

    # fallback
    return "cert_verify_failed", "cert_verify_failed", detail


def classify_tls_in_fail(e: Exception) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Return:
      (reason, category, detail)

    reason:
      - stable coarse reason for filtering (keeps existing behavior)
    category:
      - operator-friendly bucket (expired / wrong_eku / unknown_ca / signature_failure / ...)
    detail:
      - short diagnostic string (original message, verify_message, etc.)

    This is intentionally best-effort and tolerant to different OpenSSL/Python error texts.
    """
    # default coarse reason (keep your old expectations)
    reason = "tls_error"

    # best-effort detail extraction
    detail: Optional[str] = None
    category: Optional[str] = None

    # Helper: normalize text
    def _norm(s: str) -> str:
        return " ".join((s or "").strip().split()).lower()

    # Pull the "best" message we can find
    try:
        # SSLCertVerificationError has verify_message / verify_code
        if isinstance(e, ssl.SSLCertVerificationError):
            reason = "cert_verify_failed"
            msg = getattr(e, "verify_message", None) or str(e)
            code = getattr(e, "verify_code", None)
            if code is not None:
                detail = f"verify_code={code} {msg}".strip()
            else:
                detail = msg.strip()
        elif isinstance(e, ssl.SSLError):
            # many verify failures arrive as generic SSLError
            msg = str(e) or repr(e)
            n = _norm(msg)
            if "certificate verify failed" in n or "cert_verify_failed" in n:
                reason = "cert_verify_failed"
            else:
                reason = "tls_error"
            detail = msg.strip()
        else:
            # connection reset during handshake, etc.
            detail = str(e).strip() if str(e) else repr(e)
            # keep existing style: a reset is still a TLS failure at this stage
            # (but not necessarily verify-related)
            reason = "tls_error"
    except Exception:
        detail = repr(e)

    n = _norm(detail or "")

    # --- finer categorization (only meaningful if cert_verify_failed) ---
    if reason == "cert_verify_failed":
        # expired
        if ("expired" in n) or ("has expired" in n) or ("certificate_expired" in n):
            category = "expired"

        # wrong EKU / purpose
        elif ("extended key usage" in n) or ("eku" in n) or ("unsuitable certificate purpose" in n) or ("unsupported certificate purpose" in n) or ("wrong purpose" in n):
            category = "wrong_eku"

        # unknown CA / chain / issuer problems
        elif ("unknown ca" in n) or ("self signed" in n) or ("unable to get local issuer" in n) or ("unable to get issuer certificate" in n) or ("unable to verify the first certificate" in n) or ("certificate chain" in n):
            category = "unknown_ca"

        # signature failure / bad signature
        elif ("bad signature" in n) or ("signature failure" in n) or ("invalid signature" in n) or ("wrong signature" in n) or ("certificate signature failure" in n):
            category = "signature_failure"

        else:
            category = "cert_verify_failed"

    # Trim detail to be safe for UI/jsonl
    if detail:
        detail = detail[:500]

    return reason, category, detail


# TLS error classification
def classify_ssl_error(e: BaseException) -> str:
    """
    Convert a TLS handshake exception into a short, UI-friendly category.

    Examples:
      - unknown_ca
      - cert_required
      - handshake_timeout
      - wrong_version
      - protocol_error
      - other:<type>

    Used by:
      - TlsHandshakeRecord.reason
      - conn_store.set_error("tls_in_fail: ..."/"tls_out_fail: ...")
    """
    # upstream stage-specific timeouts
    if isinstance(e, UpstreamConnectTimeout):
        return "upstream_connect_timeout"
    if isinstance(e, UpstreamHandshakeTimeout):
        return "upstream_handshake_timeout"

    s = str(e).lower()
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    if "no application protocol" in s or "no_application_protocol" in s:
        return "no_application_protocol"
    if "unknown ca" in s or "unknown_ca" in s:
        return "unknown_ca"
    if "bad certificate" in s or "bad_certificate" in s:
        return "bad_certificate"
    if "handshake failure" in s or "handshake_failure" in s:
        return "handshake_failure"
    if "no shared cipher" in s or "no_shared_cipher" in s:
        return "no_shared_cipher"
    if "protocol version" in s or "unsupported protocol" in s or "wrong version" in s:
        return "protocol_version"
    if "certificate verify failed" in s:
        return "cert_verify_failed"
    if "wrongpass" in s:
        return "wrongpass"
    return "ssl_error"


def build_inbound_ssl_context(tls: TlsConfig) -> ssl.SSLContext:
    """
    TLS context for incoming (client->proxy) side.
    Uses server-side TLS, optional client cert verification (mTLS).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # cert/key
    ctx.load_cert_chain(certfile=tls.cert, keyfile=tls.key)

    # TLS minimum version
    mv = (tls.min_version or "").upper().strip()
    if mv in ("TLS1.3", "TLSV1.3"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    elif mv in ("TLS1.2", "TLSV1.2", ""):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        # safe default
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # ALPN
    if tls.alpn:
        ctx.set_alpn_protocols(list(tls.alpn))

    # mTLS
    if tls.require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if tls.client_ca:
            ctx.load_verify_locations(cafile=tls.client_ca)
    else:
        ctx.verify_mode = ssl.CERT_NONE
        # если CA задан — можно оставить как "опционально" (CERT_OPTIONAL),
        # но обычно это лишняя магия; оставляем CERT_NONE.

    return ctx


# Upstream TLS builder (with outgoing mTLS)
def build_upstream_ssl_context(up: UpstreamConfig) -> Tuple[Optional[ssl.SSLContext], Optional[str]]:
    if not up.tls:
        return None, None

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    try:
        ctx.set_alpn_protocols(list(up.alpn) if up.alpn else ["h2", "http/1.1"])
    except NotImplementedError:
        pass

    if up.client_cert and up.client_key:
        ctx.load_cert_chain(certfile=up.client_cert, keyfile=up.client_key, password=up.client_key_password)

    if not up.verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if up.ca:
            ctx.load_verify_locations(cafile=up.ca)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    up_host, _ = _parse_hostport(up.addr)
    server_hostname = up.server_name or up_host
    return ctx, server_hostname


class ListenerRuntime:
    """
    Runtime for a single listener (one config section).

    Responsibilities:
      - start a TCP server and accept connections (asyncio.start_server)
      - perform manual TLS-in upgrade (loop.start_tls) in order to:
          * report TLS handshake failures in Traffic
          * capture negotiated SNI/ALPN/version/cipher
      - enforce max_connections via a semaphore and record waiting diagnostics (maxconn_wait)
      - create and run ProxyConnection, maintaining connection lifecycle in ConnectionStore:
          * add(...) immediately on accept (so short-lived connections are not lost)
          * remove(...) in finally (move to closed ring buffer)
      - emit Traffic timeline records (ConnLifecycleRecord / TlsHandshakeRecord)

    Important:
      - all store.add(...) calls within a connection handler should be associated with the
        correct conn_id (typically via a ContextVar like CURRENT_CONN_ID).
    """
    def __init__(self, cfg: ListenerConfig, store: RecordStore, conn_store: ConnectionStore, metrics: Metrics):
        self.cfg = cfg
        self.store = store
        self.conn_store = conn_store
        self.metrics = metrics

        self.running = False
        self.active_conns = 0
        self.errors = 0

        self._policy = SecurityPolicy(cfg.policy.allowlist, cfg.logging.redact_headers)
        self._conn_sem = asyncio.Semaphore(cfg.policy.max_connections)

        self._server: Optional[asyncio.AbstractServer] = None

        self._srv_sock: Optional[socket.socket] = None
        self._accept_task: Optional[asyncio.Task] = None

        # store SNI from servername callback (sslobj -> sni)
        self._sni_map: "weakref.WeakKeyDictionary[ssl.SSLObject, str]" = weakref.WeakKeyDictionary()

    def _build_incoming_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(self.cfg.tls.cert, self.cfg.tls.key)
        except Exception:
            LOG.error("TLS-in: failed to load cert chain listener=%s cert=%r key=%r",
                      self.cfg.name, getattr(self.cfg.tls, "cert", None), getattr(self.cfg.tls, "key", None),
                      exc_info=True)
            raise

        minv = self.cfg.tls.min_version.upper().replace(".", "").replace("V", "")
        if minv in ("TLS1_2", "TLS12", "TLS1.2"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        elif minv in ("TLS1_3", "TLS13", "TLS1.3"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.cfg.tls.alpn:
            try:
                ctx.set_alpn_protocols(self.cfg.tls.alpn)
            except Exception:
                LOG.warning("TLS-in: failed to set ALPN listener=%s alpn=%r",
                            self.cfg.name, self.cfg.tls.alpn, exc_info=True)

        # incoming mTLS
        if self.cfg.tls.require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self.cfg.tls.client_ca:
                try:
                    ctx.load_verify_locations(cafile=self.cfg.tls.client_ca)
                except Exception:
                    LOG.error("TLS-in: failed to load client CA listener=%s ca=%r",
                              self.cfg.name, self.cfg.tls.client_ca, exc_info=True)
                    raise
            else:
                raise RuntimeError(f"listener {self.cfg.name}: require_client_cert=true but tls.client_ca is null")
        else:
            ctx.verify_mode = ssl.CERT_NONE

        def _sni_cb(sslobj: ssl.SSLObject, servername: str, _ctx: ssl.SSLContext):
            try:
                if servername:
                    self._sni_map[sslobj] = servername
            except Exception:
                # optional best-effort mapping; never break handshake
                LOG.debug("TLS-in: SNI callback failed listener=%s servername=%r",
                          self.cfg.name, servername, exc_info=True)

        try:
            ctx.set_servername_callback(_sni_cb)
        except Exception:
            # optional feature; not fatal
            LOG.debug("TLS-in: set_servername_callback not supported listener=%s", self.cfg.name, exc_info=True)

        return ctx

    async def start(self) -> None:
        host, port = _parse_hostport(self.cfg.listen)

        # manual TLS-in context (optional)
        self._ssl_ctx_in: Optional[ssl.SSLContext] = None
        if self.cfg.tls:
            try:
                self._ssl_ctx_in = self._build_incoming_ssl_context()
            except Exception:
                LOG.error("Listener start failed: cannot build TLS-in context listener=%s", self.cfg.name,
                          exc_info=True)
                raise

        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host=host,
                port=port,
                ssl=None,  # IMPORTANT: manual TLS happens later
                start_serving=True,
            )
        except Exception:
            LOG.error("Listener start failed: start_server error listener=%s listen=%s",
                      self.cfg.name, self.cfg.listen, exc_info=True)
            raise

        self.running = True
        try:
            await self.metrics.inc("listeners_started", 1, self.cfg.name)
        except Exception:
            LOG.debug("metrics.inc failed listeners_started listener=%s", self.cfg.name, exc_info=True)

    async def stop(self) -> None:
        # stop accepting new conns
        srv = getattr(self, "_server", None)
        if srv is not None:
            try:
                srv.close()
                await srv.wait_closed()
            except Exception:
                LOG.debug("Listener stop: server close failed listener=%s", self.cfg.name, exc_info=True)
            self._server = None

        # best-effort: cancel tracked tasks if you keep them
        tasks = list(getattr(self, "_tasks", set()))
        for t in tasks:
            try:
                t.cancel()
            except Exception:
                LOG.debug("Listener stop: cancel task failed listener=%s", self.cfg.name, exc_info=True)

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                LOG.debug("Listener stop: gather tasks failed listener=%s", self.cfg.name, exc_info=True)

        self._tasks = set()


    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Accept-handler used by asyncio.start_server.

        Steps:
          1) allowlist check (fast deny)
          2) acquire max_connections semaphore (measure waited_ms for maxconn_wait diagnostics)
          3) conn_store.add(ConnInfo) immediately (critical for short-lived connections)
          4) manual TLS-in (loop.start_tls) + emit TlsHandshakeRecord (ok/fail)
          5) create ProxyConnection and run conn.run()
          6) finally:
             - close writer
             - conn_store.remove(...) with close_reason/closed_by/flags
             - emit ConnLifecycleRecord(event=close) to Traffic

        Important:
          - CURRENT_CONN_ID must be set during the handler lifetime so all store.add(...)
            calls automatically get the correct conn_id for filtering/jumps.
        """
        peer = writer.get_extra_info("peername") or ("?", 0)
        client_ip = str(peer[0])
        try:
            client_port = int(peer[1])
        except Exception:
            client_port = 0

        if not self._policy.allow(client_ip):
            try:
                await self.metrics.inc("connections_denied", 1, self.cfg.name)
            except Exception:
                LOG.debug("metrics.inc failed connections_denied listener=%s", self.cfg.name, exc_info=True)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                LOG.debug("deny: close client socket failed listener=%s client=%s:%s",
                          self.cfg.name, client_ip, client_port, exc_info=True)
            return

        # --- max connections (semaphore) with wait diagnostics ---
        t_wait0 = time.time()
        await self._conn_sem.acquire()
        waited_ms = int((time.time() - t_wait0) * 1000)

        try:
            await self.metrics.inc("connections_accepted", 1, self.cfg.name)
        except Exception:
            LOG.debug("metrics.inc failed connections_accepted listener=%s", self.cfg.name, exc_info=True)

        conn_id = str(uuid.uuid4())
        opened_ts = time.time()

        # bind conn_id to this task context so store.add() can auto-attach conn_id
        token = None
        try:
            token = CURRENT_CONN_ID.set(conn_id)
        except Exception:
            token = None
            LOG.debug("CURRENT_CONN_ID.set failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

        # register connection ASAP
        try:
            await self.conn_store.add(
                ConnInfo(
                    id=conn_id,
                    listener=self.cfg.name,
                    client_ip=client_ip,
                    client_port=client_port,
                    upstream_addr=self.cfg.upstream.addr,
                    upstream_tls=bool(self.cfg.upstream.tls),
                    opened_ts=opened_ts,
                    last_activity_ts=opened_ts,
                )
            )
        except Exception:
            LOG.warning("conn_store.add failed listener=%s conn_id=%s client=%s:%s",
                        self.cfg.name, conn_id, client_ip, client_port, exc_info=True)

        # If accept was delayed by max_connections pressure -> record "maxconn_wait"
        try:
            warn_ms = float(getattr(self.cfg.policy, "maxconn_wait_warn_ms", 200.0) or 200.0)
        except Exception:
            warn_ms = 200.0

        if waited_ms >= int(warn_ms):
            try:
                await self.metrics.inc("maxconn_wait", 1, self.cfg.name)
            except Exception:
                LOG.debug("metrics.inc failed maxconn_wait listener=%s", self.cfg.name, exc_info=True)

            try:
                await self.conn_store.set_error(conn_id, f"maxconn_wait:{waited_ms}ms")
            except Exception:
                LOG.debug("conn_store.set_error failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

            try:
                await self.store.add(
                    ConnLifecycleRecord(
                        kind="conn",
                        id=str(uuid.uuid4()),
                        ts=opened_ts,
                        listener=self.cfg.name,
                        client_ip=client_ip,
                        client_port=client_port,
                        upstream_addr=self.cfg.upstream.addr,
                        event="wait",
                        close_reason=f"{waited_ms}ms",
                    )
                )
            except Exception:
                LOG.debug("store.add(conn wait) failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

        close_reason: Optional[str] = None
        closed_by: Optional[str] = None
        close_flags: List[str] = []
        proxy_header = ProxyProtocolHeader()
        proxy_version = "none"
        proxy_src: Optional[str] = None
        proxy_dst: Optional[str] = None

        try:
            # Auto-detect incoming PROXY protocol (v1/v2/none) before TLS-in.
            try:
                transport = getattr(writer, "_transport", None)
                if transport is None:
                    transport = writer.transport  # type: ignore[attr-defined]
                sock_obj = transport.get_extra_info("socket") if transport is not None else writer.get_extra_info("socket")
                if transport is not None:
                    try:
                        transport.pause_reading()
                    except Exception:
                        LOG.debug(
                            "pause_reading failed listener=%s conn_id=%s",
                            self.cfg.name,
                            conn_id,
                            exc_info=True,
                        )
                try:
                    proxy_header = await detect_proxy_protocol_header(sock_obj, timeout_s=1.0)
                finally:
                    if transport is not None:
                        try:
                            transport.resume_reading()
                        except Exception:
                            LOG.debug(
                                "resume_reading failed listener=%s conn_id=%s",
                                self.cfg.name,
                                conn_id,
                                exc_info=True,
                            )
            except ValueError as e:
                close_reason = "proxy_protocol_error"
                closed_by = "client"
                close_flags = ["client_proxy_protocol_error"]
                proxy_version = "invalid"
                await self.conn_store.set_error(conn_id, f"proxy protocol parse failed: {e}")
                return
            except Exception as e:
                LOG.debug("detect_proxy_protocol_header failed listener=%s conn_id=%s: %s",
                          self.cfg.name, conn_id, e, exc_info=True)

            if proxy_header.present:
                if proxy_header.version in (1, 2):
                    proxy_version = f"v{proxy_header.version}"
                if proxy_header.source_ip:
                    client_ip = proxy_header.source_ip
                if proxy_header.source_port is not None:
                    client_port = int(proxy_header.source_port)
                if proxy_header.source_ip and proxy_header.source_port is not None:
                    proxy_src = f"{proxy_header.source_ip}:{int(proxy_header.source_port)}"
                if proxy_header.dest_ip and proxy_header.dest_port is not None:
                    proxy_dst = f"{proxy_header.dest_ip}:{int(proxy_header.dest_port)}"
                try:
                    await self.conn_store.set_client_endpoint(conn_id, client_ip, client_port)
                except Exception:
                    LOG.debug("conn_store.set_client_endpoint failed listener=%s conn_id=%s",
                              self.cfg.name, conn_id, exc_info=True)
            try:
                await self.conn_store.set_proxy_info(
                    conn_id,
                    proxy_version=proxy_version,
                    proxy_src=proxy_src,
                    proxy_dst=proxy_dst,
                )
            except Exception:
                LOG.debug("conn_store.set_proxy_info failed listener=%s conn_id=%s", self.cfg.name, conn_id,
                          exc_info=True)

            # Traffic timeline: conn open (already with final client endpoint and proxy metadata)
            try:
                await self.store.add(
                    ConnLifecycleRecord(
                        kind="conn",
                        id=str(uuid.uuid4()),
                        ts=opened_ts,
                        listener=self.cfg.name,
                        client_ip=client_ip,
                        client_port=client_port,
                        upstream_addr=self.cfg.upstream.addr,
                        event="open",
                        proxy_version=proxy_version,
                        proxy_src=proxy_src,
                        proxy_dst=proxy_dst,
                    )
                )
            except Exception:
                LOG.debug("store.add(conn open) failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

            # -------- manual TLS-in --------
            ssl_ctx_in = getattr(self, "_ssl_ctx_in", None)
            if ssl_ctx_in is not None:
                loop = asyncio.get_running_loop()

                transport = getattr(writer, "_transport", None)
                if transport is None:
                    transport = writer.transport  # type: ignore[attr-defined]
                protocol = transport.get_protocol()

                ts_tls = time.time()
                try:
                    tls_transport = await loop.start_tls(
                        transport,
                        protocol,
                        ssl_ctx_in,
                        server_side=True,
                        ssl_handshake_timeout=10.0,
                    )

                    # best-effort patch writer/reader transports
                    try:
                        writer._transport = tls_transport  # type: ignore[attr-defined]
                    except Exception:
                        LOG.debug("TLS-in: failed to patch writer._transport listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)
                    try:
                        reader._transport = tls_transport  # type: ignore[attr-defined]
                    except Exception:
                        LOG.debug("TLS-in: failed to patch reader._transport listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)

                    sslobj: Optional[ssl.SSLObject] = writer.get_extra_info("ssl_object")
                    tls_in = ProxyConnection.tls_info_from_sslobj_static(sslobj)

                    try:
                        if sslobj is not None:
                            sni = self._sni_map.get(sslobj)
                            if sni:
                                tls_in.sni = sni
                    except Exception:
                        LOG.debug("TLS-in: failed to read sni_map listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)

                    alpn_in = (tls_in.alpn or "").lower() if tls_in.alpn else None

                    try:
                        await self.store.add(
                            TlsHandshakeRecord(
                                kind="tls",
                                id=str(uuid.uuid4()),
                                ts=ts_tls,
                                listener=self.cfg.name,
                                client_ip=client_ip,
                                client_port=client_port,
                                side="in",
                                outcome="ok",
                                reason=None,
                                category=None, 
                                detail=None,  
                                tls=tls_in,
                                upstream={"addr": self.cfg.upstream.addr},
                            )
                        )
                    except Exception:
                        LOG.debug("store.add(tls in ok) failed listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)

                    try:
                        await self.conn_store.set_tls_in(conn_id, tls_in, alpn_in)
                    except Exception:
                        LOG.debug("conn_store.set_tls_in failed listener=%s conn_id=%s", self.cfg.name, conn_id,
                                  exc_info=True)

                except Exception as e:
                    # richer classification (expired / wrong_eku / unknown_ca / signature_failure + detail)
                    reason, category, detail = classify_tls_in_fail(e)

                    try:
                        await self.store.add(
                            TlsHandshakeRecord(
                                kind="tls",
                                id=str(uuid.uuid4()),
                                ts=ts_tls,
                                listener=self.cfg.name,
                                client_ip=client_ip,
                                client_port=client_port,
                                side="in",
                                outcome="fail",
                                reason=reason,
                                category=category,  
                                detail=detail,  
                                tls=TlsInfo(),
                                upstream={"addr": self.cfg.upstream.addr},
                            )
                        )
                    except Exception:
                        LOG.debug("store.add(tls in fail) failed listener=%s conn_id=%s reason=%s",
                                  self.cfg.name, conn_id, reason, exc_info=True)

                    try:
                        # include category/detail in last_error so Connections view is useful too
                        extra = ""
                        if category:
                            extra += f" category={category}"
                        if detail:
                            extra += f" detail={detail}"
                        await self.conn_store.set_error(conn_id, f"tls_in_fail: {reason}{extra}")
                    except Exception:
                        LOG.debug("conn_store.set_error(tls_in_fail) failed listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)

                    close_reason = "tls_in_fail"
                    closed_by = "client"
                    close_flags = ["client_tls_fail"]

                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        LOG.debug("TLS-in fail: close client socket failed listener=%s conn_id=%s",
                                  self.cfg.name, conn_id, exc_info=True)
                    return

            # -------- run proxy --------
            conn = ProxyConnection(
                self,
                conn_id,
                client_ip,
                client_port,
                reader,
                writer,
                proxy_header=proxy_header,
            )
            await conn.run()

            close_reason = getattr(conn, "close_reason", None) or "completed"
            closed_by = getattr(conn, "closed_by", None) or "proxy"
            close_flags = list(getattr(conn, "close_flags", None) or [])

        except asyncio.CancelledError:
            close_reason = "cancelled"
            closed_by = "proxy"
            close_flags = []
            raise

        except Exception as e:
            close_reason = classify_close_reason(e)
            closed_by = "proxy"
            close_flags = []
            try:
                await self.conn_store.set_error(conn_id, f"handler error: {e}")
            except Exception:
                LOG.debug("conn_store.set_error(handler error) failed listener=%s conn_id=%s", self.cfg.name, conn_id,
                          exc_info=True)
            LOG.warning("connection handler failed listener=%s conn_id=%s client=%s:%s reason=%s",
                        self.cfg.name, conn_id, client_ip, client_port, close_reason, exc_info=True)

        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                await writer.wait_closed()
            except Exception:
                LOG.debug("finally: close client socket failed listener=%s conn_id=%s",
                          self.cfg.name, conn_id, exc_info=True)

            ci_closed: Optional[ConnInfo] = None
            try:
                ci_closed = await self.conn_store.remove(
                    conn_id,
                    close_reason=close_reason,
                    closed_by=closed_by,
                    close_flags=close_flags,
                )
            except Exception:
                LOG.warning("conn_store.remove failed listener=%s conn_id=%s close_reason=%r closed_by=%r",
                            self.cfg.name, conn_id, close_reason, closed_by, exc_info=True)

            tid = None
            path = None
            try:
                if ci_closed is not None:
                    tid = getattr(ci_closed, "last_tid", None)
                    path = getattr(ci_closed, "last_path", None)
            except Exception:
                LOG.debug(
                    "extract close tid/path failed listener=%s conn_id=%s",
                    self.cfg.name,
                    conn_id,
                    exc_info=True,
                )

            close_client_ip = client_ip
            close_client_port = client_port
            close_proxy_version = proxy_version
            close_proxy_src = proxy_src
            close_proxy_dst = proxy_dst
            try:
                if ci_closed is not None:
                    close_client_ip = getattr(ci_closed, "client_ip", close_client_ip) or close_client_ip
                    close_client_port = int(getattr(ci_closed, "client_port", close_client_port) or close_client_port)
                    close_proxy_version = getattr(ci_closed, "proxy_version", close_proxy_version) or close_proxy_version
                    close_proxy_src = getattr(ci_closed, "proxy_src", close_proxy_src) or close_proxy_src
                    close_proxy_dst = getattr(ci_closed, "proxy_dst", close_proxy_dst) or close_proxy_dst
            except Exception:
                LOG.debug(
                    "extract close endpoint/proxy fields failed listener=%s conn_id=%s",
                    self.cfg.name,
                    conn_id,
                    exc_info=True,
                )

            try:
                ts1 = time.time()
                dur_ms = int((ts1 - opened_ts) * 1000)
                await self.store.add(
                    ConnLifecycleRecord(
                        kind="conn",
                        id=str(uuid.uuid4()),
                        ts=ts1,
                        listener=self.cfg.name,
                        client_ip=close_client_ip,
                        client_port=close_client_port,
                        upstream_addr=self.cfg.upstream.addr,
                        event="close",
                        proxy_version=close_proxy_version,
                        proxy_src=close_proxy_src,
                        proxy_dst=close_proxy_dst,
                        closed_by=closed_by,
                        close_reason=close_reason,
                        duration_ms=dur_ms,
                        flags=list(close_flags),
                        tid=tid,
                        path=path,
                    )
                )
            except Exception:
                LOG.debug("store.add(conn close) failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

            # reset contextvar to avoid leaking conn_id into unrelated tasks
            try:
                if token is not None:
                    CURRENT_CONN_ID.reset(token)
            except Exception:
                LOG.debug("CURRENT_CONN_ID.reset failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)

            try:
                self._conn_sem.release()
            except Exception:
                LOG.error("semaphore release failed listener=%s conn_id=%s", self.cfg.name, conn_id, exc_info=True)


class ListenerManager:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        jsonl = None
        for l in cfg.listeners:
            if l.logging.jsonl_path:
                jsonl = l.logging.jsonl_path
                break
        self.store = RecordStore(max_events=50_000, jsonl_path=jsonl)
        self.conn_store = ConnectionStore(closed_max=2000)
        self.metrics = Metrics()
        self.listeners: Dict[str, ListenerRuntime] = {
            l.name: ListenerRuntime(l, self.store, self.conn_store, self.metrics)
            for l in cfg.listeners
        }

    async def start_all(self) -> None:
        for lr in self.listeners.values():
            await lr.start()

    async def stop_all(self) -> None:
        for lr in self.listeners.values():
            await lr.stop()
        self.store.close()

    async def reload(self, path: str) -> None:
        await self.stop_all()
        new_cfg = load_config(path)
        self.__init__(new_cfg)
        await self.start_all()


# ==========================================================
# Body tools: hexdump + gRPC frames decode
# ==========================================================

def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def fmt_full(ts: float) -> str:
    lt = time.localtime(ts)
    ms = int((ts - int(ts)) * 1000)
    return time.strftime("%Y-%m-%d %H:%M:%S", lt) + f".{ms:03d}"


def hexdump_ascii(data: bytes, width: int = 16, max_bytes: Optional[int] = None) -> List[str]:
    if max_bytes is not None:
        data = data[:max_bytes]
    out: List[str] = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        out.append(f"  {off:08x}  {hex_part}  |{ascii_part}|")
    return out


def extract_printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    res: List[str] = []
    cur: bytearray = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                res.append(cur.decode("ascii", errors="ignore"))
            cur.clear()
    if len(cur) >= min_len:
        res.append(cur.decode("ascii", errors="ignore"))

    seen = set()
    out: List[str] = []
    for s in res:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:50]


@dataclass
class GrpcFrame:
    index: int
    compressed_flag: int
    msg_len: int
    payload: bytes
    complete: bool
    note: Optional[str] = None


def parse_grpc_frames(raw: bytes) -> List[GrpcFrame]:
    frames: List[GrpcFrame] = []
    i = 0
    idx = 0
    n = len(raw)
    while i < n:
        if n - i < 5:
            frames.append(GrpcFrame(index=idx, compressed_flag=0, msg_len=0, payload=raw[i:], complete=False,
                                    note=f"incomplete header ({n-i} bytes)"))
            break
        flag = raw[i]
        msg_len = int.from_bytes(raw[i+1:i+5], "big", signed=False)
        i += 5
        if n - i < msg_len:
            payload = raw[i:]
            frames.append(GrpcFrame(index=idx, compressed_flag=flag, msg_len=msg_len, payload=payload, complete=False,
                                    note=f"incomplete payload (have {len(payload)} of {msg_len})"))
            break
        payload = raw[i:i+msg_len]
        i += msg_len
        frames.append(GrpcFrame(index=idx, compressed_flag=flag, msg_len=msg_len, payload=payload, complete=True))
        idx += 1
    return frames


@dataclass(frozen=True)
class _Clause:
    field: str
    op: str  # "=", "^=", "~", "in"
    value: str
    neg: bool = False
    rx: Optional[re.Pattern] = None
    in_items: Optional[Tuple[str, ...]] = None


def _split_tokens(expr: str) -> List[str]:
    """
    Split by spaces but keep parentheses groups intact for `in (...)`.
    No quoting support (simple & robust).
    """
    s = (expr or "").strip()
    if not s:
        return []
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch.isspace() and depth == 0:
            if buf:
                out.append("".join(buf).strip())
                buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return [t for t in out if t]


def _parse_in_list(text: str) -> Tuple[str, ...]:
    t = text.strip()
    if not (t.startswith("(") and t.endswith(")")):
        raise ValueError("in(...) expects parentheses, e.g. proto in (http*,grpc)")
    inner = t[1:-1].strip()
    if not inner:
        return tuple()
    items = [x.strip() for x in inner.split(",")]
    return tuple([x for x in items if x])


def _compile_clause(tok: str) -> _Clause:
    neg = False
    t = tok.strip()
    if t.startswith("-"):
        neg = True
        t = t[1:].strip()

    # field in (a,b,http*)
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+in\s+(.+)$", t)
    if m:
        field = m.group(1).strip()
        rest = m.group(2).strip()
        items = _parse_in_list(rest)
        return _Clause(field=field, op="in", value=rest, neg=neg, in_items=items)

    # field^=prefix
    if "^=" in t:
        field, val = t.split("^=", 1)
        return _Clause(field=field.strip(), op="^=", value=val.strip(), neg=neg)

    # field~regex
    if "~" in t:
        field, val = t.split("~", 1)
        val = val.strip()
        rx = re.compile(val)
        return _Clause(field=field.strip(), op="~", value=val, neg=neg, rx=rx)

    # field=value
    if "=" in t:
        field, val = t.split("=", 1)
        return _Clause(field=field.strip(), op="=", value=val.strip(), neg=neg)

    # bare token => substring match over a few common fields
    return _Clause(field="__any__", op="=", value=t, neg=neg)


def _lower(s: Optional[str]) -> str:
    return (s or "").lower()


def _get_record_field(rec: Any, field: str) -> str:
    f = field.lower()

    # conn id
    if f in ("conn", "conn_id"):
        return str(getattr(rec, "conn_id", "") or "")

    # proto/protocol
    if f in ("proto", "protocol"):
        # explicit by kind
        k = getattr(rec, "kind", None)
        if k == "conn":
            return "conn"
        if k == "tls":
            return "tls"
        if k == "h2ctl":
            return "h2ctl"

        # event has its own protocol field
        if hasattr(rec, "protocol"):
            return str(getattr(rec, "protocol") or "")

        # fallback by class name
        cname = rec.__class__.__name__.lower()
        if "connlifecycle" in cname:
            return "conn"
        if "tlshandshake" in cname:
            return "tls"
        if "h2control" in cname:
            return "h2ctl"
        return ""

    if f == "listener":
        return str(getattr(rec, "listener", "") or "")

    if f == "client":
        ip = str(getattr(rec, "client_ip", "") or "")
        port = getattr(rec, "client_port", None)
        return f"{ip}:{port}" if port is not None else ip

    if f == "client_ip":
        return str(getattr(rec, "client_ip", "") or "")
    if f in ("proxy", "proxy_version"):
        return str(getattr(rec, "proxy_version", "") or "")
    if f == "proxy_src":
        return str(getattr(rec, "proxy_src", "") or "")
    if f == "proxy_dst":
        return str(getattr(rec, "proxy_dst", "") or "")

    if f == "status":
        if hasattr(rec, "response") and getattr(rec, "response", None) is not None:
            st = getattr(getattr(rec, "response"), "status", None)
            return "" if st is None else str(st)
        if hasattr(rec, "outcome"):
            return str(getattr(rec, "outcome") or "")
        if hasattr(rec, "h2_event"):
            return str(getattr(rec, "h2_event") or "")
        # conn lifecycle has no status
        return ""

    if f == "error":
        if hasattr(rec, "error"):
            return "1" if getattr(rec, "error") else "0"
        if hasattr(rec, "outcome"):
            return "1" if (getattr(rec, "outcome") == "fail") else "0"
        return "0"

    # Event-specific
    if hasattr(rec, "request") and getattr(rec, "request", None) is not None:
        req = getattr(rec, "request")
        if f == "path":
            return str(getattr(req, "path", "") or "")
        if f == "method":
            return str(getattr(req, "method", "") or "")
        if f == "grpc_service":
            return str(getattr(req, "grpc_service", "") or "")
        if f == "grpc_method":
            return str(getattr(req, "grpc_method", "") or "")
        if f == "stream_id":
            sid = getattr(req, "stream_id", None)
            return "" if sid is None else str(sid)

    # TLS fields
    if hasattr(rec, "tls") and getattr(rec, "tls", None) is not None:
        tls = getattr(rec, "tls")
        if f == "sni":
            return str(getattr(tls, "sni", "") or "")
        if f == "alpn":
            return str(getattr(tls, "alpn", "") or "")
        if f in ("tlsver", "tls_version"):
            return str(getattr(tls, "version", "") or "")
        if f == "cipher":
            return str(getattr(tls, "cipher", "") or "")

    # tls handshake record fields
    if f == "side" and hasattr(rec, "side"):
        return str(getattr(rec, "side") or "")
    if f == "reason" and hasattr(rec, "reason"):
        return str(getattr(rec, "reason") or "")

    # h2 control fields
    if f in ("h2", "h2_event"):
        return str(getattr(rec, "h2_event", "") or "")
    if f == "direction" and hasattr(rec, "direction"):
        return str(getattr(rec, "direction") or "")
    if f in ("sid", "stream", "streamid"):
        sid = getattr(rec, "stream_id", None)
        return "" if sid is None else str(sid)

    return ""


def _get_conn_field(ci: Any, field: str) -> str:
    """
    Resolve filter fields for Connections view.
    """
    f = field.lower()

    if f in ("conn", "conn_id", "id"):
        return str(getattr(ci, "id", "") or "")

    if f in ("listener",):
        return str(getattr(ci, "listener", "") or "")
    if f in ("client",):
        ip = str(getattr(ci, "client_ip", "") or "")
        port = getattr(ci, "client_port", None)
        return f"{ip}:{port}" if port is not None else ip
    if f in ("client_ip",):
        return str(getattr(ci, "client_ip", "") or "")
    if f in ("proxy", "proxy_version"):
        return str(getattr(ci, "proxy_version", "") or "")
    if f == "proxy_src":
        return str(getattr(ci, "proxy_src", "") or "")
    if f == "proxy_dst":
        return str(getattr(ci, "proxy_dst", "") or "")
    if f in ("upstream", "upstream_addr"):
        return str(getattr(ci, "upstream_addr", "") or "")
    if f in ("proto", "protocol"):
        return str(getattr(ci, "alpn_in", "") or "")
    if f == "alpn_in":
        return str(getattr(ci, "alpn_in", "") or "")
    if f == "alpn_out":
        return str(getattr(ci, "alpn_out", "") or "")
    if f == "error":
        return "1" if getattr(ci, "last_error", None) else "0"
    return ""


def _match_value(op: str, actual: str, clause: _Clause) -> bool:
    if op == "=":
        return actual == clause.value
    if op == "^=":
        return actual.startswith(clause.value)
    if op == "~":
        if clause.rx is None:
            return False
        return clause.rx.search(actual) is not None
    if op == "in":
        items = clause.in_items or tuple()
        if not items:
            return True
        for it in items:
            if it.endswith("*"):
                if actual.startswith(it[:-1]):
                    return True
            else:
                if actual == it:
                    return True
        return False
    return False


@dataclass
class FilterSpec:
    """
    Parsed filter expression used for Traffic and Connections.

    Supported patterns (conceptually):
      - key=value
      - key^=prefix
      - key~regex
      - key in (a,b,c) with wildcards (http*)
      - negation: -key=value or -key in (...)

    Methods:
      - matches_record(rec): apply to Traffic records (Event/TLS/Conn/H2Control)
      - matches_conn(ci): apply to ConnInfo
    """
    raw: str = ""
    clauses: List[_Clause] = field(default_factory=list)

    def matches_record(self, rec: Any) -> bool:
        for cl in self.clauses:
            ok = self._match_record_clause(rec, cl)
            if cl.neg:
                ok = not ok
            if not ok:
                return False
        return True

    def matches_conn(self, ci: Any) -> bool:
        for cl in self.clauses:
            ok = self._match_conn_clause(ci, cl)
            if cl.neg:
                ok = not ok
            if not ok:
                return False
        return True

    def _match_record_clause(self, rec: Any, cl: _Clause) -> bool:
        if cl.field == "__any__":
            needle = _lower(cl.value)
            if not needle:
                return True
            hay = " ".join([
                _get_record_field(rec, "listener"),
                _get_record_field(rec, "client"),
                _get_record_field(rec, "proto"),
                _get_record_field(rec, "method"),
                _get_record_field(rec, "path"),
                _get_record_field(rec, "status"),
                _get_record_field(rec, "reason"),
                _get_record_field(rec, "h2_event"),
            ]).lower()
            return needle in hay

        actual = _get_record_field(rec, cl.field)
        return _match_value(cl.op, actual, cl)

    def _match_conn_clause(self, ci: Any, cl: _Clause) -> bool:
        if cl.field == "__any__":
            needle = _lower(cl.value)
            if not needle:
                return True
            hay = " ".join([
                _get_conn_field(ci, "listener"),
                _get_conn_field(ci, "client"),
                _get_conn_field(ci, "upstream"),
                _get_conn_field(ci, "alpn_in"),
                _get_conn_field(ci, "alpn_out"),
            ]).lower()
            return needle in hay

        actual = _get_conn_field(ci, cl.field)
        return _match_value(cl.op, actual, cl)


def parse_filter_expr(expr: str) -> FilterSpec:
    """
    Parse a user filter string into FilterSpec.

    Requirements:
      - produce clear errors for invalid input
      - keep semantics consistent across Traffic and Connections when possible
      - support conn=<uuid> for drill-down/jump behavior.
    """
    e = (expr or "").strip()
    if not e:
        return FilterSpec(raw="", clauses=[])

    toks = _split_tokens(e)

    # Merge: ["proto", "in", "(http*,grpc)"] -> ["proto in (http*,grpc)"]
    merged: List[str] = []
    i = 0
    ident_rx = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    while i < len(toks):
        t0 = toks[i]

        # Support "-field in (...)" too
        neg_prefix = ""
        field_tok = t0
        if t0.startswith("-"):
            neg_prefix = "-"
            field_tok = t0[1:].strip()

        if (
            i + 2 < len(toks)
            and ident_rx.match(field_tok or "") is not None
            and toks[i + 1] == "in"
            and toks[i + 2].lstrip().startswith("(")
        ):
            merged.append(f"{neg_prefix}{field_tok} in {toks[i+2]}")
            i += 3
            continue

        merged.append(t0)
        i += 1

    clauses: List[_Clause] = []
    for t in merged:
        if not t:
            continue
        clauses.append(_compile_clause(t))

    return FilterSpec(raw=e, clauses=clauses)


class ProxyConnection:
    """
    Handler for a single accepted client connection.

    Flow:
      - receives conn_id and client reader/writer (after manual TLS-in, if enabled)
      - determines negotiated ALPN (h2 vs http/1.1) and dispatches to:
          * _handle_h2_proxy(...) — full HTTP/2 <-> HTTP/2 proxy
          * _handle_raw_tunnel(...) / http1 handler — for http/1.1 and/or raw transport
      - updates ConnectionStore while processing:
          * touch() for idle/age tracking
          * set_upstream() after upstream connect/handshake
          * set_error()/close_reason/closed_by for actionable diagnostics

    Goal:
      provide transport-level blame/diagnostics (client vs upstream vs proxy) in Connections view,
      and request-level events in Traffic view.
    """
    def __init__(
        self,
        runtime: ListenerRuntime,
        conn_id: str,
        client_ip: str,
        client_port: int,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
        proxy_header: Optional[ProxyProtocolHeader] = None,
    ):
        self.runtime = runtime
        self.conn_id = conn_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.c_reader = c_reader
        self.c_writer = c_writer
        self._policy = runtime._policy
        self.proxy_header = proxy_header if proxy_header is not None else ProxyProtocolHeader()

        # transport close diagnostics
        self.close_reason: Optional[str] = None
        self.closed_by: Optional[str] = None
        self.close_flags: List[str] = []

    @staticmethod
    def tls_info_from_sslobj_static(sslobj: Optional[ssl.SSLObject]) -> TlsInfo:
        if not sslobj:
            return TlsInfo()
        alpn = None
        ver = None
        cipher = None
        try:
            alpn = sslobj.selected_alpn_protocol()
        except Exception:
            pass
        try:
            ver = sslobj.version()
        except Exception:
            pass
        try:
            c = sslobj.cipher()
            cipher = c[0] if c else None
        except Exception:
            pass
        # sni on server side is captured by callback (in runtime)
        return TlsInfo(sni=None, alpn=alpn, version=ver, cipher=cipher)

    def _tls_in(self) -> TlsInfo:
        sslobj: Optional[ssl.SSLObject] = self.c_writer.get_extra_info("ssl_object")
        return self.tls_info_from_sslobj_static(sslobj)

    def _timeouts(self) -> Tuple[float, float]:
        """
        Возвращает (read_timeout_s, idle_timeout_s).

        read_timeout_s:
          - "сколько можно ждать данных при активной фазе" (например, ожидание ответа от upstream).
          - для HTTP/1 используется при чтении заголовков/тела.
          - для HTTP/2 после доработки используется watchdog-ом: "upstream молчит слишком долго".

        idle_timeout_s:
          - общий idle по соединению (нет трафика ни туда, ни сюда).
          - полезно для защиты от висячих соединений/клиентов.

        Если в конфиге нет policy.read_timeout / policy.idle_timeout — используем безопасные дефолты.
        """
        # allow config extensions without breaking older yaml
        pol = getattr(self.runtime.cfg, "policy", None)
        rt = getattr(pol, "read_timeout", None) if pol is not None else None
        it = getattr(pol, "idle_timeout", None) if pol is not None else None

        try:
            read_timeout = float(rt) if rt is not None else 30.0
        except Exception:
            read_timeout = 30.0

        try:
            idle_timeout = float(it) if it is not None else 120.0
        except Exception:
            idle_timeout = 120.0

        # sanity
        if read_timeout <= 0:
            read_timeout = 30.0
        if idle_timeout <= 0:
            idle_timeout = 120.0

        return read_timeout, idle_timeout

    def _mark_close(self, flag: str) -> None:
        """
        Record a close-related flag (client_fin/upstream_fin/client_rst/upstream_rst/...).

        Also set closed_by/close_reason based on FIRST observed flag.

        Notes:
          - flags may include timeouts/protocol errors not strictly starting with client_/upstream_
          - for such flags we set closed_by="proxy" unless already set
        """
        if flag and flag not in self.close_flags:
            self.close_flags.append(flag)

        # First-close decides "who closed first" (best-effort)
        if self.closed_by is None:
            if flag.startswith("client_"):
                self.closed_by = "client"
            elif flag.startswith("upstream_"):
                self.closed_by = "upstream"
            elif flag.endswith("_timeout") or "timeout" in flag or "protocol" in flag:
                self.closed_by = "proxy"
            else:
                self.closed_by = "unknown"

        if self.close_reason is None:
            self.close_reason = flag

    async def _open_upstream(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, Optional[str], TlsInfo, Optional[str]]:
        """
        Open an upstream connection with separate connect and TLS-handshake timeouts.

        Returns:
          (reader, writer, sni_out, tls_out, alpn_out)

        Errors are classified as:
          - UpstreamConnectTimeout
          - UpstreamHandshakeTimeout
          - other connect/handshake failures
        """
        up_cfg = self.runtime.cfg.upstream
        host, port = _parse_hostport(up_cfg.addr)

        ts = time.time()

        # timeouts from policy (seconds)
        pol = self.runtime.cfg.policy
        connect_to = float(getattr(pol, "upstream_connect_timeout", 5.0) or 5.0)
        hs_to = float(getattr(pol, "upstream_handshake_timeout", 10.0) or 10.0)

        # 1) build SSL context may fail BEFORE any TCP packets are sent
        try:
            ssl_ctx, server_hostname = build_upstream_ssl_context(up_cfg)
        except Exception as e:
            reason = f"sslctx_build_failed: {e}"
            try:
                await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
            except Exception:
                LOG.debug("metrics.inc upstream_connect_fail failed", exc_info=True)

            if up_cfg.tls:
                try:
                    await self.runtime.metrics.inc("tls_out_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc tls_out_fail failed", exc_info=True)

                try:
                    await self.runtime.store.add(TlsHandshakeRecord(
                        kind="tls",
                        id=str(uuid.uuid4()),
                        ts=ts,
                        listener=self.runtime.cfg.name,
                        client_ip=self.client_ip,
                        client_port=self.client_port,
                        side="out",
                        outcome="fail",
                        reason=reason[:500],
                        tls=TlsInfo(),
                        upstream={
                            "addr": up_cfg.addr,
                            "verify": up_cfg.verify,
                            "server_name": up_cfg.server_name,
                            "ca": up_cfg.ca,
                            "alpn": up_cfg.alpn,
                            "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                        },
                    ))
                except Exception:
                    LOG.warning("store.add tls_out fail (sslctx_build_failed) failed conn_id=%s", self.conn_id,
                                exc_info=True)

            LOG.warning("Upstream SSL context build failed conn_id=%s upstream=%s", self.conn_id, up_cfg.addr,
                        exc_info=True)
            raise

        # 2) TCP connect (separate timeout)
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=None),
                timeout=connect_to,
            )
        except asyncio.TimeoutError:
            e = UpstreamConnectTimeout(f"tcp connect timeout {connect_to}s")
            reason = classify_ssl_error(e)

            try:
                await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
            except Exception:
                LOG.debug("metrics.inc upstream_connect_fail failed", exc_info=True)

            if up_cfg.tls:
                try:
                    await self.runtime.metrics.inc("tls_out_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc tls_out_fail failed", exc_info=True)

                try:
                    await self.runtime.store.add(TlsHandshakeRecord(
                        kind="tls",
                        id=str(uuid.uuid4()),
                        ts=ts,
                        listener=self.runtime.cfg.name,
                        client_ip=self.client_ip,
                        client_port=self.client_port,
                        side="out",
                        outcome="fail",
                        reason=reason,
                        tls=TlsInfo(),
                        upstream={
                            "addr": up_cfg.addr,
                            "verify": up_cfg.verify,
                            "server_name": up_cfg.server_name,
                            "ca": up_cfg.ca,
                            "alpn": up_cfg.alpn,
                            "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                        },
                    ))
                except Exception:
                    LOG.warning("store.add tls_out fail (connect_timeout) failed conn_id=%s", self.conn_id,
                                exc_info=True)

            LOG.info("Upstream TCP connect timeout conn_id=%s upstream=%s timeout=%ss",
                     self.conn_id, up_cfg.addr, connect_to)
            raise e

        except Exception as e:
            reason = classify_ssl_error(e)

            try:
                await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
            except Exception:
                LOG.debug("metrics.inc upstream_connect_fail failed", exc_info=True)

            if up_cfg.tls:
                try:
                    await self.runtime.metrics.inc("tls_out_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc tls_out_fail failed", exc_info=True)

                try:
                    await self.runtime.store.add(TlsHandshakeRecord(
                        kind="tls",
                        id=str(uuid.uuid4()),
                        ts=ts,
                        listener=self.runtime.cfg.name,
                        client_ip=self.client_ip,
                        client_port=self.client_port,
                        side="out",
                        outcome="fail",
                        reason=reason,
                        tls=TlsInfo(),
                        upstream={
                            "addr": up_cfg.addr,
                            "verify": up_cfg.verify,
                            "server_name": up_cfg.server_name,
                            "ca": up_cfg.ca,
                            "alpn": up_cfg.alpn,
                            "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                        },
                    ))
                except Exception:
                    LOG.warning("store.add tls_out fail (connect_error) failed conn_id=%s", self.conn_id, exc_info=True)

            LOG.info("Upstream TCP connect failed conn_id=%s upstream=%s reason=%s",
                     self.conn_id, up_cfg.addr, reason)
            raise

        # 2.5) Preserve incoming PROXY protocol version/header when forwarding upstream.
        if self.proxy_header.present and self.proxy_header.version in (1, 2) and self.proxy_header.raw:
            try:
                w.write(self.proxy_header.raw)
                await w.drain()
            except Exception as e:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    LOG.debug("upstream proxy header send error: close TCP failed conn_id=%s",
                              self.conn_id, exc_info=True)
                try:
                    await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc upstream_connect_fail failed", exc_info=True)
                raise RuntimeError(f"send PROXY header to upstream failed: {e}") from e

        # 3) TLS handshake (if needed) with separate timeout
        if up_cfg.tls:
            loop = asyncio.get_running_loop()

            transport = getattr(w, "_transport", None)
            if transport is None:
                transport = w.transport  # type: ignore[attr-defined]
            protocol = transport.get_protocol()

            try:
                tls_transport = await asyncio.wait_for(
                    loop.start_tls(
                        transport,
                        protocol,
                        ssl_ctx,
                        server_side=False,
                        server_hostname=server_hostname,
                        ssl_handshake_timeout=hs_to,
                    ),
                    timeout=hs_to,
                )
            except asyncio.TimeoutError:
                # close plain TCP writer before raising
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    LOG.debug("upstream handshake timeout: close plain TCP failed conn_id=%s", self.conn_id,
                              exc_info=True)

                e = UpstreamHandshakeTimeout(f"tls handshake timeout {hs_to}s")
                reason = classify_ssl_error(e)

                try:
                    await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
                    await self.runtime.metrics.inc("tls_out_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc failed (handshake timeout)", exc_info=True)

                try:
                    await self.runtime.store.add(TlsHandshakeRecord(
                        kind="tls",
                        id=str(uuid.uuid4()),
                        ts=ts,
                        listener=self.runtime.cfg.name,
                        client_ip=self.client_ip,
                        client_port=self.client_port,
                        side="out",
                        outcome="fail",
                        reason=reason,
                        tls=TlsInfo(),
                        upstream={
                            "addr": up_cfg.addr,
                            "verify": up_cfg.verify,
                            "server_name": up_cfg.server_name,
                            "ca": up_cfg.ca,
                            "alpn": up_cfg.alpn,
                            "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                        },
                    ))
                except Exception:
                    LOG.warning("store.add tls_out fail (handshake_timeout) failed conn_id=%s", self.conn_id,
                                exc_info=True)

                LOG.info("Upstream TLS handshake timeout conn_id=%s upstream=%s timeout=%ss",
                         self.conn_id, up_cfg.addr, hs_to)
                raise e

            except Exception as e:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    LOG.debug("upstream handshake error: close TCP failed conn_id=%s", self.conn_id, exc_info=True)

                reason = classify_ssl_error(e)

                try:
                    await self.runtime.metrics.inc("upstream_connect_fail", 1, self.runtime.cfg.name)
                    await self.runtime.metrics.inc("tls_out_fail", 1, self.runtime.cfg.name)
                except Exception:
                    LOG.debug("metrics.inc failed (handshake error)", exc_info=True)

                try:
                    await self.runtime.store.add(TlsHandshakeRecord(
                        kind="tls",
                        id=str(uuid.uuid4()),
                        ts=ts,
                        listener=self.runtime.cfg.name,
                        client_ip=self.client_ip,
                        client_port=self.client_port,
                        side="out",
                        outcome="fail",
                        reason=reason,
                        tls=TlsInfo(),
                        upstream={
                            "addr": up_cfg.addr,
                            "verify": up_cfg.verify,
                            "server_name": up_cfg.server_name,
                            "ca": up_cfg.ca,
                            "alpn": up_cfg.alpn,
                            "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                        },
                    ))
                except Exception:
                    LOG.warning("store.add tls_out fail (handshake error) failed conn_id=%s", self.conn_id,
                                exc_info=True)

                LOG.info("Upstream TLS handshake failed conn_id=%s upstream=%s reason=%s",
                         self.conn_id, up_cfg.addr, reason)
                raise

            # Patch transports so StreamReader/Writer start using TLS transport
            try:
                w._transport = tls_transport  # type: ignore[attr-defined]
            except Exception:
                LOG.debug("patch writer transport to TLS failed conn_id=%s", self.conn_id, exc_info=True)
            try:
                r._transport = tls_transport  # type: ignore[attr-defined]
            except Exception:
                LOG.debug("patch reader transport to TLS failed conn_id=%s", self.conn_id, exc_info=True)

        sslobj = w.get_extra_info("ssl_object")
        tls_out = self.tls_info_from_sslobj_static(sslobj)
        alpn_out = (tls_out.alpn or "").lower() if tls_out.alpn else None

        if up_cfg.tls:
            try:
                await self.runtime.metrics.inc("tls_out_ok", 1, self.runtime.cfg.name)
            except Exception:
                LOG.debug("metrics.inc tls_out_ok failed", exc_info=True)

            try:
                await self.runtime.store.add(TlsHandshakeRecord(
                    kind="tls",
                    id=str(uuid.uuid4()),
                    ts=ts,
                    listener=self.runtime.cfg.name,
                    client_ip=self.client_ip,
                    client_port=self.client_port,
                    side="out",
                    outcome="ok",
                    reason=None,
                    tls=tls_out,
                    upstream={
                        "addr": up_cfg.addr,
                        "verify": up_cfg.verify,
                        "server_name": up_cfg.server_name or server_hostname,
                        "ca": up_cfg.ca,
                        "alpn": up_cfg.alpn,
                        "mtls": bool(up_cfg.client_cert and up_cfg.client_key),
                    },
                ))
            except Exception:
                LOG.warning("store.add tls_out ok failed conn_id=%s", self.conn_id, exc_info=True)

        return r, w, server_hostname, tls_out, alpn_out

    async def run(self) -> None:
        """
        Wrapper: decide http1 vs h2 based on ALPN and provide
        lifecycle hints to conn_store: who closed (client/upstream) and why.

        Важно:
          - close_reason / closed_by / close_flags должны быть выставлены внутри конкретного протокольного handler-а
            (http1/h2/raw), иначе ListenerRuntime увидит "completed".
        """
        # Touch activity on start (best-effort, чтобы Connections view показывал "живость")
        try:
            await self.runtime.conn_store.touch(self.conn_id)
        except Exception:
            pass

        tls = self._tls_in()
        alpn = (tls.alpn or "http/1.1").lower().strip()

        # run protocol handler and classify failures
        try:
            if alpn == "h2":
                await self._handle_h2_proxy(tls)
            elif alpn in ("http/1.1", "http/1.0"):
                await self._handle_http1_proxy(tls)
            else:
                # fallback: tunnel any unknown / no-alpn protocols
                await self._handle_raw_tunnel(tls)

        # Ниже — страховочные catch-и, которые пишут в conn_store.last_error.
        # close_reason в этом случае определяет ListenerRuntime (через classify_close_reason),
        # но это обычно "proxy error/timeout/etc". Для диагностик — полезно.

        except asyncio.TimeoutError as e:
            try:
                await self.runtime.conn_store.set_error(self.conn_id, f"timeout: {e}")
            except Exception:
                LOG.debug("conn_store.set_error failed conn_id=%s (timeout)", self.conn_id, exc_info=True)
            raise

        except ConnectionResetError as e:
            try:
                await self.runtime.conn_store.set_error(self.conn_id, f"client reset: {e}")
            except Exception:
                LOG.debug("conn_store.set_error failed conn_id=%s (reset)", self.conn_id, exc_info=True)
            raise

        except BrokenPipeError as e:
            try:
                await self.runtime.conn_store.set_error(self.conn_id, f"broken pipe: {e}")
            except Exception:
                LOG.debug("conn_store.set_error failed conn_id=%s (broken_pipe)", self.conn_id, exc_info=True)
            raise

        except asyncio.IncompleteReadError as e:
            try:
                await self.runtime.conn_store.set_error(self.conn_id, f"eof: {e}")
            except Exception:
                LOG.debug("conn_store.set_error failed conn_id=%s (eof)", self.conn_id, exc_info=True)
            raise

        except Exception as e:
            try:
                await self.runtime.conn_store.set_error(self.conn_id, f"proxy error: {e}")
            except Exception:
                LOG.debug("conn_store.set_error failed conn_id=%s (proxy_error)", self.conn_id, exc_info=True)
            raise

    async def _handle_raw_tunnel(self, tls_in: TlsInfo) -> None:
        """
        Minimal full-duplex byte tunnel between client and upstream.

        Intended for:
          - http/1.1 when not parsing HTTP and simply forwarding bytes
          - raw transport scenarios where TCP/TLS diagnostics matter more than HTTP semantics

        Diagnostics:
          - touch(conn_id) on each read/write
          - upstream/client errors are classified at a higher level (ProxyConnection.run)
          - close_reason/closed_by are produced at connection scope.
        """
        try:
            u_reader, u_writer, sni_out, tls_out, alpn_out = await self._open_upstream()
        except Exception as e:
            await self.runtime.conn_store.set_error(self.conn_id, f"upstream connect failed: {e}")
            self.closed_by = "proxy"
            self.close_reason = "upstream_connect_fail"
            return

        await self.runtime.conn_store.set_upstream(self.conn_id, tls_out, alpn_out, sni_out)

        read_timeout, idle_timeout = self._timeouts()

        lock = asyncio.Lock()
        stop_evt = asyncio.Event()

        # per-direction idle tracking
        last_client_io_ts = time.time()  # bytes FROM client seen
        last_upstream_io_ts = time.time()  # bytes FROM upstream seen

        async def note_activity(src_name: str) -> None:
            nonlocal last_client_io_ts, last_upstream_io_ts
            now = time.time()
            if src_name == "client":
                last_client_io_ts = now
            else:
                last_upstream_io_ts = now
            try:
                await self.runtime.conn_store.touch(self.conn_id)
            except Exception:
                LOG.debug("raw watchdog failed conn_id=%s", self.conn_id, exc_info=True)

        async def note(flag: str) -> None:
            async with lock:
                self._mark_close(flag)

        async def watchdog() -> None:
            nonlocal last_client_io_ts, last_upstream_io_ts
            try:
                while not stop_evt.is_set():
                    await asyncio.sleep(0.5)
                    now = time.time()

                    client_idle = now - last_client_io_ts
                    upstream_idle = now - last_upstream_io_ts

                    # If both exceeded, choose the "more idle" side (stronger signal)
                    if client_idle >= idle_timeout or upstream_idle >= idle_timeout:
                        if client_idle >= idle_timeout and client_idle >= upstream_idle:
                            await note("client_idle_timeout")
                            self.closed_by = "proxy"
                            self.close_reason = "client_idle_timeout"
                        else:
                            await note("upstream_idle_timeout")
                            self.closed_by = "proxy"
                            self.close_reason = "upstream_idle_timeout"

                        stop_evt.set()
                        # actively close sockets to unblock pumps
                        try:
                            self.c_writer.close()
                        except Exception:
                            pass
                        try:
                            u_writer.close()
                        except Exception:
                            pass
                        break
            except Exception:
                pass

        async def pump(src_name: str, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            """
            src_name:
              - "client": reading from downstream client
              - "upstream": reading from upstream server
            """
            try:
                while not stop_evt.is_set():
                    try:
                        b = await asyncio.wait_for(r.read(65536), timeout=read_timeout)
                    except asyncio.TimeoutError:
                        await note(f"{src_name}_read_timeout")
                        self.closed_by = "proxy"
                        self.close_reason = f"{src_name}_read_timeout"
                        stop_evt.set()
                        try:
                            w.close()
                        except Exception:
                            pass
                        break
                    except ConnectionResetError:
                        await note(f"{src_name}_rst")
                        stop_evt.set()
                        break

                    if not b:
                        await note(f"{src_name}_fin")
                        stop_evt.set()
                        break

                    await note_activity(src_name)

                    try:
                        w.write(b)
                        await w.drain()
                    except BrokenPipeError:
                        dst = "upstream" if src_name == "client" else "client"
                        await note(f"{dst}_broken_pipe")
                        stop_evt.set()
                        break
                    except ConnectionResetError:
                        dst = "upstream" if src_name == "client" else "client"
                        await note(f"{dst}_rst")
                        stop_evt.set()
                        break

            except Exception as e:
                await self.runtime.conn_store.set_error(self.conn_id, f"tunnel pump {src_name} error: {e}")
                stop_evt.set()

        t_watch = asyncio.create_task(watchdog())
        try:
            t1 = asyncio.create_task(pump("client", self.c_reader, u_writer))
            t2 = asyncio.create_task(pump("upstream", u_reader, self.c_writer))

            done, pending = await asyncio.wait({t1, t2, t_watch}, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        finally:
            stop_evt.set()
            try:
                u_writer.close()
                await u_writer.wait_closed()
            except Exception:
                pass

        if self.close_reason is None:
            self.closed_by = "proxy"
            self.close_reason = "completed"

    async def _handle_http1_proxy(self, tls_in: TlsInfo) -> None:
        try:
            u_reader, u_writer, sni_out, tls_out, alpn_out = await self._open_upstream()
        except Exception as e:
            await self.runtime.conn_store.set_error(self.conn_id, f"upstream connect failed: {e}")
            self.closed_by = "proxy"
            self.close_reason = "upstream_connect_fail"
            return

        await self.runtime.conn_store.set_upstream(self.conn_id, tls_out, alpn_out, sni_out)

        read_timeout, idle_timeout = self._timeouts()

        log_headers = bool(self.runtime.cfg.logging.log_headers)
        log_body = bool(self.runtime.cfg.logging.log_body)
        capture_max = int(self.runtime.cfg.logging.body_max_bytes or 0)
        if not log_body:
            capture_max = -1
        eff_max = HARD_BODY_LIMIT if capture_max == 0 else capture_max

        def maybe_capture(buf: bytearray, trunc_flag: List[bool], data: bytes) -> None:
            if capture_max < 0:
                return
            if eff_max <= 0:
                trunc_flag[0] = True
                return
            if len(buf) < eff_max:
                take = min(eff_max - len(buf), len(data))
                buf.extend(data[:take])
                if take < len(data):
                    trunc_flag[0] = True
            else:
                trunc_flag[0] = True

        def parse_headers(raw: bytes) -> Dict[str, str]:
            text = raw.decode("iso-8859-1", errors="replace")
            lines = text.split("\r\n")
            hdrs: Dict[str, str] = {}
            for ln in lines[1:]:
                if not ln:
                    continue
                if ":" not in ln:
                    continue
                k, v = ln.split(":", 1)
                hdrs[k.strip()] = v.strip()
            return hdrs

        def headers_to_bytes(start_line: str, hdrs: Dict[str, str]) -> bytes:
            out = [start_line]
            for k, v in hdrs.items():
                out.append(f"{k}: {v}")
            out.append("")
            out.append("")
            return ("\r\n".join(out)).encode("iso-8859-1")

        async def read_headers(r: asyncio.StreamReader) -> bytes:
            return await r.readuntil(b"\r\n\r\n")

        def get_ci(h: Dict[str, str], name: str) -> Optional[str]:
            nl = name.lower()
            for k, v in h.items():
                if k.lower() == nl:
                    return v
            return None

        async def read_fixed(src_name: str, r: asyncio.StreamReader, n: int, on_chunk=None) -> bytes:
            if n <= 0:
                return b""
            got = bytearray()
            left = n
            while left > 0:
                try:
                    chunk = await asyncio.wait_for(r.read(min(65536, left)), timeout=read_timeout)
                except asyncio.TimeoutError:
                    self._mark_close(f"{src_name}_read_timeout")
                    self.closed_by = "proxy"
                    self.close_reason = f"{src_name}_read_timeout"
                    break
                if not chunk:
                    break
                got.extend(chunk)
                left -= len(chunk)
                if on_chunk:
                    on_chunk(chunk)
                await self.runtime.conn_store.touch(self.conn_id)
            return bytes(got)

        async def read_to_close(src_name: str, r: asyncio.StreamReader, on_chunk=None) -> bytes:
            got = bytearray()
            while True:
                try:
                    chunk = await asyncio.wait_for(r.read(65536), timeout=read_timeout)
                except asyncio.TimeoutError:
                    self._mark_close(f"{src_name}_read_timeout")
                    self.closed_by = "proxy"
                    self.close_reason = f"{src_name}_read_timeout"
                    break
                if not chunk:
                    break
                got.extend(chunk)
                if on_chunk:
                    on_chunk(chunk)
                await self.runtime.conn_store.touch(self.conn_id)
            return bytes(got)

        try:
            while True:
                await self.runtime.conn_store.touch(self.conn_id)
                ts0 = time.time()

                # request headers: IDLE between requests => client_idle_timeout
                try:
                    req_head = await asyncio.wait_for(read_headers(self.c_reader), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    self._mark_close("client_idle_timeout")
                    self.closed_by = "proxy"
                    self.close_reason = "client_idle_timeout"
                    break
                except asyncio.IncompleteReadError:
                    self._mark_close("client_fin")
                    break
                except ConnectionResetError:
                    self._mark_close("client_rst")
                    break

                if not req_head:
                    self._mark_close("client_fin")
                    break

                head_text = req_head.decode("iso-8859-1", errors="replace")
                lines = head_text.split("\r\n")
                req_line = lines[0]
                parts = req_line.split(" ")
                if len(parts) < 2:
                    await self.runtime.conn_store.set_error(self.conn_id, f"bad request line: {req_line!r}")
                    self.closed_by = "proxy"
                    self.close_reason = "protocol_error"
                    break
                method = parts[0]
                path = parts[1]

                try:
                    await self.runtime.conn_store.set_last_path(self.conn_id, path)
                except Exception:
                    pass

                req_hdrs = parse_headers(req_head)
                cl = get_ci(req_hdrs, "Content-Length")
                te = get_ci(req_hdrs, "Transfer-Encoding")

                req_body_buf = bytearray()
                req_trunc = [False]

                req_body = b""
                if te and "chunked" in te.lower():
                    await self.runtime.conn_store.set_error(self.conn_id, "http1: chunked request body not supported")
                    self.closed_by = "proxy"
                    self.close_reason = "protocol_error"
                    break
                elif cl:
                    try:
                        n = int(cl)
                    except Exception:
                        n = 0
                    req_body = await read_fixed("client", self.c_reader, n,
                                                on_chunk=(lambda ch: maybe_capture(req_body_buf, req_trunc, ch)))

                bytes_in = len(req_head) + len(req_body)

                up_host, up_port = _parse_hostport(self.runtime.cfg.upstream.addr)
                authority = (self.runtime.cfg.upstream.server_name or up_host)
                req_hdrs.pop("Host", None)
                req_hdrs["Host"] = f"{authority}:{up_port}"

                req_hdrs_ui = self._policy.redact(req_hdrs) if log_headers else {}

                u_writer.write(headers_to_bytes(req_line, req_hdrs))
                if req_body:
                    u_writer.write(req_body)
                await u_writer.drain()

                # response headers: upstream_read_timeout
                try:
                    resp_head = await asyncio.wait_for(read_headers(u_reader), timeout=read_timeout)
                except asyncio.TimeoutError:
                    self._mark_close("upstream_read_timeout")
                    self.closed_by = "proxy"
                    self.close_reason = "upstream_read_timeout"
                    break
                except asyncio.IncompleteReadError:
                    self._mark_close("upstream_fin")
                    break
                except ConnectionResetError:
                    self._mark_close("upstream_rst")
                    break

                resp_text = resp_head.decode("iso-8859-1", errors="replace")
                rlines = resp_text.split("\r\n")
                status_line = rlines[0]

                status = None
                try:
                    sp = status_line.split(" ")
                    if len(sp) >= 2:
                        status = int(sp[1])
                except Exception:
                    status = None

                resp_hdrs = parse_headers(resp_head)
                r_cl = get_ci(resp_hdrs, "Content-Length")
                r_te = get_ci(resp_hdrs, "Transfer-Encoding")
                conn_hdr = get_ci(resp_hdrs, "Connection")

                resp_body_buf = bytearray()
                resp_trunc = [False]

                resp_body = b""
                if r_te and "chunked" in (r_te or "").lower():
                    await self.runtime.conn_store.set_error(self.conn_id,
                                                            "http1: chunked response body not supported (yet)")
                    self.closed_by = "proxy"
                    self.close_reason = "protocol_error"
                    break
                elif r_cl:
                    try:
                        rn = int(r_cl)
                    except Exception:
                        rn = 0
                    resp_body = await read_fixed("upstream", u_reader, rn,
                                                 on_chunk=(lambda ch: maybe_capture(resp_body_buf, resp_trunc, ch)))
                else:
                    resp_body = await read_to_close("upstream", u_reader,
                                                    on_chunk=(lambda ch: maybe_capture(resp_body_buf, resp_trunc, ch)))

                bytes_out = len(resp_head) + len(resp_body)

                self.c_writer.write(resp_head)
                if resp_body:
                    self.c_writer.write(resp_body)
                await self.c_writer.drain()

                ts1 = time.time()
                resp_hdrs_ui = self._policy.redact(resp_hdrs) if log_headers else {}

                req_body_b = bytes(req_body_buf)
                resp_body_b = bytes(resp_body_buf)

                ev = Event(
                    kind="event",
                    id=str(uuid.uuid4()),
                    ts_start=ts0,
                    ts_end=ts1,
                    listener=self.runtime.cfg.name,
                    client_ip=self.client_ip,
                    client_port=self.client_port,
                    upstream_addr=self.runtime.cfg.upstream.addr,
                    protocol="http1",
                    tls=tls_in,
                    request=RequestInfo(
                        method=method,
                        path=path,
                        authority=req_hdrs.get("Host"),
                        headers=req_hdrs_ui,
                        stream_id=None,
                        body_b64=(base64.b64encode(req_body_b).decode("ascii") if req_body_b else None),
                        body_truncated=bool(req_trunc[0]),
                        grpc_service=None,
                        grpc_method=None,
                    ),
                    response=ResponseInfo(
                        status=status,
                        headers=resp_hdrs_ui,
                        body_b64=(base64.b64encode(resp_body_b).decode("ascii") if resp_body_b else None),
                        body_truncated=bool(resp_trunc[0]),
                    ),
                    bytes_in=int(bytes_in),
                    bytes_out=int(bytes_out),
                    duration_ms=int((ts1 - ts0) * 1000),
                    flags=(["timeout"] if (self.close_reason or "").endswith("_timeout") else []),
                    error=None,
                )
                await self.runtime.store.add(ev)

                d_conn = (get_ci(req_hdrs, "Connection") or "").lower()
                u_conn = (conn_hdr or "").lower()
                if "close" in d_conn or "close" in u_conn:
                    break

        finally:
            try:
                u_writer.close()
                await u_writer.wait_closed()
            except Exception:
                pass

        if self.close_reason is None:
            self.closed_by = "proxy"
            self.close_reason = "completed"

    async def _emit_h2ctl(self, direction: str, evname: str, stream_id: Optional[int], details: Dict[str, Any]) -> None:
        rec = H2ControlRecord(
            kind="h2ctl",
            id=str(uuid.uuid4()),
            ts=time.time(),
            listener=self.runtime.cfg.name,
            client_ip=self.client_ip,
            client_port=self.client_port,
            direction=direction,
            h2_event=evname,
            stream_id=stream_id,
            details=details,
            conn_id=self.conn_id,
        )
        await self.runtime.store.add(rec)

    async def _handle_h2_proxy(self, tls_in: TlsInfo) -> None:
        """
        Full HTTP/2 <-> HTTP/2 proxy.

        Fixes:
          - ensure upstream failures in h2 are reflected in close_reason/flags
            (otherwise tests see 'completed' and fail mtls_h2_upstream_fail)
          - mark upstream_fin / upstream_protocol_error / client_fin / client_protocol_error
        """
        # --- open upstream ---
        try:
            u_reader, u_writer, sni_out, tls_out, alpn_out = await self._open_upstream()
        except Exception as e:
            await self.runtime.conn_store.set_error(self.conn_id, f"upstream connect failed: {e}")
            self.closed_by = "proxy"
            self.close_reason = "upstream_connect_fail"
            self.close_flags = list(set(self.close_flags + ["upstream_connect_fail"]))
            return

        await self.runtime.conn_store.set_upstream(self.conn_id, tls_out, alpn_out, sni_out)

        # For TLS upstream we require ALPN=h2. For cleartext upstream (h2c),
        # ALPN is absent by design, so skip this check.
        if self.runtime.cfg.upstream.tls and (alpn_out or "").lower() != "h2":
            await self.runtime.conn_store.set_error(self.conn_id, f"upstream ALPN is not h2 (got {alpn_out!r})")
            self._mark_close("upstream_protocol_error")
            try:
                u_writer.close()
                await u_writer.wait_closed()
            except Exception:
                pass
            return

        log_headers = bool(self.runtime.cfg.logging.log_headers)
        log_body = bool(self.runtime.cfg.logging.log_body)
        log_h2ctl = bool(self.runtime.cfg.logging.h2_control_events)
        capture_max = int(self.runtime.cfg.logging.body_max_bytes or 0)
        if not log_body:
            capture_max = -1
        eff_max = HARD_BODY_LIMIT if capture_max == 0 else capture_max

        # ------------------------------------------------------------------
        # TIMEOUTS (для h2 watchdog)
        # ------------------------------------------------------------------
        read_timeout, idle_timeout = self._timeouts()

        last_any_io_ts = time.time()
        last_upstream_io_ts = time.time()

        def note_any_io() -> None:
            nonlocal last_any_io_ts
            last_any_io_ts = time.time()

        def note_upstream_io() -> None:
            nonlocal last_upstream_io_ts
            last_upstream_io_ts = time.time()
            note_any_io()

        stop_evt = asyncio.Event()

        async def watchdog() -> None:
            """
            Watch for hang:
              - upstream_read_timeout: upstream is silent > read_timeout
              - proxy_idle_timeout: no activity at all > idle_timeout
            """
            try:
                while not stop_evt.is_set():
                    await asyncio.sleep(0.25)
                    now = time.time()

                    if (now - last_upstream_io_ts) >= float(read_timeout):
                        self.closed_by = "proxy"
                        self.close_reason = "upstream_read_timeout"
                        if "upstream_read_timeout" not in self.close_flags:
                            self.close_flags.append("upstream_read_timeout")
                        try:
                            await self.runtime.conn_store.set_error(self.conn_id, "h2 watchdog: upstream_read_timeout")
                        except Exception:
                            pass

                        stop_evt.set()
                        try:
                            self.c_writer.close()
                        except Exception:
                            pass
                        try:
                            u_writer.close()
                        except Exception:
                            pass
                        return

                    if (now - last_any_io_ts) >= float(idle_timeout):
                        self.closed_by = "proxy"
                        self.close_reason = "proxy_idle_timeout"
                        if "proxy_idle_timeout" not in self.close_flags:
                            self.close_flags.append("proxy_idle_timeout")
                        try:
                            await self.runtime.conn_store.set_error(self.conn_id, "h2 watchdog: proxy_idle_timeout")
                        except Exception:
                            pass

                        stop_evt.set()
                        try:
                            self.c_writer.close()
                        except Exception:
                            pass
                        try:
                            u_writer.close()
                        except Exception:
                            pass
                        return
            except Exception:
                LOG.debug("h2 watchdog failed conn_id=%s", self.conn_id, exc_info=True)
                return

        # --- build H2 state machines ---
        dconn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        dconn.initiate_connection()
        try:
            self.c_writer.write(dconn.data_to_send())
            await self.c_writer.drain()
        except Exception as e:
            await self.runtime.conn_store.set_error(self.conn_id, f"send downstream h2 preface failed: {e}")
            self._mark_close("client_protocol_error")
            try:
                u_writer.close()
                await u_writer.wait_closed()
            except Exception:
                pass
            return

        uconn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        uconn.initiate_connection()
        try:
            u_writer.write(uconn.data_to_send())
            await u_writer.drain()
        except Exception as e:
            await self.runtime.conn_store.set_error(self.conn_id, f"send upstream h2 preface failed: {e}")
            self._mark_close("upstream_protocol_error")
            try:
                self.c_writer.close()
                await self.c_writer.wait_closed()
            except Exception:
                pass
            try:
                u_writer.close()
                await u_writer.wait_closed()
            except Exception:
                pass
            return

        up_host, up_port = _parse_hostport(self.runtime.cfg.upstream.addr)
        up_authority = (self.runtime.cfg.upstream.server_name or up_host)
        up_authority = f"{up_authority}:{up_port}"

        def rewrite_req_headers_for_upstream(hdrs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
            out: List[Tuple[str, str]] = []
            seen_authority = False
            for k, v in hdrs:
                kl = k.lower()
                if kl == ":authority":
                    out.append((":authority", up_authority))
                    seen_authority = True
                    continue
                if kl == "host":
                    continue
                out.append((k, v))
            if not seen_authority:
                out.append((":authority", up_authority))
            return out

        # --- per-stream state (for UI/event) ---
        st_start: Dict[int, float] = {}
        st_req_hdrs: Dict[int, Dict[str, str]] = {}
        st_resp_hdrs: Dict[int, Dict[str, str]] = {}
        st_req_body: Dict[int, bytearray] = {}
        st_resp_body: Dict[int, bytearray] = {}
        st_req_trunc: Dict[int, bool] = {}
        st_resp_trunc: Dict[int, bool] = {}
        st_bytes_in: Dict[int, int] = {}
        st_bytes_out: Dict[int, int] = {}
        st_method: Dict[int, Optional[str]] = {}
        st_path: Dict[int, Optional[str]] = {}
        st_auth: Dict[int, Optional[str]] = {}
        st_status: Dict[int, Optional[int]] = {}
        st_done_down: Dict[int, bool] = {}
        st_done_up: Dict[int, bool] = {}
        st_error: Dict[int, Optional[str]] = {}

        pend_to_up: Dict[int, Deque[bytes]] = {}
        pend_to_down: Dict[int, Deque[bytes]] = {}
        want_end_up: Dict[int, bool] = {}
        want_end_down: Dict[int, bool] = {}

        st_fc_blocked: Dict[int, float] = {}

        def maybe_capture(buf: bytearray, trunc_map: Dict[int, bool], sid: int, data: bytes):
            if capture_max < 0:
                return
            if eff_max <= 0:
                trunc_map[sid] = True
                return
            if len(buf) < eff_max:
                take = min(eff_max - len(buf), len(data))
                buf.extend(data[:take])
                if take < len(data):
                    trunc_map[sid] = True
            else:
                trunc_map[sid] = True

        def hdr_get(h: Dict[str, str], k: str) -> Optional[str]:
            kl = k.lower()
            for kk, vv in h.items():
                if kk.lower() == kl:
                    return vv
            return None

        async def mark_blocked_fc(where: str, sid: int, want: int):
            now = time.time()
            last = st_fc_blocked.get(sid, 0.0)
            if now - last < 0.5:
                return
            st_fc_blocked[sid] = now
            await self.runtime.metrics.inc("h2_flow_block", 1, self.runtime.cfg.name)
            if log_h2ctl:
                await self._emit_h2ctl(
                    direction=where,
                    evname="FLOW_BLOCK",
                    stream_id=sid,
                    details={"wanted_bytes": int(want)},
                )

        async def emit_h2ctl_if_enabled(
            direction: str, evname: str, stream_id: Optional[int], details: Dict[str, Any]
        ) -> None:
            if not log_h2ctl:
                return
            await self._emit_h2ctl(direction=direction, evname=evname, stream_id=stream_id, details=details)

        def safe_reset(sid: int, msg: str):
            st_error[sid] = msg
            st_done_up[sid] = True
            st_done_down[sid] = True
            asyncio.create_task(self.runtime.conn_store.set_error(self.conn_id, f"stream {sid}: {msg}"))
            try:
                dconn.reset_stream(sid, error_code=0x2)  # INTERNAL_ERROR
            except Exception:
                pass
            try:
                uconn.reset_stream(sid, error_code=0x2)
            except Exception:
                pass

        async def emit_if_done(sid: int):
            if not st_done_down.get(sid, False) or not st_done_up.get(sid, False):
                return

            ts0 = st_start.get(sid, time.time())
            ts1 = time.time()

            req_hdrs = st_req_hdrs.get(sid, {})
            resp_hdrs = st_resp_hdrs.get(sid, {})
            method = st_method.get(sid)
            path = st_path.get(sid)
            authority = st_auth.get(sid)
            status = st_status.get(sid)

            proto = "http2"
            grpc_svc = grpc_m = None
            is_gr = is_grpc({k: v for k, v in req_hdrs.items() if not k.startswith(":")})
            if is_gr:
                proto = "grpc"
                grpc_svc, grpc_m = grpc_parse_path(path or "")

            if is_gr:
                gs = hdr_get(resp_hdrs, "grpc-status")
                if gs is not None:
                    await self.runtime.metrics.inc(f"grpc_status_{gs}", 1, self.runtime.cfg.name)

            if log_headers:
                req_hdrs_e = self._policy.redact(req_hdrs)
                resp_hdrs_e = self._policy.redact(resp_hdrs)
            else:
                req_hdrs_e = {}
                resp_hdrs_e = {}

            req_body_b = bytes(st_req_body.get(sid, b""))
            resp_body_b = bytes(st_resp_body.get(sid, b""))

            ev = Event(
                kind="event",
                id=str(uuid.uuid4()),
                ts_start=ts0, ts_end=ts1,
                listener=self.runtime.cfg.name,
                client_ip=self.client_ip, client_port=self.client_port,
                upstream_addr=self.runtime.cfg.upstream.addr,
                protocol=proto,
                tls=tls_in,
                request=RequestInfo(
                    method=method, path=path, authority=authority,
                    headers=req_hdrs_e,
                    stream_id=sid,
                    body_b64=(base64.b64encode(req_body_b).decode("ascii") if req_body_b else None),
                    body_truncated=bool(st_req_trunc.get(sid, False)),
                    grpc_service=grpc_svc, grpc_method=grpc_m,
                ),
                response=ResponseInfo(
                    status=status,
                    headers=resp_hdrs_e,
                    body_b64=(base64.b64encode(resp_body_b).decode("ascii") if resp_body_b else None),
                    body_truncated=bool(st_resp_trunc.get(sid, False)),
                ),
                bytes_in=int(st_bytes_in.get(sid, 0)),
                bytes_out=int(st_bytes_out.get(sid, 0)),
                duration_ms=int((ts1 - ts0) * 1000),
                flags=(["error"] if st_error.get(sid) else []),
                error=st_error.get(sid),
            )
            await self.runtime.store.add(ev)

            for d in (
                    st_start, st_req_hdrs, st_resp_hdrs, st_req_body, st_resp_body,
                    st_req_trunc, st_resp_trunc, st_bytes_in, st_bytes_out,
                    st_method, st_path, st_auth, st_status, st_done_down, st_done_up,
                    st_error, st_fc_blocked, pend_to_up, pend_to_down, want_end_up, want_end_down
            ):
                d.pop(sid, None)

        def _queue_data(bufmap: Dict[int, Deque[bytes]], sid: int, data: bytes):
            q = bufmap.setdefault(sid, deque())
            if data:
                q.append(data)

        async def _flush_to_up(sid: int):
            q = pend_to_up.get(sid)
            if not q:
                if want_end_up.get(sid, False):
                    try:
                        uconn.end_stream(sid)
                    except Exception:
                        pass
                    want_end_up[sid] = False
                return

            while q:
                chunk = q[0]
                try:
                    wnd = uconn.local_flow_control_window(sid)
                    if wnd <= 0:
                        await mark_blocked_fc("upstream", sid, want=len(chunk))
                        break
                    maxf = uconn.max_outbound_frame_size
                    send_n = min(len(chunk), wnd, maxf)
                    part = chunk[:send_n]
                    uconn.send_data(sid, part, end_stream=False)
                    q[0] = chunk[send_n:]
                    if not q[0]:
                        q.popleft()
                except FlowControlError:
                    await mark_blocked_fc("upstream", sid, want=len(chunk))
                    break
                except Exception as e:
                    safe_reset(sid, f"flush upstream failed: {e}")
                    break

            if not q:
                pend_to_up.pop(sid, None)
                if want_end_up.get(sid, False):
                    try:
                        uconn.end_stream(sid)
                    except Exception:
                        pass
                    want_end_up[sid] = False

        async def _flush_to_down(sid: int):
            q = pend_to_down.get(sid)
            if not q:
                if want_end_down.get(sid, False):
                    try:
                        dconn.end_stream(sid)
                    except Exception:
                        pass
                    want_end_down[sid] = False
                return

            while q:
                chunk = q[0]
                try:
                    wnd = dconn.local_flow_control_window(sid)
                    if wnd <= 0:
                        await mark_blocked_fc("downstream", sid, want=len(chunk))
                        break
                    maxf = dconn.max_outbound_frame_size
                    send_n = min(len(chunk), wnd, maxf)
                    part = chunk[:send_n]
                    dconn.send_data(sid, part, end_stream=False)
                    q[0] = chunk[send_n:]
                    if not q[0]:
                        q.popleft()
                except FlowControlError:
                    await mark_blocked_fc("downstream", sid, want=len(chunk))
                    break
                except Exception as e:
                    safe_reset(sid, f"flush downstream failed: {e}")
                    break

            if not q:
                pend_to_down.pop(sid, None)
                if want_end_down.get(sid, False):
                    try:
                        dconn.end_stream(sid)
                    except Exception:
                        pass
                    want_end_down[sid] = False

        async def _flush_all_to_up():
            for sid in list(pend_to_up.keys()):
                await _flush_to_up(sid)

        async def _flush_all_to_down():
            for sid in list(pend_to_down.keys()):
                await _flush_to_down(sid)

        # --- main loops ---
        async def downstream_loop():
            """
            DOWNSTREAM (client -> proxy)
            """
            try:
                while not stop_evt.is_set():
                    data = await self.c_reader.read(65536)
                    if not data:
                        # client FIN
                        self._mark_close("client_fin")
                        break

                    note_any_io()
                    await self.runtime.conn_store.touch(self.conn_id)

                    try:
                        events = dconn.receive_data(data)
                    except ProtocolError as e:
                        await self.runtime.conn_store.set_error(self.conn_id, f"downstream protocol error: {e}")
                        self._mark_close("client_protocol_error")
                        break
                    except Exception as e:
                        await self.runtime.conn_store.set_error(self.conn_id, f"downstream receive error: {e}")
                        self._mark_close("client_protocol_error")
                        break

                    out = dconn.data_to_send()
                    if out:
                        self.c_writer.write(out)
                        await self.c_writer.drain()

                    for ev in events:
                        if isinstance(ev, RequestReceived):
                            sid = ev.stream_id
                            await self.runtime.conn_store.h2_stream_open(self.conn_id)
                            await self.runtime.metrics.inc("h2_streams_opened", 1, self.runtime.cfg.name)

                            st_start[sid] = time.time()
                            hdrs = {k: v for (k, v) in ev.headers}
                            st_req_hdrs[sid] = hdrs
                            st_req_body[sid] = bytearray()
                            st_resp_body[sid] = bytearray()
                            st_req_trunc[sid] = False
                            st_resp_trunc[sid] = False
                            st_bytes_in[sid] = st_bytes_in.get(sid, 0)
                            st_bytes_out[sid] = st_bytes_out.get(sid, 0)
                            st_done_down[sid] = False
                            st_done_up[sid] = False
                            st_error[sid] = None

                            st_method[sid] = hdrs.get(":method")
                            st_path[sid] = hdrs.get(":path")

                            try:
                                p = st_path[sid]
                                if p:
                                    await self.runtime.conn_store.set_last_path(self.conn_id, p)
                            except Exception:
                                pass

                            st_auth[sid] = hdrs.get(":authority") or hdrs.get("host")

                            fwd = rewrite_req_headers_for_upstream(list(ev.headers))
                            try:
                                uconn.send_headers(sid, fwd, end_stream=False)
                            except Exception as e:
                                safe_reset(sid, f"send request headers upstream failed: {e}")
                                await emit_if_done(sid)

                        elif isinstance(ev, DataReceived):
                            sid = ev.stream_id
                            st_bytes_in[sid] = st_bytes_in.get(sid, 0) + len(ev.data)
                            maybe_capture(st_req_body.setdefault(sid, bytearray()), st_req_trunc, sid, ev.data)

                            dconn.acknowledge_received_data(ev.flow_controlled_length, sid)

                            _queue_data(pend_to_up, sid, ev.data)
                            await _flush_to_up(sid)

                        elif isinstance(ev, TrailersReceived):
                            sid = ev.stream_id
                            try:
                                uconn.send_headers(sid, ev.headers, end_stream=True)
                            except Exception as e:
                                safe_reset(sid, f"send request trailers upstream failed: {e}")
                            st_done_down[sid] = True
                            await emit_if_done(sid)

                        elif isinstance(ev, StreamEnded):
                            sid = ev.stream_id
                            st_done_down[sid] = True
                            if pend_to_up.get(sid):
                                want_end_up[sid] = True
                                await _flush_to_up(sid)
                            else:
                                try:
                                    uconn.end_stream(sid)
                                except Exception:
                                    pass
                            await emit_if_done(sid)

                        elif isinstance(ev, StreamReset):
                            sid = ev.stream_id
                            await self.runtime.metrics.inc("h2_streams_reset_in", 1, self.runtime.cfg.name)
                            await emit_h2ctl_if_enabled(
                                direction="downstream",
                                evname="RST_STREAM",
                                stream_id=sid,
                                details={"error_code": int(ev.error_code)},
                            )
                            st_error[sid] = f"downstream reset: {ev.error_code}"
                            st_done_down[sid] = True
                            try:
                                uconn.reset_stream(sid, error_code=ev.error_code)
                            except Exception:
                                pass
                            await emit_if_done(sid)
                            await self.runtime.conn_store.h2_stream_close(self.conn_id)

                        elif isinstance(ev, WindowUpdated):
                            await emit_h2ctl_if_enabled(
                                direction="downstream",
                                evname="WINDOW_UPDATE",
                                stream_id=(None if ev.stream_id == 0 else ev.stream_id),
                                details={"delta": int(getattr(ev, "delta", 0))},
                            )
                            if ev.stream_id == 0:
                                await _flush_all_to_down()
                            else:
                                await _flush_to_down(ev.stream_id)

                        elif isinstance(ev, ConnectionTerminated):
                            await self.runtime.metrics.inc("h2_goaway_in", 1, self.runtime.cfg.name)
                            adata = getattr(ev, "additional_data", b"") or b""
                            await emit_h2ctl_if_enabled(
                                direction="downstream",
                                evname="GOAWAY",
                                stream_id=None,
                                details={
                                    "error_code": int(getattr(ev, "error_code", 0)),
                                    "last_stream_id": int(getattr(ev, "last_stream_id", 0)),
                                    "debug_data_b64": (base64.b64encode(adata).decode("ascii") if adata else None),
                                },
                            )

                        elif isinstance(ev, RemoteSettingsChanged):
                            changed = []
                            for code, chg in (getattr(ev, "changed_settings", {}) or {}).items():
                                changed.append(
                                    {
                                        "setting": str(getattr(code, "name", code)),
                                        "old": getattr(chg, "original_value", None),
                                        "new": getattr(chg, "new_value", None),
                                    }
                                )
                            await emit_h2ctl_if_enabled(
                                direction="downstream",
                                evname="SETTINGS",
                                stream_id=None,
                                details={"changed": changed},
                            )

                        elif isinstance(ev, SettingsAcknowledged):
                            changed = []
                            for code, chg in (getattr(ev, "changed_settings", {}) or {}).items():
                                changed.append(
                                    {
                                        "setting": str(getattr(code, "name", code)),
                                        "old": getattr(chg, "original_value", None),
                                        "new": getattr(chg, "new_value", None),
                                    }
                                )
                            await emit_h2ctl_if_enabled(
                                direction="downstream",
                                evname="SETTINGS_ACK",
                                stream_id=None,
                                details={"changed": changed},
                            )

                    outu = uconn.data_to_send()
                    if outu:
                        u_writer.write(outu)
                        await u_writer.drain()

            except ConnectionResetError as e:
                await self.runtime.conn_store.set_error(self.conn_id, f"downstream reset: {e}")
                self._mark_close("client_rst")
            except Exception as e:
                await self.runtime.conn_store.set_error(self.conn_id, f"downstream loop error: {e}")
                self._mark_close("client_protocol_error")

        async def upstream_loop():
            """
            UPSTREAM (server -> proxy)
            """
            try:
                while not stop_evt.is_set():
                    data = await u_reader.read(65536)
                    if not data:
                        # upstream FIN (this is what we need for mtls_h2_upstream_fail)
                        self._mark_close("upstream_fin")
                        break

                    note_upstream_io()
                    await self.runtime.conn_store.touch(self.conn_id)

                    try:
                        events = uconn.receive_data(data)
                    except ProtocolError as e:
                        await self.runtime.conn_store.set_error(self.conn_id, f"upstream protocol error: {e}")
                        self._mark_close("upstream_protocol_error")
                        break
                    except Exception as e:
                        await self.runtime.conn_store.set_error(self.conn_id, f"upstream receive error: {e}")
                        self._mark_close("upstream_protocol_error")
                        break

                    out = uconn.data_to_send()
                    if out:
                        u_writer.write(out)
                        await u_writer.drain()

                    for ev in events:
                        if isinstance(ev, ResponseReceived):
                            sid = ev.stream_id
                            hdrs = {k: v for (k, v) in ev.headers}
                            st_resp_hdrs[sid] = hdrs
                            st = hdrs.get(":status")
                            try:
                                st_status[sid] = int(st) if st else None
                            except Exception:
                                st_status[sid] = None

                            try:
                                dconn.send_headers(sid, ev.headers, end_stream=False)
                            except Exception as e:
                                safe_reset(sid, f"send response headers downstream failed: {e}")
                                await emit_if_done(sid)

                        elif isinstance(ev, DataReceived):
                            sid = ev.stream_id
                            st_bytes_out[sid] = st_bytes_out.get(sid, 0) + len(ev.data)
                            maybe_capture(st_resp_body.setdefault(sid, bytearray()), st_resp_trunc, sid, ev.data)

                            uconn.acknowledge_received_data(ev.flow_controlled_length, sid)

                            _queue_data(pend_to_down, sid, ev.data)
                            await _flush_to_down(sid)

                        elif isinstance(ev, TrailersReceived):
                            sid = ev.stream_id
                            st_resp_hdrs.setdefault(sid, {})
                            for k, v in ev.headers:
                                st_resp_hdrs[sid][k] = v
                            try:
                                dconn.send_headers(sid, ev.headers, end_stream=True)
                            except Exception as e:
                                safe_reset(sid, f"send response trailers downstream failed: {e}")
                            st_done_up[sid] = True
                            await emit_if_done(sid)
                            await self.runtime.conn_store.h2_stream_close(self.conn_id)

                        elif isinstance(ev, StreamEnded):
                            sid = ev.stream_id
                            st_done_up[sid] = True
                            if pend_to_down.get(sid):
                                want_end_down[sid] = True
                                await _flush_to_down(sid)
                            else:
                                try:
                                    dconn.end_stream(sid)
                                except Exception:
                                    pass
                            await emit_if_done(sid)
                            await self.runtime.conn_store.h2_stream_close(self.conn_id)

                        elif isinstance(ev, StreamReset):
                            sid = ev.stream_id
                            await self.runtime.metrics.inc("h2_streams_reset_out", 1, self.runtime.cfg.name)
                            await emit_h2ctl_if_enabled(
                                direction="upstream",
                                evname="RST_STREAM",
                                stream_id=sid,
                                details={"error_code": int(ev.error_code)},
                            )
                            st_error[sid] = f"upstream reset: {ev.error_code}"
                            st_done_up[sid] = True
                            try:
                                dconn.reset_stream(sid, error_code=ev.error_code)
                            except Exception:
                                pass
                            await emit_if_done(sid)
                            await self.runtime.conn_store.h2_stream_close(self.conn_id)

                        elif isinstance(ev, WindowUpdated):
                            await emit_h2ctl_if_enabled(
                                direction="upstream",
                                evname="WINDOW_UPDATE",
                                stream_id=(None if ev.stream_id == 0 else ev.stream_id),
                                details={"delta": int(getattr(ev, "delta", 0))},
                            )
                            if ev.stream_id == 0:
                                await _flush_all_to_up()
                            else:
                                await _flush_to_up(ev.stream_id)

                        elif isinstance(ev, ConnectionTerminated):
                            await self.runtime.metrics.inc("h2_goaway_out", 1, self.runtime.cfg.name)
                            adata = getattr(ev, "additional_data", b"") or b""
                            await emit_h2ctl_if_enabled(
                                direction="upstream",
                                evname="GOAWAY",
                                stream_id=None,
                                details={
                                    "error_code": int(getattr(ev, "error_code", 0)),
                                    "last_stream_id": int(getattr(ev, "last_stream_id", 0)),
                                    "debug_data_b64": (base64.b64encode(adata).decode("ascii") if adata else None),
                                },
                            )

                        elif isinstance(ev, RemoteSettingsChanged):
                            changed = []
                            for code, chg in (getattr(ev, "changed_settings", {}) or {}).items():
                                changed.append(
                                    {
                                        "setting": str(getattr(code, "name", code)),
                                        "old": getattr(chg, "original_value", None),
                                        "new": getattr(chg, "new_value", None),
                                    }
                                )
                            await emit_h2ctl_if_enabled(
                                direction="upstream",
                                evname="SETTINGS",
                                stream_id=None,
                                details={"changed": changed},
                            )

                        elif isinstance(ev, SettingsAcknowledged):
                            changed = []
                            for code, chg in (getattr(ev, "changed_settings", {}) or {}).items():
                                changed.append(
                                    {
                                        "setting": str(getattr(code, "name", code)),
                                        "old": getattr(chg, "original_value", None),
                                        "new": getattr(chg, "new_value", None),
                                    }
                                )
                            await emit_h2ctl_if_enabled(
                                direction="upstream",
                                evname="SETTINGS_ACK",
                                stream_id=None,
                                details={"changed": changed},
                            )

                    outd = dconn.data_to_send()
                    if outd:
                        self.c_writer.write(outd)
                        await self.c_writer.drain()

            except ConnectionResetError as e:
                await self.runtime.conn_store.set_error(self.conn_id, f"upstream reset: {e}")
                self._mark_close("upstream_rst")
            except Exception as e:
                await self.runtime.conn_store.set_error(self.conn_id, f"upstream loop error: {e}")
                self._mark_close("upstream_protocol_error")

        # --- run loops + watchdog and cleanup ---
        t1 = asyncio.create_task(downstream_loop())
        t2 = asyncio.create_task(upstream_loop())
        tw = asyncio.create_task(watchdog())

        done, pending = await asyncio.wait({t1, t2, tw}, return_when=asyncio.FIRST_COMPLETED)

        stop_evt.set()
        for p in pending:
            p.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        # best-effort final flush
        try:
            outd = dconn.data_to_send()
            if outd:
                self.c_writer.write(outd)
                await self.c_writer.drain()
        except Exception:
            pass

        try:
            outu = uconn.data_to_send()
            if outu:
                u_writer.write(outu)
                await u_writer.drain()
        except Exception:
            pass

        # close sockets
        try:
            self.c_writer.close()
        except Exception:
            pass
        try:
            u_writer.close()
        except Exception:
            pass
        try:
            await self.c_writer.wait_closed()
        except Exception:
            pass
        try:
            await u_writer.wait_closed()
        except Exception:
            pass

        # If handler ends without explicit reason — completed.
        if self.close_reason is None:
            self.closed_by = "proxy"
            self.close_reason = "completed"
            self.close_flags = list(getattr(self, "close_flags", None) or [])


# TUI: widgets
class SelectableRow(urwid.WidgetWrap):
    def selectable(self) -> bool:
        return True

    def keypress(self, size, key):
        return key


class TrafficList(urwid.WidgetWrap):
    """
    Traffic view list widget.

    Features:
      - renders mixed record types (Event/TLS/ConnLifecycle/H2Control)
      - follow_tail: tail mode (End/G), disabled by navigation (Up/Home/PgUp/PgDn)
      - force_highlight: manual highlight of the focused row when an overlay steals focus (Details)

    Methods:
      - refresh(flt): rebuild visible list using store snapshot + filter
      - focused_record(): return currently selected record
      - move_focus(delta): programmatic focus move (used by N/P in Details overlay)
    """
    COL_MARK = 2
    COL_TIME = 9
    COL_LISTENER = 18
    COL_CLIENT = 21
    COL_PROTO = 7
    COL_CODE = 8
    COL_DURATION = 8
    COL_BYTES = 8
    COL_FLAGS = 16
    COL_DIV = 1

    def __init__(self, manager: ListenerManager, is_marked_cb):
        self.manager = manager
        self.is_marked_cb = is_marked_cb
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)

        self.follow_tail = True
        self._focused_id: Optional[str] = None
        self.visible_records: List[Record] = []

        # only force "focus" painting when overlay steals focus (Details open)
        self.force_highlight: bool = False

        header = urwid.Columns([
            ("fixed", self.COL_MARK, urwid.Text("M")),
            ("fixed", self.COL_TIME, urwid.Text("Time")),
            ("fixed", self.COL_LISTENER, urwid.Text("Listener")),
            ("fixed", self.COL_CLIENT, urwid.Text("Client")),
            ("fixed", self.COL_PROTO, urwid.Text("Proto")),
            ("fixed", self.COL_CODE, urwid.Text("Code")),
            urwid.Text("What"),
            ("fixed", self.COL_DURATION, urwid.Text("Duration")),
            ("fixed", self.COL_BYTES, urwid.Text("Bytes")),
            ("fixed", self.COL_FLAGS, urwid.Text("Flags")),
        ], dividechars=self.COL_DIV)

        frame = urwid.Frame(self.listbox, header=urwid.AttrMap(header, "header"))
        super().__init__(frame)

    def keypress(self, size, key):
        if key in ("up", "down", "page up", "page down", "k", "j"):
            self.follow_tail = False
        if key in ("end", "G"):
            self.follow_tail = True
        return super().keypress(size, key)

    def move_focus(self, delta: int) -> None:
        """
        Move focus in Traffic list by delta (+1 next, -1 prev).
        If force_highlight=True (Details overlay open), paint focus row manually
        because ListBox is not focused.
        """
        try:
            walker = getattr(self, "walker", None)
            if not walker or len(walker) == 0:
                return

            cur = walker.get_focus()[1]
            if cur is None:
                cur = 0

            nxt = max(0, min(len(walker) - 1, cur + int(delta)))

            # Only in overlay-mode: manually repaint old/new
            if self.force_highlight:
                try:
                    oldw = walker[cur]
                    if isinstance(oldw, urwid.AttrMap):
                        oldw.set_attr_map({None: "bg"})
                except Exception:
                    pass

            walker.set_focus(nxt)

            if self.force_highlight:
                try:
                    neww = walker[nxt]
                    if isinstance(neww, urwid.AttrMap):
                        neww.set_attr_map({None: "focus"})
                except Exception:
                    pass

            # remember focused record id for refresh() stability
            try:
                w = walker.get_focus()[0]
                rec = getattr(w, "_rec", None)
                self._focused_id = getattr(rec, "id", None) if rec else None
            except Exception:
                pass

        except Exception:
            pass

    def focused_record(self) -> Optional[Record]:
        if not self.walker:
            return None
        w = self.walker.get_focus()[0]
        return getattr(w, "_rec", None)

    def focus_index(self) -> Optional[int]:
        if not self.walker:
            return None
        try:
            return int(self.walker.focus)
        except Exception:
            return None

    def set_focus_index(self, idx: int) -> bool:
        if not self.walker:
            return False
        idx = max(0, min(idx, len(self.walker) - 1))
        try:
            self.walker.set_focus(idx)
            return True
        except Exception:
            return False

    async def refresh(self, flt: FilterSpec) -> None:
        cur = self.focused_record()
        self._focused_id = getattr(cur, "id", None) if cur else None

        records = await self.manager.store.snapshot(limit=6000)
        records = records[-2500:]
        if flt and flt.raw:
            records = [r for r in records if flt.matches_record(r)]

        self.visible_records = records

        new_widgets: List[urwid.Widget] = []
        focus_index: Optional[int] = None
        flags_width = self.COL_FLAGS

        def _short_flag(flag: str) -> str:
            f = (flag or "").strip().lower()
            mp = {
                "upstream_protocol_error": "upst_prot_err",
                "client_protocol_error": "cl_prot_err",
                "upstream_connect_fail": "upst_conn_fail",
                "upstream_connect_timeout": "upst_conn_to",
                "upstream_handshake_timeout": "upst_hs_to",
                "client_tls_fail": "cl_tls_fail",
                "upstream_tls_fail": "upst_tls_fail",
                "proxy_protocol_error": "pp_err",
                "client_proxy_protocol_error": "cl_pp_err",
                "client_fin": "cl_fin",
                "upstream_fin": "up_fin",
                "client_rst": "cl_rst",
                "upstream_rst": "up_rst",
                "upstream_read_timeout": "upst_read_to",
                "client_read_timeout": "cl_read_to",
                "proxy_idle_timeout": "idle_to",
            }
            return mp.get(f, f[:flags_width])

        def _join_flags(flags: List[str], limit: int = 2) -> str:
            if not flags:
                return ""
            items = [_short_flag(x) for x in flags[:limit] if x]
            return ",".join(items)[:flags_width]

        def _is_error_record(rec: Record) -> bool:
            if isinstance(rec, TlsHandshakeRecord):
                return (rec.outcome or "").lower() == "fail"
            if isinstance(rec, ConnLifecycleRecord):
                if rec.event != "close":
                    return False
                cr = (rec.close_reason or "").lower()
                if any(x in cr for x in ("fail", "error", "timeout", "rst", "protocol")):
                    return True
                return any(
                    any(x in (f or "").lower() for x in ("fail", "error", "timeout", "rst", "protocol"))
                    for f in (rec.flags or [])
                )
            if isinstance(rec, Event):
                if rec.error:
                    return True
                try:
                    st = int(rec.response.status) if rec.response and rec.response.status is not None else 0
                except Exception:
                    st = 0
                if st >= 500:
                    return True
                return any(
                    any(x in (f or "").lower() for x in ("fail", "error", "timeout", "rst", "protocol"))
                    for f in (rec.flags or [])
                )
            return False

        def _is_warn_record(rec: Record) -> bool:
            if isinstance(rec, H2ControlRecord):
                ev = (rec.h2_event or "").upper()
                return ev in ("GOAWAY", "RST_STREAM", "FLOW_BLOCK")
            return False

        for idx, rec in enumerate(records):
            marked = self.is_marked_cb(rec.id)
            mark_txt = "*" if marked else " "

            if isinstance(rec, Event):
                code = rec.response.status if rec.response.status is not None else "-"
                meth = rec.request.method or "-"
                path = rec.request.path or "-"
                if rec.protocol == "grpc" and rec.request.grpc_service and rec.request.grpc_method:
                    path = f"/{rec.request.grpc_service}/{rec.request.grpc_method}"
                what = f"{meth} {path}"
                dur = f"{rec.duration_ms}ms"
                by = f"{rec.bytes_in}/{rec.bytes_out}"
                flags = _join_flags(rec.flags, limit=2)

                row = urwid.Columns([
                    ("fixed", self.COL_MARK, urwid.Text(("mark", mark_txt) if marked else mark_txt)),
                    ("fixed", self.COL_TIME, urwid.Text(fmt_ts(rec.ts_start))),
                    ("fixed", self.COL_LISTENER, urwid.Text(rec.listener[:self.COL_LISTENER])),
                    ("fixed", self.COL_CLIENT, urwid.Text(f"{rec.client_ip}:{rec.client_port}"[:self.COL_CLIENT])),
                    ("fixed", self.COL_PROTO, urwid.Text(rec.protocol[:self.COL_PROTO])),
                    ("fixed", self.COL_CODE, urwid.Text(str(code)[:self.COL_CODE])),
                    urwid.Text(what),
                    ("fixed", self.COL_DURATION, urwid.Text(dur[:self.COL_DURATION])),
                    ("fixed", self.COL_BYTES, urwid.Text(by[:self.COL_BYTES])),
                    ("fixed", flags_width, urwid.Text(flags[:flags_width])),
                ], dividechars=self.COL_DIV)

            elif isinstance(rec, TlsHandshakeRecord):
                proto = "tls"
                code = rec.outcome

                details: List[str] = []
                if rec.tls and rec.tls.version:
                    details.append(rec.tls.version)
                if rec.tls and rec.tls.alpn:
                    details.append(rec.tls.alpn)
                if rec.tls and rec.tls.sni:
                    details.append(f"sni={rec.tls.sni}")
                if rec.tls and rec.tls.cipher:
                    details.append(rec.tls.cipher)

                base = f"{rec.side} {rec.reason or ''}".strip()

                # show category + detail (short) directly in list
                extra_bits: List[str] = []
                cat = getattr(rec, "category", None)
                det = getattr(rec, "detail", None)
                if cat:
                    extra_bits.append(str(cat))
                if det:
                    extra_bits.append(str(det))

                extra_txt = ""
                if extra_bits:
                    extra_joined = " | ".join(extra_bits)
                    extra_txt = f" [{extra_joined[:140]}]"

                what = (base + extra_txt + (" " + " ".join(details) if details else "")).strip()

                dur = "-"
                by = "-"
                flags = "fail" if rec.outcome == "fail" else ""

                row = urwid.Columns([
                    ("fixed", self.COL_MARK, urwid.Text(("mark", mark_txt) if marked else mark_txt)),
                    ("fixed", self.COL_TIME, urwid.Text(fmt_ts(rec.ts))),
                    ("fixed", self.COL_LISTENER, urwid.Text(rec.listener[:self.COL_LISTENER])),
                    ("fixed", self.COL_CLIENT, urwid.Text(f"{rec.client_ip}:{rec.client_port}"[:self.COL_CLIENT])),
                    ("fixed", self.COL_PROTO, urwid.Text(proto)),
                    ("fixed", self.COL_CODE, urwid.Text(code[:self.COL_CODE])),
                    urwid.Text(what),
                    ("fixed", self.COL_DURATION, urwid.Text(dur)),
                    ("fixed", self.COL_BYTES, urwid.Text(by)),
                    ("fixed", flags_width, urwid.Text(flags[:flags_width])),
                ], dividechars=self.COL_DIV)

            elif isinstance(rec, ConnLifecycleRecord):
                proto = "conn"
                code = rec.event
                pp = (rec.proxy_version or "none")
                pp_bits = [f"pp={pp}"]
                if rec.proxy_src:
                    pp_bits.append(f"src={rec.proxy_src}")
                if rec.proxy_dst:
                    pp_bits.append(f"dst={rec.proxy_dst}")
                pp_txt = " ".join(pp_bits)

                if rec.event == "open":
                    what = f"open -> {rec.upstream_addr} {pp_txt}"
                else:
                    cr = (rec.close_reason or "-")
                    cb = (rec.closed_by or "-")
                    what = f"close {cb}:{cr} {pp_txt}"

                dur = "-" if rec.duration_ms is None else f"{rec.duration_ms}ms"
                by = "-"
                flags = _join_flags(rec.flags, limit=2)
                if rec.event == "close":
                    cr_l = (rec.close_reason or "").lower()
                    bad_markers = ("fail", "error", "timeout", "rst", "protocol")
                    if any(m in cr_l for m in bad_markers):
                        flags = ("!" if not flags else f"!,{flags}")[:flags_width]

                row = urwid.Columns([
                    ("fixed", self.COL_MARK, urwid.Text(("mark", mark_txt) if marked else mark_txt)),
                    ("fixed", self.COL_TIME, urwid.Text(fmt_ts(rec.ts))),
                    ("fixed", self.COL_LISTENER, urwid.Text(rec.listener[:self.COL_LISTENER])),
                    ("fixed", self.COL_CLIENT, urwid.Text(f"{rec.client_ip}:{rec.client_port}"[:self.COL_CLIENT])),
                    ("fixed", self.COL_PROTO, urwid.Text(proto)),
                    ("fixed", self.COL_CODE, urwid.Text(code[:self.COL_CODE])),
                    urwid.Text(what),
                    ("fixed", self.COL_DURATION, urwid.Text(dur[:self.COL_DURATION])),
                    ("fixed", self.COL_BYTES, urwid.Text(by)),
                    ("fixed", flags_width, urwid.Text(flags[:flags_width])),
                ], dividechars=self.COL_DIV)

            else:  # H2ControlRecord
                proto = "h2ctl"
                ev = str(getattr(rec, "h2_event", "") or "")
                # Keep Code compact and unambiguous in 8-char column.
                code_map = {
                    "SETTINGS": "SET",
                    "SETTINGS_ACK": "SET_ACK",
                    "WINDOW_UPDATE": "WUPD",
                    "FLOW_BLOCK": "FLOW_BLK",
                    "RST_STREAM": "RST",
                    "GOAWAY": "GOAWAY",
                }
                code = code_map.get(ev, ev[:8])

                d = rec.details or {}
                bits: List[str] = [rec.direction]
                if rec.stream_id is not None:
                    bits.append(f"sid={rec.stream_id}")

                if ev in ("SETTINGS", "SETTINGS_ACK"):
                    ch = d.get("changed")
                    if isinstance(ch, list):
                        bits.append(f"changed={len(ch)}")
                elif ev == "WINDOW_UPDATE":
                    delta = d.get("delta")
                    if delta is not None:
                        bits.append(f"delta={delta}")
                elif ev == "FLOW_BLOCK":
                    want = d.get("wanted_bytes")
                    if want is not None:
                        bits.append(f"want={want}")
                elif ev == "RST_STREAM":
                    err = d.get("error_code")
                    if err is not None:
                        bits.append(f"err={err}")
                elif ev == "GOAWAY":
                    err = d.get("error_code")
                    last = d.get("last_stream_id")
                    if err is not None:
                        bits.append(f"err={err}")
                    if last is not None:
                        bits.append(f"last={last}")

                what = " ".join(bits)
                dur = "-"
                by = "-"
                flags = "!"

                row = urwid.Columns([
                    ("fixed", self.COL_MARK, urwid.Text(("mark", mark_txt) if marked else mark_txt)),
                    ("fixed", self.COL_TIME, urwid.Text(fmt_ts(rec.ts))),
                    ("fixed", self.COL_LISTENER, urwid.Text(rec.listener[:self.COL_LISTENER])),
                    ("fixed", self.COL_CLIENT, urwid.Text(f"{rec.client_ip}:{rec.client_port}"[:self.COL_CLIENT])),
                    ("fixed", self.COL_PROTO, urwid.Text(proto)),
                    ("fixed", self.COL_CODE, urwid.Text(code[:self.COL_CODE])),
                    urwid.Text(what),
                    ("fixed", self.COL_DURATION, urwid.Text(dur)),
                    ("fixed", self.COL_BYTES, urwid.Text(by)),
                    ("fixed", flags_width, urwid.Text(flags[:flags_width])),
                ], dividechars=self.COL_DIV)

            sel = SelectableRow(row)
            base_attr = "bg"
            if _is_error_record(rec):
                base_attr = "row_error"
            elif _is_warn_record(rec):
                base_attr = "row_warn"
            w = urwid.AttrMap(sel, base_attr, focus_map="focus")
            w._rec = rec
            new_widgets.append(w)

            if self._focused_id and rec.id == self._focused_id:
                focus_index = idx

        self.walker[:] = new_widgets
        if not self.walker:
            return

        if self.follow_tail:
            self.walker.set_focus(len(self.walker) - 1)
        else:
            if focus_index is not None:
                self.walker.set_focus(focus_index)

        # Only in overlay-mode: force visible highlight
        if self.force_highlight:
            try:
                idx = self.walker.get_focus()[1]
                if idx is not None and 0 <= idx < len(self.walker):
                    ww = self.walker[idx]
                    if isinstance(ww, urwid.AttrMap):
                        ww.set_attr_map({None: "focus"})
            except Exception:
                pass


class ConnectionsList(urwid.WidgetWrap):
    """
    Connections view list widget.

    show_mode:
      - active: only currently active connections
      - all: active + closed history
      - closed: only closed history

    Features:
      - cycle_mode() bound to L
      - refresh(flt): rebuild list with optional filtering
      - focus_conn_id(id): focus a row by conn_id (jump from Traffic)
    """
    def __init__(self, manager: ListenerManager):
        self.manager = manager
        self.walker = urwid.SimpleFocusListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        self.visible_conns: List[ConnInfo] = []

        # what to show in Connections view
        self.show_mode: str = "active"

        # header: add mode indicator on the right
        self._hdr_mode = urwid.Text(self._mode_label())

        header = urwid.Columns([
            ("fixed", 6, urwid.Text("Age")),
            ("fixed", 6, urwid.Text("Idle")),
            ("fixed", 16, urwid.Text("Listener")),
            ("fixed", 21, urwid.Text("Client")),
            ("fixed", 24, urwid.Text("Upstream")),     
            ("fixed", 9, urwid.Text("ALPN i/o")),
            ("fixed", 8, urwid.Text("TLS in")),
            ("fixed", 8, urwid.Text("TLS out")),
            ("fixed", 7, urwid.Text("Streams")),
            ("fixed", 4, urwid.Text("Errs")),
            urwid.Text("Last error"),
            ("fixed", 12, self._hdr_mode),                  
        ], dividechars=1)

        self._header = header
        frame = urwid.Frame(self.listbox, header=urwid.AttrMap(header, "header"))
        super().__init__(frame)

    def _mode_label(self) -> str:
        return f"Mode: {self.show_mode}"

    def _update_header_mode(self) -> None:
        # update header right side text
        try:
            self._hdr_mode.set_text(self._mode_label())
        except Exception:
            pass

    def cycle_mode(self) -> str:
        """Cycle display mode: active -> all -> closed -> active."""
        if self.show_mode == "active":
            self.show_mode = "all"
        elif self.show_mode == "all":
            self.show_mode = "closed"
        else:
            self.show_mode = "active"
        self._update_header_mode()
        return self.show_mode

    def focus_conn_id(self, conn_id: str) -> bool:
        if not conn_id or not self.walker:
            return False
        try:
            for idx, w in enumerate(self.walker):
                ci = getattr(w, "_ci", None)
                if ci and getattr(ci, "id", None) == conn_id:
                    self.walker.set_focus(idx)
                    return True
        except Exception:
            return False
        return False

    def focused_conn(self) -> Optional[ConnInfo]:
        if not self.walker:
            return None
        w = self.walker.get_focus()[0]
        return getattr(w, "_ci", None)

    async def refresh(self, flt: FilterSpec) -> None:
        try:
            self._update_header_mode()
        except Exception:
            pass

        if self.show_mode == "active":
            conns = await self.manager.conn_store.snapshot(include_closed=False)
        else:
            conns = await self.manager.conn_store.snapshot(include_closed=True)
            if self.show_mode == "closed":
                conns = [c for c in conns if c.closed_ts is not None]

        conns.sort(key=lambda c: (c.opened_ts, c.closed_ts or 0.0))

        if flt and flt.raw:
            conns = [c for c in conns if flt.matches_conn(c)]

        self.visible_conns = conns

        new_widgets: List[urwid.Widget] = []

        def _conn_is_error(ci: ConnInfo) -> bool:
            if int(getattr(ci, "error_count", 0) or 0) > 0:
                return True
            if ci.last_error:
                return True
            cr = (ci.close_reason or "").lower()
            if any(x in cr for x in ("fail", "error", "timeout", "rst", "protocol")):
                return True
            for f in (ci.close_flags or []):
                ff = (f or "").lower()
                if any(x in ff for x in ("fail", "error", "timeout", "rst", "protocol")):
                    return True
            return False

        for ci in conns:
            age = f"{ci.age_s()}s"
            idle = f"{ci.idle_s()}s"

            upstream = ci.upstream_addr + ("/tls" if ci.upstream_tls else "/plain")
            alpn_in = (ci.alpn_in or "-")[:4]
            alpn_out = (ci.alpn_out or "-")[:4]
            tls_in = (ci.tls_in.version or "-")
            tls_out = (ci.tls_out.version or ("-" if not ci.upstream_tls else "tls"))

            streams = "-"
            if (ci.alpn_in or "").lower() == "h2":
                streams = f"{ci.h2_open_streams}/{ci.h2_total_streams}"

            meta = []
            if ci.proxy_version:
                p = [f"pp={ci.proxy_version}"]
                if ci.proxy_src:
                    p.append(f"src={ci.proxy_src}")
                if ci.proxy_dst:
                    p.append(f"dst={ci.proxy_dst}")
                meta.append(" ".join(p))
            if ci.closed_by or ci.close_reason:
                meta.append(f"{ci.closed_by or '?'}:{ci.close_reason or '?'}")
            if getattr(ci, "close_flags", None):
                meta.append(",".join(ci.close_flags[:3]))
            if ci.last_error:
                meta.append(ci.last_error)

            tail = " | ".join(meta)[:200]
            errs = str(int(getattr(ci, "error_count", 0) or 0))

            row = urwid.Columns([
                ("fixed", 6, urwid.Text(age[:6])),
                ("fixed", 6, urwid.Text(idle[:6])),
                ("fixed", 16, urwid.Text(ci.listener[:16])),
                ("fixed", 21, urwid.Text(f"{ci.client_ip}:{ci.client_port}"[:21])),
                ("fixed", 24, urwid.Text(upstream[:24])),
                ("fixed", 9, urwid.Text(f"{alpn_in}->{alpn_out}"[:9])),
                ("fixed", 8, urwid.Text(tls_in[:8])),
                ("fixed", 8, urwid.Text(tls_out[:8])),
                ("fixed", 7, urwid.Text(streams[:7])),
                ("fixed", 4, urwid.Text(errs[:4])),
                urwid.Text(tail),
            ], dividechars=1)

            sel = SelectableRow(row)
            base_attr = "row_error" if _conn_is_error(ci) else "bg"
            w = urwid.AttrMap(sel, base_attr, focus_map="focus")
            w._ci = ci
            new_widgets.append(w)

        self.walker[:] = new_widgets


class FilterDialog(urwid.WidgetWrap):
    """
    Modal filter input dialog.

    Important:
      - handles Enter/Esc in its own keypress() to avoid modifying MainLoop.unhandled_input
        (prevents global hotkeys from breaking after the dialog closes).
      - UI styling: label uses popup colors, edit field uses popup_details (black on light gray).
    """
    def __init__(self, initial: str, on_apply, on_cancel):
        self._on_apply = on_apply
        self._on_cancel = on_cancel

        # Label is normal popup text (light gray on dark blue)
        label = urwid.Text("Filter:")

        # Edit field only (no caption), styled black on light gray
        self.edit = urwid.Edit(edit_text=initial or "")
        edit_w = urwid.AttrMap(self.edit, "popup_details")

        # Put label + edit on one line
        line = urwid.Columns([
            ("fixed", 8, label),
            edit_w,
        ], dividechars=1)

        hint = urwid.Text("Enter=apply  Esc=cancel  Empty=clear filter")

        pile = urwid.Pile([
            line,
            urwid.Divider(),
            hint,
        ])

        box = urwid.LineBox(urwid.Padding(pile, left=1, right=1), title="Filter")
        super().__init__(urwid.AttrMap(box, "popup"))

    def keypress(self, size, key):
        if key == "enter":
            try:
                self._on_apply(self.edit.edit_text)
            except Exception:
                LOG.debug("FilterDialog apply callback failed", exc_info=True)
            return None
        if key == "esc":
            try:
                self._on_cancel()
            except Exception:
                LOG.debug("FilterDialog cancel callback failed", exc_info=True)
            return None
        return super().keypress(size, key)


class TuiApp:
    """
    Main TUI controller.

    Provides two primary views:
      - Traffic: timeline of requests and connection/TLS events
      - Connections: list of active/all/closed connections

    Manages:
      - global hotkeys (q, tab, m, h, r, f, ...)
      - overlays: help, metrics, details, filter dialog
      - filters (FilterSpec) applied to both views
      - navigation between views by conn_id:
          * T: connection -> traffic (apply conn=<id> filter)
          * K: traffic -> connection (switch to mode=all and focus conn_id)

    Important:
      - overlays must not break MainLoop.unhandled_input; hotkeys should always keep working.
      - opening Details disables tail and may enable force_highlight for a visible cursor under overlay.
    """
    palette = [
        # Far-ish
        ("bg", "light gray", "dark blue"),
        ("row_error", "light red", "dark blue"),
        ("row_warn", "yellow", "dark blue"),
        ("header", "black", "light gray"),
        ("focus", "black", "light cyan"),
        ("footer", "black", "light gray"),
        ("mark", "yellow", "dark blue"),
        ("input", "light gray", "dark blue"),
        ("input_focus", "black", "light cyan"),
        ("popup", "light gray", "dark blue"),
        ("popup_title", "black", "light gray"),
        ("popup_details", "black", "light gray"),
    ]

    def __init__(self, manager: ListenerManager, config_path: str, loop: asyncio.AbstractEventLoop):
        self.manager = manager
        self.config_path = config_path
        self.aio_loop = loop

        self.marked_ids: Set[str] = set()
        self.filter_spec: FilterSpec = FilterSpec()

        self.traffic = TrafficList(manager, is_marked_cb=self.is_marked)
        self.conns = ConnectionsList(manager)

        self.view_mode = "traffic"  # traffic|conns

        self._body_logging_on = any(l.cfg.logging.log_body for l in manager.listeners.values())
        self.hotkeys = urwid.Text("", align="left")
        self._update_hotkeys_hint()
        self.status = urwid.Text("", align="left")

        self.footer_w = urwid.Pile([
            urwid.AttrMap(self.hotkeys, "footer"),
            urwid.AttrMap(self.status, "footer"),
        ])

        self._body_widget = urwid.AttrMap(self.traffic, "bg")
        self.top = urwid.Frame(self._body_widget, footer=self.footer_w)

        self.loop = urwid.MainLoop(
            self.top,
            palette=self.palette,
            event_loop=urwid.AsyncioEventLoop(loop=self.aio_loop),
            unhandled_input=self.on_key
        )

        self._overlay: Optional[urwid.Overlay] = None
        self._details_overlay: Optional[urwid.Overlay] = None

    def set_status(self, msg: str) -> None:
        self.status.set_text(msg)

    def _hotkeys_hint_text(self) -> str:
        banner = " [BODY LOGGING ON - RISK]" if self._body_logging_on else ""
        if self.view_mode == "conns":
            return (
                "Q quit | R reload | Enter conn details | T jump to Traffic for conn | "
                "L cycle mode (active/all/closed) | F filter | M metrics | Tab traffic"
            )
        return (
            "Q quit | R reload | Enter details | P/N prev/next (details) | Space mark | "
            "E export | F filter | M metrics | Tab connections | C clear marks | End follow"
            f"{banner}"
        )

    def _update_hotkeys_hint(self) -> None:
        try:
            self.hotkeys.set_text(self._hotkeys_hint_text())
        except Exception:
            LOG.debug("update hotkeys hint failed", exc_info=True)

    def is_marked(self, rec_id: str) -> bool:
        return rec_id in self.marked_ids

    def toggle_mark_focused(self):
        if self.view_mode != "traffic":
            return
        rec = self.traffic.focused_record()
        if not rec:
            return
        if rec.id in self.marked_ids:
            self.marked_ids.remove(rec.id)
            self.set_status("Unmarked current row.")
        else:
            self.marked_ids.add(rec.id)
            self.set_status("Marked current row.")

    def clear_marks(self):
        self.marked_ids.clear()
        self.set_status("Marks cleared.")

    def switch_view(self):
        self.hide_overlay()
        if self.view_mode == "traffic":
            self.view_mode = "conns"
            self._body_widget = urwid.AttrMap(self.conns, "bg")
            self.top.body = self._body_widget
            self._update_hotkeys_hint()
            self.set_status("Connections view")
        else:
            self.view_mode = "traffic"
            self._body_widget = urwid.AttrMap(self.traffic, "bg")
            self.top.body = self._body_widget
            self._update_hotkeys_hint()
            self.set_status("Traffic view")

    def jump_to_traffic_for_focused_conn(self) -> None:
        ci = self.conns.focused_conn()
        if not ci:
            self.set_status("No focused connection.")
            return

        expr = f"conn={ci.id}"
        self.filter_spec = parse_filter_expr(expr)

        if self.view_mode != "traffic":
            self.switch_view()

        self.set_status(f"Traffic filtered: {expr} (clear with F -> empty)")

    def jump_to_conn_for_focused_record(self) -> None:
        rec = self.traffic.focused_record()
        if not rec:
            self.set_status("No focused row.")
            return

        cid = getattr(rec, "conn_id", None)
        if not cid:
            self.set_status("This row has no conn_id (cannot jump).")
            return

        # switch to Connections view
        if self.view_mode != "conns":
            self.switch_view()

        # IMPORTANT: ensure mode is 'all' so closed short conns are visible
        try:
            if getattr(self.conns, "show_mode", "active") != "all":
                self.conns.show_mode = "all"
                # update header label if method exists
                try:
                    self.conns._update_header_mode()
                except Exception:
                    pass
        except Exception:
            pass

        async def _do():
            try:
                await self.conns.refresh(self.filter_spec)
            except Exception:
                pass

            ok = self.conns.focus_conn_id(cid)
            if ok:
                self.set_status(f"Focused connection: {cid} (mode=all)")
            else:
                self.set_status(f"Connection not visible (filtered out?): {cid}")

        self.aio_loop.create_task(_do())

    def on_key(self, key):
        if key in ("q", "Q"):
            raise urwid.ExitMainLoop()

        # --- Tail handling (Traffic view) ---
        # Enter tail mode
        if self.view_mode == "traffic" and key in ("end", "G", "g"):
            try:
                self.traffic.follow_tail = True
                if len(self.traffic.walker) > 0:
                    self.traffic.set_focus_index(len(self.traffic.walker) - 1)
                self.set_status("Tail: ON (exit with Up/Home/PgUp/PgDn)")
            except Exception:
                pass
            return

        # Exit tail mode on navigation keys (but DO NOT swallow the key,
        # so ListBox can still scroll/focus normally)
        if self.view_mode == "traffic" and key in ("up", "home", "page up", "page down"):
            try:
                if getattr(self.traffic, "follow_tail", False):
                    self.traffic.follow_tail = False
                    self.set_status("Tail: OFF")
            except Exception:
                pass
            # no return here on purpose!

        if key in ("c", "C", "с"):
            self.clear_marks()
            return

        # L cycles: Active -> All -> Closed
        if self.view_mode == "conns" and key in ("l", "L", "д"):
            mode = self.conns.cycle_mode()
            self._update_hotkeys_hint()
            self.set_status(f"Connections mode: {mode} (L to cycle)")
            # Просто обновляем список, без reload конфигурации
            self.aio_loop.create_task(self.conns.refresh(self.filter_spec))
            return

        if key in ("tab", "Tab"):
            self.switch_view()
            return

        if key in ("m", "M", "ь"):
            self.show_metrics()
            return

        if key in ("h", "H", "f1", "F1"):
            self.show_help()
            return

        if key in ("esc",):
            self.hide_overlay()
            return

        # Details navigation (when Details open)
        if getattr(self, "_overlay_kind", None) == "details":
            if key in ("n", "N", "т"):
                try:
                    if hasattr(self.traffic, "move_focus"):
                        self.traffic.move_focus(1)
                    else:
                        # fallback: move focus via walker directly
                        w = getattr(self.traffic, "walker", None)
                        if w:
                            cur = w.get_focus()[1]
                            if cur is not None:
                                w.set_focus(min(len(w) - 1, cur + 1))
                except Exception:
                    pass
                self.show_details()
                return

            if key in ("p", "P", "з"):
                try:
                    if hasattr(self.traffic, "move_focus"):
                        self.traffic.move_focus(-1)
                    else:
                        w = getattr(self.traffic, "walker", None)
                        if w:
                            cur = w.get_focus()[1]
                            if cur is not None:
                                w.set_focus(max(0, cur - 1))
                except Exception:
                    pass
                self.show_details()
                return

        if key in ("t", "T", "е"):
            if self.view_mode == "conns":
                self.jump_to_traffic_for_focused_conn()
            return

        if key in ("k", "K", "л"):
            if self.view_mode == "traffic":
                self.jump_to_conn_for_focused_record()
            return

        if key in ("enter",):
            if self.view_mode == "traffic":
                self.show_details()
            else:
                self.show_conn_details()
            return

        if key in ("r", "R", "к"):
            self.aio_loop.create_task(self._reload())
            return

        if key in ("e", "E", "у"):
            self.aio_loop.create_task(self.export_selected())
            return

        if key in (" ",):
            self.toggle_mark_focused()
            return

        if key in ("f", "F", "а"):
            self.show_filter_dialog()
            return

    def show_help(self):
        txt = urwid.Text(
            "wiretracer\n\n"
            "Views:\n"
            "  Tab       switch Traffic <-> Connections\n\n"
            "Global:\n"
            "  Q         quit\n"
            "  R         reload config (clears history)\n"
            "  H / F1    help\n"
            "  M         metrics\n"
            "  F         filter dialog\n\n"
            "Traffic keys:\n"
            "  Enter     details for selected row (scrollable)\n"
            "  P / N     in details: prev/next row (respects filters)\n"
            "  Space     mark/unmark selected row\n"
            "  C         clear all marks\n"
            "  E         export: marked if any, else current row\n"
            "  End/G     follow tail\n"
            "  Up/Down   stop following tail\n"
            "  K         jump to Connection for selected row (needs conn_id)\n\n"
            "Connections keys:\n"
            "  Enter     details for selected connection\n"
            "  T         show Traffic only for this connection (sets filter: conn=<id>)\n\n"
            "Filter tokens (space-separated):\n"
            "  listener=<name>\n"
            "  proto=grpc|http2|http1|tls|conn|h2ctl\n"
            "  proto^=http\n"
            "  proto in (http*,grpc)\n"
            "  status=200\n"
            "  client=192.168.\n"
            "  proxy=v1|v2|none\n"
            "  proxy_src=203.0.113.10:54321\n"
            "  method=POST\n"
            "  path=/health\n"
            "  path~^/helloworld\\.Greeter/\n"
            "  conn=<uuid>          (drilldown by connection)\n"
            "  error=1\n\n"
            "Notes:\n"
            "  - h2ctl rows are optional (only if proxy emits HTTP/2 control events).\n"
        )
        self._overlay_message("Help", urwid.Filler(txt, valign="top"))

    def show_filter_dialog(self):
        # text of current filter as default
        initial = ""
        try:
            initial = getattr(self.filter_spec, "raw", "") or ""
        except Exception:
            initial = ""

        def _apply(text: str):
            text = (text or "").strip()
            try:
                self.filter_spec = parse_filter_expr(text)
            except Exception as e:
                self.set_status(f"Bad filter: {e}")
                # keep dialog open
                return

            if not text:
                self.set_status("Filter cleared.")
            else:
                self.set_status(f"Filter: {text}")

            # refresh current view after applying
            try:
                if self.view_mode == "traffic":
                    self.aio_loop.create_task(self.traffic.refresh(self.filter_spec))
                else:
                    self.aio_loop.create_task(self.conns.refresh(self.filter_spec))
            except Exception:
                pass

            self.hide_overlay()

        def _cancel():
            self.set_status("Filter cancelled.")
            self.hide_overlay()

        dlg = FilterDialog(initial=initial, on_apply=_apply, on_cancel=_cancel)

        self._overlay_kind = "filter"
        self._overlay = urwid.Overlay(
            dlg,
            self.top,
            align="center",
            width=("relative", 70),
            valign="middle",
            height=7,
            min_width=40,
            min_height=7,
        )
        self.loop.widget = self._overlay

        # put cursor inside input immediately
        try:
            self.loop.draw_screen()
        except Exception:
            pass

    def show_metrics(self):
        async def _build():
            g, by = await self.manager.metrics.snapshot()

            lines: List[str] = []
            lines.append("GLOBAL:")
            for k in sorted(g.keys()):
                lines.append(f"  {k}: {g[k]}")
            lines.append("")
            for lname in sorted(by.keys()):
                lines.append(f"{lname}:")
                d = by[lname]
                for k in sorted(d.keys()):
                    lines.append(f"  {k}: {d[k]}")
                lines.append("")

            txt = urwid.Text("\n".join(lines))
            self._overlay_message("Metrics", urwid.Filler(txt, valign="top"))

        self.aio_loop.create_task(_build())

    def hide_overlay(self):
        if getattr(self, "_overlay", None) is not None:
            self.loop.widget = self.top
            self._overlay = None

        # reset overlay state
        self._overlay_kind = None
        self._details_title = None
        self._details_body = None

        # Details-mode: back to normal focus painting
        try:
            self.traffic.force_highlight = False
        except Exception:
            pass

        # SAFETY: some dialogs may accidentally break unhandled_input.
        # Ensure our on_key is still active.
        try:
            if getattr(self.loop, "unhandled_input", None) is not self.on_key:
                self.loop.unhandled_input = self.on_key
        except Exception:
            pass

    def _overlay_message(self, title: str, body: urwid.Widget):
        header = urwid.AttrMap(urwid.Text(f" {title} "), "popup_title")
        frame = urwid.Frame(body=body, header=header)
        box = urwid.LineBox(frame)
        overlay = urwid.Overlay(
            urwid.AttrMap(box, "popup"),
            self.top,
            align="center", width=("relative", 92),
            valign="middle", height=("relative", 88)
        )
        self.loop.widget = overlay
        self._overlay = overlay
        self.loop.unhandled_input = self.on_key

    # ---- details rendering ----
    def _render_body(self, raw: bytes, truncated: bool) -> List[str]:
        out: List[str] = []
        try:
            s = raw.decode("utf-8")
            out.append("  (utf-8)")
            for line in s.splitlines():
                out.append("  " + line[:900])
        except Exception:
            out.append("  (hexdump+ascii)")
            out.extend(hexdump_ascii(raw))
            strs = extract_printable_strings(raw)
            if strs:
                out.append("  strings:")
                for s in strs:
                    out.append(f"    {s}")
        if truncated:
            out.append("  [TRUNCATED]")
        return out

    def _render_grpc_body(self, raw: bytes, truncated: bool) -> List[str]:
        out: List[str] = []
        out.append("  (gRPC frames)")
        frames = parse_grpc_frames(raw)
        if not frames:
            out.append("  (no frames)")
            out.append("  (hexdump+ascii)")
            out.extend(hexdump_ascii(raw))
            if truncated:
                out.append("  [TRUNCATED]")
            return out

        for fr in frames:
            status = "complete" if fr.complete else "incomplete"
            note = f" ({fr.note})" if fr.note else ""
            out.append(f"  frame[{fr.index}]: flag={fr.compressed_flag} len={fr.msg_len} payload={len(fr.payload)} {status}{note}")
            out.append("  payload hexdump+ascii:")
            out.extend(hexdump_ascii(fr.payload))
            strs = extract_printable_strings(fr.payload)
            if strs:
                out.append("  payload strings:")
                for s in strs:
                    out.append(f"    {s}")
            out.append("")
        if truncated:
            out.append("  [TRUNCATED]")
        return out

    def _build_details_lines(self, rec: Any) -> Tuple[str, List[str]]:
        lines: List[str] = []

        # ---- Event (http1/http2/grpc) ----
        if isinstance(rec, Event):
            title = f"{rec.protocol} {rec.request.method or '-'} {rec.request.path or '-'}"

            lines.append(f"Conn: {getattr(rec, 'conn_id', None) or '-'}")
            lines.append(f"Listener: {rec.listener}")
            lines.append(f"Client: {rec.client_ip}:{rec.client_port}")
            lines.append(f"Upstream: {rec.upstream_addr}")
            lines.append(f"Time: {fmt_ts(rec.ts_start)} .. {fmt_ts(rec.ts_end)}")
            lines.append(f"Duration: {rec.duration_ms}ms")
            lines.append(f"Bytes: in={rec.bytes_in} out={rec.bytes_out}")
            if rec.flags:
                lines.append(f"Flags: {', '.join(rec.flags)}")
            if rec.error:
                lines.append(f"Error: {rec.error}")

            if rec.tls:
                t = rec.tls
                tls_bits = []
                if t.version: tls_bits.append(t.version)
                if t.alpn: tls_bits.append(t.alpn)
                if t.sni: tls_bits.append(f"sni={t.sni}")
                if t.cipher: tls_bits.append(t.cipher)
                if tls_bits:
                    lines.append(f"TLS(in): {' '.join(tls_bits)}")

            lines.append("")
            lines.append("Request:")
            lines.append(f"  Method: {rec.request.method or '-'}")
            lines.append(f"  Path:   {rec.request.path or '-'}")
            if rec.request.authority:
                lines.append(f"  Host:   {rec.request.authority}")
            if rec.request.grpc_service and rec.request.grpc_method:
                lines.append(f"  gRPC:   /{rec.request.grpc_service}/{rec.request.grpc_method}")

            if rec.request.headers:
                lines.append("  Headers:")
                for k, v in rec.request.headers.items():
                    lines.append(f"    {k}: {v}")

            lines.append("")
            lines.append("Response:")
            lines.append(f"  Status: {rec.response.status if rec.response else '-'}")
            if rec.response and rec.response.headers:
                lines.append("  Headers:")
                for k, v in rec.response.headers.items():
                    lines.append(f"    {k}: {v}")

            return title, lines

        # ---- TLS handshake ----
        if isinstance(rec, TlsHandshakeRecord):
            title = f"tls {rec.outcome} {rec.side}"

            lines.append(f"Conn: {getattr(rec, 'conn_id', None) or '-'}")
            lines.append(f"Listener: {rec.listener}")
            lines.append(f"Client: {rec.client_ip}:{rec.client_port}")
            lines.append(f"Time: {fmt_ts(rec.ts)}")

            side = rec.side or "-"
            peer = "downstream(client)" if side == "in" else "upstream(server)" if side == "out" else "-"
            lines.append(f"Side: {side} ({peer})")
            lines.append(f"Outcome: {rec.outcome}")

            if rec.reason:
                lines.append(f"Reason: {rec.reason}")

            # show category/detail
            cat = getattr(rec, "category", None)
            det = getattr(rec, "detail", None)
            if cat:
                lines.append(f"Category: {cat}")
            if det:
                lines.append(f"Detail:   {det}")

            t = rec.tls or TlsInfo()
            lines.append(f"TLS Version: {t.version or '-'}")
            lines.append(f"ALPN:        {t.alpn or '-'}")
            lines.append(f"Cipher:      {t.cipher or '-'}")

            if side == "in":
                lines.append(f"Client SNI:  {t.sni or '-'}")
            elif side == "out":
                lines.append(f"SNI target:  {t.sni or '-'}")
            else:
                lines.append(f"SNI:         {t.sni or '-'}")

            if rec.upstream:
                up_addr = rec.upstream.get("addr")
                if up_addr:
                    lines.append(f"Upstream:    {up_addr}")
                if side == "out":
                    if "server_name" in rec.upstream and rec.upstream.get("server_name"):
                        lines.append(f"ServerName:  {rec.upstream.get('server_name')}")
                    if "verify" in rec.upstream:
                        lines.append(f"Verify:      {rec.upstream.get('verify')}")
                    if "mtls" in rec.upstream:
                        lines.append(f"mTLS:        {rec.upstream.get('mtls')}")

            return title, lines

        # ---- Connection lifecycle ----
        if isinstance(rec, ConnLifecycleRecord):
            title = f"conn {rec.event}"
            lines.append(f"Conn: {getattr(rec, 'conn_id', None) or '-'}")
            lines.append(f"Listener: {rec.listener}")
            lines.append(f"Client: {rec.client_ip}:{rec.client_port}")
            lines.append(f"PROXY(in): {rec.proxy_version or 'none'}")
            if rec.proxy_src:
                lines.append(f"PROXY src: {rec.proxy_src}")
            if rec.proxy_dst:
                lines.append(f"PROXY dst: {rec.proxy_dst}")
            lines.append(f"Upstream: {rec.upstream_addr}")
            lines.append(f"Time: {fmt_ts(rec.ts)}")
            lines.append(f"Event: {rec.event}")
            if rec.closed_by:
                lines.append(f"Closed-by: {rec.closed_by}")
            if rec.close_reason:
                lines.append(f"Reason: {rec.close_reason}")
            if rec.duration_ms is not None:
                lines.append(f"Duration: {rec.duration_ms}ms")
            if rec.flags:
                lines.append(f"Flags: {', '.join(rec.flags)}")
            return title, lines

        # ---- H2 control ----
        if isinstance(rec, H2ControlRecord):
            title = f"h2ctl {rec.h2_event}"
            lines.append(f"Conn: {getattr(rec, 'conn_id', None) or '-'}")
            lines.append(f"Listener: {rec.listener}")
            lines.append(f"Client: {rec.client_ip}:{rec.client_port}")
            lines.append(f"Time: {fmt_ts(rec.ts)}")
            lines.append(f"Direction: {rec.direction}")
            lines.append(f"Event: {rec.h2_event}")
            if rec.stream_id is not None:
                lines.append(f"Stream: {rec.stream_id}")
            if rec.details:
                lines.append("Details:")
                for k, v in rec.details.items():
                    lines.append(f"  {k}: {v}")
            return title, lines

        title = rec.__class__.__name__
        lines.append(repr(rec))
        return title, lines

    def _details_prev_next(self, delta: int) -> None:
        idx = self.traffic.focus_index()
        if idx is None:
            return
        new_idx = idx + delta
        if new_idx < 0 or new_idx >= len(self.traffic.walker):
            return
        self.traffic.set_focus_index(new_idx)
        rec = self.traffic.focused_record()
        if rec:
            self._set_details_content(rec)
            self.set_status(f"Details: {'prev' if delta < 0 else 'next'}")

    def _set_details_content(self, rec: Record) -> None:
        if not self._details_overlay:
            return
        title, lines = self._build_details_lines(rec)
        walker = urwid.SimpleListWalker([urwid.Text(line) for line in lines])
        lb = urwid.ListBox(walker)
        box = urwid.LineBox(lb, title=title)
        self._details_overlay.top_w = urwid.AttrMap(box, "popup_details")

    def show_details(self):
        # entering details disables tail and enables forced highlight
        try:
            if self.view_mode == "traffic":
                if getattr(self.traffic, "follow_tail", False):
                    self.traffic.follow_tail = False
                    self.set_status("Tail: OFF (Details opened)")
                # show cursor on the underlying list even though overlay has focus
                self.traffic.force_highlight = True
        except Exception:
            pass

        rec = self.traffic.focused_record()
        if not rec:
            self.set_status("No record selected.")
            return

        title, lines = self._build_details_lines(rec)

        if getattr(self, "_overlay_kind", None) == "details" and getattr(self, "_details_body", None) is not None:
            try:
                if getattr(self, "_details_title", None) is not None:
                    self._details_title.set_text(title)
                self._details_body.set_text("\n".join(lines))
                return
            except Exception:
                pass

        self._details_title = urwid.Text(title)
        self._details_body = urwid.Text("\n".join(lines))

        body = urwid.ListBox(urwid.SimpleFocusListWalker([self._details_body]))
        frame = urwid.Frame(body=body, header=urwid.AttrMap(self._details_title, "header"))
        box = urwid.LineBox(frame, title="Details (N/P to navigate)")

        self._overlay_kind = "details"

        self._overlay = urwid.Overlay(
            urwid.AttrMap(box, "popup"),
            self.top,
            align="center",
            width=("relative", 90),
            valign="middle",
            height=("relative", 90),
            min_width=40,
            min_height=10,
        )
        self.loop.widget = self._overlay

    def show_conn_details(self):
        ci = self.conns.focused_conn()
        if not ci:
            return

        lines: List[str] = []
        lines.append(f"Connection {ci.id}")
        lines.append(f"Listener: {ci.listener}")
        lines.append(f"Client: {ci.client_ip}:{ci.client_port}")
        lines.append(f"PROXY(in): {ci.proxy_version or 'none'}")
        if ci.proxy_src:
            lines.append(f"PROXY src: {ci.proxy_src}")
        if ci.proxy_dst:
            lines.append(f"PROXY dst: {ci.proxy_dst}")
        lines.append(f"Upstream: {ci.upstream_addr}  ({'TLS' if ci.upstream_tls else 'PLAIN'})")
        lines.append(f"Opened: {fmt_full(ci.opened_ts)}  Age: {ci.age_s()}s")
        lines.append(f"Last activity: {fmt_full(ci.last_activity_ts)}  Idle: {ci.idle_s()}s")
        lines.append("")
        lines.append("TLS IN (client -> proxy):")
        lines.append(f"  ALPN: {ci.alpn_in}")
        lines.append(f"  Version: {ci.tls_in.version}")
        lines.append(f"  Cipher: {ci.tls_in.cipher}")
        lines.append(f"  SNI(in): {ci.tls_in.sni}")
        lines.append("")
        lines.append("TLS OUT (proxy -> upstream):")
        lines.append(f"  SNI(out): {ci.sni_out}")
        lines.append(f"  ALPN(out): {ci.alpn_out}")
        lines.append(f"  Version(out): {ci.tls_out.version}")
        lines.append(f"  Cipher(out): {ci.tls_out.cipher}")
        lines.append("")
        if (ci.alpn_in or "").lower() == "h2":
            lines.append(f"HTTP/2 streams: open={ci.h2_open_streams} total={ci.h2_total_streams}")
        else:
            lines.append("HTTP/2 streams: n/a (not h2)")
        if ci.last_error:
            lines.append("")
            lines.append(f"Last error: {ci.last_error}")

        walker = urwid.SimpleListWalker([urwid.Text(line) for line in lines])
        lb = urwid.ListBox(walker)
        box = urwid.LineBox(lb, title="Connection")

        overlay = urwid.Overlay(
            urwid.AttrMap(box, "popup_details"),
            self.top,
            align="center", width=("relative", 92),
            valign="middle", height=("relative", 70)
        )
        self.loop.widget = overlay
        self._overlay = overlay

        def conn_keys(key):
            if key == "esc":
                self.hide_overlay()
                return
            return None

        self.loop.unhandled_input = conn_keys

    async def _reload(self):
        self.set_status("Reloading config...")
        try:
            await self.manager.reload(self.config_path)
            self.set_status("Reloaded.")
        except Exception as e:
            self.set_status(f"Reload failed: {e}")

    async def export_selected(self):
        ts = time.strftime("%Y%m%d-%H%M%S")
        path = f"wiretracer-{ts}.jsonl"
        count = 0

        records = await self.manager.store.snapshot(limit=50_000)
        by_id: Dict[str, Record] = {}
        for r in records:
            by_id[getattr(r, "id")] = r

        try:
            with open(path, "w", encoding="utf-8") as f:
                if self.marked_ids:
                    for rid in list(self.marked_ids):
                        r = by_id.get(rid)
                        if r:
                            f.write(json.dumps(r.to_json(), ensure_ascii=False) + "\n")
                            count += 1
                    self.set_status(f"Exported {count} MARKED rows to {path}")
                else:
                    r = self.traffic.focused_record()
                    if not r:
                        self.set_status("Export: no selected row.")
                        return
                    f.write(json.dumps(r.to_json(), ensure_ascii=False) + "\n")
                    self.set_status(f"Exported 1 CURRENT row to {path}")
        except Exception as e:
            self.set_status(f"Export failed: {e}")

    async def _tick(self):
        try:
            await self.traffic.refresh(self.filter_spec)
            await self.conns.refresh(self.filter_spec)
        except Exception:
            log_throttled(
                logging.DEBUG,
                key="tui_tick_refresh_failed",
                msg="TUI refresh tick failed",
                interval_s=5.0,
                exc_info=True,
            )
        self.loop.set_alarm_in(0.5, lambda loop, data: self.aio_loop.create_task(self._tick()))

    def run(self):
        # периодический refresh
        self._tick_task = self.aio_loop.create_task(self._tick())

        try:
            self.loop.run()
        finally:
            # 1) остановить тикер
            try:
                if getattr(self, "_tick_task", None):
                    self._tick_task.cancel()
            except Exception:
                pass

            # 2) остановить серверы/листенеры и закрыть store
            try:
                self.aio_loop.run_until_complete(self.manager.stop_all())
            except Exception:
                LOG.error("manager.stop_all failed during TUI shutdown", exc_info=True)

            # 3) отменить всё, что ещё осталось в loop (иначе pending tasks warnings)
            try:
                pending = asyncio.all_tasks(loop=self.aio_loop)
            except TypeError:
                # python 3.11+ all_tasks() без loop параметра
                pending = asyncio.all_tasks()

            # убрать текущую (если run вызывается из task — на всякий)
            cur = None
            try:
                cur = asyncio.current_task(loop=self.aio_loop)
            except Exception:
                try:
                    cur = asyncio.current_task()
                except Exception:
                    cur = None
            if cur is not None and cur in pending:
                pending.remove(cur)

            for t in pending:
                t.cancel()

            if pending:
                try:
                    self.aio_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass


# CLI / Modes
async def run_headless(config_path: str):
    cfg = load_config(config_path)
    manager = ListenerManager(cfg)
    await manager.start_all()

    stop_ev = asyncio.Event()

    def _sig(*_):
        stop_ev.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _sig)
        except NotImplementedError:
            pass

    await stop_ev.wait()
    await manager.stop_all()


def run_tui_sync(config_path: str, log_path: Optional[str] = None):
    import sys
    import os
    import traceback

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 1) Redirect stderr to a file while TUI is running (prevents screen corruption)
    # Place it next to the main log file (or in CWD by default).
    try:
        if log_path:
            log_dir = os.path.dirname(os.path.abspath(log_path)) or os.getcwd()
        else:
            log_dir = os.getcwd()
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        log_dir = os.getcwd()
    err_path = os.path.join(log_dir, "tui-stderr.log")
    old_stderr = sys.stderr
    sys.stderr = open(err_path, "a", encoding="utf-8")

    # 2) asyncio exception handler -> file (also prevents stderr spam)
    def _loop_exc_handler(_loop, context):
        try:
            msg = context.get("message", "asyncio exception")
            exc = context.get("exception")
            sys.stderr.write("\n[asyncio] " + msg + "\n")
            if exc:
                traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
            else:
                sys.stderr.write(repr(context) + "\n")
            sys.stderr.flush()
        except Exception:
            pass

    loop.set_exception_handler(_loop_exc_handler)

    cfg = load_config(config_path)
    manager = ListenerManager(cfg)
    loop.run_until_complete(manager.start_all())

    app = TuiApp(manager, config_path, loop=loop)
    try:
        app.run()
    finally:
        try:
            loop.close()
        finally:
            try:
                sys.stderr.close()
            except Exception:
                pass
            sys.stderr = old_stderr


def cmd_check(config_path: str) -> int:
    try:
        _ = load_config(config_path)
        print("OK")
        return 0
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2


def main():
    # Defaults are local to the current working directory.
    # Users can override with --config/--log.
    default_config = os.path.join(os.getcwd(), "config.yaml")
    default_log = os.path.join(os.getcwd(), "wiretracer.log")

    p = argparse.ArgumentParser(
        prog="wiretracer",
        description=(
            "TLS-terminating controlled MITM proxy for HTTP/2 + gRPC with TUI.\n"
            "Traffic includes TLS handshake events and HTTP/2 control events.\n\n"
            "Default mode: TUI.\n"
            "Use --headless to run without UI (daemon/service style).\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--config", default=default_config,
                   help=f"Path to config YAML (default: {default_config})")
    p.add_argument("--log", default=default_log,
                   help=f"Path to log file (default: {default_log})")
    p.add_argument("--log-level", default="INFO",
                   help="Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)")

    g = p.add_mutually_exclusive_group()
    g.add_argument("--headless", action="store_true", help="Run headless (no TUI).")
    g.add_argument("--check", action="store_true", help="Validate config and exit.")
    g.add_argument("--dump-example-config", action="store_true", help="Print example config and exit.")

    args = p.parse_args()

    # Initialize logging as early as possible so we don't lose diagnostics.
    try:
        setup_logging(args.log, args.log_level)
    except Exception as e:
        # Best-effort: keep running even if logging cannot be initialized.
        try:
            sys.stderr.write(f"[wiretracer] setup_logging failed: {e!r}\n")
            sys.stderr.flush()
        except Exception:
            pass

    if args.dump_example_config:
        print(dump_example_config())
        return

    if args.check:
        raise SystemExit(cmd_check(args.config))

    if args.headless:
        asyncio.run(run_headless(args.config))
        return

    # DEFAULT: TUI
    run_tui_sync(args.config, log_path=args.log)


if __name__ == "__main__":
    main()
