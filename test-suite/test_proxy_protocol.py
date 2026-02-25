#!/usr/bin/env python3
import asyncio
import importlib.util
import pathlib
import socket
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "wiretracer.py"


class _UrwidWidgetWrap:
    def __init__(self, *args, **kwargs):
        pass


class _UrwidModule(types.ModuleType):
    WidgetWrap = _UrwidWidgetWrap
    Widget = object
    ExitMainLoop = Exception

    def __getattr__(self, _name):
        def _dummy(*_args, **_kwargs):
            return object()

        return _dummy


if "urwid" not in sys.modules:
    try:
        import urwid  # type: ignore  # noqa: F401
    except Exception:
        sys.modules["urwid"] = _UrwidModule("urwid")


if "yaml" not in sys.modules:
    try:
        import yaml  # type: ignore  # noqa: F401
    except Exception:
        yaml_stub = types.ModuleType("yaml")
        yaml_stub.safe_load = lambda *_args, **_kwargs: {}
        yaml_stub.safe_dump = lambda *_args, **_kwargs: ""
        sys.modules["yaml"] = yaml_stub


try:
    import h2  # type: ignore  # noqa: F401
except Exception:
    h2_mod = types.ModuleType("h2")
    h2_config = types.ModuleType("h2.config")
    h2_conn = types.ModuleType("h2.connection")
    h2_events = types.ModuleType("h2.events")
    h2_exc = types.ModuleType("h2.exceptions")

    class _Dummy:
        pass

    h2_config.H2Configuration = _Dummy
    h2_conn.H2Connection = _Dummy
    h2_events.RequestReceived = _Dummy
    h2_events.ResponseReceived = _Dummy
    h2_events.DataReceived = _Dummy
    h2_events.StreamEnded = _Dummy
    h2_events.StreamReset = _Dummy
    h2_events.TrailersReceived = _Dummy
    h2_events.RemoteSettingsChanged = _Dummy
    h2_events.SettingsAcknowledged = _Dummy
    h2_events.WindowUpdated = _Dummy
    h2_events.ConnectionTerminated = _Dummy
    h2_exc.ProtocolError = Exception
    h2_exc.FlowControlError = Exception

    sys.modules["h2"] = h2_mod
    sys.modules["h2.config"] = h2_config
    sys.modules["h2.connection"] = h2_conn
    sys.modules["h2.events"] = h2_events
    sys.modules["h2.exceptions"] = h2_exc

SPEC = importlib.util.spec_from_file_location("packet_monitor_proxy", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load module from {MODULE_PATH}")
PMP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PMP
SPEC.loader.exec_module(PMP)


def build_proxy_v2_ipv4_header(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    payload = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + int(src_port).to_bytes(2, "big")
        + int(dst_port).to_bytes(2, "big")
    )
    return (
        PMP.PROXY_V2_SIGNATURE
        + bytes([0x21, 0x11])  # version=2, command=PROXY, family=INET, proto=STREAM
        + len(payload).to_bytes(2, "big")
        + payload
    )


class _DummyMetrics:
    async def inc(self, *_args, **_kwargs):
        return None


class _DummyStore:
    async def add(self, *_args, **_kwargs):
        return None


class _DummyRuntime:
    def __init__(self, upstream_addr: str):
        self.cfg = type(
            "Cfg",
            (),
            {
                "name": "test-listener",
                "upstream": PMP.UpstreamConfig(addr=upstream_addr, tls=False),
                "policy": PMP.PolicyConfig(upstream_connect_timeout=2.0, upstream_handshake_timeout=2.0),
            },
        )()
        self.metrics = _DummyMetrics()
        self.store = _DummyStore()
        self.conn_store = PMP.ConnectionStore()
        self._policy = PMP.SecurityPolicy([], [])


def _make_reader(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


class TestProxyProtocolDetect(unittest.IsolatedAsyncioTestCase):
    async def test_detect_none_keeps_payload(self):
        payload = b"POST /x HTTP/1.1\r\nHost: example\r\n\r\nabc"
        r = _make_reader(payload)
        h = await PMP.detect_proxy_protocol_header(r, timeout_s=0.2)
        self.assertFalse(h.present)
        self.assertIsNone(h.version)
        self.assertEqual(await r.read(), payload)

    async def test_detect_v1_and_consume_header_only(self):
        hdr = b"PROXY TCP4 203.0.113.10 192.0.2.10 54321 443\r\n"
        payload = b"\x16\x03\x01test-clienthello"
        r = _make_reader(hdr + payload)

        h = await PMP.detect_proxy_protocol_header(r, timeout_s=0.2)
        self.assertTrue(h.present)
        self.assertEqual(h.version, 1)
        self.assertEqual(h.source_ip, "203.0.113.10")
        self.assertEqual(h.source_port, 54321)
        self.assertEqual(h.dest_ip, "192.0.2.10")
        self.assertEqual(h.dest_port, 443)
        self.assertEqual(h.raw, hdr)
        self.assertEqual(await r.read(), payload)

    async def test_detect_v2_and_consume_header_only(self):
        hdr = build_proxy_v2_ipv4_header("198.51.100.20", "192.0.2.15", 42424, 8443)
        payload = b"\x16\x03\x01hello"
        r = _make_reader(hdr + payload)

        h = await PMP.detect_proxy_protocol_header(r, timeout_s=0.2)
        self.assertTrue(h.present)
        self.assertEqual(h.version, 2)
        self.assertEqual(h.source_ip, "198.51.100.20")
        self.assertEqual(h.source_port, 42424)
        self.assertEqual(h.dest_ip, "192.0.2.15")
        self.assertEqual(h.dest_port, 8443)
        self.assertEqual(h.raw, hdr)
        self.assertEqual(await r.read(), payload)

    async def test_detect_malformed_v1_raises(self):
        bad = b"PROXY TCP4 203.0.113.10 192.0.2.10 BAD 443\r\npayload"
        r = _make_reader(bad)
        with self.assertRaises(ValueError):
            await PMP.detect_proxy_protocol_header(r, timeout_s=0.2)


class TestProxyProtocolForward(unittest.IsolatedAsyncioTestCase):
    async def _assert_forward(self, hdr: bytes):
        got = bytearray()
        got_evt = asyncio.Event()

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                got.extend(await reader.readexactly(len(hdr)))
                got_evt.set()
            finally:
                writer.close()
                await writer.wait_closed()

        srv = await asyncio.start_server(handle, host="127.0.0.1", port=0)
        try:
            addr = srv.sockets[0].getsockname()
            runtime = _DummyRuntime(f"{addr[0]}:{addr[1]}")
            conn = PMP.ProxyConnection(
                runtime,
                "cid",
                "127.0.0.1",
                50000,
                asyncio.StreamReader(),
                None,  # not used by _open_upstream in this test
                proxy_header=PMP.ProxyProtocolHeader(present=True, version=(1 if hdr.startswith(b"PROXY ") else 2), raw=hdr),
            )
            _r, w, _sni, _tls, _alpn = await conn._open_upstream()
            w.close()
            await w.wait_closed()
            await asyncio.wait_for(got_evt.wait(), timeout=2.0)
            self.assertEqual(bytes(got), hdr)
        finally:
            srv.close()
            await srv.wait_closed()

    async def test_forward_v1_header_to_upstream(self):
        hdr = b"PROXY TCP4 203.0.113.1 192.0.2.1 40000 443\r\n"
        await self._assert_forward(hdr)

    async def test_forward_v2_header_to_upstream(self):
        hdr = build_proxy_v2_ipv4_header("198.51.100.1", "192.0.2.1", 40001, 443)
        await self._assert_forward(hdr)


if __name__ == "__main__":
    unittest.main()
