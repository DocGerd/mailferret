"""T-07: STARTTLS rules and TLS verification, against the fake server."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import traceback
from collections.abc import Iterator
from typing import Any

import pytest

from mailferret.imap import ConnectError, TlsMode
from mailferret.imap import connect as _connect
from mailferret.imap.probe import NoProbe as _NoProbe
from mailferret.imap.probe import bytes_pending as _bytes_pending
from mailferret.imap.probe import client_buffer as _client_buffer
from mailferret.limits import Limits
from tests.support.imap_fake import FakeImapServer, Stall, TlsMaterial

HOST = "127.0.0.1"


def connect(*args: Any, limits: Limits | None = None, **kwargs: Any) -> Any:
    return _connect(*args, limits=limits or Limits(), **kwargs)


def _verbs(server: FakeImapServer) -> list[str]:
    return [cmd.verb for cmd in server.commands]


def _no_credentials(server: FakeImapServer) -> None:
    assert not any(c.verb in {"LOGIN", "AUTHENTICATE"} for c in server.commands)


@pytest.fixture
def implicit_server(tls_material: TlsMaterial) -> Iterator[FakeImapServer]:
    with FakeImapServer(tls=tls_material, implicit_tls=True) as server:
        yield server


def test_starttls_success_rereads_capabilities(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    conn = connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    try:
        assert _verbs(fake_imap_tls) == ["CAPABILITY", "STARTTLS", "CAPABILITY"]
        assert not conn.capabilities.starttls
        assert "IMAP4REV1" in conn.capabilities.raw
    finally:
        conn.close()
    _no_credentials(fake_imap_tls)


def test_starttls_not_advertised_is_a_hard_error(
    tls_material: TlsMaterial,
) -> None:
    with FakeImapServer(tls=tls_material, advertise_starttls=False) as server:
        with pytest.raises(ConnectError) as err:
            connect(HOST, server.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
        assert err.value.code == "starttls_unavailable"
        assert "STARTTLS" not in _verbs(server)
        _no_credentials(server)


def test_starttls_without_tls_material_is_a_hard_error(fake_imap: FakeImapServer) -> None:
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap.port, TlsMode.STARTTLS)
    assert err.value.code == "starttls_unavailable"
    _no_credentials(fake_imap)


def test_starttls_stripped_by_a_middlebox(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    fake_imap_tls.on("CAPABILITY", ["* CAPABILITY IMAP4rev1\r\n", "{tag} OK done\r\n"])
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    assert err.value.code == "starttls_unavailable"
    _no_credentials(fake_imap_tls)


def test_starttls_tagged_no_is_refused(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    fake_imap_tls.on("STARTTLS", ["{tag} NO not now\r\n"])
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    assert err.value.code == "starttls_refused"
    assert "not now" not in str(err.value)
    _no_credentials(fake_imap_tls)


def test_pipelined_response_before_handshake_is_refused(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    """The injection test; CI runs it on every supported Python minor."""
    fake_imap_tls.starttls_inject = b"* CAPABILITY IMAP4rev1 AUTH=PLAIN XINJECTED\r\n"
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    assert err.value.code == "pre_tls_bytes"
    assert "handshake" not in fake_imap_tls.events
    _no_credentials(fake_imap_tls)


def test_bytes_after_the_probe_fail_the_handshake(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    hold = threading.Event()
    fake_imap_tls.starttls_hold = hold
    fake_imap_tls.starttls_late = b"* OK late\r\n"
    timer = threading.Timer(0.5, hold.set)
    timer.start()
    try:
        with pytest.raises(ConnectError) as err:
            connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    finally:
        timer.cancel()
        hold.set()
    assert err.value.code in {"pre_tls_bytes", "tls_failed"}
    _no_credentials(fake_imap_tls)


def test_starttls_untrusted_certificate(fake_imap_tls: FakeImapServer) -> None:
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS)
    assert err.value.code == "tls_verify_failed"
    _no_credentials(fake_imap_tls)


def test_starttls_wrong_host_certificate(wrong_host_material: TlsMaterial) -> None:
    with FakeImapServer(tls=wrong_host_material) as server:
        with pytest.raises(ConnectError) as err:
            connect(HOST, server.port, TlsMode.STARTTLS, ca_file=wrong_host_material.cert_file)
        assert err.value.code == "tls_verify_failed"
        _no_credentials(server)


def test_implicit_success(implicit_server: FakeImapServer, tls_material: TlsMaterial) -> None:
    conn = connect(HOST, implicit_server.port, TlsMode.IMPLICIT, ca_file=tls_material.cert_file)
    conn.close()
    assert "STARTTLS" not in _verbs(implicit_server)
    _no_credentials(implicit_server)


def test_implicit_untrusted_certificate(implicit_server: FakeImapServer) -> None:
    with pytest.raises(ConnectError) as err:
        connect(HOST, implicit_server.port, TlsMode.IMPLICIT)
    assert err.value.code == "tls_verify_failed"


def test_implicit_wrong_host_certificate(wrong_host_material: TlsMaterial) -> None:
    with FakeImapServer(tls=wrong_host_material, implicit_tls=True) as server:
        with pytest.raises(ConnectError) as err:
            connect(HOST, server.port, TlsMode.IMPLICIT, ca_file=wrong_host_material.cert_file)
        assert err.value.code == "tls_verify_failed"


def test_plaintext_server_on_implicit_port_is_refused(fake_imap: FakeImapServer) -> None:
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap.port, TlsMode.IMPLICIT)
    assert err.value.code in {"tls_failed", "connect_failed", "protocol_error"}
    _no_credentials(fake_imap)


class _Tls11Only(TlsMaterial):
    def server_context(self) -> ssl.SSLContext:
        ctx = super().server_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        return ctx


def test_tls_1_1_handshake_is_refused(tls_material: TlsMaterial) -> None:
    legacy = _Tls11Only(tls_material.cert_file, tls_material.key_file)
    try:
        legacy.server_context()
    except (ssl.SSLError, ValueError):
        pytest.skip("OpenSSL build cannot serve TLS 1.1")
    with FakeImapServer(tls=legacy, implicit_tls=True) as server:
        # Control: a client that allows TLS 1.1 does reach the server.
        control = legacy.client_context()
        control.minimum_version = ssl.TLSVersion.TLSv1
        control.maximum_version = ssl.TLSVersion.TLSv1_1
        control.set_ciphers("ALL:@SECLEVEL=0")
        try:
            with (
                socket.create_connection((HOST, server.port), timeout=5) as raw,
                control.wrap_socket(raw, server_hostname=HOST) as tls,
            ):
                assert tls.version() == "TLSv1.1"
        except ssl.SSLError:
            pytest.skip("OpenSSL build cannot negotiate TLS 1.1")
        with pytest.raises(ConnectError) as err:
            connect(HOST, server.port, TlsMode.IMPLICIT, ca_file=legacy.cert_file)
        assert err.value.code == "tls_failed"
    with FakeImapServer(tls=legacy) as server, pytest.raises(ConnectError) as err:
        connect(HOST, server.port, TlsMode.STARTTLS, ca_file=legacy.cert_file)
    assert err.value.code == "tls_failed"


def test_connect_timeout_is_bounded_by_limits() -> None:
    start = time.monotonic()
    with socket.create_server((HOST, 0)) as silent:
        port = silent.getsockname()[1]
        with pytest.raises(ConnectError) as err:
            connect(
                HOST,
                port,
                TlsMode.STARTTLS,
                limits=Limits(imap_connect_seconds=1, imap_read_seconds=30),
            )
    assert err.value.code == "timeout"
    assert time.monotonic() - start < 10


def test_read_timeout_applies_to_the_starttls_reply(tls_material: TlsMaterial) -> None:
    greeting = b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"
    with FakeImapServer(tls=tls_material, greeting=greeting) as server:
        server.on("STARTTLS", [Stall()])
        start = time.monotonic()
        with pytest.raises(ConnectError) as err:
            connect(
                HOST,
                server.port,
                TlsMode.STARTTLS,
                ca_file=tls_material.cert_file,
                limits=Limits(imap_connect_seconds=15, imap_read_seconds=1),
            )
        assert err.value.code == "timeout"
        assert time.monotonic() - start < 10
        _no_credentials(server)


@pytest.mark.parametrize("mode", [TlsMode.STARTTLS, TlsMode.IMPLICIT])
def test_hostile_8bit_capability_text_does_not_escape(
    tls_material: TlsMaterial, mode: TlsMode
) -> None:
    hostile = b"* CAPABILITY IMAP4rev1 SECRETMARK \xff\r\n"
    with FakeImapServer(tls=tls_material, implicit_tls=mode is TlsMode.IMPLICIT) as server:
        server.on("CAPABILITY", [hostile, "{tag} OK done\r\n"])
        try:
            connect(HOST, server.port, mode, ca_file=tls_material.cert_file)
        except ConnectError as exc:
            err = exc
        else:  # pragma: no cover
            pytest.fail("expected ConnectError")
        rendered = "".join(traceback.format_exception(err)) + str(err) + repr(err)
        assert "SECRETMARK" not in rendered
        assert err.__context__ is None
        assert err.__cause__ is None
        _no_credentials(server)


def test_missing_buffer_probe_fails_before_starttls_is_sent(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_probe(_imap: Any) -> Any:
        raise _NoProbe

    monkeypatch.setattr("mailferret.imap.transport.client_buffer", no_probe)
    with pytest.raises(ConnectError) as err:
        connect(HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file)
    assert err.value.code == "hook_unavailable"
    assert "STARTTLS" not in _verbs(fake_imap_tls)


def test_connection_refused() -> None:
    with socket.create_server((HOST, 0)) as probe:
        port = probe.getsockname()[1]
    with pytest.raises(ConnectError) as err:
        connect(HOST, port, TlsMode.IMPLICIT)
    assert err.value.code == "connect_failed"


def test_unreadable_ca_file(tmp_path: Any) -> None:
    with pytest.raises(ConnectError) as err:
        connect(HOST, 1, TlsMode.IMPLICIT, ca_file=tmp_path / "missing.pem")
    assert err.value.code == "ca_file_unreadable"


class _Imap:
    def __init__(self, sock: socket.socket, **attrs: Any) -> None:
        self.sock = sock
        for name, value in attrs.items():
            setattr(self, name, value)


def test_probe_sees_kernel_bytes_and_restores_timeout() -> None:
    a, b = socket.socketpair()
    with a, b:
        a.settimeout(7.0)
        imap = _Imap(a, _readbuf=bytearray())
        assert _bytes_pending(imap) is False
        b.sendall(b"x")
        assert _bytes_pending(imap) is True
        assert a.gettimeout() == 7.0
        assert a.recv(1) == b"x"


def test_probe_sees_client_buffer_and_peek() -> None:
    a, b = socket.socketpair()
    with a, b:
        assert _bytes_pending(_Imap(a, _readbuf=bytearray(b"x"))) is True

        class _File:
            def __init__(self, data: bytes) -> None:
                self.data = data

            def peek(self, _size: int) -> bytes:
                return self.data

        assert _bytes_pending(_Imap(a, file=_File(b"x"))) is True
        assert _bytes_pending(_Imap(a, file=_File(b""))) is False


def test_probe_fails_closed_without_a_buffer() -> None:
    a, b = socket.socketpair()
    with a, b, pytest.raises(_NoProbe):
        _client_buffer(_Imap(a))
    with pytest.raises(_NoProbe):
        _client_buffer(_Imap(a, file=object()))
