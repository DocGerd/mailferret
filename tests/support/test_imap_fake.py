from __future__ import annotations

import imaplib
import os
import shutil
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.conftest import tls_material_or_skip
from tests.support.imap_fake import (
    Close,
    Command,
    FakeImapServer,
    Flood,
    Literal,
    Mark,
    OpensslUnavailable,
    ReadLine,
    Stall,
    TlsMaterial,
    make_tls_material,
)

TIMEOUT = 10.0


class Raw:
    def __init__(self, server: FakeImapServer, timeout: float = TIMEOUT) -> None:
        self.sock = socket.create_connection(("127.0.0.1", server.port), timeout=timeout)
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def read_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        head, _, self.buf = self.buf.partition(marker)
        return head + marker

    def read_exact(self, size: int) -> bytes:
        while len(self.buf) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        data, self.buf = self.buf[:size], self.buf[size:]
        return data

    def close(self) -> None:
        self.sock.close()


def test_capabilities_and_wire_log(fake_imap: FakeImapServer) -> None:
    fake_imap.capabilities = ["IMAP4rev1", "IDLE", "CONDSTORE"]
    client = imaplib.IMAP4("127.0.0.1", fake_imap.port, timeout=TIMEOUT)
    assert "CONDSTORE" in client.capabilities
    client.login("user@example.com", "dummy-password")
    client.logout()
    fake_imap.wait_for("closed")
    assert fake_imap.wire[0].endswith("CAPABILITY")
    assert any(line.endswith('LOGIN user@example.com "dummy-password"') for line in fake_imap.wire)
    verbs = [c.verb for c in fake_imap.commands]
    assert verbs[0] == "CAPABILITY"
    assert verbs.index("LOGIN") < verbs.index("LOGOUT") == len(verbs) - 1


def test_scripted_untagged_tagged_no_and_bad(fake_imap: FakeImapServer) -> None:
    fake_imap.on("SELECT", ["* 3 EXISTS\r\n", "{tag} NO [NONEXISTENT] nope\r\n"])
    fake_imap.on("EXAMINE", ["{tag} BAD syntax\r\n"])
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 SELECT INBOX\r\n")
    assert raw.read_until(b"\r\n") == b"* 3 EXISTS\r\n"
    assert raw.read_until(b"\r\n") == b"a1 NO [NONEXISTENT] nope\r\n"
    raw.send(b"a2 EXAMINE INBOX\r\n")
    assert raw.read_until(b"\r\n") == b"a2 BAD syntax\r\n"
    raw.close()


def test_uid_key_wins_over_verb_and_once_is_consumed(fake_imap: FakeImapServer) -> None:
    fake_imap.on("UID", ["{tag} NO generic\r\n"])
    fake_imap.on("UID FETCH", ["{tag} BAD specific\r\n"], once=True)
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 UID FETCH 1 (UID)\r\n")
    assert raw.read_until(b"\r\n") == b"a1 BAD specific\r\n"
    raw.send(b"a2 UID FETCH 1 (UID)\r\n")
    assert raw.read_until(b"\r\n") == b"a2 NO generic\r\n"
    raw.close()


def test_callable_handler_sees_command(fake_imap: FakeImapServer) -> None:
    seen: list[Command] = []

    def handler(cmd: Command) -> list[bytes]:
        seen.append(cmd)
        return [b"{tag} OK seen\r\n"]

    fake_imap.on("NOOP", handler)
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"t9 NOOP\r\n")
    assert raw.read_until(b"\r\n") == b"t9 OK seen\r\n"
    assert seen == [Command("t9", "t9 NOOP", "NOOP", None, conn=1)]
    raw.close()


def test_client_literal_is_logged_and_continued(fake_imap: FakeImapServer) -> None:
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 APPEND INBOX {5}\r\n")
    assert raw.read_until(b"\r\n") == b"+ go\r\n"
    raw.send(b"hello\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    raw.send(b"a2 APPEND INBOX {3+}\r\nabc UID 7\r\n")
    assert raw.read_until(b"\r\n") == b"a2 OK done\r\n"
    assert fake_imap.wire == [
        "a1 APPEND INBOX {5}",
        "<literal 5>hello",
        "",
        "a2 APPEND INBOX {3+}",
        "<literal 3>abc",
        " UID 7",
    ]
    assert [c.verb for c in fake_imap.commands] == ["APPEND", "APPEND"]
    raw.close()


def test_literals_can_be_refused() -> None:
    with FakeImapServer(literals=False) as server:
        raw = Raw(server)
        raw.read_until(b"\r\n")
        raw.send(b"a1 SEARCH {4}\r\n")
        assert raw.read_until(b"\r\n") == b"a1 BAD literals refused\r\n"
        raw.send(b"a2 NOOP\r\n")
        assert raw.read_until(b"\r\n") == b"a2 OK done\r\n"
        raw.close()


@pytest.mark.parametrize("flags", [{"literals": False}, {"literal_plus": False}])
def test_non_synchronizing_literal_is_refused_and_bytes_become_a_command(
    flags: dict[str, bool],
) -> None:
    payload = b"a9 UID STORE 1 +FLAGS (\\Seen)"
    assert len(payload) == 29
    with FakeImapServer(**flags) as server:
        raw = Raw(server)
        raw.read_until(b"\r\n")
        raw.send(b"a1 SEARCH CHARSET UTF-8 TEXT {29+}\r\n" + payload + b"\r\n")
        assert raw.read_until(b"\r\n") == b"a1 BAD literals refused\r\n"
        assert raw.read_until(b"\r\n") == b"a9 OK done\r\n"
        raw.close()
        assert [(c.verb, c.sub) for c in server.commands] == [("UID", "STORE")]


def test_literal_plus_is_logged_with_content_by_default(fake_imap: FakeImapServer) -> None:
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 SEARCH CHARSET UTF-8 TEXT {5+}\r\nhello\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    assert fake_imap.wire == ["a1 SEARCH CHARSET UTF-8 TEXT {5+}", "<literal 5>hello", ""]
    assert [c.verb for c in fake_imap.commands] == ["SEARCH"]
    raw.close()


def test_server_literal_exact_and_lying(fake_imap: FakeImapServer) -> None:
    fake_imap.on("FETCH", [Literal(1000), "{tag} OK done\r\n"])
    fake_imap.on("STORE", [Literal(10, declared=4), "{tag} OK done\r\n"])
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 FETCH 1 BODY.PEEK[]\r\n")
    assert raw.read_until(b"{1000}\r\n").endswith(b"BODY[] {1000}\r\n")
    assert raw.read_exact(1000) == b"x" * 1000
    assert raw.read_until(b"\r\n") == b")\r\n"
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    raw.send(b"a2 STORE 1\r\n")
    assert raw.read_until(b"{4}\r\n").endswith(b"{4}\r\n")
    assert raw.read_exact(10) == b"x" * 10
    raw.close()


def test_oversized_literal_and_line_stream_without_buffering(fake_imap: FakeImapServer) -> None:
    size = 5 * 1024 * 1024
    fake_imap.on("FETCH", [Literal(size), Mark("literal-sent")])
    fake_imap.on("NOOP", [Flood(size), Mark("flood-sent")])
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 FETCH 1 BODY.PEEK[]\r\n")
    raw.read_until(b"{%d}\r\n" % size)
    assert len(raw.read_exact(size)) == size
    fake_imap.wait_for("literal-sent")
    raw.send(b"a2 NOOP\r\n")
    assert len(raw.read_exact(size)) == size
    fake_imap.wait_for("flood-sent")
    assert b"\n" not in raw.buf
    raw.close()


def test_stall_is_cut_by_client_timeout(fake_imap: FakeImapServer) -> None:
    fake_imap.on("NOOP", [Stall()])
    raw = Raw(fake_imap, timeout=0.3)
    raw.read_until(b"\r\n")
    raw.send(b"a1 NOOP\r\n")
    with pytest.raises(TimeoutError):
        raw.read_until(b"\r\n")
    raw.close()


def test_lines_sent_after_a_stall_are_still_logged(fake_imap: FakeImapServer) -> None:
    fake_imap.on("NOOP", [Stall()])
    raw = Raw(fake_imap, timeout=0.3)
    raw.read_until(b"\r\n")
    raw.send(b"a1 NOOP\r\n")
    with pytest.raises(TimeoutError):
        raw.read_until(b"\r\n")
    raw.send(b'a2 LOGIN user@example.com "dummy-password"\r\n')
    fake_imap.wait_for_wire('a2 LOGIN user@example.com "dummy-password"')
    raw.sock.settimeout(0.3)
    with pytest.raises(TimeoutError):
        raw.sock.recv(1)
    raw.close()
    fake_imap.wait_for("closed")


def test_close_drops_connection(fake_imap: FakeImapServer) -> None:
    fake_imap.on("NOOP", ["* partial\r\n", Close()])
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 NOOP\r\n")
    assert raw.read_until(b"\r\n") == b"* partial\r\n"
    fake_imap.wait_for("closed")
    raw.close()


def test_authenticate_plain_response_is_logged(fake_imap: FakeImapServer) -> None:
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 AUTHENTICATE PLAIN\r\n")
    assert raw.read_until(b"\r\n") == b"+ \r\n"
    raw.send(b"AHVzZXJAZXhhbXBsZS5jb20AZHVtbXk=\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    assert "AHVzZXJAZXhhbXBsZS5jb20AZHVtbXk=" in fake_imap.wire
    raw.close()


def test_readline_part_logs_extra_client_line(fake_imap: FakeImapServer) -> None:
    fake_imap.on("IDLE", ["+ idling\r\n", ReadLine(), "{tag} OK done\r\n"])
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 IDLE\r\n")
    raw.read_until(b"+ idling\r\n")
    raw.send(b"DONE\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    assert fake_imap.wire[-2:] == ["a1 IDLE", "DONE"]
    raw.close()


def test_connections_run_independently(fake_imap: FakeImapServer) -> None:
    a, b = Raw(fake_imap), Raw(fake_imap)
    for raw in (a, b):
        raw.read_until(b"\r\n")
        raw.send(b"x NOOP\r\n")
        assert raw.read_until(b"\r\n") == b"x OK done\r\n"
        raw.close()


def test_connection_accounting_and_attribution(fake_imap: FakeImapServer) -> None:
    assert fake_imap.connections == 0
    a = Raw(fake_imap)
    a.read_until(b"\r\n")
    b = Raw(fake_imap)
    b.read_until(b"\r\n")
    a.send(b"a1 NOOP\r\n")
    assert a.read_until(b"\r\n") == b"a1 OK done\r\n"
    b.send(b"b1 CAPABILITY\r\nb2 NOOP\r\n")
    assert b.read_until(b"b2 OK done\r\n").endswith(b"b2 OK done\r\n")
    assert fake_imap.connections == 2
    assert [e for e in fake_imap.events if e.startswith("accepted:")] == [
        "accepted:1",
        "accepted:2",
    ]
    assert fake_imap.wire_of(1) == ["a1 NOOP"]
    assert fake_imap.wire_of(2) == ["b1 CAPABILITY", "b2 NOOP"]
    assert [(c.conn, c.verb) for c in fake_imap.commands if c.conn == 2] == [
        (2, "CAPABILITY"),
        (2, "NOOP"),
    ]
    assert [c.verb for c in fake_imap.commands_of(1)] == ["NOOP"]
    assert len(fake_imap.wire) == 3
    a.close()
    b.close()


def test_stop_leaves_no_threads_behind() -> None:
    before = set(threading.enumerate())
    server = FakeImapServer()
    server.start()
    raw = Raw(server)
    raw.read_until(b"\r\n")
    server.stop()
    leaked = [t for t in threading.enumerate() if t not in before and t.is_alive()]
    assert leaked == []
    raw.close()


def _stop_promptly_without_leaks(server: FakeImapServer, before: set[threading.Thread]) -> None:
    started = time.monotonic()
    server.stop()
    elapsed = time.monotonic() - started
    leaked = [t for t in threading.enumerate() if t not in before and t.is_alive()]
    assert leaked == []
    assert elapsed < 1.0


def test_stop_closes_a_connection_accepted_during_teardown(
    tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = set(threading.enumerate())
    server = FakeImapServer(tls=tls_material, implicit_tls=True)
    record, join = server._event, server._accept_thread.join
    joining = threading.Event()

    def hold_until_joined(name: str) -> None:
        record(name)
        if name == "accepted:1":
            joining.wait(TIMEOUT)

    def signal_join(timeout: float | None = None) -> None:
        joining.set()
        join(timeout)

    monkeypatch.setattr(server, "_event", hold_until_joined)
    monkeypatch.setattr(server._accept_thread, "join", signal_join)
    server.start()
    raw = Raw(server)
    server.wait_for("accepted:1")
    _stop_promptly_without_leaks(server, before)
    raw.close()


@pytest.fixture
def handshake_traced(monkeypatch: pytest.MonkeyPatch) -> Iterator[threading.Event]:
    entered = threading.Event()
    original = ssl.SSLSocket.do_handshake

    def traced(self: ssl.SSLSocket, block: bool = False) -> None:
        entered.set()
        original(self, block)

    monkeypatch.setattr(ssl.SSLSocket, "do_handshake", traced)
    yield entered


def test_stop_interrupts_an_implicit_tls_handshake(
    tls_material: TlsMaterial, handshake_traced: threading.Event
) -> None:
    before = set(threading.enumerate())
    server = FakeImapServer(tls=tls_material, implicit_tls=True)
    server.start()
    raw = Raw(server)
    assert handshake_traced.wait(TIMEOUT)
    _stop_promptly_without_leaks(server, before)
    raw.close()


@pytest.mark.parametrize("after_ok", [b"", b"\x16\x03\x01"], ids=["silent", "partial-record"])
def test_stop_interrupts_a_connection_after_starttls_ok(
    tls_material: TlsMaterial, handshake_traced: threading.Event, after_ok: bytes
) -> None:
    before = set(threading.enumerate())
    server = FakeImapServer(tls=tls_material)
    server.start()
    raw = Raw(server)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
    if after_ok:
        raw.send(after_ok)
        assert handshake_traced.wait(TIMEOUT)
    _stop_promptly_without_leaks(server, before)
    raw.close()


def test_starttls_advertised_only_before_tls(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    client = imaplib.IMAP4("127.0.0.1", fake_imap_tls.port, timeout=TIMEOUT)
    assert "STARTTLS" in client.capabilities
    client.starttls(tls_material.client_context())
    typ, data = client.capability()
    assert typ == "OK"
    assert b"STARTTLS" not in data[0]
    client.logout()
    assert "handshake" in fake_imap_tls.events


def test_starttls_can_be_hidden_while_the_upgrade_still_works(tls_material: TlsMaterial) -> None:
    with FakeImapServer(tls=tls_material, advertise_starttls=False) as server:
        raw = Raw(server)
        raw.read_until(b"\r\n")
        raw.send(b"a1 CAPABILITY\r\n")
        assert b"STARTTLS" not in raw.read_until(b"a1 OK done\r\n")
        raw.send(b"a2 STARTTLS\r\n")
        assert raw.read_until(b"\r\n") == b"a2 OK begin TLS\r\n"
        raw.sock = tls_material.client_context().wrap_socket(raw.sock, server_hostname="127.0.0.1")
        raw.sock.sendall(b"a3 NOOP\r\n")
        assert raw.read_until(b"\r\n") == b"a3 OK done\r\n"
        assert "handshake" in server.events
        raw.close()


def test_trusted_cert_for_another_name_fails_hostname_verification(
    wrong_host_material: TlsMaterial,
) -> None:
    with FakeImapServer(tls=wrong_host_material) as server:
        client = imaplib.IMAP4("127.0.0.1", server.port, timeout=TIMEOUT)
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            client.starttls(wrong_host_material.client_context())
        assert "mismatch" in info.value.verify_message
        assert all(c.verb != "LOGIN" for c in server.commands)


@pytest.mark.parametrize(
    "name",
    [
        "bad name\n[x]",
        "fe80::1%x\nsubjectAltName = DNS:evil.example.com",
        "fe80::1%eth0",
        "example.com,DNS:evil.example.com",
        "example.com\r",
        "example\x00.com",
        "example\u200b.com",
        "",
    ],
)
def test_cert_names_must_be_valid(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="invalid certificate name"):
        make_tls_material(tmp_path, (name,))


@pytest.mark.parametrize(
    ("hostname", "verifies"),
    [("localhost", False), ("127.0.0.1", False), ("192.0.2.1", True)],
)
def test_ip_only_material_matches_only_its_own_address(
    ip_only_material: TlsMaterial, hostname: str, verifies: bool
) -> None:
    with FakeImapServer(tls=ip_only_material) as server:
        raw = Raw(server)
        raw.read_until(b"\r\n")
        raw.send(b"a1 STARTTLS\r\n")
        assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
        ctx = ip_only_material.client_context()
        if verifies:
            raw.sock = ctx.wrap_socket(raw.sock, server_hostname=hostname)
        else:
            with pytest.raises(ssl.SSLCertVerificationError):
                ctx.wrap_socket(raw.sock, server_hostname=hostname)
        raw.close()


def test_untrusted_cert_fails_client_verification(fake_imap_tls: FakeImapServer) -> None:
    client = imaplib.IMAP4("127.0.0.1", fake_imap_tls.port, timeout=TIMEOUT)
    with pytest.raises(ssl.SSLCertVerificationError):
        client.starttls(ssl.create_default_context())


def test_starttls_injection_arrives_before_handshake(fake_imap_tls: FakeImapServer) -> None:
    fake_imap_tls.starttls_inject = b"* CAPABILITY IMAP4rev1 XINJECTED\r\n"
    raw = Raw(fake_imap_tls)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
    assert raw.read_until(b"\r\n") == b"* CAPABILITY IMAP4rev1 XINJECTED\r\n"
    raw.close()


def test_plaintext_sent_after_starttls_is_logged_not_discarded(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    raw = Raw(fake_imap_tls)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\na2 LOGIN user@example.com dummy\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
    raw.sock = tls_material.client_context().wrap_socket(raw.sock, server_hostname="127.0.0.1")
    raw.send(b"a3 NOOP\r\n")
    assert raw.read_until(b"\r\n") == b"a3 OK done\r\n"
    assert fake_imap_tls.wire == ["a1 STARTTLS", "a2 LOGIN user@example.com dummy", "a3 NOOP"]
    assert [c.verb for c in fake_imap_tls.commands] == ["STARTTLS", "LOGIN", "NOOP"]
    assert fake_imap_tls.events.count("pre-tls-bytes") == 1
    assert fake_imap_tls.events.index("pre-tls-bytes") < fake_imap_tls.events.index("handshake")
    raw.close()


@pytest.mark.parametrize("held", [False, True], ids=["separate-write", "during-hold"])
def test_plaintext_login_after_starttls_ok_is_logged_and_skips_handshake(
    fake_imap_tls: FakeImapServer, held: bool
) -> None:
    release = threading.Event()
    if held:
        fake_imap_tls.starttls_hold = release
    raw = Raw(fake_imap_tls)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
    if held:
        fake_imap_tls.wait_for("starttls-held")
    raw.send(b"a2 LOGIN user@example.com dummy\r\n")
    release.set()
    assert raw.read_until(b"\r\n") == b"a2 OK done\r\n"
    assert fake_imap_tls.wire == ["a1 STARTTLS", "a2 LOGIN user@example.com dummy"]
    assert [c.verb for c in fake_imap_tls.commands] == ["STARTTLS", "LOGIN"]
    assert fake_imap_tls.events.count("pre-tls-bytes") == 1
    assert "handshake" not in fake_imap_tls.events
    raw.close()


def test_starttls_without_pipelined_bytes_records_no_pre_tls_event(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    client = imaplib.IMAP4("127.0.0.1", fake_imap_tls.port, timeout=TIMEOUT)
    client.starttls(tls_material.client_context())
    client.logout()
    assert "pre-tls-bytes" not in fake_imap_tls.events


def test_starttls_late_injection_waits_for_release(fake_imap_tls: FakeImapServer) -> None:
    release = threading.Event()
    fake_imap_tls.starttls_hold = release
    fake_imap_tls.starttls_late = b"* CAPABILITY IMAP4rev1 XLATE\r\n"
    raw = Raw(fake_imap_tls, timeout=0.3)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK begin TLS\r\n"
    fake_imap_tls.wait_for("starttls-held")
    with pytest.raises(TimeoutError):
        raw.sock.recv(1)
    release.set()
    raw.sock.settimeout(TIMEOUT)
    assert raw.read_until(b"\r\n") == b"* CAPABILITY IMAP4rev1 XLATE\r\n"
    raw.close()


def test_starttls_without_material_is_bad(fake_imap: FakeImapServer) -> None:
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 STARTTLS\r\n")
    assert raw.read_until(b"\r\n") == b"a1 BAD STARTTLS unavailable\r\n"
    raw.close()


def test_implicit_tls(tls_material: TlsMaterial) -> None:
    with FakeImapServer(tls=tls_material, implicit_tls=True) as server:
        raw_ctx = tls_material.client_context()
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=TIMEOUT) as sock,
            raw_ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls,
        ):
            assert tls.recv(64) == b"* OK ready\r\n"
            tls.sendall(b"a1 CAPABILITY\r\n")
            assert b"STARTTLS" not in tls.recv(256)
        server.wait_for("closed")
        assert "handshake" in server.events


def test_openssl_missing_skips_locally_and_fails_in_ci(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(pytest.skip.Exception):
        tls_material_or_skip(tmp_path)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(OpensslUnavailable):
        tls_material_or_skip(tmp_path)


def test_openssl_missing_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(OpensslUnavailable):
        make_tls_material(tmp_path)
