from __future__ import annotations

import imaplib
import os
import shutil
import socket
import ssl
import threading
from pathlib import Path

import pytest

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
    assert [c.verb for c in fake_imap.commands] == ["CAPABILITY", "LOGIN", "CAPABILITY", "LOGOUT"]


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
    assert seen == [Command("t9", "t9 NOOP", "NOOP", None)]
    raw.close()


def test_client_literal_is_logged_and_continued(fake_imap: FakeImapServer) -> None:
    raw = Raw(fake_imap)
    raw.read_until(b"\r\n")
    raw.send(b"a1 APPEND INBOX {5}\r\n")
    assert raw.read_until(b"\r\n") == b"+ go\r\n"
    raw.send(b"hello\r\n")
    assert raw.read_until(b"\r\n") == b"a1 OK done\r\n"
    raw.send(b"a2 APPEND INBOX {3+}\r\nabc\r\n")
    assert raw.read_until(b"\r\n") == b"a2 OK done\r\n"
    assert fake_imap.wire.count("<literal 5>") == 1
    assert "<literal 3>" in fake_imap.wire
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


def test_openssl_missing_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(OpensslUnavailable):
        make_tls_material(tmp_path)
