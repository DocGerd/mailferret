"""GreenMail-backed checks (V2). STARTTLS/CONDSTORE/ESEARCH live on the D0 fake server."""

from __future__ import annotations

import imaplib
import re
import socket
import ssl
from collections.abc import Callable

import pytest

from tests.fixtures.corpus import committed
from tests.integration.conftest import (
    ACCOUNTS,
    HOST,
    IMAP_PORT,
    IMAPS_PORT,
    Greenmail,
    connect,
)
from tests.integration.tls import build_context

ALICE = "alice@example.com"
BOB = "bob@example.com"
CONTROL_MESSAGE = (
    b"From: a@example.com\r\nTo: alice@example.com\r\nSubject: control\r\n\r\nbody\r\n"
)


def _flags(conn: imaplib.IMAP4, uid_range: str = "1:*") -> list[bytes]:
    _, data = conn.fetch(uid_range, "(FLAGS)")
    return [d for d in data if isinstance(d, bytes)]


def test_ca_file_required_and_sufficient(greenmail: Greenmail) -> None:
    """T-07: verification fails without the CA and passes with it, through the context builder."""
    with pytest.raises(ssl.SSLCertVerificationError):
        connect(None)
    conn = connect(greenmail.ca_file)
    try:
        assert conn.login(ALICE, ACCOUNTS[ALICE])[0] == "OK"
    finally:
        conn.logout()


def test_hostname_mismatch_rejected(greenmail: Greenmail) -> None:
    """T-07: the CA is trusted but the certificate does not cover this name."""
    with (
        pytest.raises(ssl.SSLCertVerificationError),
        socket.create_connection(("127.0.0.1", IMAPS_PORT), timeout=10) as raw,
    ):
        build_context(greenmail.ca_file).wrap_socket(raw, server_hostname="example.com")


def test_auth_enabled_rejects_bad_credentials(greenmail: Greenmail) -> None:
    conn = connect(greenmail.ca_file)
    try:
        with pytest.raises(imaplib.IMAP4.error):
            conn.login(ALICE, "wrong")
    finally:
        conn.logout()
    conn = connect(greenmail.ca_file)
    try:
        with pytest.raises(imaplib.IMAP4.error):
            conn.login("nobody@example.com", "pw")
    finally:
        conn.logout()


def test_failed_login_does_not_disturb_other_session(greenmail: Greenmail) -> None:
    bob = connect(greenmail.ca_file, BOB)
    try:
        bad = connect(greenmail.ca_file)
        try:
            with pytest.raises(imaplib.IMAP4.error):
                bad.login(ALICE, "wrong")
        finally:
            bad.logout()
        assert bob.select("INBOX", readonly=True)[0] == "OK"
        assert bob.noop()[0] == "OK"
    finally:
        bob.logout()


def test_seeded_corpus_and_account_isolation(greenmail: Greenmail) -> None:
    corpus = committed()
    alice = connect(greenmail.ca_file, ALICE)
    bob = connect(greenmail.ca_file, BOB)
    try:
        _, count = alice.select("INBOX", readonly=True)
        assert int(count[0]) == len(corpus)
        _, count = bob.select("INBOX", readonly=True)
        assert int(count[0]) == 0
    finally:
        alice.logout()
        bob.logout()


def test_no_mutation_baseline(greenmail: Greenmail) -> None:
    """EXAMINE plus BODY.PEEK leaves flags alone; the snapshot is the before/after pair."""
    conn = connect(greenmail.ca_file, ALICE)
    try:
        conn.select("INBOX", readonly=True)
        before = _flags(conn)
        assert before
        for _ in range(2):
            conn.select("INBOX", readonly=True)
            conn.fetch("1:*", "(BODY.PEEK[])")
        assert _flags(conn) == before
        assert not any(rb"\Seen" in line for line in before)
    finally:
        conn.logout()


def test_seen_control_fetch_body_sets_seen(greenmail: Greenmail) -> None:
    """Control: a mutating read does set \\Seen here, so the no-mutation test can fail.

    Raw connection in its own folder, outside the INBOX snapshot above.
    """
    conn = connect(greenmail.ca_file, ALICE)
    try:
        assert conn.create("control")[0] == "OK"
        assert conn.append("control", "", None, CONTROL_MESSAGE)[0] == "OK"  # type: ignore[arg-type]
        conn.select("control")
        assert not any(rb"\Seen" in line for line in _flags(conn))
        conn.fetch("1", "(BODY[])")
        assert any(rb"\Seen" in line for line in _flags(conn))
    finally:
        conn.logout()


class _Recorder(imaplib.IMAP4):
    sent: list[bytes]

    def send(self, data: bytes) -> None:
        self.sent.append(bytes(data))
        super().send(data)


def test_plaintext_port_has_no_starttls_and_no_login_sent(greenmail: Greenmail) -> None:
    """T-07: no STARTTLS on the real server -> hard error before any LOGIN; backend untouched."""
    gets: list[str] = []

    def backend_get(account: str) -> str:
        gets.append(account)
        return ACCOUNTS[account]

    def connect_starttls_required(get: Callable[[str], str]) -> None:
        # Stand-in for the D1 policy; swapped for the real connect() in issue #26.
        _Recorder.sent = []
        conn = _Recorder(HOST, IMAP_PORT, timeout=10)
        try:
            if "STARTTLS" not in conn.capabilities:
                raise ConnectionError("server does not offer STARTTLS")
            conn.starttls()
            conn.login(ALICE, get(ALICE))
        finally:
            conn.shutdown()

    with pytest.raises(ConnectionError):
        connect_starttls_required(backend_get)
    wire = b"".join(_Recorder.sent)
    assert not re.search(rb"(?i)\bLOGIN\b|\bAUTHENTICATE\b", wire)
    assert gets == []

    conn = imaplib.IMAP4(HOST, IMAP_PORT, timeout=10)
    try:
        assert "STARTTLS" not in conn.capabilities
        assert "IMAP4REV1" in conn.capabilities
        # imaplib.starttls() refuses client-side; send the command raw.
        with pytest.raises(imaplib.IMAP4.error, match="BAD"):
            conn._simple_command("STARTTLS")
    finally:
        conn.shutdown()


def test_corpus_is_all_fetchable(greenmail: Greenmail) -> None:
    corpus = committed()
    conn = connect(greenmail.ca_file, ALICE)
    try:
        conn.select("INBOX", readonly=True)
        for i, fixture in enumerate(corpus, start=1):
            _, data = conn.fetch(str(i), "(BODY.PEEK[])")
            assert isinstance(data[0], tuple)
            assert data[0][1], fixture.name
    finally:
        conn.logout()
