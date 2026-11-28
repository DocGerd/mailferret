"""R1-R3, T-10 on the wire: a real session against the recording fake server.

The wire is compared with the allowlist, not with the guard's own log.
"""

from __future__ import annotations

import sys
import traceback
from typing import Any

import pytest

from mailferret.imap import (
    CommandRejected,
    LiteralItem,
    LoginInputRefused,
    ReadOnlySession,
    ReadOnlyViolation,
    SessionError,
    fetch_caps,
)
from mailferret.imap.grammar import ALLOWED_VERBS
from mailferret.imap.transport import _Client
from mailferret.limits import Limits
from tests.support.imap_fake import FakeImapServer
from tests.unit.imap.conftest import Opener

OK = "{tag} OK done\r\n"


def _script(server: FakeImapServer) -> None:
    server.on("LIST", [b'* LIST () "/" INBOX\r\n', OK])
    server.on("STATUS", [b"* STATUS INBOX (MESSAGES 3)\r\n", OK])
    server.on("NAMESPACE", [b'* NAMESPACE (("" "/")) NIL NIL\r\n', OK])
    server.on("EXAMINE", [b"* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n", OK])
    server.on("UID SEARCH", [b"* SEARCH 1 2 3\r\n", OK])
    server.on("UID SORT", [b"* SORT 3 2 1\r\n", OK])
    server.on("UID THREAD", [b"* THREAD (1 2)(3)\r\n", OK])
    server.on("UID FETCH", [b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n", OK])
    server.on("LOGIN", [OK])


def _verbs(server: FakeImapServer) -> list[str]:
    return [f"UID {c.sub}" if c.sub else c.verb for c in server.commands]


def test_wire_survey_every_session_method_stays_on_the_allowlist(
    server: FakeImapServer, opener: Opener
) -> None:
    _script(server)
    session = opener(server)
    session.login("user@example.com", "secret")
    session.noop()
    session.namespace()
    session.list_folders()
    session.folder_status("INBOX", ["MESSAGES"])
    session.examine("INBOX")
    session.search(["ALL"])
    session.sort(["DATE"], ["ALL"])
    session.thread("REFERENCES", ["ALL"])
    session.fetch(
        [1],
        ["UID", "FLAGS", "BODY.PEEK[HEADER.FIELDS (FROM TO)]", "BODYSTRUCTURE"],
        caps=fetch_caps(Limits(), LiteralItem.HEADER, 1),
    )
    session.close_folder()
    session.logout()
    verbs = _verbs(server)
    assert "EXAMINE" in verbs
    allowed = {v for v in ALLOWED_VERBS if v != "UID"} | {f"UID {v}" for v in ALLOWED_VERBS}
    assert set(verbs) <= allowed
    assert "SELECT" not in verbs
    assert not any("BODY[" in line or "RFC822 " in line for line in server.wire)
    assert any("BODY.PEEK[HEADER.FIELDS (FROM TO)]" in line for line in server.wire)


def test_no_session_method_can_reach_a_write_verb() -> None:
    public = {name for name in dir(ReadOnlySession) if not name.startswith("_")}
    for forbidden in ("select", "store", "append", "copy", "move", "delete", "expunge"):
        assert not any(forbidden in name for name in public)
    assert not hasattr(ReadOnlySession, "client")
    assert not hasattr(ReadOnlySession, "_client_public")


def test_examine_never_selects(server: FakeImapServer, opener: Opener) -> None:
    _script(server)
    session = opener(server)
    session.login("user@example.com", "secret")
    session.examine("INBOX")
    assert [c.verb for c in server.commands if c.verb in {"SELECT", "EXAMINE"}] == ["EXAMINE"]


def test_literal_plus_is_hidden_from_imapclient_but_not_from_our_flags(
    tls_material: Any, opener: Opener
) -> None:
    caps = ["IMAP4rev1", "LITERAL+"]
    with FakeImapServer(
        tls=tls_material, implicit_tls=True, capabilities=caps, literal_plus=True
    ) as server:
        _script(server)
        session = opener(server)
        assert "LITERAL+" in session.capabilities.raw
        assert session._client.has_capability("LITERAL+") is False
        assert session._client.has_capability(b"literal+") is False
        assert session._client.has_capability("IMAP4rev1") is True
        session.login("user@example.com", "secret")
        session.search(["TEXT", "café"], charset="UTF-8")
        assert any(line.startswith("<literal 5>") for line in server.wire)
        assert not any("+}" in line for line in server.wire)
        sent = [c for c in server.commands if c.sub == "SEARCH"]
        assert len(sent) == 1
        literal_at = server.wire.index(next(w for w in server.wire if w.startswith("<literal")))
        assert any("{5}" in w for w in server.wire[:literal_at])


def test_literal_plus_is_refused_by_the_gate_even_when_imapclient_would_send_it(
    tls_material: Any, opener: Opener, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the ``has_capability`` hide disabled, the gate alone stops ``{n+}``."""
    monkeypatch.setattr(_Client, "has_capability", lambda self, cap: cap == "LITERAL+")
    with FakeImapServer(
        tls=tls_material, implicit_tls=True, capabilities=["IMAP4rev1", "LITERAL+"]
    ) as server:
        _script(server)
        session = opener(server)
        session.login("user@example.com", "secret")
        with pytest.raises(ReadOnlyViolation) as err:
            session.search(["TEXT", "café"], charset="UTF-8")
        assert err.value.reason in {"literal_plus_refused", "line_break_in_command"}
        assert not any(w.startswith("<literal") for w in server.wire)
        assert not session.usable


def test_literal_plus_is_refused_when_the_server_does_not_advertise_it(
    tls_material: Any, opener: Opener, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_Client, "has_capability", lambda self, cap: cap == "LITERAL+")
    with FakeImapServer(tls=tls_material, implicit_tls=True) as server:
        _script(server)
        session = opener(server)
        session.login("user@example.com", "secret")
        with pytest.raises(ReadOnlyViolation):
            session.search(["TEXT", "café"], charset="UTF-8")
        assert not any(w.startswith("<literal") for w in server.wire)


def test_a_search_literal_carrying_a_store_never_reaches_the_wire_as_a_command(
    tls_material: Any, opener: Opener
) -> None:
    """The issue #7 probe against a server that rejects literals with a tagged BAD."""
    with FakeImapServer(
        tls=tls_material, implicit_tls=True, capabilities=["IMAP4rev1"], literals=False
    ) as server:
        _script(server)
        session = opener(server)
        session.login("user@example.com", "secret")
        probe = "é\r\nA9 UID STORE 1:* +FLAGS (\\Seen)\r\n"
        with pytest.raises(SessionError):
            session.search(["TEXT", probe], charset="UTF-8")
        assert not any("STORE" in c.line for c in server.commands)
        assert not any("STORE" in w for w in server.wire if w.startswith("<literal"))


def test_embedded_crlf_in_a_login_never_becomes_a_second_command(
    server: FakeImapServer, opener: Opener, capfd: pytest.CaptureFixture[str]
) -> None:
    """At imaplib's own level: 3.13+ refuses control characters itself, below the gate does."""
    _script(server)
    session = opener(server)
    secret = "hunter2-CANARY"  # noqa: S105  # pii-check: ignore
    with pytest.raises((ReadOnlyViolation, ValueError)) as err:
        session._imap.login("user", f"{secret}\r\nA9 NOOP")
    assert not any(c.verb == "NOOP" for c in server.commands)
    shown = "".join(traceback.format_exception(err.value)) + repr(err.value) + str(err.value)
    if isinstance(err.value, ReadOnlyViolation):
        assert secret not in shown
        assert err.value.reason == "line_break_in_command"
    else:
        assert sys.version_info >= (3, 13)
    captured = capfd.readouterr()
    assert secret not in captured.out + captured.err
    assert server.wire_of(1).count("A9 NOOP") == 0


def test_embedded_crlf_through_the_session_is_refused_before_any_byte(
    server: FakeImapServer, opener: Opener
) -> None:
    """imapclient refuses CR/LF in arguments first; the session maps it to a fixed error."""
    _script(server)
    session = opener(server)
    before = len(server.commands)
    with pytest.raises(SessionError) as err:
        session.login("user", "pw\r\nA9 NOOP")
    assert "A9" not in repr(err.value) + str(err.value)
    assert len(server.commands) == before


@pytest.mark.parametrize(
    ("login", "secret"),
    [("usér", "pw-CANARY-1"), ("user", "sécret-CANARY"), ("user", "üñî")],
)
def test_login_takes_ascii_str_only_and_sends_nothing_otherwise(
    server: FakeImapServer,
    opener: Opener,
    login: str,
    secret: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _script(server)
    session = opener(server)
    before = len(server.commands)
    with pytest.raises(LoginInputRefused) as err:
        session.login(login, secret)
    shown = "".join(traceback.format_exception(err.value)) + repr(err.value) + str(err.value)
    shown += repr(err.value.args)
    assert secret not in shown
    assert err.value.__context__ is None and err.value.__cause__ is None
    captured = capfd.readouterr()
    assert secret not in captured.out + captured.err
    assert len(server.commands) == before
    assert session.usable


@pytest.mark.parametrize("bad", [b"secret", bytearray(b"x"), None, 5])
def test_login_refuses_anything_but_str(server: FakeImapServer, opener: Opener, bad: Any) -> None:
    session = opener(server)
    with pytest.raises(LoginInputRefused):
        session.login("user", bad)
    with pytest.raises(LoginInputRefused):
        session.login(bad, "secret")


def test_plain_login_carries_utf8_through_the_gate(server: FakeImapServer, opener: Opener) -> None:
    session = opener(server)
    session.plain_login("usér", "sécret")
    assert any(c.verb == "AUTHENTICATE" for c in server.commands)
    assert session.usable


def test_a_tagged_no_after_login_keeps_the_session(server: FakeImapServer, opener: Opener) -> None:
    server.on("EXAMINE", ["{tag} NO café-Needle missing\r\n"], once=True)
    _script(server)
    session = opener(server)
    session.login("user@example.com", "secret")
    with pytest.raises(CommandRejected) as err:
        session.examine("Nope")
    assert err.value.completion == "NO"
    assert "Needle" not in str(err.value) + repr(err.value.args)
    assert session.usable
    session.noop()
