"""T-03, T-21: imapclient logging is pinned off and library exceptions map to fixed codes."""

from __future__ import annotations

import logging
import socket
import sys
import threading
import traceback
from collections.abc import Iterator
from typing import Any

import pytest
from imapclient.exceptions import IMAPClientError

from mailferret.imap import (
    CommandRejected,
    ConnectionDropped,
    DeadlineExceeded,
    LoginRejected,
    ReadOnlyViolation,
    ServerError,
    SessionError,
    SessionTimeout,
)
from mailferret.imap.logging_pin import pin_imapclient_logging
from tests.support.imap_fake import Close, FakeImapServer, Stall
from tests.unit.imap.conftest import Opener

NEEDLE = "café-Needle"
OK = "{tag} OK done\r\n"


def _latin1(text: str) -> bytes:
    return text.encode("latin-1")


def _script(server: FakeImapServer) -> None:
    server.on(
        "LIST",
        [b'* LIST () "/" INBOX\r\n', _latin1(f'* LIST () "/" "{NEEDLE}"\r\n'), OK],
    )
    server.on("EXAMINE", [_latin1(f"{{tag}} NO {NEEDLE} rejected\r\n")], once=True)
    server.on("EXAMINE", [b"* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n", OK])
    server.on("UID SEARCH", [_latin1(f"{{tag}} BAD {NEEDLE} xbad\r\n")], once=True)
    server.on(
        "UID FETCH",
        [
            _latin1(
                f'* 1 FETCH (UID 1 ENVELOPE (NIL "{NEEDLE}" (("{NEEDLE}" NIL "user" "example.com"))'
                " NIL NIL NIL NIL NIL NIL NIL))\r\n"
            ),
            OK,
        ],
    )
    server.on("LOGIN", [OK])


class _Seen:
    def __init__(self) -> None:
        self.names: list[str] = []


@pytest.fixture
def records() -> Iterator[_Seen]:
    seen = _Seen()
    old = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = old(*args, **kwargs)
        seen.names.append(record.name)
        return record

    root = logging.getLogger()
    level, handlers = root.level, list(root.handlers)
    logging.setLogRecordFactory(factory)
    root.setLevel(logging.DEBUG)
    root.addHandler(logging.StreamHandler(sys.stderr))
    yield seen
    logging.setLogRecordFactory(old)
    root.setLevel(level)
    root.handlers[:] = handlers


def _drive(session: Any) -> list[str]:
    """Every error the 8-bit corpus can provoke, as the strings a caller could surface."""
    surfaced: list[str] = []
    session.login("user@example.com", "pw-not-secret")
    session.list_folders()
    for action in (
        lambda: session.examine("Nope"),
        lambda: session.examine("INBOX"),
        lambda: session.search(["ALL"]),
        lambda: session.fetch([1], ["UID", "ENVELOPE"], caps=_caps(session)),
    ):
        try:
            action()
        except SessionError as exc:
            surfaced.append(
                "".join(traceback.format_exception(exc)) + repr(exc) + str(exc) + repr(exc.args)
            )
    return surfaced


def _caps(session: Any) -> Any:
    from mailferret.imap import LiteralItem, fetch_caps
    from mailferret.limits import Limits

    return fetch_caps(Limits(), LiteralItem.HEADER, 1)


def _imapclient_records(seen: _Seen) -> list[str]:
    return [n for n in seen.names if n.startswith("imapclient")]


def test_8bit_server_text_reaches_no_record_no_output_and_no_error_string(
    server: FakeImapServer, opener: Opener, records: _Seen, capfd: pytest.CaptureFixture[str]
) -> None:
    _script(server)
    session = opener(server)
    surfaced = _drive(session)
    assert surfaced, "the corpus must provoke errors"
    assert _imapclient_records(records) == []
    captured = capfd.readouterr()
    assert captured.err == "" and captured.out == ""
    assert not any("Needle" in text for text in surfaced)


def test_a_warning_pin_would_leak_so_the_pin_is_what_holds(
    server: FakeImapServer, opener: Opener, records: _Seen, capfd: pytest.CaptureFixture[str]
) -> None:
    """The control: with the rejected WARNING pin the same corpus is visible somewhere."""
    _script(server)
    session = opener(server)
    logger = logging.getLogger("imapclient")
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    logger.handlers[:] = []
    logging.getLogger("imapclient.imaplib").propagate = True
    _drive(session)
    captured = capfd.readouterr()
    assert _imapclient_records(records) or captured.err
    pin_imapclient_logging()


def test_pinning_survives_a_second_call_and_repairs_a_changed_logger() -> None:
    logger = logging.getLogger("imapclient")
    logger.setLevel(logging.DEBUG)
    logger.propagate = True
    logger.handlers[:] = []
    pin_imapclient_logging()
    pin_imapclient_logging()
    assert logger.level == logging.CRITICAL + 1
    assert logger.propagate is False
    assert len(logger.handlers) == 1 and isinstance(logger.handlers[0], logging.NullHandler)


def test_a_tagged_bad_after_login_keeps_the_session_and_carries_no_text(
    server: FakeImapServer, opener: Opener
) -> None:
    _script(server)
    session = opener(server)
    session.login("user@example.com", "pw")
    with pytest.raises(CommandRejected):
        session.examine("INBOX")
    session.examine("INBOX")
    with pytest.raises(CommandRejected) as err:
        session.search(["ALL"])
    assert err.value.completion == "BAD"
    assert err.value.__context__ is None and err.value.__cause__ is None
    assert session.usable
    session.noop()


def test_a_drop_is_mapped_to_connection_dropped_and_discards_the_session(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("NOOP", [Close()])
    session = opener(server)
    with pytest.raises(ConnectionDropped):
        session.noop()
    assert not session.usable


def test_an_l12_read_timeout_is_a_timeout_not_a_drop(
    server: FakeImapServer, opener: Opener
) -> None:
    from mailferret.limits import Limits

    server.on("NOOP", [Stall()])
    session = opener(server, Limits(imap_read_seconds=1))
    with pytest.raises(SessionTimeout):
        session.noop()
    assert not session.usable


def test_expire_during_a_stall_is_the_deadline_not_a_drop(
    server: FakeImapServer, opener: Opener
) -> None:
    """The mark comes first: EOF after the shutdown must not look like a reconnectable drop."""
    server.on("NOOP", [Stall()])
    session = opener(server)
    timer = threading.Timer(0.5, session.expire)
    timer.start()
    watchdog = threading.Timer(8.0, session.close)
    watchdog.daemon = True
    watchdog.start()
    try:
        with pytest.raises(DeadlineExceeded):
            session.noop()
    finally:
        timer.cancel()
        watchdog.cancel()
    assert not session.usable


def test_expire_keeps_the_tls_object_attached_so_no_send_can_fall_back_to_cleartext(
    server: FakeImapServer, opener: Opener
) -> None:
    session = opener(server)
    sock = session._imap.sock
    assert sock._sslobj is not None
    session.expire()
    assert sock._sslobj is not None
    with pytest.raises(ReadOnlyViolation):
        session._imap.send(b"A1 NOOP\r\n")


def test_close_shuts_the_raw_socket_down_before_the_client_does(
    server: FakeImapServer, opener: Opener, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = opener(server)
    order: list[str] = []
    real_raw = socket.socket.shutdown
    real_client = session._client.shutdown

    def raw(self: socket.socket, how: int) -> None:
        order.append(f"raw:{self._sslobj is not None}")  # type: ignore[attr-defined]
        real_raw(self, how)

    def client() -> None:
        order.append("client")
        real_client()

    monkeypatch.setattr(socket.socket, "shutdown", raw)
    monkeypatch.setattr(session._client, "shutdown", client)
    session.close()
    assert order[:2] == ["raw:True", "client"]
    assert not session.usable


def test_a_stale_completion_is_not_read_as_the_next_failure(
    server: FakeImapServer, opener: Opener
) -> None:
    """A call that fails before any command is armed must not inherit the previous NO."""
    server.on("EXAMINE", ["{tag} NO nope\r\n"], once=True)
    session = opener(server)
    session.login("user@example.com", "pw")
    with pytest.raises(CommandRejected):
        session.examine("Nope")
    with pytest.raises(TypeError):
        session.search("ALL")  # type: ignore[arg-type]
    with pytest.raises(ServerError) as err:
        session._run(None, lambda c: (_ for _ in ()).throw(IMAPClientError("before any command")))
    assert err.value.session_usable
    assert not isinstance(err.value, CommandRejected)


def test_a_tagged_no_to_login_is_a_login_rejection_and_discards_the_session(
    server: FakeImapServer, opener: Opener
) -> None:
    server.on("LOGIN", ["{tag} NO bad credentials\r\n"])
    session = opener(server)
    with pytest.raises(LoginRejected):
        session.login("user@example.com", "pw")
    assert not session.usable
