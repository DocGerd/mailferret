"""T-02: no secret outlives its LOGIN inside the IMAP object (imaplib's command-log ring)."""

from __future__ import annotations

import base64
import io
import socket
import ssl
from collections import deque
from collections.abc import Iterator
from typing import Any

import pytest

from mailferret.imap.errors import SessionError
from tests.support.imap_fake import FakeImapServer
from tests.unit.imap.conftest import Opener

OK = "{tag} OK done\r\n"
USER = "user@example.com"
PASSWORD = "pw-CANARY-7f3a"  # noqa: S105  # pii-check: ignore


def _forms(password: str, user: str) -> list[bytes]:
    plain = password.encode()
    sasl = b"\0" + user.encode() + b"\0" + plain
    return [
        plain,
        repr(password).encode(),
        base64.b64encode(plain),
        base64.b64encode(sasl),
        base64.b64encode(user.encode() + b"\0" + plain),
    ]


def _is_io(obj: object) -> bool:
    return isinstance(obj, io.IOBase | socket.socket | ssl.SSLObject | ssl.SSLContext)


def _strings(root: object) -> Iterator[bytes]:
    """Every str and bytes reachable from ``root``'s attributes, containers and instances."""
    seen: set[int] = set()
    queue: deque[Any] = deque([root])
    while queue:
        obj = queue.popleft()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if isinstance(obj, bytes | bytearray):
            yield bytes(obj)
        elif isinstance(obj, str):
            yield obj.encode("utf-8", "replace")
        elif isinstance(obj, dict):
            queue.extend(obj.keys())
            queue.extend(obj.values())
        elif isinstance(obj, list | tuple | set | frozenset | deque):
            queue.extend(obj)
        elif hasattr(obj, "__dict__") and not callable(obj) and not _is_io(obj):
            queue.extend(vars(obj).values())


def _assert_clean(imap: Any) -> None:
    haystack = list(_strings(imap))
    for form in _forms(PASSWORD, USER):
        assert not any(form in text for text in haystack), form
    if hasattr(imap, "_cmd_log"):
        assert imap._cmd_log == {}


@pytest.mark.parametrize("method", ["login", "plain_login"])
def test_the_password_is_nowhere_in_the_imap_object_after_login_and_examine(
    server: FakeImapServer, opener: Opener, method: str
) -> None:
    server.on("EXAMINE", [b"* 3 EXISTS\r\n", OK])
    session = opener(server)
    _assert_clean(session._imap)
    getattr(session, method)(USER, PASSWORD)
    _assert_clean(session._imap)
    session.examine("INBOX")
    session.noop()
    _assert_clean(session._imap)
    _assert_clean(session._client)


def test_the_walk_would_find_a_secret_it_is_looking_for() -> None:
    class Holder:
        def __init__(self) -> None:
            self.ring = {0: (f"> {'A1 LOGIN u ' + PASSWORD!r}", 0.0)}

    assert any(PASSWORD.encode() in text for text in _strings(Holder()))


def test_a_rejected_login_leaves_no_secret_either(server: FakeImapServer, opener: Opener) -> None:
    server.on("LOGIN", ["{tag} NO nope\r\n"])
    session = opener(server)
    with pytest.raises(SessionError):
        session.login(USER, PASSWORD)
    _assert_clean(session._imap)
