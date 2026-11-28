"""``ReadOnlySession``: the type boundary around the one ``IMAPClient`` (A§6).

The raw client is private and never returned. Only read methods exist. Every library failure
is mapped to a fixed-code ``SessionError`` outside the handler, so no server text survives in
``args``, ``__context__`` or ``__cause__`` (T-03, T-21).
"""

from __future__ import annotations

import contextlib
import imaplib
import socket
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from imapclient.exceptions import (  # type: ignore[import-untyped]
    IMAPClientAbortError,
    IMAPClientError,
    ProtocolError,
)

from mailferret.imap.capabilities import Capabilities, parse_capabilities
from mailferret.imap.caps import CommandCaps, default_caps
from mailferret.imap.errors import (
    CommandRejected,
    ConnectionDropped,
    DeadlineExceeded,
    LoginInputRefused,
    LoginRejected,
    ReadOnlyViolation,
    ServerError,
    SessionError,
    SessionTimeout,
)
from mailferret.limits import Limits

T = TypeVar("T")


class ReadOnlySession:
    """An open, guarded session. Not thread-safe except ``expire`` and ``close``."""

    def __init__(self, client: Any, capabilities: Capabilities, limits: Limits) -> None:
        self._client = client
        self._imap = client._imap
        self._limits = limits
        self._mark = threading.Lock()
        self._expired = False
        self.capabilities = capabilities

    @property
    def usable(self) -> bool:
        return not (self._imap.discarded or self._expired)

    def expire(self) -> None:
        """The `L-13` deadline, callable from any thread.

        Marks the session first, then shuts its socket down: the blocked read fails, the worker
        unwinds and the failure is classified as the deadline, never as a drop to reconnect.
        """
        with self._mark:
            self._expired = True
        with contextlib.suppress(Exception):
            self._imap.sock.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        self._imap.discard()
        with contextlib.suppress(Exception):
            self._client.shutdown()

    def logout(self) -> None:
        try:
            self._run(None, lambda c: c.logout())
        finally:
            self.close()

    def login(self, username: str, password: str) -> None:
        """LOGIN with ``str`` only, and only if imaplib can encode it (T-02).

        imaplib's ASCII encoding raises ``UnicodeEncodeError`` carrying the secret, so anything
        else is refused here, before any byte is built; D3 routes it to AUTHENTICATE PLAIN.
        """
        if (
            type(username) is not str
            or type(password) is not str
            or not (username.isascii() and password.isascii())
        ):
            raise LoginInputRefused
        self._run(None, lambda c: c.login(username, password), login=True)

    def plain_login(self, identity: str, password: str) -> None:
        """AUTHENTICATE PLAIN, UTF-8 (RFC 4616); the caller checked ``AUTH=PLAIN``."""
        if type(identity) is not str or type(password) is not str:
            raise LoginInputRefused
        self._run(None, lambda c: c.plain_login(identity, password), login=True)

    def refresh_capabilities(self) -> Capabilities:
        """Re-read after login; the post-login set may differ."""
        self.capabilities = parse_capabilities(self._run(None, lambda c: c.capabilities()))
        return self.capabilities

    def noop(self) -> None:
        self._run(None, lambda c: c.noop())

    def namespace(self) -> Any:
        return self._run(None, lambda c: c.namespace())

    def list_folders(self, directory: str = "", pattern: str = "*") -> Any:
        return self._run(None, lambda c: c.list_folders(directory, pattern))

    def folder_status(self, folder: str, what: list[str]) -> Any:
        return self._run(None, lambda c: c.folder_status(folder, what))

    def examine(self, folder: str) -> Any:
        """EXAMINE: never SELECT."""
        return self._run(None, lambda c: c.select_folder(folder, readonly=True))

    def close_folder(self) -> None:
        self._run(None, lambda c: c.close_folder())

    def search(self, criteria: list[Any], charset: str | None = None) -> Any:
        """``criteria`` is always a list, never a raw string (T-09)."""
        self._criteria(criteria)
        return self._run(None, lambda c: c.search(criteria, charset))

    def sort(self, sort_criteria: list[str], criteria: list[Any], charset: str = "UTF-8") -> Any:
        self._criteria(criteria)
        return self._run(None, lambda c: c.sort(sort_criteria, criteria, charset))

    def thread(self, algorithm: str, criteria: list[Any], charset: str = "UTF-8") -> Any:
        self._criteria(criteria)
        return self._run(None, lambda c: c.thread(algorithm, criteria, charset))

    def fetch(self, messages: Any, data: list[str], *, caps: CommandCaps) -> Any:
        """The caller sets the caps (A§2.2): see ``caps.fetch_caps``."""
        return self._run(caps, lambda c: c.fetch(messages, data))

    @staticmethod
    def _criteria(criteria: object) -> None:
        if not isinstance(criteria, list):
            raise TypeError("criteria must be a list")

    def _run(self, caps: CommandCaps | None, call: Callable[[Any], T], *, login: bool = False) -> T:
        imap = self._imap
        if self._expired:
            raise DeadlineExceeded
        if imap.discarded:
            raise ReadOnlyViolation("session_discarded")
        imap.arm_caps(caps or default_caps(self._limits))
        sent = imap.commands_started
        try:
            return call(self._client)
        except Exception as exc:
            failure = self._classify(exc, login=login, sent=imap.commands_started > sent)
        except BaseException:
            self.close()
            raise
        if not self._keeps(failure):
            self.close()
        raise failure

    @staticmethod
    def _keeps(failure: SessionError) -> bool:
        if isinstance(failure, CommandRejected):
            return True
        return isinstance(failure, ServerError) and failure.session_usable

    def _classify(self, exc: Exception, *, login: bool, sent: bool) -> SessionError:
        completion = self._imap.last_completion
        if isinstance(exc, SessionError):
            return exc
        if self._expired:
            return DeadlineExceeded()
        if isinstance(exc, TimeoutError):
            return SessionTimeout()
        if isinstance(exc, imaplib.IMAP4.abort | IMAPClientAbortError):
            return ConnectionDropped()
        if isinstance(exc, OSError):
            return ConnectionDropped()
        rejected = isinstance(exc, IMAPClientError | imaplib.IMAP4.error) and completion in (
            "NO",
            "BAD",
        )
        if rejected and login:
            return LoginRejected()
        if rejected and completion in ("NO", "BAD"):
            return CommandRejected("NO" if completion == "NO" else "BAD")
        return ServerError(session_usable=isinstance(exc, ProtocolError) or not sent)
