"""One account's session: the per-call lock, the `L-13` deadline and the reconnect rules (A§2.2).

Only a dropped connection is re-opened, once per call and never in the login phase. A breach,
a guard or liveness failure, an `L-11`/`L-12` timeout and the `L-13` shutdown fail the call
with no further connection attempt. The deadline mark and the check before a socket is opened
share one lock, and a connect in progress is shut down through its ``ConnectHandle``, so the
deadline holds from the TLS handshake on. DNS and the TCP connect before the first socket exists
cannot be interrupted: a socket they open after the deadline is closed unused, nothing sent.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TypeVar

from mailferret.imap.errors import ConnectionDropped, DeadlineExceeded, ServerError, SessionError
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.session import ReadOnlySession
from mailferret.limits import Limits

T = TypeVar("T")


class AccountSession:
    """``connect`` opens an unauthenticated session; ``authenticate`` logs it in (D3)."""

    def __init__(
        self,
        connect: Callable[[ConnectHandle], ReadOnlySession],
        authenticate: Callable[[ReadOnlySession], None],
        limits: Limits,
    ) -> None:
        self._connect = connect
        self._authenticate = authenticate
        self._limits = limits
        self._call = threading.Lock()
        self._state = threading.Lock()
        self._session: ReadOnlySession | None = None
        self._expired = False
        self._token = 0
        self._active = False
        self._connecting: ConnectHandle | None = None

    def call(self, fn: Callable[[ReadOnlySession], T]) -> T:
        """Run ``fn`` on the live session; a drop is re-opened once, nothing else is.

        `L-13` runs from here, so time spent queued for the lock is not given twice.
        """
        deadline = time.monotonic() + self._limits.tool_deadline_seconds
        if not self._call.acquire(timeout=self._limits.tool_deadline_seconds):
            raise DeadlineExceeded
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded
            token = self._begin()
            timer = threading.Timer(remaining, self.expire, [token])
            timer.daemon = True
            timer.start()
            try:
                return self._attempts(fn)
            finally:
                timer.cancel()
                self._end()
        finally:
            self._call.release()

    def expire(self, token: int | None = None) -> None:
        """The `L-13` deadline: mark first, then shut down the session or the connect."""
        with self._state:
            if not self._active or (token is not None and token != self._token):
                return
            self._expired = True
            session = self._session
            connecting = self._connecting
        if session is not None:
            session.expire()
        if connecting is not None:
            connecting.shutdown()

    def close(self) -> None:
        with self._state:
            session, self._session = self._session, None
        if session is not None:
            session.close()

    def _begin(self) -> int:
        with self._state:
            self._token += 1
            self._expired = False
            self._active = True
            return self._token

    def _end(self) -> None:
        with self._state:
            self._active = False

    def _attempts(self, fn: Callable[[ReadOnlySession], T]) -> T:
        failure = ConnectionDropped()
        for _ in range(2):
            session = self._acquire()
            try:
                return fn(session)
            except ConnectionDropped as exc:
                failure = exc
            except SessionError:
                self._release(session)
                raise
            self._release(session)
        raise failure

    def _acquire(self) -> ReadOnlySession:
        with self._state:
            if self._expired:
                raise DeadlineExceeded
            session = self._session
            if session is not None and session.usable:
                return session
            self._session = None
            handle = ConnectHandle()
            self._connecting = handle
        try:
            session = self._connect(handle)
        except BaseException:
            if self._finish_connect(handle, None):
                raise DeadlineExceeded from None
            raise
        if self._finish_connect(handle, session):
            session.close()
            raise DeadlineExceeded
        return self._login(session)

    def _finish_connect(self, handle: ConnectHandle, session: ReadOnlySession | None) -> bool:
        """Publish the session unless the mark is set, under the lock ``expire`` reads both by."""
        with self._state:
            self._connecting = None
            expired = self._expired
            if session is not None and not expired:
                self._session = session
        handle.release()
        return expired

    def _login(self, session: ReadOnlySession) -> ReadOnlySession:
        failure: SessionError | None = None
        try:
            self._authenticate(session)
        except ConnectionDropped:
            failure = ServerError(session_usable=False)
        except BaseException:
            self._discard(session)
            raise
        if failure is not None:
            self._discard(session)
            raise failure
        return session

    def _discard(self, session: ReadOnlySession) -> None:
        """A session whose login failed is never reused, even when its socket still works."""
        with self._state:
            if self._session is session:
                self._session = None
        session.close()

    def _release(self, session: ReadOnlySession) -> None:
        """Drop ``session`` from the cache unless it survived its failure."""
        if session.usable:
            return
        with self._state:
            if self._session is session:
                self._session = None
        session.close()
