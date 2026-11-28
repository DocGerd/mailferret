"""A§2.2 Reconnect and Deadline: what is re-opened, what is not, and when no socket may open."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from mailferret.imap import (
    CommandRejected,
    ConnectError,
    ConnectionDropped,
    DeadlineExceeded,
    LimitBreach,
    LiteralItem,
    LoginRejected,
    ReadOnlySession,
    ReadOnlyViolation,
    ServerError,
    SessionTimeout,
    TlsMode,
    connect,
    fetch_caps,
)
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.lifecycle import AccountSession
from mailferret.limits import Limits
from tests.support.imap_fake import Close, FakeImapServer, Flood, Literal, Stall, TlsMaterial
from tests.unit.imap.conftest import CAPS, HOST

OK = "{tag} OK done\r\n"
EXAMINE = [b"* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n", OK]

Pool = Callable[..., AccountSession]


def _logins(server: FakeImapServer) -> int:
    return sum(1 for c in server.commands if c.verb in {"LOGIN", "AUTHENTICATE"})


@pytest.fixture
def server(tls_material: TlsMaterial) -> Iterator[FakeImapServer]:
    with FakeImapServer(tls=tls_material, implicit_tls=True, capabilities=CAPS) as srv:
        srv.on("EXAMINE", EXAMINE)
        yield srv


@pytest.fixture
def pool_for(tls_material: TlsMaterial) -> Iterator[Pool]:
    pools: list[AccountSession] = []

    def make(server: FakeImapServer, limits: Limits | None = None) -> AccountSession:
        effective = limits or Limits()

        def open_session(handle: ConnectHandle) -> ReadOnlySession:
            return connect(
                HOST,
                server.port,
                TlsMode.IMPLICIT,
                ca_file=tls_material.cert_file,
                limits=effective,
                handle=handle,
            )

        pool = AccountSession(
            open_session, lambda s: s.login("user@example.com", "secret"), effective
        )
        pools.append(pool)
        return pool

    yield make
    for pool in pools:
        pool.close()


def _pool(
    port: int, tls_material: TlsMaterial, limits: Limits, mode: TlsMode = TlsMode.IMPLICIT
) -> AccountSession:
    pool = AccountSession(
        lambda handle: connect(
            HOST, port, mode, ca_file=tls_material.cert_file, limits=limits, handle=handle
        ),
        lambda s: s.login("user@example.com", "secret"),
        limits,
    )
    return pool


def _watchdog(pool: AccountSession, seconds: float = 8.0) -> threading.Timer:
    """Fails a stall test fast instead of hanging if a timeout is removed."""
    timer = threading.Timer(seconds, pool.expire)
    timer.daemon = True
    timer.start()
    return timer


def test_a_session_is_opened_once_and_reused(server: FakeImapServer, pool_for: Pool) -> None:
    pool = pool_for(server)
    pool.call(lambda s: s.noop())
    pool.call(lambda s: s.noop())
    assert server.connections == 1
    assert _logins(server) == 1


def test_a_dropped_connection_is_reopened_once_per_call(
    server: FakeImapServer, pool_for: Pool
) -> None:
    server.on("NOOP", [Close()], once=True)
    pool = pool_for(server)
    pool.call(lambda s: s.noop())
    assert server.connections == 2
    assert _logins(server) == 2


def test_a_second_drop_in_the_same_call_is_not_retried(
    server: FakeImapServer, pool_for: Pool
) -> None:
    server.on("NOOP", [Close()])
    pool = pool_for(server)
    with pytest.raises(ConnectionDropped):
        pool.call(lambda s: s.noop())
    assert server.connections == 2
    assert _logins(server) == 2


def test_a_breach_is_never_reconnected(server: FakeImapServer, pool_for: Pool) -> None:
    server.on("UID FETCH", [Literal(3 * 1024 * 1024), OK], once=True)
    pool = pool_for(server)
    caps = fetch_caps(Limits(), LiteralItem.HEADER, 1)

    def fetch(s: ReadOnlySession) -> Any:
        s.examine("INBOX")
        return s.fetch([1], ["BODY.PEEK[HEADER]"], caps=caps)

    with pytest.raises(LimitBreach):
        pool.call(fetch)
    assert server.connections == 1
    assert _logins(server) == 1
    server.on("UID FETCH", [b"* 1 FETCH (UID 1 FLAGS ())\r\n", OK])
    assert pool.call(fetch)
    assert server.connections == 2


def test_an_overlong_line_is_never_reconnected(server: FakeImapServer, pool_for: Pool) -> None:
    server.on("NOOP", [Flood(100_000, terminate=True), OK], once=True)
    pool = pool_for(server, Limits(max_line_bytes=4096))
    with pytest.raises(LimitBreach):
        pool.call(lambda s: s.noop())
    assert (server.connections, _logins(server)) == (1, 1)


def test_a_guard_violation_is_never_reconnected_and_the_next_call_gets_a_new_session(
    server: FakeImapServer, pool_for: Pool
) -> None:
    pool = pool_for(server)
    with pytest.raises(ReadOnlyViolation):
        pool.call(lambda s: s._imap.send(b"A9 STORE 1 +FLAGS (\\Seen)\r\n"))
    assert (server.connections, _logins(server)) == (1, 1)
    pool.call(lambda s: s.noop())
    assert (server.connections, _logins(server)) == (2, 2)


def test_an_l12_read_timeout_is_never_reconnected(server: FakeImapServer, pool_for: Pool) -> None:
    server.on("NOOP", [Stall()], once=True)
    pool = pool_for(server, Limits(imap_read_seconds=1))
    watchdog = _watchdog(pool)
    try:
        with pytest.raises(SessionTimeout):
            pool.call(lambda s: s.noop())
    finally:
        watchdog.cancel()
    assert (server.connections, _logins(server)) == (1, 1)


def test_an_unanswered_login_is_one_login_and_no_reconnect(
    tls_material: TlsMaterial, pool_for: Pool
) -> None:
    with FakeImapServer(tls=tls_material, implicit_tls=True, capabilities=CAPS) as server:
        server.on("LOGIN", [Stall()])
        pool = pool_for(server, Limits(imap_read_seconds=1))
        watchdog = _watchdog(pool)
        try:
            with pytest.raises(SessionTimeout):
                pool.call(lambda s: s.noop())
        finally:
            watchdog.cancel()
        assert (server.connections, _logins(server)) == (1, 1)


def test_a_drop_after_login_was_sent_is_not_reconnected(
    tls_material: TlsMaterial, pool_for: Pool
) -> None:
    with FakeImapServer(tls=tls_material, implicit_tls=True, capabilities=CAPS) as server:
        server.on("LOGIN", [Close()])
        pool = pool_for(server)
        with pytest.raises(ServerError):
            pool.call(lambda s: s.noop())
        assert (server.connections, _logins(server)) == (1, 1)


def test_the_l13_deadline_shuts_the_socket_down_and_the_next_call_succeeds(
    server: FakeImapServer, pool_for: Pool
) -> None:
    """Stall mid-literal: the blocked read fails, the worker unwinds, the lock is released."""
    server.on("UID FETCH", [Literal(100, declared=100_000), Stall()], once=True)
    limits = Limits(tool_deadline_seconds=1)
    pool = pool_for(server, limits)
    caps = fetch_caps(limits, LiteralItem.HEADER, 1)

    def fetch(s: ReadOnlySession) -> Any:
        s.examine("INBOX")
        return s.fetch([1], ["BODY.PEEK[HEADER]"], caps=caps)

    start = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        pool.call(fetch)
    assert time.monotonic() - start < 10
    assert (server.connections, _logins(server)) == (1, 1)
    server.on("UID FETCH", [b"* 1 FETCH (UID 1 FLAGS ())\r\n", OK])
    assert pool.call(fetch)
    assert (server.connections, _logins(server)) == (2, 2)


def test_a_marked_session_is_never_reopened_after_a_drop(
    server: FakeImapServer, pool_for: Pool
) -> None:
    pool = pool_for(server)
    pool.call(lambda s: s.noop())

    def expire_then_drop(s: ReadOnlySession) -> None:
        pool.expire()
        raise ConnectionDropped

    with pytest.raises(DeadlineExceeded):
        pool.call(expire_then_drop)
    assert server.connections == 1


def test_no_socket_is_opened_once_the_mark_is_set(server: FakeImapServer, pool_for: Pool) -> None:
    pool = pool_for(server)
    pool._begin()
    pool.expire()
    with pytest.raises(DeadlineExceeded):
        pool._acquire()
    assert server.connections == 0


def test_expire_does_not_wait_for_a_connect_and_a_late_socket_carries_nothing(
    server: FakeImapServer, pool_for: Pool
) -> None:
    """The mark and the socket registration share one lock; ``expire`` never waits on a connect."""
    pool = pool_for(server)
    entered = threading.Event()
    release = threading.Event()
    real = pool._connect

    def slow_connect(handle: ConnectHandle) -> ReadOnlySession:
        entered.set()
        release.wait(5)
        return real(handle)

    pool._connect = slow_connect  # type: ignore[method-assign]
    pool._begin()
    outcome: list[BaseException] = []

    def acquire() -> None:
        try:
            pool._acquire()
        except DeadlineExceeded as exc:
            outcome.append(exc)

    worker = threading.Thread(target=acquire, daemon=True)
    worker.start()
    assert entered.wait(5)
    start = time.monotonic()
    pool.expire()
    assert time.monotonic() - start < 1
    release.set()
    worker.join(10)
    assert len(outcome) == 1
    assert pool._session is None
    assert server.commands == []  # no handshake byte, no CAPABILITY, no LOGIN
    assert server.wire == []


def test_a_silent_server_is_cut_at_l13_not_at_l11(tls_material: TlsMaterial) -> None:
    limits = Limits(tool_deadline_seconds=1)
    assert limits.imap_connect_seconds > 5
    with socket.create_server((HOST, 0)) as silent:
        pool = _pool(silent.getsockname()[1], tls_material, limits)
        start = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            pool.call(lambda s: s.noop())
        assert time.monotonic() - start < 4


def test_a_server_dripping_the_greeting_is_cut_at_l13(tls_material: TlsMaterial) -> None:
    """One byte per interval, each inside L-12: no per-read timeout ever fires."""
    stop = threading.Event()
    ctx = tls_material.server_context()

    with socket.create_server((HOST, 0)) as listener:
        port = listener.getsockname()[1]

        def drip() -> None:
            try:
                conn, _ = listener.accept()
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    while not stop.is_set():
                        tls.sendall(b"*")
                        stop.wait(0.2)
            except OSError:
                return

        thread = threading.Thread(target=drip, daemon=True)
        thread.start()
        limits = Limits(tool_deadline_seconds=2, imap_read_seconds=1, imap_connect_seconds=1)
        pool = _pool(port, tls_material, limits)
        start = time.monotonic()
        try:
            with pytest.raises(DeadlineExceeded):
                pool.call(lambda s: s.noop())
        finally:
            stop.set()
        assert 1.5 < time.monotonic() - start < 6
        thread.join(5)


def test_a_stalled_starttls_handshake_is_cut_at_l13(tls_material: TlsMaterial) -> None:
    """The handshake wraps and detaches the plain socket; the handle must still reach it."""
    hold = threading.Event()
    with FakeImapServer(tls=tls_material, capabilities=CAPS) as server:
        server.starttls_hold = hold
        pool = _pool(server.port, tls_material, Limits(tool_deadline_seconds=1), TlsMode.STARTTLS)
        start = time.monotonic()
        try:
            with pytest.raises(DeadlineExceeded):
                pool.call(lambda s: s.noop())
        finally:
            hold.set()
        assert time.monotonic() - start < 4
        assert _logins(server) == 0


def test_a_dripping_response_is_cut_at_l13(server: FakeImapServer, pool_for: Pool) -> None:
    class Drip:
        def __iter__(self) -> Iterator[bytes]:
            for _ in range(100):
                yield b"*"
                time.sleep(0.2)

    server.on("NOOP", lambda cmd: Drip())  # type: ignore[arg-type, return-value]
    limits = Limits(tool_deadline_seconds=2, imap_read_seconds=1)
    pool = pool_for(server, limits)
    start = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        pool.call(lambda s: s.noop())
    assert time.monotonic() - start < 5
    assert (server.connections, _logins(server)) == (1, 1)


def test_a_queued_call_never_runs_past_l13_in_total(server: FakeImapServer, pool_for: Pool) -> None:
    server.on("NOOP", [Stall()], once=True)
    limits = Limits(tool_deadline_seconds=2)
    pool = pool_for(server, limits)
    held = threading.Event()

    def hold(s: ReadOnlySession) -> None:
        held.set()
        time.sleep(1.0)

    first = threading.Thread(target=pool.call, args=(hold,), daemon=True)
    first.start()
    assert held.wait(10)
    start = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        pool.call(lambda s: s.noop())
    elapsed = time.monotonic() - start
    first.join(5)
    assert elapsed < 2.6  # the queue wait counts: ~2 s from entry, not ~1 s + 2 s


def test_calls_on_one_account_do_not_overlap(server: FakeImapServer, pool_for: Pool) -> None:
    pool = pool_for(server)
    active: list[int] = []
    overlap: list[bool] = []

    def work(s: ReadOnlySession) -> None:
        active.append(1)
        overlap.append(len(active) > 1)
        time.sleep(0.1)
        s.noop()
        active.pop()

    threads = [threading.Thread(target=pool.call, args=(work,)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert not any(overlap)
    assert server.connections == 1


@pytest.mark.parametrize("completion", ["NO", "BAD"])
def test_a_rejected_login_is_one_login_discards_the_session_and_is_not_retried(
    tls_material: TlsMaterial, pool_for: Pool, completion: str
) -> None:
    with FakeImapServer(tls=tls_material, implicit_tls=True, capabilities=CAPS) as server:
        server.on("LOGIN", ["{tag} " + completion + " nope\r\n"])
        pool = pool_for(server)
        with pytest.raises(LoginRejected):
            pool.call(lambda s: s.noop())
        assert (server.connections, _logins(server)) == (1, 1)
        assert pool._session is None


def test_an_l11_connect_timeout_is_one_attempt_and_no_login(
    tls_material: TlsMaterial, pool_for: Pool
) -> None:
    with socket.create_server((HOST, 0)) as silent:
        port = silent.getsockname()[1]
        limits = Limits(imap_connect_seconds=1)
        attempts: list[int] = []

        def open_session(handle: ConnectHandle) -> ReadOnlySession:
            attempts.append(1)
            return connect(
                HOST,
                port,
                TlsMode.IMPLICIT,
                ca_file=tls_material.cert_file,
                limits=limits,
                handle=handle,
            )

        logins: list[int] = []
        pool = AccountSession(open_session, lambda s: logins.append(1), limits)
        with pytest.raises(ConnectError) as err:
            pool.call(lambda s: s.noop())
        assert err.value.code == "timeout"
        assert (len(attempts), len(logins)) == (1, 0)


def test_a_drop_raised_from_the_authenticator_is_a_login_phase_failure_not_a_retry(
    server: FakeImapServer, tls_material: TlsMaterial
) -> None:
    attempts: list[int] = []

    def drop(session: ReadOnlySession) -> None:
        attempts.append(1)
        raise ConnectionDropped

    limits = Limits()
    pool = AccountSession(
        lambda handle: connect(
            HOST,
            server.port,
            TlsMode.IMPLICIT,
            ca_file=tls_material.cert_file,
            limits=limits,
            handle=handle,
        ),
        drop,
        limits,
    )
    try:
        with pytest.raises(ServerError):
            pool.call(lambda s: s.noop())
    finally:
        pool.close()
    assert (server.connections, len(attempts)) == (1, 1)


def test_a_tagged_bad_to_a_search_literal_is_a_rejection_not_a_drop(
    tls_material: TlsMaterial, pool_for: Pool
) -> None:
    """The issue #7 shape: imapclient raises an abort when the tagged BAD replaces the ``+``."""
    with FakeImapServer(
        tls=tls_material, implicit_tls=True, capabilities=CAPS, literals=False
    ) as server:
        pool = pool_for(server)
        with pytest.raises(CommandRejected) as err:
            pool.call(lambda s: s.search(["TEXT", "café"], "UTF-8"))
        assert err.value.completion == "BAD"
        assert (server.connections, _logins(server)) == (1, 1)
        pool.call(lambda s: s.noop())
        assert (server.connections, _logins(server)) == (1, 1)


def test_a_garbage_reply_is_a_server_error_never_a_reconnect(
    server: FakeImapServer, pool_for: Pool
) -> None:
    server.on("NOOP", [b"garbage\r\n", OK], once=True)
    pool = pool_for(server)
    with pytest.raises(ServerError) as err:
        pool.call(lambda s: s.noop())
    assert not err.value.session_usable
    assert (server.connections, _logins(server)) == (1, 1)
    pool.call(lambda s: s.noop())
    assert (server.connections, _logins(server)) == (2, 2)


def test_a_connection_closed_between_calls_is_reopened_once(
    server: FakeImapServer, pool_for: Pool
) -> None:
    server.on("NOOP", [OK, Close()], once=True)
    pool = pool_for(server)
    pool.call(lambda s: s.noop())
    pool.call(lambda s: s.noop())
    assert (server.connections, _logins(server)) == (2, 2)


def test_a_partial_response_left_behind_is_not_attributed_to_the_next_command(
    server: FakeImapServer, pool_for: Pool
) -> None:
    """imapclient can fail on a NOOP's untagged lines before it reads the tagged completion."""
    server.on(
        "NOOP",
        [b"* 9 EXISTS (\r\n", b"* 2 FETCH (UID 2 FLAGS (\\Flagged))\r\n", OK],
        once=True,
    )
    server.on("UID FETCH", [b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n", OK])
    pool = pool_for(server)
    caps = fetch_caps(Limits(), None, 2)

    def fetch(s: ReadOnlySession) -> Any:
        s.examine("INBOX")
        return s.fetch([1, 2], ["FLAGS"], caps=caps)

    with pytest.raises(ServerError) as err:
        pool.call(lambda s: s.noop())
    assert not err.value.session_usable
    assert pool._session is None
    assert list(pool.call(fetch)) == [1]
