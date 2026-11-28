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

        def open_session() -> ReadOnlySession:
            return connect(
                HOST,
                server.port,
                TlsMode.IMPLICIT,
                ca_file=tls_material.cert_file,
                limits=effective,
            )

        pool = AccountSession(
            open_session, lambda s: s.login("user@example.com", "secret"), effective
        )
        pools.append(pool)
        return pool

    yield make
    for pool in pools:
        pool.close()


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


def test_the_mark_and_the_socket_open_share_one_lock(
    server: FakeImapServer, pool_for: Pool
) -> None:
    """``expire`` cannot slip between the mark check and the connect."""
    pool = pool_for(server)
    entered = threading.Event()
    release = threading.Event()
    real = pool._connect

    def slow_connect() -> ReadOnlySession:
        entered.set()
        release.wait(5)
        return real()

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
    expirer = threading.Thread(target=pool.expire, daemon=True)
    expirer.start()
    time.sleep(0.2)
    assert expirer.is_alive()  # blocked on the same lock as the connect in progress
    release.set()
    worker.join(10)
    expirer.join(10)
    assert server.connections == 1
    assert len(outcome) == 1  # the mark reached the published session
    assert _logins(server) <= 1


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

        def open_session() -> ReadOnlySession:
            attempts.append(1)
            return connect(
                HOST, port, TlsMode.IMPLICIT, ca_file=tls_material.cert_file, limits=limits
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
        lambda: connect(
            HOST, server.port, TlsMode.IMPLICIT, ca_file=tls_material.cert_file, limits=limits
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
