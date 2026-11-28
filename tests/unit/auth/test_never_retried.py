"""T-16, A§2.2: a failed login is never retried, in this process or any other."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from mailferret.auth import PAUSE_SECONDS, AuthFailed, AuthMarkers, LoginPaused, PasswordAuth
from mailferret.credentials import Secret
from mailferret.imap import (
    ConnectionDropped,
    DeadlineExceeded,
    LoginInputRefused,
    LoginRejected,
    ServerError,
    SessionTimeout,
    parse_capabilities,
)
from mailferret.limits import Limits
from tests.support.imap_fake import Close, Stall
from tests.unit.auth.conftest import PASSWORD, Maker, Rig, key_for, logins


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _marker_files(rig: Rig) -> list[Path]:
    return sorted(rig.data_dir.glob("auth-failed-*.json")) if rig.data_dir.exists() else []


@pytest.mark.parametrize("completion", ["NO", "BAD"])
def test_a_rejection_is_one_login_then_auth_failed_without_connecting(
    make_rig: Maker, completion: str
) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", [f"{{tag}} {completion} rejected\r\n"])
    pool = rig.pool()
    with pytest.raises(AuthFailed) as first:
        pool.call(lambda s: s.noop())
    assert first.value.reason == "rejected"
    assert "mailferret auth set acct" in str(first.value)
    assert "mailferret auth retry acct" in str(first.value)
    assert len(_marker_files(rig)) == 1
    for _ in range(3):
        with pytest.raises(AuthFailed) as again:
            pool.call(lambda s: s.noop())
        assert again.value.reason == "blocked"
    assert (rig.server.connections, logins(rig.server)) == (1, 1)


def test_a_second_server_process_does_not_connect_either(make_rig: Maker) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", ["{tag} NO rejected\r\n"])
    with pytest.raises(AuthFailed):
        rig.pool().call(lambda s: s.noop())
    for _ in range(2):
        other = rig.pool()
        with pytest.raises(AuthFailed) as err:
            other.call(lambda s: s.noop())
        assert err.value.reason == "blocked"
    assert (rig.server.connections, logins(rig.server)) == (1, 1)


def test_the_rejection_survives_a_corrected_secret_until_the_marker_is_cleared(
    make_rig: Maker,
) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", ["{tag} NO rejected\r\n"], once=True)
    with pytest.raises(AuthFailed):
        rig.pool().call(lambda s: s.noop())
    rig.store("new-" + PASSWORD)
    with pytest.raises(AuthFailed):
        rig.pool().call(lambda s: s.noop())
    assert rig.server.connections == 1
    AuthMarkers(rig.data_dir).clear(key_for())
    rig.pool().call(lambda s: s.noop())
    assert (rig.server.connections, logins(rig.server)) == (2, 2)


def test_a_drop_after_login_is_one_login_no_reconnect_and_a_time_box(make_rig: Maker) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", [Close()])
    clock = Clock()
    pool = rig.pool(markers=AuthMarkers(rig.data_dir, clock))
    with pytest.raises(ServerError):
        pool.call(lambda s: s.noop())
    assert (rig.server.connections, logins(rig.server)) == (1, 1)
    for process in (pool, rig.pool(markers=AuthMarkers(rig.data_dir, clock))):
        with pytest.raises(LoginPaused) as err:
            process.call(lambda s: s.noop())
        assert err.value.code == "server_error"
    assert (rig.server.connections, logins(rig.server)) == (1, 1)


def test_an_unanswered_login_is_one_login_no_reconnect_and_a_time_box(make_rig: Maker) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", [Stall()])
    pool = rig.pool(limits=Limits(imap_read_seconds=1))
    watchdog = threading.Timer(8.0, pool.expire)
    watchdog.daemon = True
    watchdog.start()
    try:
        with pytest.raises(SessionTimeout):
            pool.call(lambda s: s.noop())
    finally:
        watchdog.cancel()
    assert (rig.server.connections, logins(rig.server)) == (1, 1)
    with pytest.raises(LoginPaused):
        pool.call(lambda s: s.noop())
    assert (rig.server.connections, logins(rig.server)) == (1, 1)


def test_the_time_box_ends_and_a_success_removes_the_marker(make_rig: Maker) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", [Close()], once=True)
    clock = Clock()
    pool = rig.pool(markers=AuthMarkers(rig.data_dir, clock))
    with pytest.raises(ServerError):
        pool.call(lambda s: s.noop())
    clock.now += PAUSE_SECONDS - 1
    with pytest.raises(LoginPaused):
        pool.call(lambda s: s.noop())
    clock.now += 1
    pool.call(lambda s: s.noop())
    assert (rig.server.connections, logins(rig.server)) == (2, 2)
    assert _marker_files(rig) == []


def test_a_rejection_after_a_time_box_becomes_permanent(make_rig: Maker) -> None:
    rig = make_rig()
    rig.server.on("LOGIN", [Close()], once=True)
    rig.server.on("LOGIN", ["{tag} NO rejected\r\n"])
    clock = Clock()
    pool = rig.pool(markers=AuthMarkers(rig.data_dir, clock))
    with pytest.raises(ServerError):
        pool.call(lambda s: s.noop())
    clock.now += PAUSE_SECONDS
    with pytest.raises(AuthFailed):
        pool.call(lambda s: s.noop())
    clock.now += 100 * PAUSE_SECONDS
    with pytest.raises(AuthFailed) as err:
        pool.call(lambda s: s.noop())
    assert err.value.reason == "blocked"
    assert (rig.server.connections, logins(rig.server)) == (2, 2)


def test_a_failure_before_any_login_byte_sets_no_marker(make_rig: Maker) -> None:
    rig = make_rig(secret=None)
    with pytest.raises(Exception, match="no credential"):
        rig.pool().call(lambda s: s.noop())
    assert _marker_files(rig) == []


class _Session:
    """What ``PasswordAuth`` reads of a session; ``login`` fails the way a test says."""

    def __init__(self, failure: Exception, *, sent: bool) -> None:
        self.capabilities = parse_capabilities(["IMAP4rev1"])
        self.login_sent = False
        self._failure, self._sent = failure, sent

    def login(self, login: str, secret: str) -> None:
        self.login_sent = self._sent
        raise self._failure

    plain_login = login


def _auth(tmp_path: Path, failure: Exception, *, sent: bool) -> tuple[PasswordAuth, Any, Any]:
    markers = AuthMarkers(tmp_path / "data")
    auth = PasswordAuth(markers)
    backend = _Backend()
    return auth, _Session(failure, sent=sent), (markers, backend)


class _Backend:
    def get(self, key: Any) -> Secret:
        return Secret(PASSWORD)


@pytest.mark.parametrize("failure", [ConnectionDropped(), SessionTimeout(), DeadlineExceeded()])
def test_an_indeterminate_outcome_marks_only_when_the_command_was_sent(
    tmp_path: Path, failure: Exception
) -> None:
    for sent in (False, True):
        auth, session, (markers, backend) = _auth(tmp_path / str(sent), failure, sent=sent)
        with pytest.raises(type(failure)):
            auth.authenticate(session, key_for(), backend)
        assert markers.blocked(key_for()) == ("indeterminate" if sent else None)


def test_a_refused_input_and_a_rejection_are_not_indeterminate(tmp_path: Path) -> None:
    auth, session, (markers, backend) = _auth(tmp_path, LoginInputRefused(), sent=True)
    with pytest.raises(LoginInputRefused):
        auth.authenticate(session, key_for(), backend)
    assert markers.blocked(key_for()) is None
    auth, session, (markers, backend) = _auth(tmp_path / "r", LoginRejected(), sent=True)
    with pytest.raises(AuthFailed):
        auth.authenticate(session, key_for(), backend)
    assert markers.blocked(key_for()) == "rejected"
