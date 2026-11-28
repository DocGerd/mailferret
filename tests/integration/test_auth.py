"""PasswordAuth against GreenMail (auth enabled): LOGIN, and T-16 across separate processes.

AUTHENTICATE PLAIN does not authenticate on GreenMail (V2), so that leg runs on the fake server.
The server's wire is TLS, so the processes count their own connects and LOGIN calls.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mailferret.auth import AuthFailed, AuthMarkers, PasswordAuth, guard_connect
from mailferret.credentials import EntryKey, Secret
from mailferret.credentials.memory import MemoryBackend
from mailferret.imap import ReadOnlySession, TlsMode
from mailferret.imap import connect as mf_connect
from mailferret.imap.lifecycle import AccountSession
from mailferret.limits import Limits
from tests.integration.conftest import ACCOUNTS, HOST, IMAPS_PORT, Greenmail

ALICE = "alice@example.com"
WRONG = "wrong-password-7f3a"  # pii-check: ignore

PROCESS = """
import json, sys
from pathlib import Path
from mailferret.auth import AuthError, AuthFailed, AuthMarkers, PasswordAuth, guard_connect
from mailferret.credentials import EntryKey, Secret
from mailferret.credentials.memory import MemoryBackend
from mailferret.imap import ReadOnlySession, TlsMode, connect
from mailferret.imap.lifecycle import AccountSession
from mailferret.limits import Limits

data_dir, ca_file, host, port, login, secret, calls = sys.argv[1:8]
counts = {"connects": 0, "logins": 0}
real_login = ReadOnlySession.login

def counted_login(self, user, password):
    counts["logins"] += 1
    return real_login(self, user, password)

ReadOnlySession.login = counted_login
key = EntryKey("acct", login, host)
backend = MemoryBackend()
backend.set(key, Secret(secret))
auth = PasswordAuth(AuthMarkers(Path(data_dir)))
limits = Limits()

def open_session(handle):
    counts["connects"] += 1
    return connect(host, int(port), TlsMode.IMPLICIT, ca_file=Path(ca_file), limits=limits,
                   handle=handle)

pool = AccountSession(
    guard_connect(auth, key, open_session),
    lambda session: auth.authenticate(session, key, backend),
    limits,
)
reasons = []
for _ in range(int(calls)):
    try:
        pool.call(lambda s: s.noop())
        reasons.append("ok")
    except AuthFailed as exc:
        reasons.append(exc.reason)
pool.close()
print(json.dumps({**counts, "reasons": reasons}))
"""


def _process(data_dir: Path, greenmail: Greenmail, secret: str, calls: int) -> dict[str, object]:
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            PROCESS,
            str(data_dir),
            str(greenmail.ca_file),
            HOST,
            str(IMAPS_PORT),
            ALICE,
            secret,
            str(calls),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-500:]
    assert secret not in done.stdout + done.stderr
    result: dict[str, object] = json.loads(done.stdout)
    return result


def test_password_auth_logs_in_with_login(greenmail: Greenmail, tmp_path: Path) -> None:
    key = EntryKey("acct", ALICE, HOST)
    backend = MemoryBackend()
    backend.set(key, Secret(ACCOUNTS[ALICE]))
    auth = PasswordAuth(AuthMarkers(tmp_path))
    limits = Limits()

    def open_session(handle: object) -> ReadOnlySession:
        return mf_connect(
            HOST, IMAPS_PORT, TlsMode.IMPLICIT, ca_file=greenmail.ca_file, limits=limits
        )

    pool = AccountSession(
        guard_connect(auth, key, open_session),
        lambda session: auth.authenticate(session, key, backend),
        limits,
    )
    try:
        pool.call(lambda s: s.examine("INBOX"))
    finally:
        pool.close()
    assert not list(tmp_path.glob("auth-failed-*"))


def test_a_wrong_password_is_one_login_across_calls_and_processes(
    greenmail: Greenmail, tmp_path: Path
) -> None:
    first = _process(tmp_path, greenmail, WRONG, calls=3)
    assert first["reasons"] == ["rejected", "blocked", "blocked"]
    assert (first["connects"], first["logins"]) == (1, 1)
    for _ in range(2):
        later = _process(tmp_path, greenmail, WRONG, calls=2)
        assert later["reasons"] == ["blocked", "blocked"]
        assert (later["connects"], later["logins"]) == (0, 0)
    assert len(list(tmp_path.glob("auth-failed-*.json"))) == 1


def test_clearing_the_marker_allows_one_new_login(greenmail: Greenmail, tmp_path: Path) -> None:
    assert _process(tmp_path, greenmail, WRONG, calls=1)["reasons"] == ["rejected"]
    AuthMarkers(tmp_path).clear(EntryKey("acct", ALICE, HOST))
    again = _process(tmp_path, greenmail, ACCOUNTS[ALICE], calls=2)
    assert again["reasons"] == ["ok", "ok"]
    assert (again["connects"], again["logins"]) == (1, 1)


def test_the_failure_is_typed_and_names_the_command(greenmail: Greenmail, tmp_path: Path) -> None:
    key = EntryKey("acct", ALICE, HOST)
    backend = MemoryBackend()
    backend.set(key, Secret(WRONG))
    auth = PasswordAuth(AuthMarkers(tmp_path))
    limits = Limits()
    session = mf_connect(
        HOST, IMAPS_PORT, TlsMode.IMPLICIT, ca_file=greenmail.ca_file, limits=limits
    )
    try:
        with pytest.raises(AuthFailed) as err:
            auth.authenticate(session, key, backend)
    finally:
        session.close()
    assert err.value.reason == "rejected"
    assert WRONG not in str(err.value)
    assert "mailferret auth set acct" in str(err.value)
