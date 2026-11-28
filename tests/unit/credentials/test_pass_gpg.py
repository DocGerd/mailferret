"""Real ``pass`` and gpg in a throwaway home (A§2.1, A§10 item 7; T-17).

Every path is a private temp directory: the user's gpg home and password store are never read.
Tests skip when ``gpg`` or ``pass`` is missing, except on the Linux CI runner, where that fails.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from mailferret.credentials import (
    CommandBackend,
    CredentialBackendError,
    CredentialLocked,
    CredentialNotFound,
    EntryKey,
    Secret,
    recipe,
)
from mailferret.credentials.bindings import write_binding
from mailferret.credentials.command_backend import _raise_for
from mailferret.credentials.process import minimal_env, run_bounded
from mailferret.limits import Limits

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="pass is a POSIX tool")

KEY = EntryKey("work", "user", "imap.example.com")
ENTRY = "mailferret/work"
SECRET = secrets.token_hex(8)
PASSPHRASE = secrets.token_hex(8)
EXPIRY_WAIT = 6.0
LIMITS = Limits(credential_command_seconds=10)


@dataclass
class Home:
    base: Path
    gnupg: Path
    store: Path
    wrappers: Path
    log: Path
    gpg: str
    pass_: str

    def env(self, *, gpg2: bool = False, **extra: str) -> dict[str, str]:
        path = f"{self.wrappers_dir(gpg2)}{os.pathsep}{os.environ['PATH']}"
        env = {
            "PATH": path,
            "HOME": str(self.base / "home"),
            "GNUPGHOME": str(self.gnupg),
            "PASSWORD_STORE_DIR": str(self.store),
            "LC_ALL": "C",
        }
        env.update(extra)
        return env

    def wrappers_dir(self, gpg2: bool) -> Path:
        return self.wrappers / ("gpg2" if gpg2 else "gpg")

    def gpg_run(self, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            [self.gpg, "--batch", *args],
            input=stdin,
            env=self.env(),
            capture_output=True,
            check=False,
            timeout=60,
        )

    def agent_conf(self, ttl: int) -> None:
        conf = f"allow-loopback-pinentry\ndefault-cache-ttl {ttl}\nmax-cache-ttl {ttl}\n"
        (self.gnupg / "gpg-agent.conf").write_text(conf)
        self.kill_agent()

    def kill_agent(self) -> None:
        subprocess.run(
            ["gpgconf", "--kill", "all"],  # noqa: S607
            env=self.env(),
            capture_output=True,
            check=False,
            timeout=30,
        )

    def unlock(self) -> None:
        entry = self.store / f"{ENTRY}.gpg"
        done = self.gpg_run(
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(self.base / "passphrase"),
            "-d",
            str(entry),
        )
        assert done.returncode == 0
        assert done.stdout.strip() == SECRET.encode()


def _tool_or_skip(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    if os.environ.get("CI") and sys.platform.startswith("linux"):
        pytest.fail(f"{name} is required in CI")
    pytest.skip(f"{name} not available")


def _write_wrapper(directory: Path, name: str, real: str, log: Path) -> None:
    directory.mkdir()
    script = directory / name
    script.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexec "{real}" "$@"\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def home() -> Iterator[Home]:
    gpg = _tool_or_skip("gpg")
    pass_ = _tool_or_skip("pass")
    _tool_or_skip("gpgconf")
    base = Path(tempfile.mkdtemp(prefix="mfp", dir="/tmp"))  # short: agent socket path limit
    (base / "home").mkdir()
    gnupg = base / "g"
    gnupg.mkdir(mode=0o700)
    log = base / "gpg.log"
    wrappers = base / "w"
    wrappers.mkdir()
    _write_wrapper(wrappers / "gpg", "gpg", gpg, log)
    _write_wrapper(wrappers / "gpg2", "gpg2", gpg, log)
    (base / "passphrase").write_text(PASSPHRASE)
    h = Home(base, gnupg, base / "s", wrappers, log, gpg, pass_)
    try:
        h.agent_conf(600)
        made = h.gpg_run(
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(base / "passphrase"),
            "--quick-gen-key",
            "user@example.com",
            "default",
            "default",
            "never",
        )
        assert made.returncode == 0
        init = subprocess.run(  # noqa: S603
            [pass_, "init", "user@example.com"],
            env=h.env(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert init.returncode == 0
        yield h
    finally:
        h.kill_agent()
        shutil.rmtree(base, ignore_errors=True)


def backend(home: Home, environ: dict[str, str]) -> CommandBackend:
    return CommandBackend(
        home.base / "data",
        [home.pass_, "show", ENTRY],
        [home.pass_, "insert", "-m", "-f", ENTRY],
        limits=LIMITS,
        environ=environ,
    )


def run_pass_direct(home: Home, env: dict[str, str]) -> Callable[[], Secret]:
    """A ``get`` through ``run_bounded`` with an explicit env (``GPG_AGENT_INFO`` included)."""

    def get() -> Secret:
        opts = "--quiet"
        result = run_bounded(
            [home.pass_, "show", ENTRY],
            env=minimal_env(env, names=tuple(env)),
            cwd=home.base / "data",
            deadline=10,
            stdout_cap=LIMITS.credential_command_output_bytes,
            stderr_cap=LIMITS.credential_stderr_bytes,
            status_cap=LIMITS.credential_status_bytes,
            status_env=lambda fd: recipe.pass_env(opts, fd),
        )
        _raise_for(result, True)
        return Secret(result.stdout.decode().strip())

    return get


def gpg_calls(home: Home) -> str:
    return home.log.read_text() if home.log.exists() else ""


def drive(home: Home, get: Callable[[], Secret]) -> None:
    """Cold, warm, then expired cache through one ``get``."""
    home.agent_conf(600)
    with pytest.raises(CredentialLocked):
        get()
    home.unlock()
    assert get().reveal() == SECRET
    home.agent_conf(1)
    home.unlock()
    time.sleep(EXPIRY_WAIT)
    with pytest.raises(CredentialLocked):
        get()


@pytest.fixture
def stored(home: Home) -> Home:
    (home.base / "data").mkdir()
    write_binding(home.base / "data", KEY)
    return home


def test_set_get_and_locked_through_the_real_spawn_path(stored: Home) -> None:
    home = stored
    b = backend(home, home.env())
    home.agent_conf(600)
    b.set(KEY, Secret(SECRET))  # encrypting needs no passphrase, so a locked store still sets
    held = [os.open(os.devnull, os.O_RDONLY) for _ in range(12)]  # status fd above 9
    try:
        with pytest.raises(CredentialLocked):
            b.get(KEY)
    finally:
        for fd in held:
            os.close(fd)
    home.unlock()
    assert b.get(KEY).reveal() == SECRET
    assert b.get(KEY).reveal() == SECRET  # the agent survives the post-exit group kill


def test_plain_gpg_branch_warm_and_expired(stored: Home) -> None:
    if shutil.which("gpg2"):
        pytest.skip("gpg2 on PATH selects the other branch")
    home = stored
    backend(home, home.env()).set(KEY, Secret(SECRET))
    drive(home, lambda: backend(home, home.env()).get(KEY))
    assert "--use-agent" not in gpg_calls(home)


def test_gpg2_branch_warm_and_expired(stored: Home) -> None:
    home = stored
    env = home.env(gpg2=True)
    backend(home, env).set(KEY, Secret(SECRET))
    drive(home, lambda: backend(home, env).get(KEY))
    assert "--use-agent" in gpg_calls(home)


def test_gpg_agent_info_branch_warm_and_expired(stored: Home) -> None:
    if shutil.which("gpg2"):
        pytest.skip("gpg2 on PATH selects the other branch")
    home = stored
    backend(home, home.env()).set(KEY, Secret(SECRET))
    env = home.env(GPG_AGENT_INFO=f"{home.gnupg}/S.gpg-agent:0:1")
    home.log.unlink(missing_ok=True)
    drive(home, run_pass_direct(home, env))
    assert "--use-agent" in gpg_calls(home)


def test_missing_entry_is_not_found(stored: Home) -> None:
    home = stored
    home.agent_conf(600)
    with pytest.raises(CredentialNotFound):
        backend(home, home.env()).get(KEY)


def test_a_pass_that_cannot_decrypt_for_another_reason_is_an_error(stored: Home) -> None:
    home = stored
    backend(home, home.env()).set(KEY, Secret(SECRET))
    (home.store / f"{ENTRY}.gpg").write_bytes(b"not an encrypted file")
    with pytest.raises(CredentialBackendError) as info:
        backend(home, home.env()).get(KEY)
    assert not isinstance(info.value, CredentialLocked)
