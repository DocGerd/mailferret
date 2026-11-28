from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

FAKE_KEYRING = """
import hashlib, os, sys, types
store = os.environ["XDG_CONFIG_HOME"]
errors = types.ModuleType("keyring.errors")
for name, base in (("KeyringError", Exception),):
    setattr(errors, name, type(name, (base,), {}))
for name in ("NoKeyringError", "KeyringLocked", "PasswordDeleteError", "InitError"):
    setattr(errors, name, type(name, (errors.KeyringError,), {}))
kr = types.ModuleType("keyring")
class Backend:
    pass
def _path(service, username):
    return os.path.join(store, hashlib.sha256((service + "|" + username).encode()).hexdigest())
def get_keyring():
    return Backend()
def get_password(service, username):
    try:
        with open(_path(service, username)) as f:
            return f.read()
    except FileNotFoundError:
        return None
def set_password(service, username, password):
    with open(_path(service, username), "w") as f:
        f.write(password)
def delete_password(service, username):
    try:
        os.remove(_path(service, username))
    except FileNotFoundError:
        raise errors.PasswordDeleteError()
kr.get_keyring, kr.get_password = get_keyring, get_password
kr.set_password, kr.delete_password = set_password, delete_password
sys.modules["keyring"], sys.modules["keyring.errors"] = kr, errors
from mailferret.credentials.keyring_probe import main
sys.exit(main())
"""


def py(code: str) -> list[str]:
    return [sys.executable, "-I", "-c", code]


def fake_probe(code: str) -> list[str]:
    """argv prefix for a stand-in probe; the parent appends the operation and the entry key."""
    return py(code)


def pid_dead(pid: int, wait: float = 5.0) -> bool:
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if sys.platform == "win32":
            out = subprocess.run(  # noqa: S603
                ["tasklist", "/FI", f"PID eq {pid}"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            if str(pid) not in out:
                return True
        else:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            state = subprocess.run(  # noqa: S603
                ["ps", "-o", "stat=", "-p", str(pid)],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if not state or state.startswith("Z"):
                return True
        time.sleep(0.05)
    return False


def read_pid(path: Path, wait: float = 5.0) -> int:
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if path.exists() and path.read_text():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError("pid file not written")
