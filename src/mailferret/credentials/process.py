"""Bounded credential subprocess: daemon readers, bounded joins, fail-closed return (A§2.1, T-17).

The return time never depends on the readers ending: a descendant that leaves the process
group (``setsid``) may keep the pipes, so at the bound the parent closes its pipe ends.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mailferret.credentials.errors import CredentialBackendError
from mailferret.credentials.jobobject import JobObject

_USE_JOB = sys.platform == "win32"

Status = Literal["exited", "timeout", "limit_exceeded"]

_CHUNK = 64 * 1024
_JOIN_GRACE = 0.2
_POLL = 0.01

_POSIX_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
_WINDOWS_ENV = ("SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATH", "TEMP", "TMP")
_LINUX_ENV = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


@dataclass(frozen=True)
class BoundedResult:
    status: Status
    returncode: int | None
    # Hidden from repr: stdout may be a secret and stderr may contain one.
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)


def minimal_env(
    environ: Mapping[str, str],
    extra: Mapping[str, str] | None = None,
    *,
    names: Sequence[str] = (),
) -> dict[str, str]:
    base = _WINDOWS_ENV if sys.platform == "win32" else _POSIX_ENV
    env = {k: environ[k] for k in (*base, *names) if k in environ}
    if extra:
        env.update(extra)
    return env


def session_env_names() -> tuple[str, ...]:
    return _LINUX_ENV if sys.platform.startswith("linux") else ()


class _Reader:
    """Reads its own duplicate of the pipe fd, which only this thread closes."""

    def __init__(self, fd: int, cap: int, *, truncate: bool) -> None:
        self._fd = os.dup(fd)
        self._cap = cap
        self._truncate = truncate
        self.data = bytearray()
        self.eof = threading.Event()
        self.breach = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self._loop()
        finally:
            with contextlib.suppress(OSError):
                os.close(self._fd)

    def _loop(self) -> None:
        while not self.stop.is_set():
            try:
                chunk = os.read(self._fd, _CHUNK)
            except OSError:
                return
            if self.stop.is_set():
                return
            if not chunk:
                self.eof.set()
                return
            room = max(self._cap - len(self.data), 0)
            self.data += chunk[:room]
            if not self._truncate and len(chunk) > room:
                self.breach.set()
                return


def _write_all(fd: int, data: bytes) -> None:
    """Write on an owned duplicate and close it, which is what ends the child's stdin."""
    view = memoryview(data)
    try:
        with contextlib.suppress(OSError):
            while view:
                view = view[os.write(fd, view) :]
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _kill(proc: subprocess.Popen[bytes], job: JobObject | None) -> None:
    if job is not None:
        job.terminate()
    elif sys.platform != "win32":
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()


def _has_exited(proc: subprocess.Popen[bytes]) -> bool:
    """Detect exit without reaping where possible, so ``killpg`` never meets a recycled group."""
    waitid: Any = getattr(os, "waitid", None)
    if waitid is None:
        return proc.poll() is not None
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT  # type: ignore[attr-defined,unused-ignore]
    try:
        return waitid(os.P_PID, proc.pid, flags) is not None  # type: ignore[attr-defined,unused-ignore]
    except ChildProcessError:
        return True


def _spawn(
    argv: Sequence[str], env: Mapping[str, str], cwd: Path, *, stdin_pipe: bool
) -> subprocess.Popen[bytes]:
    stdin = subprocess.PIPE if stdin_pipe else subprocess.DEVNULL
    try:
        if sys.platform == "win32":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            return subprocess.Popen(  # noqa: S603
                list(argv),
                shell=False,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=dict(env),
                cwd=cwd,
                bufsize=0,
                creationflags=flags,
            )
        return subprocess.Popen(  # noqa: S603
            list(argv),
            shell=False,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=dict(env),
            cwd=cwd,
            bufsize=0,
            start_new_session=True,
        )
    except (OSError, ValueError):
        raise CredentialBackendError from None


def _close_pipes(proc: subprocess.Popen[bytes]) -> None:
    for pipe in (proc.stdout, proc.stderr, proc.stdin):
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


def _start_io(
    proc: subprocess.Popen[bytes], stdout_cap: int, stderr_cap: int, stdin_data: bytes | None
) -> tuple[_Reader, _Reader]:
    if proc.stdout is None or proc.stderr is None:
        raise ValueError("pipes")
    out = _Reader(proc.stdout.fileno(), stdout_cap, truncate=False)
    err = _Reader(proc.stderr.fileno(), stderr_cap, truncate=True)
    writer_fd: int | None = None
    if stdin_data is not None and proc.stdin is not None:
        writer_fd = os.dup(proc.stdin.fileno())
        proc.stdin.close()
    out.thread.start()
    err.thread.start()
    if writer_fd is not None and stdin_data is not None:
        threading.Thread(target=_write_all, args=(writer_fd, stdin_data), daemon=True).start()
    return out, err


def run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    deadline: float,
    stdout_cap: int,
    stderr_cap: int,
    stdin_data: bytes | None = None,
) -> BoundedResult:
    """Run ``argv`` and return within ``deadline`` plus a bounded grace, whatever the tree does.

    ``exited`` carries the exit status and buffers. ``timeout`` (killed at the deadline, or a
    reader not at EOF at the return) and ``limit_exceeded`` (stdout over ``stdout_cap``) discard
    both buffers.
    """
    end = time.monotonic() + deadline
    proc = _spawn(argv, env, cwd, stdin_pipe=stdin_data is not None)
    job: JobObject | None = None
    if _USE_JOB:
        job = JobObject.create()
        if job is None or not job.assign(int(getattr(proc, "_handle", 0))):
            if job is not None:
                job.close()
            _kill(proc, None)
            _close_pipes(proc)
            raise CredentialBackendError from None
    try:
        readers = _start_io(proc, stdout_cap, stderr_cap, stdin_data)
    except (OSError, ValueError):
        _kill(proc, job)
        _close_pipes(proc)
        raise CredentialBackendError from None
    out, err = readers

    status: Status = "exited"
    while True:
        if out.breach.is_set():
            status = "limit_exceeded"
            break
        if _has_exited(proc):
            break
        if time.monotonic() >= end:
            status = "timeout"
            break
        time.sleep(_POLL)

    if status == "exited":
        for reader in readers:
            reader.thread.join(max(0.0, end - time.monotonic()))
        if out.breach.is_set():
            status = "limit_exceeded"
        elif not all(r.eof.is_set() for r in readers):
            status = "timeout"

    if status != "exited":
        _kill(proc, job)
    for reader in readers:
        reader.stop.set()
    if status != "exited":
        for reader in readers:
            reader.thread.join(_JOIN_GRACE)
    try:
        returncode: int | None = proc.wait(timeout=_JOIN_GRACE)
    except subprocess.TimeoutExpired:
        returncode = None
    _close_pipes(proc)
    if job is not None:
        job.close()
    if status != "exited":
        return BoundedResult(status, returncode)
    return BoundedResult(status, returncode, bytes(out.data), bytes(err.data))
