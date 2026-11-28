"""Status channel and cleanup of ``run_bounded`` (A§2.1, T-17, L-14, L-28, L-29)."""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

from mailferret.credentials.errors import CredentialBackendError
from mailferret.credentials.process import BoundedResult, minimal_env, run_bounded
from mailferret.limits import CEILINGS
from tests.unit.credentials.helpers import pid_dead, py, read_pid
from tests.unit.credentials.test_process import ERR_CAP, MARGIN, OUT_CAP, run

STATUS_CAP = CEILINGS["credential_status_bytes"]
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX pipes and sessions")


def fd_count() -> int:
    return len(os.listdir("/dev/fd"))


def settle(before: int) -> int:
    end = time.monotonic() + 3
    while fd_count() > before and time.monotonic() < end:
        time.sleep(0.05)
    return fd_count()


def run_status(
    code: str, tmp_path: Path, *, deadline: float = 1.0
) -> tuple[BoundedResult, float, list[int]]:
    """Run ``code`` with a status pipe whose fd number the child reads from ``STATUS_FD``."""
    fds: list[int] = []

    def status_env(fd: int) -> dict[str, str]:
        fds.append(fd)
        return {"STATUS_FD": str(fd)}

    start = time.monotonic()
    result = run_bounded(
        py(code),
        env=minimal_env(os.environ),
        cwd=tmp_path,
        deadline=deadline,
        stdout_cap=OUT_CAP,
        stderr_cap=ERR_CAP,
        status_cap=STATUS_CAP,
        status_env=status_env,
    )
    return result, time.monotonic() - start, fds


def test_status_channel_is_delivered_and_separate_from_stderr(tmp_path: Path) -> None:
    code = (
        "import os, sys\n"
        "os.write(int(os.environ['STATUS_FD']), b'[GNUPG:] ERROR x 1\\n')\n"
        "sys.stderr.write('err')\n"
        "print('out')"
    )
    result, _, fds = run_status(code, tmp_path)
    assert result.status == "exited"
    assert (result.stdout.strip(), result.stderr, result.aux) == (
        b"out",
        b"err",
        b"[GNUPG:] ERROR x 1\n",
    )
    assert fds


def test_status_flood_is_capped_and_memory_bounded(tmp_path: Path) -> None:
    code = (
        "import os\n"
        "fd = int(os.environ['STATUS_FD'])\n"
        "chunk = b's' * 65536\n"
        "for _ in range(1024): os.write(fd, chunk)\n"
        "print('done')"
    )
    tracemalloc.start()
    try:
        result, elapsed, _ = run_status(code, tmp_path, deadline=20.0)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.status == "exited"
    assert len(result.aux) == STATUS_CAP
    assert peak < 4 * 1024 * 1024
    assert elapsed < 20.0


def test_status_pipe_held_by_setsid_descendant_gives_timeout(tmp_path: Path) -> None:
    pid_file = tmp_path / "status-holder.pid"
    code = (
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        f"    open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "os.write(int(os.environ['STATUS_FD']), b'[GNUPG:] ERROR x 1\\n')\n"
        "os.close(1)\n"
        "os.close(2)\n"
        "os._exit(0)"
    )
    try:
        result, elapsed, _ = run_status(code, tmp_path)
        assert result.status == "timeout"
        assert result.aux == b""
        assert elapsed < 1.0 + MARGIN
    finally:
        if pid_file.exists() and pid_file.read_text():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid_file.read_text()), signal.SIGKILL)


def test_status_pipe_does_not_leak_fds(tmp_path: Path) -> None:
    run_status("print('x')", tmp_path)
    before = fd_count()
    run_status("print('x')", tmp_path)
    run_status("import time; time.sleep(60)", tmp_path)
    assert settle(before) <= before


def test_status_channel_needs_an_env_hook(tmp_path: Path) -> None:
    with pytest.raises(CredentialBackendError):
        run_bounded(
            py("pass"),
            env=minimal_env(os.environ),
            cwd=tmp_path,
            deadline=1.0,
            stdout_cap=OUT_CAP,
            stderr_cap=ERR_CAP,
            status_cap=STATUS_CAP,
        )


def test_same_session_leftover_is_killed_after_a_normal_exit(tmp_path: Path) -> None:
    pid_file = tmp_path / "leftover.pid"
    code = (
        "import os, sys, time\n"
        "if os.fork() == 0:\n"
        "    os.close(1)\n"
        "    os.close(2)\n"
        "    open(sys.argv[1], 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "print('x')"
    )
    result, _ = run(code, tmp_path, args=(str(pid_file),))
    pid = read_pid(pid_file)
    assert result.status == "exited"
    assert pid_dead(pid), "same-session process left behind after a normal exit"


def test_start_io_failure_leaks_no_fd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run("print('x')", tmp_path)
    before = fd_count()
    calls = {"n": 0}
    real_start = threading.Thread.start

    def failing_start(self: threading.Thread) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("no threads")
        real_start(self)

    monkeypatch.setattr(threading.Thread, "start", failing_start)
    with pytest.raises(CredentialBackendError):
        run("import time; time.sleep(60)", tmp_path, deadline=5.0, stdin_data=b"x")
    monkeypatch.undo()
    assert settle(before) <= before
