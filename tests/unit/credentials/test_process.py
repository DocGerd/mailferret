from __future__ import annotations

import contextlib
import os
import signal
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

from mailferret.credentials.errors import CredentialBackendError
from mailferret.credentials.process import BoundedResult, minimal_env, run_bounded
from mailferret.limits import CEILINGS
from tests.unit.credentials.helpers import pid_dead, py, read_pid

OUT_CAP = CEILINGS["credential_command_output_bytes"]
ERR_CAP = CEILINGS["credential_stderr_bytes"]
MARGIN = 2.0
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX sessions")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows job object")


def run(
    code_or_argv: str | list[str],
    tmp_path: Path,
    *,
    deadline: float = 1.0,
    stdin_data: bytes | None = None,
    args: tuple[str, ...] = (),
) -> tuple[BoundedResult, float]:
    argv = py(code_or_argv) if isinstance(code_or_argv, str) else code_or_argv
    start = time.monotonic()
    result = run_bounded(
        [*argv, *args],
        env=minimal_env(os.environ),
        cwd=tmp_path,
        deadline=deadline,
        stdout_cap=OUT_CAP,
        stderr_cap=ERR_CAP,
        stdin_data=stdin_data,
    )
    return result, time.monotonic() - start


def test_clean_exit(tmp_path: Path) -> None:
    result, _ = run("print('hello')", tmp_path)
    assert (result.status, result.returncode) == ("exited", 0)
    assert result.stdout.strip() == b"hello"


def test_nonzero_exit(tmp_path: Path) -> None:
    result, _ = run("import sys; sys.exit(7)", tmp_path)
    assert (result.status, result.returncode) == ("exited", 7)


def test_sleeping_child_times_out(tmp_path: Path) -> None:
    result, elapsed = run("import time; time.sleep(60)", tmp_path)
    assert result.status == "timeout"
    assert result.stdout == b""
    assert elapsed < 1.0 + MARGIN


def test_prompting_child_gets_no_stdin(tmp_path: Path) -> None:
    result, elapsed = run("import sys; sys.exit(0 if sys.stdin.read() == '' else 1)", tmp_path)
    assert (result.status, result.returncode) == ("exited", 0)
    assert elapsed < 1.0 + MARGIN


def test_stdout_flood_is_limit_exceeded_and_discarded(tmp_path: Path) -> None:
    code = "import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)"
    result, elapsed = run(code, tmp_path, deadline=5.0)
    assert result.status == "limit_exceeded"
    assert result.stdout == b""
    assert elapsed < 5.0


def test_secret_on_stderr_stays_out_of_repr(tmp_path: Path) -> None:
    code = "import sys; sys.stderr.write('hunter2-secret'); print('ok')"
    result, _ = run(code, tmp_path)
    assert result.stderr == b"hunter2-secret"
    assert "hunter2" not in repr(result) + str(result)


def test_stderr_flood_is_capped_and_memory_bounded(tmp_path: Path) -> None:
    code = (
        "import sys\n"
        "chunk = b'e' * 65536\n"
        "for _ in range(1024): sys.stderr.buffer.write(chunk)\n"
        "sys.stdout.write('done')"
    )
    tracemalloc.start()
    try:
        result, elapsed = run(code, tmp_path, deadline=20.0)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.status == "exited"
    assert result.stdout == b"done"
    assert len(result.stderr) == ERR_CAP
    assert peak < 4 * 1024 * 1024
    assert elapsed < 20.0


def test_stdin_write_reaches_child(tmp_path: Path) -> None:
    code = "import sys; print(len(sys.stdin.buffer.read()))"
    result, _ = run(code, tmp_path, stdin_data=b"x" * 1000)
    assert result.stdout.strip() == b"1000"


def test_child_that_neither_reads_stdin_nor_exits(tmp_path: Path) -> None:
    result, elapsed = run("import time; time.sleep(60)", tmp_path, stdin_data=b"x" * 2_000_000)
    assert result.status == "timeout"
    assert elapsed < 1.0 + MARGIN


def test_child_that_exits_without_reading_stdin(tmp_path: Path) -> None:
    result, elapsed = run("pass", tmp_path, stdin_data=b"x" * 2_000_000)
    assert result.status == "exited"
    assert elapsed < 1.0 + MARGIN


def test_same_session_grandchild_holding_stdout(tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys\n"
        "p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
        "open(sys.argv[1], 'w').write(str(p.pid))\n"
        "print('secret-looking')"
    )
    result, elapsed = run(code, tmp_path, args=(str(pid_file),))
    pid = read_pid(pid_file)
    assert result.status == "timeout"
    assert result.stdout == b""
    assert elapsed < 1.0 + MARGIN
    assert pid_dead(pid), "grandchild left behind"


@posix_only
def test_setsid_descendant_holding_stdout(tmp_path: Path) -> None:
    pid_file = tmp_path / "escaped.pid"
    code = (
        "import os, sys, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    open(sys.argv[1], 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "print('x', flush=True)\n"
        "os._exit(0)"
    )
    try:
        result, elapsed = run(code, tmp_path, args=(str(pid_file),))
        assert result.status == "timeout"
        assert result.stdout == b""
        assert elapsed < 1.0 + MARGIN
    finally:
        if pid_file.exists() and pid_file.read_text():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(pid_file.read_text()), signal.SIGKILL)


@windows_only
def test_job_object_kills_descendant_that_tries_to_break_away(tmp_path: Path) -> None:
    pid_file = tmp_path / "breakaway.pid"
    code = (
        "import subprocess, sys\n"
        "flags = subprocess.CREATE_BREAKAWAY_FROM_JOB\n"
        "try:\n"
        "    p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'],\n"
        "                         creationflags=flags)\n"
        "except OSError:\n"
        "    p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
        "open(sys.argv[1], 'w').write(str(p.pid))\n"
        "print('x', flush=True)"
    )
    result, elapsed = run(code, tmp_path, args=(str(pid_file),))
    pid = read_pid(pid_file)
    assert result.status == "timeout"
    assert elapsed < 1.0 + MARGIN
    assert pid_dead(pid), "descendant escaped the job object"


def test_spawn_failure_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(CredentialBackendError) as info:
        run(["/nonexistent/executable-for-test"], tmp_path)
    assert info.value.args == (CredentialBackendError.message,)


def test_minimal_env_drops_unlisted_variables() -> None:
    env = minimal_env(
        {"PATH": "/bin", "HOME": "/h", "SECRET_THING": "x", "PYTHON_KEYRING_BACKEND": "k"},
        {"PASSWORD_STORE_DIR": "/s"},
    )
    assert "SECRET_THING" not in env
    assert "PYTHON_KEYRING_BACKEND" not in env
    assert env["PASSWORD_STORE_DIR"] == "/s"  # noqa: S105
