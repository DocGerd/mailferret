"""Runs the PDF worker in a bounded subprocess and validates its result (T-06, A§10 item 10).

The worker gets the PDF on stdin and nothing else: no network, no files, no secrets, a minimal
environment. The host bounds wall time (``L-10``), stdout bytes and, per OS, memory: the worker
applies ``RLIMIT_AS`` to itself on POSIX (macOS may not enforce it), the host puts the process in
a job object with a process memory limit on Windows. Where no memory limit holds, the bound is
the wall time plus the page, char and per-stream caps inside the worker. The result is treated
as untrusted: re-parsed, re-capped and failed closed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Final, Literal, get_args

from mailferret.content.mime import Note, NoteKind
from mailferret.content.pdf_job import MemoryJob
from mailferret.content.pdf_worker import RESULT_VERSION
from mailferret.content.truncate import truncate_chars
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
_CHUNK: Final = 64 * 1024
_POLL: Final = 0.01
_JOIN_GRACE: Final = 0.5
_OVERHEAD: Final = 16 * 1024
_MAX_CHAR_BYTES: Final = 6
_MAX_NOTES: Final = 16
_LIMIT_ID: Final = re.compile(r"L-\d{2}")
_NOTE_KINDS: Final[frozenset[str]] = frozenset(get_args(NoteKind))
_POSIX_ENV: Final = ("PATH",)
_WINDOWS_ENV: Final = ("SYSTEMROOT", "PATH", "TEMP", "TMP")

WORKER_MODULE: Final = "mailferret.content.pdf_worker"

Status = Literal["exited", "timeout", "output_exceeded"]


@dataclass(frozen=True, slots=True)
class RunResult:
    status: Status
    returncode: int | None
    stdout: bytes = field(default=b"", repr=False)
    job_failed: bool = False


@dataclass(frozen=True, slots=True)
class PdfText:
    """``text`` is ``None`` when nothing could be extracted; ``notes`` say why."""

    text: str | None
    truncated: bool
    notes: tuple[Note, ...] = ()


def _env() -> dict[str, str]:
    names = _WINDOWS_ENV if sys.platform == "win32" else _POSIX_ENV
    return {k: os.environ[k] for k in names if k in os.environ}


class _Sink(threading.Thread):
    """Reads a pipe to EOF, keeping ``cap`` bytes (``None``: none); ``breach`` marks any excess."""

    def __init__(self, stream: IO[bytes], cap: int | None) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self.data = bytearray()
        self.breach = threading.Event()
        self.done = threading.Event()

    def run(self) -> None:
        try:
            while True:
                chunk = self._stream.read(_CHUNK)
                if not chunk:
                    return
                if self._cap is None:
                    continue
                room = self._cap - len(self.data)
                self.data += chunk[: max(room, 0)]
                if len(chunk) > room:
                    self.breach.set()
                    return
        except (OSError, ValueError):
            return
        finally:
            self.done.set()


def _feed(stream: IO[bytes], data: bytes) -> None:
    with contextlib.suppress(OSError, ValueError):
        try:
            stream.write(data)
        finally:
            stream.close()


def _spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    cwd = Path(tempfile.gettempdir())
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        return subprocess.Popen(  # noqa: S603
            list(argv),
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=_env(),
            cwd=cwd,
            bufsize=0,
            creationflags=flags,
        )
    return subprocess.Popen(  # noqa: S603
        list(argv),
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=_env(),
        cwd=cwd,
        bufsize=0,
        start_new_session=True,
    )


def _kill(proc: subprocess.Popen[bytes], job: MemoryJob | None, *, group: bool = True) -> None:
    """Kill the worker and its descendants; ``group`` is False once the leader is reaped."""
    if job is not None:
        job.terminate()
    elif sys.platform != "win32" and group:
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


def _close_pipes(proc: subprocess.Popen[bytes]) -> None:
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


def _attach_job(proc: subprocess.Popen[bytes], memory_bytes: int) -> tuple[MemoryJob | None, bool]:
    """The job object holding ``proc``, and whether it could not be set up (then no memory cap)."""
    try:
        job = MemoryJob.create(memory_bytes)
        if job is None:
            return None, True
        if not job.assign(int(getattr(proc, "_handle", 0))):
            job.close()
            return None, True
        return job, False
    except BaseException:
        _kill(proc, None)
        _close_pipes(proc)
        raise


def worker_argv(limits: Limits) -> list[str]:
    options = {
        "pages": limits.max_pdf_pages,
        "chars": limits.max_body_chars,
        "stream-bytes": limits.pdf_stream_bytes,
        "memory": limits.pdf_worker_memory_bytes,
        "input-bytes": limits.max_attachment_bytes,
    }
    argv = [sys.executable, "-I", "-m", WORKER_MODULE]
    for name, value in options.items():
        argv += [f"--{name}", str(value)]
    return argv


def run_bounded(
    argv: Sequence[str],
    data: bytes,
    *,
    deadline: float,
    memory_bytes: int,
    stdout_cap: int,
) -> RunResult:
    """Run ``argv`` with ``data`` on stdin and return within ``deadline`` plus a short grace."""
    end = time.monotonic() + deadline
    proc = _spawn(argv)
    job: MemoryJob | None = None
    job_failed = False
    if sys.platform == "win32":
        job, job_failed = _attach_job(proc, memory_bytes)
    stdin, stdout, stderr = proc.stdin, proc.stdout, proc.stderr
    if stdin is None or stdout is None or stderr is None:
        _kill(proc, job)
        _close_pipes(proc)
        raise OSError("missing pipe")
    out = _Sink(stdout, stdout_cap)
    err = _Sink(stderr, None)
    out.start()
    err.start()
    threading.Thread(target=_feed, args=(stdin, data), daemon=True).start()

    status: Status = "exited"
    while not _has_exited(proc):
        if out.breach.is_set():
            status = "output_exceeded"
            break
        if time.monotonic() >= end:
            status = "timeout"
            break
        time.sleep(_POLL)
    # The leader is unreaped here wherever ``waitid`` exists, so its group id is still ours.
    can_kill_group = hasattr(os, "waitid")
    if status != "exited":
        _kill(proc, job)
    else:
        out.join(max(0.0, end - time.monotonic()))
        if not out.done.is_set():
            status = "timeout"
        elif out.breach.is_set():
            status = "output_exceeded"
        if status != "exited" or can_kill_group:
            _kill(proc, job, group=can_kill_group)
    try:
        returncode: int | None = proc.wait(timeout=_JOIN_GRACE)
    except subprocess.TimeoutExpired:
        returncode = None
    for sink in (out, err):
        sink.join(_JOIN_GRACE)
    if job is not None:
        job.close()
    for sink, pipe in ((out, stdout), (err, stderr)):
        if sink.done.is_set():
            with contextlib.suppress(OSError):
                pipe.close()
    if status != "exited":
        return RunResult(status, returncode, job_failed=job_failed)
    return RunResult(status, returncode, bytes(out.data), job_failed)


def _failed(kind: NoteKind, limit: str | None = None) -> PdfText:
    return PdfText(None, False, (Note(kind, limit),))


def _notes(raw: object) -> tuple[Note, ...] | None:
    if not isinstance(raw, list) or len(raw) > _MAX_NOTES:
        return None
    notes: list[Note] = []
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            return None
        kind, limit = item
        if kind not in _NOTE_KINDS:
            return None
        if limit is not None and not (isinstance(limit, str) and _LIMIT_ID.fullmatch(limit)):
            return None
        notes.append(Note(kind, limit))
    return tuple(notes)


def parse_result(stdout: bytes, limits: Limits) -> PdfText:
    """Validate the worker's JSON; anything else is ``part_failed``."""
    try:
        body = json.loads(stdout)
    except (ValueError, RecursionError):
        return _failed("part_failed")
    if not isinstance(body, dict) or body.get("v") != RESULT_VERSION:
        return _failed("part_failed")
    text, truncated, notes = body.get("text"), body.get("truncated"), _notes(body.get("notes"))
    if not isinstance(text, str) or not isinstance(truncated, bool) or notes is None:
        return _failed("part_failed")
    capped = truncate_chars(text, limits.max_body_chars)
    if capped.truncated:
        notes = (*notes, Note("limit_exceeded", "L-03"))
    kept = capped.text.encode("utf-8", "replace").decode("utf-8")
    return PdfText(kept if kept or not notes else None, truncated or capped.truncated, notes)


def _interpret(result: RunResult, limits: Limits) -> PdfText:
    if result.status == "timeout":
        return _failed("limit_exceeded", "L-10")
    if result.status == "output_exceeded":
        return _failed("limit_exceeded", "L-03")
    if result.returncode != 0:
        return _failed("part_failed")
    return parse_result(result.stdout, limits)


def _noting(text: PdfText, job_failed: bool) -> PdfText:
    if not job_failed:
        return text
    return PdfText(text.text, text.truncated, (*text.notes, Note("memory_cap_unavailable")))


def extract_pdf(
    data: bytes, limits: Limits = _DEFAULT_LIMITS, *, argv: Sequence[str] | None = None
) -> PdfText:
    """Extract the text of a PDF in the worker; never raises."""
    try:
        if len(data) > limits.max_attachment_bytes:
            return _failed("limit_exceeded", "L-08")
        result = run_bounded(
            argv if argv is not None else worker_argv(limits),
            data,
            deadline=float(limits.pdf_worker_seconds),
            memory_bytes=limits.pdf_worker_memory_bytes,
            stdout_cap=_MAX_CHAR_BYTES * limits.max_body_chars + _OVERHEAD,
        )
        return _noting(_interpret(result, limits), result.job_failed)
    except Exception:  # per-part fault isolation
        return _failed("part_failed")
