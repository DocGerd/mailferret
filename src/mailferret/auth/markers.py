"""Persistent auth-failed markers per ``<login>@<host>``, shared by every server process (T-16).

Two files per key, so no writer ever replaces or deletes the other kind: ``auth-failed-*`` holds
an explicit server rejection and stays until ``clear``; ``auth-paused-*`` holds a login that was
sent and got no tagged answer, and blocks for ``PAUSE_SECONDS`` by the stamp inside it. Nothing
deletes a marker except ``clear``, so there is no read-then-delete to race. ``blocked`` reads
both files and this process's own record and takes the strictest. A marker that cannot be read
counts as a rejection. When a marker cannot be written, the process keeps it in memory, so it
still never logs in twice.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal

from mailferret.credentials import EntryKey

PAUSE_SECONDS: Final = 300
_MAX_BYTES: Final = 4096

MarkerKind = Literal["rejected", "indeterminate"]
_PREFIX: Final[dict[MarkerKind, str]] = {
    "rejected": "auth-failed-",
    "indeterminate": "auth-paused-",
}


def marker_path(data_dir: Path, key: EntryKey, kind: MarkerKind = "rejected") -> Path:
    digest = hashlib.sha256(key.username.encode()).hexdigest()[:32]
    return data_dir / f"{_PREFIX[kind]}{digest}.json"


class AuthMarkers:
    def __init__(self, data_dir: Path, clock: Callable[[], float] = time.time) -> None:
        self._dir = data_dir
        self._clock = clock
        self._lock = threading.Lock()
        self._unwritten: dict[tuple[str, MarkerKind], float] = {}

    def blocked(self, key: EntryKey) -> MarkerKind | None:
        """The strictest marker in force for ``key``, or ``None``."""
        with self._lock:
            kept = {kind: self._unwritten.get((key.username, kind)) for kind in _PREFIX}
        paused = self._paused(key)
        if self._rejected(key) or kept["rejected"] is not None or paused is False:
            return "rejected"
        stamps = [at for at in (paused, kept["indeterminate"]) if at is not None]
        if any(abs(self._clock() - at) < PAUSE_SECONDS for at in stamps):
            return "indeterminate"
        return None

    def record_rejected(self, key: EntryKey) -> None:
        self._record(key, "rejected")

    def record_indeterminate(self, key: EntryKey) -> None:
        self._record(key, "indeterminate")

    def clear(self, key: EntryKey) -> None:
        """For `auth set`, `setup` and `auth retry`; raises ``OSError`` if a file stays."""
        with self._lock:
            for kind in _PREFIX:
                self._unwritten.pop((key.username, kind), None)
        for kind in _PREFIX:
            marker_path(self._dir, key, kind).unlink(missing_ok=True)

    def _load(self, key: EntryKey, kind: MarkerKind) -> dict[str, object] | Literal[False] | None:
        """The file's body, ``None`` if absent, ``False`` if it exists but cannot be trusted."""
        try:
            with marker_path(self._dir, key, kind).open("rb") as handle:
                raw = handle.read(_MAX_BYTES + 1)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError:
            return False
        try:
            body = json.loads(raw) if len(raw) <= _MAX_BYTES else None
        except (ValueError, RecursionError):
            return False
        if not isinstance(body, dict) or body.get("username") != key.username:
            return False
        return body

    def _rejected(self, key: EntryKey) -> bool:
        return self._load(key, "rejected") is not None

    def _paused(self, key: EntryKey) -> float | Literal[False] | None:
        """The stamp, ``None`` if absent, ``False`` if the file cannot be trusted."""
        body = self._load(key, "indeterminate")
        if body is None or body is False:
            return body
        at = body.get("at")
        if isinstance(at, int | float) and not isinstance(at, bool):
            return float(at)
        return False

    def _record(self, key: EntryKey, kind: MarkerKind) -> None:
        now = self._clock()
        path = marker_path(self._dir, key, kind)
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        payload = json.dumps({"username": key.username, "kind": kind, "at": now}).encode()
        try:
            self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()
            with self._lock:
                self._unwritten[(key.username, kind)] = now
