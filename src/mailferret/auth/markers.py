"""Persistent auth-failed markers per ``<login>@<host>``, shared by every server process (T-16).

``rejected``: an explicit server rejection; it stays until ``clear``. ``indeterminate``: a login
that was sent and got no tagged answer; it blocks for ``PAUSE_SECONDS`` by the stamp inside the
file. A marker that cannot be read counts as present. When it cannot be written either, the
process keeps its own record, so it still never logs in twice.
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


def marker_path(data_dir: Path, key: EntryKey) -> Path:
    digest = hashlib.sha256(key.username.encode()).hexdigest()[:32]
    return data_dir / f"auth-failed-{digest}.json"


class AuthMarkers:
    def __init__(self, data_dir: Path, clock: Callable[[], float] = time.time) -> None:
        self._dir = data_dir
        self._clock = clock
        self._lock = threading.Lock()
        self._unwritten: dict[str, tuple[MarkerKind, float]] = {}

    def blocked(self, key: EntryKey) -> MarkerKind | None:
        """The marker in force for ``key``, or ``None``."""
        found = self._read(key)
        if found is not None:
            return self._in_force(*found)
        with self._lock:
            kept = self._unwritten.get(key.username)
        return None if kept is None else self._in_force(*kept)

    def record_rejected(self, key: EntryKey) -> None:
        self._record(key, "rejected")

    def record_indeterminate(self, key: EntryKey) -> None:
        self._record(key, "indeterminate")

    def clear(self, key: EntryKey) -> None:
        """For `auth set`, `setup` and `auth retry`; raises ``OSError`` if the file stays."""
        with self._lock:
            self._unwritten.pop(key.username, None)
        marker_path(self._dir, key).unlink(missing_ok=True)

    def clear_indeterminate(self, key: EntryKey) -> None:
        """After a successful login: drops a time-boxed marker, never a rejection."""
        found = self._read(key)
        with self._lock:
            kept = self._unwritten.get(key.username)
            if kept is not None and kept[0] == "indeterminate":
                del self._unwritten[key.username]
        if found is not None and found[0] == "indeterminate":
            with contextlib.suppress(OSError):
                marker_path(self._dir, key).unlink(missing_ok=True)

    def _in_force(self, kind: MarkerKind, at: float) -> MarkerKind | None:
        if kind == "rejected":
            return kind
        return kind if abs(self._clock() - at) < PAUSE_SECONDS else None

    def _read(self, key: EntryKey) -> tuple[MarkerKind, float] | None:
        try:
            with marker_path(self._dir, key).open("rb") as handle:
                raw = handle.read(_MAX_BYTES + 1)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError:
            return "rejected", 0.0
        try:
            body = json.loads(raw) if len(raw) <= _MAX_BYTES else None
        except (ValueError, RecursionError):
            body = None
        if not isinstance(body, dict) or body.get("username") != key.username:
            return "rejected", 0.0
        at = body.get("at")
        if (
            body.get("kind") == "indeterminate"
            and isinstance(at, int | float)
            and not isinstance(at, bool)
        ):
            return "indeterminate", float(at)
        return "rejected", 0.0

    def _record(self, key: EntryKey, kind: MarkerKind) -> None:
        now = self._clock()
        path = marker_path(self._dir, key)
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
                self._unwritten[key.username] = (kind, now)
