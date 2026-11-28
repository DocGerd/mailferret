"""Backup, atomic write and duplicate detection for client config files (T-12)."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

_PRIVATE_MODE = 0o600


class RegistrationError(Exception):
    """The config cannot be safely modified; the config file was not changed."""


class ConcurrentModificationError(RegistrationError):
    """The file changed between reading and replacing it."""


class DuplicateEntryError(RegistrationError):
    """A different entry of that name already exists."""


class VerificationError(Exception):
    """The file was replaced but did not re-parse as written.

    Deliberately not a RegistrationError: the config has changed. `backup` is the
    pre-write copy to restore from, or None when the file was newly created.
    """

    def __init__(self, message: str, *, path: Path, backup: Path | None) -> None:
        super().__init__(message)
        self.path = path
        self.backup = backup


class EntryState(Enum):
    ABSENT = "absent"
    IDENTICAL = "identical"
    DIFFERENT = "different"


def entry_state(config: dict[str, Any], name: str, entry: dict[str, Any]) -> EntryState:
    """Compare an existing server entry with `entry`; `env` is ignored (A§9.5)."""
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers:
        return EntryState.ABSENT
    current = servers[name]
    if not isinstance(current, dict):
        return EntryState.DIFFERENT

    def key(e: dict[str, Any]) -> tuple[Any, Any]:
        return e.get("command"), e.get("args", [])

    return EntryState.IDENTICAL if key(current) == key(entry) else EntryState.DIFFERENT


def backup_file(path: Path, *, now: datetime | None = None) -> Path:
    """Copy `path` to a timestamped sibling with mode 0600 (POSIX)."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S%fZ")
    target = path.with_name(f"{path.name}.{stamp}.bak")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_MODE)
    with path.open("rb") as src, os.fdopen(fd, "wb") as dst:
        shutil.copyfileobj(src, dst)
    if os.name == "posix":
        target.chmod(_PRIVATE_MODE)
    return target


def _write_fd(fd: int, text: str) -> None:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def _install_new(tmp: Path, path: Path, text: str, mode: int) -> None:
    appeared = ConcurrentModificationError(f"{path.name} appeared during update")
    try:
        os.link(tmp, path)
        return
    except FileExistsError:
        raise appeared from None
    except OSError:
        pass
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        raise appeared from None
    _write_fd(fd, text)
    if os.name == "posix":
        path.chmod(mode)


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int = _PRIVATE_MODE,
    expect: os.stat_result | None = None,
    exclusive: bool = False,
) -> None:
    """Write via a same-directory temp file and `os.replace`.

    With `expect`, the file's mtime and size must still match before replacing.
    With `exclusive`, an existing file is never overwritten: the temp file is
    hard-linked into place and EEXIST raises ConcurrentModificationError. Where
    hard links are unavailable it falls back to an `O_EXCL` create, which keeps
    the no-overwrite guarantee but is not atomic for concurrent readers.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        _write_fd(fd, text)
        if os.name == "posix":
            tmp.chmod(mode)
        if exclusive:
            _install_new(tmp, path, text, mode)
            return
        if expect is not None:
            now = path.stat()
            if (now.st_mtime_ns, now.st_size) != (expect.st_mtime_ns, expect.st_size):
                raise ConcurrentModificationError(f"{path.name} changed during update")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistrationError(f"{path.name} is not readable JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistrationError(f"{path.name}: top level is not an object")
    servers = data.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        raise RegistrationError(f"{path.name}: mcpServers is not an object")
    return data


def _verify(path: Path, name: str, entry: dict[str, Any], backup: Path | None) -> None:
    try:
        written = _load(path).get("mcpServers", {}).get(name)
    except RegistrationError as exc:
        raise VerificationError(str(exc), path=path, backup=backup) from exc
    if written != entry:
        raise VerificationError(
            f"{path.name} did not re-parse as written", path=path, backup=backup
        )


def _is_absolute(command: object) -> bool:
    return isinstance(command, str) and (
        PurePosixPath(command).is_absolute() or PureWindowsPath(command).is_absolute()
    )


def merge_server(
    path: Path,
    name: str,
    entry: dict[str, Any],
    *,
    replace: bool = False,
    now: datetime | None = None,
) -> Path | None:
    """Add `entry` under `mcpServers[name]`, touching nothing else.

    `entry["command"]` must be an absolute path (POSIX or Windows form).
    Returns the backup path, or None when the file did not exist or the entry
    was already identical (nothing written). A different existing entry raises
    DuplicateEntryError unless `replace`. RegistrationError means the file is
    unchanged; VerificationError means it was replaced and carries the backup.
    """
    if not _is_absolute(entry.get("command")):
        raise RegistrationError("entry command must be an absolute path")
    path = Path(os.path.realpath(path))
    if not path.exists():
        text = json.dumps({"mcpServers": {name: entry}}, indent=2) + "\n"
        atomic_write_text(path, text, exclusive=True)
        _verify(path, name, entry, None)
        return None

    before = path.stat()
    if sys.platform != "win32" and (
        not before.st_mode & stat.S_IWUSR
        or before.st_uid != os.geteuid()
        or not os.access(path, os.W_OK)
    ):
        raise RegistrationError(f"{path.name} is read-only or not owned by this user")
    config = _load(path)
    state = entry_state(config, name, entry)
    if state is EntryState.IDENTICAL:
        return None
    if state is EntryState.DIFFERENT and not replace:
        raise DuplicateEntryError(f"{name!r} already exists in {path.name}")

    config.setdefault("mcpServers", {})[name] = entry
    text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    backup = backup_file(path, now=now)
    atomic_write_text(path, text, mode=stat.S_IMODE(before.st_mode), expect=before)
    _verify(path, name, entry, backup)
    return backup
