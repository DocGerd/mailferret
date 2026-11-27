from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from mailferret.registration import (
    ConcurrentModificationError,
    DuplicateEntryError,
    EntryState,
    RegistrationError,
    atomic_write_text,
    backup_file,
    claude_code_scope_file,
    desktop_candidates,
    entry_state,
    merge_server,
)

ENTRY: dict[str, Any] = {
    "command": "/opt/x/uvx",
    "args": ["--from", "mailferret", "serve"],
}
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


def _write(path: Path, data: Any, mode: int = 0o640) -> None:
    path.write_text(json.dumps(data))
    path.chmod(mode)


def _backups(path: Path) -> list[Path]:
    return sorted(path.parent.glob(f"{path.name}.*.bak"))


def _temps(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.suffix == ".tmp"]


def test_backup_taken_with_original_content_before_write(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    original = {"mcpServers": {"other": {"command": "x"}}}
    _write(cfg, original)
    backup = merge_server(cfg, "mailferret", ENTRY)
    assert backup is not None
    assert json.loads(backup.read_text()) == original
    if os.name == "posix":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_unknown_keys_and_other_servers_preserved(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"theme": {"a": [1]}, "mcpServers": {"other": {"command": "x"}}})
    merge_server(cfg, "mailferret", ENTRY)
    out = json.loads(cfg.read_text())
    assert out["theme"] == {"a": [1]}
    assert out["mcpServers"] == {"other": {"command": "x"}, "mailferret": ENTRY}


@posix_only
def test_permissions_preserved(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {}, 0o640)
    merge_server(cfg, "mailferret", ENTRY)
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o640


def test_missing_file_created_without_backup(tmp_path: Path) -> None:
    cfg = tmp_path / "sub" / "c.json"
    assert merge_server(cfg, "mailferret", ENTRY) is None
    assert json.loads(cfg.read_text()) == {"mcpServers": {"mailferret": ENTRY}}
    if os.name == "posix":
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600


@pytest.mark.parametrize("content", ["{not json", "[]", '{"mcpServers": []}'])
def test_invalid_existing_aborts_without_writing(tmp_path: Path, content: str) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(content)
    with pytest.raises(RegistrationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert cfg.read_text() == content
    assert _backups(cfg) == []


@posix_only
def test_read_only_file_refused(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {}, 0o444)
    with pytest.raises(RegistrationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert json.loads(cfg.read_text()) == {}


def test_failed_replace_leaves_original_and_no_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"k": 1})

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        merge_server(cfg, "mailferret", ENTRY)
    assert json.loads(cfg.read_text()) == {"k": 1}
    assert _temps(tmp_path) == []


def test_concurrent_modification_detected(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"k": 1})
    expect = cfg.stat()
    cfg.write_text(json.dumps({"k": 2, "extra": True}))
    with pytest.raises(ConcurrentModificationError):
        atomic_write_text(cfg, "{}", expect=expect)
    assert json.loads(cfg.read_text())["k"] == 2
    assert _temps(tmp_path) == []


def test_duplicate_identical_is_noop(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"mcpServers": {"mailferret": {**ENTRY, "env": {"A": "1"}}}})
    assert merge_server(cfg, "mailferret", ENTRY) is None
    assert _backups(cfg) == []


def test_duplicate_different_refused_unless_replace(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"mcpServers": {"mailferret": {"command": "old"}}})
    with pytest.raises(DuplicateEntryError):
        merge_server(cfg, "mailferret", ENTRY)
    assert _backups(cfg) == []
    assert merge_server(cfg, "mailferret", ENTRY, replace=True) is not None
    assert json.loads(cfg.read_text())["mcpServers"]["mailferret"] == ENTRY


def test_entry_state() -> None:
    assert entry_state({}, "m", ENTRY) is EntryState.ABSENT
    assert entry_state({"mcpServers": {"m": "s"}}, "m", ENTRY) is EntryState.DIFFERENT
    same = {"mcpServers": {"m": dict(ENTRY)}}
    assert entry_state(same, "m", ENTRY) is EntryState.IDENTICAL


@posix_only
def test_symlinked_config_keeps_link(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    _write(real, {})
    link = tmp_path / "link.json"
    link.symlink_to(real)
    merge_server(link, "mailferret", ENTRY)
    assert link.is_symlink()
    assert "mailferret" in json.loads(real.read_text())["mcpServers"]


def test_backup_names_do_not_collide(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text("{}")
    backup_file(cfg)
    backup_file(cfg)
    assert len(_backups(cfg)) == 2


def test_claude_code_scope_files(tmp_path: Path) -> None:
    home, cwd = tmp_path / "h", tmp_path / "p"
    assert claude_code_scope_file("user", home, cwd) == home / ".claude.json"
    assert claude_code_scope_file("local", home, cwd) == home / ".claude.json"
    assert claude_code_scope_file("project", home, cwd) == cwd / ".mcp.json"


def test_desktop_candidates_linux_and_windows(tmp_path: Path) -> None:
    cfg = tmp_path / ".config" / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{}")
    assert [c.path for c in desktop_candidates("linux", {}, tmp_path)] == [cfg]
    assert desktop_candidates("win32", {}, tmp_path) == []

    appdata = tmp_path / "AppData"
    win = appdata / "Claude" / "claude_desktop_config.json"
    win.parent.mkdir(parents=True)
    win.write_text("{}")
    pkg = tmp_path / "Local" / "Packages" / "Claude_abc123"
    pkg.mkdir(parents=True)
    env = {"APPDATA": str(appdata), "LOCALAPPDATA": str(tmp_path / "Local")}
    got = desktop_candidates("win32", env, tmp_path)
    assert [(c.path, c.kind) for c in got] == [(win, "regular"), (pkg, "msix")]
