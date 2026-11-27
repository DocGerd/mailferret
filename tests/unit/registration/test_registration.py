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
    VerificationError,
    atomic_write_text,
    backup_file,
    claude_code_scope_file,
    desktop_candidates,
    entry_state,
    files,
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


def test_desktop_candidates_wsl_reads_windows_side_only(tmp_path: Path) -> None:
    mount = tmp_path / "mnt"
    alice = mount / "c" / "Users" / "alice" / "AppData"
    cfg = alice / "Roaming" / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{}")
    pkg = alice / "Local" / "Packages" / "Claude_abc123"
    pkg.mkdir(parents=True)
    (mount / "d" / "Users" / "bob").mkdir(parents=True)
    (mount / "wsl").mkdir()
    linux = tmp_path / "home" / ".config" / "Claude" / "claude_desktop_config.json"
    linux.parent.mkdir(parents=True)
    linux.write_text("{}")

    env = {"WSL_DISTRO_NAME": "Distro"}
    got = desktop_candidates("linux", env, tmp_path / "home", wsl_mount=mount)
    assert [(c.path, c.kind) for c in got] == [(cfg, "regular"), (pkg, "msix")]
    plain = desktop_candidates("linux", {}, tmp_path / "home", wsl_mount=mount)
    assert [c.path for c in plain] == [linux]


def test_desktop_candidates_wsl_without_mount(tmp_path: Path) -> None:
    env = {"WSL_DISTRO_NAME": "Distro"}
    assert desktop_candidates("linux", env, tmp_path, wsl_mount=tmp_path / "none") == []


def test_merge_server_detects_modification_between_read_and_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"k": 1})
    other = json.dumps({"k": 2, "written_by_someone_else": True})
    real_backup = files.backup_file

    def racing_backup(path: Path, **kw: Any) -> Path:
        path.write_text(other)
        return real_backup(path, **kw)

    monkeypatch.setattr(files, "backup_file", racing_backup)
    with pytest.raises(ConcurrentModificationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert cfg.read_text() == other
    assert _temps(tmp_path) == []


def _write_other_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    real = files.atomic_write_text

    def wrong(path: Path, text: str, **kw: Any) -> None:
        real(path, json.dumps({"mcpServers": {}}), **kw)

    monkeypatch.setattr(files, "atomic_write_text", wrong)


def test_verification_failure_after_replace_carries_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {"k": 1})
    _write_other_entry(monkeypatch)
    with pytest.raises(VerificationError) as info:
        merge_server(cfg, "mailferret", ENTRY)
    assert not isinstance(info.value, RegistrationError)
    assert info.value.backup is not None
    assert json.loads(info.value.backup.read_text()) == {"k": 1}
    assert info.value.path == cfg


def test_verification_failure_on_create_has_no_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    _write_other_entry(monkeypatch)
    with pytest.raises(VerificationError) as info:
        merge_server(cfg, "mailferret", ENTRY)
    assert info.value.backup is None


def test_verification_failure_when_rewritten_file_is_unparseable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    real = files.atomic_write_text

    def garbage(path: Path, text: str, **kw: Any) -> None:
        real(path, "{not json", **kw)

    monkeypatch.setattr(files, "atomic_write_text", garbage)
    with pytest.raises(VerificationError):
        merge_server(cfg, "mailferret", ENTRY)


@posix_only
def test_foreign_owner_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {})
    owner = cfg.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(RegistrationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert json.loads(cfg.read_text()) == {}
    assert _backups(cfg) == []


@posix_only
def test_no_effective_write_access_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.json"
    _write(cfg, {})
    monkeypatch.setattr(os, "access", lambda *a, **k: False)
    with pytest.raises(RegistrationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert json.loads(cfg.read_text()) == {}


def test_create_never_overwrites_file_that_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "c.json"
    real_link = os.link

    def racing_link(src: Any, dst: Any, **kw: Any) -> None:
        Path(dst).write_text('{"theirs": true}')
        real_link(src, dst, **kw)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(ConcurrentModificationError):
        merge_server(cfg, "mailferret", ENTRY)
    assert cfg.read_text() == '{"theirs": true}'
    assert _temps(tmp_path) == []


def test_create_without_hard_links_still_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_link(src: object, dst: object) -> None:
        raise PermissionError("no hard links")

    monkeypatch.setattr(os, "link", no_link)
    cfg = tmp_path / "c.json"
    assert merge_server(cfg, "mailferret", ENTRY) is None
    assert json.loads(cfg.read_text()) == {"mcpServers": {"mailferret": ENTRY}}
    assert _temps(tmp_path) == []

    other = tmp_path / "d.json"
    other.write_text("keep")
    with pytest.raises(ConcurrentModificationError):
        atomic_write_text(other, "{}", exclusive=True)
    assert other.read_text() == "keep"
    assert _temps(tmp_path) == []


@pytest.mark.parametrize("command", ["uvx", "./uvx", "", None, 3, "C:uvx"])
def test_relative_command_refused(tmp_path: Path, command: object) -> None:
    cfg = tmp_path / "c.json"
    with pytest.raises(RegistrationError):
        merge_server(cfg, "mailferret", {"command": command, "args": []})
    assert not cfg.exists()
    assert _temps(tmp_path) == []


def test_windows_absolute_command_accepted(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    entry = {"command": "C:\\Windows\\System32\\wsl.exe", "args": ["--exec", "/x"]}
    merge_server(cfg, "mailferret", entry)
    assert json.loads(cfg.read_text())["mcpServers"]["mailferret"] == entry
