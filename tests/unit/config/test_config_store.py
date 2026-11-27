import stat
import sys
from pathlib import Path

import pytest

from mailferret.config import ConfigError, load, parse, resolve_location, write
from mailferret.config.paths import default_config_path

ACCOUNT = """# keep me
[accounts.work]
host = "imap.example.com"
tls = "implicit"
login = "user@example.com"
"""


@pytest.fixture(autouse=True)
def _isolated_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAILFERRET_CONFIG", raising=False)


def test_missing_default_file_means_no_accounts() -> None:
    assert load().accounts == {}


def test_missing_env_override_means_no_accounts_not_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = default_config_path()
    default.parent.mkdir(parents=True)
    default.write_text(ACCOUNT)
    assert "work" in load().accounts
    monkeypatch.setenv("MAILFERRET_CONFIG", str(tmp_path / "missing.toml"))
    assert load().accounts == {}


def test_missing_flag_means_no_accounts_not_default(tmp_path: Path) -> None:
    default = default_config_path()
    default.parent.mkdir(parents=True)
    default.write_text(ACCOUNT)
    assert load(tmp_path / "missing.toml").accounts == {}


def test_flag_beats_env(tmp_path: Path) -> None:
    flag, env = tmp_path / "a.toml", tmp_path / "b.toml"
    location = resolve_location(flag, {"MAILFERRET_CONFIG": str(env)})
    assert location.path == flag
    assert location.overridden


def test_env_beats_default(tmp_path: Path) -> None:
    location = resolve_location(None, {"MAILFERRET_CONFIG": str(tmp_path / "b.toml")})
    assert location.path == tmp_path / "b.toml"


def test_empty_env_falls_back_to_default() -> None:
    location = resolve_location(None, {"MAILFERRET_CONFIG": ""})
    assert location.path == default_config_path()
    assert not location.overridden


@pytest.mark.skipif(sys.platform == "win32", reason="XDG applies to POSIX")
def test_default_path_follows_xdg(tmp_path: Path) -> None:
    assert default_config_path() == tmp_path / "xdg" / "mailferret" / "config.toml"


def test_write_then_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "config.toml"
    config = parse(ACCOUNT)
    write(config, path)
    assert load(path) == config


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_write_modes_and_no_leftover(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "config.toml"
    write(parse(ACCOUNT), path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert [p.name for p in path.parent.iterdir()] == ["config.toml"]


def test_write_keeps_comments(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(ACCOUNT)
    write(parse(ACCOUNT.replace("work", "other")), path)
    text = path.read_text()
    assert "# keep me" in text
    assert "other" in text
    assert "accounts.work" not in text


def test_invalid_file_error_does_not_leak_values(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(ACCOUNT + 'password = "hunter2-value"\n')  # pii-check: ignore
    with pytest.raises(ConfigError) as info:
        load(path)
    assert "hunter2-value" not in str(info.value)
