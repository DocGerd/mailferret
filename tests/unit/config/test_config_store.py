import stat
import sys
from pathlib import Path

import pytest

from mailferret.config import ConfigError, load, parse, paths, resolve_location, write
from mailferret.config.paths import default_config_path as real_default_config_path

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
    sandbox = tmp_path / "default" / "config.toml"
    monkeypatch.setattr(paths, "default_config_path", lambda: sandbox)


def test_missing_default_file_means_no_accounts() -> None:
    assert load().accounts == {}


def test_missing_env_override_means_no_accounts_not_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = paths.default_config_path()
    default.parent.mkdir(parents=True)
    default.write_text(ACCOUNT)
    assert "work" in load().accounts
    monkeypatch.setenv("MAILFERRET_CONFIG", str(tmp_path / "missing.toml"))
    assert load().accounts == {}


def test_missing_flag_means_no_accounts_not_default(tmp_path: Path) -> None:
    default = paths.default_config_path()
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
    assert location.path == paths.default_config_path()
    assert not location.overridden


@pytest.mark.skipif(sys.platform == "win32", reason="XDG applies to POSIX")
def test_default_path_follows_xdg(tmp_path: Path) -> None:
    assert real_default_config_path() == tmp_path / "xdg" / "mailferret" / "config.toml"


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


def _chain(error: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    pending: list[BaseException | None] = [error]
    while pending:
        item = pending.pop()
        if item is not None and item not in seen:
            seen.append(item)
            pending += [item.__cause__, item.__context__]
    return seen


@pytest.mark.parametrize(
    ("content", "marker"),
    [
        (ACCOUNT.encode() + b'password = "hunter2-value"\n', "hunter2-value"),  # pii-check: ignore
        (b'password = "hunter2-value"\naccounts = [\n', "hunter2-value"),  # pii-check: ignore
        (b'# file-text-marker\nlogin = "\xff\xfe"\n', "file-text-marker"),
    ],
    ids=["validation", "toml-syntax", "undecodable"],
)
def test_invalid_file_error_does_not_leak_values(
    tmp_path: Path, content: bytes, marker: str
) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(content)
    with pytest.raises(ConfigError) as info:
        load(path)
    assert marker not in str(info.value)
    assert _chain(info.value) == [info.value]
    assert info.value.__context__ is None
    assert info.value.__cause__ is None


A7_EXAMPLE = """schema_version = 1
default_account = "work"            # optional

[limits]                            # optional
max_body_chars = 50000              # L-03
max_page_size = 100                 # L-15

[accounts.work]
preset = "generic"
host = "imap.example.com"
port = 993
tls = "implicit"                    # implicit | starttls
login = "user@example.com"
credential_backend = "keyring"      # keyring | command
# ca_file = "/path/to/ca.pem"       # added to the system trust store

[accounts.work.aliases]
domains = ["example.com"]
plus_separator = "+"
header_priority = ["Delivered-To", "X-Original-To", "To", "Cc"]

[accounts.shop]
preset = "hetzner"                  # supplies host, port and TLS mode
login = "shop@example.com"
credential_backend = "command"

[accounts.shop.credential_command]
get = ["/usr/bin/pass", "show", "mailferret/shop"]
set = ["/usr/bin/pass", "insert", "--multiline", "--force", "mailferret/shop"]
env = { PASSWORD_STORE_GPG_OPTS = "--pinentry-mode=error" }   # allowlisted names only
"""


def test_write_leaves_the_example_config_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(A7_EXAMPLE)
    write(parse(A7_EXAMPLE), path)
    assert path.read_text() == A7_EXAMPLE


def test_write_keeps_inline_table_comment_when_it_changes(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(A7_EXAMPLE)
    changed = A7_EXAMPLE.replace("--pinentry-mode=error", "--batch")
    write(parse(changed), path)
    assert path.read_text() == changed
    assert "# allowlisted names only" in path.read_text()


def test_write_does_not_reorder_out_of_order_tables(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    text = (
        "schema_version = 1\n\n"
        '[accounts.a]\nhost = "h"\ntls = "implicit"\nlogin = "a@example.com"\n'
        "\n[limits]\nmax_page_size = 5\n"
        '\n[accounts.b]\nhost = "h"\ntls = "implicit"\nlogin = "b@example.com"\n'
    )
    path.write_text(text)
    write(parse(text), path)
    assert path.read_text() == text
    changed = text.replace("max_page_size = 5", "max_page_size = 6")
    write(parse(changed), path)
    assert path.read_text() == changed


def test_write_adds_only_keys_that_were_set(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    write(parse(ACCOUNT), path)
    assert path.read_text() == (
        "schema_version = 1\n\n"
        "[accounts.work]\n"
        'host = "imap.example.com"\n'
        'tls = "implicit"\n'
        'login = "user@example.com"\n'
    )


def test_write_drops_a_key_set_back_to_its_default(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(ACCOUNT + 'port = 143\n[accounts.work.aliases]\nplus_separator = "+"\n')
    write(parse(ACCOUNT), path)
    text = path.read_text()
    assert "port" not in text
    assert "plus_separator" not in text
    assert "# keep me" in text
