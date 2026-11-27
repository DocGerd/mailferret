import pytest

from mailferret.config import Account, parse
from mailferret.providers import ProviderError, apply_preset, builtin_presets, resolve_presets


def _account(body: str, login: str = "user@example.com") -> Account:
    return parse(f'[accounts.a]\nlogin = "{login}"\n{body}').accounts["a"]


def test_builtin_names() -> None:
    assert {"generic", "hetzner"} <= set(builtin_presets())


def test_hetzner_supplies_defaults() -> None:
    result = apply_preset(_account('preset = "hetzner"'), resolve_presets())
    assert (result.host, result.port, result.tls) == ("mail.your-server.de", 993, "implicit")


def test_explicit_keys_win() -> None:
    account = _account('preset = "hetzner"\nhost = "imap.example.com"\nport = 1993')
    result = apply_preset(account, resolve_presets())
    assert (result.host, result.port) == ("imap.example.com", 1993)


def test_tls_override_drops_preset_port() -> None:
    result = apply_preset(_account('preset = "hetzner"\ntls = "starttls"'), resolve_presets())
    assert (result.tls, result.port) == ("starttls", 143)


def test_generic_needs_host() -> None:
    with pytest.raises(ProviderError, match="unset"):
        apply_preset(_account('preset = "generic"'), resolve_presets())


def test_generic_with_host() -> None:
    account = _account('preset = "generic"\nhost = "imap.example.com"')
    result = apply_preset(account, resolve_presets())
    assert (result.port, result.tls) == (993, "implicit")


def test_no_preset_is_untouched() -> None:
    account = _account('host = "imap.example.com"\ntls = "implicit"')
    assert apply_preset(account, resolve_presets()) is account


def test_unknown_preset() -> None:
    with pytest.raises(ProviderError, match="unknown preset"):
        apply_preset(_account('preset = "nope"'), resolve_presets())


def test_login_must_be_address() -> None:
    with pytest.raises(ProviderError, match="full address"):
        apply_preset(_account('preset = "hetzner"', login="shop"), resolve_presets())


def test_user_preset() -> None:
    presets = resolve_presets(
        {"corp": {"host": "imap.example.org", "tls": "starttls", "header_priority": ["To"]}}
    )
    result = apply_preset(_account('preset = "corp"'), presets)
    assert (result.host, result.port, result.tls) == ("imap.example.org", 143, "starttls")
    assert result.aliases.header_priority == ["To"]


def test_explicit_header_priority_wins() -> None:
    presets = resolve_presets(
        {"corp": {"host": "h.example.org", "tls": "implicit", "header_priority": ["To"]}}
    )
    account = _account('preset = "corp"\n[accounts.a.aliases]\nheader_priority = ["Cc"]')
    assert apply_preset(account, presets).aliases.header_priority == ["Cc"]


def test_user_preset_cannot_shadow_builtin() -> None:
    with pytest.raises(ProviderError, match="shadows"):
        resolve_presets({"hetzner": {"host": "evil.example.org"}})


def test_invalid_user_preset_hides_values() -> None:
    bad = {"host": "h.example.org", "unknown_key": "x-marker"}
    with pytest.raises(ProviderError) as info:
        resolve_presets({"bad": bad})
    assert "x-marker" not in str(info.value)
