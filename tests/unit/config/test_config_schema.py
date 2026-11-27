import pytest
from pydantic import ConfigDict, ValidationError

from mailferret.config import ConfigError, parse
from mailferret.config.schema import _Strict
from mailferret.limits import CEILINGS as LIMIT_CEILINGS

ACCOUNT = """
[accounts.work]
host = "imap.example.com"
port = 993
tls = "implicit"
login = "user@example.com"
"""


def test_minimal_account_parses() -> None:
    config = parse("schema_version = 1\n" + ACCOUNT)
    assert config.accounts["work"].effective_port == 993
    assert config.accounts["work"].credential_backend == "keyring"


def test_empty_config_has_no_accounts() -> None:
    assert parse("").accounts == {}


KEY_RULE = "secret-named keys are not allowed"


@pytest.mark.parametrize("key", ["password", "token", "secret", "api_key", "Passphrase"])
def test_secret_named_keys_rejected_without_echoing_value(key: str) -> None:
    with pytest.raises(ConfigError) as info:
        parse(ACCOUNT + f'{key} = "hunter2-value"\n')
    assert KEY_RULE in str(info.value)
    assert "hunter2-value" not in str(info.value)


@pytest.mark.parametrize(
    "section", ["", "[accounts.work.aliases]", "[limits]", "[accounts.work.credential_command]"]
)
def test_secret_named_keys_rejected_in_every_section(section: str) -> None:
    text = ACCOUNT if section == "" else ACCOUNT + section + "\n"
    with pytest.raises(ConfigError) as info:
        parse(text + 'token = "hunter2-value"\n')  # pii-check: ignore
    assert KEY_RULE in str(info.value)
    assert "hunter2-value" not in str(info.value)


def test_secret_rule_holds_where_extra_keys_are_allowed() -> None:
    class Loose(_Strict):
        model_config = ConfigDict(extra="allow")

    assert Loose.model_validate({"colour": "red"}).model_dump() == {"colour": "red"}
    with pytest.raises(ValidationError, match=KEY_RULE):
        Loose.model_validate({"api_key": "hunter2-value"})  # pii-check: ignore


def test_unknown_key_rejected() -> None:
    with pytest.raises(ConfigError):
        parse(ACCOUNT + 'colour = "red"\n')


def test_credential_env_outside_allowlist_rejected() -> None:
    text = (
        ACCOUNT.replace('tls = "implicit"', 'tls = "implicit"\ncredential_backend = "command"')
        + '[accounts.work.credential_command]\nget = ["/usr/bin/pass", "show", "x"]\n'
        + '[accounts.work.credential_command.env]\nLD_PRELOAD = "/tmp/x.so"\n'
    )
    with pytest.raises(ConfigError):
        parse(text)


def test_credential_env_allowlisted_name_accepted() -> None:
    text = (
        ACCOUNT.replace('tls = "implicit"', 'tls = "implicit"\ncredential_backend = "command"')
        + '[accounts.work.credential_command]\nget = ["/usr/bin/pass", "show", "x"]\n'
        + "[accounts.work.credential_command.env]\n"
        + 'PASSWORD_STORE_GPG_OPTS = "--pinentry-mode=error"\n'
    )
    assert parse(text).accounts["work"].credential_command is not None


def test_command_backend_needs_command() -> None:
    with pytest.raises(ConfigError):
        parse(
            ACCOUNT.replace('tls = "implicit"', 'tls = "implicit"\ncredential_backend = "command"')
        )


@pytest.mark.parametrize("account_id", ["Work", "-a", "a" * 33, "a b", ""])
def test_bad_account_id_rejected(account_id: str) -> None:
    with pytest.raises(ConfigError):
        parse(ACCOUNT.replace("accounts.work", f'accounts."{account_id}"'))


def test_default_account_must_exist() -> None:
    with pytest.raises(ConfigError):
        parse('default_account = "ghost"\n' + ACCOUNT)


def test_preset_account_may_omit_host_and_tls() -> None:
    config = parse('[accounts.shop]\npreset = "hetzner"\nlogin = "shop@example.com"\n')
    assert config.accounts["shop"].host is None


def test_preset_less_account_needs_host() -> None:
    with pytest.raises(ConfigError):
        parse('[accounts.shop]\nlogin = "shop@example.com"\n')


@pytest.mark.parametrize("section", ["[smtp]", "[accounts.work.write]"])
def test_write_and_smtp_reject_enabled(section: str) -> None:
    parse(ACCOUNT + f"{section}\nenabled = false\n")
    with pytest.raises(ConfigError):
        parse(ACCOUNT + f"{section}\nenabled = true\n")


def test_write_section_rejects_other_keys() -> None:
    with pytest.raises(ConfigError):
        parse(ACCOUNT + "[accounts.work.write]\nenabled = false\nconfirm = false\n")


@pytest.mark.parametrize(("key", "ceiling"), sorted(LIMIT_CEILINGS.items()))
def test_limit_may_lower_but_not_raise(key: str, ceiling: int) -> None:
    parse(f"[limits]\n{key} = {ceiling}\n")
    parse(f"[limits]\n{key} = 1\n")
    with pytest.raises(ConfigError):
        parse(f"[limits]\n{key} = {ceiling + 1}\n")
    with pytest.raises(ConfigError):
        parse(f"[limits]\n{key} = 0\n")


def test_unknown_limit_rejected() -> None:
    with pytest.raises(ConfigError):
        parse("[limits]\nmax_everything = 1\n")


def test_invalid_toml_error() -> None:
    with pytest.raises(ConfigError):
        parse("accounts = [")


@pytest.mark.parametrize(
    "text",
    [
        ACCOUNT.replace("port = 993", "port = true"),
        ACCOUNT.replace("port = 993", 'port = "993"'),
        ACCOUNT.replace("port = 993", "port = 993.0"),
        "[limits]\nmax_page_size = true\n",
        '[limits]\nmax_page_size = "50"\n',
        "schema_version = true\n",
        "schema_version = 2\n",
        ACCOUNT + "[accounts.work.write]\nenabled = 0\n",
        ACCOUNT + '[accounts.work.write]\nenabled = "false"\n',
        "[smtp]\nenabled = 0\n",
    ],
)
def test_toml_values_are_not_coerced(text: str) -> None:
    with pytest.raises(ConfigError):
        parse(text)


@pytest.mark.parametrize(
    "text",
    [
        ACCOUNT.replace('host = "imap.example.com"', 'host = ""'),
        '[accounts.shop]\npreset = ""\nlogin = "shop@example.com"\n',
        '[accounts.shop]\npreset = "x"\nhost = ""\nlogin = "shop@example.com"\n',
        ACCOUNT + '[accounts.work.aliases]\nplus_separator = ""\n',
    ],
)
def test_empty_strings_rejected(text: str) -> None:
    with pytest.raises(ConfigError):
        parse(text)
