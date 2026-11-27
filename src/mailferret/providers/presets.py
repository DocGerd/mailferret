"""Provider presets (A§2): defaults only, explicit account keys win."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from functools import cache
from importlib import resources
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mailferret.config.schema import Account

_DEFAULT_PORTS = {"implicit": 993, "starttls": 143}


class ProviderError(Exception):
    """Invalid preset or preset reference. Messages never contain field values."""


class Preset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    description: str = ""
    host: str | None = Field(default=None, min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    tls: Literal["implicit", "starttls"] | None = None
    login_is_address: bool = False
    header_priority: list[str] | None = Field(default=None, min_length=1)


def _parse(table: Mapping[str, Any], origin: str) -> dict[str, Preset]:
    presets: dict[str, Preset] = {}
    for name, body in table.items():
        try:
            presets[name] = Preset.model_validate(body)
        except ValidationError as error:
            fields = ", ".join(
                ".".join(str(part) for part in item["loc"]) or "<root>"
                for item in error.errors(include_input=False, include_url=False)
            )
            message = f"{origin} preset {name!r} is invalid: {fields}"
        else:
            continue
        # Raised outside the handler so __context__ holds no field values.
        raise ProviderError(message)
    return presets


@cache
def builtin_presets() -> Mapping[str, Preset]:
    text = resources.files(__package__).joinpath("presets.toml").read_text(encoding="utf-8")
    return _parse(tomllib.loads(text), "built-in")


def resolve_presets(user: Mapping[str, Any] | None = None) -> dict[str, Preset]:
    """Built-in presets plus user presets; a user preset may not reuse a built-in name."""
    merged = dict(builtin_presets())
    for name, preset in _parse(user or {}, "user").items():
        if name in merged:
            raise ProviderError(f"user preset {name!r} shadows a built-in preset")
        merged[name] = preset
    return merged


def apply_preset(account: Account, presets: Mapping[str, Preset]) -> Account:
    """Fill the account's unset host, port, tls and alias header priority from its preset."""
    if account.preset is None:
        return account
    preset = presets.get(account.preset)
    if preset is None:
        raise ProviderError(f"unknown preset {account.preset!r}")
    if preset.login_is_address and "@" not in account.login:
        raise ProviderError(f"preset {account.preset!r} needs the full address as login")

    tls = account.tls or preset.tls
    host = account.host or preset.host
    if host is None or tls is None:
        raise ProviderError(f"preset {account.preset!r} leaves host or tls unset")

    port = account.port
    if port is None:
        use_preset_port = preset.port is not None and preset.tls in (None, tls)
        port = preset.port if use_preset_port else _DEFAULT_PORTS[tls]

    update: dict[str, Any] = {"host": host, "port": port, "tls": tls}
    if preset.header_priority is not None and "header_priority" not in (
        account.aliases.model_fields_set
    ):
        update["aliases"] = account.aliases.model_copy(
            update={"header_priority": list(preset.header_priority)}
        )
    return account.model_copy(update=update)
