"""Config schema (A§7). Unknown keys and secret-named keys are rejected (T-01, T-11)."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from mailferret.limits import CEILINGS, merge, violation
from mailferret.limits import Limits as EffectiveLimits

ACCOUNT_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"
AccountId = Annotated[str, StringConstraints(pattern=ACCOUNT_ID_PATTERN)]
PresetName = AccountId

CREDENTIAL_ENV_ALLOWLIST = frozenset({"PASSWORD_STORE_GPG_OPTS", "PASSWORD_STORE_DIR", "GNUPGHOME"})

_SECRET_KEY = re.compile(r"pass(word|wd|phrase)|token|secret|api[_-]?key", re.IGNORECASE)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_secret_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in data:
                if isinstance(key, str) and _SECRET_KEY.search(key):
                    raise ValueError("secret-named keys are not allowed in the config")
        return data


class Limits(_Strict):
    """Optional overrides; a value may only lower the ceiling."""

    max_message_bytes: int | None = None
    max_part_bytes: int | None = None
    max_body_chars: int | None = None
    max_header_value_chars: int | None = None
    max_header_bytes: int | None = None
    max_mime_depth: int | None = None
    max_mime_parts: int | None = None
    max_attachment_bytes: int | None = None
    max_pdf_pages: int | None = None
    pdf_worker_seconds: int | None = None
    pdf_worker_memory_bytes: int | None = None
    pdf_stream_bytes: int | None = None
    imap_connect_seconds: int | None = None
    imap_read_seconds: int | None = None
    tool_deadline_seconds: int | None = None
    credential_command_seconds: int | None = None
    max_page_size: int | None = None
    max_candidates: int | None = None
    max_thread_messages: int | None = None
    max_alias_period_days: int | None = None
    max_alias_scan: int | None = None
    max_attachments_listed: int | None = None
    max_response_bytes: int | None = None
    max_line_bytes: int | None = None
    max_folders: int | None = None
    credential_command_output_bytes: int | None = None
    max_query_chars: int | None = None
    max_criteria: int | None = None
    fetch_batch_size: int | None = None
    max_command_response_bytes: int | None = None
    keyring_probe_seconds: int | None = None
    credential_stderr_bytes: int | None = None
    credential_status_bytes: int | None = None
    max_header_values: int | None = None
    max_header_addresses: int | None = None

    @model_validator(mode="after")
    def _only_lower(self) -> Self:
        for key in CEILINGS:
            value = getattr(self, key)
            problem = None if value is None else violation(key, value)
            if problem:
                raise ValueError(problem)
        return self

    def resolve(self) -> EffectiveLimits:
        return merge(self.model_dump())


class Aliases(_Strict):
    domains: list[str] = Field(default_factory=list)
    plus_separator: str | None = Field(default=None, min_length=1)
    header_priority: list[str] = Field(
        default_factory=lambda: ["Delivered-To", "X-Original-To", "To", "Cc"]
    )


class CredentialCommand(_Strict):
    get: list[str] = Field(min_length=1)
    set: list[str] | None = Field(default=None, min_length=1)
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("env")
    @classmethod
    def _env_allowlist(cls, env: dict[str, str]) -> dict[str, str]:
        for name in env:
            if name not in CREDENTIAL_ENV_ALLOWLIST:
                raise ValueError(f"env name {name!r} is not allowed")
        return env


class Disabled(_Strict):
    """Reserved position: only `enabled = false` validates (A§2.5)."""

    enabled: StrictBool = False

    @field_validator("enabled")
    @classmethod
    def _stay_disabled(cls, enabled: bool) -> bool:
        if enabled:
            raise ValueError("this feature cannot be enabled in this version")
        return enabled


class Preset(_Strict):
    description: str = ""
    host: str | None = Field(default=None, min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    tls: Literal["implicit", "starttls"] | None = None
    login_is_address: bool = False
    header_priority: list[str] | None = Field(default=None, min_length=1)


class Account(_Strict):
    preset: str | None = Field(default=None, min_length=1)
    host: str | None = Field(default=None, min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    tls: Literal["implicit", "starttls"] | None = None
    login: str = Field(min_length=1)
    credential_backend: Literal["keyring", "command"] = "keyring"
    ca_file: str | None = None
    aliases: Aliases = Field(default_factory=Aliases)
    credential_command: CredentialCommand | None = None
    write: Disabled = Field(default_factory=Disabled)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.preset is None and (self.host is None or self.tls is None):
            raise ValueError("host and tls are required without a preset")
        if self.credential_backend == "command" and self.credential_command is None:
            raise ValueError("credential_backend 'command' needs credential_command")
        if self.credential_backend == "keyring" and self.credential_command is not None:
            raise ValueError("credential_command needs credential_backend 'command'")
        return self

    @property
    def effective_port(self) -> int | None:
        if self.port is not None:
            return self.port
        return {"implicit": 993, "starttls": 143}.get(self.tls or "")


class Config(_Strict):
    schema_version: StrictInt = 1
    default_account: AccountId | None = None
    limits: Limits = Field(default_factory=Limits)
    accounts: dict[AccountId, Account] = Field(default_factory=dict)
    presets: dict[PresetName, Preset] = Field(default_factory=dict)
    smtp: Disabled = Field(default_factory=Disabled)

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, version: int) -> int:
        if version != 1:
            raise ValueError("unsupported schema_version")
        return version

    @model_validator(mode="after")
    def _default_exists(self) -> Self:
        if self.default_account is not None and self.default_account not in self.accounts:
            raise ValueError("default_account names no configured account")
        return self
