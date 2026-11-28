"""Backend protocol and the ``<login>@<host>`` entry key (A§2, T-11)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from mailferret.credentials.errors import CredentialRejected
from mailferret.credentials.secret import Secret

SERVICE_PREFIX = "mailferret/"
_FORBIDDEN = frozenset("\r\n\0")


@dataclass(frozen=True)
class EntryKey:
    """Service ``mailferret/<account_id>``, username ``<login>@<host>``."""

    account_id: str
    login: str
    host: str

    def __post_init__(self) -> None:
        for part in (self.account_id, self.login, self.host):
            if not part or _FORBIDDEN.intersection(part):
                raise CredentialRejected from None

    @property
    def service(self) -> str:
        return f"{SERVICE_PREFIX}{self.account_id}"

    @property
    def username(self) -> str:
        return f"{self.login}@{self.host}"


@dataclass(frozen=True)
class BackendDescription:
    kind: str
    backend: str | None
    secure: bool
    status: str
    wsl: bool = False
    bus: str | None = None


@runtime_checkable
class CredentialBackend(Protocol):
    def get(self, key: EntryKey) -> Secret: ...

    def set(self, key: EntryKey, secret: Secret) -> None: ...

    def delete(self, key: EntryKey) -> None: ...

    def describe(self) -> BackendDescription: ...
