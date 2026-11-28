"""In-memory backend for tests, through the same protocol (A§2.1)."""

from __future__ import annotations

from mailferret.credentials.errors import CredentialNotFound
from mailferret.credentials.protocol import BackendDescription, EntryKey
from mailferret.credentials.secret import Secret


class MemoryBackend:
    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get(self, key: EntryKey) -> Secret:
        try:
            return Secret(self._store[(key.service, key.username)])
        except KeyError:
            raise CredentialNotFound from None

    def set(self, key: EntryKey, secret: Secret) -> None:
        self._store[(key.service, key.username)] = secret.reveal()

    def delete(self, key: EntryKey) -> None:
        if self._store.pop((key.service, key.username), None) is None:
            raise CredentialNotFound

    def describe(self) -> BackendDescription:
        return BackendDescription(kind="memory", backend=None, secure=False, status="ok")
