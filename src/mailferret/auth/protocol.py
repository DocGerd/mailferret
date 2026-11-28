"""The ``Authenticator`` protocol (A§2): ``account`` is the validated ``<login>@<host>`` key."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from mailferret.credentials import CredentialBackend, EntryKey
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.session import ReadOnlySession


class Authenticator(Protocol):
    def check(self, account: EntryKey) -> None:
        """Raise before any connection when a marker forbids a login."""
        ...

    def authenticate(
        self, session: ReadOnlySession, account: EntryKey, backend: CredentialBackend
    ) -> None: ...


def guard_connect(
    authenticator: Authenticator,
    account: EntryKey,
    connect: Callable[[ConnectHandle], ReadOnlySession],
) -> Callable[[ConnectHandle], ReadOnlySession]:
    """The ``connect`` for ``AccountSession``: no socket opens while a marker forbids a login."""

    def guarded(handle: ConnectHandle) -> ReadOnlySession:
        authenticator.check(account)
        return connect(handle)

    return guarded
