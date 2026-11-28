"""``PasswordAuth``: LOGIN or AUTHENTICATE PLAIN from the post-TLS capabilities (A§2, T-02, T-16).

``LOGIN`` unless ``LOGINDISABLED``, else ``AUTHENTICATE PLAIN`` if advertised, else refused
before ``credentials/`` is touched. LOGIN carries the login as a bare atom and the secret as a
quoted string, both printable ASCII; anything else (non-ASCII, a space, a quote or backslash in
the login, a control character in the secret) takes PLAIN (UTF-8, RFC 4616) or is refused with a
fixed-text error. The failure outcome is read after the ``except`` block, so no exception holds
the secret in its ``__context__`` or its traceback.
"""

from __future__ import annotations

import logging
from typing import Final

from mailferret.auth.errors import AuthFailed, LoginPaused
from mailferret.auth.markers import AuthMarkers
from mailferret.credentials import CredentialBackend, CredentialRejected, EntryKey
from mailferret.imap.capabilities import Capabilities
from mailferret.imap.errors import LoginInputRefused, LoginRejected, SessionError
from mailferret.imap.session import ReadOnlySession
from mailferret.logging import authenticate_in_progress, event, get_logger, register_secret

_LOG: Final = get_logger("auth")
_NOT_ATOM: Final = frozenset('(){%*"\\]')
_FORBIDDEN: Final = frozenset("\r\n\0")


def _atom(login: str) -> bool:
    return bool(login) and all("!" <= c <= "~" and c not in _NOT_ATOM for c in login)


def _quotable(secret: str) -> bool:
    return all(" " <= c <= "~" for c in secret)


def _uses_login(login: str, secret: str) -> bool:
    return login.isascii() and secret.isascii() and _atom(login) and _quotable(secret)


def _note(code: str, account: EntryKey, mechanism: str | None = None) -> None:
    fields = {} if mechanism is None else {"mechanism": mechanism}
    try:
        event(_LOG, logging.WARNING, code, account=account.account_id, **fields)
    except (ValueError, TypeError):
        _LOG.warning(code)


class PasswordAuth:
    def __init__(self, markers: AuthMarkers) -> None:
        self._markers = markers

    def check(self, account: EntryKey) -> None:
        state = self._markers.blocked(account)
        if state == "rejected":
            raise AuthFailed("blocked", account.account_id)
        if state == "indeterminate":
            raise LoginPaused

    def authenticate(
        self, session: ReadOnlySession, account: EntryKey, backend: CredentialBackend
    ) -> None:
        self.check(account)
        caps = session.capabilities
        login = account.login
        if caps.logindisabled and not caps.auth_plain:
            raise AuthFailed("no_mechanism", account.account_id)
        if not caps.auth_plain and not (login.isascii() and _atom(login)):
            raise AuthFailed("needs_plain", account.account_id)
        self._send(session, account, backend, caps)
        self._markers.clear_indeterminate(account)
        session.refresh_capabilities()

    def _send(
        self,
        session: ReadOnlySession,
        account: EntryKey,
        backend: CredentialBackend,
        caps: Capabilities,
    ) -> None:
        login = account.login
        secret = backend.get(account)
        value = secret.reveal()
        del secret
        plain = caps.logindisabled or not _uses_login(login, value)
        empty = not value or not _FORBIDDEN.isdisjoint(value)
        unsupported = plain and not caps.auth_plain
        if empty or unsupported:
            del value
            if empty:
                raise CredentialRejected
            raise AuthFailed("needs_plain", account.account_id)
        register_secret(value, login)
        failure: SessionError | None = None
        with authenticate_in_progress():
            try:
                if plain:
                    session.plain_login(login, value)
                else:
                    session.login(login, value)
            except SessionError as exc:
                failure = exc.with_traceback(None)
        del value
        if failure is not None:
            self._fail(session, account, failure, "plain" if plain else "password")

    def _fail(
        self, session: ReadOnlySession, account: EntryKey, failure: SessionError, mechanism: str
    ) -> None:
        if isinstance(failure, LoginRejected):
            self._markers.record_rejected(account)
            _note("auth_rejected", account, mechanism)
            raise AuthFailed("rejected", account.account_id)
        if session.login_sent and not isinstance(failure, LoginInputRefused):
            self._markers.record_indeterminate(account)
            _note("auth_indeterminate", account, mechanism)
        raise failure
