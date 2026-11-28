"""Typed authentication errors with fixed text: no argument can carry a secret (T-02, T-03).

``code`` is a tool error code (A§2.7). None of these subclasses ``imaplib.IMAP4.error``.
"""

from __future__ import annotations

from typing import Final, Literal

AuthFailedReason = Literal["rejected", "blocked", "no_mechanism", "needs_plain"]

_RETRY: Final = (
    "run `mailferret auth set {account}`, or `mailferret auth retry {account}` "
    "if the secret was changed outside mailferret"
)
MESSAGES: Final[dict[AuthFailedReason, str]] = {
    "rejected": "the server rejected the login; " + _RETRY,
    "blocked": "a login was rejected earlier and is not retried; " + _RETRY,
    "no_mechanism": "the server offers no login mechanism mailferret may use for account {account}",
    "needs_plain": (
        "the login or secret of account {account} needs AUTHENTICATE PLAIN, "
        "which the server does not offer"
    ),
}


class AuthError(Exception):
    code = "auth_failed"
    message = "authentication failed"

    def __init__(self) -> None:
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class AuthFailed(AuthError):
    """No login was sent, or the server rejected it; ``reason`` says which."""

    def __init__(self, reason: AuthFailedReason, account_id: str) -> None:
        self.reason: AuthFailedReason = reason
        self.message = MESSAGES[reason].format(account=account_id)
        super().__init__()


class LoginPaused(AuthError):
    """An earlier login got no answer: no new one is sent until the time box ends (T-16)."""

    code = "server_error"
    message = "an earlier login attempt got no answer; no new login is sent for a while"
