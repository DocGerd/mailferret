"""Typed credential errors with fixed text: no argument can carry a secret (T-02, T-03)."""

from __future__ import annotations


class CredentialError(Exception):
    code = "error"
    message = "credential lookup failed"

    def __init__(self) -> None:
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class CredentialBackendUnavailable(CredentialError):
    code = "backend_unavailable"
    message = "credential backend unavailable; run `mailferret doctor`"


class CredentialNotFound(CredentialError):
    code = "not_found"
    message = "no credential stored for this account"


class CredentialLocked(CredentialError):
    code = "locked"
    message = "credential store is locked"


class CredentialTimeout(CredentialError):
    code = "timeout"
    message = "credential backend timed out"


class CredentialLimitExceeded(CredentialError):
    code = "limit_exceeded"
    message = "credential backend output exceeded its limit"


class CredentialRejected(CredentialError):
    code = "error"
    message = "credential refused by the secret rule"


class CredentialBackendError(CredentialError):
    code = "error"
    message = "credential backend failed"
