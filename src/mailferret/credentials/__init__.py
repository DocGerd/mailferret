"""Credential backends (A§2, A§2.1). Only this package touches secrets."""

from mailferret.credentials.command_backend import CommandBackend
from mailferret.credentials.errors import (
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialRejected,
    CredentialTimeout,
)
from mailferret.credentials.protocol import BackendDescription, CredentialBackend, EntryKey
from mailferret.credentials.secret import Secret, accept_output, validate_new_secret

__all__ = [
    "BackendDescription",
    "CommandBackend",
    "CredentialBackend",
    "CredentialBackendError",
    "CredentialBackendUnavailable",
    "CredentialError",
    "CredentialLimitExceeded",
    "CredentialLocked",
    "CredentialNotFound",
    "CredentialRejected",
    "CredentialTimeout",
    "EntryKey",
    "Secret",
    "accept_output",
    "validate_new_secret",
]
