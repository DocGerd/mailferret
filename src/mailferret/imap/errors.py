"""Connection errors with fixed codes; server text never reaches a message (T-03, T-21)."""

from __future__ import annotations

from typing import Final, Literal

ConnectErrorCode = Literal[
    "connect_failed",
    "timeout",
    "tls_verify_failed",
    "tls_failed",
    "ca_file_unreadable",
    "starttls_unavailable",
    "starttls_refused",
    "pre_tls_bytes",
    "hook_unavailable",
    "protocol_error",
]

MESSAGES: Final[dict[ConnectErrorCode, str]] = {
    "connect_failed": "could not connect to the server",
    "timeout": "the server did not answer in time",
    "tls_verify_failed": "the server certificate was not accepted",
    "tls_failed": "the TLS handshake failed",
    "ca_file_unreadable": "the CA file could not be loaded",
    "starttls_unavailable": "the server does not offer STARTTLS",
    "starttls_refused": "the server refused STARTTLS",
    "pre_tls_bytes": "the server sent data before the TLS handshake",
    "hook_unavailable": "the STARTTLS buffer probe is unavailable on this interpreter",
    "protocol_error": "the server sent an unexpected response",
}


class ConnectError(Exception):
    """A connection that was not, or must not be, used; ``code`` is the stable reason."""

    def __init__(self, code: ConnectErrorCode) -> None:
        super().__init__(MESSAGES[code])
        self.code: ConnectErrorCode = code
