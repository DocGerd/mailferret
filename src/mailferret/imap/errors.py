"""Typed errors with fixed codes; server text never reaches a message (T-03, T-21).

None of these subclasses ``imaplib.IMAP4.error``: imaplib re-wraps those with server text.
"""

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
    "hook_bypassed",
    "limit_exceeded",
    "read_only_violation",
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
    "hook_unavailable": "the imaplib hooks are unavailable on this interpreter",
    "hook_bypassed": "an imaplib hook did not run",
    "limit_exceeded": "the server response exceeded a limit",
    "read_only_violation": "a command was refused by the read-only guard",
    "protocol_error": "the server sent an unexpected response",
}


class ConnectError(Exception):
    """A connection that was not, or must not be, used; ``code`` is the stable reason."""

    def __init__(self, code: ConnectErrorCode) -> None:
        super().__init__(MESSAGES[code])
        self.code: ConnectErrorCode = code


ViolationReason = Literal[
    "verb_not_allowed",
    "fetch_item_not_allowed",
    "unparseable_command",
    "foreign_tag",
    "illegal_bytes",
    "line_break_in_command",
    "unterminated_command",
    "literal_in_command",
    "literal_plus_refused",
    "command_in_flight",
    "send_outside_command",
    "literal_before_continuation",
    "literal_length_mismatch",
    "session_discarded",
]

VIOLATION_MESSAGES: Final[dict[ViolationReason, str]] = {
    "verb_not_allowed": "the command is not on the read-only allowlist",
    "fetch_item_not_allowed": "a FETCH item is not on the read-only allowlist",
    "unparseable_command": "the command line could not be parsed",
    "foreign_tag": "the command line does not carry the armed tag",
    "illegal_bytes": "the command line contains illegal bytes",
    "line_break_in_command": "a line break inside a command",
    "unterminated_command": "a command line that cannot be completed",
    "literal_in_command": "a literal in a command that may not carry one",
    "literal_plus_refused": "non-synchronising literals are refused",
    "command_in_flight": "a new command while another is in flight",
    "send_outside_command": "bytes sent outside a command in flight",
    "literal_before_continuation": "literal bytes before the server's continuation",
    "literal_length_mismatch": "literal bytes do not match the announced length",
    "session_discarded": "the session was discarded",
}


class SessionError(Exception):
    """Base of the errors raised by a live session; ``code`` is the stable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReadOnlyViolation(SessionError):
    """Raised before a byte is sent; never carries the line (it may be a LOGIN)."""

    def __init__(self, reason: ViolationReason) -> None:
        super().__init__("read_only_violation", VIOLATION_MESSAGES[reason])
        self.reason: ViolationReason = reason


BreachKind = Literal["literal_over_cap", "response_over_total", "line_over_limit"]


class LimitBreach(SessionError):
    """A hostile response: over a literal cap, the response total or `L-20` (T-08)."""

    def __init__(self, kind: BreachKind, limit: str) -> None:
        super().__init__("limit_exceeded", f"the server response exceeded {limit}")
        self.kind: BreachKind = kind
        self.limit = limit


class HookBypassed(SessionError):
    """A liveness check or the tripwire found a hook that did not run (R5)."""

    def __init__(self, check: str) -> None:
        super().__init__("hook_bypassed", f"an imaplib hook did not run: {check}")
        self.check = check


class SessionTimeout(SessionError):
    """An `L-11` or `L-12` timeout: never reconnected."""

    def __init__(self) -> None:
        super().__init__("timeout", "the server did not answer in time")


class DeadlineExceeded(SessionError):
    """The `L-13` deadline shut the session down: never reconnected."""

    def __init__(self) -> None:
        super().__init__("timeout", "the tool deadline passed")


class ConnectionDropped(SessionError):
    """A dropped connection: the only failure that is re-opened, once per call."""

    def __init__(self) -> None:
        super().__init__("connection_dropped", "the connection was dropped")


class CommandRejected(SessionError):
    """A tagged NO or BAD after login; the session stays usable."""

    def __init__(self, completion: Literal["NO", "BAD"]) -> None:
        super().__init__("command_rejected", f"the server answered {completion}")
        self.completion: Literal["NO", "BAD"] = completion


class LoginRejected(SessionError):
    """A tagged NO or BAD to LOGIN or AUTHENTICATE: an explicit rejection (T-16)."""

    def __init__(self) -> None:
        super().__init__("login_rejected", "the server rejected the login")


class LoginInputRefused(SessionError):
    """`login` takes ASCII ``str`` only (T-02); nothing was sent."""

    def __init__(self) -> None:
        super().__init__("non_ascii_credential", "the credential cannot be sent with LOGIN")


class ServerError(SessionError):
    """Any other library failure; ``session_usable`` says whether the session was kept."""

    def __init__(self, *, session_usable: bool) -> None:
        super().__init__("server_error", "the server sent an unusable response")
        self.session_usable = session_usable
