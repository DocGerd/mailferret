"""IMAP connection layer: guarded sessions only; see ARCHITECTURE A§2.2, A§6, SECURITY §3."""

from mailferret.imap.capabilities import Capabilities, parse_capabilities
from mailferret.imap.caps import CommandCaps, LiteralItem, default_caps, fetch_caps, max_messages
from mailferret.imap.errors import (
    CommandRejected,
    ConnectError,
    ConnectErrorCode,
    ConnectionDropped,
    DeadlineExceeded,
    HookBypassed,
    LimitBreach,
    LoginInputRefused,
    LoginRejected,
    ReadOnlyViolation,
    ServerError,
    SessionError,
    SessionTimeout,
)
from mailferret.imap.lifecycle import AccountSession
from mailferret.imap.logging_pin import pin_imapclient_logging
from mailferret.imap.session import ReadOnlySession
from mailferret.imap.tls import TlsMode, build_context
from mailferret.imap.transport import connect

pin_imapclient_logging()

__all__ = [
    "AccountSession",
    "Capabilities",
    "CommandCaps",
    "CommandRejected",
    "ConnectError",
    "ConnectErrorCode",
    "ConnectionDropped",
    "DeadlineExceeded",
    "HookBypassed",
    "LimitBreach",
    "LiteralItem",
    "LoginInputRefused",
    "LoginRejected",
    "ReadOnlySession",
    "ReadOnlyViolation",
    "ServerError",
    "SessionError",
    "SessionTimeout",
    "TlsMode",
    "build_context",
    "connect",
    "default_caps",
    "fetch_caps",
    "max_messages",
    "parse_capabilities",
    "pin_imapclient_logging",
]
