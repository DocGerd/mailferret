"""IMAP connection layer; see ARCHITECTURE A§2.2, SECURITY T-07."""

from mailferret.imap.capabilities import Capabilities, parse_capabilities
from mailferret.imap.errors import ConnectError, ConnectErrorCode
from mailferret.imap.tls import TlsMode, build_context
from mailferret.imap.transport import Connection, connect

__all__ = [
    "Capabilities",
    "ConnectError",
    "ConnectErrorCode",
    "Connection",
    "TlsMode",
    "build_context",
    "connect",
    "parse_capabilities",
]
