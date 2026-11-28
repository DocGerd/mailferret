"""Connect: implicit TLS or STARTTLS, never plaintext (T-07, A§2.2)."""

from __future__ import annotations

import contextlib
import imaplib
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from imapclient import IMAPClient  # type: ignore[import-untyped]
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from imapclient.imap4 import IMAP4WithTimeout  # type: ignore[import-untyped]
from imapclient.imapclient import SocketTimeout  # type: ignore[import-untyped]

from mailferret.imap.capabilities import Capabilities, parse_capabilities
from mailferret.imap.errors import ConnectError
from mailferret.imap.tls import TlsMode, build_context
from mailferret.limits import Limits


class _PreTlsBytes(Exception):
    """Bytes were buffered after the STARTTLS OK, before the handshake."""


class _NoProbe(Exception):
    """Neither read buffer is reachable on this interpreter."""


def _client_buffer(imap: Any) -> Any:
    """The probe's read buffer by feature: ``_readbuf``, else ``file.peek``."""
    if hasattr(imap, "_readbuf"):
        readbuf = imap._readbuf
        if isinstance(readbuf, bytes | bytearray | list | tuple):
            return readbuf
        raise _NoProbe
    peek = getattr(getattr(imap, "file", None), "peek", None)
    if callable(peek):
        return peek
    raise _NoProbe


def _bytes_pending(imap: Any) -> bool:
    """Whether any byte sits in the client buffer or the kernel buffer."""
    buffer = _client_buffer(imap)
    sock: socket.socket = imap.sock
    previous = sock.gettimeout()
    sock.settimeout(0.0)
    try:
        try:
            if callable(buffer):
                if buffer(1):
                    return True
            elif any(buffer) if isinstance(buffer, list | tuple) else len(buffer):
                return True
        except BlockingIOError:
            pass
        try:
            return bool(sock.recv(1, socket.MSG_PEEK))
        except (BlockingIOError, ssl.SSLWantReadError):
            return False
    finally:
        sock.settimeout(previous)


class _ProbedIMAP4(IMAP4WithTimeout):  # type: ignore[misc]
    """Plain-socket IMAP4 whose STARTTLS OK is probed before the wrap."""

    def _command_complete(self, name: str, tag: bytes) -> Any:
        result = super()._command_complete(name, tag)
        if name == "STARTTLS" and result[0] == "OK" and _bytes_pending(self):
            raise _PreTlsBytes
        return result


class _Client(IMAPClient):  # type: ignore[misc]
    def _create_IMAP4(self) -> Any:
        if self.ssl:
            return super()._create_IMAP4()
        return _ProbedIMAP4(self.host, self.port, getattr(self._timeout, "connect", None))


@dataclass
class Connection:
    """An unauthenticated TLS session; ``capabilities`` are the post-TLS ones."""

    client: Any
    capabilities: Capabilities

    def close(self) -> None:
        _shutdown(self.client)


def _shutdown(client: Any) -> None:
    with contextlib.suppress(Exception):
        client.shutdown()


def _starttls(client: Any, ctx: ssl.SSLContext) -> Capabilities:
    """Upgrade; returns the capabilities imaplib re-read after the wrap, never the pre-TLS ones."""
    imap = client._imap
    if not isinstance(getattr(imap, "untagged_responses", None), dict):
        raise ConnectError("hook_unavailable")
    try:
        _client_buffer(imap)
    except _NoProbe:
        raise ConnectError("hook_unavailable") from None
    if not parse_capabilities(client.capabilities()).starttls:
        raise ConnectError("starttls_unavailable")
    try:
        client.starttls(ctx)
    except _PreTlsBytes:
        raise ConnectError("pre_tls_bytes") from None
    except (imaplib.IMAP4.error, IMAPClientError):
        raise ConnectError("starttls_refused") from None
    return parse_capabilities(imap.capabilities)


def connect(
    host: str,
    port: int,
    mode: TlsMode,
    *,
    ca_file: Path | None = None,
    limits: Limits | None = None,
) -> Connection:
    """Open a verified TLS session or raise ``ConnectError``; no credential is ever sent."""
    limits = limits or Limits()
    timeout = SocketTimeout(limits.imap_connect_seconds, limits.imap_read_seconds)
    try:
        ctx = build_context(ca_file)
    except (OSError, ssl.SSLError):
        raise ConnectError("ca_file_unreadable") from None
    client: Any = None
    try:
        client = _Client(host, port, ssl=mode is TlsMode.IMPLICIT, ssl_context=ctx, timeout=timeout)
        if mode is TlsMode.STARTTLS:
            return Connection(client, _starttls(client, ctx))
        return Connection(client, parse_capabilities(client.capabilities()))
    except Exception as exc:
        if client is not None:
            _shutdown(client)
        raise _map(exc) from None


def _map(exc: Exception) -> Exception:
    if isinstance(exc, ConnectError):
        return exc
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ConnectError("tls_verify_failed")
    if isinstance(exc, ssl.SSLError):
        return ConnectError("tls_failed")
    if isinstance(exc, TimeoutError):
        return ConnectError("timeout")
    if isinstance(exc, OSError):
        return ConnectError("connect_failed")
    if isinstance(exc, imaplib.IMAP4.error | IMAPClientError):
        return ConnectError("protocol_error")
    return exc
