"""STARTTLS buffered-bytes probe by feature, not by version (A§2.2, T-07)."""

from __future__ import annotations

import socket
import ssl
from typing import Any


class PreTlsBytes(Exception):
    """Bytes were buffered after the STARTTLS OK, before the handshake."""


class NoProbe(Exception):
    """Neither read buffer is reachable on this interpreter."""


def client_buffer(imap: Any) -> Any:
    """The probe's read buffer by feature: ``_readbuf``, else ``file.peek``."""
    if hasattr(imap, "_readbuf"):
        readbuf = imap._readbuf
        if isinstance(readbuf, bytes | bytearray | list | tuple):
            return readbuf
        raise NoProbe
    peek = getattr(getattr(imap, "file", None), "peek", None)
    if callable(peek):
        return peek
    raise NoProbe


def bytes_pending(imap: Any) -> bool:
    """Whether any byte sits in the client buffer or the kernel buffer."""
    buffer = client_buffer(imap)
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
