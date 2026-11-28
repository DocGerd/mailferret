"""A connect in progress that another thread can shut down (`L-13`, A§2.2).

The socket exists only inside imaplib's constructor, which blocks through the TLS handshake and
the greeting. The transport registers each socket object that carries the connection (the TLS
object, registered before its handshake runs), so ``shutdown`` acts on the very object a blocked
read waits on. A duplicate would not do: on Windows a shutdown of a duplicate does not wake a
``recv`` on the original.
"""

from __future__ import annotations

import contextlib
import socket
import sys
import threading

from mailferret.imap.errors import DeadlineExceeded


class ConnectHandle:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._closed = False
        self._registered = False

    @property
    def registered(self) -> bool:
        return self._registered

    def register(self, sock: socket.socket) -> None:
        """Replaces the registered socket; refused once ``shutdown`` ran (the caller closes it)."""
        with self._lock:
            if self._closed:
                raise DeadlineExceeded
            self._sock = sock
            self._registered = True

    def shutdown(self) -> None:
        """Interrupt a blocked connect; the handle refuses every later socket."""
        with self._lock:
            self._closed = True
            sock = self._sock
            if sock is None:
                return
            # Not SSLSocket.shutdown: it detaches the TLS object, and a blocked read would stay.
            with contextlib.suppress(OSError):
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            if sys.platform == "win32":
                # Closing aborts a blocked call there; a shutdown alone may not.
                with contextlib.suppress(OSError):
                    sock.close()

    def release(self) -> None:
        """The connect finished or failed; the socket belongs to the session now."""
        with self._lock:
            self._closed = True
            self._sock = None
