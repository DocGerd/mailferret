"""A connect in progress that another thread can shut down (`L-13`, A§2.2).

The socket exists only inside imaplib's constructor, which blocks through the TLS handshake and
the greeting. ``_create_socket`` registers a duplicate of it here, so ``shutdown`` interrupts
every later step, including a STARTTLS handshake that detaches the registered object itself.
"""

from __future__ import annotations

import contextlib
import socket
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
        """Refused once ``shutdown`` ran: the caller closes ``sock`` and nothing is sent on it."""
        with self._lock:
            if self._closed:
                raise DeadlineExceeded
            self._sock = sock.dup()
            self._registered = True

    def shutdown(self) -> None:
        """Interrupt a blocked connect; the handle refuses every later socket."""
        with self._lock:
            self._closed = True
            sock = self._sock
        if sock is not None:
            with contextlib.suppress(OSError):
                socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def release(self) -> None:
        """Close the duplicate; the connect finished or failed."""
        with self._lock:
            self._closed = True
            sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()
