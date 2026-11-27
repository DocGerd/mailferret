"""Scriptable IMAP server on 127.0.0.1, one thread per connection, with a wire log."""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Self

from tests.support.imap_fake.tls import TlsMaterial

_CHUNK = 64 * 1024
_LITERAL_RE = re.compile(rb"\{(\d+)(\+?)\}$")


@dataclass(frozen=True)
class Literal:
    """`prefix {declared}CRLF <size bytes> suffix`; `declared` defaults to `size`."""

    size: int
    declared: int | None = None
    prefix: bytes = b"* 1 FETCH (UID 1 BODY[] "
    suffix: bytes = b")\r\n"
    fill: bytes = b"x"


@dataclass(frozen=True)
class Flood:
    """`size` bytes with no line ending (an oversized line), CRLF-terminated if asked."""

    size: int
    terminate: bool = False
    fill: bytes = b"x"


@dataclass(frozen=True)
class Stall:
    """Send nothing more, but keep reading and logging client lines until EOF or stop."""


@dataclass(frozen=True)
class Close:
    """Drop the connection."""


@dataclass(frozen=True)
class Mark:
    """Record `name` in `events` once everything before it has been sent."""

    name: str


@dataclass(frozen=True)
class ReadLine:
    """Read and log one more client line (e.g. an AUTHENTICATE response)."""


Part = bytes | str | Literal | Flood | Stall | Close | Mark | ReadLine


@dataclass(frozen=True)
class Command:
    tag: str
    line: str
    verb: str
    sub: str | None
    conn: int = 0


Handler = Callable[[Command], Sequence[Part]]
_REFUSED = object()


class _Conn:
    """Socket plus read buffer; no `makefile`, so `close()` wakes a blocked read on Windows."""

    def __init__(self, sock: socket.socket, index: int) -> None:
        self.index = index
        self.sock: socket.socket = sock
        self.buf = b""
        self.tls = False

    def upgrade(self, ctx: ssl.SSLContext) -> None:
        self.sock = ctx.wrap_socket(self.sock, server_side=True)
        self.buf = b""
        self.tls = True

    def _fill(self) -> bool:
        chunk = self.sock.recv(_CHUNK)
        self.buf += chunk
        return bool(chunk)

    def read_line(self) -> bytes | None:
        while b"\n" not in self.buf:
            if not self._fill():
                break
        if not self.buf:
            return None
        line, sep, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r") if sep else line

    def read(self, size: int) -> bytes:
        while len(self.buf) < size and self._fill():
            pass
        data, self.buf = self.buf[:size], self.buf[size:]
        return data

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


class FakeImapServer:
    def __init__(
        self,
        *,
        capabilities: list[str] | None = None,
        tls: TlsMaterial | None = None,
        implicit_tls: bool = False,
        greeting: bytes = b"* OK ready\r\n",
        literals: bool = True,
        literal_plus: bool = True,
        advertise_starttls: bool = True,
    ) -> None:
        self.capabilities = capabilities if capabilities is not None else ["IMAP4rev1"]
        self.advertise_starttls = advertise_starttls
        self.greeting = greeting
        self.literals = literals
        self.literal_plus = literal_plus
        self.implicit_tls = implicit_tls
        self.starttls_inject = b""
        self.starttls_late = b""
        self.starttls_hold: threading.Event | None = None
        self.commands: list[Command] = []
        self.events: list[str] = []
        self._wire: list[tuple[int, str]] = []
        self._connections = 0
        self._threads: list[threading.Thread] = []
        self._ctx = tls.server_context() if tls else None
        self._handlers: dict[str, list[tuple[Sequence[Part] | Handler, bool]]] = {}
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._conns: list[_Conn] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="fake-imap-accept", daemon=True
        )

    @property
    def wire(self) -> list[str]:
        """Every client line, literal and continuation, across all connections."""
        return [line for _, line in self._wire]

    @property
    def connections(self) -> int:
        """Connections accepted so far; the nth one has index n (1-based)."""
        return self._connections

    def wire_of(self, conn: int) -> list[str]:
        return [line for index, line in self._wire if index == conn]

    def commands_of(self, conn: int) -> list[Command]:
        return [cmd for cmd in self.commands if cmd.conn == conn]

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> None:
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        self._listener.close()
        with self._cond:
            conns = list(self._conns)
            threads = [self._accept_thread, *self._threads]
        for conn in conns:
            conn.close()
        for thread in threads:
            if thread.is_alive():
                thread.join(5)

    def on(self, key: str, reply: Sequence[Part] | Handler, *, once: bool = False) -> None:
        """Script `key` ("FETCH" or "UID FETCH"; the more specific wins); `{tag}` is substituted."""
        self._handlers.setdefault(key.upper(), []).append((reply, once))

    def wait_for_wire(self, line: str, timeout: float = 10.0) -> None:
        with self._cond:
            if not self._cond.wait_for(lambda: line in self.wire, timeout):
                raise TimeoutError(f"wire line {line!r} not seen; wire={self.wire}")

    def wait_for(self, name: str, timeout: float = 10.0) -> None:
        with self._cond:
            if not self._cond.wait_for(lambda: name in self.events, timeout):
                raise TimeoutError(f"event {name!r} not reached; events={self.events}")

    def _event(self, name: str) -> None:
        with self._cond:
            self.events.append(name)
            self._cond.notify_all()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock, _ = self._listener.accept()
            except OSError:
                return
            if self._stop.is_set():
                sock.close()
                return
            with self._cond:
                self._connections += 1
                index = self._connections
            self._event(f"accepted:{index}")
            thread = threading.Thread(
                target=self._serve, args=(sock, index), name="fake-imap-conn", daemon=True
            )
            with self._cond:
                self._threads.append(thread)
            thread.start()

    def _serve(self, sock: socket.socket, index: int) -> None:
        conn = _Conn(sock, index)
        with self._cond:
            self._conns.append(conn)
        try:
            if self.implicit_tls:
                self._upgrade(conn)
            conn.sock.sendall(self.greeting)
            self._loop(conn)
        except (OSError, ssl.SSLError) as exc:
            self._event(f"error:{type(exc).__name__}")
        finally:
            conn.close()
            self._event("closed")

    def _upgrade(self, conn: _Conn) -> None:
        if self._ctx is None:
            raise ssl.SSLError("no TLS material configured")
        conn.upgrade(self._ctx)
        self._event("handshake")

    def _loop(self, conn: _Conn) -> None:
        while not self._stop.is_set():
            cmd = self._read_command(conn)
            if cmd is None:
                return
            if cmd is _REFUSED:
                continue
            assert isinstance(cmd, Command)
            self.commands.append(cmd)
            if not self._dispatch(conn, cmd):
                return

    def _log(self, conn: _Conn, line: bytes) -> None:
        with self._cond:
            self._wire.append((conn.index, line.decode("latin-1")))
            self._cond.notify_all()

    def _read_command(self, conn: _Conn) -> Command | object | None:
        first = conn.read_line()
        if first is None:
            return None
        self._log(conn, first)
        text, line = first, first
        while m := _LITERAL_RE.search(line):
            if not self.literals or (m[2] and not self.literal_plus):
                refuse_tag = first.split(b" ")[0]
                conn.sock.sendall(refuse_tag + b" BAD literals refused\r\n")
                return _REFUSED
            if not m[2]:
                conn.sock.sendall(b"+ go\r\n")
            size = int(m[1])
            data = conn.read(size)
            if len(data) != size:
                return None
            self._log(conn, b"<literal %d>" % size + data)
            tail = conn.read_line()
            if tail is None:
                return None
            self._log(conn, tail)
            line = tail
            text += b"<lit>" + tail
        decoded = text.decode("latin-1")
        tag, _, rest = decoded.partition(" ")
        words = rest.split(" ")
        verb = words[0].upper()
        sub = words[1].upper() if verb == "UID" and len(words) > 1 else None
        return Command(tag, decoded, verb, sub, conn.index)

    def _lookup(self, cmd: Command) -> Sequence[Part] | Handler | None:
        keys = [f"{cmd.verb} {cmd.sub}"] if cmd.sub else []
        for key in (*keys, cmd.verb):
            entries = self._handlers.get(key)
            if entries:
                reply, once = entries[0]
                if once:
                    entries.pop(0)
                return reply
        return None

    def _dispatch(self, conn: _Conn, cmd: Command) -> bool:
        scripted = self._lookup(cmd)
        if scripted is not None:
            parts = scripted(cmd) if callable(scripted) else scripted
            return self._emit(conn, cmd, parts)
        if cmd.verb == "STARTTLS":
            return self._starttls(conn, cmd)
        return self._emit(conn, cmd, self._default(conn, cmd))

    def _caps(self, conn: _Conn) -> str:
        caps = list(self.capabilities)
        if self._ctx and not conn.tls and self.advertise_starttls:
            caps.append("STARTTLS")
        return " ".join(caps)

    def _default(self, conn: _Conn, cmd: Command) -> Sequence[Part]:
        ok: Part = b"{tag} OK done\r\n"
        if cmd.verb == "CAPABILITY":
            return [f"* CAPABILITY {self._caps(conn)}\r\n", ok]
        if cmd.verb == "AUTHENTICATE":
            return [b"+ \r\n", ReadLine(), ok]
        if cmd.verb == "LOGOUT":
            return [b"* BYE bye\r\n", ok, Close()]
        return [ok]

    def _starttls(self, conn: _Conn, cmd: Command) -> bool:
        if self._ctx is None or conn.tls:
            conn.sock.sendall(f"{cmd.tag} BAD STARTTLS unavailable\r\n".encode())
            return True
        conn.sock.sendall(f"{cmd.tag} OK begin TLS\r\n".encode() + self.starttls_inject)
        if self.starttls_hold is not None:
            self._event("starttls-held")
            self.starttls_hold.wait(10)
        if self.starttls_late:
            conn.sock.sendall(self.starttls_late)
        self._upgrade(conn)
        return True

    def _emit(self, conn: _Conn, cmd: Command, parts: Sequence[Part]) -> bool:
        tag = cmd.tag.encode()
        for part in parts:
            if isinstance(part, str):
                part = part.encode()
            if isinstance(part, bytes):
                conn.sock.sendall(part.replace(b"{tag}", tag))
            elif isinstance(part, Literal):
                declared = part.size if part.declared is None else part.declared
                conn.sock.sendall(part.prefix + b"{%d}\r\n" % declared)
                self._send_filler(conn, part.fill, part.size)
                conn.sock.sendall(part.suffix)
            elif isinstance(part, Flood):
                self._send_filler(conn, part.fill, part.size)
                if part.terminate:
                    conn.sock.sendall(b"\r\n")
            elif isinstance(part, Stall):
                while (line := conn.read_line()) is not None:
                    self._log(conn, line)
                return False
            elif isinstance(part, Close):
                return False
            elif isinstance(part, Mark):
                self._event(part.name)
            else:
                line = conn.read_line()
                if line is None:
                    return False
                self._log(conn, line)
        return True

    @staticmethod
    def _send_filler(conn: _Conn, fill: bytes, size: int) -> None:
        block = (fill * (_CHUNK // len(fill) + 1))[:_CHUNK]
        remaining = size
        while remaining > 0:
            n = min(remaining, _CHUNK)
            conn.sock.sendall(block[:n])
            remaining -= n
