"""The read-only guard and read caps, as one mixin on imaplib's ``IMAP4`` (A§2.2, A§6, R1-R5).

``_command`` is not a choke point: imapclient sends SEARCH, SORT and THREAD through
``_new_tag`` + ``send``. So ``_new_tag`` arms the guard, every ``send`` passes the gate, and
``read`` and ``readline`` enforce the caps. After any guard, breach or liveness failure the
session is dead: it never sends or reads again.
"""

from __future__ import annotations

import imaplib
import re
from dataclasses import dataclass, field
from typing import Any, Final, NoReturn

from mailferret.imap import grammar
from mailferret.imap.caps import CommandCaps, default_caps
from mailferret.imap.errors import (
    BreachKind,
    HookBypassed,
    LimitBreach,
    ReadOnlyViolation,
    ViolationReason,
)
from mailferret.imap.probe import PreTlsBytes, bytes_pending
from mailferret.limits import LINE_OVERHEAD_BYTES, Limits

_LITERAL_END: Final = re.compile(rb"\{(\d{1,10})\}\Z")
_IN_FLIGHT: Final = frozenset({"open", "await", "literal", "auth"})


@dataclass
class _State:
    limits: Limits
    caps: CommandCaps
    next_caps: CommandCaps | None = None
    phase: str = "closed"  # closed | armed | open | await | literal | auth
    tag: bytes = b""
    tail: bytes = b""
    literal_left: int = 0
    budget: int = 0
    vetted: set[bytes] = field(default_factory=set)
    vetted_total: int = 0
    completions: int = 0
    lines_read: int = 0
    greeting_lines: int | None = None
    starttls_probed: bool = False
    pending_literal: int | None = None
    expect_trailer: bool = False
    completion: str | None = None
    finished: bytes = b""  # tag whose completion was read, still owed to _command_complete
    dead: bool = False
    dropped: bool = False


def tagre_of(imap: object) -> re.Pattern[bytes] | None:
    """imaplib's tagged-response pattern if it still has the ``tag`` and ``type`` groups."""
    pattern = getattr(imap, "tagre", None)
    if isinstance(pattern, re.Pattern) and {"tag", "type"} <= set(pattern.groupindex):
        return pattern
    return None


def apply_line_cap(limits: Limits) -> None:
    """Set ``imaplib._MAXLINE`` from `L-20`; process-global, so ``readline`` checks it too."""
    imaplib._MAXLINE = limits.max_line_bytes  # type: ignore[attr-defined]


class GuardMixin(imaplib.IMAP4):
    """Put in front of ``IMAP4WithTimeout`` and ``IMAP4_TLS``; needs ``limits=`` at construction."""

    def __init__(self, *args: Any, limits: Limits, **kwargs: Any) -> None:
        self._mf = _State(limits=limits, caps=default_caps(limits))
        super().__init__(*args, **kwargs)

    @property
    def debug(self) -> int:
        return 0

    @debug.setter
    def debug(self, value: int) -> None:
        """imapclient sets 5 after construction; stay at 0 so nothing is ever logged."""

    @property
    def last_completion(self) -> str | None:
        """The type (OK, NO, BAD) of the last tagged completion read for the armed tag."""
        return self._mf.completion

    @property
    def connection_lost(self) -> bool:
        """The socket reached EOF or failed (never a timeout) during the armed command."""
        return self._mf.dropped

    @property
    def commands_started(self) -> int:
        """Command lines the guard has vetted, so a caller can tell whether bytes left."""
        return self._mf.vetted_total

    @property
    def discarded(self) -> bool:
        return self._mf.dead

    def arm_caps(self, caps: CommandCaps) -> None:
        """Caps for the next command only; ``_new_tag`` consumes them."""
        self._mf.next_caps = caps

    def discard(self) -> None:
        """Terminal: nothing is sent or read afterwards."""
        self._mf.dead = True

    def verify_liveness(self, *, starttls: bool) -> None:
        """Each hook ran before LOGIN; raises ``HookBypassed`` and discards on a miss."""
        s = self._mf
        if not s.greeting_lines:
            self._bypassed("greeting")
        if s.vetted_total < 1:
            self._bypassed("send")
        if s.completions < 1:
            self._bypassed("command_complete")
        if starttls and not s.starttls_probed:
            self._bypassed("starttls_probe")
        if self.debug != 0:
            self._bypassed("debug")

    def _violate(self, reason: ViolationReason) -> NoReturn:
        raise ReadOnlyViolation(reason)

    def _breach(self, kind: BreachKind, limit: str) -> NoReturn:
        self._mf.dead = True
        raise LimitBreach(kind, limit)

    def _bypassed(self, check: str) -> NoReturn:
        self._mf.dead = True
        raise HookBypassed(check)

    def _lost(self, exc: OSError) -> None:
        if not isinstance(exc, TimeoutError):
            self._mf.dropped = True

    def _alive(self) -> None:
        if self._mf.dead:
            raise ReadOnlyViolation("session_discarded")

    def _command(self, name: str, *args: Any) -> Any:  # a clearer error only; send is the gate
        self._alive()
        try:
            grammar.vet_name(name, args[0] if args else None)
        except ReadOnlyViolation:
            self._mf.dead = True
            raise
        return super()._command(name, *args)  # type: ignore[misc]

    def _new_tag(self) -> bytes:
        self._alive()
        s = self._mf
        if s.phase in _IN_FLIGHT:
            self._mf.dead = True
            self._violate("command_in_flight")
        if s.greeting_lines is None:
            s.greeting_lines = s.lines_read
        s.phase = "armed"
        s.tail = b""
        s.literal_left = 0
        s.budget = 0
        s.caps, s.next_caps = s.next_caps or default_caps(s.limits), None
        s.pending_literal = None
        s.expect_trailer = False
        s.completion = None
        s.finished = b""
        s.dropped = False
        self.untagged_responses.clear()
        tag: bytes = super()._new_tag()  # type: ignore[misc]
        s.tag = tag
        return tag

    def send(self, data: bytes) -> None:  # type: ignore[override]
        self._alive()
        if not isinstance(data, bytes):
            self._mf.dead = True
            self._violate("unparseable_command")
        data = bytes(data)
        try:
            self._gate(data)
        except ReadOnlyViolation:
            self._mf.dead = True
            raise
        try:
            super().send(data)
        except OSError as exc:
            self._lost(exc)
            raise

    def _gate(self, data: bytes) -> None:
        s = self._mf
        phase = s.phase
        if phase == "armed":
            self._vet_armed(data)
        elif phase == "open":
            self._vet_fragment(data)
        elif phase == "literal":
            if len(data) != s.literal_left:
                self._violate("literal_length_mismatch")
            s.phase = "open"
            s.tail = b""
        elif phase == "auth":
            if not grammar.is_auth_reply(data):
                self._violate("send_outside_command")
        elif phase == "await":
            self._violate("literal_before_continuation")
        else:
            self._violate("send_outside_command")

    def _vet_armed(self, data: bytes) -> None:
        s = self._mf
        command = grammar.parse_armed(data, s.tag)
        s.vetted.add(s.tag)
        s.vetted_total += 1
        if command.verb not in grammar.RAW_VERBS:
            s.phase = "auth" if command.verb == "AUTHENTICATE" else "closed"
        elif command.announced is not None:
            s.phase, s.literal_left = "await", command.announced
        else:
            s.phase = "closed" if command.terminated else "open"
            s.tail = grammar.pending(data)

    def _vet_fragment(self, data: bytes) -> None:
        """Mid-command shapes of SEARCH, SORT and THREAD: text, a literal announcement, CRLF."""
        s = self._mf
        line = grammar.split_line(data)
        if not line.terminated:
            s.tail = grammar.pending(s.tail + line.content)
            return
        announced = grammar.announcement(s.tail + line.content)
        if announced is None:
            s.phase = "closed"
        else:
            s.phase, s.literal_left = "await", announced

    def _charge(self, size: int) -> None:
        s = self._mf
        s.budget += size
        if s.budget > s.caps.total:
            self._breach("response_over_total", "L-26")

    def read(self, size: int) -> bytes:
        self._alive()
        s = self._mf
        if s.pending_literal != size:
            self._bypassed("literal_read")
        if size > s.caps.literal_cap:
            self._breach("literal_over_cap", s.caps.limit)
        self._charge(size)
        try:
            data: bytes = super().read(size)
        except OSError as exc:
            self._lost(exc)
            raise
        if len(data) != size:
            s.dropped = True
            raise self.abort("socket error: EOF")
        s.pending_literal = None
        s.expect_trailer = True
        return data

    def readline(self) -> bytes:
        self._alive()
        s = self._mf
        if s.pending_literal is not None:
            self._bypassed("literal_read")
        overlong = False
        try:
            line: bytes = super().readline()
        except imaplib.IMAP4.error as exc:
            if isinstance(exc, imaplib.IMAP4.abort):
                raise
            overlong = True
        except OSError as exc:
            self._lost(exc)
            raise
        if overlong:
            self._breach("line_over_limit", "L-20")
        if not line:
            s.dropped = True  # EOF: imaplib raises its abort one frame above this hook
            return line
        s.lines_read += 1
        if len(line) > s.limits.max_line_bytes:
            self._breach("line_over_limit", "L-20")
        self._charge(len(line) + LINE_OVERHEAD_BYTES)
        self._note_line(line[:-2] if line.endswith(b"\r\n") else line)
        return line

    def _note_line(self, text: bytes) -> None:
        s = self._mf
        tagre = tagre_of(self)
        if tagre is None:
            self._bypassed("tagre")
        match = tagre.match(text)
        if match is not None:
            tag = match.group("tag")
            if tag not in s.vetted:
                self._bypassed("unvetted_tag")
            if tag == s.tag:
                s.vetted.discard(tag)
                s.finished = tag
                s.completion = match.group("type").decode("ascii", "replace")
                s.phase = "closed"
        elif s.phase == "await" and text.startswith(b"+"):
            s.phase = "literal"
        elif text.startswith(b"*") or (s.expect_trailer and text):
            announced = _LITERAL_END.search(text)
            s.pending_literal = int(announced.group(1)) if announced else None
            s.expect_trailer = False

    def _command_complete(self, name: str, tag: bytes) -> Any:
        self._alive()
        s = self._mf
        if tag not in s.vetted and tag != s.finished:
            self._bypassed("unvetted_tag")
        try:
            result = super()._command_complete(name, tag)  # type: ignore[misc]
        finally:
            s.vetted.discard(tag)
            s.finished = b""
        s.completions += 1
        if name == "STARTTLS" and result[0] == "OK":
            self.untagged_responses.clear()
            if bytes_pending(self):
                s.dead = True
                raise PreTlsBytes
            s.starttls_probed = True
        return result
