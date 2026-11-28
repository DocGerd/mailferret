"""Test doubles for the guard mixin: no network, so the same code runs on every minor."""

from __future__ import annotations

import imaplib
import re
from typing import Any

from mailferret.imap.caps import default_caps
from mailferret.imap.guard import GuardMixin, _State
from mailferret.limits import Limits


class _MemoryIO(imaplib.IMAP4):
    """Bytes in, bytes out; stands where imaplib's socket I/O is, below the mixin."""

    sent: list[bytes]
    incoming: list[bytes]
    reads: list[int]

    def send(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def readline(self) -> bytes:
        return self.incoming.pop(0)

    def read(self, size: int) -> bytes:
        self.reads.append(size)
        data = self.incoming.pop(0)
        return data[:size]


class Sink(GuardMixin, _MemoryIO):
    """A guarded ``IMAP4`` that never connects."""


def make_sink(
    limits: Limits | None = None, incoming: list[bytes] | None = None, *, greeting: bool = True
) -> Sink:
    limits = limits or Limits()
    imap = Sink.__new__(Sink)
    imap._mf = _State(limits=limits, caps=default_caps(limits))
    imap.sent = []
    imap.reads = []
    imap.incoming = list(incoming or [])
    imap.tagpre = b"A"
    imap.tagnum = 0
    imap.tagged_commands = {}
    imap.untagged_responses = {}
    imap._encoding = "ascii"
    imap.tagre = re.compile(rb"(?P<tag>A\d+) (?P<type>[A-Z]+) (?P<data>.*)", re.ASCII)
    if greeting:
        imap._mf.lines_read = 1
    return imap


def arm(imap: Sink) -> bytes:
    """What imapclient does first: take a tag."""
    tag: bytes = imap._new_tag()
    return tag


def line(tag: bytes, text: bytes) -> bytes:
    return tag + b" " + text


def dead(imap: Any) -> bool:
    return bool(imap.discarded)
