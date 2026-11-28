"""Pure vetting of command lines for the read-only guard (R1, R2; A§6). No I/O.

Every function raises ``ReadOnlyViolation`` with a fixed reason and never echoes the line,
which may be a LOGIN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from mailferret.imap.errors import ReadOnlyViolation

ALLOWED_VERBS: Final = frozenset(
    {
        "CAPABILITY",
        "NOOP",
        "LOGOUT",
        "STARTTLS",
        "LOGIN",
        "AUTHENTICATE",
        "ID",
        "NAMESPACE",
        "LIST",
        "LSUB",
        "STATUS",
        "EXAMINE",
        "CLOSE",
        "UNSELECT",
        "SEARCH",
        "FETCH",
        "SORT",
        "THREAD",
    }
)
UID_VERBS: Final = frozenset({"SEARCH", "FETCH", "SORT", "THREAD"})
RAW_VERBS: Final = frozenset({"SEARCH", "SORT", "THREAD"})

CRLF: Final = b"\r\n"
_ILLEGAL = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f-\xff]")
_ANNOUNCEMENT = re.compile(rb"\{(\d{1,10})(\+?)\}\Z")
_VERB = re.compile(rb"(?:(UID) )?([A-Za-z]+)(?= |\Z)", re.IGNORECASE)

_FIELD = rb"""(?:[A-Za-z0-9!#$&'+\-./;<=>?@^_`|~]+|"(?:[^"\\\x00-\x1f\x7f-\xff]|\\["\\])*")"""
_MSGTEXT = rb"(?:HEADER\.FIELDS(?:\.NOT)? \(" + _FIELD + rb"(?: " + _FIELD + rb")*\)|HEADER|TEXT)"
_PART = rb"[1-9][0-9]{0,9}(?:\.[1-9][0-9]{0,9})*"
_SECTION = rb"(?:" + _MSGTEXT + rb"|" + _PART + rb"(?:\.(?:" + _MSGTEXT + rb"|MIME))?)?"
_ITEM = (
    rb"(?:UID|FLAGS|INTERNALDATE|RFC822\.SIZE|ENVELOPE|BODYSTRUCTURE|RFC822\.HEADER"
    rb"|BODY\.PEEK\[" + _SECTION + rb"\](?:<[0-9]{1,10}\.[0-9]{1,10}>)?)"
)
_FETCH_ARGS = re.compile(
    rb" [0-9*:,]+ (?:" + _ITEM + rb"|\(" + _ITEM + rb"(?: " + _ITEM + rb")*\))\Z",
    re.IGNORECASE,
)
_AUTH_REPLY = re.compile(rb"[A-Za-z0-9+/=]*|\*")


@dataclass(frozen=True)
class Line:
    """A send split into its content and whether it ends the line with CRLF."""

    content: bytes
    terminated: bool


@dataclass(frozen=True)
class Command:
    verb: str
    uid: bool
    announced: int | None
    terminated: bool


def split_line(data: bytes) -> Line:
    """Reject every control or 8-bit byte except one closing CRLF."""
    terminated = data.endswith(CRLF)
    content = data[:-2] if terminated else data
    if b"\r" in content or b"\n" in content:
        raise ReadOnlyViolation("line_break_in_command")
    if _ILLEGAL.search(content):
        raise ReadOnlyViolation("illegal_bytes")
    return Line(content, terminated)


def announcement(tail: bytes) -> int | None:
    """The size of a literal announced at the end of ``tail``; ``{n+}`` is always refused."""
    match = _ANNOUNCEMENT.search(tail)
    if match is None:
        return None
    if match.group(2):
        raise ReadOnlyViolation("literal_plus_refused")
    return int(match.group(1))


def parse_armed(data: bytes, tag: bytes) -> Command:
    """Vet the first ``send`` after ``_new_tag`` before any byte is written."""
    if not data.startswith(tag + b" "):
        raise ReadOnlyViolation("foreign_tag")
    line = split_line(data)
    rest = line.content[len(tag) + 1 :]
    match = _VERB.match(rest)
    if match is None:
        raise ReadOnlyViolation("unparseable_command")
    uid = match.group(1) is not None
    verb = match.group(2).decode("ascii").upper()
    if verb == "UID" or verb not in ALLOWED_VERBS or (uid and verb not in UID_VERBS):
        raise ReadOnlyViolation("verb_not_allowed")
    if verb == "FETCH" and not _FETCH_ARGS.fullmatch(rest[match.end() :]):
        raise ReadOnlyViolation("fetch_item_not_allowed")
    announced = announcement(line.content)
    if verb in RAW_VERBS:
        if announced is not None and not line.terminated:
            raise ReadOnlyViolation("unterminated_command")
    else:
        if not line.terminated:
            raise ReadOnlyViolation("unterminated_command")
        if announced is not None:
            raise ReadOnlyViolation("literal_in_command")
    return Command(verb, uid, announced, line.terminated)


def vet_name(name: str, first_arg: object) -> None:
    """The early, clearer check of ``_command``: the verb alone, never the arguments."""
    verb = name.upper()
    if verb == "UID":
        if str(first_arg).upper() not in UID_VERBS:
            raise ReadOnlyViolation("verb_not_allowed")
    elif verb not in ALLOWED_VERBS:
        raise ReadOnlyViolation("verb_not_allowed")


def is_auth_reply(data: bytes) -> bool:
    """An AUTHENTICATE reply: a base64 token, the cancel ``*``, or the closing CRLF."""
    return data == CRLF or _AUTH_REPLY.fullmatch(data) is not None
