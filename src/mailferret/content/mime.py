"""Bounded MIME structure: BODYSTRUCTURE and raw walks, part selection, part decoding (T-05).

Everything here treats its input as hostile: walks are iterative (no recursion), count every
node against ``L-07`` and depth against ``L-06``, never allocate from a declared size, and parse
each part in its own try block so one bad part costs a note, not the message. Notes carry codes,
limit IDs and part sections only, never mail-derived text.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import islice
from typing import Final, Literal

from mailferret.content.charset import decode_text
from mailferret.content.headers import (
    Parameters,
    decode_header_value,
    decode_parameters,
    parse_header_parameters,
)
from mailferret.content.truncate import truncate_chars
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
_TOKEN: Final = re.compile(r"[a-z0-9!#$&^_.+-]{1,64}")
_TYPE: Final = re.compile(r"[a-z0-9!#$&^_.+-]{1,64}/[a-z0-9!#$&^_.+-]{1,64}")
_MAX_BOUNDARY: Final = 128
_MAX_PARAM_PAIRS: Final = 64
_MAX_ENCODING_CHARS: Final = 32
_HEADERS: Final = frozenset(
    {b"content-type", b"content-transfer-encoding", b"content-disposition", b"content-id"}
)
_BASE64_JUNK: Final = bytes(
    b
    for b in range(256)
    if b not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
_HEX: Final = b"0123456789abcdefABCDEF"
_IDENTITY_ENCODINGS: Final = frozenset({"7bit", "8bit", "binary", ""})
_BODY_TYPES: Final = ("text/plain", "text/html")

NoteKind = Literal["limit_exceeded", "malformed", "part_failed", "charset_fallback", "unsupported"]


@dataclass(frozen=True, slots=True)
class Note:
    """A fact about the input; ``limit`` is an L-table ID, ``part`` an IMAP section."""

    kind: NoteKind
    limit: str | None = None
    part: str | None = None


@dataclass(frozen=True, slots=True)
class PartInfo:
    """A leaf part. ``size`` is a declared hint (BODYSTRUCTURE) or the encoded body length."""

    section: str
    content_type: str
    encoding: str
    size: int | None
    depth: int
    charset: str | None = None
    disposition: str | None = None
    filename: str | None = None
    content_id: str | None = None
    span: tuple[int, int] | None = None

    @property
    def is_attachment(self) -> bool:
        if self.disposition == "attachment" or self.filename:
            return True
        return self.content_type not in _BODY_TYPES


@dataclass(frozen=True, slots=True)
class MimeTree:
    """Leaf parts in document order. ``usable`` is false only if no structure could be read."""

    parts: tuple[PartInfo, ...]
    notes: tuple[Note, ...]
    usable: bool


@dataclass(frozen=True, slots=True)
class BodySelection:
    part: PartInfo | None
    fetch_bytes: int
    notes: tuple[Note, ...] = ()


@dataclass(frozen=True, slots=True)
class AttachmentListing:
    items: tuple[PartInfo, ...]
    total: int
    truncated: bool
    notes: tuple[Note, ...] = ()


@dataclass(frozen=True, slots=True)
class DecodedPart:
    section: str
    text: str | None
    charset: str | None
    truncated: bool
    notes: tuple[Note, ...] = ()


class _Notes:
    def __init__(self) -> None:
        self._seen: set[tuple[NoteKind, str | None, str | None]] = set()
        self.items: list[Note] = []

    def add(self, kind: NoteKind, limit: str | None = None, part: str | None = None) -> None:
        key = (kind, limit, None if limit else part)
        if key not in self._seen:
            self._seen.add(key)
            self.items.append(Note(kind, limit, part))


def _join(section: str, index: int) -> str:
    return f"{section}.{index}" if section else str(index)


def _token(value: object, default: str) -> str:
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    if isinstance(value, str):
        lowered = value.strip().lower()
        if _TOKEN.fullmatch(lowered):
            return lowered
    return default


def _size(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _text(value: object, limits: Limits) -> str | None:
    if isinstance(value, bytes | str):
        return decode_header_value(value, limits).text
    return None


def _pairs(value: object) -> list[tuple[bytes | str, bytes | str]]:
    if not isinstance(value, tuple | list):
        return []
    flat = list(islice(value, _MAX_PARAM_PAIRS * 2))
    return [
        (name, val)
        for name, val in zip(flat[0::2], flat[1::2], strict=False)
        if isinstance(name, bytes | str) and isinstance(val, bytes | str)
    ]


def _param_values(value: object, limits: Limits) -> Parameters:
    return decode_parameters(_pairs(value), limits)


def _disposition(value: object, limits: Limits) -> tuple[str | None, Mapping[str, str]]:
    if isinstance(value, tuple | list) and len(value) >= 1 and isinstance(value[0], bytes | str):
        name = _token(value[0], "")
        params = _param_values(value[1], limits).values if len(value) > 1 else {}
        return name or None, params
    return None, {}


# --- BODYSTRUCTURE ----------------------------------------------------------------------------


def _is_multipart(node: tuple[object, ...] | list[object]) -> bool:
    return bool(node) and isinstance(node[0], list | tuple)


def _children(node: tuple[object, ...] | list[object], budget: int) -> list[object]:
    first = node[0]
    if isinstance(first, list):
        return list(islice(first, budget))
    out: list[object] = []
    for item in islice(node, budget):
        if not isinstance(item, tuple):
            break
        out.append(item)
    return out


def _leaf(
    node: tuple[object, ...] | list[object], section: str, depth: int, limits: Limits
) -> PartInfo:
    if len(node) < 7:
        raise ValueError("short body part")
    maintype = _token(node[0], "application")
    subtype = _token(node[1], "octet-stream")
    content_type = f"{maintype}/{subtype}"
    params = _param_values(node[2], limits)
    index = 9 if maintype == "text" else 11 if content_type == "message/rfc822" else 8
    disposition, disp_params = _disposition(node[index] if len(node) > index else None, limits)
    filename = disp_params.get("filename") or params.values.get("name")
    encoding = node[5]
    encoded = encoding.decode("latin-1") if isinstance(encoding, bytes) else encoding
    return PartInfo(
        section=section,
        content_type=content_type,
        encoding=encoded.strip().lower()[:_MAX_ENCODING_CHARS] if isinstance(encoded, str) else "",
        size=_size(node[6]),
        depth=depth,
        charset=params.values.get("charset"),
        disposition=disposition,
        filename=filename or None,
        content_id=_text(node[3], limits),
    )


def parse_bodystructure(structure: object, limits: Limits = _DEFAULT_LIMITS) -> MimeTree:
    """Flatten an imapclient ``BODYSTRUCTURE`` value (or any tuple/list of that shape).

    The walk stops at ``max_mime_depth`` (L-06) and ``max_mime_parts`` (L-07) with a note and a
    still-usable tree. A node that cannot be read is dropped with a ``part_failed`` note.
    """
    notes = _Notes()
    parts: list[PartInfo] = []
    if not isinstance(structure, tuple | list) or not structure:
        return MimeTree((), (Note("malformed"),), False)
    stack: list[tuple[object, int, str]] = [(structure, 1, "")]
    visited = 0
    failed = False
    while stack:
        node, depth, section = stack.pop()
        if visited >= limits.max_mime_parts:
            notes.add("limit_exceeded", "L-07")
            break
        visited += 1
        if depth > limits.max_mime_depth:
            notes.add("limit_exceeded", "L-06")
            continue
        try:
            if not isinstance(node, tuple | list) or not node:
                raise ValueError("not a body part")
            if _is_multipart(node):
                kids = _children(node, limits.max_mime_parts - visited + 1)
                for index in reversed(range(len(kids))):
                    stack.append((kids[index], depth + 1, _join(section, index + 1)))
            else:
                parts.append(_leaf(node, section or "1", depth, limits))
        except Exception:  # per-part fault isolation: hostile shapes raise anything
            notes.add("part_failed", part=section or "1")
            failed = True
    usable = bool(parts) or not failed
    return MimeTree(tuple(parts), tuple(notes.items), usable)


# --- raw message ------------------------------------------------------------------------------


def _header_block(raw: bytes, start: int, end: int) -> tuple[int, int]:
    """Return ``(header_end, body_start)`` of the part spanning ``raw[start:end]``."""
    if raw.startswith(b"\r\n", start, end):
        return start, start + 2
    if raw.startswith(b"\n", start, end):
        return start, start + 1
    lf = raw.find(b"\n\n", start, end)
    crlf = raw.find(b"\n\r\n", start, end)
    candidates = [(i + 1, i + 2) for i in (lf,) if i >= 0]
    candidates += [(i + 1, i + 3) for i in (crlf,) if i >= 0]
    if not candidates:
        return end, end
    return min(candidates)


def _read_headers(
    raw: bytes, start: int, header_end: int, limits: Limits, notes: _Notes
) -> dict[bytes, bytes]:
    cap = start + limits.max_header_bytes
    if header_end > cap:
        notes.add("limit_exceeded", "L-05")
    out: dict[bytes, bytes] = {}
    name: bytes | None = None
    value: list[bytes] = []

    def flush() -> None:
        if name is not None and name in _HEADERS and name not in out:
            out[name] = b" ".join(value)

    for line in raw[start : min(header_end, cap)].split(b"\n"):
        line = line.rstrip(b"\r")
        if line[:1] in (b" ", b"\t"):
            if name is not None:
                value.append(line.strip())
            continue
        flush()
        key, sep, rest = line.partition(b":")
        name = key.strip().lower() if sep else None
        value = [rest.strip()]
    flush()
    return out


def _find_delimiter(
    raw: bytes, delimiter: bytes, pos: int, end: int, floor: int
) -> tuple[int, int, bool] | None:
    """Find the next delimiter line: ``(line_start, next_line_start, closing)``."""
    while True:
        at = raw.find(delimiter, pos, end)
        if at < 0:
            return None
        pos = at + 1
        if at != floor and raw[at - 1] != 10:
            continue
        cursor = at + len(delimiter)
        closing = raw.startswith(b"--", cursor, end)
        if closing:
            cursor += 2
        while cursor < end and raw[cursor] in (32, 9):
            cursor += 1
        if cursor >= end:
            return at, end, closing
        if raw[cursor] == 10:
            return at, cursor + 1, closing
        if raw[cursor] == 13 and raw.startswith(b"\n", cursor + 1, end):
            return at, cursor + 2, closing


def _split_multipart(
    raw: bytes, body_start: int, end: int, boundary: bytes, limit: int
) -> tuple[list[tuple[int, int]], bool]:
    """Child spans (at most ``limit`` + 1) and whether the closing delimiter was seen."""
    delimiter = b"--" + boundary
    spans: list[tuple[int, int]] = []
    child: int | None = None
    pos = body_start
    while len(spans) <= limit:
        found = _find_delimiter(raw, delimiter, pos, end, body_start)
        if found is None:
            break
        line_start, next_start, closing = found
        if child is not None:
            stop = line_start
            if stop > child and raw[stop - 1] == 10:
                stop -= 1
                if stop > child and raw[stop - 1] == 13:
                    stop -= 1
            spans.append((child, stop))
        child = None if closing else next_start
        if closing:
            return spans, True
        pos = next_start
    if child is not None and len(spans) <= limit:
        spans.append((child, end))
    return spans, False


def _raw_leaf(
    raw: bytes,
    headers: Mapping[bytes, bytes],
    content_type: str,
    section: str,
    depth: int,
    body: tuple[int, int],
    limits: Limits,
) -> PartInfo:
    ctype = parse_header_parameters(headers.get(b"content-type", b""), limits)
    dispo = parse_header_parameters(headers.get(b"content-disposition", b""), limits)
    encoding = headers.get(b"content-transfer-encoding", b"").decode("latin-1")
    cid = headers.get(b"content-id")
    filename = dispo.parameters.values.get("filename") or ctype.parameters.values.get("name")
    return PartInfo(
        section=section,
        content_type=content_type,
        encoding=encoding.strip().lower()[:_MAX_ENCODING_CHARS],
        size=body[1] - body[0],
        depth=depth,
        charset=ctype.parameters.values.get("charset"),
        disposition=_token(dispo.value, "") or None,
        filename=filename or None,
        content_id=_text(cid, limits) if cid is not None else None,
        span=body,
    )


def walk_message(raw: bytes, limits: Limits = _DEFAULT_LIMITS) -> MimeTree:
    """Walk a full RFC 822 message (the ``BODY.PEEK[]`` fallback) without copying regions.

    Only the first ``max_message_bytes`` (L-01) are read. A part is a leaf unless it is a
    multipart with a usable boundary; ``message/rfc822`` parts are leaves and are not descended.
    """
    notes = _Notes()
    end = len(raw)
    if end > limits.max_message_bytes:
        end = limits.max_message_bytes
        notes.add("limit_exceeded", "L-01")
    parts: list[PartInfo] = []
    failed = False
    stack: list[tuple[int, int, int, str, str]] = [(0, end, 1, "", "text/plain")]
    visited = 0
    while stack:
        start, stop, depth, section, default = stack.pop()
        if visited >= limits.max_mime_parts:
            notes.add("limit_exceeded", "L-07")
            break
        visited += 1
        if depth > limits.max_mime_depth:
            notes.add("limit_exceeded", "L-06")
            continue
        try:
            header_end, body_start = _header_block(raw, start, stop)
            headers = _read_headers(raw, start, header_end, limits, notes)
            ctype = parse_header_parameters(headers.get(b"content-type", b""), limits)
            content_type = (
                ctype.value
                if _TOKEN.fullmatch(ctype.value.replace("/", "", 1)) and "/" in ctype.value
                else default
            )
            if content_type.startswith("multipart/"):
                boundary = ctype.parameters.values.get("boundary", "").encode("utf-8", "replace")
                kids: list[tuple[int, int]] = []
                if 0 < len(boundary) <= _MAX_BOUNDARY:
                    room = limits.max_mime_parts - visited + 1
                    kids, closed = _split_multipart(raw, body_start, stop, boundary, room)
                    if kids and not closed and len(kids) <= room:
                        notes.add("malformed", part=section or "1")
                if kids:
                    child_default = (
                        "message/rfc822" if content_type == "multipart/digest" else "text/plain"
                    )
                    for index in reversed(range(len(kids))):
                        child = kids[index]
                        stack.append(
                            (
                                child[0],
                                child[1],
                                depth + 1,
                                _join(section, index + 1),
                                child_default,
                            )
                        )
                    continue
                notes.add("malformed", part=section or "1")
                content_type = "text/plain"
            parts.append(
                _raw_leaf(
                    raw, headers, content_type, section or "1", depth, (body_start, stop), limits
                )
            )
        except Exception:  # per-part fault isolation
            notes.add("part_failed", part=section or "1")
            failed = True
    return MimeTree(tuple(parts), tuple(notes.items), bool(parts) or not failed)


# --- selection ------------------------------------------------------------------------------


def select_body(tree: MimeTree, limits: Limits = _DEFAULT_LIMITS) -> BodySelection:
    """Pick the text body: the first inline ``text/plain``, else the first inline ``text/html``.

    ``fetch_bytes`` is the partial-fetch length, always ``max_part_bytes`` (L-02): a declared
    size is a hint and never shortens the fetch. A declared size over the cap adds an L-02 note;
    the cap is enforced on read.
    """
    chosen: PartInfo | None = None
    for wanted in _BODY_TYPES:
        for part in tree.parts:
            if part.content_type == wanted and not part.is_attachment:
                chosen = part
                break
        if chosen is not None:
            break
    if chosen is None:
        return BodySelection(None, 0)
    cap = limits.max_part_bytes
    if chosen.size is not None and chosen.size > cap:
        return BodySelection(chosen, cap, (Note("limit_exceeded", "L-02", chosen.section),))
    return BodySelection(chosen, cap)


def list_attachments(
    tree: MimeTree, body: PartInfo | None = None, limits: Limits = _DEFAULT_LIMITS
) -> AttachmentListing:
    """Attachments in order, at most ``max_attachments_listed`` (L-18); ``total`` counts all."""
    found = [p for p in tree.parts if p.is_attachment and p is not body]
    kept = tuple(found[: limits.max_attachments_listed])
    cut = len(found) > len(kept)
    return AttachmentListing(
        kept, len(found), cut, (Note("limit_exceeded", "L-18"),) if cut else ()
    )


def attachment_fetchable(part: PartInfo, limits: Limits = _DEFAULT_LIMITS) -> bool:
    """False if the declared size already exceeds ``max_attachment_bytes`` (L-08)."""
    return part.size is None or part.size <= limits.max_attachment_bytes


# --- decoding -------------------------------------------------------------------------------


def _decode_base64(data: bytes, *, partial: bool) -> bytes:
    clean = data.translate(None, _BASE64_JUNK)
    tail = len(clean) % 4
    if tail:
        clean = clean[:-tail] if partial or tail == 1 else clean + b"=" * (4 - tail)
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _decode_qp(data: bytes, *, partial: bool) -> bytes:
    if partial:
        cut = data.rfind(b"=", max(0, len(data) - 2))
        if cut >= 0 and all(c in _HEX for c in data[cut + 1 :]):
            data = data[:cut]
    return binascii.a2b_qp(data)


def decode_transfer(data: bytes, encoding: str, *, partial: bool = False) -> bytes | None:
    """Undo the transfer encoding; ``None`` if ``encoding`` is not one this module decodes."""
    if encoding == "base64":
        return _decode_base64(data, partial=partial)
    if encoding == "quoted-printable":
        return _decode_qp(data, partial=partial)
    if encoding in _IDENTITY_ENCODINGS:
        return data
    return None


def decode_part(
    part: PartInfo,
    data: bytes,
    *,
    partial: bool = False,
    max_chars: int | None = None,
    limits: Limits = _DEFAULT_LIMITS,
) -> DecodedPart:
    """Transfer-decode, charset-decode and cap one part's bytes.

    ``data`` is the part body as fetched. Input over ``max_part_bytes`` (L-02) is cut and the
    result is truncated; output is capped at ``min(max_chars, max_body_chars)`` (L-03), except
    ``text/html``: its markup is converted first (A§3 step 7), so the caller truncates after that.
    """
    notes = _Notes()
    cut = len(data) > limits.max_part_bytes
    if cut:
        data = data[: limits.max_part_bytes]
        notes.add("limit_exceeded", "L-02", part.section)
    incomplete = partial or cut
    raw = decode_transfer(data, part.encoding, partial=incomplete)
    if raw is None:
        notes.add("unsupported", part=part.section)
        raw = data
    decoded = decode_text(raw, part.charset, partial=incomplete, limits=limits)
    if decoded.fallback:
        notes.add("charset_fallback", part=part.section)
    if decoded.truncated:
        notes.add("limit_exceeded", "L-02", part.section)
    text = decoded.text
    text_cut = False
    if part.content_type != "text/html":
        cap = limits.max_body_chars if max_chars is None else min(max_chars, limits.max_body_chars)
        capped = truncate_chars(text, cap)
        text, text_cut = capped.text, capped.truncated
        if text_cut:
            notes.add("limit_exceeded", "L-03", part.section)
    return DecodedPart(
        part.section,
        text,
        decoded.charset,
        cut or decoded.truncated or text_cut,
        tuple(notes.items),
    )


def decode_parts(
    items: Iterable[tuple[PartInfo, bytes]],
    *,
    partial: bool = False,
    max_chars: int | None = None,
    limits: Limits = _DEFAULT_LIMITS,
) -> list[DecodedPart]:
    """Decode each part in its own try block; a failing part yields ``text=None`` and a note."""
    results: list[DecodedPart] = []
    for part, data in items:
        try:
            results.append(
                decode_part(part, data, partial=partial, max_chars=max_chars, limits=limits)
            )
        except Exception:  # per-part fault isolation
            results.append(
                DecodedPart(
                    part.section, None, None, False, (Note("part_failed", part=part.section),)
                )
            )
    return results


def part_bytes(raw: bytes, part: PartInfo, limits: Limits = _DEFAULT_LIMITS) -> bytes:
    """The encoded body of a part from :func:`walk_message`, cut to ``max_part_bytes`` (L-02)."""
    if part.span is None:
        raise ValueError("part has no span")
    start, stop = part.span
    return raw[start : min(stop, start + limits.max_part_bytes + 1)]
