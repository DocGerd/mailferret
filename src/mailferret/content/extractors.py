"""Attachment text extractors keyed by MIME type (A§2, T-06).

Every extractor takes the part as fetched (transfer-encoded) and returns a :class:`DecodedPart`
within the same byte and char limits; one failing part costs a note, never the message. The HTML
slot is filled by the HTML converter (C3); until then it reports ``unsupported``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from mailferret.content.mime import (
    DecodedPart,
    Note,
    PartInfo,
    decode_part,
    decode_transfer,
)
from mailferret.content.pdf_host import extract_pdf
from mailferret.content.truncate import truncate_chars
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()

Extractor = Callable[[PartInfo, bytes, Limits], DecodedPart]


def _failed(part: PartInfo, *notes: Note) -> DecodedPart:
    return DecodedPart(part.section, None, None, False, notes)


def extract_plain(part: PartInfo, data: bytes, limits: Limits) -> DecodedPart:
    return decode_part(part, data, limits=limits)


def extract_pdf_part(part: PartInfo, data: bytes, limits: Limits) -> DecodedPart:
    raw = decode_transfer(data, part.encoding)
    if raw is None:
        return _failed(part, Note("unsupported", part=part.section))
    result = extract_pdf(raw, limits)
    notes = tuple(Note(n.kind, n.limit, part.section) for n in result.notes)
    text = None if result.text is None else truncate_chars(result.text, limits.max_body_chars).text
    return DecodedPart(part.section, text, None, result.truncated, notes)


def extract_unsupported(part: PartInfo, data: bytes, limits: Limits) -> DecodedPart:
    return _failed(part, Note("unsupported", part=part.section))


DEFAULT_EXTRACTORS: Final[Mapping[str, Extractor]] = MappingProxyType(
    {
        "application/pdf": extract_pdf_part,
        "text/plain": extract_plain,
        "text/html": extract_unsupported,
    }
)


def extract_text(
    part: PartInfo,
    data: bytes,
    limits: Limits = _DEFAULT_LIMITS,
    *,
    extractors: Mapping[str, Extractor] = DEFAULT_EXTRACTORS,
) -> DecodedPart:
    """Text of one attachment, from the extractor for its MIME type; never raises."""
    try:
        extractor = extractors.get(part.content_type.lower())
        if extractor is None:
            return _failed(part, Note("unsupported", part=part.section))
        if len(data) > limits.max_attachment_bytes:
            return _failed(part, Note("limit_exceeded", "L-08", part.section))
        return extractor(part, data, limits)
    except Exception:  # per-part fault isolation
        return _failed(part, Note("part_failed", part=part.section))
