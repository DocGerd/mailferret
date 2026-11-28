"""Bytes to text: declared charset, then a guarded fallback chain (R§11, T-19)."""

from __future__ import annotations

import codecs
from dataclasses import dataclass
from typing import Final

from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
_MAX_LABEL_CHARS: Final = 64
_UTF8: Final = "utf-8"
_CP1252: Final = "cp1252"
_LATIN1: Final = "iso8859-1"
_LATIN_FAMILY: Final = frozenset({"ascii", _LATIN1, _CP1252})
# Codecs that transform rather than label a charset (UTF-7 can smuggle markup).
_DENIED: Final = frozenset(
    {
        "utf-7",
        "idna",
        "punycode",
        "unicode-escape",
        "raw-unicode-escape",
        "undefined",
        "mbcs",
        "oem",
        "charmap",
    }
)


@dataclass(frozen=True, slots=True)
class DecodedText:
    text: str
    charset: str
    fallback: bool
    truncated: bool


def resolve_charset(label: str | bytes | None) -> str | None:
    """Return the Python codec name for a declared charset, or ``None`` if unusable."""
    if label is None:
        return None
    try:
        text = label.decode("ascii") if isinstance(label, bytes) else label
        text = text.strip().strip("\"'").strip()
        if not text or len(text) > _MAX_LABEL_CHARS or not text.isascii():
            return None
        name = codecs.lookup(text).name
        if name in _DENIED:
            return None
        b"".decode(name)
        "".encode(name)
    except Exception:  # CPython codecs can raise outside the documented errors
        return None
    return name


def _attempt(data: bytes, codec: str, errors: str, *, final: bool) -> str | None:
    try:
        return codecs.getincrementaldecoder(codec)(errors=errors).decode(data, final=final)
    except Exception:  # CPython codecs can raise outside the documented errors
        return None


def decode_text(
    data: bytes,
    charset: str | bytes | None = None,
    *,
    partial: bool = False,
    limits: Limits = _DEFAULT_LIMITS,
) -> DecodedText:
    """Decode ``data`` to text; never raises and never trusts the label.

    ``partial`` marks data cut at an arbitrary byte (a partial fetch): an incomplete
    trailing sequence is dropped, not read as a mislabel. Input over ``max_part_bytes``
    (L-02) is cut and counts as partial.
    """
    truncated = len(data) > limits.max_part_bytes
    if truncated:
        data = data[: limits.max_part_bytes]
    final = not (partial or truncated)

    declared = resolve_charset(charset)
    if declared is None or declared in _LATIN_FAMILY:
        order = [_UTF8, _CP1252, _LATIN1]
    elif declared == _UTF8:
        order = [_UTF8]
    else:
        order = [declared, _UTF8]

    for codec in order:
        text = _attempt(data, codec, "strict", final=final)
        if text is not None:
            same_family = codec in _LATIN_FAMILY and declared in _LATIN_FAMILY
            fallback = (
                bool(charset) and codec != declared and not same_family and not data.isascii()
            )
            return DecodedText(text, codec, fallback, truncated)

    codec = _UTF8 if declared is None or declared in _LATIN_FAMILY else declared
    text = _attempt(data, codec, "replace", final=final)
    if text is None:
        codec = _UTF8
        text = _attempt(data, _UTF8, "replace", final=final) or ""
    return DecodedText(text, codec, True, truncated)
