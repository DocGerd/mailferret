"""Codepoint-safe truncation (A§2.4, T-19)."""

from __future__ import annotations

from dataclasses import dataclass

_CONTINUATION_MASK = 0xC0
_CONTINUATION = 0x80
_MAX_SEQUENCE = 4


@dataclass(frozen=True, slots=True)
class Truncated:
    text: str
    truncated: bool
    stripped: bool = False


def truncate_chars(text: str, max_chars: int) -> Truncated:
    """Keep at most ``max_chars`` codepoints."""
    if max_chars < 0:
        raise ValueError("max_chars must not be negative")
    if len(text) <= max_chars:
        return Truncated(text, False)
    return Truncated(text[:max_chars], True)


def truncate_utf8_bytes(data: bytes, max_bytes: int) -> tuple[bytes, bool]:
    """Cut UTF-8 ``data`` to at most ``max_bytes`` without splitting a sequence."""
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    if len(data) <= max_bytes:
        return data, False
    cut = max_bytes
    for _ in range(_MAX_SEQUENCE - 1):
        if cut > 0 and data[cut] & _CONTINUATION_MASK == _CONTINUATION:
            cut -= 1
        else:
            break
    return data[:cut], True


def truncate_text_bytes(text: str, max_bytes: int) -> Truncated:
    """Keep the longest prefix of ``text`` whose UTF-8 form fits ``max_bytes``."""
    encoded = text.encode("utf-8", errors="replace")
    kept, truncated = truncate_utf8_bytes(encoded, max_bytes)
    if not truncated:
        return Truncated(text, False)
    return Truncated(kept.decode("utf-8", errors="ignore"), True)


def drop_incomplete_utf8_tail(data: bytes) -> bytes:
    """Drop a trailing UTF-8 sequence cut short, as left by a partial fetch."""
    size = len(data)
    for back in range(1, min(_MAX_SEQUENCE, size) + 1):
        byte = data[size - back]
        if byte & _CONTINUATION_MASK == _CONTINUATION:
            continue
        return data[: size - back] if _sequence_length(byte) > back else data
    return data


def _sequence_length(lead: int) -> int:
    if 0xC2 <= lead < 0xE0:
        return 2
    if 0xE0 <= lead < 0xF0:
        return 3
    if 0xF0 <= lead < 0xF5:
        return 4
    return 1
