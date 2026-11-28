"""Removal of characters that hide or reorder displayed text (T-04, T-21)."""

from __future__ import annotations

import unicodedata
from typing import Final

# Not Cf, but blank when rendered: grapheme joiner, Hangul and Khmer fillers.
_BLANKS: Final = dict.fromkeys(
    [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0],
)


def strip_format(text: str) -> tuple[str, bool]:
    """Remove Cf characters (bidi controls, zero-width, BOM, tags); report whether any went."""
    if text.isascii():
        return text, False
    kept = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return kept, len(kept) != len(text)


def strip_invisible(text: str) -> tuple[str, bool]:
    """Remove Cf characters and the non-Cf invisibles; report whether any went."""
    if text.isascii():
        return text, False
    kept, _ = strip_format(text)
    kept = kept.translate(_BLANKS)
    return kept, kept != text
