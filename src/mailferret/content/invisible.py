"""Removal of characters that hide or reorder displayed text (T-04, T-21)."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

# Not Cf, but blank when rendered: grapheme joiner, Hangul and Khmer fillers, and the
# supplementary variation selectors (a covert 256-symbol channel).
_BLANKS: Final = dict.fromkeys([0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0])
_BLANKS.update(dict.fromkeys(range(0xE0100, 0xE01F0)))
_VS16: Final = chr(0xFE0F)
_SELECTORS: Final = re.compile(f"[{chr(0xFE00)}-{_VS16}]+")


def strip_format(text: str) -> tuple[str, bool]:
    """Remove Cf characters (bidi controls, zero-width, BOM, tags); report whether any went."""
    if text.isascii():
        return text, False
    kept = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return kept, len(kept) != len(text)


def _selector_run(match: re.Match[str]) -> str:
    """Keep one emoji presentation selector that follows a character; drop any other run."""
    start = match.start()
    keep = match.group() == _VS16 and start > 0 and not match.string[start - 1].isspace()
    return _VS16 if keep else ""


def strip_invisible(text: str) -> tuple[str, bool]:
    """Remove Cf characters, blank fillers and stray variation selectors; report any change."""
    if text.isascii():
        return text, False
    kept, _ = strip_format(text)
    kept = _SELECTORS.sub(_selector_run, kept.translate(_BLANKS))
    return kept, kept != text
