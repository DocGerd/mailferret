"""Exact and wildcard alias patterns, matched client-side only (T-09, A§2.6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
MIN_PREFILTER_CHARS: Final = 3


@dataclass(frozen=True, slots=True)
class Pattern:
    text: str
    wildcard: bool


def compile_pattern(raw: str, limits: Limits = _DEFAULT_LIMITS) -> Pattern:
    """Validate and lower-case a pattern; ``*`` and ``?`` are the only metacharacters.

    Raises ``ValueError`` for an empty, over-long (L-23) or control-bearing pattern.
    """
    if not raw or len(raw) > limits.max_query_chars:
        raise ValueError("alias pattern is empty or too long")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in raw):
        raise ValueError("alias pattern contains control characters")
    text = raw.lower()
    return Pattern(text, "*" in text or "?" in text)


def glob_match(pattern: str, text: str) -> bool:
    """Iterative ``*``/``?`` match with no backtracking blow-up and no character classes."""
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif star >= 0:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def matches(pattern: Pattern, address: str) -> bool:
    """``address`` must already be lower-case (as ``Alias.address`` is)."""
    if pattern.wildcard:
        return glob_match(pattern.text, address)
    return pattern.text == address


def prefilter_fragment(pattern: Pattern) -> str | None:
    """The literal text for the server-side prefilter (A§2.6).

    An exact pattern is its own fragment. A wildcard yields its longest literal run when that
    has at least ``MIN_PREFILTER_CHARS`` characters, else ``None`` (no prefilter).
    """
    if not pattern.wildcard:
        return pattern.text
    runs = [run for chunk in pattern.text.split("*") for run in chunk.split("?")]
    best = max(runs, key=len, default="")
    return best if len(best) >= MIN_PREFILTER_CHARS else None
