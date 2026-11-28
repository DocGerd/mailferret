"""Aggregation for ``list_aliases`` (R§5): aliases seen with their message counts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from mailferret.aliases.resolver import resolve_alias
from mailferret.aliases.rules import AliasRules
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()


@dataclass(frozen=True, slots=True)
class AliasCount:
    address: str
    count: int


@dataclass(frozen=True, slots=True)
class Aggregation:
    aliases: list[AliasCount]
    scanned: int
    truncated: bool


def aggregate_aliases(
    messages: Iterable[Mapping[str, Sequence[str | bytes]]],
    rules: AliasRules,
    limits: Limits = _DEFAULT_LIMITS,
) -> Aggregation:
    """Count the resolved alias per message, most frequent first, ties by address.

    Stops after ``max_alias_scan`` (L-17) messages and sets ``truncated`` if more remain.
    """
    counts: Counter[str] = Counter()
    scanned = 0
    truncated = False
    for headers in messages:
        if scanned >= limits.max_alias_scan:
            truncated = True
            break
        scanned += 1
        alias = resolve_alias(headers, rules, limits)
        if alias is not None:
            counts[alias.address] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return Aggregation([AliasCount(a, n) for a, n in ranked], scanned, truncated)
