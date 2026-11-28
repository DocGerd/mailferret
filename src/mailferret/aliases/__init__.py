"""Alias resolution: pure functions over header values, no I/O (A§2.6, R§5)."""

from mailferret.aliases.aggregate import Aggregation, AliasCount, aggregate_aliases
from mailferret.aliases.match import (
    Pattern,
    compile_pattern,
    glob_match,
    matches,
    prefilter_fragment,
)
from mailferret.aliases.resolver import Alias, resolve_alias
from mailferret.aliases.rules import AliasRules, validate_header_names

__all__ = [
    "Aggregation",
    "Alias",
    "AliasCount",
    "AliasRules",
    "Pattern",
    "aggregate_aliases",
    "compile_pattern",
    "glob_match",
    "matches",
    "prefilter_fragment",
    "resolve_alias",
    "validate_header_names",
]
