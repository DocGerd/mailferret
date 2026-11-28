"""Resolve the recipient alias from header values in the account's priority (R§5, A§2.6).

Header values are untrusted. Addresses go through ``content.headers.format_address`` field
by field; an address it had to rewrite or strip is skipped, never repaired into a match.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.utils import getaddresses
from typing import Final

from mailferret.aliases.rules import AliasRules
from mailferret.content.headers import format_address
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
_MAX_VALUES_PER_HEADER: Final = 16
_MAX_ADDRESSES_PER_HEADER: Final = 64


@dataclass(frozen=True, slots=True)
class Alias:
    address: str
    local: str
    domain: str
    base: str
    tag: str | None
    header: str


@dataclass(frozen=True, slots=True)
class _Parts:
    name: None
    route: None
    mailbox: str
    host: str


def _text(value: str | bytes, limits: Limits) -> str:
    if isinstance(value, bytes):
        value = value[: limits.max_header_bytes].decode("utf-8", errors="replace")
    return value[: limits.max_header_value_chars]


def _addresses(values: Sequence[str | bytes], limits: Limits) -> list[str]:
    texts = [_text(v, limits) for v in values[:_MAX_VALUES_PER_HEADER]]
    out: list[str] = []
    for _, raw in getaddresses(texts)[:_MAX_ADDRESSES_PER_HEADER]:
        local, sep, host = raw.rpartition("@")
        if not sep:
            continue
        formatted = format_address(_Parts(None, None, local, host), limits)
        if formatted is None or formatted.stripped or "?" in formatted.address:
            continue
        out.append(formatted.address.lower())
    return out


def _qualify(address: str, header: str, rules: AliasRules) -> Alias | None:
    local, _, domain = address.rpartition("@")
    if not local or not domain:
        return None
    base, tag = local, None
    separator = rules.plus_separator
    if separator is not None:
        head, sep, rest = local.partition(separator)
        if sep and head:
            base, tag = head, rest
    if rules.domains:
        if domain not in rules.domains:
            return None
    elif tag is None:
        return None
    return Alias(address, local, domain, base, tag, header)


def resolve_alias(
    headers: Mapping[str, Sequence[str | bytes]],
    rules: AliasRules,
    limits: Limits = _DEFAULT_LIMITS,
) -> Alias | None:
    """First qualifying address of the first header, in ``rules.header_priority``, that has one.

    ``headers`` maps field names (any case) to their raw values. With alias domains set, an
    address qualifies by domain; with only a plus separator, by carrying a tag.
    """
    if not rules.enabled:
        return None
    by_name: dict[str, list[str | bytes]] = {}
    for name, values in headers.items():
        by_name.setdefault(name.lower(), []).extend(values)
    for header in rules.header_priority:
        for address in _addresses(by_name.get(header.lower(), ()), limits):
            alias = _qualify(address, header, rules)
            if alias is not None:
                return alias
    return None
