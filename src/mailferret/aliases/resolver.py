"""Resolve the recipient alias from header values in the account's priority (R§5, A§2.6).

Header values are untrusted. Addresses go through ``content.headers.format_address`` field
by field; an address it had to rewrite, strip or cut is skipped, never repaired into a match.
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


@dataclass(frozen=True, slots=True)
class Alias:
    address: str
    local: str
    domain: str
    base: str
    tag: str | None
    header: str


@dataclass(frozen=True, slots=True)
class Resolution:
    """The alias, if any, and whether an input bound hid part of the headers read."""

    alias: Alias | None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Parts:
    name: None
    route: None
    mailbox: str
    host: str


def _text(value: str | bytes, limits: Limits) -> tuple[str, bool]:
    cut = len(value) > limits.max_header_bytes
    if isinstance(value, bytes):
        text = value[: limits.max_header_bytes].decode("utf-8", errors="replace")
    else:
        text = value[: limits.max_header_bytes]
    if len(text) > limits.max_header_value_chars:
        return text[: limits.max_header_value_chars], True
    return text, cut


def _parse_value(text: str, cut: bool) -> list[str]:
    """Raw addresses of one value; a malformed fragment costs only itself.

    Strict ``getaddresses`` returns empty entries for a bad fragment, sometimes for the whole
    value, so the value is then re-parsed piece by piece. The last address of a cut value may
    be incomplete and is dropped.
    """
    pairs = getaddresses([text])
    if any(not addr for _, addr in pairs):
        pairs = [pair for piece in text.split(",") for pair in getaddresses([piece])]
    found = [addr for _, addr in pairs if addr]
    return found[:-1] if cut else found


def _clean(raw: str, limits: Limits) -> str | None:
    local, sep, host = raw.rpartition("@")
    if not sep:
        return None
    formatted = format_address(_Parts(None, None, local, host), limits)
    if formatted is None or formatted.stripped or formatted.truncated or "?" in formatted.address:
        return None
    return formatted.address.lower()


def _header_addresses(values: Sequence[str | bytes], limits: Limits) -> tuple[list[str], bool]:
    truncated = len(values) > limits.max_header_values
    out: list[str] = []
    seen = 0
    for value in values[: limits.max_header_values]:
        text, cut = _text(value, limits)
        truncated = truncated or cut
        for raw in _parse_value(text, cut):
            if seen >= limits.max_header_addresses:
                return out, True
            seen += 1
            address = _clean(raw, limits)
            if address is not None:
                out.append(address)
    return out, truncated


def _qualify(address: str, header: str, rules: AliasRules) -> Alias | None:
    local, _, domain = address.rpartition("@")
    if not local or not domain:
        return None
    base, tag = local, None
    separator = rules.plus_separator
    if separator is not None:
        head, sep, rest = local.partition(separator)
        if sep and head and rest:
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
) -> Resolution:
    """First qualifying address of the first header, in ``rules.header_priority``, that has one.

    ``headers`` maps field names (any case) to their raw values. With alias domains set, an
    address qualifies by domain whatever the separator; with only a plus separator, by
    carrying a non-empty tag. ``truncated`` is set when L-04, L-05, L-30 or L-31 hid input
    from a header read before the result.
    """
    if not rules.enabled:
        return Resolution(None)
    by_name: dict[str, list[str | bytes]] = {}
    for name, values in headers.items():
        by_name.setdefault(name.lower(), []).extend(values)
    truncated = False
    for header in rules.header_priority:
        addresses, cut = _header_addresses(by_name.get(header.lower(), ()), limits)
        truncated = truncated or cut
        for address in addresses:
            alias = _qualify(address, header, rules)
            if alias is not None:
                return Resolution(alias, truncated)
    return Resolution(None, truncated)
