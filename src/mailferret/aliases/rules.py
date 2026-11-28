"""Per-account alias rules, validated once (A§2.6, R§5)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Protocol, Self

DEFAULT_HEADER_PRIORITY: Final = ("Delivered-To", "X-Original-To", "To", "Cc")
# RFC 5322 ftext minus the IMAP atom-specials ( ) { % * " \ ]: names are spliced into FETCH.
_FIELD_NAME: Final = re.compile(r"[!#$&'+-9;-\[^-z|-~]{1,64}")
_SEPARATOR: Final = re.compile(r"[!-?A-~]{1,8}")


def _plain_domain(domain: str) -> bool:
    return bool(domain) and not any(
        c == "@" or c.isspace() or unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"}
        for c in domain
    )


class AliasConfig(Protocol):
    """The fields of ``config.schema.Aliases`` the rules read."""

    @property
    def domains(self) -> Iterable[str]: ...

    @property
    def plus_separator(self) -> str | None: ...

    @property
    def header_priority(self) -> Iterable[str]: ...


def validate_header_names(names: Iterable[str]) -> tuple[str, ...]:
    """Accept RFC 5322 field names only: printable ASCII without a colon.

    Non-ASCII names are rejected rather than folded, so a compatibility look-alike
    (NFKC) of ``To`` cannot name a different header. Duplicates, ignoring case, are dropped.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if _FIELD_NAME.fullmatch(name) is None:
            raise ValueError("header_priority entries must be plain ASCII header field names")
        if name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    if not out:
        raise ValueError("header_priority must name at least one header")
    return tuple(out)


@dataclass(frozen=True, slots=True)
class AliasRules:
    domains: frozenset[str]
    plus_separator: str | None
    header_priority: tuple[str, ...]

    @classmethod
    def create(
        cls,
        domains: Iterable[str] = (),
        plus_separator: str | None = None,
        header_priority: Iterable[str] = DEFAULT_HEADER_PRIORITY,
    ) -> Self:
        cleaned: set[str] = set()
        for domain in domains:
            lowered = domain.strip().lower().rstrip(".")
            if not _plain_domain(lowered):
                raise ValueError("alias domains must be plain domain names")
            cleaned.add(lowered)
        if plus_separator is not None and _SEPARATOR.fullmatch(plus_separator) is None:
            raise ValueError("plus_separator must be 1-8 printable ASCII characters without '@'")
        return cls(frozenset(cleaned), plus_separator, validate_header_names(header_priority))

    @classmethod
    def from_config(cls, aliases: AliasConfig) -> Self:
        return cls.create(aliases.domains, aliases.plus_separator, aliases.header_priority)

    @property
    def enabled(self) -> bool:
        """Off when the account has neither alias domains nor a plus separator (A§2.6)."""
        return bool(self.domains) or self.plus_separator is not None
