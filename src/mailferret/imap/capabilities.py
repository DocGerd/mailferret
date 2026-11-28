"""Capabilities parsed once per connection into flags (A§2.2, R§11)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Capabilities:
    raw: frozenset[str]
    starttls: bool
    sort: bool
    thread_references: bool
    uidplus: bool
    condstore: bool
    special_use: bool
    logindisabled: bool
    auth_plain: bool
    idle: bool


def parse_capabilities(tokens: Iterable[bytes | str]) -> Capabilities:
    raw = frozenset(
        (t.decode("ascii", "replace") if isinstance(t, bytes) else t).upper() for t in tokens
    )
    return Capabilities(
        raw=raw,
        starttls="STARTTLS" in raw,
        sort="SORT" in raw,
        thread_references="THREAD=REFERENCES" in raw,
        uidplus="UIDPLUS" in raw,
        condstore="CONDSTORE" in raw,
        special_use="SPECIAL-USE" in raw,
        logindisabled="LOGINDISABLED" in raw,
        auth_plain="AUTH=PLAIN" in raw,
        idle="IDLE" in raw,
    )
