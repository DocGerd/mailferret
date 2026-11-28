from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mailferret.aliases import (
    AliasRules,
    aggregate_aliases,
    compile_pattern,
    glob_match,
    matches,
    prefilter_fragment,
    resolve_alias,
    validate_header_names,
)
from mailferret.config.schema import Aliases
from mailferret.limits import Limits
from tests.strategies import addresses, alias_headers, header_values

FUZZ = settings(max_examples=200, deadline=None)
RULES = AliasRules.create(["example.com"], "+")


def test_priority_order_decides() -> None:
    headers = {"To": ["x@example.com"], "Delivered-To": ["shop@example.com"]}
    alias = resolve_alias(headers, RULES)
    assert alias is not None
    assert (alias.address, alias.header) == ("shop@example.com", "Delivered-To")


def test_priority_is_configurable_and_header_names_ignore_case() -> None:
    rules = AliasRules.create(["example.com"], None, ["Cc", "To"])
    alias = resolve_alias({"to": ["a@example.com"], "CC": ["b@example.com"]}, rules)
    assert alias is not None and alias.address == "b@example.com"


def test_falls_through_headers_without_a_qualifying_address() -> None:
    headers = {"Delivered-To": ["other@example.org"], "To": ["Name <Shop@EXAMPLE.com>"]}
    alias = resolve_alias(headers, RULES)
    assert alias is not None and alias.address == "shop@example.com"


def test_plus_tag_is_split() -> None:
    alias = resolve_alias({"To": ["shop+news@example.com"]}, RULES)
    assert alias is not None
    assert (alias.base, alias.tag, alias.local) == ("shop", "news", "shop+news")


def test_plus_only_requires_a_tag_on_any_domain() -> None:
    rules = AliasRules.create([], "+")
    assert resolve_alias({"To": ["a@host.test"]}, rules) is None
    alias = resolve_alias({"To": ["a+x@host.test"]}, rules)
    assert alias is not None and alias.tag == "x"


def test_domains_only_ignores_plus() -> None:
    rules = AliasRules.create(["example.com"])
    alias = resolve_alias({"To": ["a+x@example.com"]}, rules)
    assert alias is not None and alias.tag is None and alias.local == "a+x"


def test_disabled_without_domains_or_separator() -> None:
    rules = AliasRules.create()
    assert not rules.enabled
    assert resolve_alias({"To": ["a@example.com"]}, rules) is None


def test_bytes_values_and_address_lists() -> None:
    headers = {"To": [b'"Doe, John" <x@example.net>, shop@example.com']}
    alias = resolve_alias(headers, RULES)
    assert alias is not None and alias.address == "shop@example.com"


@pytest.mark.parametrize(
    "value",
    ["sh​op@example.com", "shop@exa‮mple.com", '"a b"@example.com', "shop@example.com\x00"],
)
def test_disguised_addresses_never_match(value: str) -> None:
    assert resolve_alias({"To": [value]}, RULES) is None


LOOKALIKES = [chr(0xFF34) + chr(0xFF4F), "To" + chr(0x200B), "T" + chr(0x43E)]


@pytest.mark.parametrize("name", [*LOOKALIKES, "To:", "T o", "", "x\r\nBcc", "To\x00"])
def test_header_names_reject_lookalikes_and_syntax(name: str) -> None:
    with pytest.raises(ValueError, match="header"):
        validate_header_names([name])


def test_header_names_dedupe_and_require_one() -> None:
    assert validate_header_names(["To", "to", "Cc"]) == ("To", "Cc")
    with pytest.raises(ValueError, match="at least one"):
        validate_header_names([])


def test_rules_from_config_and_validation() -> None:
    rules = AliasRules.from_config(
        Aliases(domains=["Example.COM."], plus_separator="+", header_priority=["To"])
    )
    assert rules.domains == frozenset({"example.com"}) and rules.header_priority == ("To",)
    for bad in ({"domains": ["a@b"]}, {"domains": [""]}, {"plus_separator": "@"}):
        with pytest.raises(ValueError, match="must be"):
            AliasRules.create(**bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("pattern", "address", "expected"),
    [
        ("shop@example.com", "shop@example.com", True),
        ("Shop@Example.com", "shop@example.com", True),
        ("shop@example.com", "shop+x@example.com", False),
        ("shop-*@example.com", "shop-2024@example.com", True),
        ("shop-*@example.com", "shop-@example.com", True),
        ("shop-*@example.com", "shop@example.com", False),
        ("sh?p@example.com", "shop@example.com", True),
        ("sh?p@example.com", "shp@example.com", False),
        ("*@example.com", "a@b@example.com", True),
        ("*", "", True),
        ("a*b*c", "aXbYbZc", True),
        ("a*b*c", "aXbYbZ", False),
        ("[a-z]@example.com", "a@example.com", False),
    ],
)
def test_pattern_matching(pattern: str, address: str, expected: bool) -> None:
    assert matches(compile_pattern(pattern), address) is expected


def test_glob_is_linear_enough_for_hostile_patterns() -> None:
    start = time.perf_counter()
    assert not glob_match("*a" * 120 + "b", "a" * 5000)
    assert time.perf_counter() - start < 5


def test_pattern_bounds_and_controls() -> None:
    limits = Limits()
    compile_pattern("a" * limits.max_query_chars)
    for bad in ("", "a" * (limits.max_query_chars + 1), "a\r\nb", "a\x00"):
        with pytest.raises(ValueError, match="alias pattern"):
            compile_pattern(bad)


@pytest.mark.parametrize("pattern", ['a") OR HEADER x "', "a{5}\r\nb", "*) (DELETED", "a\\"])
def test_injection_text_is_inert_data(pattern: str) -> None:
    try:
        compiled = compile_pattern(pattern)
    except ValueError:
        return
    assert matches(compiled, "shop@example.com") is False


@pytest.mark.parametrize(
    ("pattern", "fragment"),
    [
        ("shop@example.com", "shop@example.com"),
        ("shop-*@example.com", "@example.com"),
        ("s*p*@e?.c?", None),
        ("*abc*", "abc"),
        ("*ab*", None),
    ],
)
def test_prefilter_fragment(pattern: str, fragment: str | None) -> None:
    assert prefilter_fragment(compile_pattern(pattern)) == fragment


def test_aggregate_counts_and_order() -> None:
    messages = [
        {"To": ["b@example.com"]},
        {"To": ["a@example.com"]},
        {"Delivered-To": ["b@example.com"], "To": ["a@example.com"]},
        {"To": ["nobody@example.org"]},
    ]
    result = aggregate_aliases(messages, RULES)
    assert [(c.address, c.count) for c in result.aliases] == [
        ("b@example.com", 2),
        ("a@example.com", 1),
    ]
    assert (result.scanned, result.truncated) == (4, False)


def test_aggregate_stops_at_scan_limit() -> None:
    limits = Limits(max_alias_scan=3)
    result = aggregate_aliases(({"To": ["a@example.com"]} for _ in range(10)), RULES, limits)
    assert (result.scanned, result.truncated, result.aliases[0].count) == (3, True, 3)
    exact = aggregate_aliases([{"To": ["a@example.com"]}] * 3, RULES, limits)
    assert not exact.truncated


@FUZZ
@given(alias_headers(), addresses())
def test_fuzz_resolved_alias_is_well_formed(headers: dict[str, list[str]], extra: str) -> None:
    alias = resolve_alias({**headers, "X-Extra": [extra]}, RULES)
    if alias is not None:
        assert alias.address == alias.address.lower()
        assert alias.address == f"{alias.local}@{alias.domain}"
        assert alias.domain == "example.com"


@FUZZ
@given(st.lists(header_values(), max_size=4), st.lists(st.binary(max_size=64), max_size=3))
def test_fuzz_arbitrary_values_never_raise(texts: list[str], blobs: list[bytes]) -> None:
    limits = Limits()
    alias = resolve_alias({"To": [*texts, *blobs], "Delivered-To": texts}, RULES, limits)
    if alias is not None:
        assert len(alias.address) <= 2 * limits.max_header_value_chars + 1
        assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in alias.address)


@FUZZ
@given(st.text(max_size=40), st.text(max_size=60))
def test_fuzz_glob_matches_like_fnmatch_subset(pattern: str, text: str) -> None:
    import re

    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    assert glob_match(pattern, text) is (re.fullmatch(regex, text, re.DOTALL) is not None)


@FUZZ
@given(st.text(max_size=300))
def test_fuzz_compile_pattern_total(raw: str) -> None:
    try:
        compiled = compile_pattern(raw)
    except ValueError:
        return
    assert len(compiled.text) <= Limits().max_query_chars + 8 * len(raw)
    matches(compiled, "shop@example.com")
