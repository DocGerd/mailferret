from __future__ import annotations

import ast
import logging
import time
import tracemalloc
from email import message_from_bytes
from pathlib import Path
from typing import NamedTuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mailferret.content import headers
from mailferret.content.headers import (
    decode_header_value,
    decode_parameters,
    format_address,
    format_addresses,
    parse_header_parameters,
)
from mailferret.content.truncate import truncate_chars
from mailferret.limits import Limits
from tests.fixtures import corpus, generators
from tests.strategies import encoded_words, header_values, rfc2231_parameters

FIXTURES = {f.name: f for f in corpus.committed()}
CONTROLS = {chr(c) for c in [*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029]}
FUZZ = settings(max_examples=200, deadline=None)
MIB = 1024 * 1024


def _raw_headers(name: str) -> list[tuple[str, str]]:
    return list(message_from_bytes(FIXTURES[name].raw).raw_items())


def _header(name: str, field: str) -> str:
    return next(v for k, v in _raw_headers(name) if k == field)


def _has_no_controls(text: str) -> bool:
    return not CONTROLS & set(text)


class Address(NamedTuple):
    name: bytes | None
    route: bytes | None
    mailbox: bytes | None
    host: bytes | None


def test_rfc2047_subject_and_folded_header_from_corpus() -> None:
    assert decode_header_value(_header("headers_2047", "Subject")).text == (
        "Grüße aus München \u2013 日本語"
    )
    assert decode_header_value(_header("headers_2047", "X-Folded")).text == "first second third"


def test_broken_encoded_words_stay_literal() -> None:
    value = _header("headers_2047_broken", "X-Broken")
    assert decode_header_value(value).text == "=?UTF-8?Q?unterminated"
    assert decode_header_value("=?utf-8?B?!!!?=").text == "=?utf-8?B?!!!?="
    assert decode_header_value("=?utf-8?B?A?=").text == "=?utf-8?B?A?="
    assert decode_header_value("=?utf-8?Q?ü?=").text == "=?utf-8?Q?ü?="


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("=?UTF-8?B?4pyT?=", "✓"),
        ("=?UTF-8?B?4g==?= =?UTF-8?B?nJM=?=", "✓"),
        ("=?utf-8?q?a?= =?utf-8?q?b?=", "ab"),
        ("=?utf-8?q?a?=  \t =?utf-8?q?b?=", "ab"),
        ("=?utf-8?q?a?= and =?utf-8?q?b?=", "a and b"),
        ("x=?utf-8?q?a?=y", "xay"),
        ("=?utf-8*en?q?a_b?=", "a b"),
        ("=?x-no-such-charset?q?caf=E9?=", "café"),
        ("=?utf-8?q?bad=ZZ?=", "bad=ZZ"),
        ("=?utf-7?q?+ADw-?=", "+ADw-"),
        ("=?zlib?b?eJw=?=", "xœ"),
    ],
)
def test_encoded_word_cases(raw: str, expected: str) -> None:
    assert decode_header_value(raw).text == expected


def test_bytes_header_with_raw_8bit_and_invalid_utf8() -> None:
    assert decode_header_value("Grüße".encode()).text == "Grüße"
    assert decode_header_value(b"caf\xe9").text == "café"
    assert decode_header_value(b"\xff\xfe\xc3(").text.encode("utf-8")


def test_decoded_crlf_cannot_inject_a_header_line() -> None:
    for field in ("Subject", "X-B64", "X-Delim-Q", "X-Delim-B", "X-Raw"):
        text = decode_header_value(_header("header_injection", field)).text
        assert _has_no_controls(text), field
    subject = decode_header_value(_header("header_injection", "Subject")).text
    assert "\n" not in subject
    assert subject.startswith("hello")
    assert decode_header_value("a\x00b\x1bc\x85d\u2028e").text == "a b c d e"


def test_every_corpus_header_decodes_to_clean_bounded_text() -> None:
    for fixture in corpus.committed() + corpus.charset_cases():
        for _, value in message_from_bytes(fixture.raw).raw_items():
            result = decode_header_value(value)
            assert _has_no_controls(result.text)
            assert len(result.text) <= Limits().max_header_value_chars


def test_l04_value_over_limit_is_cut_and_flagged() -> None:
    limits = Limits(max_header_value_chars=10)
    result = decode_header_value("é" * 11, limits)
    assert result.truncated
    assert result.text == "é" * 10
    assert not decode_header_value("é" * 10, limits).truncated


def test_l04_default_is_the_ceiling() -> None:
    size = Limits().max_header_value_chars
    assert not decode_header_value("a" * size).truncated
    over = decode_header_value("a" * (size + 1))
    assert over.truncated
    assert len(over.text) == size


def test_l04_applies_after_decoding_not_before() -> None:
    limits = Limits(max_header_value_chars=8)
    words = " ".join(["=?utf-8?B?QUFB?="] * 20)
    result = decode_header_value(words, limits)
    assert result.truncated
    assert len(result.text) <= 8


def test_l05_ten_mib_header_is_bounded_in_memory_and_flagged() -> None:
    raw = generators.huge_header_mail(10 * MIB)
    value = raw.split(b"X-Huge: ", 1)[1].split(b"\r\n", 1)[0]
    limits = Limits()
    tracemalloc.start()
    try:
        result = decode_header_value(value, limits)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.truncated
    assert len(result.text) <= limits.max_header_value_chars
    assert peak < 4 * limits.max_header_bytes


def test_l05_applies_to_str_input_too() -> None:
    limits = Limits(max_header_bytes=64)
    result = decode_header_value("a" * 1000, limits)
    assert result.truncated
    assert len(result.text) <= 64


def test_l05_cut_mid_codepoint_leaves_no_replacement_char() -> None:
    limits = Limits(max_header_bytes=64)
    result = decode_header_value("日".encode() * 100, limits)
    assert result.truncated
    assert "�" not in result.text


def test_encoded_word_bomb_is_linear_and_bounded() -> None:
    raw = generators.encoded_word_bomb_mail(250_000)
    value = raw.split(b"Subject: ", 1)[1].split(b"\r\n", 1)[0]
    assert len(value) > Limits().max_header_bytes
    tracemalloc.start()
    started = time.monotonic()
    try:
        result = decode_header_value(value)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.truncated
    assert len(result.text) <= Limits().max_header_value_chars
    assert peak < 8 * MIB
    assert time.monotonic() - started < 10


def test_pathological_word_lookalikes_are_linear() -> None:
    started = time.monotonic()
    for text in ("=?" * 100_000, "=?a?b?" * 40_000, "=?" + "a" * 200_000, "=?a?q?" + "=" * 200_000):
        decode_header_value(text)
    assert time.monotonic() - started < 10


@FUZZ
@given(header_values(), st.integers(1, 64))
def test_arbitrary_header_values_stay_valid_clean_and_bounded(value: str, cap: int) -> None:
    result = decode_header_value(value, Limits(max_header_value_chars=cap))
    result.text.encode("utf-8")
    assert len(result.text) <= cap
    assert _has_no_controls(result.text)


@FUZZ
@given(encoded_words())
def test_arbitrary_encoded_words_never_raise(word: str) -> None:
    result = decode_header_value(word)
    result.text.encode("utf-8")


@FUZZ
@given(st.binary(max_size=300))
def test_arbitrary_header_bytes_never_raise(raw: bytes) -> None:
    result = decode_header_value(raw)
    result.text.encode("utf-8")
    assert _has_no_controls(result.text)


def test_rfc2231_filename_from_corpus() -> None:
    value = next(
        part.get("Content-Disposition")
        for part in message_from_bytes(FIXTURES["rfc2231_filename"].raw).walk()
        if part.get("Content-Disposition")
    )
    parsed = parse_header_parameters(value)
    assert parsed.value == "attachment"
    assert parsed.parameters.values == {"filename": "naïve report.txt"}


@pytest.mark.parametrize(
    ("pairs", "expected"),
    [
        ([("filename*", "UTF-8''a%20b")], "a b"),
        ([("filename*", "utf-8'en'caf%C3%A9")], "café"),
        ([("filename*", "iso-8859-1''caf%E9")], "café"),
        ([("filename*0*", "utf-8''%E2%9C"), ("filename*1*", "%93")], "✓"),
        ([("filename*1", "b"), ("filename*0", "a")], "ab"),
        ([("filename*0", "a"), ("filename*2", "c")], "ac"),
        ([("filename*1*", "%E9")], "é"),
        ([("filename", "plain"), ("filename*", "utf-8''ext")], "ext"),
        ([("filename*", "utf-8''ext"), ("filename", "plain")], "ext"),
        ([("filename", "first"), ("filename", "second")], "first"),
        ([("FILENAME*0", "a"), ("Filename*1", "b")], "ab"),
        ([("filename", "=?UTF-8?B?w7w=?=.txt")], "ü.txt"),
        ([("filename*", "no-quotes-at-all")], "no-quotes-at-all"),
        ([("filename*", "x-no-such''caf%E9")], "café"),
        ([(b"filename*", b"UTF-8''caf%C3%A9")], "café"),
        ([("filename*", "utf-8''a%0D%0ABcc:%20x")], "a  Bcc: x"),
        ([("filename*", "utf-8''%")], "%"),
    ],
)
def test_parameter_continuations_and_extended_values(
    pairs: list[tuple[str | bytes, str | bytes]], expected: str
) -> None:
    assert decode_parameters(pairs).values == {"filename": expected}


def test_huge_and_sparse_indexes_do_not_allocate_or_raise() -> None:
    pairs = [
        ("filename*999999", "z"),
        ("filename*0", "a"),
        ("filename*" + "9" * 5000, "ignored"),
        ("filename*" + "9" * 5000 + "*", "ignored"),
        ("a*b", "ignored"),
        ("", "ignored"),
    ]
    assert decode_parameters(pairs).values == {"filename": "az"}


def test_parameter_values_are_bounded_and_flagged() -> None:
    limits = Limits(max_header_value_chars=8, max_header_bytes=64)
    result = decode_parameters([("filename", "a" * 100)], limits)
    assert result.truncated
    assert len(result.values["filename"]) <= 8
    many = [(f"filename*{i}", "b" * 10) for i in range(100)]
    capped = decode_parameters(many, limits)
    assert capped.truncated
    assert len(capped.values["filename"]) <= 8


def test_l05_bounds_a_parameter_bomb() -> None:
    value = "attachment; " + "; ".join(f"p{i}=v" for i in range(200_000))
    limits = Limits()
    started = time.monotonic()
    parsed = parse_header_parameters(value, limits)
    assert parsed.truncated
    assert len(parsed.parameters.values) < limits.max_header_bytes
    assert time.monotonic() - started < 10


def test_header_parameter_parsing() -> None:
    parsed = parse_header_parameters(
        'Text/Plain; charset="utf-8"; name="a;b=c\\"d"; format=flowed;\r\n delsp=yes; =bad; nope'
    )
    assert parsed.value == "text/plain"
    assert parsed.parameters.values == {
        "charset": "utf-8",
        "name": 'a;b=c"d',
        "format": "flowed",
        "delsp": "yes",
    }
    assert not parsed.truncated


@FUZZ
@given(rfc2231_parameters())
def test_arbitrary_rfc2231_parameters_never_raise_and_stay_bounded(params: str) -> None:
    limits = Limits(max_header_value_chars=32)
    parsed = parse_header_parameters("attachment; " + params, limits)
    for value in parsed.parameters.values.values():
        value.encode("utf-8")
        assert len(value) <= 32
        assert _has_no_controls(value)


@FUZZ
@given(st.text(max_size=200))
def test_arbitrary_header_text_parses(text: str) -> None:
    parsed = parse_header_parameters(text)
    parsed.value.encode("utf-8")
    for value in parsed.parameters.values.values():
        value.encode("utf-8")


def _address(
    mailbox: bytes | None = b"user",
    host: bytes | None = b"example.com",
    name: bytes | None = None,
    route: bytes | None = None,
) -> Address:
    return Address(name, route, mailbox, host)


def test_address_formats() -> None:
    plain = format_address(_address())
    assert plain is not None
    assert (plain.name, plain.address, plain.display) == (
        "",
        "user@example.com",
        "user@example.com",
    )
    named = format_address(_address(name=b"Alice"))
    assert named is not None
    assert named.display == "Alice <user@example.com>"
    encoded = format_address(_address(name=b"=?UTF-8?Q?Gr=C3=BC=C3=9Fe?="))
    assert encoded is not None
    assert encoded.name == "Grüße"


def test_display_name_cannot_spoof_the_address() -> None:
    spoof = format_address(_address(name=b'Bob <ceo@example.com> "x"', mailbox=b"evil"))
    assert spoof is not None
    assert spoof.address == "evil@example.com"
    assert spoof.display == '"Bob <ceo@example.com> \\"x\\"" <evil@example.com>'
    comma = format_address(_address(name=b"Doe, John"))
    assert comma is not None
    assert comma.display == '"Doe, John" <user@example.com>'


def test_address_parts_cannot_break_out_of_the_angle_brackets() -> None:
    result = format_address(_address(mailbox=b"a> <ceo", host=b"example.com>\r\nBcc: x"))
    assert result is not None
    assert not {"<", ">", '"', "\r", "\n", " "} & set(result.address)


def test_group_markers_and_empty_entries_are_skipped_and_never_print_none() -> None:
    entries = [
        Address(None, None, b"Team", None),
        Address(None, b"route", b"user", b"example.com"),
        Address(None, None, None, None),
        Address(b"x", None, None, b"example.com"),
        Address(None, None, b"", b"example.com"),
        Address(None, None, b"user", b""),
    ]
    formatted = format_addresses(entries)
    assert [a.address for a in formatted] == ["user@example.com"]
    assert "None" not in repr(formatted)
    assert format_addresses(None) == []


def test_address_bytes_that_are_not_utf8_decode_without_raising() -> None:
    result = format_address(_address(mailbox=b"\xff\xfeuser", name=b"caf\xe9"))
    assert result is not None
    assert result.name == "café"
    result.address.encode("utf-8")


def test_address_length_is_bounded_and_flagged() -> None:
    limits = Limits(max_header_value_chars=8)
    result = format_address(_address(mailbox=b"a" * 100, name=b"n" * 100), limits)
    assert result is not None
    assert result.truncated
    assert len(result.name) <= 8
    assert len(result.address) <= 8 + 1 + len("example.com")


class _Hostile:
    """Raises if anything formats it or touches a field it should not."""

    def __init__(self, **fields: bytes | None) -> None:
        self._fields = fields

    @property
    def name(self) -> bytes | None:
        return self._fields.get("name")

    @property
    def route(self) -> bytes | None:
        raise AssertionError("route is never read")

    @property
    def mailbox(self) -> bytes | None:
        return self._fields.get("mailbox")

    @property
    def host(self) -> bytes | None:
        return self._fields.get("host")

    def __str__(self) -> str:
        raise AssertionError("address was stringified")

    __repr__ = __str__

    def __format__(self, format_spec: str) -> str:
        raise AssertionError("address was formatted")


def test_address_is_formatted_field_by_field_never_stringified() -> None:
    hostile = _Hostile(name=b"Alice", mailbox=b"user", host=b"example.com")
    result = format_address(hostile)
    assert result is not None
    assert result.display == "Alice <user@example.com>"
    assert format_addresses([hostile, _Hostile(mailbox=b"g")])[0].address == "user@example.com"


def test_content_helpers_log_nothing_and_never_import_logging(
    caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    for fixture in corpus.committed() + corpus.charset_cases():
        for _, value in message_from_bytes(fixture.raw).raw_items():
            decode_header_value(value)
            parse_header_parameters(value)
    format_addresses([_address(name=b"=?UTF-8?Q?Gr=C3=BC=C3=9Fe?=")])
    assert caplog.records == []
    out, err = capfd.readouterr()
    assert out == err == ""
    package = Path(headers.__file__).parent
    for module in ("charset.py", "headers.py", "truncate.py"):
        tree = ast.parse((package / module).read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert "logging" not in imported, module
        assert "mailferret.logging" not in imported, module


def test_errors_carry_no_input() -> None:
    marker = "MAILFERRET-CANARY-SUBJECT"
    for call in (
        lambda: decode_header_value(marker, Limits(max_header_value_chars=1)),
        lambda: decode_parameters([("filename", marker)]),
    ):
        call()
    with pytest.raises(ValueError) as info:
        truncate_chars(marker, -1)
    assert marker not in str(info.value)


def test_l05_bounds_the_work_for_many_large_continuations() -> None:
    limits = Limits()
    value = "b" * limits.max_header_bytes
    pairs = ((f"filename*{i}", value) for i in range(200))
    tracemalloc.start()
    try:
        result = decode_parameters(pairs, limits)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.truncated
    assert peak < 16 * limits.max_header_bytes
