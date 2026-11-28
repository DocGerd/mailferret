from __future__ import annotations

import zlib
from email import message_from_bytes

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mailferret.content.charset import decode_text, resolve_charset
from mailferret.limits import Limits
from tests.fixtures import corpus
from tests.strategies import accepted_codecs, arbitrary_bytes, charset_labels, mime_bytes

UMLAUTS = "Grüße aus München"
CJK = "日本語のテキスト"
FFFD = "�"
INTERNAL_ERROR_BYTES = b"\x1b.J\x1bN\x88"
CASES = {f.name: f for f in corpus.charset_cases()}

EXPECTED = {
    "utf8_umlauts": UMLAUTS,
    "utf8_cjk": CJK,
    "latin1": UMLAUTS,
    "latin9": "Preis 5 €",
    "utf8_labelled_latin1": UMLAUTS,
    "latin9_labelled_latin1": "Preis 5 ¤",
    "cp1252_labelled_latin1": "“quoted” — dash",
    "shift_jis": CJK,
    "unknown_label": "plain ascii",
    "no_charset": UMLAUTS,
    "no_content_type": "bare body",
}


def _label_and_body(name: str) -> tuple[str | None, bytes]:
    raw = CASES[name].raw
    return message_from_bytes(raw).get_content_charset(), raw.split(b"\r\n\r\n", 1)[1]


@pytest.mark.parametrize("name", list(EXPECTED))
def test_corpus_decodes_to_the_intended_text(name: str) -> None:
    label, body = _label_and_body(name)
    result = decode_text(body, label)
    assert result.text == EXPECTED[name]
    assert FFFD not in result.text


def test_utf8_labelled_latin1_is_flagged_as_fallback() -> None:
    label, body = _label_and_body("utf8_labelled_latin1")
    result = decode_text(body, label)
    assert result.fallback
    assert result.charset == "utf-8"


def test_latin1_label_is_read_as_cp1252() -> None:
    label, body = _label_and_body("cp1252_labelled_latin1")
    assert decode_text(body, label).charset == "cp1252"


@pytest.mark.parametrize("name", ["utf8_umlauts", "latin1", "shift_jis"])
def test_correct_labels_are_not_fallbacks(name: str) -> None:
    label, body = _label_and_body(name)
    assert not decode_text(body, label).fallback


def test_latin1_text_labelled_utf8_falls_back_to_replace() -> None:
    label, body = _label_and_body("latin1_labelled_utf8")
    result = decode_text(body, label)
    assert result.fallback
    assert FFFD in result.text
    assert result.text.startswith("Gr")


@pytest.mark.parametrize("name", ["invalid_utf8", "overlong_utf8", "surrogate_utf8"])
def test_invalid_utf8_is_replaced_not_raised(name: str) -> None:
    label, body = _label_and_body(name)
    result = decode_text(body, label)
    assert FFFD in result.text
    assert result.fallback
    result.text.encode("utf-8")


def test_surrogate_and_overlong_never_decode_to_their_codepoints() -> None:
    result = decode_text(b"\xed\xa0\x80 \xc0\xaf", "utf-8")
    assert not any(0xD800 <= ord(c) <= 0xDFFF or c == "/" for c in result.text)


def test_truncated_tail_is_replaced_when_the_part_is_complete() -> None:
    label, body = _label_and_body("truncated_tail_utf8")
    assert decode_text(body, label).text.endswith(FFFD)


def test_truncated_tail_is_dropped_when_the_fetch_was_partial() -> None:
    label, body = _label_and_body("truncated_tail_utf8")
    result = decode_text(body, label, partial=True)
    assert result.text == CJK[:-1]
    assert not result.fallback


@pytest.mark.parametrize("charset", ["utf-8", "shift_jis", "utf-16-le", "euc-jp", "gb18030"])
def test_every_cut_of_a_partial_fetch_has_no_replacement_char(charset: str) -> None:
    text = CJK + "é😀"
    data = text.encode(charset, errors="ignore")
    for cut in range(len(data) + 1):
        decoded = decode_text(data[:cut], charset, partial=True).text
        assert FFFD not in decoded
        assert data.decode(charset).startswith(decoded)


@pytest.mark.parametrize(
    "label",
    [
        "zlib",
        "hex",
        "base64",
        "bz2",
        "rot13",
        "uu",
        "utf-7",
        "UTF7",
        "idna",
        "punycode",
        "undefined",
        "unicode_escape",
        "raw-unicode-escape",
        "mbcs",
        "",
        " ",
        '"utf-8',
        "utf-8\x00",
        "ü",
        "a" * 200,
        "x-no-such-charset",
    ],
)
def test_pseudo_codecs_and_garbage_labels_never_decode_anything_special(label: str) -> None:
    payload = zlib.compress(b"hidden") + b"+ADw-script+AD4- abc"
    result = decode_text(payload, label)
    assert result.charset in {"utf-8", "cp1252", "iso8859-1"}
    assert "hidden" not in result.text
    assert "<script>" not in result.text
    assert resolve_charset(label) in (None, "utf-8", "ascii", "iso8859-1", "cp1252")


def test_utf7_payload_stays_literal() -> None:
    assert decode_text(b"+ADw-script+AD4-", "utf-7").text == "+ADw-script+AD4-"


def test_decompression_bomb_label_cannot_inflate() -> None:
    bomb = zlib.compress(b"a" * (8 * 1024 * 1024))
    assert len(decode_text(bomb, "zlib").text) <= len(bomb)


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("UTF8", "utf-8"),
        ("latin1", "iso8859-1"),
        ("ISO_8859-15", "iso8859-15"),
        (b"Shift_JIS", "shift_jis"),
        ('"utf-8"', "utf-8"),
        (None, None),
    ],
)
def test_label_resolution(label: str | bytes | None, expected: str | None) -> None:
    assert resolve_charset(label) == expected


def test_input_over_l02_is_cut_and_reported() -> None:
    limits = Limits(max_part_bytes=16)
    data = "é".encode() * 20
    result = decode_text(data, "utf-8", limits=limits)
    assert result.truncated
    assert result.text == "é" * 8
    assert not decode_text(data[:16], "utf-8", limits=limits).truncated


def test_input_over_l02_cut_mid_sequence_drops_the_tail() -> None:
    limits = Limits(max_part_bytes=15)
    result = decode_text("é".encode() * 20, "utf-8", limits=limits)
    assert result.truncated
    assert result.text == "é" * 7


def test_default_limit_is_l02() -> None:
    size = Limits().max_part_bytes
    assert not decode_text(b"a" * size).truncated
    over = decode_text(b"a" * (size + 1))
    assert over.truncated
    assert len(over.text) == size


FUZZ = settings(max_examples=200, deadline=None)


@FUZZ
@given(st.one_of(arbitrary_bytes, mime_bytes), charset_labels, st.booleans())
def test_arbitrary_bytes_and_labels_give_valid_bounded_text(
    data: bytes, label: str, partial: bool
) -> None:
    limits = Limits(max_part_bytes=1024)
    result = decode_text(data, label, partial=partial, limits=limits)
    assert isinstance(result.text, str)
    result.text.encode("utf-8")
    assert len(result.text) <= limits.max_part_bytes
    assert result.truncated == (len(data) > limits.max_part_bytes)


ACCEPTED = accepted_codecs()
CODEC_SAMPLES = [
    b"",
    b"\x1b.J\x1bN\x88",
    b"\xff" * 7,
    b"\x1b$B0!\x1b(B",
    b"\x1b$)C\x0e!!",
    "日本語é😀".encode(),
    b"\x00\xd8\x00\xdc\x00\xd8",
    bytes(range(256)),
]


def test_sweep_covers_the_codec_with_the_known_internal_error() -> None:
    assert "iso2022_jp_2" in {c.replace("-", "_") for c in ACCEPTED}
    assert len(ACCEPTED) > 50


@pytest.mark.parametrize("codec", ACCEPTED)
def test_every_accepted_codec_decodes_to_valid_bounded_text(codec: str) -> None:
    limits = Limits(max_part_bytes=256)
    for data in CODEC_SAMPLES:
        for partial in (False, True):
            result = decode_text(data, codec, partial=partial, limits=limits)
            result.text.encode("utf-8")
            assert len(result.text) <= limits.max_part_bytes


def test_codec_internal_error_falls_back_instead_of_raising() -> None:
    result = decode_text(INTERNAL_ERROR_BYTES, "iso-2022-jp-2")
    assert result.fallback
    result.text.encode("utf-8")


@FUZZ
@given(st.binary(max_size=64), st.sampled_from(ACCEPTED), st.booleans())
def test_arbitrary_bytes_with_every_accepted_codec(data: bytes, codec: str, partial: bool) -> None:
    result = decode_text(data, codec, partial=partial)
    result.text.encode("utf-8")
    assert len(result.text) <= len(data)
