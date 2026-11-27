import base64
import binascii
import re
import zlib
from email import message_from_bytes, policy
from email.message import EmailMessage, Message

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.fixtures import corpus, generators
from tests.strategies import (
    addresses,
    alias_headers,
    charset_labels,
    encoded_words,
    header_values,
    mime_bytes,
    rfc2231_parameters,
)

FUZZ = settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _defects(msg: Message) -> list[object]:
    return [d for part in msg.walk() for d in part.defects]


def _depth(msg: Message) -> int:
    kids = msg.get_payload() if msg.is_multipart() else []
    return 1 + max((_depth(k) for k in kids), default=0)  # type: ignore[arg-type]


def _is_example(domain: str) -> bool:
    d = domain.lower()
    return d == "example.com" or d.endswith(".example.com")


def _named() -> dict[str, corpus.Fixture]:
    return {f.name: f for f in _all_fixtures()}


def _all_fixtures() -> list[corpus.Fixture]:
    return corpus.committed() + corpus.charset_cases()


def test_committed_corpus_is_present_and_small() -> None:
    fixtures = corpus.committed()
    assert len(fixtures) >= 13
    assert all(len(f.raw) < 4096 for f in fixtures)


@pytest.mark.parametrize("fx", _all_fixtures(), ids=lambda f: f.name)
def test_every_fixture_parses_and_stays_example_com(fx: corpus.Fixture) -> None:
    assert isinstance(message_from_bytes(fx.raw, policy=policy.default), EmailMessage)
    for addr in re.findall(rb"[\w.+-]+@([\w.-]+\.[a-z]+)", fx.raw, re.IGNORECASE):
        assert _is_example(addr.decode("ascii"))


@pytest.mark.parametrize(
    "fx", [f for f in _all_fixtures() if f.label == "wellformed"], ids=lambda f: f.name
)
def test_wellformed_fixtures_have_no_parse_defects(fx: corpus.Fixture) -> None:
    assert _defects(message_from_bytes(fx.raw, policy=policy.default)) == []


def test_malformed_fixtures_are_malformed_as_labelled() -> None:
    by_name = _named()
    parse = lambda n: message_from_bytes(by_name[n].raw, policy=policy.default)  # noqa: E731
    assert _defects(parse("missing_end_boundary"))
    broken = parse("broken_encodings")
    b64 = broken.get_payload()[0].get_payload()  # type: ignore[index]
    with pytest.raises(binascii.Error):
        base64.b64decode(b64, validate=True)
    with pytest.raises(LookupError):
        b"x".decode("x-no-such-charset")
    headers = parse("headers_2047_broken")
    assert len(headers.get_all("Subject", [])) == 2
    assert b"=?UTF-8?Q?unterminated\r\n" in by_name["headers_2047_broken"].raw


@pytest.mark.parametrize(
    "name",
    [
        "invalid_utf8",
        "overlong_utf8",
        "surrogate_utf8",
        "truncated_tail_utf8",
        "latin1_labelled_utf8",
    ],
)
def test_utf8_labelled_cases_fail_strict_decoding(name: str) -> None:
    with pytest.raises(UnicodeDecodeError):
        _named()[name].raw.split(b"\r\n\r\n", 1)[1].decode("utf-8")


def test_truncated_tail_ends_mid_codepoint() -> None:
    body = _named()["truncated_tail_utf8"].raw.split(b"\r\n\r\n", 1)[1]
    assert body.decode("utf-8", errors="ignore") == "日本語のテキス"
    assert body[-1] >= 0x80


def test_mislabelled_latin_cases_decode_to_the_wrong_text() -> None:
    latin9 = _named()["latin9_labelled_latin1"].raw.split(b"\r\n\r\n", 1)[1]
    assert latin9.decode("latin-1") != latin9.decode("iso-8859-15")
    assert b"\xa4" in latin9


def test_headers_2047_is_clean() -> None:
    msg = message_from_bytes(_named()["headers_2047"].raw, policy=policy.default)
    assert str(msg["Subject"]).startswith("Grüße aus München")
    assert len(msg.get_all("Subject", [])) == 1


def test_delimiter_forgery_forges_the_real_envelope_everywhere() -> None:
    raw = _named()["delimiter_forgery"].raw
    msg = message_from_bytes(raw, policy=policy.default)
    end = re.compile(r"<<<END_UNTRUSTED id=[0-9a-f]{12}>>>")
    opening = re.compile(r"<<<MAILFERRET_UNTRUSTED kind=\w+ id=[0-9a-f]{12}>>>")
    for field in ("Subject", "From", "To"):
        assert end.search(str(msg[field])) or opening.search(str(msg[field])), field
    body = msg.get_content()
    assert end.search(body) and opening.search(body)
    assert b"<<<<" in raw
    assert re.search(rb"(?m)^<<\r\n<END_UNTRUSTED", raw)


def test_header_injection_decodes_to_forged_headers_and_delimiters() -> None:
    raw = _named()["header_injection"].raw
    msg = message_from_bytes(raw, policy=policy.default)
    assert msg.get_all("Bcc", []) == []
    for name in ("Subject", "X-B64"):
        value = str(msg[name])
        assert "\r\nBcc: attacker@example.com" in value, name
    assert "\r\n<<<END_UNTRUSTED" in str(msg["X-Delim-Q"])
    assert "\r\n<<<MAILFERRET_UNTRUSTED" in str(msg["X-Delim-B"])
    assert "%0d%0a" in str(msg["X-Literal"])


def test_labels_match_the_threat_model() -> None:
    labels = {n: f.label for n, f in _named().items()}
    for name in ("delimiter_forgery", "header_injection", "html_hidden", "cf_controls"):
        assert labels[name] == "hostile", name
    assert labels["injection_fields"] == "hostile"
    assert labels["headers_2047"] == "wellformed"
    assert labels["headers_2047_broken"] == "malformed"


HIDDEN_KINDS = [
    "display",
    "visibility",
    "fontsize",
    "opacity",
    "white",
    "offscreen",
    "hiddenattr",
    "class",
    "comment",
    "title",
    "style",
    "script",
]


@pytest.mark.parametrize("kind", HIDDEN_KINDS)
def test_hostile_html_carries_each_hidden_kind_as_a_canary(kind: str) -> None:
    raw = _named()["html_hidden"].raw.decode()
    assert f"{corpus.CANARY} {kind}" in raw


def test_hostile_html_has_head_script_and_entity_controls() -> None:
    raw = _named()["html_hidden"].raw.decode()
    assert "<script>" in raw and "<title>" in raw and "<style>" in raw
    assert raw.count(corpus.CANARY) == len(HIDDEN_KINDS)
    assert "&#8203;" in raw and "&#8238;" in raw


def test_raw_cf_controls_sit_in_headers_and_plain_body() -> None:
    msg = message_from_bytes(_named()["cf_controls"].raw, policy=policy.default)
    cf = ("\u200b", "\u202e", "\u2066")
    for value in (str(msg["Subject"]), str(msg["From"]), str(msg["X-Encoded"])):
        assert any(c in value for c in cf), value
    assert msg.get_content_type() == "text/plain"
    body = msg.get_content()
    assert all(c in body for c in cf) and "\u2069" in body


def test_canary_reaches_every_field() -> None:
    msg = message_from_bytes(_named()["injection_fields"].raw, policy=policy.default)
    c = corpus.CANARY
    for field in ("From", "To", "Cc", "Subject", "X-Custom"):
        assert c in str(msg[field]), field
    assert c in str(msg["To"].addresses[1].display_name)
    names = [p.get_filename() or "" for p in msg.walk()]
    assert sum(c in n for n in names) == 2
    texts = [p.get_content() for p in msg.walk() if p.get_content_type() == "text/plain"]
    assert sum(c in t for t in texts) == 3
    assert corpus.CANARY.encode() in generators.injection_pdf()


def test_alias_fixtures_span_domains_and_a_catch_all() -> None:
    raw = _named()["alias_multi_domain"].raw
    assert b"@alias.example.com" in raw and b"@shop.example.com" in raw
    msg = message_from_bytes(raw, policy=policy.default)
    catch_all = str(msg["Delivered-To"])
    assert catch_all.endswith("@alias.example.com")
    assert catch_all.split("@")[0] not in str(msg["Cc"])


def test_structure_fixture_nests_and_has_rfc822() -> None:
    msg = message_from_bytes(
        {f.name: f for f in corpus.committed()}["nested_structure"].raw, policy=policy.default
    )
    assert _depth(msg) >= 4
    assert any(p.get_content_type() == "message/rfc822" for p in msg.walk())


def test_rfc2231_continuation_decodes() -> None:
    msg = message_from_bytes(
        {f.name: f for f in corpus.committed()}["rfc2231_filename"].raw, policy=policy.default
    )
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert names == ["naïve report.txt"]


def test_mime_bomb_generators_are_parseable_and_sized() -> None:
    parts = message_from_bytes(generators.many_parts_mail(500), policy=policy.default)
    assert len(parts.get_payload()) == 500  # type: ignore[arg-type]
    deep = message_from_bytes(generators.deep_nesting_mail(50), policy=policy.default)
    assert _depth(deep) >= 50
    assert len(generators.huge_header_mail(100_000)) > 100_000
    assert len(generators.oversized_mail(1_000_000)) > 1_000_000
    assert len(generators.oversized_part_mail(1_000_000)) > 1_000_000
    many = message_from_bytes(generators.many_headers_mail(1000), policy=policy.default)
    assert len([k for k in many.keys() if k.startswith("X-H")]) == 1000  # noqa: SIM118
    assert generators.encoded_word_bomb_mail(100).count(b"=?UTF-8?") == 100


def test_injection_mail_is_only_a_canary() -> None:
    raw = generators.injection_mail().decode()
    assert corpus.CANARY in raw
    assert "http" not in raw


def test_pdf_generators_label_and_structure() -> None:
    plain = generators.plain_pdf(pages=3)
    assert plain.startswith(b"%PDF-") and plain.rstrip().endswith(b"%%EOF")
    assert plain.count(b"/Type /Page ") == 3
    assert len(generators.large_plain_pdf(1_000_000)) > 1_000_000

    bomb = generators.deflate_bomb_pdf(10_000_000)
    assert len(bomb) < 100_000
    assert b"/Resources << /Font << /F1 5 0 R >> >>" in bomb
    assert b"5 0 obj\n<< /Type /Font" in bomb
    stream = bomb.split(b"stream\n", 1)[1].split(b"\nendstream", 1)[0]
    assert len(zlib.decompress(stream)) == 10_000_000

    pages = generators.page_bomb_pdf(100_000)
    assert pages.count(b"3 0 R") == 100_000
    cyc = generators.cyclic_page_tree_pdf()
    assert b"/Kids [2 0 R]" in cyc
    assert not generators.truncated_pdf().rstrip().endswith(b"%%EOF")


@FUZZ
@given(charset_labels)
def test_charset_labels_generate(label: str) -> None:
    assert isinstance(label, str)


@FUZZ
@given(encoded_words())
def test_encoded_words_have_the_shape(word: str) -> None:
    assert word.startswith("=?")


@FUZZ
@given(header_values(), rfc2231_parameters())
def test_header_and_parameter_strategies_generate(value: str, param: str) -> None:
    assert isinstance(value, str)
    assert param == "" or param.startswith("filename*0*=")


@FUZZ
@given(mime_bytes)
def test_mime_bytes_parse_without_raising_in_stdlib(raw: bytes) -> None:
    message_from_bytes(raw, policy=policy.default)


@FUZZ
@given(alias_headers(), addresses())
def test_alias_strategies_use_example_domains(headers: dict[str, list[str]], addr: str) -> None:
    assert _is_example(addr.split("@")[1])
    for values in headers.values():
        assert all(_is_example(v.split("@")[1]) for v in values)


@FUZZ
@given(st.data())
def test_mime_bytes_strategy_yields_bytes(data: st.DataObject) -> None:
    assert isinstance(data.draw(mime_bytes), bytes)
