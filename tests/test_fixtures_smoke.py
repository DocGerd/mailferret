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


def _all_fixtures() -> list[corpus.Fixture]:
    return corpus.committed() + corpus.charset_cases()


def test_committed_corpus_is_present_and_small() -> None:
    fixtures = corpus.committed()
    assert len(fixtures) >= 9
    assert all(len(f.raw) < 4096 for f in fixtures)


@pytest.mark.parametrize("fx", _all_fixtures(), ids=lambda f: f.name)
def test_every_fixture_parses_and_stays_example_com(fx: corpus.Fixture) -> None:
    assert isinstance(message_from_bytes(fx.raw, policy=policy.default), EmailMessage)
    for addr in re.findall(rb"[\w.+-]+@([\w.-]+\.[a-z]+)", fx.raw, re.IGNORECASE):
        assert addr.lower().endswith(b"example.com")


@pytest.mark.parametrize(
    "fx", [f for f in _all_fixtures() if f.label == "wellformed"], ids=lambda f: f.name
)
def test_wellformed_fixtures_have_no_parse_defects(fx: corpus.Fixture) -> None:
    assert _defects(message_from_bytes(fx.raw, policy=policy.default)) == []


def test_malformed_fixtures_are_malformed_as_labelled() -> None:
    by_name = {f.name: f for f in _all_fixtures()}
    parse = lambda n: message_from_bytes(by_name[n].raw, policy=policy.default)  # noqa: E731
    assert _defects(parse("missing_end_boundary"))
    broken = parse("broken_encodings")
    b64 = broken.get_payload()[0].get_payload()  # type: ignore[index]
    with pytest.raises(binascii.Error):
        base64.b64decode(b64, validate=True)
    with pytest.raises(UnicodeDecodeError):
        by_name["invalid_utf8"].raw.split(b"\r\n\r\n", 1)[1].decode("utf-8")
    with pytest.raises(LookupError):
        b"x".decode("x-no-such-charset")
    assert b"</untrusted>" in by_name["delimiter_forgery"].raw
    assert len(parse("header_injection").get_all("Bcc", [])) == 0


def test_hostile_html_carries_only_canaries() -> None:
    raw = {f.name: f for f in corpus.committed()}["html_hidden"].raw.decode()
    assert raw.count(corpus.CANARY) >= 8
    assert "​" in raw or "&#8203;" in raw


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
    assert addr.lower().split("@")[1].endswith("example.com")
    for values in headers.values():
        assert all(v.lower().split("@")[1].endswith("example.com") for v in values)


@FUZZ
@given(st.data())
def test_mime_bytes_strategy_yields_bytes(data: st.DataObject) -> None:
    assert isinstance(data.draw(mime_bytes), bytes)
