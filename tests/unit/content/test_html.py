from __future__ import annotations

import ast
import socket
import time
import unicodedata
from email import message_from_bytes
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mailferret.content import html as html_module
from mailferret.content.html import (
    NOTE_COMMENTS,
    NOTE_FORMAT,
    NOTE_HIDDEN,
    NOTE_LIMIT_BODY,
    NOTE_LIMIT_PART,
    NOTE_PARSE_FAILED,
    NOTE_STRUCTURE,
    html_to_text,
    strip_body_text,
)
from mailferret.content.invisible import strip_format, strip_invisible
from mailferret.limits import Limits
from tests.fixtures import corpus

FIXTURES = {f.name: f for f in corpus.committed()}
CANARY = corpus.CANARY
ZWSP, RLO, PDF, ISOLATE = (chr(c) for c in (0x200B, 0x202E, 0x202C, 0x2066))
HANGUL_FILLER, GRAPHEME_JOINER, TAG_A = chr(0x3164), chr(0x034F), chr(0xE0041)
REPLACEMENT, NUL, SURROGATE, EMOJI = chr(0xFFFD), chr(0), chr(0xD800), chr(0x1F600)
NONCHARS = chr(0xFFFE) + chr(0xFFFF)
FUZZ = settings(max_examples=200, deadline=None)


def _text(html: str, **kwargs: Any) -> str:
    return html_to_text(html, **kwargs).text


def _body(name: str) -> tuple[bytes, str]:
    message = message_from_bytes(FIXTURES[name].raw)
    payload = message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    return payload, message.get_content_charset() or "utf-8"


def _is_format(char: str) -> bool:
    return unicodedata.category(char) == "Cf"


def _vector(name: str) -> str:
    return HIDDEN_VECTORS[name].replace("{c}", CANARY).replace("{{", "{").replace("}}", "}")


# --- hidden content (T-04) -------------------------------------------------------------------

HIDDEN_VECTORS = {
    "display": '<span style="display:none">{c}</span>',
    "display_case_space": '<span style="DISPLAY : None !important">{c}</span>',
    "display_comment": '<span style="display/**/:/**/none">{c}</span>',
    "display_escape": '<span style="d\\69splay:none">{c}</span>',
    "display_entity": '<span style="display&#58;none">{c}</span>',
    "visibility": '<span style="visibility:hidden">{c}</span>',
    "collapse": '<span style="visibility:collapse">{c}</span>',
    "font_size": '<span style="font-size:0">{c}</span>',
    "font_size_unit": '<span style="font-size:0px">{c}</span>',
    "font_size_one_px": '<span style="font-size:1px">{c}</span>',
    "opacity": '<span style="opacity:0">{c}</span>',
    "white_on_white": '<span style="color:#fff;background:#ffffff">{c}</span>',
    "white_default": '<span style="color:white">{c}</span>',
    "rgb_on_same": '<span style="color:rgb(1,2,3);background-color:#010203">{c}</span>',
    "transparent": '<span style="color:transparent">{c}</span>',
    "alpha_zero": '<span style="color:rgba(0,0,0,0)">{c}</span>',
    "font_attr": '<table bgcolor="#fff"><tr><td><font color="#FFFFFF">{c}</font></td></tr></table>',
    "offscreen": '<span style="position:absolute;left:-9999px">{c}</span>',
    "text_indent": '<p style="text-indent:-5000px">{c}</p>',
    "clipped_box": '<div style="max-height:0;overflow:hidden">{c}</div>',
    "mso_hide": '<div style="mso-hide:all">{c}</div>',
    "hidden_attr": "<span hidden>{c}</span>",
    "hidden_attr_value": '<div hidden="until-found">{c}</div>',
    "class_rule": "<style>.h{{display:none}}</style><span class='x h'>{c}</span>",
    "id_rule": "<style>#h{{visibility:hidden}}</style><span id='h'>{c}</span>",
    "tag_rule": "<style>em{{font-size:0}}</style><em>{c}</em>",
    "tag_class_rule": "<style>b.h,i{{opacity:0}}</style><b class='h'>{c}</b>",
    "script": "<script>var x = '{c}';</script>",
    "style_text": "<style>/* {c} */</style>",
    "head_title": "<head><title>{c}</title></head>",
    "comment": "<!-- {c} -->",
    "conditional_comment": "<!--[if mso]>{c}<![endif]-->",
    "template": "<template>{c}</template>",
    "iframe": "<iframe>{c}</iframe>",
    "nested_in_hidden": '<div style="display:none"><p><b>{c}</b></p></div>',
}


@pytest.mark.parametrize("name", sorted(HIDDEN_VECTORS))
def test_hidden_vector_is_removed(name: str) -> None:
    result = html_to_text(f"<html><body><p>before</p>{_vector(name)}<p>after</p></body></html>")
    assert CANARY not in result.text
    assert result.text == "before\n\nafter"
    assert set(result.notes) & {NOTE_HIDDEN, NOTE_STRUCTURE, NOTE_COMMENTS}


@pytest.mark.parametrize(
    "visible",
    [
        '<span style="color:#fff;background:#000">{c}</span>',
        '<table bgcolor="#222222"><tr><td style="color:#fff">{c}</td></tr></table>',
        '<span style="font-size:12px">{c}</span>',
        '<span style="display:block;opacity:1">{c}</span>',
        '<div style="max-height:0">{c}</div>',
        "<style>.h{{display:none}}</style><span class='shown'>{c}</span>",
        "<style>@media (max-width:480px){{.d{{display:none}}}}</style><b class='d'>{c}</b>",
        "<style>div span{{display:none}}</style><div><span>{c}</span></div>",
    ],
)
def test_visible_content_is_kept(visible: str) -> None:
    html = visible.replace("{{", "{").replace("}}", "}").replace("{c}", CANARY)
    assert _text(html) == CANARY


def test_hidden_removal_keeps_tail_text() -> None:
    assert _text("a<span hidden>X</span>b") == "ab"
    assert _text("a<!-- X -->b") == "ab"
    assert _text("<p>a<script>X</script>b</p>") == "ab"


def test_corpus_hidden_fixture_has_no_canary() -> None:
    body, charset = _body("html_hidden")
    result = html_to_text(body, charset)
    assert CANARY not in result.text
    assert "visible" in result.text
    assert "zerowidth bidi text" in result.text
    assert {NOTE_HIDDEN, NOTE_STRUCTURE, NOTE_COMMENTS, NOTE_FORMAT} <= set(result.notes)
    assert not any(_is_format(c) for c in result.text)


def test_notes_never_repeat_mail_content() -> None:
    body, charset = _body("html_hidden")
    for note in html_to_text(body, charset).notes:
        assert CANARY not in note
        assert note.isascii()


def test_clean_html_has_no_notes() -> None:
    assert html_to_text("<p>plain</p>").notes == ()


# --- format controls and invisibles (T-04) ---------------------------------------------------


def test_cf_from_source_and_entities_is_stripped() -> None:
    raw = f"<p>a{ZWSP}b{RLO}c{PDF}d{TAG_A}e{ISOLATE}</p><p>x&#8203;y&#8238;z&#x2066;</p>"
    result = html_to_text(raw)
    assert result.text == "abcde\n\nxyz"
    assert NOTE_FORMAT in result.notes


def test_entity_only_cf_is_noted() -> None:
    result = html_to_text("<p>x&#8203;y</p>")
    assert result.text == "xy"
    assert NOTE_FORMAT in result.notes


def test_non_cf_invisibles_are_stripped() -> None:
    result = html_to_text(f"<p>a{HANGUL_FILLER}b{GRAPHEME_JOINER}c&#12644;d&#847;e</p>")
    assert result.text == "abcde"


def test_cf_in_style_cannot_defeat_detection() -> None:
    zero = f"display:no{ZWSP}ne"
    assert CANARY not in _text(f'<span style="{zero}">{CANARY}</span>')


def test_cf_in_link_and_alt_is_stripped() -> None:
    result = html_to_text(f'<a href="https://example.com/a{ZWSP}b">t{RLO}x</a><img alt="i{ZWSP}m">')
    assert result.text == "tx (https://example.com/ab) [image: im]"
    assert not any(_is_format(c) for c in result.text)


def test_plain_body_cf_stripping() -> None:
    body = message_from_bytes(FIXTURES["cf_controls"].raw).get_payload(decode=True)
    assert isinstance(body, bytes)
    result = strip_body_text(body.decode("utf-8"))
    assert "zerowidth bidi isolate" in result.text
    assert not any(_is_format(c) for c in result.text)
    assert NOTE_FORMAT in result.notes
    assert strip_body_text("clean").notes == ()


def test_shared_helper_rules() -> None:
    assert strip_format(f"a{ZWSP}b{HANGUL_FILLER}") == (f"ab{HANGUL_FILLER}", True)
    assert strip_invisible(f"a{ZWSP}b{HANGUL_FILLER}{GRAPHEME_JOINER}") == ("ab", True)
    assert strip_invisible("plain") == ("plain", False)
    kept = f"Grüße 日本語 {EMOJI}"
    assert strip_invisible(kept) == (kept, False)


# --- structure -------------------------------------------------------------------------------


def test_lists_links_tables_images() -> None:
    html = (
        "<ul><li>one<li>two <a href='https://example.com/x'>link</a><ol><li>deep</ol></ul>"
        "<table><tr><td>1<td>2<td></td></tr><tr><td>3</table>"
        "<a href='https://example.com/y'>https://example.com/y</a>"
        "<a href='javascript:alert(1)'>js</a><a href='https://example.com'></a>"
        "<img alt='pic' src='https://example.com/p.png'><img src='https://example.com/q.png'>"
    )
    text = _text(html)
    assert "- one\n- two link (https://example.com/x)\n  1. deep" in text
    assert "1 | 2\n3" in text
    assert text.count("https://example.com/y") == 1
    assert "javascript" not in text
    assert "https://example.com" in text
    assert "[image: pic]" in text
    assert "p.png" not in text
    assert "q.png" not in text


def test_whitespace_and_breaks() -> None:
    assert _text("<p>  a \n\t b  </p><p>c</p>") == "a b\n\nc"
    assert _text("a<br>b<br><br>c") == "a\nb\n\nc"
    assert _text("<pre>  x\n y</pre>") == "x\n y"
    assert _text("<div>a</div><div>b</div>") == "a\nb"
    assert _text("<p>a</p>" + "<br>" * 50 + "<p>b</p>") == "a\n\nb"


def test_overlong_or_unsafe_links_are_dropped() -> None:
    long_url = "https://example.com/" + "a" * 2000
    assert _text(f'<a href="{long_url}">t</a>') == "t"
    assert _text('<a href="data:text/html,x">t</a><a href="ftp://example.com/f">u</a>') == "tu"
    assert _text('<a href="mailto:user@example.com">mail me</a>') == (
        "mail me (mailto:user@example.com)"
    )


def test_empty_and_odd_documents_do_not_raise() -> None:
    for html in (
        "",
        "   ",
        "<!-- only a comment -->",
        "<?xml version='1.0' encoding='latin-1'?><p>x</p>",
        f"<p>a{NUL}b</p>",
        f"<p>lone {SURROGATE} surrogate</p>",
        NONCHARS,
        "<<<>>>&&&;;;",
        "<html><body></body></html>",
        "text without markup",
    ):
        assert isinstance(html_to_text(html).text, str)
    assert _text("<?xml version='1.0' encoding='latin-1'?><p>x</p>") == "x"
    assert _text("text without markup") == "text without markup"
    assert _text(f"<p>a{NUL}b</p>") == "a b"
    assert html_to_text("<!-- only a comment -->").notes == (NOTE_COMMENTS,)


def test_bytes_charset_fallbacks() -> None:
    latin = "<p>Grüße</p>".encode("latin-1")
    assert html_to_text(latin, "iso-8859-1").text == "Grüße"
    assert html_to_text(latin).text == "Grüße"
    assert html_to_text("<p>日本語</p>".encode(), "iso-8859-1").text == "日本語"
    assert isinstance(html_to_text(b"<p>\xff\xfe\x80</p>", "utf-8").text, str)


def test_partial_bytes_drop_the_cut_sequence() -> None:
    data = "<p>日本語</p>".encode()
    cut = data[: data.index("語".encode()) + 1]
    assert html_to_text(cut, "utf-8", partial=True).text == "日本"


# --- limits (L-02, L-03) ---------------------------------------------------------------------


def test_l02_input_cap_cuts_on_codepoint_boundary() -> None:
    limits = Limits(max_part_bytes=1000)
    html = "<p>" + "日本語" * 2000 + "</p>"
    for result in (
        html_to_text(html, limits=limits),
        html_to_text(html.encode(), "utf-8", limits=limits),
    ):
        assert NOTE_LIMIT_PART in result.notes
        assert result.truncated
        assert REPLACEMENT not in result.text
        assert 0 < len(result.text.encode()) <= 1000


def test_l03_output_cap() -> None:
    limits = Limits(max_body_chars=50)
    result = html_to_text("<p>" + "word " * 500 + "</p>", limits=limits)
    assert len(result.text) <= 50
    assert result.truncated
    assert NOTE_LIMIT_BODY in result.notes
    exact = html_to_text("<p>" + "x" * 50 + "</p>", limits=limits)
    assert not exact.truncated
    assert NOTE_LIMIT_BODY not in exact.notes


def test_l03_counts_codepoints_not_bytes() -> None:
    limits = Limits(max_body_chars=10)
    result = html_to_text("<p>" + EMOJI * 40 + "</p>", limits=limits)
    assert result.text == EMOJI * 10


def test_deep_nesting_and_large_input_are_bounded() -> None:
    limits = Limits()
    cases = {
        "div": "<div>" * 100_000 + "deep" + "</div>" * 100_000,
        "unclosed_b": "<b>" * 300_000 + "tail",
        "spans": "<span>x</span>" * 150_000,
        "attrs": "<p " + 'a="1" ' * 100_000 + ">x</p>",
        "style": '<span style="' + "color:red;" * 150_000 + 'display:none">c</span>',
        "rules": "<style>" + ".a{display:none}" * 100_000 + "</style><p class=a>x</p>y",
    }
    for name, html in cases.items():
        started = time.monotonic()
        result = html_to_text(html, limits=limits)
        assert time.monotonic() - started < 20, name
        assert len(result.text) <= limits.max_body_chars, name


def test_output_budget_stops_the_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    limits = Limits(max_body_chars=100)
    walked: list[int] = []
    original = html_module._walk

    def spy(*args: Any) -> Any:
        result = original(*args)
        walked.append(len(result[0]))
        return result

    monkeypatch.setattr(html_module, "_walk", spy)
    result = html_to_text("<p>x</p>" * 200_000, limits=limits)
    assert result.truncated
    assert NOTE_LIMIT_BODY in result.notes
    assert len(result.text) <= 100
    assert walked and walked[0] <= 3 * 100 + 3


def test_entity_declarations_are_not_expanded() -> None:
    html = (
        '<!DOCTYPE html SYSTEM "http://example.com/x.dtd" '
        '[<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;">'
        '<!ENTITY x SYSTEM "file:///etc/hostname">]>'
        "<p>&b; &x; &lt;ok&gt;</p>"
    )
    result = html_to_text(html)
    assert "AAAA" not in result.text
    assert "<ok>" in result.text


def test_per_part_fault_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(html_module.etree, "fromstring", boom)
    result = html_to_text(f"<p>{CANARY}</p>")
    assert result.text == ""
    assert result.notes == (NOTE_PARSE_FAILED,)


# --- no network (T-18) -----------------------------------------------------------------------

FETCH_BAIT = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://example.com/x.dtd">'
    "<html><head><link rel='stylesheet' href='https://example.com/a.css'>"
    "<base href='https://example.com/'><style>@import url(https://example.com/b.css);"
    "body{background:url(https://example.com/bg.png)}</style></head>"
    "<body background='https://example.com/bg.gif'><img src='https://example.com/p.png' alt='a'>"
    "<iframe src='https://example.com/f'></iframe><object data='https://example.com/o'></object>"
    "<a href='https://example.com/l'>l</a><video poster='https://example.com/v.png'></video>"
    "<?xml-stylesheet href='https://example.com/s.xsl'?><svg><image href='https://example.com/i'/>"
    "</svg></body></html>"
)


def test_no_network_during_conversion(monkeypatch: pytest.MonkeyPatch) -> None:
    # Only Python-level calls are visible here; libxml2's own I/O is covered by the parser
    # options test below.
    calls: list[str] = []

    def forbid(name: str) -> Any:
        def inner(*_args: object, **_kwargs: object) -> None:
            calls.append(name)
            raise AssertionError(name)

        return inner

    for name in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, name, forbid(name))
    for name in ("connect", "connect_ex", "send", "sendall", "sendto"):
        monkeypatch.setattr(socket.socket, name, forbid(name))
    body, charset = _body("html_hidden")
    html_to_text(FETCH_BAIT)
    html_to_text(body, charset)
    assert calls == []


def test_parser_is_hardened(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []
    original = html_module.etree.HTMLParser

    def spy(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(html_module.etree, "HTMLParser", spy)
    html_to_text(FETCH_BAIT)
    assert seen
    options = seen[0]
    assert options["no_network"] is True
    assert options["huge_tree"] is False
    assert options["recover"] is True
    assert options["encoding"] == "utf-8"


def test_fetch_bait_leaves_only_the_link_text() -> None:
    result = html_to_text(FETCH_BAIT)
    assert result.text == "[image: a] l (https://example.com/l)"


def test_modules_are_pure() -> None:
    forbidden = {
        "socket",
        "urllib",
        "http",
        "requests",
        "ssl",
        "os",
        "subprocess",
        "logging",
        "pathlib",
    }
    for module in (html_module, __import__("mailferret.content.invisible", fromlist=["x"])):
        tree = ast.parse(Path(module.__file__ or "").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        assert not imported & forbidden, module.__name__


# --- Hypothesis ------------------------------------------------------------------------------

_tags = st.sampled_from(["p", "div", "span", "b", "a", "ul", "li", "table", "tr", "td", "pre"])
_attrs = st.sampled_from(
    ["", " hidden", " style='display:none'", " style='color:#fff'", " href='https://example.com/'"]
)
_bits = st.one_of(
    st.text(max_size=12),
    st.builds(lambda t, a: f"<{t}{a}>", _tags, _attrs),
    st.builds(lambda t: f"</{t}>", _tags),
    st.sampled_from([ZWSP, RLO, HANGUL_FILLER, "&#8203;", "<!--", "-->", "&", "<", NUL, CANARY]),
)
_documents = st.lists(_bits, max_size=40).map("".join)


@FUZZ
@given(_documents)
def test_fuzz_output_is_bounded_and_clean(document: str) -> None:
    result = html_to_text(document, limits=Limits(max_body_chars=200))
    assert len(result.text) <= 200
    assert not any(_is_format(c) for c in result.text)
    assert not set(result.text) & {HANGUL_FILLER, GRAPHEME_JOINER, NUL}
    assert "\n\n\n" not in result.text
    assert result.text == result.text.strip()


@FUZZ
@given(st.binary(max_size=2048), st.sampled_from([None, "utf-8", "latin-1", "shift_jis", "x-bad"]))
def test_fuzz_arbitrary_bytes_never_raise(data: bytes, charset: str | None) -> None:
    assert isinstance(html_to_text(data, charset).text, str)


@FUZZ
@given(
    st.sampled_from(sorted(HIDDEN_VECTORS)),
    st.lists(st.sampled_from(["<p>x</p>", "text ", "<br>", "<div>", "</div>", "<b>"]), max_size=8),
    st.lists(st.sampled_from(["<p>y</p>", " more", "<br>", "</b>", "<td>"]), max_size=8),
)
def test_fuzz_hidden_canary_never_survives(
    vector: str, before: list[str], after: list[str]
) -> None:
    document = "<html><body>" + "".join(before) + _vector(vector) + "".join(after)
    assert CANARY not in html_to_text(document).text


@FUZZ
@given(st.text(max_size=300))
def test_fuzz_plain_body_stripping(text: str) -> None:
    result = strip_body_text(text, Limits(max_body_chars=100))
    assert len(result.text) <= 100
    assert not any(_is_format(c) for c in result.text)
