from __future__ import annotations

import time

import pytest

from mailferret.content.css import (
    evaluate,
    parse_declarations,
    parse_stylesheet,
    preprocess,
)
from mailferret.content.html import NOTE_HIDDEN, html_to_text

CR, LF, FF, NUL, REPLACEMENT = chr(13), chr(10), chr(12), chr(0), chr(0xFFFD)
BACKSLASH = chr(92)
CANARY = "MAILFERRET-CANARY"

# `\75` is "u"; the escape swallows exactly one whitespace character after it.
URL_NAME_VARIANTS = {
    "cr": BACKSLASH + "75" + CR + "rl",
    "lf": BACKSLASH + "75" + LF + "rl",
    "ff": BACKSLASH + "75" + FF + "rl",
    "crlf": BACKSLASH + "75" + CR + LF + "rl",
    "space": BACKSLASH + "75 rl",
    "none": BACKSLASH + "75rl",
    "padded": BACKSLASH + "000075" + CR + "rl",
}


def _hides(css: str) -> bool:
    return parse_stylesheet(css).style_for("b", ["h"], None).hidden


def test_preprocess_normalises_newlines_and_nul() -> None:
    assert preprocess(f"a{CR}{LF}b{CR}c{FF}d{NUL}e") == f"a{LF}b{LF}c{LF}d{REPLACEMENT}e"
    assert preprocess("plain") == "plain"


@pytest.mark.parametrize("variant", sorted(URL_NAME_VARIANTS))
def test_escaped_url_name_followed_by_any_newline_keeps_the_scan_in_sync(variant: str) -> None:
    name = URL_NAME_VARIANTS[variant]
    css = f'.h{{background:{name}(a"b);display:none;x:{name}(c"d)}}'
    assert _hides(css), variant


def test_escape_swallows_only_one_whitespace_after_preprocessing() -> None:
    css = f'.h{{background:{BACKSLASH}75{CR}{LF}rl(a"b);display:none;x:y}}'
    assert _hides(css)


@pytest.mark.parametrize(
    "css",
    [
        f".h{{display:{CR}none}}",
        f".h{{display{CR}:{FF}none{CR}}}",
        f".h{{x:y;{CR}display:none}}",
        f".h{{display:none{CR}!{FF}important}}",
        f".h{{{BACKSLASH}64{CR}isplay:none}}",
        f".h{{{BACKSLASH}64{FF}isplay:none}}",
        f".h{{{BACKSLASH}64{CR}{LF}isplay:none}}",
    ],
)
def test_cr_and_ff_separated_declarations(css: str) -> None:
    assert _hides(css)


def test_escape_in_a_function_name_fails_closed_inline() -> None:
    for name in URL_NAME_VARIANTS.values():
        _, unsafe = parse_declarations(f"background:{name}(x.png)")
        assert unsafe, name
    assert parse_declarations(f"color:r{BACKSLASH}67b(1,2,3)")[1]
    for safe in ("background:url(x.png)", "color:rgb(1,2,3)", f"{BACKSLASH}63olor:red", "a:b"):
        assert not parse_declarations(safe)[1], safe


def test_escape_in_a_function_name_hides_the_element_with_a_note() -> None:
    name = URL_NAME_VARIANTS["cr"]
    result = html_to_text(f"<p>a</p><span style='background:{name}(x.png)'>{CANARY}</span>")
    assert result.text == "a"
    assert NOTE_HIDDEN in result.notes


def test_cr_separated_inline_display_none() -> None:
    declarations, unsafe = parse_declarations(f"color:red;{CR}display{FF}:{CR}none")
    assert not unsafe
    assert declarations == [("color", "red", False), ("display", "none", False)]
    assert evaluate(declarations).hidden


def test_preprocessing_and_name_scan_are_linear() -> None:
    cases = [
        (BACKSLASH + "75" + CR) * 200_000,
        "a" * 1_000_000,
        BACKSLASH + "75" * 400_000,
        (BACKSLASH + "75rl(") * 150_000,
    ]
    started = time.monotonic()
    for css in cases:
        parse_declarations(css)
        parse_stylesheet(f"x{{{css}}}")
    assert time.monotonic() - started < 3.0
