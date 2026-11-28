from __future__ import annotations

import time

import pytest

from mailferret.content.css import (
    ColorValue,
    Flag,
    Style,
    evaluate,
    override,
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


def _tiny(css: str) -> Flag | None:
    return evaluate(parse_declarations(css)[0]).tiny


@pytest.mark.parametrize(
    ("css", "expected"),
    [
        ("font-size:0", Flag.ON),
        ("font-size:1px", Flag.ON),
        ("font-size:1pt", Flag.ON),
        ("font-size:0.3mm", Flag.ON),
        ("font-size:0em", Flag.ON),
        ("font-size:12px", Flag.OFF),
        ("font-size:1in", Flag.OFF),
        ("font-size:xx-large", Flag.OFF),
        ("font-size:initial", Flag.OFF),
        ("font:italic bold 12px/1.5 a", Flag.INHERIT),
        ("font:small a", Flag.INHERIT),
        ("font:0/0 a", Flag.ON),
        ("font-size:1em", Flag.INHERIT),
        ("font-size:100%", Flag.INHERIT),
        ("font-size:12", Flag.INHERIT),
        ("font-size:larger", Flag.INHERIT),
        ("font-size:calc(1px+1em)", Flag.INHERIT),
        ("font-size:var(--s)", Flag.ON),
        ("font:1em a", Flag.INHERIT),
        ("font:inherit", Flag.INHERIT),
        ("font:initial", Flag.INHERIT),
        ("font:12px", Flag.INHERIT),
        ("font:large", Flag.INHERIT),
        ("font:bogus 12px a", Flag.INHERIT),
        ("font:initial a", Flag.INHERIT),
        ("font:12px/1.5", Flag.INHERIT),
        ("font:12px / 1.5 a", Flag.INHERIT),
        ("font:bogus 0 a", Flag.ON),
        ("font:0", Flag.ON),
        ("font-size:12.px", Flag.INHERIT),
        ("font-size:", None),
        ("color:red", None),
    ],
)
def test_font_size_allowlist(css: str, expected: Flag | None) -> None:
    assert _tiny(css) is expected


def test_an_unrecognised_value_never_clears_a_hiding_one() -> None:
    assert override(Flag.ON, Flag.INHERIT) is Flag.ON
    assert override(Flag.ON, Flag.OFF) is Flag.OFF
    assert override(Flag.OFF, Flag.INHERIT) is Flag.INHERIT
    assert override(Flag.ON, None) is Flag.ON
    assert _tiny("font-size:0;font-size:bogus") is Flag.ON
    assert _tiny("font-size:12px;font-size:1em") is Flag.INHERIT
    assert _tiny("font-size:0 !important;font-size:12px") is Flag.ON


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("hidden", Flag.ON),
        ("collapse", Flag.ON),
        ("visible", Flag.OFF),
        ("initial", Flag.OFF),
        ("inherit", Flag.INHERIT),
        ("unset", Flag.INHERIT),
        ("revert", Flag.INHERIT),
        ("bogus", Flag.INHERIT),
    ],
)
def test_visibility_allowlist(value: str, expected: Flag) -> None:
    assert evaluate(parse_declarations(f"visibility:{value}")[0]).invisible is expected


@pytest.mark.parametrize(
    ("css", "expected"),
    [
        ("background:linear-gradient(#fff,#fff)", (255, 255, 255)),
        (
            "background-image:linear-gradient(white 0%,#ffffff 50%,rgb(255,255,255))",
            (255, 255, 255),
        ),
        ("background:radial-gradient(circle at 50% 50%,#000,#000)", (0, 0, 0)),
        ("background:linear-gradient(#fff,#000)", "image"),
        ("background:linear-gradient(#fff,transparent)", "image"),
        ("background:linear-gradient(#fff,blue)", "image"),
        ("background:linear-gradient(#fff,#fff),url(x.png)", "image"),
        ("background:url(x.png)", "image"),
        ("background:url(x.png) #123456", (0x12, 0x34, 0x56)),
        ("background:linear-gradient(#000,#111) #fff", (255, 255, 255)),
        ("background:transparent", None),
    ],
)
def test_backdrop_of_gradients_and_fallbacks(css: str, expected: ColorValue) -> None:
    assert evaluate(parse_declarations(css)[0]).background == expected


def test_exponents_parse_and_em_is_not_an_exponent() -> None:
    assert _tiny("font-size:1e1px") is Flag.OFF
    assert _tiny("font-size:1e-9px") is Flag.ON
    assert _tiny("font-size:1em") is Flag.INHERIT
    assert _tiny("font-size:1ex") is Flag.INHERIT
    assert _tiny("font-size:1e1em") is Flag.INHERIT


@pytest.mark.parametrize(
    ("css", "expected"),
    [
        ("font-size:calc(0px)", Flag.ON),
        ("font-size:min(0px,12px)", Flag.ON),
        ("font-size:min(0px,var(--x))", Flag.ON),
        ("font-size:clamp(0px,0px,0px)", Flag.ON),
        ("font-size:clamp(0px,var(--x),0px)", Flag.ON),
        ("font-size:calc(0.5em * 0)", Flag.ON),
        ("font-size:calc(12px)", Flag.INHERIT),
        ("font-size:max(12px,0px)", Flag.INHERIT),
        ("font-size:max(0px,var(--x))", Flag.ON),
        ("font-size:calc(1em + 0px)", Flag.INHERIT),
        ("font-size:calc(0px", Flag.ON),
        ("font-size:calc(0px) bogus", Flag.INHERIT),
        ("font-size:calc(0px 1px)", Flag.INHERIT),
        ("font-size:calc(1px / 0)", Flag.ON),
    ],
)
def test_constant_math_functions(css: str, expected: Flag) -> None:
    flag = _tiny(css)
    assert flag is expected


def test_nested_math_is_bounded_and_fails_closed() -> None:
    started = time.monotonic()
    deep = "font-size:" + "calc(" * 200_000 + "12px" + ")" * 200_000
    assert _tiny(deep) is Flag.ON
    flat = "font-size:calc(" + "1px + " * 200_000 + "1px)"
    assert _tiny(flat) is Flag.INHERIT
    assert time.monotonic() - started < 3.0


def test_opacity_and_offsets_accept_exponents_and_math() -> None:
    for css in (
        "opacity:0e0",
        "opacity:1e-9",
        "opacity:calc(0)",
        "left:-1e9px",
        "left:calc(-9999px)",
    ):
        assert evaluate(parse_declarations(css)[0]).hidden, css
    for css in ("opacity:1", "opacity:1e-1", "opacity:calc(1)", "left:-1e2px", "left:1e9px"):
        assert not evaluate(parse_declarations(css)[0]).hidden, css


UNIMPLEMENTED = [
    "round(0.4px,1px)",
    "abs(0px)",
    "sign(0)",
    "sin(0)",
    "cos(1)",
    "mod(5px,2px)",
    "rem(5px,2px)",
    "pow(2,3)",
    "hypot(3px,4px)",
    "log(1)",
    "exp(0)",
    "atan2(1,1)",
    "attr(x)",
    "foo(1)",
    "-webkit-foo(1)",
    "calc(round(1px,1px))",
]


@pytest.mark.parametrize("function", UNIMPLEMENTED)
def test_unimplemented_functions_fail_closed_in_every_hiding_property(function: str) -> None:
    assert _tiny(f"font-size:{function}") is Flag.ON
    assert _tiny(f"font:{function} a") is Flag.ON
    assert evaluate(parse_declarations(f"visibility:{function}")[0]).invisible is Flag.ON
    for css in (f"opacity:{function}", f"left:{function}", f"text-indent:{function}"):
        assert evaluate(parse_declarations(css)[0]).hidden, css
    boxed = evaluate(parse_declarations(f"overflow:hidden;max-height:{function}")[0])
    assert boxed.hidden


@pytest.mark.parametrize(
    ("css", "expected"),
    [
        ("font-size:-webkit-calc(0px)", Flag.ON),
        ("font-size:-moz-calc(0px)", Flag.ON),
        ("font-size:-webkit-calc(12px)", Flag.INHERIT),
        ("font-size:calc(0px / 0)", Flag.ON),
        ("font-size:calc(0 / 0)", Flag.ON),
        ("font-size:calc(1px / 0)", Flag.ON),
        ("font-size:calc(-1px / 0)", Flag.ON),
        ("font-size:calc(0px * nan)", Flag.ON),
        ("font-size:calc(nan * 1px)", Flag.ON),
        ("font-size:calc(infinity * 1px)", Flag.ON),
        ("font-size:calc(-infinity * 1px)", Flag.ON),
        ("font-size:calc(infinity * 0px)", Flag.ON),
        ("font-size:min(nan * 1px, 20px)", Flag.ON),
        ("font-size:min(20px, nan * 1px)", Flag.ON),
        ("font-size:max(20px, nan * 1px)", Flag.ON),
        ("font-size:clamp(20px, 30px, nan * 1px)", Flag.ON),
        ("font-size:calc(pi * 0px)", Flag.ON),
        ("font-size:calc(pi * 1px)", Flag.INHERIT),
        ("font-size:calc(e * 1px)", Flag.INHERIT),
        ("font-size:calc(1e999px)", Flag.ON),
        ("font:calc(0px) a", Flag.ON),
        ("font:calc(12px) a", Flag.INHERIT),
        ("font:calc(12px/2) a", Flag.INHERIT),
        ("font:calc(0px)/1 a", Flag.ON),
        ("font:12px/calc(0px) a", Flag.INHERIT),
        ("font:clamp(14px,2vw,18px) a", Flag.INHERIT),
    ],
)
def test_degenerate_results_prefixes_and_shorthand_math(css: str, expected: Flag) -> None:
    assert _tiny(css) is expected


@pytest.mark.parametrize(
    "css",
    [
        "opacity:calc(0/0)",
        "opacity:calc(nan)",
        "opacity:calc(0%)",
        "opacity:min(0%,1)",
        "opacity:calc(0.2%)",
        "opacity:min(1, 0.2%)",
        "opacity:calc(1/0)",
        "left:calc(-infinity * 1px)",
        "left:calc(nan * 1px)",
        "left:calc(1px / 0)",
        "left:-webkit-calc(-9999px)",
    ],
)
def test_degenerate_opacity_and_offset_values_hide(css: str) -> None:
    assert evaluate(parse_declarations(css)[0]).hidden


@pytest.mark.parametrize(
    "css",
    ["opacity:calc(0.5)", "opacity:calc(50%)", "opacity:min(50%,1)", "left:calc(1px - 99px)"],
)
def test_ordinary_math_does_not_hide(css: str) -> None:
    assert not evaluate(parse_declarations(css)[0]).hidden


def test_non_finite_results_fail_closed_even_where_they_are_not_small() -> None:
    # Without the finite check NaN compares false and +inf is not tiny: both would show the text.
    assert _tiny("font-size:calc(0px / 0)") is Flag.ON
    assert _tiny("font-size:calc(infinity * 1px)") is Flag.ON
    assert evaluate(parse_declarations("left:calc(1px / 0)")[0]).hidden
    assert evaluate(parse_declarations("opacity:calc(nan)")[0]).hidden


def test_an_upper_bound_is_never_used_as_an_exact_operand() -> None:
    # min() with an unknown only bounds the value from above: later arithmetic must not treat
    # the bound as the value, or readable text is hidden.
    assert _tiny("font-size:calc(min(0px, 1%) * -1)") is Flag.INHERIT
    assert _tiny("font-size:calc(1px - min(0px, 1%))") is Flag.INHERIT
    assert _tiny("font-size:calc(1em + 2px)") is Flag.INHERIT
    assert _tiny("font-size:calc(1em * 0 + 12px)") is Flag.INHERIT


def _style(css: str) -> Style:
    return evaluate(parse_declarations(css)[0])


# Any variable read in a hiding property hides, wherever it sits and whatever it falls back to.
VARIABLE_READS = [
    "var(--x)",
    "var(--x, 13px)",
    "var(--x, var(--y, 13px))",
    "VAR(--X)",
    "v\\61r(--x)",
    "env(x)",
    "env(x, 13px)",
    "env(safe-area-inset-left)",
    "calc(var(--x) + 1px)",
    "calc(20px + env(x))",
    "min(20px, var(--x))",
    "max(20px, var(--x, 20px))",
    "clamp(14px, var(--x), 18px)",
]
HIDING_DECLARATIONS = [
    "font-size:{v}",
    "font:{v} a",
    "font:12px/{v} a",
    "font:italic bold 12px a, {v}",
    "visibility:{v}",
    "opacity:{v}",
    "display:{v}",
    "mso-hide:{v}",
    "clip-path:{v}",
    "left:{v}",
    "margin-left:{v}",
    "text-indent:{v}",
    "overflow:{v};height:0",
    "overflow:hidden;height:{v}",
    "overflow:hidden;max-width:{v}",
]


@pytest.mark.parametrize("read", VARIABLE_READS)
@pytest.mark.parametrize("declaration", HIDING_DECLARATIONS)
def test_any_variable_read_in_a_hiding_property_hides(declaration: str, read: str) -> None:
    style = _style("--x:13px;" + declaration.replace("{v}", read))
    hidden_by = [
        style.hidden,
        style.tiny is Flag.ON,
        style.invisible is Flag.ON,
    ]
    assert any(hidden_by), declaration


@pytest.mark.parametrize(
    "css",
    [
        "color:var(--x)",
        "background:var(--x)",
        "background-color:var(--x, #fff)",
        "padding:var(--x)",
        "margin:var(--x)",
        "border-color:var(--x)",
        "line-height:var(--x)",
        "font-family:var(--x)",
        "font-weight:var(--x)",
        "padding-left:env(safe-area-inset-left)",
        "--x:0px;color:red",
        "--font-size:0;color:red",
    ],
)
def test_variables_in_other_properties_stay_harmless(css: str) -> None:
    style = _style(css)
    assert not style.hidden
    assert style.tiny is None
    assert style.invisible is None


def test_clipping_and_a_zero_box_from_different_rules_hide() -> None:
    sheet = parse_stylesheet(".a{overflow:hidden} .b{height:0}")
    assert sheet.style_for("b", ["a", "b"], None).hidden
    assert not sheet.style_for("b", ["a"], None).hidden
    assert not sheet.style_for("b", ["b"], None).hidden


def test_rules_apply_in_source_order_not_class_attribute_order() -> None:
    sheet = parse_stylesheet(".v{font-size:14px}.h{font-size:0}")
    assert sheet.style_for("b", ["h", "v"], None).tiny is Flag.ON
    assert sheet.style_for("b", ["v", "h"], None).tiny is Flag.ON
    sheet = parse_stylesheet(".h{font-size:0}.v{font-size:14px}")
    assert sheet.style_for("b", ["h", "v"], None).tiny is Flag.OFF
    assert sheet.style_for("b", ["v", "h"], None).tiny is Flag.OFF


def test_specificity_importance_and_style_elements() -> None:
    sheet = parse_stylesheet(".h{font-size:0}b{font-size:14px}")
    assert sheet.style_for("b", ["h"], None).tiny is Flag.ON
    sheet = parse_stylesheet("#i{font-size:14px}.h{font-size:0}b.h{font-size:0}")
    assert sheet.style_for("b", ["h"], "i").tiny is Flag.OFF
    sheet = parse_stylesheet(".h{font-size:0 !important}.v{font-size:14px}")
    assert sheet.style_for("b", ["v", "h"], None).tiny is Flag.ON
    first = parse_stylesheet(".v{font-size:14px}")
    later = parse_stylesheet(".h{font-size:0}")
    first.update(later)
    assert first.style_for("b", ["h", "v"], None).tiny is Flag.ON
    assert first.style_for("b", ["v"], None).tiny is Flag.OFF
    reverse = parse_stylesheet(".h{font-size:0}")
    reverse.update(parse_stylesheet(".v{font-size:14px}"))
    assert reverse.style_for("b", ["h", "v"], None).tiny is Flag.OFF


def test_a_key_with_many_rules_stays_cheap_and_keeps_the_last_effect() -> None:
    started = time.monotonic()
    sheet = parse_stylesheet(".g{font-size:14px}" + ".f{color:red}" * 50_000 + ".f{font-size:0}")
    for _ in range(20_000):
        assert sheet.style_for("b", ["g", "f"], None).tiny is Flag.ON
    assert time.monotonic() - started < 3.0


def test_selectors_are_stored_only_in_one_of_the_supported_forms() -> None:
    sheet = parse_stylesheet("span#x{font-size:0}#x{font-size:14px}")
    assert sheet.style_for("span", [], "x").tiny is Flag.ON
    assert sheet.style_for("div", [], "x").tiny is Flag.OFF
    sheet = parse_stylesheet("#x{font-size:14px}span#x{font-size:0}")
    assert sheet.style_for("span", [], "x").tiny is Flag.ON
    assert sheet.style_for("div", [], "x").tiny is Flag.OFF
    mixed = parse_stylesheet(".a, .b.a{font-size:0}")
    assert mixed.style_for("b", ["a"], None).tiny is Flag.ON
    assert mixed.style_for("b", ["b"], None).tiny is None
    for selector in (".a.b", "div .x", ".a#x", "span.a.b", "a[href]", "b:hover", "*", ".a > .b"):
        ignored = parse_stylesheet(f"{selector}{{font-size:0}}")
        for tag, classes, ident in (("b", ["a", "b", "x"], "x"), ("div", ["x"], None)):
            assert ignored.style_for(tag, classes, ident).tiny is None, selector
