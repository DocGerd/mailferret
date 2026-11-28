from __future__ import annotations

import ast
import re
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
    NOTE_NESTING,
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
    template = {**HIDDEN_VECTORS, **INHERITED_HIDDEN_VECTORS}[name]
    return template.replace("{c}", CANARY).replace("{{", "{").replace("}}", "}")


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
    "important_spaced": '<span style="display:none ! important">{c}</span>',
    "important_comment": '<span style="display:none !/**/important">{c}</span>',
    "important_escaped": '<span style="display:none !\\69mportant">{c}</span>',
    "class_case_sheet": "<style>.Hide{{display:none}}</style><span class='hIDE'>{c}</span>",
    "id_case_sheet": "<style>#Box{{display:none}}</style><span id='bOX'>{c}</span>",
    "class_escaped_selector": "<style>.\\68 ide{{display:none}}</style><b class='hide'>{c}</b>",
    "cdo_cdc": "<style><!-- .h{{display:none}} --></style><span class='h'>{c}</span>",
    "charset_rule": '<style>@charset "utf-8"; .h{{display:none}}</style><b class="h">{c}</b>',
    "import_rule": "<style>@import url(a.css);.h{{display:none}}</style><b class='h'>{c}</b>",
    "after_at_block": (
        "<style>@media print{{.x{{color:red}}}} .h{{display:none}}</style><b class='h'>{c}</b>"
    ),
    "after_failed_rule": "<style>a;b;.h{{display:none}}</style><b class='h'>{c}</b>",
    "string_with_comment_start": "<span style=\"content:'/*';display:none\">{c}</span>",
    "escaped_comment_start": '<span style="x:\\/* ;display:none;y:z */">{c}</span>',
    "unclosed_comment_style": '<span style="/* display:none">{c}</span>',
    "font_zero_shorthand": '<span style="font:0/0 a">{c}</span>',
    "font_small_shorthand": '<span style="font:italic bold 0px serif">{c}</span>',
    "dialog": "<dialog>{c}</dialog>",
    "datalist": "<datalist><option>{c}</option></datalist>",
    "svg_desc": "<svg><desc>{c}</desc></svg>",
    "svg_defs": "<svg><defs><text>{c}</text></defs></svg>",
    "svg_metadata": "<svg><metadata>{c}</metadata></svg>",
    "padded_display_inline": '<span style="display:' + " " * 5000 + 'none">{c}</span>',
    "padded_font_size": '<span style="font-size:0.' + "0" * 5000 + 'px">{c}</span>',
    "padded_opacity": '<span style="opacity:0.' + "0" * 5000 + '">{c}</span>',
    "padded_display_sheet": "<style>.h{{display:"
    + " " * 20000
    + "none}}</style><b class=h>{c}</b>",
    "soft_child_text_stays_hidden": '<div style="font-size:0">{c}<b>{c}</b></div>',
    "hidden_after_filler_rules": (
        "<style>" + ".f{{color:red}}" * 6000 + ".h{{display:none}}</style><b class=h>{c}</b>"
    ),
    "url_quote_sheet": (
        '<style>.x{{background:url(a"b)}}.h{{display:none}}.y{{background:url(c"d)}}</style>'
        "<b class=h>{c}</b>"
    ),
    "url_quote_same_rule": (
        '<style>.h{{background:url(a"b);display:none;background:url(c"d)}}</style>'
        "<b class=h>{c}</b>"
    ),
    "url_quote_single_sheet": (
        "<style>.h{{background:url(a'b);display:none;background:url(c'd)}}</style>"
        "<b class=h>{c}</b>"
    ),
    "url_escaped_name_sheet": (
        '<style>.h{{background:\\75rl(a"b);display:none;x:\\75 rl(c"d)}}</style><b class=h>{c}</b>'
    ),
    "url_comment_in_body": (
        "<style>.h{{background:url(a/*);display:none;b:c*/d)}}</style><b class=h>{c}</b>"
    ),
    "url_quote_inline": (
        "<span style='background:url(a\"b);display:none;background:url(c\"d)'>{c}</span>"
    ),
    "url_quote_inline_no_hide": "<span style='background:url(a\"b)'>{c}</span>",
    "important_sheet_beats_inline_size": (
        "<style>.h{{font-size:0 !important}}</style><b class=h style='font-size:13px'>{c}</b>"
    ),
    "important_sheet_beats_inline_visibility": (
        "<style>.h{{visibility:hidden !important}}</style>"
        "<b class=h style='visibility:visible'>{c}</b>"
    ),
    "important_sheet_beats_inline_color": (
        "<style>.h{{color:#fff !important}}</style><b class=h style='color:#000'>{c}</b>"
    ),
    "important_sheet_display_vs_inline": (
        "<style>.h{{display:none !important}}</style><b class=h style='display:block'>{c}</b>"
    ),
    "important_inline_display_vs_sheet": (
        "<style>.h{{display:block !important}}</style><b class=h style='display:none'>{c}</b>"
    ),
    "important_earlier_in_list": '<span style="font-size:0 !important;font-size:13px">{c}</span>',
    "important_inherited_by_child": (
        "<style>.h{{font-size:0 !important}}</style>"
        "<div class=h><b style='font-size:0'>{c}</b></div>"
    ),
    "fallback_color_with_image": (
        '<span style="background:#fff url(x.png) no-repeat;color:#fff">{c}</span>'
    ),
    "fallback_color_with_gradient": (
        '<span style="background:linear-gradient(#000,#111) #fff;color:#fff">{c}</span>'
    ),
    "fallback_background_color_and_image": (
        '<span style="background-image:url(x.png);background-color:#fff;color:#fff">{c}</span>'
    ),
    "fallback_on_parent": (
        '<div style="background:#fff url(x.png)"><span style="color:#fff">{c}</span></div>'
    ),
    "fallback_from_sheet": (
        "<style>.h{{background:url(x.png)}}</style>"
        "<span class=h style='background-color:#fff;color:#fff'>{c}</span>"
    ),
    "color_on_parent_bg": (
        '<div style="background:#123456"><span style="color:#123456">{c}</span></div>'
    ),
    "size_exponent_zero": '<span style="font-size:0e0px">{c}</span>',
    "size_exponent_tiny": '<span style="font-size:1e-9px">{c}</span>',
    "size_exponent_unitless_zero": '<span style="font-size:0e0">{c}</span>',
    "opacity_exponent_zero": '<span style="opacity:0e0">{c}</span>',
    "opacity_exponent_tiny": '<span style="opacity:1e-9">{c}</span>',
    "opacity_calc": '<span style="opacity:calc(0)">{c}</span>',
    "opacity_min": '<span style="opacity:min(0,1)">{c}</span>',
    "opacity_percent_zero": '<span style="opacity:0%">{c}</span>',
    "offset_exponent": '<span style="position:absolute;left:-1e9px">{c}</span>',
    "offset_calc": '<span style="position:absolute;left:calc(0px - 9999px)">{c}</span>',
    "indent_min": '<p style="text-indent:min(-5000px,1px)">{c}</p>',
    "size_calc_divide_zero": '<span style="font-size:calc(0px / 0)">{c}</span>',
    "opacity_calc_divide_zero": '<span style="opacity:calc(0/0)">{c}</span>',
    "opacity_calc_nan": '<span style="opacity:calc(nan)">{c}</span>',
    "opacity_calc_percent": '<span style="opacity:calc(0%)">{c}</span>',
    "opacity_calc_small_percent": '<span style="opacity:calc(0.2%)">{c}</span>',
    "size_min_nan_second": '<span style="font-size:min(20px, nan * 1px)">{c}</span>',
    "opacity_min_percent": '<span style="opacity:min(0%,1)">{c}</span>',
    "size_calc_nan": '<span style="font-size:calc(0px * nan)">{c}</span>',
    "size_calc_infinity": '<span style="font-size:calc(-infinity * 1px)">{c}</span>',
    "offset_calc_infinity": (
        '<span style="position:absolute;left:calc(-infinity * 1px)">{c}</span>'
    ),
    "size_webkit_calc": '<span style="font-size:-webkit-calc(0px)">{c}</span>',
    "size_moz_calc": '<span style="font-size:-moz-calc(0px)">{c}</span>',
    "size_round": '<span style="font-size:round(0.4px,1px)">{c}</span>',
    "size_abs": '<span style="font-size:abs(0px)">{c}</span>',
    "opacity_sin": '<span style="opacity:sin(0)">{c}</span>',
    "opacity_round": '<span style="opacity:round(0.2)">{c}</span>',
    "opacity_abs": '<span style="opacity:abs(0)">{c}</span>',
    "font_shorthand_calc_zero": '<span style="font:calc(0px) a">{c}</span>',
    "font_shorthand_unknown_function": '<span style="font:round(1px) a">{c}</span>',
    "visibility_unknown_function": '<span style="visibility:round(1px)">{c}</span>',
    "var_undefined_fallback": '<span style="font-size:var(--undefined, 0px)">{c}</span>',
    "var_declared_zero": '<span style="--z:0px;font-size:var(--z)">{c}</span>',
    "var_unresolved_size": '<span style="font-size:var(--x)">{c}</span>',
    "var_unresolved_opacity": '<span style="opacity:var(--o)">{c}</span>',
    "var_unresolved_visibility": '<span style="visibility:var(--v)">{c}</span>',
    "var_unresolved_offset": '<span style="position:absolute;left:var(--x)">{c}</span>',
    "var_unresolved_display": '<span style="display:var(--d)">{c}</span>',
    "env_opacity": '<span style="opacity:env(x)">{c}</span>',
    "env_size_with_fallback": '<span style="font-size:env(x, 13px)">{c}</span>',
    "var_cycle": '<span style="--a:var(--b);--b:var(--a);font-size:var(--a)">{c}</span>',
    "var_zero_opacity": '<span style="--o:0;opacity:var(--o)">{c}</span>',
    "var_offscreen": '<span style="--l:-9999px;position:absolute;left:var(--l)">{c}</span>',
    "var_hidden_visibility": '<span style="--v:hidden;visibility:var(--v)">{c}</span>',
    "var_clipped_empty_box": ('<div style="overflow:hidden;--h:0;height:var(--h)">{c}</div>'),
    "var_sheet_declares_inline_reads": (
        "<style>.a{{--z:0px}}</style><span class=a style='font-size:var(--z)'>{c}</span>"
    ),
    "var_sheet_reads_inline_declares": (
        "<style>.a{{font-size:var(--z)}}</style><span class=a style='--z:0px'>{c}</span>"
    ),
    "var_sheet_declares_sheet_reads": (
        "<style>.a{{--z:0px}}.b{{font-size:var(--z)}}</style><span class='a b'>{c}</span>"
    ),
    "var_two_style_elements": (
        "<style>.a{{--z:0px}}</style><style>.a{{font-size:var(--z)}}</style>"
        "<span class=a>{c}</span>"
    ),
    "clip_and_zero_box_from_two_rules": (
        "<style>.a{{overflow:hidden}}.b{{height:0}}</style><div class='a b'>{c}</div>"
    ),
    "var_important_beats_inline": (
        "<style>.a{{--z:0px !important}}</style>"
        "<span class=a style='--z:13px;font-size:var(--z)'>{c}</span>"
    ),
    "var_inline_overrides_sheet_into_zero": (
        "<style>.a{{--z:13px;font-size:var(--z)}}</style><span class=a style='--z:0px'>{c}</span>"
    ),
    "var_order_is_unknown_hiding_wins": (
        '<span style="--z:13px;font-size:var(--z);font-size:0">{c}</span>'
    ),
    "size_calc_zero": '<span style="font-size:calc(0px)">{c}</span>',
    "size_min": '<span style="font-size:min(0px,12px)">{c}</span>',
    "size_min_unknown": '<span style="font-size:min(0px,var(--x))">{c}</span>',
    "size_clamp": '<span style="font-size:clamp(0px,0px,0px)">{c}</span>',
    "size_max_zero": '<span style="font-size:max(0px,0px)">{c}</span>',
    "size_calc_product": '<span style="font-size:calc(12px * 0)">{c}</span>',
    "size_calc_difference": '<span style="font-size:calc((2px + 3px) - 5px)">{c}</span>',
    "size_calc_exponent": '<span style="font-size:calc(1e-9px)">{c}</span>',
    "size_calc_too_deep": '<span style="font-size:'
    + "calc(" * 60
    + "12px"
    + ")" * 60
    + '">{c}</span>',
    "clipped_box_calc": '<div style="max-height:calc(0px);overflow:hidden">{c}</div>',
    "cascade_attr_order_hv": (
        "<style>.v{{font-size:14px}}.h{{font-size:0}}</style><span class='h v'>{c}</span>"
    ),
    "cascade_attr_order_vh": (
        "<style>.v{{font-size:14px}}.h{{font-size:0}}</style><span class='v h'>{c}</span>"
    ),
    "cascade_visibility_hv": (
        "<style>.v{{visibility:visible}}.h{{visibility:hidden}}</style><span class='h v'>{c}</span>"
    ),
    "cascade_visibility_vh": (
        "<style>.v{{visibility:visible}}.h{{visibility:hidden}}</style><span class='v h'>{c}</span>"
    ),
    "cascade_tag_class_hv": (
        "<style>span.v{{font-size:14px}}span.h{{font-size:0}}</style><span class='h v'>{c}</span>"
    ),
    "cascade_tag_class_vh": (
        "<style>span.v{{font-size:14px}}span.h{{font-size:0}}</style><span class='v h'>{c}</span>"
    ),
    "cascade_important_hv": (
        "<style>.v{{font-size:14px !important}}.h{{font-size:0 !important}}</style>"
        "<span class='h v'>{c}</span>"
    ),
    "cascade_important_vh": (
        "<style>.v{{font-size:14px !important}}.h{{font-size:0 !important}}</style>"
        "<span class='v h'>{c}</span>"
    ),
    "cascade_across_style_elements": (
        "<style>.v{{font-size:14px}}</style><style>.h{{font-size:0}}</style>"
        "<span class='h v'>{c}</span>"
    ),
    "cascade_class_beats_tag": (
        "<style>.h{{font-size:0}}span{{font-size:14px}}</style><span class=h>{c}</span>"
    ),
    "cascade_id_beats_class": (
        "<style>#i{{font-size:0}}.v{{font-size:14px}}</style><span id=i class=v>{c}</span>"
    ),
    "cascade_parent_class_child_two_classes": (
        "<style>.v{{font-size:14px}}.h{{font-size:0}}</style>"
        "<div class='h'><b class='h v'>{c}</b></div>"
    ),
    "cascade_important_sheet_beats_later_normal": (
        "<style>.h{{font-size:0 !important}}.v{{font-size:14px}}</style>"
        "<span class='v h'>{c}</span>"
    ),
    "cascade_later_rule_same_class": (
        "<style>.h{{font-size:14px}}.v{{font-size:14px}}.h{{font-size:0}}</style>"
        "<span class='v h'>{c}</span>"
    ),
    "transparent_bg_no_coloured_ancestor": (
        '<span style="background:transparent;color:#fff">{c}</span>'
    ),
    "uniform_gradient": '<span style="background:linear-gradient(#fff,#fff);color:#fff">{c}</span>',
    "uniform_gradient_stops_and_positions": (
        '<span style="background:linear-gradient(to right,white 0%,#ffffff 50%,rgb(255,255,255));'
        'color:#fff">{c}</span>'
    ),
    "uniform_gradient_image": (
        '<span style="background-image:radial-gradient(circle at 50% 50%,#fff,#fff);'
        'color:#fff">{c}</span>'
    ),
    "uniform_gradient_on_parent": (
        '<div style="background-image:linear-gradient(white,white)">'
        '<span style="color:white">{c}</span></div>'
    ),
    "empty_background_attribute": '<td background="" style="color:#fff">{c}</td>',
    "blank_background_attribute": '<td background="  " style="color:#fff">{c}</td>',
    "blank_background_attribute_with_bgcolor": (
        "<table><tr><td background=' ' bgcolor=#fff><font color=#fff>{c}</font></td></tr></table>"
    ),
    "fallback_with_background_attribute": (
        '<table><tr><td bgcolor="#fff" background="https://example.com/b.png">'
        '<font color="#fff">{c}</font></td></tr></table>'
    ),
}

# A relative, inherited or unrecognised child value must never clear a hiding parent (T-04).
INHERITED_HIDDEN_VECTORS = {
    "size_em": '<span style="font-size:0"><span style="font-size:1em">{c}</span></span>',
    "size_percent": '<span style="font-size:0"><span style="font-size:100%">{c}</span></span>',
    "size_10em": '<span style="font-size:0"><span style="font-size:10em">{c}</span></span>',
    "size_shorthand_em": '<span style="font-size:0"><span style="font:1em a">{c}</span></span>',
    "size_shorthand_2em": '<span style="font-size:0px"><b style="font:2em Arial">{c}</b></span>',
    "size_rem": '<span style="font-size:0"><span style="font-size:1rem">{c}</span></span>',
    "size_ex": '<span style="font-size:0"><span style="font-size:1ex">{c}</span></span>',
    "size_ch": '<span style="font-size:0"><span style="font-size:1ch">{c}</span></span>',
    "size_vw": '<span style="font-size:0"><span style="font-size:5vw">{c}</span></span>',
    "size_larger": '<span style="font-size:0"><span style="font-size:larger">{c}</span></span>',
    "size_inherit": '<span style="font-size:0"><span style="font-size:inherit">{c}</span></span>',
    "size_unset": '<span style="font-size:0"><span style="font-size:unset">{c}</span></span>',
    "size_calc": '<span style="font-size:0"><b style="font-size:calc(1px+1em)">{c}</b></span>',
    "size_var": '<span style="font-size:0"><span style="font-size:var(--s)">{c}</span></span>',
    "size_unitless": '<span style="font-size:0"><span style="font-size:12">{c}</span></span>',
    "size_garbage": '<span style="font-size:0"><span style="font-size:bogus">{c}</span></span>',
    "size_trailing_dot": '<span style="font-size:0"><b style="font-size:12.px">{c}</b></span>',
    "font_shorthand_13px": '<span style="font-size:0"><b style="font:13px Arial">{c}</b></span>',
    "font_shorthand_full": (
        '<span style="font-size:0"><b style="font:italic bold 14px/1.5 a">{c}</b></span>'
    ),
    "font_shorthand_keyword": '<span style="font-size:0"><b style="font:large a">{c}</b></span>',
    "font_shorthand_initial": '<span style="font-size:0"><b style="font:initial">{c}</b></span>',
    "font_shorthand_spaced_line_height": (
        '<span style="font-size:0"><b style="font:12px / 1.5 Arial">{c}</b></span>'
    ),
    "font_no_family": '<span style="font-size:0"><b style="font:12px">{c}</b></span>',
    "font_keyword_no_family": '<span style="font-size:0"><b style="font:large">{c}</b></span>',
    "font_unknown_prefix": '<span style="font-size:0"><b style="font:bogus 12px a">{c}</b></span>',
    "font_initial_with_family": (
        '<span style="font-size:0"><b style="font:initial a">{c}</b></span>'
    ),
    "font_no_family_line_height": (
        '<span style="font-size:0"><b style="font:12px/1.5">{c}</b></span>'
    ),
    "font_tiny_size_in_invalid_shorthand": '<b style="font:bogus 0 a">{c}</b>',
    "size_calc_under_tiny": (
        '<span style="font-size:0"><b style="font-size:calc(12px)">{c}</b></span>'
    ),
    "size_max_under_tiny": (
        '<span style="font-size:0"><b style="font-size:max(12px,1px)">{c}</b></span>'
    ),
    "size_calc_var_top_level_then_zero": '<b style="font-size:12px;font-size:calc(0px)">{c}</b>',
    "size_sheet_em": ('<style>b{{font-size:1em}}</style><div style="font-size:0"><b>{c}</b></div>'),
    "size_sheet_absolute_then_inline_em": (
        "<style>.a{{font-size:12px}}</style>"
        '<div style="font-size:0"><b class=a style="font-size:1em">{c}</b></div>'
    ),
    "size_same_element_absolute_then_em": (
        '<div style="font-size:0"><b style="font-size:12px;font-size:1em">{c}</b></div>'
    ),
    "size_same_element_zero_then_garbage": '<b style="font-size:0;font-size:bogus">{c}</b>',
    "size_important_garbage": ('<b style="font-size:0;font-size:bogus !important">{c}</b>'),
    "visibility_inherit": (
        '<div style="visibility:hidden"><b style="visibility:inherit">{c}</b></div>'
    ),
    "visibility_unset": '<div style="visibility:hidden"><b style="visibility:unset">{c}</b></div>',
    "visibility_revert": (
        '<div style="visibility:hidden"><b style="visibility:revert">{c}</b></div>'
    ),
    "visibility_invalid": (
        '<div style="visibility:hidden"><b style="visibility:bogus">{c}</b></div>'
    ),
    "visibility_sheet_visible_then_inline_inherit": (
        "<style>.v{{visibility:visible}}</style>"
        '<div style="visibility:hidden"><b class=v style="visibility:inherit">{c}</b></div>'
    ),
    "visibility_hidden_then_garbage": '<b style="visibility:hidden;visibility:bogus">{c}</b>',
}


@pytest.mark.parametrize("name", sorted({**HIDDEN_VECTORS, **INHERITED_HIDDEN_VECTORS}))
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
        '<div style="font-size:0"><div style="font-size:13px">{c}</div></div>',
        '<div style="font:0/0 a"><div style="font-size:14px">{c}</div></div>',
        '<div style="visibility:hidden"><span style="visibility:visible">{c}</span></div>',
        '<div style="visibility:hidden"><span style="visibility:initial">{c}</span></div>',
        '<div style="font-size:0"><span style="font-size:large">{c}</span></div>',
        '<div style="font-size:0"><span style="font-size:13px">{c}</span></div>',
        '<div style="font-size:0"><span style="font-size:1e1px">{c}</span></div>',
        '<span style="font-size:1em">{c}</span>',
        '<span style="font-size:1ex">{c}</span>',
        '<span style="font-size:calc(12px)">{c}</span>',
        '<span style="font-size:clamp(14px,2vw,18px)">{c}</span>',
        '<span style="font-size:calc(min(0px, 1%) * -1)">{c}</span>',
        '<span style="color:var(--x)">{c}</span>',
        '<span style="padding:var(--x);margin:var(--m)">{c}</span>',
        '<span style="background:var(--b, #000);color:#000">{c}</span>',
        '<span style="--font-size:0;--opacity:0;font-size:12px">{c}</span>',
        '<span style="padding-left:env(safe-area-inset-left)">{c}</span>',
        '<span style="font-size:calc(1em+2px)">{c}</span>',
        '<span style="font-size:-webkit-calc(12px)">{c}</span>',
        '<span style="font:calc(12px) a">{c}</span>',
        '<span style="font:clamp(14px,2vw,18px) Arial">{c}</span>',
        '<span style="opacity:calc(50%)">{c}</span>',
        '<span style="opacity:calc(0.5)">{c}</span>',
        '<span style="font-size:max(12px,0px)">{c}</span>',
        '<span style="font-size:clamp(10px,1em,20px)">{c}</span>',
        '<span style="font-size:calc(1em + 2px)">{c}</span>',
        '<span style="opacity:1e-1">{c}</span>',
        '<span style="opacity:calc(1)">{c}</span>',
        '<span style="opacity:50%">{c}</span>',
        '<span style="position:absolute;left:-1e2px">{c}</span>',
        '<span style="position:absolute;left:calc(1px - 99px)">{c}</span>',
        '<div style="font-size:0"><span style="font-size:12pt">{c}</span></div>',
        '<div style="font-size:0"><span style="font-size:0.2in">{c}</span></div>',
        '<div style="font-size:0"><span style="font-size:initial">{c}</span></div>',
        '<td style="font-size:0"><span style="font-size:12px;font-size:13px">{c}</span></td>',
        '<style>.a{{font-size:12px}}</style><div style="font-size:0"><b class=a>{c}</b></div>',
        '<td background="https://example.com/b.png" style="color:#fff">{c}</td>',
        "<style>.h{{font-size:0}}.v{{font-size:14px}}</style><span class='h v'>{c}</span>",
        "<style>.h{{font-size:0}}.v{{font-size:14px}}</style><span class='v h'>{c}</span>",
        "<style>.h{{visibility:hidden}}.v{{visibility:visible}}</style>"
        "<span class='v h'>{c}</span>",
        "<style>span.h{{font-size:0}}span.v{{font-size:14px}}</style><span class='v h'>{c}</span>",
        "<style>.h{{font-size:0}}.v{{font-size:14px}}</style>"
        "<div class=h><b class='h v'>{c}</b></div>",
        "<style>.h{{font-size:0}}#i{{font-size:14px}}</style><span id=i class=h>{c}</span>",
        "<style>span{{font-size:0}}.v{{font-size:14px}}</style><span class=v>{c}</span>",
        "<style>.h{{font-size:0 !important}}.v{{font-size:14px !important}}</style>"
        "<span class='h v'>{c}</span>",
        "<style>.v{{font-size:14px !important}}.h{{font-size:0}}</style>"
        "<span class='h v'>{c}</span>",
        '<span style="background:linear-gradient(#fff,#000);color:#fff">{c}</span>',
        '<span style="background:linear-gradient(#fff,#fff),url(x.png);color:#fff">{c}</span>',
        '<span style="background:linear-gradient(#fff,blue);color:#fff">{c}</span>',
        '<span style="background:linear-gradient(#fff,transparent);color:#fff">{c}</span>',
        '<div style="color:#fff"><span style="color:#000">{c}</span></div>',
        '<div style="background:#000">'
        '<span style="background:transparent;color:#fff">{c}</span></div>',
        '<span style="background:url(x.png);color:#fff">{c}</span>',
        '<span style="background:linear-gradient(#000,#111);color:#fff">{c}</span>',
        '<table bgcolor="#000"><tr><td><font color="#fff">{c}</font></td></tr></table>',
        "<dialog open>{c}</dialog>",
        "<style>.f{{color:red}}</style><b class='f'>{c}</b>",
        "<span style=\"background:url('a;b.png');color:red\">{c}</span>",
        "<span style=\"background:url( 'x.png' );color:red\">{c}</span>",
        "<style>.h{{background:url(a.png)}}.k{{display:none}}</style><b class=h>{c}</b>",
        "<style>.h{{font-size:0}}</style><b class=h style='font-size:13px !important'>{c}</b>",
        "<style>.h{{font-size:0 !important}}</style>"
        "<b class=h style='font-size:13px !important'>{c}</b>",
        "<style>.h{{color:#fff}}</style><b class=h style='color:#000 !important'>{c}</b>",
        '<span style="font-size:0 !important;font-size:13px !important">{c}</span>',
        '<span style="font-size:13px !important;font-size:0">{c}</span>',
        '<span style="background:#000 url(x.png);color:#fff">{c}</span>',
        '<span style="background:url(x.png) #000;color:#fff">{c}</span>',
        "<style>.h{{background:#000 !important}}</style>"
        "<b class=h style='background:#fff;color:#fff'>{c}</b>",
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

    entered: list[int] = []
    original_enter = html_module._enter

    def count_enter(*args: Any) -> None:
        entered.append(1)
        original_enter(*args)

    monkeypatch.setattr(html_module, "_walk", spy)
    monkeypatch.setattr(html_module, "_enter", count_enter)
    result = html_to_text("<p>x</p>" * 200_000, limits=limits)
    assert result.truncated
    assert NOTE_LIMIT_BODY in result.notes
    assert len(result.text) <= 100
    assert walked and walked[0] <= 3 * 100 + 3
    assert len(entered) < 1000


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
    st.sampled_from(sorted({**HIDDEN_VECTORS, **INHERITED_HIDDEN_VECTORS})),
    st.lists(st.sampled_from(["<p>x</p>", "text ", "<br>", "<div>", "</div>", "<b>"]), max_size=8),
    st.lists(st.sampled_from(["<p>y</p>", " more", "<br>", "</b>", "<td>"]), max_size=8),
)
def test_fuzz_hidden_canary_never_survives(
    vector: str, before: list[str], after: list[str]
) -> None:
    document = "<html><body>" + "".join(before) + _vector(vector) + "".join(after)
    assert CANARY not in html_to_text(document).text


# An oracle written apart from css.py: under a hiding parent only these child values show text.
_ORACLE_PX = {"px": 1.0, "pt": 4 / 3, "pc": 16.0, "cm": 96 / 2.54, "mm": 96 / 25.4, "in": 96.0}
_ORACLE_PX["q"] = 96 / 101.6
_ORACLE_KEYWORDS = {
    *("xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "xxx-large"),
    "initial",
}
_NUMBER_TEXT = re.compile(r"(\d*\.?\d+(?:e[+-]?\d+)?)([a-z%]*)")


def _oracle_size_clears(value: str) -> bool:
    if value in _ORACLE_KEYWORDS:
        return True
    match = _NUMBER_TEXT.fullmatch(value)
    if match is None or match.group(2) not in _ORACLE_PX:
        return False
    return float(match.group(1)) * _ORACLE_PX[match.group(2)] > 4 / 3


_numbers = st.sampled_from(
    ["0", "0.5", "1", "1.5", "2", "12", "13.5", "100", "0.0001", "-1", "0e0", "1e-9", "1e1", "2e0"]
)
_units = st.sampled_from(
    ["", "px", "pt", "pc", "cm", "mm", "in", "q", "em", "%", "ex", "ch", "rem", "vw", "vh", "fr"]
)
_size_values = st.one_of(
    st.builds(lambda n, u: n + u, _numbers, _units),
    st.sampled_from(sorted(_ORACLE_KEYWORDS | {"larger", "smaller", "inherit", "unset", "revert"})),
    st.sampled_from(["calc(1px+1em)", "var(--s)", "env(x)", "min(1px,1em)", "clamp(1px,1em,2px)"]),
    st.sampled_from(
        ["calc(0px)", "calc(12px)", "min(0px,12px)", "max(12px,0px)", "clamp(0px,0px,0px)"]
    ),
    st.from_regex(r"[a-z0-9%.()-]{1,12}", fullmatch=True),
)
_visibility_values = st.one_of(
    st.sampled_from(["visible", "hidden", "collapse", "initial", "inherit", "unset", "revert"]),
    st.from_regex(r"[a-z-]{1,10}", fullmatch=True),
)


def _child(css: str, where: str) -> str:
    if where == "inline":
        return f'<b style="{css}">{CANARY}</b>'
    return f"<style>b{{{css}}}</style><b>{CANARY}</b>"


_font_tokens = st.one_of(
    _size_values,
    st.sampled_from(
        ["italic", "bold", "700", "small-caps", "/", "/1.5", "1.5", "a", "Arial,", "initial"]
    ),
)
_font_shorthands = st.lists(_font_tokens, min_size=1, max_size=6).map(" ".join)


@FUZZ
@given(_font_shorthands, st.sampled_from(["inline", "sheet"]))
def test_fuzz_tiny_parent_is_never_cleared_by_the_font_shorthand(
    shorthand: str, where: str
) -> None:
    result = html_to_text(f'<div style="font-size:0">{_child(f"font:{shorthand}", where)}</div>')
    assert result.text == ""
    assert NOTE_HIDDEN in result.notes


@FUZZ
@given(_size_values, st.sampled_from(["inline", "sheet"]))
def test_fuzz_tiny_parent_only_an_allowlisted_size_clears(value: str, where: str) -> None:
    result = html_to_text(f'<div style="font-size:0">{_child(f"font-size:{value}", where)}</div>')
    if _oracle_size_clears(value):
        assert result.text == CANARY
    else:
        assert result.text == ""
        assert NOTE_HIDDEN in result.notes


@FUZZ
@given(_visibility_values, st.sampled_from(["inline", "sheet"]))
def test_fuzz_hidden_parent_only_visible_or_initial_clears(value: str, where: str) -> None:
    result = html_to_text(
        f'<div style="visibility:hidden">{_child(f"visibility:{value}", where)}</div>'
    )
    if value in ("visible", "initial"):
        assert result.text == CANARY
    else:
        assert result.text == ""
        assert NOTE_HIDDEN in result.notes


@FUZZ
@given(_size_values, st.booleans())
def test_fuzz_same_element_only_an_allowlisted_size_overrides_an_earlier_zero(
    value: str, tiny_parent: bool
) -> None:
    child = f'<b style="font-size:0;font-size:{value}">{CANARY}</b>'
    html = f'<div style="font-size:0">{child}</div>' if tiny_parent else child
    assert (html_to_text(html).text == CANARY) == _oracle_size_clears(value)


_leaf = st.sampled_from([-2000, -1000, -5, 0, 1, 2, 3, 12, 20]).map(lambda n: (f"{n}px", n))


def _extend(children: st.SearchStrategy[tuple[str, int]]) -> st.SearchStrategy[tuple[str, int]]:
    pair = st.tuples(children, children)
    triple = st.tuples(children, children, children)
    return st.one_of(
        pair.map(lambda t: (f"({t[0][0]} + {t[1][0]})", t[0][1] + t[1][1])),
        pair.map(lambda t: (f"({t[0][0]} - {t[1][0]})", t[0][1] - t[1][1])),
        st.tuples(children, st.sampled_from([-1, 0, 2, 3])).map(
            lambda t: (f"({t[0][0]} * {t[1]})", t[0][1] * t[1])
        ),
        pair.map(lambda t: (f"min({t[0][0]}, {t[1][0]})", min(t[0][1], t[1][1]))),
        pair.map(lambda t: (f"max({t[0][0]}, {t[1][0]})", max(t[0][1], t[1][1]))),
        triple.map(
            lambda t: (
                f"clamp({t[0][0]}, {t[1][0]}, {t[2][0]})",
                max(t[0][1], min(t[1][1], t[2][1])),
            )
        ),
    )


_constants = st.recursive(_leaf, _extend, max_leaves=6)


@FUZZ
@given(_constants)
def test_fuzz_constant_math_hides_exactly_below_the_thresholds(expr: tuple[str, int]) -> None:
    text, value = expr
    size = html_to_text(f'<span style="font-size:calc({text})">{CANARY}</span>')
    assert (size.text == "") == (value <= 4 / 3)
    offset = html_to_text(f'<span style="position:absolute;left:calc({text})">{CANARY}</span>')
    assert (offset.text == "") == (value <= -1000)


_FUNCTION_NAMES = st.one_of(
    st.sampled_from(
        ["round", "abs", "sign", "sin", "cos", "tan", "mod", "rem", "pow", "hypot", "log", "exp"]
    ),
    st.from_regex(r"[a-z][a-z0-9]{0,8}", fullmatch=True).filter(
        lambda name: name not in {"calc", "min", "max", "clamp", "var", "env"}
    ),
)
_HIDING_DECLARATIONS = [
    "font-size:{f}",
    "font:{f} a",
    "opacity:{f}",
    "visibility:{f}",
    "position:absolute;left:{f}",
    "text-indent:{f}",
]


@FUZZ
@given(
    _FUNCTION_NAMES,
    st.sampled_from(["0", "1px", "0.5", "50%", "1, 2", "calc(1px)"]),
    st.sampled_from(_HIDING_DECLARATIONS),
    st.sampled_from(["", "-webkit-"]),
)
def test_fuzz_unknown_function_in_a_hiding_property_fails_closed(
    name: str, arguments: str, declaration: str, prefix: str
) -> None:
    css = declaration.replace("{f}", f"{prefix}{name}({arguments})")
    result = html_to_text(f'<p>a</p><span style="{css}">{CANARY}</span>')
    assert result.text == "a"
    assert NOTE_HIDDEN in result.notes


_VARIABLE_FORMS = [
    "var(--u)",
    "var(--z)",
    "var(--u, {fallback})",
    "var(--z, {fallback})",
    "var(--u, var(--z, {fallback}))",
    "env(x)",
    "env(safe-area-inset-left, {fallback})",
    "VAR(--U)",
]
_VARIABLE_POSITIONS = [
    "{f}",
    "calc({f} + 1px)",
    "calc(20px - {f})",
    "min(20px, {f})",
    "max(20px, {f})",
    "clamp(1px, {f}, 20px)",
    "calc(calc({f}))",
]
_HIDING_PROPERTIES = [
    "font-size:{v}",
    "font:{v} a",
    "font:12px/{v} a",
    "font:italic 12px a, {v}",
    "visibility:{v}",
    "opacity:{v}",
    "display:{v}",
    "mso-hide:{v}",
    "clip-path:{v}",
    "position:absolute;left:{v}",
    "margin-left:{v}",
    "text-indent:{v}",
    "overflow:{v};height:0",
    "overflow:hidden;height:{v}",
]


@FUZZ
@given(
    st.sampled_from(_HIDING_PROPERTIES),
    st.sampled_from(_VARIABLE_FORMS),
    st.sampled_from(_VARIABLE_POSITIONS),
    st.sampled_from(["0px", "13px", "0", "1", "none", "visible", "block", "1em", ""]),
    st.sampled_from(["", "--z:13px;", "--u:0px;--z:13px;", "--z:var(--z);"]),
    st.booleans(),
    st.booleans(),
)
def test_fuzz_any_variable_read_in_a_hiding_property_hides(
    declaration: str,
    form: str,
    position: str,
    fallback: str,
    custom: str,
    sheet: bool,
    tiny_parent: bool,
) -> None:
    value = position.replace("{f}", form.replace("{fallback}", fallback))
    css = custom + declaration.replace("{v}", value)
    if sheet:
        child = f"<style>b{{{css}}}</style><b>{CANARY}</b>"
    else:
        child = f'<b style="{css}">{CANARY}</b>'
    html = f'<div style="font-size:0">{child}</div>' if tiny_parent else child
    result = html_to_text(f"<p>a</p>{html}")
    assert result.text == "a"
    assert NOTE_HIDDEN in result.notes


# One fixed sheet, in source order: (selector, specificity, size, important)
_CASCADE_RULES = [
    ("span", 1, "14px", False),
    (".a", 10, "14px", False),
    (".b", 10, "0", False),
    (".c", 10, "14px", False),
    (".d", 10, "0", False),
    ("span.a", 11, "0", False),
    ("#i", 100, "14px", False),
    (".e", 10, "14px", True),
    (".f", 10, "0", True),
    (".b", 10, "14px", False),
    ("span", 1, "0", False),
]
_CASCADE_SHEET = (
    "<style>"
    + "".join(
        f"{selector}{{font-size:{size}{' !important' if important else ''}}}"
        for selector, _, size, important in _CASCADE_RULES
    )
    + "</style>"
)


def _cascade_shows(classes: list[str], ident: bool) -> bool:
    """The browser result: the winner by importance, specificity, then source position."""

    def matches(selector: str) -> bool:
        if selector == "span":
            return True
        if selector == "#i":
            return ident
        name = selector.removeprefix("span").removeprefix(".")
        return name in classes

    winner = max(
        (
            (important, specificity, position, size)
            for position, (selector, specificity, size, important) in enumerate(_CASCADE_RULES)
            if matches(selector)
        ),
        default=(False, 0, 0, "14px"),
    )
    return winner[3] != "0"


@FUZZ
@given(
    st.lists(st.sampled_from(list("abcdef")), unique=True, max_size=6),
    st.booleans(),
)
def test_fuzz_class_attribute_order_never_changes_the_cascade(
    classes: list[str], ident: bool
) -> None:
    attributes = (f"class='{' '.join(classes)}'" if classes else "") + (" id=i" if ident else "")
    result = html_to_text(f"{_CASCADE_SHEET}<span {attributes}>{CANARY}</span>")
    assert (result.text == CANARY) == _cascade_shows(classes, ident)


@FUZZ
@given(st.text(max_size=300))
def test_fuzz_plain_body_stripping(text: str) -> None:
    result = strip_body_text(text, Limits(max_body_chars=100))
    assert len(result.text) <= 100
    assert not any(_is_format(c) for c in result.text)


# --- controls and adversarial CSS ------------------------------------------------------------

CONTROL_CHARS = [chr(c) for c in (*range(0x20), *range(0x7F, 0xA0)) if chr(c) not in "\t\n\r"]


def test_controls_are_replaced_in_html_text() -> None:
    esc = chr(0x1B)
    raw = (
        f"<p>a{esc}[31mred{chr(0x9B)}b{chr(0x85)}c{chr(0x07)}d</p>"
        "<p>e&#x9b;f&#133;g&#27;h&#x7f;i</p>"
    )
    result = html_to_text(raw)
    assert not set(result.text) & set(CONTROL_CHARS)
    assert "a [31mred b c d" in result.text
    assert NOTE_FORMAT in result.notes


def test_controls_are_replaced_in_plain_bodies() -> None:
    result = strip_body_text(f"line{chr(0x1B)}[2J\r\nnext{chr(0x9B)}x\tend")
    assert result.text == "line [2J\r\nnext x\tend"
    assert not set(result.text) & set(CONTROL_CHARS)
    assert NOTE_FORMAT in result.notes
    assert strip_body_text("a\tb\r\nc").notes == ()


@pytest.mark.parametrize("char", CONTROL_CHARS)
def test_each_control_is_replaced(char: str) -> None:
    assert char not in _text(f"<p>x{char}y</p>")
    assert char not in strip_body_text(f"x{char}y").text


ADVERSARIAL_CSS = {
    "unclosed_comments": "/*a" * 400_000,
    "unclosed_comment_tail": "a:b;" * 100_000 + "/*a" * 200_000,
    "star_runs": "/*" + "*" * 1_000_000,
    "digits": "font-size:" + "1" * 1_000_000,
    "dots": "font-size:" + "1." * 400_000 + "x",
    "paren_runs": "color:rgb(" + "(" * 1_000_000,
    "close_parens": "background:" + ") " * 400_000,
    "spaces_in_parens": "background:#fff " + "( " * 300_000 + "red",
    "rgb_digits": "color:rgb(" + "1," * 300_000 + ")",
    "escapes": "color:" + "\\" * 500_000,
    "semicolons": ";" * 1_000_000,
    "colons": ":" * 1_000_000,
    "url_opens": "background:" + "url(" * 300_000,
    "url_quotes": 'background:url(a"b);' * 60_000,
    "url_escaped_names": "\\75rl(" * 150_000,
    "important_runs": "color:red " + "! " * 400_000 + "important",
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_CSS))
def test_adversarial_css_is_linear(name: str) -> None:
    css = ADVERSARIAL_CSS[name]
    documents = (
        f'<span style="{css}">{CANARY}</span>',
        f"<style>.a{{{css}}}</style><p class=a>{CANARY}</p>",
        f"<style>{css}</style>{CANARY}",
    )
    started = time.monotonic()
    for document in documents:
        html_to_text(document)
    assert time.monotonic() - started < 1.0


def test_unclosed_comment_fails_closed() -> None:
    for style in ("display:none /*", "color:red /*", "/* display:none", "a:b;/*"):
        result = html_to_text(f'<span style="{style}">{CANARY}</span>')
        assert CANARY not in result.text
        assert NOTE_HIDDEN in result.notes


def test_quote_inside_an_unquoted_url_fails_closed_inline() -> None:
    result = html_to_text(f"<p>a</p><span style='background:url(a\"b)'>{CANARY}</span>")
    assert result.text == "a"
    assert NOTE_HIDDEN in result.notes
    quoted = html_to_text(f"<span style='background:url(\"a.png\")'>{CANARY}</span>")
    assert quoted.text == CANARY
    assert NOTE_HIDDEN not in quoted.notes


def test_unclosed_comment_in_a_stylesheet_ends_the_sheet_like_a_browser() -> None:
    html = f"<style>.h{{display:none}} /* .k{{display:none}}</style><b class=k>{CANARY}</b>"
    assert _text(html) == CANARY


def test_oversized_inline_style_fails_closed_with_a_note() -> None:
    harmless = "color:red;" * 1000
    assert len(harmless) > html_module._MAX_STYLE_CHARS
    result = html_to_text(f'<p>a</p><span style="{harmless}">{CANARY}</span>')
    assert result.text == "a"
    assert NOTE_HIDDEN in result.notes
    short = html_to_text(f'<span style="{"color:red;" * 100}">{CANARY}</span>')
    assert short.text == CANARY
    assert NOTE_HIDDEN not in short.notes


def test_many_filler_rules_do_not_hide_the_hiding_rule() -> None:
    css = ".f{color:red}" * 10_000 + ".h{display:none}"
    assert CANARY not in _text(f"<style>{css}</style><b class=h>{CANARY}</b>")


def test_soft_hidden_text_is_noted_and_overridable_per_child() -> None:
    html = f'<div style="font-size:0">{CANARY}<b style="font-size:12px">shown</b></div>'
    result = html_to_text(html)
    assert result.text == "shown"
    assert NOTE_HIDDEN in result.notes


def test_tail_of_a_soft_hidden_element_uses_the_parents_state() -> None:
    html = '<p>a<span style="font-size:0">X</span>b</p>'
    assert _text(html) == "ab"
    assert _text('<div style="font-size:0"><i></i>X</div>') == ""


def test_hidden_link_and_image_are_not_emitted() -> None:
    html = (
        '<div style="font-size:0"><a href="https://example.com/x">t</a>'
        '<img alt="alt text"></div>shown'
    )
    assert _text(html) == "shown"


def test_nesting_limit_is_reported() -> None:
    result = html_to_text("<font>" * 300 + "tail text")
    assert result.truncated
    assert NOTE_NESTING in result.notes
    assert NOTE_LIMIT_BODY not in result.notes
    assert html_to_text("<font>" * 100 + "tail text").notes == ()


def test_variation_selectors_are_stripped() -> None:
    vs16, heart = chr(0xFE0F), chr(0x2764)
    hidden = "".join(chr(0xE0100 + n) for n in (1, 2, 3))
    assert strip_invisible(f"a{hidden}b") == ("ab", True)
    assert strip_invisible(f"a{chr(0xFE00)}{chr(0xFE01)}b")[0] == "ab"
    assert strip_invisible(f"a{chr(0xFE01)}b")[0] == "ab"
    assert strip_invisible(f"a{vs16}{vs16}b")[0] == "ab"
    assert strip_invisible(f"{heart}{vs16} ok") == (f"{heart}{vs16} ok", False)
    assert strip_invisible(f" {vs16}x")[0] == " x"
    assert strip_format(f"a{hidden}b") == (f"a{hidden}b", False)
