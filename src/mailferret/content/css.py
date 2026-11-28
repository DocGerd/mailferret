"""The small CSS subset that decides whether mail text is shown (T-04).

Pure and linear in the input: comments, strings and escapes are scanned once with regexes whose
alternatives cannot overlap, and no value is skipped for being long. Only what hides text is
understood: ``display``, ``visibility``, ``opacity``, font size, text and background colour,
clipping, off-screen positioning, plus single tag, class, id or ``tag.class`` rules from
stylesheets. Everything else is ignored.

Cascade: for the inherited properties an ``!important`` declaration beats a normal one from any
origin, otherwise the later wins; ``display`` and the other subtree-hiding properties are an OR,
so a conflict hides. An unquoted ``url(`` is one token (CSS Syntax 4.3.6); a quote inside it, or an
unclosed comment, or an escape inside a function name, makes the caller treat the element as
hidden. Input is preprocessed first (CR, CRLF and FF become LF). A background image with a known
fallback colour is compared by that colour; with none the backdrop is unknown and text is kept.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

Color = tuple[int, int, int]
# None: not declared. "transparent": fully transparent. "image": an image or gradient (unknown).
ColorValue = Color | str | None

_ESCAPE: Final = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?|\\(.)", re.DOTALL)
# An unquoted ``url(`` (the name may be escaped) runs to ``)``; quotes inside are not strings
# (CSS Syntax 4.3.6). Without this a quote inside it would hide the declarations that follow.
_URL: Final = (
    r"(?:[uU]|\\0{0,4}[57]5[ \t\n]?)(?:[rR]|\\0{0,4}[57]2[ \t\n]?)"
    r"(?:[lL]|\\0{0,4}[46][cC][ \t\n]?)\((?![ \t\r\n\f]*[\"'])(?:[^)\\]|\\.)*\)?"
)
_SKIPPED: Final = _URL + r"""|\\.|"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?"""
_IDENT_RUN: Final = re.compile(r"(?:[\w-]|\\(?:[0-9a-fA-F]{1,6}[ \t\n]?|.))+", re.DOTALL)
_URL_BODY: Final = re.compile(r"url\((?![ \t\r\n\f]*[\"'])([^)]*)\)?")
_COMMENT_SCAN: Final = re.compile(_SKIPPED + r"|/\*", re.DOTALL)
_STRUCTURE: Final = re.compile(_SKIPPED + r"|[(){};]", re.DOTALL)
_NUMBER: Final = re.compile(r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))([a-z%]*)")
_SIMPLE_SELECTOR: Final = re.compile(r"([a-z][a-z0-9]*)?(?:([.#])([a-z_][\w-]*))?")
_HEX_COLOR: Final = re.compile(r"#([0-9a-f]{3,8})")
_RGB_COLOR: Final = re.compile(
    r"rgba?\(\s*([\d.]+%?)[\s,]+([\d.]+%?)[\s,]+([\d.]+%?)(?:[\s,/]+([\d.]+%?))?\s*\)"
)
_NAMED_COLORS: Final = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "red": (255, 0, 0),
    "yellow": (255, 255, 0),
    "silver": (192, 192, 192),
    "gray": (128, 128, 128),
}
_FAR: Final = 1000.0
_OFFSET_PROPERTIES: Final = frozenset(
    {"left", "right", "top", "bottom", "text-indent", "margin-left"}
)
_SIZE_PROPERTIES: Final = frozenset({"height", "max-height", "width", "max-width"})
_CLIPPING: Final = frozenset({"hidden", "clip"})

Declarations = list[tuple[str, str, bool]]  # name, value, !important


@dataclass(frozen=True, slots=True)
class Props:
    """Inherited properties of one importance level; ``None`` means not declared."""

    tiny: bool | None = None  # the text is too small to read
    invisible: bool | None = None  # visibility is hidden or collapse
    color: ColorValue = None  # text colour
    background: ColorValue = None  # the known (fallback) colour, never "transparent"
    image: bool = False  # a background image or gradient

    def merge(self, later: Props) -> Props:
        return Props(
            self.tiny if later.tiny is None else later.tiny,
            self.invisible if later.invisible is None else later.invisible,
            self.color if later.color is None else later.color,
            self.background if later.background is None else later.background,
            self.image or later.image,
        )


@dataclass(frozen=True, slots=True)
class Style:
    """What declarations say about visibility; an important value beats a normal one.

    ``hidden`` is an OR over every origin and importance, so a conflict hides rather than
    shows. The inherited properties follow the cascade: important first, then the later one.
    """

    hidden: bool = False  # the whole subtree is gone, whatever its children declare
    normal: Props = Props()
    important: Props = Props()

    def merge(self, later: Style) -> Style:
        return Style(
            self.hidden or later.hidden,
            self.normal.merge(later.normal),
            self.important.merge(later.important),
        )

    @property
    def tiny(self) -> bool | None:
        return self.normal.tiny if self.important.tiny is None else self.important.tiny

    @property
    def invisible(self) -> bool | None:
        value = self.important.invisible
        return self.normal.invisible if value is None else value

    @property
    def color(self) -> ColorValue:
        return self.normal.color if self.important.color is None else self.important.color

    @property
    def background(self) -> ColorValue:
        """The fallback colour if one is known, else ``"image"`` for an image, else ``None``."""
        known = (
            self.normal.background
            if self.important.background is None
            else self.important.background
        )
        if known is None and (self.normal.image or self.important.image):
            return "image"
        return known


def _unescape_match(match: re.Match[str]) -> str:
    hexa, char = match.group(1), match.group(2)
    if char is not None:
        return str(char)
    code = int(hexa, 16)
    return chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else ""


def preprocess(text: str) -> str:
    """CSS input preprocessing (CSS Syntax 3.3): CR, CRLF and FF become LF, NUL becomes U+FFFD."""
    if "\r" in text or "\f" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n")
    return text.replace("\x00", chr(0xFFFD))


def normalize(text: str) -> str:
    """Decode CSS escapes, lower-case and collapse whitespace."""
    return " ".join(_ESCAPE.sub(_unescape_match, preprocess(text)).lower().split())


def strip_comments(text: str) -> tuple[str, bool]:
    """Replace comments with a space; ``/*`` inside a string or after ``\\`` starts none.

    The second value is true when a comment is never closed (the rest is dropped).
    """
    text = preprocess(text)
    parts: list[str] = []
    index = last = 0
    while True:
        match = _COMMENT_SCAN.search(text, index)
        if match is None:
            break
        if match.group() != "/*":
            index = match.end()
            continue
        parts.append(text[last : match.start()])
        parts.append(" ")
        end = text.find("*/", match.end())
        if end < 0:
            return "".join(parts), True
        index = last = end + 2
    parts.append(text[last:])
    return "".join(parts), False


def _split_important(value: str) -> tuple[str, bool]:
    stripped = value.rstrip()
    if stripped.endswith("important"):
        head = stripped[: -len("important")].rstrip()
        if head.endswith("!"):
            return head[:-1].rstrip(), True
    return stripped, False


def _quote_in_url(text: str) -> bool:
    """Whether an unquoted ``url(`` holds a quote: browsers read it as a bad url, others may not."""
    unescaped = _ESCAPE.sub(_unescape_match, text).lower()
    return any('"' in m.group(1) or "'" in m.group(1) for m in _URL_BODY.finditer(unescaped))


def _escaped_function_name(text: str) -> bool:
    """Whether an identifier written with an escape names a function, as in ``\\75rl(``."""
    return any(
        "\\" in run.group() and text[run.end() : run.end() + 1] == "("
        for run in _IDENT_RUN.finditer(text)
    )


def parse_declarations(text: str) -> tuple[Declarations, bool]:
    """Split a declaration list; the flag asks the caller to fail closed.

    It is set for an unclosed comment and for a quote inside an unquoted ``url(``, which parsers
    disagree about.
    """
    text, unclosed = strip_comments(text)
    unsafe = unclosed or _quote_in_url(text) or _escaped_function_name(text)
    parts: list[str] = []
    depth = start = 0
    for match in _STRUCTURE.finditer(text):
        sym = match.group()
        if sym == "(":
            depth += 1
        elif sym == ")":
            depth = max(depth - 1, 0)
        elif sym == ";" and depth == 0:
            parts.append(text[start : match.start()])
            start = match.end()
    parts.append(text[start:])
    result: Declarations = []
    for part in parts:
        name, sep, value = part.partition(":")
        if sep:
            cleaned, important = _split_important(normalize(value))
            result.append((normalize(name), cleaned, important))
    return result, unsafe


# --- values ----------------------------------------------------------------------------------


def _number(value: str) -> tuple[float, str] | None:
    match = _NUMBER.fullmatch(value)
    if match is None:
        return None
    try:
        return float(match.group(1)), match.group(2)
    except (ValueError, OverflowError):
        return None


def _tiny(number: tuple[float, str]) -> bool:
    return number[0] <= 0 or (number[0] <= 1 and number[1] in ("px", "pt"))


def _channel(token: str) -> int | None:
    try:
        return round(float(token[:-1]) * 2.55) if token.endswith("%") else round(float(token))
    except (ValueError, OverflowError):
        return None


def _color(value: str) -> ColorValue:
    if value == "transparent":
        return "transparent"
    if value in _NAMED_COLORS:
        return _NAMED_COLORS[value]
    hexa = _HEX_COLOR.fullmatch(value)
    if hexa:
        digits = hexa.group(1)
        if len(digits) in (3, 4):
            digits = "".join(c * 2 for c in digits)
        if len(digits) not in (6, 8):
            return None
        if len(digits) == 8 and digits[6:] == "00":
            return "transparent"
        return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)
    rgb = _RGB_COLOR.fullmatch(value)
    if rgb:
        red, green, blue = (_channel(rgb.group(i)) for i in (1, 2, 3))
        if red is None or green is None or blue is None:
            return None
        alpha = _number(rgb.group(4)) if rgb.group(4) else None
        if alpha is not None and alpha[0] <= 0:
            return "transparent"
        return red, green, blue
    return None


def _tokens(value: str) -> list[str]:
    """Split on whitespace outside parentheses in one pass."""
    tokens: list[str] = []
    depth = start = 0
    for index, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == " " and depth == 0:
            if index > start:
                tokens.append(value[start:index])
            start = index + 1
    if start < len(value):
        tokens.append(value[start:])
    return tokens


def first_color(value: str) -> ColorValue:
    for token in _tokens(value):
        found = _color(token)
        if found is not None:
            return found
    return None


def _font_size(value: str) -> bool | None:
    """Whether a ``font-size`` value is too small to read; ``None`` when it is not a size."""
    number = _number(value)
    if number is not None:
        return _tiny(number)
    return False if value in _SIZE_KEYWORDS else None


_SIZE_KEYWORDS: Final = frozenset(
    {"xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "initial"}
)


def _shorthand_size(value: str) -> bool | None:
    """The size inside a ``font`` shorthand: the first ``<size>[/<line-height>]`` token."""
    for token in _tokens(value):
        number = _number(token.split("/", 1)[0])
        if number is not None and (number[1] or number[0] == 0):
            return _tiny(number)
    return None


def _off_screen(value: str) -> bool:
    parsed = _number(value)
    return parsed is not None and parsed[0] <= -_FAR and parsed[1] in ("", "px", "pt", "em", "rem")


def _hides(name: str, value: str) -> bool:
    """Whether one declaration removes the element and everything below it."""
    number = _number(value)
    if name == "display":
        return value == "none"
    if name == "opacity":
        return number is not None and number[0] <= 0
    if name == "mso-hide":
        return value == "all"
    if name in _OFFSET_PROPERTIES:
        return _off_screen(value)
    return name == "clip-path" and value.replace(" ", "").startswith("inset(100%")


def _background(name: str, value: str) -> tuple[bool, ColorValue]:
    """Return (has an image or gradient, the first colour that is not transparent)."""
    image = "url(" in value or "gradient(" in value
    if name == "background-image":
        return image, None
    found = first_color(value)
    return image, None if found == "transparent" else found


def _props(declarations: Declarations) -> Props:
    tiny: bool | None = None
    invisible: bool | None = None
    color: ColorValue = None
    background: ColorValue = None
    image = False
    for name, value, _ in declarations:
        if name == "visibility" and value:
            invisible = value in ("hidden", "collapse")
        elif name in ("font-size", "font"):
            size = _font_size(value) if name == "font-size" else _shorthand_size(value)
            tiny = tiny if size is None else size
        elif name == "color":
            color = _color(value) or color
        elif name in ("background", "background-color", "background-image"):
            has_image, found = _background(name, value)
            image = image or has_image
            background = found or background
    return Props(tiny, invisible, color, background, image)


def evaluate(declarations: Declarations) -> Style:
    """Reduce declarations to a ``Style``; later declarations of a property win per importance."""
    hidden = clipped = zero_size = False
    for name, value, _ in declarations:
        if _hides(name, value):
            hidden = True
        elif name in ("overflow", "overflow-x", "overflow-y"):
            clipped = clipped or any(word in _CLIPPING for word in value.split())
        elif name in _SIZE_PROPERTIES:
            number = _number(value)
            zero_size = zero_size or (number is not None and number[0] <= 0)
    return Style(
        hidden or (clipped and zero_size),
        _props([d for d in declarations if not d[2]]),
        _props([d for d in declarations if d[2]]),
    )


# --- stylesheets -----------------------------------------------------------------------------


class Sheet:
    """Top-level rules whose selector is one tag, ``.class``, ``#id`` or ``tag.class``."""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, str], Style] = {}

    def add(self, key: tuple[str, str], style: Style) -> None:
        known = self._rules.get(key)
        self._rules[key] = style if known is None else known.merge(style)

    def update(self, other: Sheet) -> None:
        for key, style in other._rules.items():
            self.add(key, style)

    def style_for(self, tag: str, classes: list[str], ident: str | None) -> Style:
        """Merge the matching rules; classes and ids are lower-case, as the sheet is."""
        keys = [("t", tag)]
        keys += [("c", c) for c in classes]
        keys += [("tc", f"{tag}.{c}") for c in classes]
        if ident:
            keys.append(("i", ident))
        merged = Style()
        for key in keys:
            style = self._rules.get(key)
            if style is not None:
                merged = merged.merge(style)
        return merged


def _add_rule(sheet: Sheet, prelude: str, body: str) -> None:
    prelude = prelude.strip()
    if not prelude or prelude.startswith("@") or "{" in body:
        return
    declarations, _ = parse_declarations(body)
    style = evaluate(declarations)
    if style == Style():
        return
    for raw in prelude.split(","):
        match = _SIMPLE_SELECTOR.fullmatch(normalize(raw))
        if match is None or not match.group():
            continue
        tag, kind, name = match.groups()
        if kind is None:
            sheet.add(("t", str(tag)), style)
        elif kind == "#":
            sheet.add(("i", name), style)
        elif tag:
            sheet.add(("tc", f"{tag}.{name}"), style)
        else:
            sheet.add(("c", name), style)


def parse_stylesheet(css: str) -> Sheet:
    """Read top-level rules; at-rules (with or without a block) and nested rules are skipped."""
    sheet = Sheet()
    text, _ = strip_comments(css)
    text = text.replace("<!--", " ").replace("-->", " ")
    parens = block = start = body_start = 0
    prelude = ""
    for match in _STRUCTURE.finditer(text):
        sym = match.group()
        if sym == "(":
            parens += 1
        elif sym == ")":
            parens = max(parens - 1, 0)
        elif parens:
            continue
        elif sym == "{":
            if block == 0:
                prelude, body_start = text[start : match.start()], match.end()
            block += 1
        elif sym == "}":
            if block == 0:
                start = match.end()
                continue
            block -= 1
            if block == 0:
                _add_rule(sheet, prelude, text[body_start : match.start()])
                start = match.end()
        elif sym == ";" and block == 0:
            start = match.end()
    return sheet


__all__ = [
    "Color",
    "ColorValue",
    "Props",
    "Sheet",
    "Style",
    "evaluate",
    "first_color",
    "normalize",
    "parse_declarations",
    "parse_stylesheet",
    "preprocess",
    "strip_comments",
]
