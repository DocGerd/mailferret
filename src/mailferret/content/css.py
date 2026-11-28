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
fallback colour is compared by that colour; a gradient counts as a colour only when all its stops
agree; otherwise the backdrop is unknown and text is kept.

Hiding states inherit through a ``Flag`` allowlist: only a recognised value (an absolute size above
one point, a size keyword, ``visible``, ``initial``) clears an inherited state. Relative sizes,
``inherit``, functions, garbage and the whole ``font`` shorthand never do.

Any ``var()`` or ``env()`` in a hiding property fails closed (hidden): the value of a variable
depends on ancestors, case and rule order, which are not modelled. Layouts built on variables
over-hide, and the note says so.
"""

from __future__ import annotations

import enum
import math
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
_NUMBER: Final = re.compile(r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)([a-z%]*)")
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
# Absolute lengths in px. Every other unit (em, %, ex, ch, rem, vw, ...) is relative to something
# that may itself be zero, so it can never clear an inherited tiny size.
_ABSOLUTE_UNITS: Final = {
    "px": 1.0,
    "pt": 4 / 3,
    "pc": 16.0,
    "cm": 96 / 2.54,
    "mm": 96 / 25.4,
    "in": 96.0,
    "q": 96 / 101.6,
}
_TINY_PX: Final = 4 / 3  # one point
_EM_PX: Final = 16.0  # an em, for the off-screen and zero-box checks only
_ALPHA_STEP: Final = 1 / 255
_OFFSET_PROPERTIES: Final = frozenset(
    {"left", "right", "top", "bottom", "text-indent", "margin-left"}
)
_SIZE_PROPERTIES: Final = frozenset({"height", "max-height", "width", "max-width"})
_CLIPPING: Final = frozenset({"hidden", "clip"})

Declarations = list[tuple[str, str, bool]]  # name, value, !important


class Flag(enum.Enum):
    """A hiding state a declaration sets, clears or leaves to the parent; ``None``: no declaration.

    Only a positively recognised value is ``OFF``. Anything else that is not a hiding value
    (relative sizes, ``inherit``, functions, garbage) is ``INHERIT``, so it never clears a state.
    """

    ON = "on"
    OFF = "off"
    INHERIT = "inherit"


def override(base: Flag | None, top: Flag | None) -> Flag | None:
    """The state once ``top`` is applied over ``base``; an unrecognised value cannot clear ON."""
    if top is None:
        return base
    if top is Flag.INHERIT and base is Flag.ON:
        return Flag.ON
    return top


@dataclass(frozen=True, slots=True)
class Props:
    """Inherited properties of one importance level; ``None`` means not declared."""

    tiny: Flag | None = None  # the text is too small to read
    invisible: Flag | None = None  # visibility is hidden or collapse
    color: ColorValue = None  # text colour
    background: ColorValue = None  # the known (fallback) colour, never "transparent"
    image: bool = False  # a background image or gradient

    def merge(self, later: Props) -> Props:
        return Props(
            override(self.tiny, later.tiny),
            override(self.invisible, later.invisible),
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

    direct: bool = False  # display, opacity, off-screen, ...: the subtree is gone
    clipped: bool = False  # overflow clips
    empty: bool = False  # a zero-size box
    normal: Props = Props()
    important: Props = Props()

    @property
    def hidden(self) -> bool:
        """The whole subtree is gone, whatever its children declare."""
        return self.direct or (self.clipped and self.empty)

    def merge(self, later: Style) -> Style:
        return Style(
            self.direct or later.direct,
            self.clipped or later.clipped,
            self.empty or later.empty,
            self.normal.merge(later.normal),
            self.important.merge(later.important),
        )

    @property
    def tiny(self) -> Flag | None:
        return override(self.normal.tiny, self.important.tiny)

    @property
    def invisible(self) -> Flag | None:
        return override(self.normal.invisible, self.important.invisible)

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


def _tiny(number: float, unit: str) -> bool:
    return number * _ABSOLUTE_UNITS[unit] <= _TINY_PX


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


_SIZE_KEYWORDS: Final = frozenset(
    {
        "xx-small",
        "x-small",
        "small",
        "medium",
        "large",
        "x-large",
        "xx-large",
        "xxx-large",
        "initial",
    }
)


# --- constant math functions -----------------------------------------------------------------

_MATH_FUNCTIONS: Final = frozenset({"calc", "min", "max", "clamp"})
_FUNCTION: Final = re.compile(r"(-(?:webkit|moz)-)?([a-z][a-z0-9-]*)\(")
_MATH_TOKEN: Final = re.compile(
    r"\s*(?:(?P<num>[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(?P<unit>[a-z%]*)"
    r"|(?P<fn>-?[a-z][a-z0-9-]*)\(|(?P<op>[-+*/(),)])|(?P<word>[^\s()+*/,-]+))"
)
_CONSTANTS: Final = {
    "infinity": math.inf,
    "nan": math.nan,
    "pi": math.pi,
    "e": math.e,
}
_MAX_MATH_DEPTH: Final = 24
_DEEP: Final = float("-inf")  # fails closed: below every hiding threshold
_Token = tuple[str, str, str]  # kind (num, fn, op, word), text, unit
_Val = tuple[float | None, bool]  # a value or upper bound (None: unknown), and whether exact
_UNKNOWN: Final[_Val] = (None, False)


class _Bail(Exception):
    """The expression is not one this module understands."""


class _FailClosed(Exception):
    """Too deeply nested, or a function this module does not implement."""


def _function_name(value: str) -> str | None:
    """The name of the function a value starts with, without a vendor prefix."""
    match = _FUNCTION.match(value)
    return match.group(2) if match else None


def _canonical(name: str) -> str:
    return name.removeprefix("-webkit-").removeprefix("-moz-")


def _math_tokens(text: str) -> list[_Token] | None:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        match = _MATH_TOKEN.match(text, position)
        if match is None:
            return None if text[position:].strip() else tokens
        position = match.end()
        for kind in ("num", "fn", "op", "word"):
            if match.group(kind) is not None:
                tokens.append((kind, match.group(kind), match.group("unit") or ""))
                break
    return tokens


def _divide(left: float, right: float) -> float:
    if right != 0:
        return left / right
    return math.nan if left == 0 or math.isnan(left) else math.copysign(math.inf, left)


def _nonfinite(value: _Val) -> bool:
    return value[1] and value[0] is not None and not math.isfinite(value[0])


class _MathParser:
    """Evaluates ``calc()``, ``min()``, ``max()`` and ``clamp()`` over constants only.

    ``%`` (unless ``percent`` gives its scale) and ``em``/``rem`` (unless ``em`` is given) are
    unknown. ``min()`` and ``clamp()`` still give an upper bound, which is all the hiding checks
    need. Any other function fails closed.
    """

    def __init__(self, tokens: list[_Token], em: float | None, percent: float | None) -> None:
        self.tokens = tokens
        self.index = 0
        self.em = em
        self.percent = percent

    def _peek(self, kind: str, *texts: str) -> bool:
        if self.index >= len(self.tokens):
            return False
        token = self.tokens[self.index]
        return token[0] == kind and token[1] in texts

    def _next(self) -> _Token:
        if self.index >= len(self.tokens):
            raise _Bail
        self.index += 1
        return self.tokens[self.index - 1]

    def _expect(self, text: str) -> None:
        if self.index < len(self.tokens) and self._next()[1] != text:  # end of input closes
            raise _Bail

    def done(self) -> bool:
        return self.index == len(self.tokens)

    def total(self, depth: int) -> _Val:
        value = self._product(depth)
        while self._peek("op", "+", "-"):
            sign = self._next()[1]
            left, right = value[0], self._product(depth)
            if left is None or right[0] is None or not (value[1] and right[1]):
                value = _UNKNOWN
            else:
                value = (left + right[0] if sign == "+" else left - right[0], True)
        return value

    def _product(self, depth: int) -> _Val:
        value = self._operand(depth)
        while self._peek("op", "*", "/"):
            sign = self._next()[1]
            left, right = value[0], self._operand(depth)
            zero = (value[1] and left == 0 and not _nonfinite(right)) or (
                right[1] and right[0] == 0 and not _nonfinite(value)
            )
            if sign == "*" and zero:
                value = (0.0, True)
            elif left is None or right[0] is None or not (value[1] and right[1]):
                value = _UNKNOWN
            elif sign == "*":
                value = (left * right[0], True)
            else:
                value = (_divide(left, right[0]), True)
        return value

    def _operand(self, depth: int) -> _Val:
        if depth > _MAX_MATH_DEPTH:
            raise _FailClosed
        kind, text, unit = self._next()
        if kind == "num":
            return self._number(text, unit)
        if kind == "op" and text in "+-":
            value = self._operand(depth + 1)
            return (-value[0], value[1]) if text == "-" and value[0] is not None else value
        if kind == "op" and text == "(":
            value = self.total(depth + 1)
            self._expect(")")
            return value
        if kind == "fn":
            name = _canonical(text)
            if name in _MATH_FUNCTIONS:
                return self._call(name, depth + 1)
            raise _FailClosed
        if kind == "word":
            return (_CONSTANTS[text], True) if text in _CONSTANTS else _UNKNOWN
        raise _Bail

    def _skip_group(self) -> None:
        open_groups = 1
        while open_groups:
            kind, text, _ = self._next()
            if kind == "fn" or (kind == "op" and text == "("):
                open_groups += 1
            elif kind == "op" and text == ")":
                open_groups -= 1

    def _number(self, text: str, unit: str) -> _Val:
        try:
            number = float(text)
        except (ValueError, OverflowError):
            raise _Bail from None
        if unit == "":
            return number, True
        if unit in _ABSOLUTE_UNITS:
            return number * _ABSOLUTE_UNITS[unit], True
        if unit in ("em", "rem") and self.em is not None:
            return number * self.em, True
        if unit == "%" and self.percent is not None:
            return number * self.percent, True
        return (0.0, True) if number == 0 else _UNKNOWN

    def _call(self, name: str, depth: int) -> _Val:
        args = [self.total(depth)]
        while self._peek("op", ","):
            self._next()
            args.append(self.total(depth))
        self._expect(")")
        known = [a[0] for a in args if a[0] is not None]
        exact = all(a[1] for a in args)
        if any(math.isnan(v) for v in known):
            return math.nan, True
        if name == "calc":
            if len(args) != 1:
                raise _Bail
            return args[0]
        if name == "min":
            return (min(known), exact) if known else _UNKNOWN
        if name == "max":
            return (max(known), True) if exact and known else _UNKNOWN
        if len(args) != 3:
            raise _Bail
        low, value, high = args
        if low[1] and high[1] and low[0] is not None and high[0] is not None:
            if value[1] and value[0] is not None:
                return max(low[0], min(value[0], high[0])), True
            return max(low[0], high[0]), False
        return _UNKNOWN


def _math_value(value: str, em: float | None, percent: float | None = None) -> float | None:
    """The value (or an upper bound) of a constant math function, ``None`` if not understood.

    A function that is not implemented (``var()`` and ``env()`` are resolved before this), a
    non-finite result and nesting past the limit fail closed: ``-inf``, under every threshold.
    """
    name = _function_name(value)
    if name is None:
        return None
    if name not in _MATH_FUNCTIONS:
        return _DEEP
    tokens = _math_tokens(value)
    if tokens is None:
        return None
    parser = _MathParser(tokens, em, percent)
    try:
        result = parser.total(0)
    except _FailClosed:
        return _DEEP
    except _Bail:
        return None
    if not parser.done() or result[0] is None:
        return None
    return result[0] if math.isfinite(result[0]) else _DEEP


_STRICT_LENGTH: Final = re.compile(r"(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?[a-z]+")


def _size_flag(value: str) -> Flag:
    """Classify one size value: only an absolute length or keyword may clear a tiny size."""
    constant = _math_value(value, None)
    if constant is not None:
        return Flag.ON if constant <= _TINY_PX else Flag.INHERIT
    number = _number(value)
    if number is not None:
        size, unit = number
        if size <= 0:
            return Flag.ON
        if unit in _ABSOLUTE_UNITS:
            if _tiny(size, unit):
                return Flag.ON
            return Flag.OFF if _STRICT_LENGTH.fullmatch(value.lstrip("+")) else Flag.INHERIT
        return Flag.INHERIT
    return Flag.OFF if value in _SIZE_KEYWORDS else Flag.INHERIT


def _font_size(value: str) -> Flag | None:
    return _size_flag(value) if value else None


def _before_slash(token: str) -> str:
    """The part of a shorthand token before a ``/`` outside parentheses."""
    depth = 0
    for index, char in enumerate(token):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == "/" and depth == 0:
            return token[:index]
    return token


def _is_size(head: str) -> bool:
    number = _number(head)
    return head in _SIZE_KEYWORDS or (number is not None and bool(number[1] or number[0] == 0))


def _shorthand_size(value: str) -> Flag | None:
    """The ``font`` shorthand can set a tiny size but never clears an inherited one.

    Validating the shorthand grammar (prefix words, line-height, family list) is a source of
    fail-open gaps, so only the ``font-size`` longhand clears. Any tiny size token hides; the rest
    inherits. A mail that resets its size with ``font:`` under a zero-size parent is over-hidden
    and noted.
    """
    if not value:
        return None
    tiny = any(
        (_is_size(head) or _function_name(head) is not None) and _size_flag(head) is Flag.ON
        for head in map(_before_slash, _tokens(value))
    )
    return Flag.ON if tiny else Flag.INHERIT


def _visibility(value: str) -> Flag:
    name = _function_name(value)
    if value in ("hidden", "collapse") or name is not None:
        return Flag.ON
    return Flag.OFF if value in ("visible", "initial") else Flag.INHERIT


def _off_screen(value: str) -> bool:
    parsed = _number(value)
    if parsed is None:
        constant = _math_value(value, _EM_PX)
        return constant is not None and constant <= -_FAR
    return parsed[0] <= -_FAR and parsed[1] in ("", "px", "pt", "em", "rem")


def _transparent(value: str) -> bool:
    """Whether an ``opacity`` value renders as nothing (below one 8-bit alpha step)."""
    number = _number(value)
    if number is not None:
        return number[0] / (100 if number[1] == "%" else 1) < _ALPHA_STEP
    constant = _math_value(value, None, 0.01)
    return constant is not None and constant < _ALPHA_STEP


def _empty_size(value: str) -> bool:
    number = _number(value)
    if number is not None:
        return number[0] <= 0
    constant = _math_value(value, _EM_PX)
    return constant is not None and constant <= 0


def _hides(name: str, value: str) -> bool:
    """Whether one declaration removes the element and everything below it."""
    if value == _FAILED and name in ("display", "mso-hide", "clip-path"):
        return True
    if name == "display":
        return value == "none"
    if name == "opacity":
        return _transparent(value)
    if name == "mso-hide":
        return value == "all"
    if name in _OFFSET_PROPERTIES:
        return _off_screen(value)
    return name == "clip-path" and value.replace(" ", "").startswith("inset(100%")


_GRADIENT: Final = re.compile(r"(?:repeating-)?(?:linear|radial|conic)-gradient\(")
_NON_STOP: Final = re.compile(
    r"[+-]?[\d.]+[a-z%]*|(?:to|circle|ellipse|at|closest|farthest|from|in)\b.*"
)


def _arguments(text: str, start: int) -> tuple[list[str], int]:
    """The comma-separated arguments of the call whose ``(`` ends before ``start``."""
    arguments: list[str] = []
    depth = 1
    begin = start
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                arguments.append(text[begin:index])
                return arguments, index + 1
        elif char == "," and depth == 1:
            arguments.append(text[begin:index])
            begin = index + 1
    arguments.append(text[begin:])
    return arguments, len(text)


def _gradient_color(value: str) -> ColorValue:
    """The one colour every stop of every gradient has, else ``None``; any ``url(`` spoils it."""
    if "url(" in value:
        return None
    stops: set[Color] = set()
    position = 0
    while True:
        match = _GRADIENT.search(value, position)
        if match is None:
            return next(iter(stops)) if len(stops) == 1 else None
        arguments, position = _arguments(value, match.end())
        for argument in arguments:
            text = argument.strip()
            found = first_color(text)
            if isinstance(found, tuple):
                stops.add(found)
            elif found is not None or not _NON_STOP.fullmatch(text):
                return None  # a transparent or unrecognised stop: the backdrop is unknown


def _background(name: str, value: str) -> tuple[bool, ColorValue]:
    """Return (has an image or gradient, the colour the backdrop is known to have).

    A declared fallback colour counts even with an image present. Without one, a gradient whose
    stops all share a colour is that colour; a ``url()`` or mixed gradient leaves it unknown.
    """
    image = "url(" in value or "gradient(" in value
    found = None if name == "background-image" else first_color(value)
    if found == "transparent":
        found = None
    if found is None and image:
        found = _gradient_color(value)
    return image, found


def _props(declarations: Declarations) -> Props:
    tiny: Flag | None = None
    invisible: Flag | None = None
    color: ColorValue = None
    background: ColorValue = None
    image = False
    for name, value, _ in declarations:
        if name == "visibility" and value:
            invisible = override(invisible, _visibility(value))
        elif name in ("font-size", "font"):
            size = _font_size(value) if name == "font-size" else _shorthand_size(value)
            tiny = override(tiny, size)
        elif name == "color":
            color = _color(value) or color
        elif name in ("background", "background-color", "background-image"):
            has_image, found = _background(name, value)
            image = image or has_image
            background = found or background
    return Props(tiny, invisible, color, background, image)


# --- variables ---------------------------------------------------------------------------------

_VARIABLE_PROPERTIES: Final = frozenset(
    {
        "display",
        "visibility",
        "opacity",
        "mso-hide",
        "clip-path",
        "font-size",
        "font",
        "overflow",
        "overflow-x",
        "overflow-y",
        *_OFFSET_PROPERTIES,
        *_SIZE_PROPERTIES,
    }
)
# A value no property can read as visible: functions it does not implement fail closed.
_FAILED: Final = "fail-closed()"


def _close_variables(declarations: Declarations) -> Declarations:
    """Make a declaration that reads ``var()`` or ``env()`` in a hiding property fail closed.

    The value of a variable depends on ancestors, case and rule order, so it is not modelled.
    """
    return [
        (name, _FAILED, important)
        if name in _VARIABLE_PROPERTIES and ("var(" in value or "env(" in value)
        else (name, value, important)
        for name, value, important in declarations
    ]


def evaluate(declarations: Declarations) -> Style:
    """Reduce declarations to a ``Style``; later declarations of a property win per importance."""
    declarations = _close_variables(declarations)
    direct = clipped = empty = False
    for name, value, _ in declarations:
        if _hides(name, value):
            direct = True
        elif name in ("overflow", "overflow-x", "overflow-y"):
            clipped = (
                clipped or value == _FAILED or any(word in _CLIPPING for word in value.split())
            )
        elif name in _SIZE_PROPERTIES:
            empty = empty or _empty_size(value)
    return Style(
        direct,
        clipped,
        empty,
        _props([d for d in declarations if not d[2]]),
        _props([d for d in declarations if d[2]]),
    )


# --- stylesheets -----------------------------------------------------------------------------


_SPECIFICITY: Final = {"t": 1, "c": 10, "tc": 11, "i": 100, "ti": 101}  # by selector kind
_Key = tuple[str, str]
# Per selector, the last effect on each inherited property and level: (rule position, value).
_Entries = dict[tuple[bool, str], tuple[int, Props]]


def _single_properties(props: Props) -> list[tuple[str, Props]]:
    """One ``Props`` per declared property, so each can carry the position of its last rule."""
    singles: list[tuple[str, Props]] = []
    if props.tiny is not None:
        singles.append(("tiny", Props(tiny=props.tiny)))
    if props.invisible is not None:
        singles.append(("invisible", Props(invisible=props.invisible)))
    if props.color is not None:
        singles.append(("color", Props(color=props.color)))
    if props.background is not None:
        singles.append(("background", Props(background=props.background)))
    if props.image:
        singles.append(("image", Props(image=True)))
    return singles


class Sheet:
    """Top-level rules whose selector is exactly ``tag``, ``.class``, ``#id``, ``tag.class`` or
    ``tag#id``; every other selector is ignored, never reduced to a part of itself.

    Matching rules are applied in cascade order: specificity, then position in the sheets (all
    ``<style>`` elements in document order), never the order of the ``class`` attribute.
    """

    def __init__(self) -> None:
        self._flags: dict[_Key, Style] = {}
        self._entries: dict[_Key, _Entries] = {}
        self.count = 0  # rules seen: the position of the next one

    def add(self, key: _Key, style: Style, position: int) -> None:
        known = self._flags.get(key, Style())
        self._flags[key] = known.merge(Style(style.direct, style.clipped, style.empty))
        entries = self._entries.setdefault(key, {})
        for important, props in ((False, style.normal), (True, style.important)):
            for name, single in _single_properties(props):
                previous = entries.get((important, name))
                merged = single if previous is None else previous[1].merge(single)
                entries[(important, name)] = (position, merged)

    def update(self, other: Sheet) -> None:
        """Append the rules of a later ``<style>`` element."""
        for key, flags in other._flags.items():
            self._flags[key] = self._flags.get(key, Style()).merge(flags)
        for key, entries in other._entries.items():
            own = self._entries.setdefault(key, {})
            for slot, (position, props) in entries.items():
                previous = own.get(slot)
                merged = props if previous is None else previous[1].merge(props)
                own[slot] = (position + self.count, merged)
        self.count += other.count

    def style_for(self, tag: str, classes: list[str], ident: str | None) -> Style:
        """Merge the matching rules; classes and ids are lower-case, as the sheet is."""
        keys = [("t", tag)]
        keys += [("c", c) for c in classes]
        keys += [("tc", f"{tag}.{c}") for c in classes]
        if ident:
            keys += [("i", ident), ("ti", f"{tag}#{ident}")]
        flags = Style()
        applicable: list[tuple[int, int, bool, Props]] = []
        for key in dict.fromkeys(keys):
            if key in self._flags:
                flags = flags.merge(self._flags[key])
                for (important, _), (position, props) in self._entries[key].items():
                    applicable.append((_SPECIFICITY[key[0]], position, important, props))
        applicable.sort(key=lambda entry: entry[:2])
        normal = important_props = Props()
        for _, _, important, props in applicable:
            if important:
                important_props = important_props.merge(props)
            else:
                normal = normal.merge(props)
        return Style(flags.direct, flags.clipped, flags.empty, normal, important_props)


def _add_rule(sheet: Sheet, prelude: str, body: str) -> None:
    prelude = prelude.strip()
    if not prelude or prelude.startswith("@") or "{" in body:
        return
    declarations, _ = parse_declarations(body)
    style = evaluate(declarations)
    if style == Style():
        return
    position = sheet.count
    sheet.count += 1
    for raw in prelude.split(","):
        match = _SIMPLE_SELECTOR.fullmatch(normalize(raw))
        if match is None or not match.group():
            continue
        tag, kind, name = match.groups()
        if kind is None:
            sheet.add(("t", str(tag)), style, position)
        elif kind == "#":
            sheet.add(("ti", f"{tag}#{name}") if tag else ("i", name), style, position)
        elif tag:
            sheet.add(("tc", f"{tag}.{name}"), style, position)
        else:
            sheet.add(("c", name), style, position)


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
    "Declarations",
    "Flag",
    "Props",
    "Sheet",
    "Style",
    "evaluate",
    "first_color",
    "normalize",
    "override",
    "parse_declarations",
    "parse_stylesheet",
    "preprocess",
    "strip_comments",
]
