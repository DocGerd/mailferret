"""HTML to text with hidden content removed (T-04, T-18, A§2.4).

Pure: no I/O, no logging, no network. The tree is built by libxml2 through lxml with
``no_network`` set; this module never reads a URL, resolves an image or follows a link.
Hidden content (``<head>``, scripts, styles, comments, ``hidden``, inline and simple
stylesheet rules) is skipped during one iterative walk, and every format or invisible
character is stripped from the text, including those produced by entity decoding.

Residual risk: only inline styles and single-class, single-id or single-tag stylesheet rules
are evaluated. Content hidden by a descendant selector, ``@media`` rule, external stylesheet
or an ancestor's colour scheme is kept.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from lxml import etree

from mailferret.content.charset import decode_text
from mailferret.content.invisible import strip_invisible
from mailferret.content.truncate import truncate_chars, truncate_text_bytes
from mailferret.limits import Limits

NOTE_HIDDEN: Final = "hidden_html_removed"
NOTE_STRUCTURE: Final = "html_script_style_head_removed"
NOTE_COMMENTS: Final = "html_comments_removed"
NOTE_FORMAT: Final = "format_controls_removed"
NOTE_PARSE_FAILED: Final = "html_parse_failed"
NOTE_LIMIT_PART: Final = "limit_exceeded:L-02"
NOTE_LIMIT_BODY: Final = "limit_exceeded:L-03"

_DEFAULT_LIMITS: Final = Limits()
_MAX_URL_CHARS: Final = 1024
_MAX_ALT_CHARS: Final = 200
_MAX_STYLE_RULES: Final = 5000
_BUDGET_FACTOR: Final = 3  # blank runs shrink in _tidy; a worst case keeps one char in three
_LINK_SCHEMES: Final = ("http://", "https://", "mailto:")
_C0: Final = dict.fromkeys([*range(0x09), 0x0B, *range(0x0E, 0x20), 0x7F, 0xFFFE, 0xFFFF], " ")

# Skipped with their subtree and noted as script/style/head removal.
_STRUCTURAL: Final = frozenset({"head", "script", "style", "title", "meta", "link", "base"})
# Skipped with their subtree and noted as hidden.
_NEVER_SHOWN: Final = frozenset(
    {"template", "iframe", "object", "embed", "applet", "canvas", "noembed", "frameset"}
)
_BLOCK: Final = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "center",
        "dd",
        "details",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "header",
        "main",
        "nav",
        "section",
        "summary",
        "tr",
        "ul",
        "ol",
        "li",
    }
)
_PARAGRAPH: Final = frozenset({"p", "h1", "h2", "h3", "h4", "h5", "h6", "table", "pre", "hr"})

_SPACES: Final = " \t\r\n\f\v" + "".join(
    map(chr, (0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000))
)
_WHITESPACE: Final = re.compile(f"[{re.escape(_SPACES)}]+")
_CSS_COMMENT: Final = re.compile(r"/\*.*?\*/", re.DOTALL)
_CSS_ESCAPE: Final = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?|\\(.)", re.DOTALL)
_NUMBER: Final = re.compile(r"([+-]?(?:\d+\.?\d*|\.\d+))([a-z%]*)")
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

Color = tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class HtmlText:
    text: str
    truncated: bool
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlainText:
    text: str
    truncated: bool
    notes: tuple[str, ...]


def strip_body_text(text: str, limits: Limits = _DEFAULT_LIMITS) -> PlainText:
    """Clean a plain-text body: strip format controls and invisibles, then cap at L-03."""
    cleaned, removed = strip_invisible(text)
    cut = truncate_chars(cleaned, limits.max_body_chars)
    notes = ((NOTE_FORMAT,) if removed else ()) + ((NOTE_LIMIT_BODY,) if cut.truncated else ())
    return PlainText(cut.text, cut.truncated, notes)


# --- CSS -------------------------------------------------------------------------------------


def _unescape(match: re.Match[str]) -> str:
    hexa, char = match.group(1), match.group(2)
    if char is not None:
        return str(char)
    code = int(hexa, 16)
    return chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else ""


def _normalize_css(text: str) -> str:
    return _CSS_ESCAPE.sub(_unescape, _CSS_COMMENT.sub(" ", text)).lower()


def _declarations(style: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for part in _normalize_css(style).split(";"):
        name, sep, value = part.partition(":")
        if not sep:
            continue
        value = value.replace("!important", "").strip().strip("\"'").strip()
        result.append((name.strip(), value))
    return result


def _number(value: str) -> tuple[float, str] | None:
    match = _NUMBER.fullmatch(value.strip())
    if match is None:
        return None
    try:
        return float(match.group(1)), match.group(2)
    except ValueError:
        return None


def _channel(token: str) -> int | None:
    try:
        if token.endswith("%"):
            return round(float(token[:-1]) * 2.55)
        return round(float(token))
    except ValueError:
        return None


def _color(value: str) -> Color | str | None:
    """Return an RGB triple, ``"transparent"``, or ``None`` when the value is not understood."""
    value = value.strip()
    if value == "transparent":
        return "transparent"
    if value in _NAMED_COLORS:
        return _NAMED_COLORS[value]
    hexa = _HEX_COLOR.fullmatch(value)
    if hexa:
        digits = hexa.group(1)
        if len(digits) in (3, 4):
            digits = "".join(c * 2 for c in digits)
        if len(digits) in (6, 8):
            if len(digits) == 8 and digits[6:] == "00":
                return "transparent"
            return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)
        return None
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


def _first_color(value: str) -> Color | str | None:
    for token in re.split(r"\s+(?![^(]*\))", value):
        found = _color(token)
        if found is not None:
            return found
    return None


def _zero_or_less(value: str) -> bool:
    parsed = _number(value)
    return parsed is not None and parsed[0] <= 0


def _tiny(number: tuple[float, str]) -> bool:
    return number[0] <= 0 or (number[0] <= 1 and number[1] in ("px", "pt"))


def _off_screen(value: str) -> bool:
    parsed = _number(value)
    return parsed is not None and parsed[0] <= -_FAR and parsed[1] in ("", "px", "pt", "em", "rem")


def _hidden_declarations(decls: list[tuple[str, str]]) -> bool:
    """Whether any single declaration, or the overflow and size pair, hides the content."""
    seen = dict(decls)
    clipped = seen.get("overflow") in ("hidden", "clip") or seen.get("overflow-y") in (
        "hidden",
        "clip",
    )
    for name, value in decls:
        number = _number(value)
        if name == "display" and value == "none":
            return True
        if name == "visibility" and value in ("hidden", "collapse"):
            return True
        if name == "font-size" and number is not None and _tiny(number):
            return True
        if name == "opacity" and number is not None and number[0] <= 0:
            return True
        if name == "mso-hide" and value == "all":
            return True
        if name in ("left", "right", "top", "bottom", "text-indent", "margin-left") and _off_screen(
            value
        ):
            return True
        if name == "clip-path" and value.replace(" ", "").startswith("inset(100%"):
            return True
        if (
            name in ("height", "max-height", "width", "max-width")
            and clipped
            and _zero_or_less(value)
        ):
            return True
        if name == "color" and _color(value) == "transparent":
            return True
    return False


def _own_background(decls: list[tuple[str, str]]) -> Color | str | None:
    found: Color | str | None = None
    for name, value in decls:
        if name in ("background", "background-color"):
            parsed = _first_color(value)
            if parsed is not None:
                found = parsed
    return found


def _own_color(decls: list[tuple[str, str]]) -> Color | str | None:
    found: Color | str | None = None
    for name, value in decls:
        if name == "color":
            parsed = _color(value)
            if parsed is not None:
                found = parsed
    return found


def _camouflaged(color: Color | str | None, background: Color | str | None) -> bool:
    """Text colour equal to the background; white on an unset background counts as white."""
    if color is None or isinstance(color, str):
        return False
    return color == (255, 255, 255) if background is None else color == background


@dataclass(slots=True)
class _Sheet:
    classes: set[str]
    ids: set[str]
    tags: set[str]
    tag_classes: set[tuple[str, str]]

    def hides(self, tag: str, classes: list[str], ident: str | None) -> bool:
        if tag in self.tags or (ident is not None and ident in self.ids):
            return True
        return any(c in self.classes or (tag, c) in self.tag_classes for c in classes)


def _parse_sheet(css: str) -> _Sheet:
    """Collect top-level rules whose selector is one tag, ``.class``, ``#id`` or ``tag.class``."""
    sheet = _Sheet(set(), set(), set(), set())
    text = _normalize_css(css)
    depth = 0
    start = 0
    selector = ""
    rules = 0
    for match in re.finditer(r"[{}]", text):
        char = match.group()
        if char == "{":
            if depth == 0:
                selector = text[start : match.start()]
                body_start = match.end()
            depth += 1
        else:
            depth = max(depth - 1, 0)
            if depth == 0:
                body = text[body_start : match.start()] if selector else ""
                start = match.end()
                rules += 1
                if rules > _MAX_STYLE_RULES:
                    break
                if selector.strip().startswith("@") or "{" in body:
                    continue
                if _hidden_declarations(_declarations(body)):
                    _add_selectors(sheet, selector)
                selector = ""
    return sheet


def _add_selectors(sheet: _Sheet, selectors: str) -> None:
    for raw in selectors.split(","):
        match = _SIMPLE_SELECTOR.fullmatch(raw.strip())
        if match is None or not raw.strip():
            continue
        tag, kind, name = match.groups()
        if kind is None:
            if tag:
                sheet.tags.add(tag)
        elif kind == "#":
            sheet.ids.add(name)
        elif tag:
            sheet.tag_classes.add((tag, name))
        else:
            sheet.classes.add(name)


# --- output ----------------------------------------------------------------------------------


class _Writer:
    """Collects collapsed text with pending breaks; stops accepting text over ``budget``."""

    def __init__(self, budget: int) -> None:
        self.parts: list[str] = []
        self.length = 0
        self.full = False
        self._budget = budget
        self._newlines = 0
        self._space = False
        self._line_start = True
        self._deferred = ""

    def _emit(self, text: str) -> None:
        if self.parts and self._newlines:
            self._push("\n" * min(self._newlines, 2))
            self._line_start = True
        elif self._space and not self._line_start:
            self._push(" ")
        self._newlines = 0
        self._space = False
        if self._deferred:
            self._push(self._deferred)
            self._deferred = ""
        room = self._budget - self.length
        if len(text) > room:
            text = text[: max(room, 0)]
            self.full = True
        if text:
            self._push(text)
            self._line_start = text.endswith("\n")
        if self.length >= self._budget:
            self.full = True

    def _push(self, text: str) -> None:
        self.parts.append(text)
        self.length += len(text)

    def text(self, raw: str) -> None:
        if not raw or self.full:
            return
        core = _WHITESPACE.sub(" ", raw)
        stripped = core.strip(" ")
        if not stripped:
            self._space = True
            return
        if core[0] == " ":
            self._space = True
        self._emit(stripped)
        self._space = core[-1] == " "

    def pre(self, raw: str) -> None:
        if not raw or self.full:
            return
        self._emit(raw.replace("\r\n", "\n").replace("\r", "\n"))

    def literal(self, text: str) -> None:
        if not self.full:
            self._emit(text)

    def defer(self, text: str) -> None:
        """Emit ``text`` before the next text, unless a block break comes first."""
        self._deferred = text

    def block(self, count: int) -> None:
        self._newlines = max(self._newlines, count)
        self._space = False
        self._deferred = ""

    def line_break(self) -> None:
        self._newlines = min(self._newlines + 1, 2)
        self._space = False


def _safe_url(href: str) -> str | None:
    cleaned, _ = strip_invisible("".join(href.split()))
    if len(cleaned) > _MAX_URL_CHARS or not cleaned.lower().startswith(_LINK_SCHEMES):
        return None
    return cleaned


# --- tree walk -------------------------------------------------------------------------------

_ENTER, _EXIT, _TAIL = 0, 1, 2


@dataclass(slots=True)
class _Counts:
    hidden: bool = False
    structure: bool = False


@dataclass(slots=True)
class _Walk:
    sheet: _Sheet
    writer: _Writer
    counts: _Counts
    pre_depth: int = 0
    lists: list[list[Any]] = None  # type: ignore[assignment]
    rows: list[list[int | None]] = None  # type: ignore[assignment]
    links: list[tuple[str | None, int, int]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.lists = []
        self.rows = []
        self.links = []


def _classify(
    el: Any, sheet: _Sheet, bg: Color | str | None
) -> tuple[bool, bool, Color | str | None]:
    """Return (structural, hidden, effective background) for an element."""
    tag: str = el.tag
    if tag in _STRUCTURAL:
        return True, False, bg
    attrs = el.attrib
    decls = _declarations(attrs.get("style", "")) if "style" in attrs else []
    own_bg = _own_background(decls)
    if own_bg is None and "bgcolor" in attrs:
        own_bg = _first_color(_normalize_css(attrs.get("bgcolor", "")))
    effective = own_bg if own_bg is not None else bg
    color = _own_color(decls)
    if color is None and tag == "font" and "color" in attrs:
        color = _color(_normalize_css(attrs.get("color", "")))
    classes = attrs.get("class", "").split() if "class" in attrs else []
    hidden = (
        tag in _NEVER_SHOWN
        or "hidden" in attrs
        or (tag == "input" and attrs.get("type", "").lower() == "hidden")
        or _hidden_declarations(decls)
        or sheet.hides(tag, classes, attrs.get("id"))
        or _camouflaged(color, effective if own_bg is None else own_bg)
    )
    return False, hidden, effective


def _enter(el: Any, walk: _Walk, stack: list[tuple[int, Any, Any]], bg: Color | str | None) -> None:
    if not isinstance(el.tag, str):
        stack.append((_TAIL, el, None))
        return
    structural, hidden, effective = _classify(el, walk.sheet, bg)
    if structural or hidden:
        if structural:
            walk.counts.structure = True
        else:
            walk.counts.hidden = True
        stack.append((_TAIL, el, None))
        return
    tag: str = el.tag
    writer = walk.writer
    if tag in _PARAGRAPH:
        writer.block(2)
    elif tag in _BLOCK:
        writer.block(1)
    if tag == "br":
        writer.line_break()
    elif tag == "hr":
        writer.literal("---")
    elif tag == "pre":
        walk.pre_depth += 1
    elif tag in ("ul", "ol"):
        walk.lists.append([tag == "ol", 0])
    elif tag == "li":
        if walk.lists:
            info = walk.lists[-1]
            info[1] += 1
            marker = f"{info[1]}. " if info[0] else "- "
            writer.literal("  " * (len(walk.lists) - 1) + marker)
        else:
            writer.literal("- ")
    elif tag == "tr":
        walk.rows.append([None])
    elif tag in ("td", "th") and walk.rows:
        previous = walk.rows[-1][0]
        if previous is not None and writer.length > previous:
            writer.defer(" | ")
        walk.rows[-1][0] = writer.length
    elif tag == "a":
        walk.links.append((_safe_url(el.get("href", "")), writer.length, len(writer.parts)))
    elif tag == "img":
        alt = _WHITESPACE.sub(" ", el.get("alt", "")).strip()[:_MAX_ALT_CHARS]
        if alt:
            writer.text(f" [image: {alt}] ")
    if walk.pre_depth:
        writer.pre(el.text or "")
    else:
        writer.text(el.text or "")
    stack.append((_TAIL, el, None))
    stack.append((_EXIT, el, None))
    for child in reversed(el):
        stack.append((_ENTER, child, effective))


def _exit(el: Any, walk: _Walk) -> None:
    tag: str = el.tag
    writer = walk.writer
    if tag in _PARAGRAPH:
        writer.block(2)
    elif tag in _BLOCK:
        writer.block(1)
    if tag == "pre":
        walk.pre_depth = max(walk.pre_depth - 1, 0)
    elif tag in ("ul", "ol") and walk.lists:
        walk.lists.pop()
    elif tag == "tr" and walk.rows:
        walk.rows.pop()
    elif tag == "a" and walk.links:
        url, start, index = walk.links.pop()
        if url is None:
            return
        label = "".join(writer.parts[index:]) if writer.length - start <= _MAX_URL_CHARS else ""
        if label.strip() in (url, url.split(":", 1)[1].lstrip("/")):
            return
        writer.text(f" ({url})" if label.strip() else f" {url}")


def _walk(root: Any, sheet: _Sheet, budget: int) -> tuple[str, _Counts, bool]:
    walk = _Walk(sheet, _Writer(budget), _Counts())
    stack: list[tuple[int, Any, Any]] = [(_ENTER, root, None)]
    while stack and not walk.writer.full:
        kind, el, bg = stack.pop()
        if kind == _ENTER:
            _enter(el, walk, stack, bg)
        elif kind == _EXIT:
            _exit(el, walk)
        elif el is not root and el.tail:
            if walk.pre_depth:
                walk.writer.pre(el.tail)
            else:
                walk.writer.text(el.tail)
    return "".join(walk.writer.parts), walk.counts, walk.writer.full


def _collect_sheet(root: Any) -> _Sheet:
    sheet = _Sheet(set(), set(), set(), set())
    for style in root.iter("style"):
        parsed = _parse_sheet(style.text or "")
        sheet.classes |= parsed.classes
        sheet.ids |= parsed.ids
        sheet.tags |= parsed.tags
        sheet.tag_classes |= parsed.tag_classes
    return sheet


def _parse(source: str) -> Any:
    parser = etree.HTMLParser(
        encoding="utf-8",
        recover=True,
        no_network=True,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
        collect_ids=False,
    )
    return etree.fromstring(source.encode("utf-8", errors="replace"), parser)


_BLANK_RUN: Final = re.compile(r"[ \t]+\n")
_NEWLINES: Final = re.compile(r"\n{3,}")


def _tidy(text: str) -> str:
    return _NEWLINES.sub("\n\n", _BLANK_RUN.sub("\n", text)).strip()


def html_to_text(
    html: bytes | str,
    charset: str | bytes | None = None,
    *,
    partial: bool = False,
    limits: Limits = _DEFAULT_LIMITS,
) -> HtmlText:
    """Convert an HTML part to bounded plain text; never raises, never touches the network.

    Input over ``max_part_bytes`` (L-02) is cut; output over ``max_body_chars`` (L-03) is cut on
    a codepoint boundary. ``notes`` is a fixed vocabulary that never repeats mail content.
    """
    notes: list[str] = []
    try:
        if isinstance(html, bytes):
            decoded = decode_text(html, charset, partial=partial, limits=limits)
            source, cut = decoded.text, decoded.truncated
        else:
            clipped = truncate_text_bytes(html, limits.max_part_bytes)
            source, cut = clipped.text, clipped.truncated
        if cut:
            notes.append(NOTE_LIMIT_PART)
        source, removed = strip_invisible(source.translate(_C0))
        if removed:
            notes.append(NOTE_FORMAT)
        if "<!--" in source:
            notes.append(NOTE_COMMENTS)
        text, counts, full = _extract(source, _BUDGET_FACTOR * limits.max_body_chars + 3)
    except Exception:  # lxml and libxml2 can fail outside their documented errors
        return HtmlText("", False, (*notes, NOTE_PARSE_FAILED))
    text, late = strip_invisible(text)
    if late and NOTE_FORMAT not in notes:
        notes.append(NOTE_FORMAT)
    if counts.hidden:
        notes.append(NOTE_HIDDEN)
    if counts.structure:
        notes.append(NOTE_STRUCTURE)
    result = truncate_chars(_tidy(text), limits.max_body_chars)
    over = result.truncated or full
    if over:
        notes.append(NOTE_LIMIT_BODY)
    return HtmlText(result.text, over or cut, tuple(notes))


def _extract(source: str, budget: int) -> tuple[str, _Counts, bool]:
    root = _parse(source)
    if root is None:
        return "", _Counts(), False
    return _walk(root, _collect_sheet(root), budget)
