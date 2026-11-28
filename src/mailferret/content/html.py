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
from dataclasses import dataclass, field
from typing import Any, Final

from lxml import etree

from mailferret.content.charset import decode_text
from mailferret.content.css import (
    ColorValue,
    Sheet,
    Style,
    evaluate,
    first_color,
    normalize,
    parse_declarations,
    parse_stylesheet,
)
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
NOTE_NESTING: Final = "html_nesting_limit"

_DEFAULT_LIMITS: Final = Limits()
_MAX_URL_CHARS: Final = 1024
_MAX_ALT_CHARS: Final = 200
_BUDGET_FACTOR: Final = 3  # blank runs shrink in _tidy; a worst case keeps one char in three
_LINK_SCHEMES: Final = ("http://", "https://", "mailto:")
_MAX_STYLE_CHARS: Final = 8192  # a longer inline style is treated as hidden (padding attack)
# C0 and C1 controls other than tab, LF and CR (as headers._CONTROLS), plus noncharacters.
_CONTROLS: Final = dict.fromkeys(
    [0x00, *range(0x01, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), *range(0x7F, 0xA0), 0xFFFE, 0xFFFF],
    " ",
)

# Skipped with their subtree and noted as script/style/head removal.
_STRUCTURAL: Final = frozenset({"head", "script", "style", "title", "meta", "link", "base"})
# Skipped with their subtree and noted as hidden.
_NEVER_SHOWN: Final = frozenset(
    {
        "template",
        "iframe",
        "object",
        "embed",
        "applet",
        "canvas",
        "noembed",
        "frameset",
        "datalist",
        "desc",
        "defs",
        "metadata",
    }
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


def _clean(text: str) -> tuple[str, bool]:
    """Replace control characters, then strip Cf and invisibles; report any change."""
    spaced = text.translate(_CONTROLS)
    kept, removed = strip_invisible(spaced)
    return kept, removed or spaced != text


def strip_body_text(text: str, limits: Limits = _DEFAULT_LIMITS) -> PlainText:
    """Clean a plain-text body: strip format controls and invisibles, then cap at L-03."""
    cleaned, removed = _clean(text)
    cut = truncate_chars(cleaned, limits.max_body_chars)
    notes = ((NOTE_FORMAT,) if removed else ()) + ((NOTE_LIMIT_BODY,) if cut.truncated else ())
    return PlainText(cut.text, cut.truncated, notes)


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


def _camouflaged(color: ColorValue, background: ColorValue) -> bool:
    """Text colour equal to the background; white on an unset background counts as white."""
    if color == "transparent":
        return True
    if not isinstance(color, tuple) or background == "image":
        return False
    return color == (255, 255, 255) if background is None else color == background


@dataclass(frozen=True, slots=True)
class _State:
    """Inherited presentation: a child can override colour, size and visibility."""

    background: ColorValue = None
    color: ColorValue = None
    tiny: bool = False
    invisible: bool = False

    @property
    def soft_hidden(self) -> bool:
        return self.tiny or self.invisible or _camouflaged(self.color, self.background)


@dataclass(slots=True)
class _Flags:
    hidden: bool = False
    structure: bool = False
    nesting: bool = False


@dataclass(slots=True)
class _Walk:
    sheet: Sheet
    writer: _Writer
    flags: _Flags
    pre_depth: int = 0
    lists: list[list[Any]] = field(default_factory=list)
    rows: list[list[int | None]] = field(default_factory=list)
    links: list[tuple[str | None, int, int]] = field(default_factory=list)

    def text(self, raw: str, soft: bool) -> None:
        if not raw:
            return
        if soft:
            if raw.strip():
                self.flags.hidden = True
            return
        if self.pre_depth:
            self.writer.pre(raw)
        else:
            self.writer.text(raw)


def _attribute_style(el: Any) -> Style:
    """Presentation attributes (``bgcolor``, ``<font color>``), weaker than any CSS."""
    attrs = el.attrib
    background = first_color(normalize(attrs.get("bgcolor", ""))) if "bgcolor" in attrs else None
    color = None
    if el.tag == "font" and "color" in attrs:
        color = first_color(normalize(attrs.get("color", "")))
    return Style(color=color, background=background)


def _classify(el: Any, walk: _Walk, inherited: _State) -> tuple[bool, bool, _State]:
    """Return (structural, subtree hidden, the element's own state)."""
    tag: str = el.tag
    if tag in _STRUCTURAL:
        return True, False, inherited
    attrs = el.attrib
    hidden = (
        tag in _NEVER_SHOWN
        or "hidden" in attrs
        or (tag == "dialog" and "open" not in attrs)
        or (tag == "input" and attrs.get("type", "").lower() == "hidden")
    )
    raw_style = attrs.get("style", "")
    if len(raw_style) > _MAX_STYLE_CHARS:
        return False, True, inherited
    classes = [c.lower() for c in attrs.get("class", "").split()]
    ident = attrs.get("id")
    style = _attribute_style(el).merge(
        walk.sheet.style_for(tag, classes, ident.lower() if ident else None)
    )
    if raw_style:
        declarations, unclosed = parse_declarations(raw_style)
        hidden = hidden or unclosed
        style = style.merge(evaluate(declarations))
    hidden = hidden or style.hidden
    background = inherited.background if style.background is None else style.background
    color = inherited.color if style.color is None else style.color
    tiny = inherited.tiny if style.tiny is None else style.tiny
    invisible = inherited.invisible if style.invisible is None else style.invisible
    return False, hidden, _State(background, color, tiny, invisible)


def _enter(el: Any, walk: _Walk, stack: list[tuple[int, Any, _State]], inherited: _State) -> None:
    stack.append((_TAIL, el, inherited))
    if not isinstance(el.tag, str):
        return
    structural, hidden, state = _classify(el, walk, inherited)
    if structural or hidden:
        if structural:
            walk.flags.structure = True
        else:
            walk.flags.hidden = True
        return
    soft = state.soft_hidden
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
        url = None if soft else _safe_url(el.get("href", ""))
        walk.links.append((url, writer.length, len(writer.parts)))
    elif tag == "img":
        alt = _WHITESPACE.sub(" ", el.get("alt", "")).strip()[:_MAX_ALT_CHARS]
        if alt:
            walk.text(f" [image: {alt}] ", soft)
    walk.text(el.text or "", soft)
    stack.append((_EXIT, el, state))
    for child in reversed(el):
        stack.append((_ENTER, child, state))


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


def _walk(root: Any, sheet: Sheet, budget: int) -> tuple[str, _Flags, bool]:
    walk = _Walk(sheet, _Writer(budget), _Flags())
    stack: list[tuple[int, Any, _State]] = [(_ENTER, root, _State())]
    while stack and not walk.writer.full:
        kind, el, state = stack.pop()
        if kind == _ENTER:
            _enter(el, walk, stack, state)
        elif kind == _EXIT:
            _exit(el, walk)
        elif el is not root:
            walk.text(el.tail or "", state.soft_hidden)
    return "".join(walk.writer.parts), walk.flags, walk.writer.full


def _collect_sheet(root: Any) -> Sheet:
    sheet = Sheet()
    for style in root.iter("style"):
        sheet.update(parse_stylesheet(style.text or ""))
    return sheet


def _parse(source: str) -> tuple[Any, bool]:
    """Parse to a tree; the flag is set when libxml2 stopped at its nesting limit."""
    parser = etree.HTMLParser(
        encoding="utf-8",
        recover=True,
        no_network=True,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
        collect_ids=False,
    )
    root = etree.fromstring(source.encode("utf-8", errors="replace"), parser)
    limited = any(entry.type_name == "ERR_RESOURCE_LIMIT" for entry in parser.error_log)
    return root, limited


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
        source, removed = _clean(source)
        if removed:
            notes.append(NOTE_FORMAT)
        if "<!--" in source:
            notes.append(NOTE_COMMENTS)
        text, flags, full = _extract(source, _BUDGET_FACTOR * limits.max_body_chars + 3)
    except Exception:  # lxml and libxml2 can fail outside their documented errors
        return HtmlText("", False, (*notes, NOTE_PARSE_FAILED))
    text, late = _clean(text)
    if late and NOTE_FORMAT not in notes:
        notes.append(NOTE_FORMAT)
    if flags.hidden:
        notes.append(NOTE_HIDDEN)
    if flags.structure:
        notes.append(NOTE_STRUCTURE)
    if flags.nesting:
        notes.append(NOTE_NESTING)
    result = truncate_chars(_tidy(text), limits.max_body_chars)
    over = result.truncated or full or flags.nesting
    if over:
        notes.append(NOTE_LIMIT_BODY)
    return HtmlText(result.text, over or cut, tuple(notes))


def _extract(source: str, budget: int) -> tuple[str, _Flags, bool]:
    root, limited = _parse(source)
    if root is None:
        return "", _Flags(nesting=limited), False
    text, flags, full = _walk(root, _collect_sheet(root), budget)
    flags.nesting = limited
    return text, flags, full
