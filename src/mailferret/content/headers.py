"""Header values, RFC 2047 words, RFC 2231 parameters and addresses (T-05, T-19, T-21).

No function here logs, and none formats a mail-derived value into an exception.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import unquote_to_bytes

from mailferret.content.charset import decode_text
from mailferret.content.truncate import Truncated, truncate_chars, truncate_utf8_bytes
from mailferret.limits import Limits

_DEFAULT_LIMITS: Final = Limits()
_MAX_INDEX_DIGITS: Final = 6
_CONTROLS: Final = dict.fromkeys([*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029], " ")
_ENCODED_WORD: Final = re.compile(r"=\?([^?\s*]+)(?:\*[^?\s]*)?\?([bBqQ])\?([^?\s]*)\?=")
_FOLD: Final = re.compile(r"\r?\n(?=[ \t])")
_PARAM_NAME: Final = re.compile(rf"([^*\s]+?)(?:\*([0-9]{{1,{_MAX_INDEX_DIGITS}}}))?(\*)?")
_ADDRESS_UNSAFE: Final = re.compile(r"[\s<>\"@,;()\x00-\x1f\x7f-\x9f]")
_NAME_SPECIALS: Final = frozenset('()<>[]:;@\\,."')
_WHITESPACE: Final = " \t\r\n"


def _strip_format(text: str) -> tuple[str, bool]:
    """Remove Cf characters (bidi controls, zero-width, BOM) that disguise displayed text."""
    if text.isascii():
        return text, False
    kept = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return kept, len(kept) != len(text)


def _clean(text: str) -> tuple[str, bool]:
    return _strip_format(text.translate(_CONTROLS))


def _header_text(raw: bytes | str, limits: Limits) -> tuple[str, bool]:
    """Bound a header input to L-05 bytes and decode it; lone surrogates become ``?``."""
    size = limits.max_header_bytes
    cut = False
    if isinstance(raw, str):
        cut = len(raw) > size
        raw = raw[:size].encode("utf-8", errors="replace")
    data, bytes_cut = truncate_utf8_bytes(raw, size)
    decoded = decode_text(data, None, partial=bytes_cut, limits=limits)
    return decoded.text, cut or bytes_cut or decoded.truncated


def _word_payload(encoding: str, payload: str) -> bytes | None:
    if encoding in "bB":
        stripped = payload.rstrip("=")
        if len(stripped) % 4 == 1 or not stripped.isascii():
            return None
        try:
            return base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
    out = bytearray()
    index = 0
    while index < len(payload):
        char = payload[index]
        if char == "_":
            out.append(0x20)
        elif char == "=" and re.fullmatch(r"[0-9A-Fa-f]{2}", payload[index + 1 : index + 3]):
            out.append(int(payload[index + 1 : index + 3], 16))
            index += 2
        elif char.isascii():
            out.append(ord(char))
        else:
            return None
        index += 1
    return bytes(out)


def _flush(group: list[tuple[str, bytes]], out: list[str], limits: Limits) -> None:
    index = 0
    while index < len(group):
        charset = group[index][0]
        end = index
        while end < len(group) and group[end][0] == charset:
            end += 1
        joined = b"".join(payload for _, payload in group[index:end])
        out.append(decode_text(joined, charset, limits=limits).text)
        index = end
    group.clear()


def _decode_words(text: str, limits: Limits) -> str:
    out: list[str] = []
    group: list[tuple[str, bytes]] = []
    pos = 0
    for match in _ENCODED_WORD.finditer(text):
        gap = text[pos : match.start()]
        payload = _word_payload(match.group(2), match.group(3))
        if not (payload is not None and group and not gap.strip(_WHITESPACE)):
            _flush(group, out, limits)
            out.append(gap)
        if payload is None:
            _flush(group, out, limits)
            out.append(match.group(0))
        else:
            group.append((match.group(1).lower(), payload))
        pos = match.end()
    _flush(group, out, limits)
    out.append(text[pos:])
    return "".join(out)


def decode_header_value(raw: bytes | str, limits: Limits = _DEFAULT_LIMITS) -> Truncated:
    """Unfold, decode RFC 2047 words and flatten controls to a bounded single line.

    Input is cut to ``max_header_bytes`` (L-05) first, output to ``max_header_value_chars``
    (L-04) last; either cut sets ``truncated``.
    """
    text, cut = _header_text(raw, limits)
    unfolded = _FOLD.sub("", text)
    decoded = _decode_words(unfolded, limits) if "=?" in unfolded else unfolded
    cleaned, stripped = _clean(decoded)
    result = truncate_chars(cleaned, limits.max_header_value_chars)
    return Truncated(result.text, result.truncated or cut, stripped)


@dataclass(frozen=True, slots=True)
class Parameters:
    values: dict[str, str]
    truncated: bool
    stripped: bool = False


@dataclass(frozen=True, slots=True)
class HeaderParameters:
    value: str
    parameters: Parameters

    @property
    def truncated(self) -> bool:
        return self.parameters.truncated

    @property
    def stripped(self) -> bool:
        return self.parameters.stripped


def _split_header(text: str) -> tuple[str, list[tuple[str, str]]]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if quoted and char == "\\" and index + 1 < len(text):
            current.append(text[index + 1])
            index += 1
        elif char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    pairs = []
    for part in parts[1:]:
        name, sep, value = part.partition("=")
        if sep and name.strip():
            pairs.append((name.strip(), value.strip()))
    return parts[0].strip(), pairs


def _percent_bytes(segment: str) -> bytes:
    return unquote_to_bytes(segment.encode("utf-8", errors="replace"))


def _assemble(segments: dict[int, tuple[bool, str]], limits: Limits) -> tuple[str, bool]:
    data = bytearray()
    charset: str | None = None
    first = True
    for _, (encoded, value) in sorted(segments.items()):
        if encoded:
            if first:
                head, sep1, rest = value.partition("'")
                _, sep2, rest = rest.partition("'")
                if sep1 and sep2:
                    charset, value = head, rest
            data += _percent_bytes(value)
        else:
            data += value.encode("utf-8", errors="replace")
        first = False
        if len(data) > limits.max_header_bytes:
            break
    kept, cut = truncate_utf8_bytes(bytes(data), limits.max_header_bytes)
    decoded = decode_text(kept, charset, partial=cut, limits=limits)
    return decoded.text, cut or decoded.truncated


def decode_parameters(
    pairs: Iterable[tuple[str | bytes, str | bytes]], limits: Limits = _DEFAULT_LIMITS
) -> Parameters:
    """Join RFC 2231 continuations and decode extended values.

    ``pairs`` are raw ``(name, value)`` parameters, as a BODYSTRUCTURE or a header yields
    them. Names are lower-cased; the first occurrence wins; indexes only order segments. Pairs past
    ``max_header_bytes`` (L-05) in total are dropped.
    """
    groups: dict[str, dict[int, tuple[bool, str]]] = {}
    truncated = False
    stripped = False
    budget = limits.max_header_bytes
    for raw_name, raw_value in pairs:
        if budget <= 0:
            truncated = True
            break
        name, name_cut = _header_text(raw_name, limits)
        value, value_cut = _header_text(raw_value, limits)
        budget -= len(name) + len(value)
        truncated = truncated or name_cut or value_cut
        match = _PARAM_NAME.fullmatch(name.lower())
        if match is None:
            continue
        base, index, star = match.groups()
        slot = groups.setdefault(base, {})
        position = int(index) if index is not None else 0
        encoded = star is not None
        existing = slot.get(position)
        if existing is None or (encoded and not existing[0]):
            slot[position] = (encoded, value)

    values: dict[str, str] = {}
    for base, segments in groups.items():
        if any(encoded for encoded, _ in segments.values()):
            text, cut = _assemble(segments, limits)
        else:
            text, cut = _assemble({i: (False, v) for i, (_, v) in segments.items()}, limits)
            if "=?" in text:
                decoded = decode_header_value(text, limits)
                text, cut = decoded.text, cut or decoded.truncated
                stripped = stripped or decoded.stripped
        cleaned, removed = _clean(text)
        result = truncate_chars(cleaned, limits.max_header_value_chars)
        values[base] = result.text
        truncated = truncated or cut or result.truncated
        stripped = stripped or removed
    return Parameters(values, truncated, stripped)


def parse_header_parameters(raw: bytes | str, limits: Limits = _DEFAULT_LIMITS) -> HeaderParameters:
    """Split a Content-Type or Content-Disposition value into its main value and parameters."""
    text, cut = _header_text(raw, limits)
    main, pairs = _split_header(_FOLD.sub("", text))
    parameters = decode_parameters(pairs, limits)
    cleaned, removed = _clean(main)
    head = truncate_chars(cleaned.lower(), limits.max_header_value_chars)
    return HeaderParameters(
        head.text,
        Parameters(
            parameters.values,
            parameters.truncated or cut or head.truncated,
            parameters.stripped or removed,
        ),
    )


class AddressLike(Protocol):
    """The fields of imapclient's ``Address``; formatted field by field, never stringified."""

    @property
    def name(self) -> bytes | str | None: ...

    @property
    def route(self) -> bytes | str | None: ...

    @property
    def mailbox(self) -> bytes | str | None: ...

    @property
    def host(self) -> bytes | str | None: ...


@dataclass(frozen=True, slots=True)
class FormattedAddress:
    name: str
    address: str
    display: str
    truncated: bool
    stripped: bool = False


def _address_part(raw: bytes | str, limits: Limits) -> Truncated:
    text, cut = _header_text(raw, limits)
    text, removed = _strip_format(text)
    text, rewritten = _ADDRESS_UNSAFE.subn("?", text)
    result = truncate_chars(text, limits.max_header_value_chars)
    return Truncated(result.text, result.truncated or cut, removed or rewritten > 0)


def _display(name: str, address: str) -> str:
    if not name:
        return address
    if any(c in _NAME_SPECIALS for c in name):
        name = '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f"{name} <{address}>"


def format_address(
    address: AddressLike, limits: Limits = _DEFAULT_LIMITS
) -> FormattedAddress | None:
    """Format one ENVELOPE address; ``None`` for a group marker or an empty entry."""
    mailbox, host, name = address.mailbox, address.host, address.name
    if mailbox is None or host is None:
        return None
    local = _address_part(mailbox, limits)
    domain = _address_part(host, limits)
    if not local.text or not domain.text:
        return None
    shown = decode_header_value(name, limits) if name is not None else Truncated("", False)
    email = f"{local.text}@{domain.text}"
    return FormattedAddress(
        shown.text,
        email,
        _display(shown.text, email),
        local.truncated or domain.truncated or shown.truncated,
        local.stripped or domain.stripped or shown.stripped,
    )


def format_addresses(
    addresses: Iterable[AddressLike] | None, limits: Limits = _DEFAULT_LIMITS
) -> list[FormattedAddress]:
    """Format an ENVELOPE address list, skipping group markers."""
    formatted = (format_address(a, limits) for a in addresses or ())
    return [a for a in formatted if a is not None]
