"""Hypothesis strategies for fuzzing the pure content/ and aliases/ functions."""

from __future__ import annotations

import base64

from hypothesis import strategies as st

from tests.fixtures import corpus

KNOWN_CHARSETS = ["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252", "shift_jis", "ascii"]

charset_labels = st.one_of(
    st.sampled_from(KNOWN_CHARSETS),
    st.sampled_from(["", "x-unknown", "UTF8", "utf-8 ", '"utf-8"', "latin1", "unicode-1-1-utf-7"]),
    st.text(max_size=20),
)

arbitrary_bytes = st.binary(max_size=2048)


@st.composite
def encoded_words(draw: st.DrawFn) -> str:
    charset = draw(charset_labels)
    payload = draw(st.binary(max_size=40))
    if draw(st.booleans()):
        enc, text = "B", base64.b64encode(payload).decode("ascii")
    else:
        enc, text = "Q", "".join(f"={b:02X}" for b in payload)
    if draw(st.booleans()):
        text = text[: draw(st.integers(0, len(text)))]
    return f"=?{charset}?{enc}?{text}?="


@st.composite
def header_values(draw: st.DrawFn) -> str:
    pieces = draw(
        st.lists(
            st.one_of(encoded_words(), st.text(max_size=20), st.sampled_from(["\r\n ", "\t", " "])),
            max_size=6,
        )
    )
    return "".join(pieces)


@st.composite
def rfc2231_parameters(draw: st.DrawFn) -> str:
    n = draw(st.integers(0, 4))
    charset = draw(charset_labels)
    parts = []
    for i in range(n + 1):
        value = "".join(f"%{b:02X}" for b in draw(st.binary(max_size=8)))
        prefix = f"{charset}''" if i == 0 else ""
        parts.append(f"filename*{i}*={prefix}{value}")
    if draw(st.booleans()):
        parts = parts[: draw(st.integers(0, len(parts)))]
    return "; ".join(parts)


_local = st.from_regex(r"[a-z0-9]{1,8}", fullmatch=True)
_domain = st.sampled_from(["example.com", "alias.example.com", "shop.example.com", "EXAMPLE.com"])


@st.composite
def addresses(draw: st.DrawFn) -> str:
    local = draw(_local)
    if draw(st.booleans()):
        local += "+" + draw(_local)
    return f"{local}@{draw(_domain)}"


@st.composite
def alias_headers(draw: st.DrawFn) -> dict[str, list[str]]:
    names = ["Delivered-To", "X-Original-To", "To", "Cc", "Bcc", "Envelope-To"]
    headers: dict[str, list[str]] = {}
    for name in draw(st.lists(st.sampled_from(names), unique=True, max_size=len(names))):
        headers[name] = draw(st.lists(addresses(), min_size=1, max_size=3))
    return headers


@st.composite
def mutated_mail(draw: st.DrawFn) -> bytes:
    raw = draw(st.sampled_from([f.raw for f in corpus.committed() + corpus.charset_cases()]))
    start = draw(st.integers(0, len(raw)))
    end = draw(st.integers(start, min(len(raw), start + 64)))
    return raw[:start] + draw(st.binary(max_size=64)) + raw[end:]


mime_bytes = st.one_of(arbitrary_bytes, mutated_mail())
