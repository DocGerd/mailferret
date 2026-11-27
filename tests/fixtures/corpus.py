"""Labelled fixture access: committed .eml files plus charset cases built from bytes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Label = Literal["wellformed", "malformed", "hostile"]

EML_DIR = Path(__file__).parent / "eml"
CANARY = "MAILFERRET-CANARY"

_MALFORMED = {
    "missing_end_boundary",
    "broken_encodings",
    "header_injection",
    "delimiter_forgery",
}
_HOSTILE = {"html_hidden"}


@dataclass(frozen=True)
class Fixture:
    name: str
    raw: bytes
    label: Label


def _label(name: str) -> Label:
    if name in _HOSTILE:
        return "hostile"
    return "malformed" if name in _MALFORMED else "wellformed"


def committed() -> list[Fixture]:
    return [
        Fixture(
            p.stem, p.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"), _label(p.stem)
        )
        for p in sorted(EML_DIR.glob("*.eml"))
    ]


def _text_mail(body: bytes, content_type: str | None) -> bytes:
    headers = [b"From: user@example.com", b"To: bob@example.com", b"MIME-Version: 1.0"]
    if content_type is not None:
        headers.append(b"Content-Type: " + content_type.encode("ascii"))
    return b"\r\n".join([*headers, b"", body])


def charset_cases() -> list[Fixture]:
    umlauts = "Grüße aus München"
    cjk = "日本語のテキスト"
    cases: list[tuple[str, bytes, str | None, Label]] = [
        ("utf8_umlauts", umlauts.encode(), "text/plain; charset=utf-8", "wellformed"),
        ("utf8_cjk", cjk.encode(), "text/plain; charset=utf-8", "wellformed"),
        ("latin1", umlauts.encode("latin-1"), "text/plain; charset=iso-8859-1", "wellformed"),
        (
            "latin9",
            "Preis 5 €".encode("iso-8859-15"),
            "text/plain; charset=iso-8859-15",
            "wellformed",
        ),
        (
            "utf8_labelled_latin1",
            umlauts.encode(),
            "text/plain; charset=iso-8859-1",
            "malformed",
        ),
        (
            "cp1252_labelled_latin1",
            "“quoted” — dash".encode("cp1252"),
            "text/plain; charset=iso-8859-1",
            "malformed",
        ),
        ("shift_jis", cjk.encode("shift_jis"), "text/plain; charset=shift_jis", "wellformed"),
        ("unknown_label", b"plain ascii", "text/plain; charset=x-no-such-charset", "malformed"),
        ("invalid_utf8", b"ok \xff\xfe\xc3\x28 end", "text/plain; charset=utf-8", "malformed"),
        ("no_charset", umlauts.encode("latin-1"), "text/plain", "malformed"),
        ("no_content_type", b"bare body", None, "wellformed"),
    ]
    return [Fixture(n, _text_mail(b, ct), label) for n, b, ct, label in cases]
