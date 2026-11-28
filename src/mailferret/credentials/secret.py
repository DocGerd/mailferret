"""``Secret`` wrapper and the secret-acceptance rule (T-02)."""

from __future__ import annotations

from typing import NoReturn

from mailferret.credentials.errors import CredentialRejected

REDACTED = "***"
_FORBIDDEN = frozenset("\r\n\0")


class Secret:
    """Holds a secret; ``repr``, ``str`` and ``format`` are redacted."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        value: str = object.__getattribute__(self, "_value")
        return value

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Secret is immutable")

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        return REDACTED

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be serialised")

    def __bool__(self) -> bool:
        return bool(self.reveal())

    __hash__ = None  # type: ignore[assignment]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self.reveal() == other.reveal()


def _strip_one_line_ending(raw: bytes) -> bytes:
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n"):
        return raw[:-1]
    return raw


def accept_output(raw: bytes, *, strip: bool = True) -> Secret:
    """Apply the rule to the stdout of a process that exited 0 with every reader at EOF.

    One trailing line ending is stripped; the rest must be non-empty UTF-8 without CR, LF or NUL.
    """
    body = _strip_one_line_ending(raw) if strip else raw
    text: str | None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or not text or _FORBIDDEN.intersection(text):
        raise CredentialRejected from None
    return Secret(text)


def validate_new_secret(value: str | Secret, max_stdout_bytes: int) -> Secret:
    """Refuse before any spawn a secret ``get`` would refuse (L-22 counts the line ending)."""
    text = value.reveal() if isinstance(value, Secret) else value
    encoded: bytes | None
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        encoded = None
    if encoded is None or len(encoded) + 1 > max_stdout_bytes:
        raise CredentialRejected from None
    return accept_output(encoded, strip=False)
