"""stderr-only logging with secret redaction (T-03) and no mail-derived text (T-21)."""

import base64
import logging
import re
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

REDACTED = "***"
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_COMMAND_LINE = re.compile(r"\b(?:LOGIN|AUTHENTICATE)\b", re.IGNORECASE)
_AUTH_PENDING = "[redacted: authenticate in progress]"
_LOGGER_NAME = "mailferret"

_lock = threading.Lock()
_secret_forms: set[str] = set()
_auth_depth = 0
_handler: logging.Handler | None = None


def _forms(secret: str, login: str) -> set[str]:
    quoted = secret.replace("\\", "\\\\").replace('"', '\\"')
    blob = base64.b64encode(f"\0{login}\0{secret}".encode()).decode("ascii")
    return {secret, quoted, blob}


def register_secret(secret: str, login: str) -> None:
    """Add the raw, IMAP-quoted and SASL PLAIN base64 forms of a secret for the process."""
    if not secret:
        return
    with _lock:
        _secret_forms.update(_forms(secret, login))


def clear_secrets() -> None:
    with _lock:
        _secret_forms.clear()


def redact(text: str) -> str:
    """Replace registered secret forms, and whole LOGIN/AUTHENTICATE lines."""
    with _lock:
        forms = sorted(_secret_forms, key=len, reverse=True)
    lines = []
    for line in text.split("\n"):
        if _COMMAND_LINE.search(line):
            line = REDACTED
        else:
            for form in forms:
                line = line.replace(form, REDACTED)
        lines.append(line)
    return "\n".join(lines)


@contextmanager
def authenticate_in_progress() -> Iterator[None]:
    """While active, every record is replaced whole: continuation lines carry credentials."""
    global _auth_depth
    with _lock:
        _auth_depth += 1
    try:
        yield
    finally:
        with _lock:
            _auth_depth -= 1


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        with _lock:
            pending = _auth_depth > 0
        message = _AUTH_PENDING if pending else redact(record.getMessage())
        record.msg = message
        record.args = None
        # Exception text and tracebacks carry server text (T-21).
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def event(
    logger: logging.Logger, level: int, code: str, **fields: int | float | bool | str
) -> None:
    """Log a code plus ids, sizes and durations; free-form strings are refused."""
    parts = [_checked(code, "code")]
    for key, value in fields.items():
        if isinstance(value, str):
            value = _checked(value, key)
        parts.append(f"{_checked(key, 'key')}={value}")
    logger.log(level, " ".join(parts))


def _checked(value: str, what: str) -> str:
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError(f"log {what} is not a plain identifier")
    return value


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME if name is None else f"{_LOGGER_NAME}.{name}")


def pin_imapclient_off() -> None:
    logger = logging.getLogger("imapclient")
    logger.setLevel(logging.CRITICAL + 1)
    logger.propagate = False
    logger.handlers[:] = [logging.NullHandler()]


def configure_logging(level: int = logging.WARNING) -> None:
    """Route the mailferret logger to stderr only; safe to call repeatedly."""
    global _handler
    logger = logging.getLogger(_LOGGER_NAME)
    if _handler is not None:
        logger.removeHandler(_handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _handler = handler
    pin_imapclient_off()
