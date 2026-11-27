"""stderr-only logging with secret redaction (T-03) and no mail-derived text (T-21)."""

import base64
import logging
import re
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

REDACTED = "***"
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
# Closed set of str-valued keys: configured ids and protocol tokens, never mail data.
_STR_KEYS = frozenset({"account", "mechanism", "limit"})
_COMMAND_LINE = re.compile(r"\b(?:LOGIN|AUTHENTICATE)\b", re.IGNORECASE)
_AUTH_PENDING = "[redacted: authenticate in progress]"
_UNFORMATTABLE = "[unformattable log record]"
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
    for form in forms:
        text = text.replace(form, REDACTED)
    return "\n".join(REDACTED if _COMMAND_LINE.search(line) else line for line in text.split("\n"))


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


def _message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception:
        return _UNFORMATTABLE


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        with _lock:
            pending = _auth_depth > 0
        message = _AUTH_PENDING if pending else redact(_message(record))
        record.msg = message
        record.args = None
        # Exception text and tracebacks carry server text (T-21).
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


_factory_marker = "_mailferret_redacting"


def _install_record_factory() -> None:
    """Redact at record creation so no logger, configured or not, can emit a raw secret."""
    previous = logging.getLogRecordFactory()
    if getattr(previous, _factory_marker, False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        RedactionFilter().filter(record)
        return record

    setattr(factory, _factory_marker, True)
    logging.setLogRecordFactory(factory)


_install_record_factory()


def event(
    logger: logging.Logger, level: int, code: str, **fields: int | float | bool | str
) -> None:
    """Log a code plus ids, sizes and durations.

    Values must be int, float or bool; str only under a key in _STR_KEYS. Everything else,
    bytes included, is refused, as is any token the LOGIN/AUTHENTICATE rule would swallow.
    """
    parts = [_checked(code, "code")]
    for key, value in fields.items():
        if isinstance(value, str):
            if key not in _STR_KEYS:
                raise ValueError(f"log field {key!r} may not hold a string")
            value = _checked(value, key)
        elif not isinstance(value, int | float):
            raise TypeError(f"log field {key!r} must be int, float or bool")
        parts.append(f"{_checked(key, 'key')}={value}")
    logger.log(level, " ".join(parts))


def _checked(value: str, what: str) -> str:
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError(f"log {what} is not a plain identifier")
    if _COMMAND_LINE.search(value):
        raise ValueError(f"log {what} would be redacted as a command line")
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
