import base64
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from mailferret import logging as mflog

SECRET = 'dummy"pass\\word-NOT-REAL'  # noqa: S105
LOGIN = "user@example.com"


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    mflog.clear_secrets()
    yield
    mflog.clear_secrets()
    logging.getLogger("mailferret").handlers.clear()
    mflog._handler = None


def _forms() -> list[str]:
    quoted = SECRET.replace("\\", "\\\\").replace('"', '\\"')
    blob = base64.b64encode(f"\0{LOGIN}\0{SECRET}".encode()).decode()
    return [SECRET, quoted, blob]


@pytest.mark.parametrize("form", _forms())
def test_each_secret_form_is_redacted(form: str) -> None:
    mflog.register_secret(SECRET, LOGIN)
    assert form not in mflog.redact(f"before {form} after")


def test_login_and_authenticate_lines_redacted_whole() -> None:
    out = mflog.redact('A1 LOGIN user "x"\nok\nA2 AUTHENTICATE PLAIN abc')
    assert out == "***\nok\n***"


def test_records_reach_stderr_only(capfd: pytest.CaptureFixture[str]) -> None:
    mflog.configure_logging(logging.DEBUG)
    mflog.register_secret(SECRET, LOGIN)
    log = mflog.get_logger("t")
    for form in _forms():
        log.error("leak %s", form)
    out, err = capfd.readouterr()
    assert out == ""
    assert err.count("***") == 3
    assert not any(f in err for f in _forms())


def test_continuation_lines_redacted_while_authenticating(
    capfd: pytest.CaptureFixture[str],
) -> None:
    mflog.configure_logging(logging.DEBUG)
    log = mflog.get_logger("t")
    with mflog.authenticate_in_progress():
        log.debug("+ AGVzZXIAcGFzcw==")
    log.debug("after")
    err = capfd.readouterr().err
    assert "AGVzZXI" not in err
    assert "after" in err


def test_exception_text_dropped(capfd: pytest.CaptureFixture[str]) -> None:
    mflog.configure_logging(logging.DEBUG)
    try:
        raise ValueError("NO folder-name-from-server")
    except ValueError:
        mflog.get_logger().exception("failed")
    err = capfd.readouterr().err
    assert "folder-name-from-server" not in err
    assert "Traceback" not in err


def test_event_accepts_numbers_and_allowlisted_strings(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    mflog.event(
        mflog.get_logger(), logging.INFO, "fetch_ok", uid=7, ratio=0.5, ok=True, account="work"
    )
    assert "fetch_ok uid=7 ratio=0.5 ok=True account=work" in caplog.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("folder", "Archive"),
        ("subject", "Invoice"),
        ("sender", "bob"),
        ("folder", "user@example.com"),
        ("subject", "Hello there, Bob"),
        ("account", "Hello there, Bob"),
    ],
)
def test_event_refuses_mail_strings(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=r"string|plain identifier"):
        mflog.event(mflog.get_logger(), logging.INFO, "fetch_ok", **{field: value})


@pytest.mark.parametrize("value", [b"Hello there, Bob", bytearray(b"x"), None, ["a"]])
def test_event_refuses_non_scalar_values(value: object) -> None:
    for field in ("subject", "account", "uid"):
        with pytest.raises(TypeError, match="int, float or bool"):
            mflog.event(mflog.get_logger(), logging.INFO, "fetch_ok", **{field: value})  # type: ignore[arg-type]


def test_event_refuses_bytes_under_allowlisted_key() -> None:
    with pytest.raises(TypeError):
        mflog.event(mflog.get_logger(), logging.INFO, "fetch_ok", account=b"work")  # type: ignore[arg-type]


@pytest.mark.parametrize("code", ["login", "LOGIN-failed", "x.authenticate", "authenticate"])
def test_event_refuses_codes_the_command_rule_would_swallow(code: str) -> None:
    with pytest.raises(ValueError, match="command line"):
        mflog.event(mflog.get_logger(), logging.INFO, code)


def test_event_refuses_command_words_in_fields() -> None:
    log = mflog.get_logger()
    with pytest.raises(ValueError, match="command line"):
        mflog.event(log, logging.INFO, "auth_failed", mechanism="login")
    with pytest.raises(ValueError, match="command line"):
        mflog.event(log, logging.INFO, "auth_failed", **{"login": 1})  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["mailferret.child", "thirdparty"])
@pytest.mark.parametrize("configured", [False, True])
def test_malformed_log_call_never_raises_or_leaks(
    name: str,
    configured: bool,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    if configured:
        mflog.configure_logging(logging.DEBUG)
    caplog.set_level(logging.DEBUG)
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    try:
        log.info("%d", "dummyarg-NOT-REAL")
        log.info("dummymsg-NOT-REAL %s %s", "dummyarg-NOT-REAL")
        log.info("%d", "dummyarg-NOT-REAL", exc_info=True)
    finally:
        log.setLevel(logging.NOTSET)
    seen = caplog.text + "".join(capfd.readouterr())
    assert "dummyarg-NOT-REAL" not in seen
    assert "dummymsg-NOT-REAL" not in seen
    assert "[unformattable log record]" in seen


@pytest.fixture
def _pristine_imapclient() -> Iterator[None]:
    names = ("imapclient", "imapclient.imaplib", "imapclient.x")
    loggers = [logging.getLogger(n) for n in names]
    saved = [(lg.level, lg.propagate, lg.handlers[:], lg.disabled) for lg in loggers]
    root = logging.getLogger()
    root_level = root.level
    for lg in loggers:
        lg.setLevel(logging.NOTSET)
        lg.propagate = True
        lg.handlers[:] = []
        lg.disabled = False
    try:
        yield
    finally:
        for lg, (level, propagate, handlers, disabled) in zip(loggers, saved, strict=True):
            lg.setLevel(level)
            lg.propagate = propagate
            lg.handlers[:] = handlers
            lg.disabled = disabled
        root.setLevel(root_level)


@pytest.mark.usefixtures("_pristine_imapclient")
def test_imapclient_logger_pinned() -> None:
    logging.getLogger().setLevel(logging.DEBUG)
    mflog.configure_logging(logging.DEBUG)
    logger = logging.getLogger("imapclient")
    assert logger.level == logging.CRITICAL + 1
    assert logger.propagate is False
    assert [type(h) for h in logger.handlers] == [logging.NullHandler]

    previous = logging.getLogRecordFactory()
    created: list[str] = []

    def spy(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        created.append(record.name)
        return record

    logging.setLogRecordFactory(spy)
    try:
        for name in ("imapclient", "imapclient.imaplib", "imapclient.x"):
            logging.getLogger(name).debug("server said \xff")
            logging.getLogger(name).warning("server said \xff")
            logging.getLogger(name).error("server said \xff")
    finally:
        logging.setLogRecordFactory(previous)
    assert [n for n in created if n.startswith("imapclient")] == []


def test_redaction_without_configure(caplog: pytest.LogCaptureFixture) -> None:
    mflog.register_secret(SECRET, LOGIN)
    caplog.set_level(logging.DEBUG)
    logging.getLogger("mailferret.child").error("x %s y", SECRET)
    logging.getLogger("other").error("x %s y", SECRET)
    assert SECRET not in caplog.text
    assert caplog.text.count("***") == 2


def test_secret_split_across_lines_is_redacted() -> None:
    mflog.register_secret("dummy\nsplit-NOT-REAL", LOGIN)
    assert "split-NOT-REAL" not in mflog.redact("a dummy\nsplit-NOT-REAL b")
