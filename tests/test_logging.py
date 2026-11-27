import base64
import logging
from collections.abc import Iterator

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


def test_event_refuses_free_text() -> None:
    log = mflog.get_logger()
    mflog.event(log, logging.INFO, "fetch_ok", uid=7, size=120, account="work")
    with pytest.raises(ValueError, match="plain identifier"):
        mflog.event(log, logging.INFO, "fetch_ok", subject="Hello there, Bob")
    with pytest.raises(ValueError, match="plain identifier"):
        mflog.event(log, logging.INFO, "fetch_ok", folder="user@example.com")


def test_imapclient_logger_pinned(capfd: pytest.CaptureFixture[str]) -> None:
    mflog.configure_logging(logging.DEBUG)
    logging.getLogger("imapclient.imaplib").warning("server said \xff")
    out, err = capfd.readouterr()
    assert (out, err) == ("", "")
    assert logging.getLogger("imapclient").propagate is False


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
