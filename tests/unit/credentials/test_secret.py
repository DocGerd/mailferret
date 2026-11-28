from __future__ import annotations

import copy
import logging
import pickle

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mailferret.credentials import (
    CredentialRejected,
    EntryKey,
    Secret,
    accept_output,
    validate_new_secret,
)
from mailferret.credentials.errors import (
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialTimeout,
)
from mailferret.limits import CEILINGS

CAP = CEILINGS["credential_command_output_bytes"]
VALUE = 's3cr3t-é"\\'


def test_secret_is_redacted_everywhere(caplog: pytest.LogCaptureFixture) -> None:
    secret = Secret(VALUE)
    assert repr(secret) == "Secret(***)"
    assert str(secret) == "***"
    assert f"{secret}" == "***"
    assert f"{secret:>20}" == "***"
    assert "%s %r" % (secret, secret) == "*** Secret(***)"  # noqa: UP031
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("t").debug("%s %r", secret, secret)
    assert VALUE not in caplog.text
    assert VALUE not in repr([secret]) + repr({"k": secret})


def test_secret_is_not_serialisable_or_mutable() -> None:
    secret = Secret(VALUE)
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        copy.deepcopy(secret)
    with pytest.raises(AttributeError):
        secret.x = 1  # type: ignore[attr-defined]
    assert secret.reveal() == VALUE


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"pw\n", "pw"),
        (b"pw\r\n", "pw"),
        (b"pw", "pw"),
        (b" pw \n", " pw "),
        ("pwé\n".encode(), "pwé"),
    ],
)
def test_accept_output_strips_one_line_ending(raw: bytes, expected: str) -> None:
    assert accept_output(raw).reveal() == expected


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n",
        b"\r\n",
        b"pw\n\n",
        b"pw\r\n\n",
        b"a\nlogin: x\n",
        b"a\rb",
        b"a\0b",
        b"pw\0\n",
        b"\xff\xfe\n",
    ],
)
def test_accept_output_refuses(raw: bytes) -> None:
    with pytest.raises(CredentialRejected) as info:
        accept_output(raw)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__
    assert info.value.args == (CredentialRejected.message,)


@given(st.text(min_size=1).filter(lambda s: not set(s) & set("\r\n\0")))
def test_accepted_text_round_trips(text: str) -> None:
    try:
        encoded = text.encode()
    except UnicodeEncodeError:
        return
    if len(encoded) + 1 > CAP:
        return
    assert validate_new_secret(text, CAP).reveal() == text
    assert accept_output(encoded + b"\n").reveal() == text


@given(st.text(), st.sampled_from("\r\n\0"), st.text())
def test_forbidden_characters_are_refused_without_leaking(head: str, bad: str, tail: str) -> None:
    value = head + bad + tail
    with pytest.raises(CredentialRejected) as info:
        validate_new_secret(value, CAP)
    assert str(info.value) == CredentialRejected.message
    assert info.value.args == (CredentialRejected.message,)


@pytest.mark.parametrize("value", ["", "\n", "a\nb", "a\rb", "a\0b", "x" * CAP, "\ud800"])
def test_validate_new_secret_refuses_before_spawn(value: str) -> None:
    with pytest.raises(CredentialRejected):
        validate_new_secret(value, CAP)
    with pytest.raises(CredentialRejected):
        validate_new_secret(Secret(value), CAP)


def test_validate_new_secret_limit_counts_line_ending() -> None:
    assert validate_new_secret("x" * (CAP - 1), CAP)
    with pytest.raises(CredentialRejected):
        validate_new_secret("x" * CAP, CAP)


@pytest.mark.parametrize(
    "cls",
    [
        CredentialBackendError,
        CredentialBackendUnavailable,
        CredentialLimitExceeded,
        CredentialLocked,
        CredentialNotFound,
        CredentialRejected,
        CredentialTimeout,
    ],
)
def test_errors_take_no_arguments_and_have_fixed_text(cls: type[CredentialError]) -> None:
    with pytest.raises(TypeError):
        cls(VALUE)  # type: ignore[call-arg]
    assert cls().args == (cls.message,)
    assert str(cls()) == cls.message


def test_unavailable_hints_at_doctor() -> None:
    assert "doctor" in str(CredentialBackendUnavailable())


def test_entry_key() -> None:
    key = EntryKey("work", "user", "imap.example.com")
    assert key.service == "mailferret/work"
    assert key.username == "user@imap.example.com"
    for bad in ({"login": "a\nb"}, {"host": "h\0"}, {"account_id": ""}):
        args = {"account_id": "work", "login": "user", "host": "imap.example.com", **bad}
        with pytest.raises(CredentialRejected):
            EntryKey(**args)
