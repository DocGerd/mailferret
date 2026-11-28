"""T-02, T-03, T-16: mechanism choice, the isascii branch and the secret's path (A§2, A§2.2)."""

from __future__ import annotations

import base64
import logging
import traceback
from collections.abc import Iterator

import pytest

from mailferret.auth import AuthFailed
from mailferret.credentials import CredentialRejected
from mailferret.imap import TlsMode
from mailferret.logging import clear_secrets, redact
from tests.support.imap_fake import Close, Command, FakeImapServer
from tests.unit.auth.conftest import (
    BASE,
    LOGIN,
    NON_ASCII,
    OK,
    PASSWORD,
    Maker,
    Rig,
    logins,
    sasl,
)

PLAIN_ONLY = [*BASE, "LOGINDISABLED", "AUTH=PLAIN"]
PLAIN_OFFERED = [*BASE, "AUTH=PLAIN"]


@pytest.fixture(autouse=True)
def _clean_redaction_set() -> Iterator[None]:
    yield
    clear_secrets()


def _verbs(server: FakeImapServer, conn: int = 1) -> list[str]:
    return [c.verb for c in server.commands_of(conn)]


def _blob(server: FakeImapServer, conn: int = 1) -> str:
    """The continuation line after AUTHENTICATE PLAIN."""
    wire = server.wire_of(conn)
    index = next(i for i, line in enumerate(wire) if " AUTHENTICATE PLAIN" in line)
    return wire[index + 1]


def _forms(secret: str) -> list[str]:
    return [secret, secret.encode().decode("latin-1")]


def _outside_the_command(server: FakeImapServer, secret: str) -> list[str]:
    """Wire lines holding the secret that are neither the LOGIN line nor the PLAIN blob."""
    blobs = {sasl(LOGIN, secret), sasl("üser@example.com", secret)}
    return [
        line
        for line in server.wire
        if any(form in line for form in _forms(secret))
        and line.split(" ")[1:2] != ["LOGIN"]
        and line not in blobs
    ]


def _assert_exception_clean(exc: BaseException, secret: str) -> None:
    seen: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or current in seen:
            continue
        seen.append(current)
        pending += [current.__cause__, current.__context__]
        texts = [str(current), repr(current), *(str(a) for a in current.args)]
        texts.append("".join(traceback.format_exception(current)))
        for text in texts:
            assert not any(form in text for form in _forms(secret))
        tb = current.__traceback__
        while tb is not None:
            if tb.tb_frame.f_globals.get("__name__", "").startswith("mailferret"):
                for value in tb.tb_frame.f_locals.values():
                    assert not (isinstance(value, str) and secret in value)
            tb = tb.tb_next
    assert exc.__cause__ is None
    assert exc.__context__ is None


def test_login_is_the_mechanism_when_it_is_not_disabled(make_rig: Maker) -> None:
    rig = make_rig(PLAIN_OFFERED)
    rig.pool().call(lambda s: s.noop())
    assert "LOGIN" in _verbs(rig.server)
    assert "AUTHENTICATE" not in _verbs(rig.server)
    assert any(line.endswith(f'LOGIN {LOGIN} "{PASSWORD}"') for line in rig.server.wire)


def test_logindisabled_with_plain_authenticates_with_the_sasl_blob(make_rig: Maker) -> None:
    rig = make_rig(PLAIN_ONLY)
    rig.pool().call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert "AUTHENTICATE" in _verbs(rig.server)
    assert _blob(rig.server) == sasl(LOGIN, PASSWORD)
    assert base64.b64decode(_blob(rig.server)) == b"\0" + LOGIN.encode() + b"\0" + PASSWORD.encode()


def test_logindisabled_without_plain_never_asks_the_backend(make_rig: Maker) -> None:
    rig = make_rig([*BASE, "LOGINDISABLED"])
    with pytest.raises(AuthFailed) as err:
        rig.pool().call(lambda s: s.noop())
    assert err.value.reason == "no_mechanism"
    assert err.value.code == "auth_failed"
    assert rig.backend.gets == 0
    assert logins(rig.server) == 0


def test_a_non_ascii_secret_takes_plain_in_utf8(make_rig: Maker) -> None:
    rig = make_rig(PLAIN_OFFERED, secret=NON_ASCII)
    rig.pool().call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert base64.b64decode(_blob(rig.server)) == f"\0{LOGIN}\0{NON_ASCII}".encode()
    assert _outside_the_command(rig.server, NON_ASCII) == []


def test_a_non_ascii_login_takes_plain_in_utf8(make_rig: Maker) -> None:
    login = "üser@example.com"
    rig = make_rig(PLAIN_OFFERED, secret=None)
    rig.store(PASSWORD, login)
    rig.pool(login).call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert base64.b64decode(_blob(rig.server)) == f"\0{login}\0{PASSWORD}".encode()


@pytest.mark.parametrize("login", ["first last@example.com", 'a"b@example.com', "a(b)@example.com"])
def test_a_login_that_is_not_a_bare_atom_takes_plain(make_rig: Maker, login: str) -> None:
    rig = make_rig(PLAIN_OFFERED, secret=None)
    rig.store(PASSWORD, login)
    rig.pool(login).call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert base64.b64decode(_blob(rig.server)) == f"\0{login}\0{PASSWORD}".encode()


@pytest.mark.parametrize("secret", ['qu"ote', "back\\slash"])
def test_ascii_secrets_with_specials_stay_on_login_and_are_quoted(
    make_rig: Maker, secret: str
) -> None:
    rig = make_rig(PLAIN_OFFERED, secret=secret)
    rig.pool().call(lambda s: s.noop())
    quoted = secret.replace("\\", "\\\\").replace('"', '\\"')
    assert any(line.endswith(f'LOGIN {LOGIN} "{quoted}"') for line in rig.server.wire)


def test_a_control_character_in_the_secret_takes_plain(make_rig: Maker) -> None:
    rig = make_rig(PLAIN_OFFERED, secret="tab\tsecret")  # noqa: S106  # pii-check: ignore
    rig.pool().call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert base64.b64decode(_blob(rig.server)) == f"\0{LOGIN}\0tab\tsecret".encode()


def test_a_non_ascii_secret_without_plain_is_refused_with_fixed_text(make_rig: Maker) -> None:
    rig = make_rig(BASE, secret=NON_ASCII)
    with pytest.raises(AuthFailed) as err:
        rig.pool().call(lambda s: s.noop())
    assert err.value.reason == "needs_plain"
    assert "AUTHENTICATE PLAIN" in str(err.value)
    _assert_exception_clean(err.value, NON_ASCII)
    assert logins(rig.server) == 0
    assert _outside_the_command(rig.server, NON_ASCII) == []
    assert not any(NON_ASCII in line for line in rig.server.wire)


def test_a_non_ascii_login_without_plain_is_refused_before_the_backend_is_asked(
    make_rig: Maker,
) -> None:
    login = "üser@example.com"
    rig = make_rig(BASE, secret=None)
    rig.store(PASSWORD, login)
    with pytest.raises(AuthFailed) as err:
        rig.pool(login).call(lambda s: s.noop())
    assert err.value.reason == "needs_plain"
    assert rig.backend.gets == 0
    assert logins(rig.server) == 0


@pytest.mark.parametrize("secret", ["", "one\ntwo", "one\rtwo", "one\0two"])
def test_a_secret_the_rule_would_refuse_sends_nothing(make_rig: Maker, secret: str) -> None:
    rig = make_rig(PLAIN_OFFERED, secret=secret)
    with pytest.raises(CredentialRejected):
        rig.pool().call(lambda s: s.noop())
    assert logins(rig.server) == 0
    assert all(NON_ASCII not in line and "two" not in line for line in rig.server.wire)


@pytest.mark.parametrize("secret", [PASSWORD, NON_ASCII])
@pytest.mark.parametrize("outcome", ["ok", "rejected", "dropped"])
def test_the_secret_is_only_in_the_login_command(
    make_rig: Maker,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    secret: str,
    outcome: str,
) -> None:
    rig = make_rig(PLAIN_OFFERED, secret=secret)
    if outcome == "rejected":
        rig.server.on("LOGIN", ["{tag} NO [AUTHENTICATIONFAILED] server-detail\r\n"])
        rig.server.on("AUTHENTICATE", ["{tag} NO [AUTHENTICATIONFAILED] server-detail\r\n"])
    elif outcome == "dropped":
        rig.server.on("LOGIN", [Close()])
        rig.server.on("AUTHENTICATE", [Close()])
    caplog.set_level(logging.DEBUG)
    pool = rig.pool()
    failure: Exception | None = None
    try:
        pool.call(lambda s: s.noop())
    except Exception as exc:
        failure = exc
    assert (failure is None) == (outcome == "ok")
    if failure is not None:
        assert "server-detail" not in str(failure)
        _assert_exception_clean(failure, secret)
    assert _outside_the_command(rig.server, secret) == []
    captured = capsys.readouterr()
    for text in (caplog.text, captured.out, captured.err):
        assert not any(form in text for form in _forms(secret))
        assert sasl(LOGIN, secret) not in text
    assert redact(secret) == "***"


def test_after_a_failed_login_the_unauthenticated_session_is_not_reused(
    make_rig: Maker,
) -> None:
    rig = make_rig(secret=None)
    pool = rig.pool()
    with pytest.raises(Exception, match="no credential"):
        pool.call(lambda s: s.examine("INBOX"))
    rig.store(PASSWORD)
    pool.call(lambda s: s.examine("INBOX"))
    assert rig.server.connections == 2
    assert set(_verbs(rig.server, 1)) <= {"CAPABILITY", "LOGOUT"}
    assert "LOGIN" in _verbs(rig.server, 2)
    assert "EXAMINE" in _verbs(rig.server, 2)


def test_a_backend_failure_sets_no_marker_and_is_not_a_rejection(make_rig: Maker) -> None:
    rig = make_rig(secret=None)
    with pytest.raises(Exception, match="no credential"):
        rig.pool().call(lambda s: s.noop())
    rig.store(PASSWORD)
    rig.pool().call(lambda s: s.noop())
    assert logins(rig.server) == 1


def test_a_successful_login_registers_the_secret_and_re_reads_capabilities(
    make_rig: Maker,
) -> None:
    rig = make_rig()

    def login(cmd: Command) -> list[str]:
        rig.server.capabilities.append("IDLE")
        return [OK]

    rig.server.on("LOGIN", login)
    pool = rig.pool()
    assert pool.call(lambda s: s.capabilities.idle) is True
    verbs = _verbs(rig.server)
    assert verbs.index("CAPABILITY", verbs.index("LOGIN")) > verbs.index("LOGIN")
    assert redact(PASSWORD) == "***"
    assert redact(f'A9 LOGIN {LOGIN} "x"') == "***"


class _Phase:
    """Capabilities that differ before and after STARTTLS, in a reply keyed by the connection."""

    def __init__(self, server: FakeImapServer, pre: list[str], post: list[str]) -> None:
        self.server, self.pre, self.post = server, pre, post

    def __call__(self, cmd: Command) -> list[str]:
        tls = any(c.verb == "STARTTLS" and c.conn == cmd.conn for c in self.server.commands)
        return [f"* CAPABILITY {' '.join(self.post if tls else self.pre)}\r\n", OK]


def _starttls_rig(make_rig: Maker, pre: list[str], post: list[str]) -> Rig:
    rig = make_rig(implicit_tls=False)
    rig.server.on("CAPABILITY", _Phase(rig.server, [*pre, "STARTTLS"], post))
    return rig


def test_only_the_post_tls_capabilities_choose_the_mechanism(make_rig: Maker) -> None:
    rig = _starttls_rig(make_rig, [*BASE, "LOGINDISABLED"], BASE)
    rig.pool(mode=TlsMode.STARTTLS).call(lambda s: s.noop())
    assert "LOGIN" in _verbs(rig.server)

    rig = _starttls_rig(make_rig, BASE, PLAIN_ONLY)
    rig.pool(mode=TlsMode.STARTTLS).call(lambda s: s.noop())
    assert "LOGIN" not in _verbs(rig.server)
    assert "AUTHENTICATE" in _verbs(rig.server)

    rig = _starttls_rig(make_rig, [*BASE, "LOGINDISABLED", "AUTH=PLAIN"], [*BASE, "LOGINDISABLED"])
    with pytest.raises(AuthFailed) as err:
        rig.pool(mode=TlsMode.STARTTLS).call(lambda s: s.noop())
    assert err.value.reason == "no_mechanism"
    assert logins(rig.server) == 0
    assert rig.backend.gets == 0
