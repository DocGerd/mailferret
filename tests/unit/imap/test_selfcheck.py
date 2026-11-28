"""R5: the hook set checks itself, and every hook that does not run aborts before LOGIN."""

from __future__ import annotations

import imaplib
import logging
import re
import socket
from collections.abc import Callable
from typing import Any

import pytest
from imapclient import IMAPClient
from imapclient.imap4 import IMAP4WithTimeout
from imapclient.tls import IMAP4_TLS

from mailferret.imap import ConnectError, DeadlineExceeded, HookBypassed, TlsMode, connect
from mailferret.imap.guard import GuardMixin
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.logging_pin import logging_is_pinned, pin_imapclient_logging
from mailferret.imap.selfcheck import check_hooks, check_instance
from mailferret.imap.transport import GuardedPlain, GuardedTLS, _Client
from mailferret.limits import Limits
from tests.support.imap_fake import FakeImapServer, TlsMaterial
from tests.unit.imap.conftest import HOST, Opener
from tests.unit.imap.support import arm, make_sink


def _no_login(server: FakeImapServer) -> None:
    assert not any(c.verb in {"LOGIN", "AUTHENTICATE"} for c in server.commands)


def _reshaped(self: Any, extra: object) -> None:  # pragma: no cover - never called
    raise AssertionError


def _refused(server: FakeImapServer, tls: TlsMaterial, mode: TlsMode = TlsMode.IMPLICIT) -> str:
    with pytest.raises(ConnectError) as err:
        connect(HOST, server.port, mode, ca_file=tls.cert_file, limits=Limits())
    return err.value.code


@pytest.mark.parametrize(
    "name", ["_new_tag", "send", "_command", "read", "readline", "_command_complete"]
)
def test_a_missing_imaplib_hook_refuses_to_connect(
    name: str, server: FakeImapServer, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(imaplib.IMAP4, name)
    assert _refused(server, tls_material) == "hook_unavailable"
    assert server.connections == 0


@pytest.mark.parametrize(
    "name", ["_new_tag", "send", "_command", "read", "readline", "_command_complete"]
)
def test_a_reshaped_imaplib_hook_refuses_to_connect(
    name: str, server: FakeImapServer, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(imaplib.IMAP4, name, _reshaped)
    assert _refused(server, tls_material) == "hook_unavailable"
    assert server.connections == 0


@pytest.mark.parametrize("value", [None, "1000000", 1.5, True])
def test_a_changed_maxline_refuses_to_connect(
    value: object,
    server: FakeImapServer,
    tls_material: TlsMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(imaplib, "_MAXLINE", value)
    assert _refused(server, tls_material) == "hook_unavailable"
    assert server.connections == 0


def test_a_missing_maxline_refuses_to_connect(
    server: FakeImapServer, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(imaplib, "_MAXLINE")
    assert _refused(server, tls_material) == "hook_unavailable"


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        (IMAPClient, "_create_IMAP4"),
        (IMAPClient, "has_capability"),
        (IMAP4WithTimeout, "__init__"),
        (IMAP4_TLS, "__init__"),
        (IMAP4WithTimeout, "_create_socket"),
        (IMAP4_TLS, "_create_socket"),
    ],
)
def test_a_missing_or_reshaped_imapclient_hook_refuses_to_connect(
    owner: type,
    name: str,
    server: FakeImapServer,
    tls_material: TlsMaterial,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(owner, name, _reshaped)
    assert _refused(server, tls_material) == "hook_unavailable"
    assert server.connections == 0


def test_check_hooks_passes_on_the_installed_stack() -> None:
    check_hooks()


def test_the_mixin_keeps_imaplibs_signatures() -> None:
    """The self-check compares them: a mixin that drifted would refuse every connection."""
    for name in ("_new_tag", "send", "_command", "read", "readline", "_command_complete"):
        assert callable(getattr(GuardMixin, name))


def test_instance_checks_cover_class_dict_debug_timeouts_and_logging(
    opener: Opener, server: FakeImapServer
) -> None:
    session = opener(server)
    imap = session._imap
    limits = Limits()
    check_instance(imap, limits)
    with pytest.raises(ConnectError):
        check_instance(object(), limits)
    with pytest.raises(ConnectError):
        check_instance(imap, Limits(imap_connect_seconds=7))
    with pytest.raises(ConnectError):
        check_instance(imap, Limits(imap_read_seconds=7))
    imap.untagged_responses = []
    with pytest.raises(ConnectError):
        check_instance(imap, limits)
    imap.untagged_responses = {}
    logging.getLogger("imapclient").setLevel(logging.WARNING)
    with pytest.raises(ConnectError):
        check_instance(imap, limits)
    pin_imapclient_logging()
    check_instance(imap, limits)


def test_debug_is_pinned_to_zero_after_imapclient_sets_it(
    opener: Opener, server: FakeImapServer
) -> None:
    session = opener(server)
    assert session._imap.debug == 0
    session._imap.debug = 5
    assert session._imap.debug == 0
    assert session._client._imap is session._imap


def test_an_unpinned_debug_refuses_before_login(
    server: FakeImapServer, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(GuardMixin, "debug", 5)
    assert _refused(server, tls_material) == "hook_unavailable"
    _no_login(server)


def test_connect_pins_the_logger_before_the_client_exists(
    server: FakeImapServer, tls_material: TlsMaterial
) -> None:
    logging.getLogger("imapclient").setLevel(logging.DEBUG)
    logging.getLogger("imapclient").propagate = True
    assert not logging_is_pinned()
    connect(
        HOST, server.port, TlsMode.IMPLICIT, ca_file=tls_material.cert_file, limits=Limits()
    ).close()
    assert logging_is_pinned()


# One stub per hook. Each leaves the hook in place but makes it not run; the session aborts
# before LOGIN: no LOGIN or AUTHENTICATE reaches the wire.


class _SkipGreeting:
    first = True

    def readline(self) -> bytes:
        if self.first:  # type: ignore[attr-defined]
            self.first = False  # type: ignore[attr-defined]
            return imaplib.IMAP4.readline(self)  # type: ignore[arg-type]
        return super().readline()  # type: ignore[misc, no-any-return]


class _RawSend:
    def send(self, data: bytes) -> None:
        self.sock.sendall(data)  # type: ignore[attr-defined]


class _SkipComplete:
    def _command_complete(self, name: str, tag: bytes) -> Any:
        return imaplib.IMAP4._command_complete(self, name, tag)  # type: ignore[arg-type]


class _NoPublish:
    def _publish(self, sock: Any) -> Any:
        return sock


class _NoProbeStarttls:
    def _command_complete(self, name: str, tag: bytes) -> Any:
        if name == "STARTTLS":
            return imaplib.IMAP4._command_complete(self, name, tag)  # type: ignore[arg-type]
        return super()._command_complete(name, tag)  # type: ignore[misc]


def _stubbed(stub: type, monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    monkeypatch.setattr(_Client, "_plain_cls", type("PlainStub", (stub, GuardedPlain), {}))
    monkeypatch.setattr(_Client, "_tls_cls", type("TlsStub", (stub, GuardedTLS), {}))
    return lambda: None


@pytest.mark.parametrize(
    ("stub", "mode"),
    [
        (_SkipGreeting, TlsMode.IMPLICIT),
        (_SkipGreeting, TlsMode.STARTTLS),
        (_RawSend, TlsMode.IMPLICIT),
        (_RawSend, TlsMode.STARTTLS),
        (_SkipComplete, TlsMode.IMPLICIT),
        (_SkipComplete, TlsMode.STARTTLS),
        (_NoProbeStarttls, TlsMode.STARTTLS),
    ],
)
def test_a_hook_that_does_not_run_aborts_the_session_before_login(
    stub: type, mode: TlsMode, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stubbed(stub, monkeypatch)
    with FakeImapServer(tls=tls_material, implicit_tls=mode is TlsMode.IMPLICIT) as server:
        with pytest.raises(ConnectError) as err:
            connect(HOST, server.port, mode, ca_file=tls_material.cert_file, limits=Limits())
        assert err.value.code == "hook_bypassed"
        _no_login(server)


def test_the_unstubbed_session_passes_the_same_liveness_checks(
    server: FakeImapServer, opener: Opener
) -> None:
    session = opener(server)
    session._imap.verify_liveness(starttls=False)


def test_a_session_with_no_probe_flag_fails_liveness_for_starttls(
    server: FakeImapServer, opener: Opener
) -> None:

    session = opener(server)
    with pytest.raises(HookBypassed) as err:
        session._imap.verify_liveness(starttls=True)
    assert err.value.check == "starttls_probe"


def test_the_starttls_probe_flag_is_set_by_a_clean_upgrade(
    fake_imap_tls: FakeImapServer, tls_material: TlsMaterial
) -> None:
    session = connect(
        HOST, fake_imap_tls.port, TlsMode.STARTTLS, ca_file=tls_material.cert_file, limits=Limits()
    )
    try:
        assert session._imap._mf.starttls_probed
    finally:
        session.close()


def test_leftover_pre_tls_untagged_entries_are_cleared_after_starttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mailferret.imap.guard.bytes_pending", lambda _imap: False)
    imap = make_sink(incoming=[b"* 3 EXISTS\r\n", b"A0 OK begin TLS\r\n"])
    tag = arm(imap)
    imap.send(tag + b" STARTTLS\r\n")
    imap._command_complete("STARTTLS", tag)
    assert imap.untagged_responses == {}
    assert imap._mf.starttls_probed


def _no_groups() -> re.Pattern[bytes]:
    return re.compile(rb"(A\d+) ([A-Z]+) (.*)")


@pytest.mark.parametrize("replacement", [None, "missing", b"A1 OK", _no_groups()])
def test_a_missing_or_reshaped_tagre_fails_the_instance_check(
    opener: Opener, server: FakeImapServer, replacement: object
) -> None:
    imap = opener(server)._imap
    if replacement == "missing":
        del imap.tagre
    else:
        imap.tagre = replacement
    with pytest.raises(ConnectError) as err:
        check_instance(imap, Limits())
    assert err.value.code == "hook_unavailable"


@pytest.mark.parametrize("replacement", [None, "missing", _no_groups()])
def test_a_missing_or_reshaped_tagre_discards_the_session_at_the_next_line(
    replacement: object,
) -> None:
    imap = make_sink(incoming=[b"A1 OK done\r\n"])
    if replacement == "missing":
        del imap.tagre
    else:
        imap.tagre = replacement  # type: ignore[assignment]
    arm(imap)
    with pytest.raises(HookBypassed) as err:
        imap.readline()
    assert err.value.check == "tagre"
    assert imap.discarded


@pytest.mark.parametrize("mode", [TlsMode.IMPLICIT, TlsMode.STARTTLS])
def test_a_socket_that_never_reached_the_deadline_handle_aborts_the_connect(
    mode: TlsMode, tls_material: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stubbed(_NoPublish, monkeypatch)
    with FakeImapServer(tls=tls_material, implicit_tls=mode is TlsMode.IMPLICIT) as server:
        with pytest.raises(ConnectError) as err:
            connect(
                HOST,
                server.port,
                mode,
                ca_file=tls_material.cert_file,
                limits=Limits(),
                handle=ConnectHandle(),
            )
        assert err.value.code == "hook_bypassed"
        _no_login(server)


def test_the_handle_refuses_a_socket_after_shutdown_and_releases_its_duplicate() -> None:
    handle = ConnectHandle()
    first, peer = socket.socketpair()
    handle.register(first)
    handle.shutdown()
    assert peer.recv(1) == b""
    late, _ = socket.socketpair()
    with pytest.raises(DeadlineExceeded):
        handle.register(late)
    handle.release()
    first.close()
    peer.close()
    late.close()
