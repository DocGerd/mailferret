"""Connect: implicit TLS or STARTTLS, never plaintext, and always behind the guard (A§2.2)."""

from __future__ import annotations

import contextlib
import imaplib
import socket
import ssl
from pathlib import Path
from typing import Any

from imapclient import IMAPClient  # type: ignore[import-untyped]
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from imapclient.imap4 import IMAP4WithTimeout  # type: ignore[import-untyped]
from imapclient.imapclient import SocketTimeout  # type: ignore[import-untyped]
from imapclient.tls import IMAP4_TLS, wrap_socket  # type: ignore[import-untyped]

from mailferret.imap.capabilities import Capabilities, parse_capabilities
from mailferret.imap.errors import ConnectError, HookBypassed, LimitBreach, ReadOnlyViolation
from mailferret.imap.guard import GuardMixin, apply_line_cap
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.logging_pin import pin_imapclient_logging
from mailferret.imap.probe import NoProbe, PreTlsBytes, client_buffer
from mailferret.imap.selfcheck import check_hooks, check_instance
from mailferret.imap.session import ReadOnlySession
from mailferret.imap.tls import TlsMode, build_context
from mailferret.limits import Limits


class GuardedPlain(GuardMixin, IMAP4WithTimeout):  # type: ignore[misc]
    """Plain-socket IMAP4 (STARTTLS); the STARTTLS probe lives in the mixin."""

    def _create_socket(self, timeout: float | None = None) -> socket.socket:
        sock = socket.create_connection(
            (self.host, self.port), timeout if timeout is not None else self._timeout
        )
        return self._publish(sock)


class GuardedTLS(GuardMixin, IMAP4_TLS):  # type: ignore[misc]
    """Implicit-TLS IMAP4, which is not an ``IMAP4WithTimeout`` and needs the mixin too."""

    def _create_socket(self, timeout: float | None = None) -> socket.socket:
        sock = socket.create_connection(
            (self.host, self.port), timeout=timeout if timeout is not None else self._timeout
        )
        self._publish(sock)
        return wrap_socket(sock, self.ssl_context, self.host)  # type: ignore[no-any-return]


class _Client(IMAPClient):  # type: ignore[misc]
    _plain_cls: type[GuardMixin] = GuardedPlain
    _tls_cls: type[GuardMixin] = GuardedTLS

    def __init__(
        self, *args: Any, limits: Limits, handle: ConnectHandle | None, **kwargs: Any
    ) -> None:
        self._mf_limits = limits
        self._mf_handle = handle
        super().__init__(*args, **kwargs)

    def _create_IMAP4(self) -> Any:
        if self.stream:
            raise ConnectError("hook_unavailable")
        connect_timeout = getattr(self._timeout, "connect", None)
        if self.ssl:
            return self._tls_cls(
                self.host,
                self.port,
                self.ssl_context,
                connect_timeout,
                limits=self._mf_limits,
                handle=self._mf_handle,
            )
        return self._plain_cls(
            self.host, self.port, connect_timeout, limits=self._mf_limits, handle=self._mf_handle
        )

    def has_capability(self, capability: str | bytes) -> bool:
        """Hide ``LITERAL+`` so imapclient sends every literal synchronously (A§6)."""
        name = (
            capability.decode("ascii", "replace") if isinstance(capability, bytes) else capability
        )
        if name.upper() == "LITERAL+":
            return False
        return bool(super().has_capability(capability))


def _shutdown(client: Any) -> None:
    with contextlib.suppress(Exception):
        client.shutdown()


def _starttls(client: Any, ctx: ssl.SSLContext) -> Capabilities:
    """Upgrade; returns the capabilities imaplib re-read after the wrap, never the pre-TLS ones."""
    imap = client._imap
    try:
        client_buffer(imap)
    except NoProbe:
        raise ConnectError("hook_unavailable") from None
    if not parse_capabilities(client.capabilities()).starttls:
        raise ConnectError("starttls_unavailable")
    try:
        client.starttls(ctx)
    except PreTlsBytes:
        raise ConnectError("pre_tls_bytes") from None
    except (imaplib.IMAP4.error, IMAPClientError):
        raise ConnectError("starttls_refused") from None
    return parse_capabilities(imap.capabilities)


def connect(
    host: str,
    port: int,
    mode: TlsMode,
    *,
    limits: Limits,
    ca_file: Path | None = None,
    handle: ConnectHandle | None = None,
) -> ReadOnlySession:
    """Open a verified TLS session or raise ``ConnectError``; no credential is ever sent.

    The returned session is unauthenticated and guarded: every hook has run, and the hook set,
    the logging pin and the timeouts were checked first. DNS resolution is not bounded by
    ``L-11``, and neither is the TCP connect to each address. From the TLS handshake on,
    ``handle.shutdown()`` (the caller's `L-13` deadline) interrupts this call. A ``handle`` that
    no socket was registered with means the ``_create_socket`` hook did not run.
    """
    check_hooks()
    pin_imapclient_logging()
    apply_line_cap(limits)
    timeout = SocketTimeout(limits.imap_connect_seconds, limits.imap_read_seconds)
    try:
        ctx = build_context(ca_file)
    except (OSError, ssl.SSLError):
        raise ConnectError("ca_file_unreadable") from None
    client: Any = None
    failure: ConnectError
    try:
        client = _Client(
            host,
            port,
            ssl=mode is TlsMode.IMPLICIT,
            ssl_context=ctx,
            timeout=timeout,
            limits=limits,
            handle=handle,
        )
        if handle is not None and not handle.registered:
            raise HookBypassed("create_socket")
        imap = client._imap
        check_instance(imap, limits)
        starttls = mode is TlsMode.STARTTLS
        capabilities = (
            _starttls(client, ctx) if starttls else parse_capabilities(client.capabilities())
        )
        imap.verify_liveness(starttls=starttls)
        imap.clear_command_log()
        return ReadOnlySession(client, capabilities, limits)
    except Exception as exc:
        failure = _map(exc)
        if client is not None:
            _shutdown(client)
    raise failure


def _map(exc: Exception) -> ConnectError:
    """A fresh error, raised outside the handler so no server text hangs off ``__context__``."""
    if isinstance(exc, ConnectError):
        return ConnectError(exc.code)
    if isinstance(exc, PreTlsBytes):
        return ConnectError("pre_tls_bytes")
    if isinstance(exc, NoProbe):
        return ConnectError("hook_unavailable")
    if isinstance(exc, LimitBreach):
        return ConnectError("limit_exceeded")
    if isinstance(exc, HookBypassed):
        return ConnectError("hook_bypassed")
    if isinstance(exc, ReadOnlyViolation):
        return ConnectError("read_only_violation")
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ConnectError("tls_verify_failed")
    if isinstance(exc, ssl.SSLError):
        return ConnectError("tls_failed")
    if isinstance(exc, TimeoutError):
        return ConnectError("timeout")
    if isinstance(exc, OSError):
        return ConnectError("connect_failed")
    return ConnectError("protocol_error")
