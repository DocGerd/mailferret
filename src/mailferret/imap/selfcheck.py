"""The hook set checks itself and fails closed (SECURITY §3 R5, A§2.2).

``check_hooks`` runs before the first socket of every connection; ``check_instance`` runs on the
constructed client before STARTTLS or LOGIN. A miss or a changed shape raises
``ConnectError("hook_unavailable")``; the liveness checks (``GuardMixin.verify_liveness``) catch
a hook that exists but did not run.
"""

from __future__ import annotations

import imaplib
import inspect
from collections.abc import Callable
from typing import Any, Final

from imapclient import IMAPClient  # type: ignore[import-untyped]
from imapclient.imap4 import IMAP4WithTimeout  # type: ignore[import-untyped]
from imapclient.tls import IMAP4_TLS  # type: ignore[import-untyped]

from mailferret.imap.errors import ConnectError
from mailferret.imap.guard import GuardMixin, tagre_of
from mailferret.imap.logging_pin import logging_is_pinned
from mailferret.limits import Limits

_Params = tuple[tuple[str, Any], ...]

# imaplib methods the mixin overrides; the mixin's own signature must equal imaplib's.
_IMAPLIB_HOOKS: Final = ("_new_tag", "send", "_command", "read", "readline", "_command_complete")


def _params(func: Callable[..., Any]) -> _Params:
    return tuple((p.name, p.kind) for p in inspect.signature(func).parameters.values())


def _shape(owner: object, name: str) -> _Params:
    func = getattr(owner, name, None)
    if not callable(func):
        raise ConnectError("hook_unavailable")
    try:
        return _params(func)
    except (TypeError, ValueError):
        raise ConnectError("hook_unavailable") from None


def _expect(owner: object, name: str, names: tuple[str, ...]) -> None:
    if tuple(p[0] for p in _shape(owner, name)) != names:
        raise ConnectError("hook_unavailable")


def check_hooks() -> None:
    """Every method and global the guard, the caps and the probe rely on."""
    for name in _IMAPLIB_HOOKS:
        if _shape(imaplib.IMAP4, name) != _shape(GuardMixin, name):
            raise ConnectError("hook_unavailable")
    maxline = getattr(imaplib, "_MAXLINE", None)
    if type(maxline) is not int:
        raise ConnectError("hook_unavailable")
    _expect(IMAPClient, "_create_IMAP4", ("self",))
    _expect(IMAPClient, "has_capability", ("self", "capability"))
    _expect(IMAP4WithTimeout, "__init__", ("self", "address", "port", "timeout"))
    _expect(IMAP4_TLS, "__init__", ("self", "host", "port", "ssl_context", "timeout"))
    _expect(IMAP4WithTimeout, "_create_socket", ("self", "timeout"))
    _expect(IMAP4_TLS, "_create_socket", ("self", "timeout"))
    for cls in (IMAP4WithTimeout, IMAP4_TLS):
        if not issubclass(cls, imaplib.IMAP4):
            raise ConnectError("hook_unavailable")


def check_instance(imap: Any, limits: Limits) -> None:
    """The constructed client: our class, its dict, the pinned debug, the timeouts in force."""
    if not isinstance(imap, GuardMixin):
        raise ConnectError("hook_unavailable")
    if not isinstance(getattr(imap, "untagged_responses", None), dict):
        raise ConnectError("hook_unavailable")
    if tagre_of(imap) is None:
        raise ConnectError("hook_unavailable")
    if not isinstance(type(imap).debug, property) or imap.debug != 0:
        raise ConnectError("hook_unavailable")
    if getattr(imap, "_timeout", None) != limits.imap_connect_seconds:
        raise ConnectError("hook_unavailable")
    if imap.sock.gettimeout() != limits.imap_read_seconds:
        raise ConnectError("hook_unavailable")
    if not logging_is_pinned():
        raise ConnectError("hook_unavailable")
