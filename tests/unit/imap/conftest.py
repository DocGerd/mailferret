from __future__ import annotations

import imaplib
from collections.abc import Callable, Iterator

import pytest

from mailferret.imap import ReadOnlySession, TlsMode, connect
from mailferret.limits import Limits
from tests.support.imap_fake import FakeImapServer, TlsMaterial

HOST = "127.0.0.1"
CAPS = ["IMAP4rev1", "SORT", "THREAD=REFERENCES", "UIDPLUS", "AUTH=PLAIN", "NAMESPACE", "ID"]

Opener = Callable[..., ReadOnlySession]


@pytest.fixture(autouse=True)
def _restore_maxline() -> Iterator[None]:
    """``imaplib._MAXLINE`` is process-global: tests with small limits must not leak it."""
    saved = imaplib._MAXLINE  # type: ignore[attr-defined]
    yield
    imaplib._MAXLINE = saved  # type: ignore[attr-defined]


@pytest.fixture
def server(tls_material: TlsMaterial) -> Iterator[FakeImapServer]:
    with FakeImapServer(tls=tls_material, implicit_tls=True, capabilities=CAPS) as srv:
        yield srv


@pytest.fixture
def opener(tls_material: TlsMaterial) -> Iterator[Opener]:
    opened: list[ReadOnlySession] = []

    def open_session(
        srv: FakeImapServer, limits: Limits | None = None, mode: TlsMode = TlsMode.IMPLICIT
    ) -> ReadOnlySession:
        session = connect(
            HOST, srv.port, mode, ca_file=tls_material.cert_file, limits=limits or Limits()
        )
        opened.append(session)
        return session

    yield open_session
    for session in opened:
        session.close()
