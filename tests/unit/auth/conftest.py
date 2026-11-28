from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mailferret.auth import AuthMarkers, PasswordAuth, guard_connect
from mailferret.credentials import EntryKey, Secret
from mailferret.credentials.memory import MemoryBackend
from mailferret.imap import ReadOnlySession, TlsMode, connect
from mailferret.imap.handle import ConnectHandle
from mailferret.imap.lifecycle import AccountSession
from mailferret.limits import Limits
from tests.support.imap_fake import FakeImapServer, TlsMaterial

HOST = "127.0.0.1"
LOGIN = "user@example.com"
PASSWORD = "pw-CANARY-7f3a"  # noqa: S105  # pii-check: ignore
NON_ASCII = "pässwörd-ÄÖ-7f3a"  # pii-check: ignore
OK = "{tag} OK done\r\n"
EXAMINE = [b"* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n", OK]
BASE = ["IMAP4rev1", "NAMESPACE", "ID"]


def sasl(login: str, secret: str) -> str:
    return base64.b64encode(f"\0{login}\0{secret}".encode()).decode("ascii")


def logins(server: FakeImapServer) -> int:
    return sum(1 for c in server.commands if c.verb in {"LOGIN", "AUTHENTICATE"})


def key_for(login: str = LOGIN) -> EntryKey:
    return EntryKey("acct", login, HOST)


class SpyBackend(MemoryBackend):
    def __init__(self) -> None:
        super().__init__()
        self.gets = 0

    def get(self, key: EntryKey) -> Secret:
        self.gets += 1
        return super().get(key)


@dataclass
class Rig:
    server: FakeImapServer
    tls: TlsMaterial
    data_dir: Path
    backend: SpyBackend = field(default_factory=SpyBackend)
    pools: list[AccountSession] = field(default_factory=list)

    def store(self, secret: str, login: str = LOGIN) -> None:
        self.backend.set(key_for(login), Secret(secret))

    def pool(
        self,
        login: str = LOGIN,
        *,
        limits: Limits | None = None,
        markers: AuthMarkers | None = None,
        mode: TlsMode = TlsMode.IMPLICIT,
    ) -> AccountSession:
        """A fresh server process: its own markers object over the shared data directory."""
        effective = limits or Limits()
        auth = PasswordAuth(markers or AuthMarkers(self.data_dir))
        account = key_for(login)

        def open_session(handle: ConnectHandle) -> ReadOnlySession:
            return connect(
                HOST,
                self.server.port,
                mode,
                ca_file=self.tls.cert_file,
                limits=effective,
                handle=handle,
            )

        pool = AccountSession(
            guard_connect(auth, account, open_session),
            lambda session: auth.authenticate(session, account, self.backend),
            effective,
        )
        self.pools.append(pool)
        return pool


Maker = Callable[..., Rig]


@pytest.fixture
def make_rig(tls_material: TlsMaterial, tmp_path: Path) -> Iterator[Maker]:
    servers: list[FakeImapServer] = []
    rigs: list[Rig] = []

    def make(
        capabilities: list[str] | None = None,
        *,
        implicit_tls: bool = True,
        secret: str | None = PASSWORD,
    ) -> Rig:
        server = FakeImapServer(
            tls=tls_material,
            implicit_tls=implicit_tls,
            capabilities=BASE if capabilities is None else capabilities,
        )
        server.start()
        server.on("EXAMINE", EXAMINE)
        servers.append(server)
        rig = Rig(server, tls_material, tmp_path / "data")
        if secret is not None:
            rig.store(secret)
        rigs.append(rig)
        return rig

    yield make
    for rig in rigs:
        for pool in rig.pools:
            pool.close()
    for server in servers:
        server.stop()
