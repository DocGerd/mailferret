from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.support.imap_fake import (
    FakeImapServer,
    OpensslUnavailable,
    TlsMaterial,
    make_tls_material,
)


@pytest.fixture(scope="session")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> TlsMaterial:
    directory: Path = tmp_path_factory.mktemp("fake-imap-tls")
    try:
        return make_tls_material(directory)
    except OpensslUnavailable:
        pytest.skip("openssl CLI not available")


@pytest.fixture
def fake_imap() -> Iterator[FakeImapServer]:
    with FakeImapServer() as server:
        yield server


@pytest.fixture
def fake_imap_tls(tls_material: TlsMaterial) -> Iterator[FakeImapServer]:
    with FakeImapServer(tls=tls_material) as server:
        yield server
