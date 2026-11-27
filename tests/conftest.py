from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from tests.support.imap_fake import (
    FakeImapServer,
    OpensslUnavailable,
    TlsMaterial,
    make_tls_material,
)
from tests.support.imap_fake.tls import DEFAULT_NAMES


def tls_material_or_skip(directory: Path, names: Sequence[str] = DEFAULT_NAMES) -> TlsMaterial:
    try:
        return make_tls_material(directory, names)
    except OpensslUnavailable:
        if os.environ.get("CI"):
            raise
        pytest.skip("openssl CLI not available")


@pytest.fixture(scope="session")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> TlsMaterial:
    return tls_material_or_skip(tmp_path_factory.mktemp("fake-imap-tls"))


@pytest.fixture(scope="session")
def wrong_host_material(tmp_path_factory: pytest.TempPathFactory) -> TlsMaterial:
    return tls_material_or_skip(tmp_path_factory.mktemp("fake-imap-tls-wrong"), ("example.com",))


@pytest.fixture(scope="session")
def ip_only_material(tmp_path_factory: pytest.TempPathFactory) -> TlsMaterial:
    return tls_material_or_skip(tmp_path_factory.mktemp("fake-imap-tls-ip"), ("192.0.2.1",))


@pytest.fixture
def fake_imap() -> Iterator[FakeImapServer]:
    with FakeImapServer() as server:
        yield server


@pytest.fixture
def fake_imap_tls(tls_material: TlsMaterial) -> Iterator[FakeImapServer]:
    with FakeImapServer(tls=tls_material) as server:
        yield server
