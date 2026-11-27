from __future__ import annotations

import imaplib
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.fixtures.corpus import Fixture, committed
from tests.integration.tls import build_context
from tests.support.imap_fake import OpensslUnavailable, make_tls_material

COMPOSE_FILE = Path(__file__).parent / "docker-compose.yml"
HOST = "localhost"
IMAP_PORT = 3143
IMAPS_PORT = 3993
KEYSTORE_PASSWORD = "throwaway-keystore"  # noqa: S105  # pii-check: ignore
ACCOUNTS = {"alice@example.com": "pw-a", "bob@example.com": "pw-b"}
READY_TIMEOUT = 90.0


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "integration: needs Docker and the GreenMail container")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if Path(str(item.fspath)).parent == Path(__file__).parent:
            item.add_marker(pytest.mark.integration)


def _unavailable(reason: str) -> None:
    # Linux CI runners ship Docker, so a gap there is a failure, not a skip.
    if os.environ.get("CI") and sys.platform == "linux":
        pytest.fail(reason)
    pytest.skip(reason)


@dataclass(frozen=True)
class Greenmail:
    ca_file: Path


def _compose(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", "compose", "-p", "mailferret-it", "-f", str(COMPOSE_FILE), *args],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def connect(ca_file: Path | None, account: str | None = None) -> imaplib.IMAP4_SSL:
    conn = imaplib.IMAP4_SSL(HOST, IMAPS_PORT, ssl_context=build_context(ca_file))
    if account is not None:
        conn.login(account, ACCOUNTS[account])
    return conn


def _wait_ready(ca_file: Path) -> None:
    deadline = time.monotonic() + READY_TIMEOUT
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            connect(ca_file).logout()
            return
        except (OSError, imaplib.IMAP4.error) as exc:
            last = exc
            time.sleep(1)
    raise RuntimeError(f"GreenMail not ready: {last!r}")


def seed(account: str, messages: list[Fixture], ca_file: Path) -> None:
    conn = connect(ca_file, account)
    try:
        for message in messages:
            status, _ = conn.append("INBOX", "", None, message.raw)  # type: ignore[arg-type]
            assert status == "OK", message.name
    finally:
        conn.logout()


@pytest.fixture(scope="session")
def greenmail(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Greenmail]:
    if shutil.which("docker") is None:
        _unavailable("docker CLI not available")
    probe = subprocess.run(
        ["docker", "info"],  # noqa: S607
        capture_output=True,
        timeout=60,
        check=False,
    )
    if probe.returncode != 0:
        _unavailable("docker daemon not available")
    for port in (IMAP_PORT, IMAPS_PORT):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                _unavailable(f"port {port} already in use")

    certs = tmp_path_factory.mktemp("greenmail-certs")
    try:
        material = make_tls_material(certs, ("localhost", "127.0.0.1"))
    except OpensslUnavailable:
        _unavailable("openssl CLI not available")
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "openssl",
            "pkcs12",
            "-export",
            "-in",
            str(material.cert_file),
            "-inkey",
            str(material.key_file),
            "-out",
            str(certs / "greenmail.p12"),
            "-passout",
            f"pass:{KEYSTORE_PASSWORD}",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    material.key_file.unlink()
    # The container user must read the keystore through the read-only mount.
    certs.chmod(0o755)
    (certs / "greenmail.p12").chmod(0o644)
    material.cert_file.chmod(0o644)

    env = {**os.environ, "CERTS_DIR": str(certs), "KEYSTORE_PASSWORD": KEYSTORE_PASSWORD}
    try:
        up = _compose(env, "up", "-d")
        if up.returncode != 0:
            _unavailable(f"docker compose up failed: {up.stderr.strip()[-300:]}")
        _wait_ready(material.cert_file)
        seed("alice@example.com", committed(), material.cert_file)
        yield Greenmail(ca_file=material.cert_file)
    finally:
        _compose(env, "down", "-v")
