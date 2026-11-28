from __future__ import annotations

import ssl
import subprocess
from pathlib import Path

import pytest

from mailferret.imap import TlsMode, build_context, connect, parse_capabilities
from tests.conftest import tls_material_or_skip
from tests.support.imap_fake import FakeImapServer, TlsMaterial
from tests.support.imap_fake.tls import _find_openssl


def test_context_defaults() -> None:
    ctx = build_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_ca_file_extends_the_store(tls_material: TlsMaterial) -> None:
    before = build_context().cert_store_stats()["x509_ca"]
    after = build_context(tls_material.cert_file).cert_store_stats()["x509_ca"]
    assert after == before + 1


def test_unreadable_ca_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        build_context(tmp_path / "missing.pem")


def test_capability_flags() -> None:
    caps = parse_capabilities(
        [b"IMAP4rev1", b"starttls", b"LOGINDISABLED", b"THREAD=REFERENCES", b"AUTH=PLAIN"]
    )
    assert caps.starttls and caps.logindisabled and caps.thread_references and caps.auth_plain
    assert not (caps.sort or caps.uidplus or caps.condstore or caps.special_use or caps.idle)
    assert "IMAP4REV1" in caps.raw


def test_capability_flags_all_set_and_str_tokens() -> None:
    caps = parse_capabilities(["SORT", "UIDPLUS", "CONDSTORE", "SPECIAL-USE", "IDLE"])
    assert caps.sort and caps.uidplus and caps.condstore and caps.special_use and caps.idle
    assert not caps.starttls


def test_capabilities_tolerate_non_ascii() -> None:
    assert parse_capabilities([b"X-\xff"]).raw == frozenset({"X-�"})


def _other_ca(directory: Path) -> TlsMaterial:
    """A second self-signed CA with its own subject, so lookup by subject is unambiguous."""
    cert, key = directory / "other-cert.pem", directory / "other-key.pem"
    subprocess.run(  # noqa: S603
        [
            _find_openssl(),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-subj",
            "/CN=mailferret other test CA",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return TlsMaterial(cert, key)


def test_ca_file_extends_system_store_instead_of_replacing_it(
    tls_material: TlsMaterial, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tls_material_or_skip(tmp_path)  # skips when the openssl CLI is missing
    system = _other_ca(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(system.cert_file))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    for server_material in (tls_material, system):
        with FakeImapServer(tls=server_material, implicit_tls=True) as server:
            connect(
                "127.0.0.1", server.port, TlsMode.IMPLICIT, ca_file=tls_material.cert_file
            ).close()
