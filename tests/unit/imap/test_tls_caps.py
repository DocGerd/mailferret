from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from mailferret.imap import build_context, parse_capabilities
from tests.support.imap_fake import TlsMaterial


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
