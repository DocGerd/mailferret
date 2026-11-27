"""Throwaway TLS material, generated per test run with the openssl CLI."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import ssl
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_NAMES = ("127.0.0.1", "localhost")
_DNS_RE = re.compile(r"[A-Za-z0-9*]([A-Za-z0-9.*-]*[A-Za-z0-9])?")

_CONFIG = """\
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = mailferret test certificate
[ext]
subjectAltName = {san}
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign
"""


def _san_entry(name: str) -> str:
    if "%" in name or "," in name or not name.isprintable():
        raise ValueError(f"invalid certificate name: {name!r}")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        if not _DNS_RE.fullmatch(name):
            raise ValueError(f"invalid certificate name: {name!r}") from None
        return f"DNS:{name}"
    return f"IP:{name}"


class OpensslUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class TlsMaterial:
    cert_file: Path
    key_file: Path

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_file, self.key_file)
        return ctx

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.cert_file))


def _find_openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            candidate = Path(git).resolve().parents[1] / "usr" / "bin" / "openssl.exe"
            if candidate.exists():
                return str(candidate)
    raise OpensslUnavailable("openssl CLI not found")


def make_tls_material(directory: Path, names: Sequence[str] = DEFAULT_NAMES) -> TlsMaterial:
    """Self-signed cert whose SAN lists `names` (its CN is not a host name); trusted as a CA."""
    if not names:
        raise ValueError("names must not be empty")
    san = ", ".join(_san_entry(name) for name in names)
    openssl = _find_openssl()
    config = directory / "openssl.cnf"
    config.write_text(_CONFIG.format(san=san))
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(  # noqa: S603
        [
            openssl,
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
            "-config",
            str(config),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return TlsMaterial(cert, key)
