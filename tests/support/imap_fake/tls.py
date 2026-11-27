"""Throwaway TLS material, generated per test run with the openssl CLI."""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
from dataclasses import dataclass
from pathlib import Path

_CONFIG = """\
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = localhost
[ext]
subjectAltName = IP:127.0.0.1, DNS:localhost
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign
"""


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


def make_tls_material(directory: Path) -> TlsMaterial:
    openssl = _find_openssl()
    config = directory / "openssl.cnf"
    config.write_text(_CONFIG)
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
