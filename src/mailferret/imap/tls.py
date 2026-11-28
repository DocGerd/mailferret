"""Client TLS context (A§2.2): verification on, TLS 1.2 minimum, ``ca_file`` extends the store."""

from __future__ import annotations

import ssl
from enum import StrEnum
from pathlib import Path


class TlsMode(StrEnum):
    IMPLICIT = "implicit"
    STARTTLS = "starttls"


def build_context(ca_file: Path | None = None) -> ssl.SSLContext:
    """Default context plus ``ca_file`` via ``load_verify_locations``.

    ``create_default_context(cafile=...)`` would skip the system store.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    if ca_file is not None:
        ctx.load_verify_locations(cafile=str(ca_file))
    return ctx
