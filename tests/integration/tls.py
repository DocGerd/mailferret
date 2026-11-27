"""Client TLS context as A§2.2 prescribes; stand-in until `imap/` provides it (issue #26)."""

from __future__ import annotations

import ssl
from pathlib import Path


def build_context(ca_file: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file is not None:
        ctx.load_verify_locations(cafile=str(ca_file))
    return ctx
