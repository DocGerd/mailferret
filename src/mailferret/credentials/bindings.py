"""Binding record: ties a ``command`` credential to ``<login>@<host>`` (A§2, T-11).

``set`` writes it only after the command succeeded; ``get`` checks it before any spawn, so a
tampered host or login finds no secret instead of sending one elsewhere.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
from pathlib import Path

from mailferret.credentials.errors import CredentialBackendError
from mailferret.credentials.protocol import EntryKey

_MAX_BYTES = 4096


def binding_path(data_dir: Path, key: EntryKey) -> Path:
    digest = hashlib.sha256(key.service.encode()).hexdigest()[:32]
    return data_dir / f"command-binding-{digest}.json"


def check_binding(data_dir: Path, key: EntryKey) -> bool:
    path = binding_path(data_dir, key)
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            return False
        body = json.loads(raw)
    except (OSError, ValueError):
        return False
    return (
        isinstance(body, dict)
        and body.get("service") == key.service
        and body.get("username") == key.username
    )


def write_binding(data_dir: Path, key: EntryKey) -> None:
    path = binding_path(data_dir, key)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    payload = json.dumps({"service": key.service, "username": key.username}).encode()
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise CredentialBackendError from None


def remove_binding(data_dir: Path, key: EntryKey) -> None:
    try:
        binding_path(data_dir, key).unlink(missing_ok=True)
    except OSError:
        raise CredentialBackendError from None
