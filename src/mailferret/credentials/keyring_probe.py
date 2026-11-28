"""Keyring probe worker: the only code that imports ``keyring`` (A§2.1, T-17).

Started by the parent as ``sys.executable -I -m``. Backend selection, detection, the D-Bus
error mapping and every lookup or write run here. The secret leaves on stdout (``get``) or
arrives on stdin (``set``); stderr and exit codes carry no secret.
"""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Callable
from types import ModuleType
from typing import BinaryIO

from mailferret.credentials import probe_protocol as proto
from mailferret.credentials.detect import classify, qualified_name
from mailferret.credentials.errors import CredentialRejected
from mailferret.credentials.secret import accept_output
from mailferret.limits import CEILINGS

Loader = Callable[[str], ModuleType]

_UNAVAILABLE_ERRORS = (FileNotFoundError, ConnectionError, TimeoutError, ImportError)


def _describe(backend: object, out: BinaryIO) -> int:
    verdict = classify(backend)
    body = {"backend": qualified_name(backend), "secure": verdict.usable, "reason": verdict.reason}
    out.write(json.dumps(body).encode("ascii", "replace"))
    out.flush()
    return proto.OK if verdict.usable else proto.UNAVAILABLE


def run(
    argv: list[str],
    stdin: BinaryIO,
    stdout: BinaryIO,
    load: Loader = importlib.import_module,
) -> int:
    cap = CEILINGS["credential_command_output_bytes"]
    if not argv or argv[0] not in proto.OPS or len(argv) != (1 if argv[0] == "describe" else 3):
        return proto.ERROR
    op = argv[0]
    try:
        keyring = load("keyring")
        errors = load("keyring.errors")
    except _UNAVAILABLE_ERRORS:
        return proto.UNAVAILABLE
    try:
        backend = keyring.get_keyring()
        if op == "describe":
            return _describe(backend, stdout)
        if not classify(backend).usable:
            return proto.UNAVAILABLE
        service, username = argv[1], argv[2]
        if op == "get":
            value = keyring.get_password(service, username)
            if value is None:
                return proto.NOT_FOUND
            try:
                accept_output(value.encode("utf-8"), strip=False)
            except (CredentialRejected, UnicodeEncodeError):
                return proto.ERROR
            stdout.write(value.encode("utf-8") + b"\n")
            stdout.flush()
            return proto.OK
        if op == "set":
            data = stdin.read(cap + 1)
            if len(data) > cap:
                return proto.ERROR
            try:
                secret = accept_output(data, strip=False)
            except CredentialRejected:
                return proto.ERROR
            keyring.set_password(service, username, secret.reveal())
            return proto.OK
        keyring.delete_password(service, username)
        return proto.OK
    except _UNAVAILABLE_ERRORS:
        return proto.UNAVAILABLE
    except Exception as exc:
        return _map_keyring_error(exc, errors)


def _map_keyring_error(exc: Exception, errors: ModuleType) -> int:
    def is_a(name: str) -> bool:
        cls = getattr(errors, name, None)
        return isinstance(cls, type) and isinstance(exc, cls)

    if is_a("KeyringLocked"):
        return proto.LOCKED
    if is_a("NoKeyringError") or is_a("InitError"):
        return proto.UNAVAILABLE
    if is_a("PasswordDeleteError"):
        return proto.NOT_FOUND
    return proto.ERROR


def main() -> int:
    return run(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    sys.exit(main())
