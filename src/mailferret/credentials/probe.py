"""Parent side of the keyring probe, shared by ``serve``, ``doctor`` and ``auth set`` (A§2.1).

No process calls ``keyring`` in-process; this module only runs the bus-address pre-check
and starts the probe under ``L-27``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mailferret.credentials import probe_protocol as proto
from mailferret.credentials.dbus import check_bus_address
from mailferret.credentials.errors import (
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialTimeout,
)
from mailferret.credentials.process import minimal_env, run_bounded
from mailferret.credentials.protocol import EntryKey
from mailferret.credentials.secret import Secret, validate_new_secret
from mailferret.limits import Limits

ProbeStatus = Literal[
    "ok", "not_found", "unavailable", "locked", "timeout", "limit_exceeded", "error"
]

PROBE_ARGV: tuple[str, ...] = (sys.executable, "-I", "-m", "mailferret.credentials.keyring_probe")
BUS_VAR = "DBUS_SESSION_BUS_ADDRESS"
_PROBE_ONLY_VARS = ("PYTHON_KEYRING_BACKEND", "XDG_CONFIG_HOME")
_SESSION_VARS = ("XDG_RUNTIME_DIR",)

_EXIT_STATUS: dict[int, ProbeStatus] = {
    proto.OK: "ok",
    proto.NOT_FOUND: "not_found",
    proto.UNAVAILABLE: "unavailable",
    proto.LOCKED: "locked",
}

_ERRORS: dict[str, type[CredentialError]] = {
    "not_found": CredentialNotFound,
    "unavailable": CredentialBackendUnavailable,
    "locked": CredentialLocked,
    "timeout": CredentialTimeout,
    "limit_exceeded": CredentialLimitExceeded,
    "error": CredentialBackendError,
}


@dataclass(frozen=True)
class ProbeOutcome:
    status: ProbeStatus
    bus: str | None = None
    # May hold the secret (``get``): hidden from repr.
    stdout: bytes = field(default=b"", repr=False)

    def raise_for_status(self) -> None:
        if self.status != "ok":
            raise _ERRORS[self.status]


def probe_env(environ: Mapping[str, str], bus_address: str | None) -> dict[str, str]:
    """Minimal env; the keyring variables go to the probe only."""
    names = (*_SESSION_VARS, *_PROBE_ONLY_VARS)
    env = minimal_env(environ, names=names)
    if bus_address:
        env[BUS_VAR] = bus_address
    return env


def run_probe(
    op: str,
    key: EntryKey | None,
    *,
    data_dir: Path,
    limits: Limits,
    environ: Mapping[str, str] | None = None,
    secret: Secret | None = None,
    argv: Sequence[str] = PROBE_ARGV,
    platform: str | None = None,
) -> ProbeOutcome:
    env_in = os.environ if environ is None else environ
    stdin_data: bytes | None = None
    if op == "set":
        if secret is None:
            raise CredentialBackendError from None
        stdin_data = (
            validate_new_secret(secret, limits.credential_command_output_bytes).reveal().encode()
        )
    bus_status: str | None = None
    bus_address: str | None = None
    if (platform or sys.platform).startswith("linux"):
        check = check_bus_address(env_in.get(BUS_VAR))
        bus_status = check.status
        if not check.usable:
            return ProbeOutcome("unavailable", bus_status)
        bus_address = check.address
    try:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        raise CredentialBackendError from None
    command = [*argv, op] if key is None else [*argv, op, key.service, key.username]
    result = run_bounded(
        command,
        env=probe_env(env_in, bus_address),
        cwd=data_dir,
        deadline=limits.keyring_probe_seconds,
        stdout_cap=limits.credential_command_output_bytes,
        stderr_cap=limits.credential_stderr_bytes,
        stdin_data=stdin_data,
    )
    if result.status != "exited":
        return ProbeOutcome(result.status, bus_status)
    status = _EXIT_STATUS.get(result.returncode if result.returncode is not None else -1, "error")
    return ProbeOutcome(status, bus_status, result.stdout)


def parse_description(stdout: bytes) -> tuple[str | None, bool]:
    """Backend class name and whether it is usable, from a ``describe`` result."""
    try:
        body = json.loads(stdout.decode("ascii"))
        backend = body.get("backend")
        secure = body.get("secure")
    except (ValueError, AttributeError):
        return None, False
    name = backend if isinstance(backend, str) and len(backend) <= 200 else None
    return name, secure is True
