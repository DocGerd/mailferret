"""``keyring`` credential backend, used only through the probe (A§2.1, T-11, T-17)."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path

from mailferret.credentials.probe import PROBE_ARGV, parse_description, run_probe
from mailferret.credentials.protocol import BackendDescription, EntryKey
from mailferret.credentials.secret import Secret, accept_output
from mailferret.credentials.wsl import is_wsl
from mailferret.limits import Limits
from mailferret.logging import register_secret


class KeyringBackend:
    def __init__(
        self,
        data_dir: Path,
        limits: Limits | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        argv: Sequence[str] = PROBE_ARGV,
    ) -> None:
        self._data_dir = data_dir
        self._limits = limits or Limits()
        self._environ = environ
        self._argv = argv

    def _run(self, op: str, key: EntryKey | None, secret: Secret | None = None) -> bytes:
        outcome = run_probe(
            op,
            key,
            data_dir=self._data_dir,
            limits=self._limits,
            environ=self._environ,
            secret=secret,
            argv=self._argv,
        )
        outcome.raise_for_status()
        return outcome.stdout

    def get(self, key: EntryKey) -> Secret:
        secret = accept_output(self._run("get", key))
        register_secret(secret.reveal(), key.login)
        return secret

    def set(self, key: EntryKey, secret: Secret) -> None:
        register_secret(secret.reveal(), key.login)
        self._run("set", key, secret)

    def delete(self, key: EntryKey) -> None:
        self._run("delete", key)

    def describe(self) -> BackendDescription:
        environ = os.environ if self._environ is None else self._environ
        outcome = run_probe(
            "describe",
            None,
            data_dir=self._data_dir,
            limits=self._limits,
            environ=environ,
            argv=self._argv,
        )
        backend, secure = parse_description(outcome.stdout)
        return BackendDescription(
            kind="keyring",
            backend=backend,
            secure=secure and outcome.status == "ok",
            status=outcome.status,
            wsl=is_wsl(environ),
            bus=outcome.bus,
        )
