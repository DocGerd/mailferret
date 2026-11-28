"""``command`` credential backend under the process rules of A§2.1 (T-02, T-11, T-17)."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from mailferret.credentials import recipe
from mailferret.credentials.bindings import check_binding, remove_binding, write_binding
from mailferret.credentials.errors import (
    CredentialBackendError,
    CredentialBackendUnavailable,
    CredentialLimitExceeded,
    CredentialLocked,
    CredentialNotFound,
    CredentialTimeout,
)
from mailferret.credentials.process import BoundedResult, minimal_env, run_bounded
from mailferret.credentials.protocol import BackendDescription, EntryKey
from mailferret.credentials.secret import Secret, accept_output, validate_new_secret
from mailferret.limits import Limits
from mailferret.logging import register_secret

ENV_ALLOWLIST = frozenset({"PASSWORD_STORE_GPG_OPTS", "PASSWORD_STORE_DIR", "GNUPGHOME"})
_SESSION_NAMES = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
_FORBIDDEN = frozenset("\r\n\0")


class CommandBackend:
    def __init__(
        self,
        data_dir: Path,
        get_argv: Sequence[str],
        set_argv: Sequence[str] | None = None,
        *,
        env: Mapping[str, str] | None = None,
        limits: Limits | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._get_argv = list(get_argv)
        self._set_argv = list(set_argv) if set_argv is not None else None
        self._env = dict(env or {})
        self._limits = limits or Limits()
        self._environ = environ

    def _prepare(self, argv: Sequence[str]) -> dict[str, str]:
        if not argv or not Path(argv[0]).is_absolute():
            raise CredentialBackendError from None
        for name, value in self._env.items():
            if name not in ENV_ALLOWLIST or _FORBIDDEN & set(value):
                raise CredentialBackendError from None
        if not recipe.gpg_opts_allowed(self._env.get(recipe.GPG_OPTS, "")):
            raise CredentialBackendError from None
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise CredentialBackendError from None
        environ = os.environ if self._environ is None else self._environ
        names: tuple[str, ...] = ("GNUPGHOME", "PASSWORD_STORE_DIR")
        if sys.platform.startswith("linux"):
            names += _SESSION_NAMES
        return minimal_env(environ, self._env, names=names)

    def _invoke(self, argv: Sequence[str], stdin_data: bytes | None) -> BoundedResult:
        return self._run(argv, self._prepare(argv), stdin_data)

    def _run(
        self, argv: Sequence[str], env: dict[str, str], stdin_data: bytes | None
    ) -> BoundedResult:
        use_recipe = recipe.is_pass_recipe(argv)
        user_opts = self._env.get(recipe.GPG_OPTS, "")
        result = run_bounded(
            argv,
            env=env,
            cwd=self._data_dir,
            deadline=self._limits.credential_command_seconds,
            stdout_cap=self._limits.credential_command_output_bytes,
            stderr_cap=self._limits.credential_stderr_bytes,
            stdin_data=stdin_data,
            status_cap=self._limits.credential_status_bytes if use_recipe else None,
            status_env=(lambda fd: recipe.pass_env(user_opts, fd)) if use_recipe else None,
        )
        _raise_for(result, use_recipe)
        return result

    def get(self, key: EntryKey) -> Secret:
        if not check_binding(self._data_dir, key):
            raise CredentialNotFound from None
        result = self._invoke(self._get_argv, None)
        secret = accept_output(result.stdout)
        register_secret(secret.reveal(), key.login)
        return secret

    def set(self, key: EntryKey, secret: Secret) -> None:
        if self._set_argv is None:
            raise CredentialBackendUnavailable from None
        accepted = validate_new_secret(secret, self._limits.credential_command_output_bytes)
        register_secret(accepted.reveal(), key.login)
        env = self._prepare(self._set_argv)
        # A failed or ambiguous write must leave no binding, so a later get finds nothing.
        remove_binding(self._data_dir, key)
        self._run(self._set_argv, env, accepted.reveal().encode() + b"\n")
        write_binding(self._data_dir, key)

    def delete(self, key: EntryKey) -> None:
        remove_binding(self._data_dir, key)

    def describe(self) -> BackendDescription:
        name = Path(self._get_argv[0]).name if self._get_argv else None
        secure = recipe.is_pass_recipe(self._get_argv)
        return BackendDescription(kind="command", backend=name, secure=secure, status="configured")


def _raise_for(result: BoundedResult, use_recipe: bool) -> None:
    if result.status == "timeout":
        raise CredentialTimeout from None
    if result.status == "limit_exceeded":
        raise CredentialLimitExceeded from None
    if result.returncode == 0:
        return
    if use_recipe:
        if recipe.is_locked(result.aux):
            raise CredentialLocked from None
        if recipe.is_not_found(result.returncode, result.stderr):
            raise CredentialNotFound from None
    raise CredentialBackendError from None
