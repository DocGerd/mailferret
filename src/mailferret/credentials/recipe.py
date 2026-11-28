"""The ``pass`` recipe: ``--pinentry-mode=error`` and a gpg status channel (A§2.1, T-17).

A recipe is recognised by the basename of ``argv[0]`` being ``pass``, on POSIX only (the status
channel is an inherited pipe fd). Any other command gets no status channel and no ``locked``.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import PurePath

GPG_OPTS = "PASSWORD_STORE_GPG_OPTS"
PINENTRY_UNAVAILABLE = 67108949
NOT_IN_STORE = b"is not in the password store"

# Everything else is refused: gpg takes unique abbreviations and many options redirect output,
# channels, the agent or the keyring, so only these exact tokens are known harmless.
ALLOWED_OPTIONS = frozenset({"--pinentry-mode=error", "--quiet", "--no-tty"})


def is_pass_recipe(argv: Sequence[str]) -> bool:
    return sys.platform != "win32" and bool(argv) and PurePath(argv[0]).name == "pass"


def gpg_opts_allowed(value: str) -> bool:
    return all(token in ALLOWED_OPTIONS for token in value.split())


def pass_env(user_opts: str, status_fd: int) -> dict[str, str]:
    """Environment entries of the recipe; ours come last so they win over the user's."""
    ours = f"--pinentry-mode=error --status-fd={status_fd}"
    return {GPG_OPTS: f"{user_opts} {ours}".strip(), "LC_ALL": "C"}


def is_locked(status: bytes) -> bool:
    """True for a complete ``ERROR pkdecrypt_failed`` line whose code is NO_PIN_ENTRY."""
    lines = status.split(b"\n")
    for line in lines[:-1]:
        parts = line.rstrip(b"\r").split(b" ")
        if (
            len(parts) == 4
            and parts[0] == b"[GNUPG:]"
            and parts[1] == b"ERROR"
            and parts[2] == b"pkdecrypt_failed"
            and parts[3].isdigit()
            and int(parts[3]) == PINENTRY_UNAVAILABLE
        ):
            return True
    return False


def is_not_found(returncode: int | None, stderr: bytes) -> bool:
    return returncode == 1 and NOT_IN_STORE in stderr
