"""WSL detection (A§2.1)."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

_OSRELEASE = Path("/proc/sys/kernel/osrelease")


def _read_osrelease() -> str:
    try:
        return _OSRELEASE.read_text(encoding="ascii", errors="replace")
    except OSError:
        return ""


def is_wsl(
    environ: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
    read_osrelease: Callable[[], str] = _read_osrelease,
) -> bool:
    if not (platform or sys.platform).startswith("linux"):
        return False
    env = os.environ if environ is None else environ
    if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return True
    return "microsoft" in read_osrelease().lower()
