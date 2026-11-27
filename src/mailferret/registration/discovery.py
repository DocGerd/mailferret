"""Locate client config files from injected environment; nothing is run."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Scope = Literal["user", "project", "local"]

_FILE = "claude_desktop_config.json"


@dataclass(frozen=True)
class Candidate:
    path: Path
    kind: Literal["regular", "msix"]


def claude_code_scope_file(scope: Scope, home: Path, cwd: Path) -> Path:
    """File that `claude mcp add-json --scope <scope>` writes (V4 item 13)."""
    if scope == "project":
        return cwd / ".mcp.json"
    return home / ".claude.json"


def _regular(platform: str, env: Mapping[str, str], home: Path) -> Path | None:
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / _FILE
    if platform == "win32":
        appdata = env.get("APPDATA")
        return Path(appdata) / "Claude" / _FILE if appdata else None
    return home / ".config" / "Claude" / _FILE


def desktop_candidates(platform: str, env: Mapping[str, str], home: Path) -> list[Candidate]:
    """Existing Desktop config files for the platform.

    MSIX package directories (family suffix globbed) are reported as `msix`;
    callers must not rely on their config path (A§9.6).
    """
    found: list[Candidate] = []
    regular = _regular(platform, env, home)
    if regular is not None and regular.is_file():
        found.append(Candidate(regular, "regular"))
    local = env.get("LOCALAPPDATA")
    if platform == "win32" and local:
        packages = Path(local) / "Packages"
        if packages.is_dir():
            found.extend(Candidate(p, "msix") for p in sorted(packages.glob("Claude_*")))
    return found
