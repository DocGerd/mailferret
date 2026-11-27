#!/usr/bin/env python3
"""PostToolUse(Edit|Write): `ruff format` + `ruff check --fix` on the edited .py file.

No-op unless the file sits in a tree with pyproject.toml. Remaining lint errors
exit 2 so Claude sees them (PostToolUse cannot block).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def project_root(path: Path) -> Path | None:
    for parent in path.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
        if (parent / ".git").exists():
            return None
    return None


def main() -> int:
    payload = json.load(sys.stdin)
    file_path = (payload.get("tool_input") or {}).get("file_path") or ""
    path = Path(file_path)
    if path.suffix not in (".py", ".pyi") or not path.is_file():
        return 0
    root = project_root(path)
    if root is None:
        return 0
    try:
        subprocess.run(["uv", "run", "ruff", "format", "--quiet", str(path)], cwd=root,
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        res = subprocess.run(["uv", "run", "ruff", "check", "--fix", "--quiet", str(path)], cwd=root,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"ruff_fix: skipped ({exc.__class__.__name__})", file=sys.stderr)
        return 0
    if res.returncode == 1:
        print("ruff check found issues it could not fix:\n" + (res.stdout + res.stderr).strip()[-3000:], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ruff_fix: internal error: {exc!r}", file=sys.stderr)
        sys.exit(0)
