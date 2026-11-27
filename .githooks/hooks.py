"""Git hooks of this repo, started by the sh wrappers next to this file.

  pre-commit, pre-merge-commit   PII scan of the staged changes, then the tests once pyproject.toml exists
  commit-msg FILE                PII scan of the message content, never of its path

Enable once per clone: git config core.hooksPath .githooks
Honours the optional untracked .git/info/pii-patterns via scripts/pii_check.py.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(hook: str, args: list[str]) -> str | None:
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    root = Path(top.stdout.strip())
    scanner = root / "scripts" / "pii_check.py"
    if not scanner.is_file():
        return f"{hook}: scripts/pii_check.py missing"
    if hook == "commit-msg":
        if not args:
            return "commit-msg: message file missing"
        scan = ["--message-file", str(Path(args[0]).resolve())]
    else:
        scan = ["--staged"]
    if subprocess.run([sys.executable, str(scanner), *scan], cwd=root, stdin=subprocess.DEVNULL).returncode != 0:
        return f"{hook}: blocked by the PII scan (see above)"
    if hook != "commit-msg" and (root / "pyproject.toml").is_file():
        try:
            rc = subprocess.run(["uv", "run", "pytest", "-q", "-x"], cwd=root, stdin=subprocess.DEVNULL).returncode
        except FileNotFoundError:
            return f"{hook}: uv not found, tests cannot run"
        if rc not in (0, 5):  # 5 = no tests collected
            return f"{hook}: tests failed (exit {rc})"
    return None


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
