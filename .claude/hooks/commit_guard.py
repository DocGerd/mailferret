#!/usr/bin/env python3
"""PreToolUse(Bash) guard for `git commit`.

  commit_guard.py tests  -> block (exit 2) if `uv run pytest -q -x` fails; skipped without pyproject.toml
  commit_guard.py pii    -> block (exit 2) if scripts/pii_check.py finds credentials or personal data

Any other command passes. Internal errors exit 0 with a warning, so a broken
guard never blocks unrelated Bash calls.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "env"}


def git_invocations(command: str) -> list[tuple[str | None, str, list[str]]]:
    """Return (dir from -C, subcommand, args) for each git call in the command text."""
    calls = []
    for segment in SEPARATORS.split(command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        while tokens and (re.fullmatch(r"\w+=.*", tokens[0]) or tokens[0] in WRAPPERS):
            tokens.pop(0)
            while tokens and tokens[0].startswith("-"):  # wrapper flags such as timeout -k 5
                tokens.pop(0)
                if tokens and re.fullmatch(r"[\d.]+[smhd]?", tokens[0]):
                    tokens.pop(0)
            if tokens and re.fullmatch(r"[\d.]+[smhd]?", tokens[0]):
                tokens.pop(0)
        if not tokens or Path(tokens[0]).name not in ("git", "git.exe"):
            continue
        i, cdir = 1, None
        while i < len(tokens) and tokens[i].startswith("-"):
            opt = tokens[i]
            if opt in GIT_OPTS_WITH_VALUE:
                if opt == "-C" and i + 1 < len(tokens):
                    cdir = tokens[i + 1]
                i += 2
            else:
                i += 1
        if i < len(tokens):
            calls.append((cdir, tokens[i], tokens[i + 1 :]))
    return calls


def toplevel(cwd: str) -> Path | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return Path(out.stdout.strip()) if out.returncode == 0 else None


def run_tests(root: Path) -> int:
    if not (root / "pyproject.toml").is_file():
        return 0
    try:
        res = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=540,
        )
    except FileNotFoundError:
        print("commit_guard: uv not found; tests not run", file=sys.stderr)
        return 0
    except subprocess.TimeoutExpired:
        print("Commit blocked: the test suite timed out.", file=sys.stderr)
        return 2
    if res.returncode in (0, 5):  # 5 = no tests collected
        return 0
    tail = "\n".join((res.stdout + res.stderr).strip().splitlines()[-30:])
    print(f"Commit blocked: `uv run pytest -q -x` failed (exit {res.returncode}).\n{tail}", file=sys.stderr)
    return 2


def run_pii(root: Path, include_untracked: bool) -> int:
    scanner = Path(os.environ.get("CLAUDE_PROJECT_DIR", root)) / "scripts" / "pii_check.py"
    if not scanner.is_file():
        scanner = root / "scripts" / "pii_check.py"
    if not scanner.is_file():
        print("commit_guard: scripts/pii_check.py not found; PII scan skipped", file=sys.stderr)
        return 0
    argv = [sys.executable, str(scanner), "--worktree"] + (["--include-untracked"] if include_untracked else [])
    res = subprocess.run(argv, cwd=root, capture_output=True, text=True, errors="replace", timeout=120)
    if res.returncode == 1:
        print("Commit blocked by the PII guard.\n" + res.stderr.strip(), file=sys.stderr)
        return 2
    if res.returncode != 0:
        print(f"commit_guard: scanner error (exit {res.returncode}); not blocking", file=sys.stderr)
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    payload = json.load(sys.stdin)
    command = (payload.get("tool_input") or {}).get("command") or ""
    calls = git_invocations(command)
    commits = [c for c in calls if c[1] == "commit"]
    if not commits:
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    cdir = commits[0][0]
    if cdir:
        cwd = str(Path(cwd, cdir))
    root = toplevel(cwd)
    if root is None:
        return 0
    if mode == "tests":
        return run_tests(root)
    if mode == "pii":
        adds = any(sub in ("add", "rm", "mv") for _, sub, _ in calls)
        return run_pii(root, include_untracked=adds)
    print(f"commit_guard: unknown mode {mode!r}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never block unrelated calls on a guard bug
        print(f"commit_guard: internal error, not blocking: {exc!r}", file=sys.stderr)
        sys.exit(0)
