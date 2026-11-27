#!/usr/bin/env python3
"""PreToolUse(Bash) guard for `git commit` in this project.

  commit_guard.py pii    block (exit 2) on credentials/personal data in what the commit records
  commit_guard.py tests  block (exit 2) if `uv run pytest -q -x` fails; skipped without pyproject.toml
  commit_guard.py all    both, PII first

A command that mentions git and commit but cannot be parsed unambiguously is
treated as a commit and scanned in full. Commits in any repository outside
CLAUDE_PROJECT_DIR are left alone: nothing runs there. This hook is a
convenience layer; `.githooks/pre-commit` is the enforcement point.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
SEPARATORS = re.compile(r"&&|\|\||[;|&\n()]")
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
COMMIT_OPTS_WITH_VALUE = {
    "-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
    "--author", "--date", "--fixup", "--squash", "-t", "--template", "--cleanup", "--trailer",
    "--pathspec-from-file",
}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "env", "then", "do", "else", "exec"}


@dataclass
class Commit:
    detected: bool = False
    ambiguous: bool = False
    worktree: bool = False  # -a/--all/pathspecs/--include/--only: unstaged changes get committed
    adds: bool = False  # git add/rm/mv in the same command
    cdir: str | None = None
    dirs: list[str] = field(default_factory=list)


def _strip_wrappers(tokens: list[str]) -> list[str]:
    while tokens and (re.fullmatch(r"\w+=.*", tokens[0]) or tokens[0] in WRAPPERS):
        tokens.pop(0)
        while tokens and (tokens[0].startswith("-") or re.fullmatch(r"[\d.]+[smhd]?", tokens[0])):
            tokens.pop(0)
    return tokens


def analyse(command: str) -> Commit:
    result = Commit()
    for segment in SEPARATORS.split(command):
        mentions = re.search(r"\bgit\b", segment) and re.search(r"\bcommit\b", segment)
        try:
            tokens = _strip_wrappers(shlex.split(segment))
        except ValueError:
            if mentions:
                result.detected = result.ambiguous = True
            continue
        if not tokens or Path(tokens[0]).name not in ("git", "git.exe"):
            if mentions:  # bash -c "git commit", aliases, scripts
                result.detected = result.ambiguous = True
            continue
        i, cdir = 1, None
        while i < len(tokens) and tokens[i].startswith("-"):
            if tokens[i] in GIT_OPTS_WITH_VALUE:
                if tokens[i] == "-C" and i + 1 < len(tokens):
                    cdir = tokens[i + 1]
                i += 2
            else:
                i += 1
        sub, rest = (tokens[i], tokens[i + 1 :]) if i < len(tokens) else ("", [])
        if sub in ("add", "rm", "mv"):
            result.adds = True
        if sub != "commit":
            continue
        result.detected = True
        result.dirs.append(cdir or "")
        j = 0
        while j < len(rest):
            arg = rest[j]
            if arg == "--":
                result.worktree = j + 1 < len(rest) or result.worktree
                break
            if arg in COMMIT_OPTS_WITH_VALUE:
                j += 2
                continue
            if arg in ("--all", "--include", "--only") or re.fullmatch(r"-[a-zA-Z]*a[a-zA-Z]*", arg) and not arg.startswith("--"):
                result.worktree = True
            elif re.fullmatch(r"-[a-zA-Z]*[ioa][a-zA-Z]*", arg):
                result.worktree = True
            elif not arg.startswith("-"):
                result.worktree = True  # pathspec
            j += 1
    if result.ambiguous:
        result.worktree = result.adds = True
    return result


def inside(path: Path, base: Path) -> bool:
    path, base = path.resolve(), base.resolve()
    return path == base or base in path.parents


def toplevel(cwd: Path) -> Path | None:
    try:
        out = subprocess.run([*GIT, "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(out.stdout.strip()) if out.returncode == 0 else None


def run_pii(project: Path, root: Path, commit: Commit) -> int:
    scanner = project / "scripts" / "pii_check.py"
    if not scanner.is_file():
        print("Commit blocked: scripts/pii_check.py is missing.", file=sys.stderr)
        return 2
    argv = [sys.executable, str(scanner), "--staged"]
    argv += ["--unstaged"] if commit.worktree or commit.adds else []
    argv += ["--include-untracked"] if commit.adds else []
    try:
        res = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Commit blocked: PII scanner did not run ({exc.__class__.__name__}).", file=sys.stderr)
        return 2
    if res.returncode != 0:
        print(f"Commit blocked by the PII guard (scanner exit {res.returncode}).\n{res.stderr.strip()}", file=sys.stderr)
        return 2
    return 0


def run_tests(root: Path) -> int:
    if not (root / "pyproject.toml").is_file():
        return 0
    try:
        res = subprocess.run(["uv", "run", "pytest", "-q", "-x"], cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, errors="replace", timeout=540)
    except FileNotFoundError:
        print("Commit blocked: uv not found, tests cannot run.", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired:
        print("Commit blocked: the test suite timed out.", file=sys.stderr)
        return 2
    if res.returncode in (0, 5):  # 5 = no tests collected
        return 0
    tail = "\n".join((res.stdout + res.stderr).strip().splitlines()[-30:])
    print(f"Commit blocked: `uv run pytest -q -x` failed (exit {res.returncode}).\n{tail}", file=sys.stderr)
    return 2


def main(mode: str, payload: dict) -> int:
    commit = analyse((payload.get("tool_input") or {}).get("command") or "")
    if not commit.detected:
        return 0
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or "").resolve()
    if not (project / ".git").exists():
        return 0
    cwd = Path(payload.get("cwd") or os.getcwd())
    targets = [cwd / d for d in commit.dirs] or [cwd]
    # Decide on paths alone first: never run git or tests in a foreign tree.
    roots = {t for t in targets if inside(t, project)}
    if not roots:
        return 0
    for candidate in sorted(roots):
        root = toplevel(candidate)
        if root is None or not inside(root, project):
            continue
        for step in (("pii",) if mode == "pii" else ("tests",) if mode == "tests" else ("pii", "tests")):
            rc = run_pii(project, root, commit) if step == "pii" else run_tests(root)
            if rc:
                return rc
    return 0


if __name__ == "__main__":
    try:
        data = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)
    try:
        sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "all", data))
    except Exception as exc:
        # A crash on a commit must not let it through; anything else passes.
        is_commit = re.search(r"\bcommit\b", str((data.get("tool_input") or {}).get("command")))
        print(f"commit_guard: internal error {exc!r}", file=sys.stderr)
        sys.exit(2 if is_commit else 0)
