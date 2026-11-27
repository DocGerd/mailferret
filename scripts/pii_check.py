#!/usr/bin/env python3
"""Scan files for credentials and personal data. Stdlib only.

Modes:
  (default)          every tracked file
  --staged           lines added in the index, plus staged file names
  --worktree         lines added against HEAD in tracked files (staged or not);
                     with --include-untracked also untracked, non-ignored files
  PATH ...           the given files

Extra fixed-string patterns (case-insensitive, one per line) are read from the
untracked file `.git/info/pii-patterns` when it exists. Findings print only
`file:line: category`, never the matched text, so CI logs stay clean.
A line containing `pii-check: ignore` is skipped.

Exit: 0 clean, 1 findings, 3 usage or git error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

IGNORE_MARK = "pii-check: ignore"

ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "users.noreply.github.com")
ALLOWED_EMAIL_TLDS = (".example", ".invalid", ".test", ".localhost")
ALLOWED_EMAILS = ("git@github.com", "noreply@anthropic.com")
PLACEHOLDER_NAMES = {
    "user", "username", "name", "me", "you", "runner", "runneradmin", "example",
    "alice", "bob", "default", "public", "shared", "all users", "...",
}

# Split so the scanner does not flag its own source.
_KEY_HEADER = "-----BEGIN " + r"(?:[A-Z0-9]+ )*PRIVATE KEY" + "-----"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(_KEY_HEADER)),
    (
        "secret-assignment",
        re.compile(
            r"""(?ix)
            \b(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b
            ["']?\s*[:=]\s*["']
            (?![<$%{*])(?!x{3})(?!\.{3})
            [^\s"']{6,}["']
            """
        ),
    ),
    (
        "token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|xox[abpr]-[A-Za-z0-9-]{10,})\b"),
    ),
]
EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
HOME_POSIX = re.compile(r"(?:^|[^\w.-])/(?:home|Users)/([^/\s\"'`<>*$%{}()\[\]]+)/")
HOME_WIN = re.compile(r"(?i)\b[A-Z]:\\{1,2}Users\\{1,2}([^\\\s\"'`<>*$%{}()\[\]]+)\\")


def _email_ok(match: re.Match[str]) -> bool:
    address, domain = match.group(0).lower(), match.group(1).lower()
    if address in ALLOWED_EMAILS:
        return True
    if any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS):
        return True
    return domain.endswith(ALLOWED_EMAIL_TLDS)


def _name_ok(name: str) -> bool:
    return name.lower() in PLACEHOLDER_NAMES


def scan_line(line: str, local: list[str]) -> Iterator[str]:
    if IGNORE_MARK in line:
        return
    for category, pattern in PATTERNS:
        if pattern.search(line):
            yield category
    if any(not _email_ok(m) for m in EMAIL.finditer(line)):
        yield "email-address"
    if any(not _name_ok(m.group(1)) for m in HOME_POSIX.finditer(line)) or any(
        not _name_ok(m.group(1)) for m in HOME_WIN.finditer(line)
    ):
        yield "home-path"
    lowered = line.lower()
    if any(p in lowered for p in local):
        yield "local-pattern"


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], capture_output=True, check=True)
    return out.stdout.decode("utf-8", "replace")


def load_local_patterns() -> list[str]:
    try:
        path = Path(git("rev-parse", "--git-path", "info/pii-patterns").strip())
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, subprocess.CalledProcessError):
        return []
    return [p.strip().lower() for p in text.splitlines() if p.strip() and not p.lstrip().startswith("#")]


def read_lines(path: Path) -> list[str] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace").splitlines()


def scan_files(paths: Iterable[str], local: list[str]) -> Iterator[str]:
    for name in paths:
        yield from (f"{name}:0: {c}" for c in dict.fromkeys(scan_line(name, local)))
        lines = read_lines(Path(name))
        for no, line in enumerate(lines or [], 1):
            for category in dict.fromkeys(scan_line(line, local)):
                yield f"{name}:{no}: {category}"


def scan_diff(diff: str, local: list[str]) -> Iterator[str]:
    current, line_no = "?", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            current = raw[6:] if raw.startswith("+++ b/") else raw[4:]
            yield from (f"{current}:0: {c}" for c in dict.fromkeys(scan_line(current, local)))
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            line_no = int(m.group(1)) if m else 0
        elif raw.startswith("+"):
            for category in dict.fromkeys(scan_line(raw[1:], local)):
                yield f"{current}:{line_no}: {category}"
            line_no += 1
        elif raw.startswith(" "):
            line_no += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--worktree", action="store_true")
    parser.add_argument("--include-untracked", action="store_true")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)

    local = load_local_patterns()
    diff_args = ["diff", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR"]
    try:
        if args.staged:
            findings = list(scan_diff(git(*diff_args, "--cached"), local))
        elif args.worktree:
            has_head = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode == 0
            diff = git(*diff_args, "HEAD") if has_head else git(*diff_args, "--cached") + git(*diff_args)
            findings = list(scan_diff(diff, local))
            if args.include_untracked:
                untracked = git("ls-files", "--others", "--exclude-standard", "-z").split("\0")
                findings += scan_files([p for p in untracked if p], local)
        elif args.paths:
            findings = list(scan_files(args.paths, local))
        else:
            findings = list(scan_files([p for p in git("ls-files", "-z").split("\0") if p], local))
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"pii_check: git failed: {exc}", file=sys.stderr)
        return 3

    if findings:
        print("pii_check: possible credentials or personal data (text not shown):", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(f"Use example.com, <user> placeholders, or mark a false positive with '{IGNORE_MARK}'.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
