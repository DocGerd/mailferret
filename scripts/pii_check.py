#!/usr/bin/env python3
"""Scan for credentials and personal data. Stdlib only.

Modes (combinable; none given and no PATH = every tracked file):
  --staged               lines added in the index (exactly what a commit records)
  --unstaged             lines added in tracked files' working tree vs the index
  --include-untracked    untracked, non-ignored files
  --force-added SPEC     untracked files matching SPEC, ignored ones included (`git add -f`); repeatable
  --message-file FILE    the content of FILE only, never its name (a commit message); repeatable
  --commits RANGE        every commit in RANGE: added lines, file names, message, author/committer email
  PATH ...               the given files

Extra fixed-string patterns (case-insensitive, one per line, `#` comments) come
from the untracked `.git/info/pii-patterns` when present. Findings print only
`file:line: category`, never the matched text; a file name that itself matches
prints as `<path redacted #n>`. Files with NUL bytes are scanned as UTF-16 or
through their printable strings. A line containing `pii-check: ignore` is skipped.

Exit: 0 clean, 1 findings, 2 usage, 3 scan error. Callers block on any non-zero.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path

IGNORE_MARK = "pii-check: ignore"

ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "users.noreply.github.com")
ALLOWED_EMAIL_TLDS = (".example", ".invalid", ".test", ".localhost")
ALLOWED_EMAILS = ("git@github.com", "noreply@github.com", "noreply@anthropic.com")
IDENTITY_DOMAINS = ("example.com", "example.org", "example.net")
# Placeholders plus well-known default, CI and container accounts: none of them is personal data.
PLACEHOLDER_NAMES = {
    "user", "username", "name", "me", "you", "example", "alice", "bob",
    "default", "public", "shared", "all users", "...",
    "runner", "runneradmin", "ubuntu", "debian", "ec2-user", "vscode", "node", "codespace", "linuxbrew",
}
CODE_SUFFIXES = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift",
}

# Neutralise repo config that could run programs (fsmonitor, hooks, external diff, textconv).
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false"]
DIFF_OPTS = ["--no-color", "--no-ext-diff", "--no-textconv", "--text", "-U0", "--no-relative",
             "--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=d"]  # every status except deletions

# Split so the scanner does not flag its own source.
_KEY_HEADER = "-----BEGIN " + r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?" + "-----"
_PUTTY_HEADER = "PuTTY-User-" + r"Key-File-\d+:"
_SECRET_KEY = (
    r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?token"
    r"|auth[_-]?token|token)|(?:[A-Za-z0-9_.-]*[_.-])?(?:pass|pwd))"
)
_WORDS = r"(?:string|required|optional|redacted|none|null|true|false)"
_NOT_PLACEHOLDER = r"(?![<$%{*\[(!>|&~])(?!x{3})(?!\.{3})(?!(?:example|dummy|fake|placeholder))"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(_KEY_HEADER)),
    ("private-key", re.compile(_PUTTY_HEADER)),
    (
        "token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|sk-[A-Za-z0-9_-]{30,}"
            r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[abpr]-[A-Za-z0-9-]{10,})"
        ),
    ),
]
QUOTED_SECRET = re.compile(
    rf"(?i){_SECRET_KEY}[\"']?\s*[:=]\s*(?P<q>[\"']){_NOT_PLACEHOLDER}(?!{_WORDS}[\"'])[^\"'\n]{{6,}}(?P=q)"
)
# Unquoted values in code are expressions (`token = load()`), so this one applies to config, env and prose only.
UNQUOTED_SECRET = re.compile(
    rf"(?i){_SECRET_KEY}\s*[:=]\s*{_NOT_PLACEHOLDER}(?!{_WORDS}(?:[\s,;#]|$))[^\s\"'`,;#]{{6,}}"
)
EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
_NAME = r"([^/\\\s\"'`<>*$%{}()\[\]]+)"
HOME_POSIX = re.compile(r"(?:^|[^\w.-])(?:/var)?/(?:home|Users)/" + _NAME)
HOME_WSL = re.compile(r"(?i)/mnt/[a-z]/Users/" + _NAME)
HOME_WIN = re.compile(r"(?i)\b[A-Z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/)" + _NAME)


def _email_ok(match: re.Match[str]) -> bool:
    address, domain = match.group(0).lower(), match.group(1).lower()
    if address in ALLOWED_EMAILS:
        return True
    if any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS):
        return True
    return domain.endswith(ALLOWED_EMAIL_TLDS)


def identity_ok(address: str) -> bool:
    address = address.strip().lower()
    domain = address.rpartition("@")[2]
    return address == "noreply@github.com" or domain == "users.noreply.github.com" or domain in IDENTITY_DOMAINS


def scan_line(line: str, local: list[str], code: bool = False) -> Iterator[str]:
    if IGNORE_MARK in line:
        return
    line = line.replace("\0", "")
    for category, pattern in PATTERNS:
        if pattern.search(line):
            yield category
    if QUOTED_SECRET.search(line) or (not code and UNQUOTED_SECRET.search(line)):
        yield "secret-assignment"
    if any(not _email_ok(m) for m in EMAIL.finditer(line)):
        yield "email-address"
    for pattern in (HOME_POSIX, HOME_WSL, HOME_WIN):
        if any(m.group(1).lower() not in PLACEHOLDER_NAMES for m in pattern.finditer(line)):
            yield "home-path"
            break
    lowered = line.lower()
    if any(p in lowered for p in local):
        yield "local-pattern"


def is_code(path: str) -> bool:
    return Path(path).suffix.lower() in CODE_SUFFIXES


_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{4,}")
_UTF16LE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
_MAX_INFLATE = 16 << 20


def _strings(data: bytes) -> list[str]:
    out = [m.group().decode("ascii") for m in _PRINTABLE.finditer(data)]
    out += [m.group().decode("utf-16-le") for m in _UTF16LE.finditer(data)]
    out += [m.group().decode("utf-16-be") for m in _UTF16BE.finditer(data)]
    for m in _STREAM.finditer(data):  # compressed PDF streams
        try:
            inflated = zlib.decompressobj().decompress(m.group(1), _MAX_INFLATE)
        except zlib.error:
            continue
        out += [s.group().decode("ascii") for s in _PRINTABLE.finditer(inflated)]
    return out


def extract_lines(data: bytes) -> list[tuple[int, str]]:
    """(line number, text) pairs; line 0 for strings pulled out of binary data."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return list(enumerate(data.decode("utf-16", "replace").splitlines(), 1))
    if b"\0" not in data:
        return list(enumerate(data.decode("utf-8", "replace").splitlines(), 1))
    sample = data[:8192]
    half = max(len(sample) // 2, 1)
    even, odd = sample[0::2].count(0), sample[1::2].count(0)
    if odd > 0.4 * half and even < 0.05 * half:
        return list(enumerate(data.decode("utf-16-le", "replace").splitlines(), 1))
    if even > 0.4 * half and odd < 0.05 * half:
        return list(enumerate(data.decode("utf-16-be", "replace").splitlines(), 1))
    return [(0, s) for s in _strings(data)]


def git_bytes(*args: str) -> bytes:
    return subprocess.run([*GIT, *args], capture_output=True, check=True, timeout=120).stdout or b""


def git(*args: str) -> str:
    return git_bytes(*args).decode("utf-8", "replace")


class ScanError(Exception):
    pass


class Report:
    def __init__(self, local: list[str]) -> None:
        self.local = local
        self.findings: dict[str, None] = {}
        self._labels: dict[str, str] = {}

    def label(self, path: str) -> str:
        if path not in self._labels:
            hit = any(True for _ in scan_line(path, self.local))
            self._labels[path] = f"<path redacted #{sum(v.startswith('<') for v in self._labels.values()) + 1}>" if hit else path
        return self._labels[path]

    def add(self, where: str, line_no: int, category: str) -> None:
        self.findings[f"{where}:{line_no}: {category}"] = None

    def path(self, path: str, prefix: str = "") -> None:
        for category in dict.fromkeys(scan_line(path, self.local)):
            self.add(prefix + self.label(path), 0, category)

    def text(self, where: str, lines: Iterable[tuple[int, str]], code: bool = False) -> None:
        for no, line in lines:
            for category in dict.fromkeys(scan_line(line, self.local, code)):
                self.add(where, no, category)

    def file(self, path: str, data: bytes) -> None:
        self.path(path)
        self.text(self.label(path), extract_lines(data), is_code(path))


HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
HANDLED_STATUSES = frozenset("ACMRT")


def changed_paths(*extra: str) -> list[str]:
    """New-side paths of a diff; a status the scanner does not handle is an error."""
    fields = git("diff", "--name-status", "-z", "--no-color", "--no-relative", "--diff-filter=d", *extra).split("\0")
    paths, i = [], 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        if status[0] not in HANDLED_STATUSES:
            raise ScanError(f"unhandled diff status {status[0]!r}")
        step = 2 if status[0] in "RC" else 1
        paths.append(fields[i + step])
        i += 1 + step
    return paths


def added_lines(patch: bytes) -> Iterator[tuple[int, bytes]]:
    """Added lines of a single-file `-U0` patch. Headers end at the first `@@`; hunk lengths are counted."""
    lines = patch.split(b"\n")
    i = 0
    while i < len(lines) and not lines[i].startswith(b"@@"):
        i += 1
    while i < len(lines):
        m = HUNK.match(lines[i].decode("ascii", "replace"))
        i += 1
        if not m:
            continue
        old_left, new_no, new_left = int(m.group(1) or 1), int(m.group(2)), int(m.group(3) or 1)
        while (old_left > 0 or new_left > 0) and i < len(lines):
            raw = lines[i]
            i += 1
            if raw.startswith(b"+"):
                yield new_no, raw[1:]
                new_no, new_left = new_no + 1, new_left - 1
            elif raw.startswith(b"-"):
                old_left -= 1
            elif raw.startswith(b" "):
                new_no, old_left, new_left = new_no + 1, old_left - 1, new_left - 1


def scan_patch(report: Report, path: str, patch: bytes, prefix: str = "") -> None:
    rows = list(added_lines(patch))
    where, code = prefix + report.label(path), is_code(path)
    if b"\0" in b"".join(r for _, r in rows):
        # UTF-16 or binary: newline splitting is meaningless, scan the added bytes as one blob.
        report.text(where, extract_lines(b"\n".join(r for _, r in rows)), code)
    else:
        report.text(where, ((no, r.decode("utf-8", "replace")) for no, r in rows), code)


def scan_changes(report: Report, *extra: str) -> None:
    for path in changed_paths(*extra):
        report.path(path)
        scan_patch(report, path, git_bytes("diff", *DIFF_OPTS, *extra, "--", path))


def scan_commits(report: Report, rev_range: str) -> None:
    log = git("log", "--format=%H%x00%ae%x00%ce%x00%B%x00%x01", rev_range)
    for record in log.split("\0\x01"):
        parts = record.lstrip("\n").split("\0", 3)
        if len(parts) < 4:
            continue
        sha, author, committer, message = parts
        where = f"commit {sha[:12]}"
        if not identity_ok(author):
            report.add(where, 0, "author-email")
        if not identity_ok(committer):
            report.add(where, 0, "committer-email")
        report.text(f"{where} message", enumerate(message.splitlines(), 1))
    # Merge commits are covered by their parents' commits and the final-tree scan.
    for sha in git("rev-list", "--no-merges", rev_range).split():
        names = git("diff-tree", "-r", "--root", "--no-commit-id", "--name-status", "-z", "--diff-filter=d", sha)
        fields, i = names.split("\0"), 0
        while i < len(fields) and fields[i]:
            step = 2 if fields[i][0] in "RC" else 1
            path = fields[i + step]
            i += 1 + step
            report.path(path, f"commit {sha[:12]}:")
            patch = git_bytes("diff-tree", "-p", "--root", "--no-commit-id", *DIFF_OPTS, sha, "--", path)
            scan_patch(report, path, patch, f"commit {sha[:12]}:")


def load_local_patterns() -> list[str]:
    try:
        path = Path(git("rev-parse", "--git-path", "info/pii-patterns").strip())
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    return [p.strip().lower() for p in text.splitlines() if p.strip() and not p.lstrip().startswith("#")]


def scan_files(report: Report, paths: Iterable[str]) -> None:
    for name in paths:
        path = Path(name)
        try:
            # A symlink's committed content is its target string; never follow it out of the tree.
            data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        except (IsADirectoryError, FileNotFoundError):
            continue
        report.file(name, data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--unstaged", action="store_true")
    parser.add_argument("--include-untracked", action="store_true")
    parser.add_argument("--force-added", action="append", default=[], metavar="PATHSPEC")
    parser.add_argument("--message-file", action="append", default=[], metavar="FILE")
    parser.add_argument("--commits", metavar="RANGE")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)

    try:
        local = load_local_patterns()
        report = Report(local)
        if args.staged:
            scan_changes(report, "--cached")
        if args.unstaged:
            scan_changes(report)
        if args.include_untracked:
            scan_files(report, [p for p in git("ls-files", "--others", "--exclude-standard", "-z").split("\0") if p])
        if args.force_added:
            # No exclude options: ignored files are listed too.
            scan_files(report, [p for p in git("ls-files", "--others", "-z", "--", *args.force_added).split("\0") if p])
        for i, name in enumerate(args.message_file, 1):
            report.text(f"commit message #{i}", extract_lines(Path(name).read_bytes()))
        if args.commits:
            scan_commits(report, args.commits)
        if args.paths:
            scan_files(report, args.paths)
        if not (args.staged or args.unstaged or args.include_untracked or args.force_added
                or args.message_file or args.commits or args.paths):
            scan_files(report, [p for p in git("ls-files", "-z").split("\0") if p])
    except (subprocess.SubprocessError, OSError, ScanError) as exc:
        print(f"pii_check: scan failed ({exc.__class__.__name__}); treating as a failure", file=sys.stderr)
        return 3

    if report.findings:
        print("pii_check: possible credentials or personal data (text not shown):", file=sys.stderr)
        for f in report.findings:
            print(f"  {f}", file=sys.stderr)
        print(f"Use example.com, <user> placeholders, or mark a false positive with '{IGNORE_MARK}'.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
