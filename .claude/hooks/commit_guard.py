#!/usr/bin/env python3
"""PreToolUse(Bash) guard for commit-creating git commands in this project.

  commit_guard.py pii    block (exit 2) on credentials/personal data in what the commit records
  commit_guard.py tests  block (exit 2) if `uv run pytest -q -x` fails; skipped without pyproject.toml
  commit_guard.py all    both, PII first

A command that could create a commit but cannot be parsed unambiguously (shell
expansion, an unknown subcommand or alias, `bash -c`, broken quoting) is
treated as a commit and scanned in full. A commit is checked when its target
shares this project's git common dir (any linked worktree, wherever it lives);
other repositories are left alone. Any error on a possible commit blocks it.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# CI `pii-check` on every PR is the authoritative gate; this hook is defense in depth.
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
# The hook timeout in settings.json is 600 s. All steps share this deadline so the hook never times out.
DEADLINE = time.monotonic() + 540
PYTEST_CAP_S = 420
# Inherited, these give the commit another repo, index or config than the guard resolves: a commit then blocks.
REDIRECTING_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                   "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                   "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM")
# The guard's own git and scanner runs drop these; anything in REDIRECTING_ENV has blocked before they start.
SCRUBBED_ENV = ("GIT_PREFIX", "GIT_CONFIG")

PUNCT = ";&|()<>\n"
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env",
                       "--super-prefix", "--list-cmds"}
COMMIT_OPTS_WITH_VALUE = {
    "-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
    "--author", "--date", "--fixup", "--squash", "-t", "--template", "--cleanup", "--trailer",
    "--pathspec-from-file", "--strategy", "--strategy-option",
}
SHORT_WITH_VALUE = {"commit": set("mFCct"), "merge": set("mFsX")}
# Subcommands that create commits from the index, the working tree or external input.
COMMIT_LIKE = {"commit", "merge", "cherry-pick", "revert", "am", "rebase", "stash", "commit-tree", "pull",
               "filter-branch", "citool", "gui"}
# Known not to create commits. Anything else (an alias, a plugin) is ambiguous.
NON_COMMITTING = {
    "log", "show", "diff", "status", "grep", "blame", "shortlog", "rev-list", "rev-parse", "describe",
    "cat-file", "ls-files", "ls-tree", "diff-tree", "diff-index", "diff-files", "show-ref", "for-each-ref",
    "reflog", "branch", "tag", "add", "rm", "mv", "restore", "reset", "checkout", "switch", "fetch", "clone",
    "init", "remote", "clean", "format-patch", "help", "version", "worktree", "whatchanged", "name-rev",
    "merge-base", "push", "config", "gc", "fsck", "prune", "ls-remote", "show-branch", "range-diff",
    "apply", "archive", "bundle", "count-objects", "var", "check-ignore", "check-attr", "check-ref-format",
    "hash-object", "verify-commit", "verify-tag", "maintenance", "sparse-checkout", "lfs",
}
# Deliberately absent: `bisect run` and `submodule foreach` execute arbitrary commands.
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "env", "then", "do", "else",
            "exec", "!", "{", "if", "while", "until", "elif"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
COULD_COMMIT = re.compile(r"\bgit\b|[$`]|\b(?:" + "|".join(map(re.escape, COMMIT_LIKE)) + r")\b")
HEREDOC = re.compile(r"(<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\2[^\n]*)\n(?:(.*?)\n)?[ \t]*\3[ \t]*(?=\n|$)", re.S)


class Blocked(Exception):
    pass


@dataclass
class Commit:
    detected: bool = False
    ambiguous: bool = False
    worktree: bool = False  # -a/--all/pathspecs/--include/--only: unstaged changes get committed
    adds: bool = False  # git add/rm/mv in the same command
    all_worktrees: bool = False  # the target directory cannot be known: scan every worktree
    dirs: list[Path] = field(default_factory=list)
    maybe_dirs: list[Path] = field(default_factory=list)  # earlier cd targets a subshell may have returned to
    force_paths: list[Path] = field(default_factory=list)  # `git add -f` pathspecs, absolute
    messages: list[str] = field(default_factory=list)
    message_files: list[Path] = field(default_factory=list)

    def merge(self, other: Commit) -> None:
        for name in ("detected", "ambiguous", "worktree", "adds", "all_worktrees"):
            setattr(self, name, getattr(self, name) or getattr(other, name))
        for name in ("dirs", "maybe_dirs", "force_paths", "messages", "message_files"):
            getattr(self, name).extend(getattr(other, name))


def expands(token: str) -> bool:
    return "$" in token or "`" in token


def segments(text: str) -> tuple[list[list[str]], bool] | None:
    """Command words split at shell operators, redirections dropped; plus whether a subshell occurs."""
    lex = shlex.shlex(text, posix=True, punctuation_chars=PUNCT)
    lex.whitespace, lex.whitespace_split, lex.commenters = " \t\r", True, ""
    try:
        tokens = list(lex)
    except ValueError:
        return None
    out: list[list[str]] = [[]]
    skip = subshell = False
    for tok in tokens:
        if skip:
            skip = False
        elif tok and all(c in PUNCT for c in tok):
            if ("<" in tok or ">" in tok) and "(" not in tok:  # `<(`/`>(` open a process substitution
                skip = True  # redirection target
            else:
                subshell = subshell or "(" in tok or ")" in tok
                out.append([])
        else:
            out[-1].append(tok)
    return [s for s in out if s], subshell


def _strip_wrappers(tokens: list[str], result: Commit) -> list[str]:
    while tokens and (re.fullmatch(r"\w+=.*", tokens[0]) or tokens[0] in WRAPPERS):
        if tokens[0].startswith(("GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=", "GIT_COMMON_DIR=")):
            result.all_worktrees = result.ambiguous = True
        tokens.pop(0)
        while tokens and (tokens[0].startswith("-") or re.fullmatch(r"[\d.]+[smhd]?", tokens[0])):
            tokens.pop(0)
    return tokens


def _commit_args(rest: list[str], target: Path, result: Commit, sub: str) -> None:
    is_commit, short_with_value = sub == "commit", SHORT_WITH_VALUE[sub]
    def message(value: str) -> None:
        result.messages.append(value)

    def message_file(value: str) -> None:
        if value == "-" or expands(value):
            result.messages.append("\0stdin")
        else:
            result.message_files.append(target / os.path.expanduser(value))

    j = 0
    while j < len(rest):
        arg = rest[j]
        nxt = rest[j + 1] if j + 1 < len(rest) else ""
        if arg == "--":
            result.worktree = result.worktree or (is_commit and j + 1 < len(rest))
            break
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if name in ("--message", "--file"):
                (message if name == "--message" else message_file)(value if eq else nxt)
            if name in ("--trailer", "--author"):
                message(value if eq else nxt)
            if is_commit and name in ("--all", "--include", "--only", "--interactive", "--patch"):
                result.worktree = True
            j += 2 if name in COMMIT_OPTS_WITH_VALUE and not eq else 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            k = 1
            while k < len(arg):
                c = arg[k]
                if c in short_with_value:
                    value = arg[k + 1 :]
                    if not value:
                        value, j = nxt, j + 1
                    if c == "m":
                        message(value)
                    elif c == "F":
                        message_file(value)
                    break
                if is_commit and c in "aiop":
                    result.worktree = True
                k += 1
            j += 1
            continue
        if is_commit:
            result.worktree = True  # pathspec
        j += 1


def _git_segment(tokens: list[str], cur: Path, result: Commit) -> None:
    if any(expands(t) for t in tokens):
        result.ambiguous = True
    i, cdir = 1, Path()
    while i < len(tokens) and tokens[i].startswith("-"):
        name, eq, value = tokens[i].partition("=")
        if name in ("--git-dir", "--work-tree"):
            result.all_worktrees = True
        if name in GIT_OPTS_WITH_VALUE and not eq:
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            i += 1
        if name == "-C":
            if expands(value):
                result.all_worktrees = True
            cdir = cdir / os.path.expanduser(value)
        i += 1
    sub, rest = (tokens[i], tokens[i + 1 :]) if i < len(tokens) else ("", [])
    target = cur / cdir
    if not sub:
        return
    if sub in ("add", "rm", "mv"):
        result.adds = True
    if sub == "add":
        opts = rest[: rest.index("--")] if "--" in rest else rest
        if any(t == "--force" or re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", t) for t in opts):
            specs = [t for t in rest if t != "--" and not t.startswith("-")]
            for spec in specs or ["."]:
                bad = expands(spec) or spec.startswith(":") or any(t.startswith("--pathspec-from-file") for t in rest)
                result.force_paths.append(target if bad else target / spec)
    if sub in NON_COMMITTING and not expands(sub):
        return
    result.detected = True
    result.dirs.append(target)
    if sub not in COMMIT_LIKE or expands(sub):
        result.ambiguous = True
        return
    if sub != "commit":
        result.worktree = True
    if sub in ("commit", "merge"):
        _commit_args(rest, target, result, sub)


def analyse(command: str, cwd: Path) -> Commit:
    result = Commit()
    bodies: list[str] = []

    def keep_header(m: re.Match[str]) -> str:
        bodies.append(m.group(4) or "")
        return m.group(1)

    text = HEREDOC.sub(keep_header, command).replace("\\\n", " ")  # line continuations
    parsed = segments(text)
    mentions_git = re.search(r"\bgit\b", command) is not None
    if parsed is None:
        if mentions_git:
            result.detected = result.ambiguous = result.all_worktrees = True
            result.dirs.append(cwd)
    else:
        segs, subshell = parsed
        cur, visited = cwd, [cwd]
        for raw in segs:
            tokens = _strip_wrappers(list(raw), result)
            if not tokens:
                continue
            head = tokens[0]
            if head in ("cd", "pushd", "popd"):
                args = [t for t in tokens[1:] if not t.startswith("-")]
                if head == "popd" or (args and (args[0] == "-" or expands(args[0]))):
                    result.all_worktrees = True
                else:
                    cur = cur / os.path.expanduser(args[0]) if args else Path.home()
                    visited.append(cur)
                continue
            if head in SHELLS and "-c" in tokens[1:-1]:
                result.merge(analyse(tokens[tokens.index("-c") + 1], cur))
                continue
            if expands(head) or Path(head).name not in ("git", "git.exe"):
                seg = " ".join(tokens)
                words = set(re.findall(r"[\w-]+", seg))
                if (expands(head) and mentions_git) or (re.search(r"\bgit\b", seg) and words & COMMIT_LIKE):
                    # xargs/sudo/env -C git commit, $G commit: directory and message are unknown.
                    result.detected = result.ambiguous = result.all_worktrees = True
                    result.dirs.append(cur)
                    result.messages.append(seg)
                continue
            _git_segment(tokens, cur, result)
        if subshell and len(visited) > 1:
            result.maybe_dirs.extend(visited)
    if result.detected:
        result.messages.extend(bodies)
        if "\0stdin" in result.messages:
            result.messages = [m for m in result.messages if m != "\0stdin"]
            if not bodies:
                result.messages.append(command)  # piped message: the command text is all we can see
    if result.ambiguous:
        result.worktree = result.adds = True
    return result


def remaining(cap: float) -> float:
    left = DEADLINE - time.monotonic()
    if left < 5:
        raise Blocked("Commit blocked: the guard ran out of its time budget.")
    return min(cap, left)


def git_env(drop_all: bool = False) -> dict[str, str]:
    return {k: v for k, v in os.environ.items()
            if not (k.startswith("GIT_") if drop_all else
                    k in SCRUBBED_ENV or k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")))}


def git_out(cwd: Path, *args: str) -> str | None:
    try:
        out = subprocess.run([*GIT, *args], cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                             env=git_env(), timeout=remaining(15))
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def repo_of(path: Path) -> tuple[Path, Path] | None:
    """(toplevel, common git dir) of the work tree containing path."""
    out = git_out(path, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir")
    lines = (out or "").splitlines()
    if len(lines) != 2:
        return None
    return Path(lines[0]).resolve(), Path(lines[1]).resolve()


def worktrees(project: Path) -> list[Path]:
    out = git_out(project, "worktree", "list", "--porcelain")
    if out is None:
        raise Blocked("Commit blocked: cannot list this repository's worktrees.")
    paths = [Path(line[9:]) for line in out.splitlines() if line.startswith("worktree ")]
    return [p for p in paths if p.is_dir()]  # stale (prunable) entries have no directory


def run_scanner(project: Path, cwd: Path, args: list[str]) -> None:
    scanner = project / "scripts" / "pii_check.py"
    if not scanner.is_file():
        raise Blocked("Commit blocked: scripts/pii_check.py is missing.")
    try:
        res = subprocess.run([sys.executable, str(scanner), *args], cwd=cwd, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, errors="replace", env=git_env(),
                             timeout=remaining(120))
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked(f"Commit blocked: PII scanner did not run ({exc.__class__.__name__}).") from None
    if res.returncode != 0:
        raise Blocked(f"Commit blocked by the PII guard (scanner exit {res.returncode}).\n{res.stderr.strip()}")


def run_pii(project: Path, root: Path, commit: Commit) -> None:
    args = ["--staged"]
    args += ["--unstaged"] if commit.worktree or commit.adds else []
    args += ["--include-untracked"] if commit.adds else []
    for path in commit.force_paths:
        resolved = path.resolve()
        if resolved == root or root in resolved.parents:
            args += ["--force-added", str(resolved)]
    run_scanner(project, root, args)


def run_messages(project: Path, root: Path, commit: Commit) -> None:
    if not (commit.messages or commit.message_files):
        return
    with tempfile.TemporaryDirectory() as tmp:
        text_file = Path(tmp) / "message"
        text_file.write_text("\n".join(commit.messages), encoding="utf-8")
        args = ["--message-file", str(text_file)]
        for path in commit.message_files:
            args += ["--message-file", str(path)]
        run_scanner(project, root, args)


def run_tests(root: Path) -> None:
    if not (root / "pyproject.toml").is_file():
        return
    try:
        res = subprocess.run(["uv", "run", "pytest", "-q", "-x"], cwd=root, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, errors="replace", env=git_env(drop_all=True),
                             timeout=remaining(PYTEST_CAP_S))
    except FileNotFoundError:
        raise Blocked("Commit blocked: uv not found, tests cannot run.") from None
    except subprocess.TimeoutExpired:
        raise Blocked("Commit blocked: the test suite timed out.") from None
    if res.returncode not in (0, 5):  # 5 = no tests collected
        tail = "\n".join((res.stdout + res.stderr).strip().splitlines()[-30:])
        raise Blocked(f"Commit blocked: `uv run pytest -q -x` failed (exit {res.returncode}).\n{tail}")


def main(mode: str, payload: dict) -> int:
    cwd = Path(payload.get("cwd") or os.getcwd())
    commit = analyse(str((payload.get("tool_input") or {}).get("command") or ""), cwd)
    if not commit.detected:
        return 0
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or "").resolve()
    if not (project / ".git").exists():
        return 0
    try:
        inherited = sorted(k for k in REDIRECTING_ENV if k in os.environ)
        if inherited:
            raise Blocked(f"Commit blocked: inherited {', '.join(inherited)} would redirect the commit; unset it.")
        own = repo_of(project)
        if own is None:
            raise Blocked("Commit blocked: cannot resolve this project's git repository.")
        targets = list(dict.fromkeys(commit.dirs or [cwd]))
        if commit.all_worktrees:
            targets += worktrees(project)
        roots: dict[Path, None] = {}
        for target in targets + [d for d in dict.fromkeys(commit.maybe_dirs) if d not in targets]:
            repo = repo_of(target)
            if repo is None and target not in targets:
                continue
            if repo is None:
                raise Blocked("Commit blocked: a commit target is not a resolvable git work tree "
                              f"({target}). Run the commit from inside the repository.")
            if repo[1] == own[1]:
                roots[repo[0]] = None
        if not roots:
            return 0
        steps = {"pii": ("pii",), "tests": ("tests",)}.get(mode, ("pii", "tests"))
        if "pii" in steps:
            run_messages(project, next(iter(roots)), commit)
        for root in roots:
            for step in steps:
                run_pii(project, root, commit) if step == "pii" else run_tests(root)
    except Blocked as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        command = str(((data.get("tool_input") or {}) if isinstance(data, dict) else {}).get("command") or "")
    except (ValueError, AttributeError):
        sys.exit(2 if COULD_COMMIT.search(raw) else 0)
    try:
        sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "all", data))
    except Exception as exc:
        # A crash must not let a possible commit through; anything else passes.
        print(f"commit_guard: internal error {exc.__class__.__name__}", file=sys.stderr)
        sys.exit(2 if COULD_COMMIT.search(command) else 0)
