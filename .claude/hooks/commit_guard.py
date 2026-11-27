#!/usr/bin/env python3
"""PreToolUse(Bash) guard for commit-creating git commands in this project.

  commit_guard.py pii    block (exit 2) on credentials/personal data in what the commit records
  commit_guard.py tests  block (exit 2) if `uv run pytest -q -x` fails; skipped without pyproject.toml
  commit_guard.py all    both, PII first

A command that could commit must be plain, or it blocks. It could commit when
git runs a subcommand that is not known to be read-only, a git word is followed
by a committing subcommand under another command, a git word is obfuscated with
quotes or backslashes, a command runner (eval, env, xargs, sh, ...) sees git or
an expansion, an expanded command name may be git, a $(...) or backtick body
could commit, or the text cannot be parsed. Plain is git (with only -C <path> or
--no-pager before the subcommand) and simple commands, joined only by &&, ;, ||
or newlines, with no redirect but a quoted `git commit -F -` heredoc.
Assignments, shell builtins and keywords, runners, a git or shell word under
another command, comments, unknown git subcommands, expansions before the
subcommand, and $(...) or backticks other than a `$(cat <<'EOF' ... EOF)`
message are not plain; cd/pushd may only come first, followed by &&. Other
expansions in a commit's arguments, or a commit only named inside an argument,
make it scanned in full. This is best-effort: the .githooks pre-commit hook and
CI enforce. A commit is checked when its target shares this project's git
common dir (any linked worktree, wherever it lives); other repositories are left
alone. Any error on a possible commit blocks it.
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
# Inherited, these give the commit another repo, index, config or discovery than the guard resolves, or make the
# shell that runs it load code first: a commit then blocks.
REDIRECTING_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                   "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                   "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_CEILING_DIRECTORIES",
                   "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")
REDIRECTING_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "BASH_FUNC_")
SCRUBBED_ENV = ("GIT_PREFIX", "GIT_CONFIG")
NOT_PLAIN = ("Commit blocked: run the commit as a plain `git commit` command (no env assignments, exports, "
             "env/eval/source/., subshells, functions or expansions before git).")
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*\+?=")
# Bash builtins and keywords (`compgen -b -k`) can change what a later git inherits; these few cannot.
SAFE_BUILTINS = {"echo", "printf", "true", "false", "test", "[", "pwd", ":"}
SHELL_WORDS = {
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen", "complete",
    "compopt", "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false",
    "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd",
    "printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift", "shopt", "source",
    "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait",
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do", "done", "in",
    "function", "time", "{", "}", "!", "[[", "]]", "coproc",
}
GIT_NAMES = ("git", "git.exe")

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
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
# Commands that run their arguments as commands; not a closed set.
RUNNERS = {"env", "sudo", "doas", "su", "xargs", "nohup", "timeout", "nice", "stdbuf", "setsid", "flock", "watch",
           "script", "ssh", "parallel", "python", "python3", "perl", "ruby", "node", "awk", *SHELLS}
UNSAFE_HEADS = SHELL_WORDS - SAFE_BUILTINS | RUNNERS
EXECUTORS = RUNNERS | {"eval", "exec", "command", "builtin", "source", "."}
CAT_HEREDOC = re.compile(r"\$\(cat <<-?'[A-Za-z_]\w*'\s*\)")
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
    risky: bool = False  # the command could commit, so it must be plain (see the module docstring)
    plain: bool = True
    dirs: list[Path] = field(default_factory=list)
    force_paths: list[Path] = field(default_factory=list)  # `git add -f` pathspecs, absolute
    messages: list[str] = field(default_factory=list)
    message_files: list[Path] = field(default_factory=list)


def expands(token: str) -> bool:
    return "$" in token or "`" in token


def redirecting(name: str) -> bool:
    return name in REDIRECTING_ENV or name.startswith(REDIRECTING_PREFIXES)


def names_commit(text: str) -> bool:
    return re.search(r"\bgit\b", text) is not None and bool(set(re.findall(r"[\w-]+", text)) & COMMIT_LIKE)


def runs_code(token: str) -> bool:
    """Command substitution or a comment, quoted or not."""
    return "$(" in token or "`" in token or token.startswith("#")


@dataclass
class Segment:
    words: list[str] = field(default_factory=list)
    raws: list[str] = field(default_factory=list)  # each word as written, before quote and escape removal
    redirects: list[str] = field(default_factory=list)  # also any operator other than &&, ;, || and newline
    joiner: str = ""  # the operator after it
    quoted_heredoc: bool = False


def segments(text: str) -> list[Segment] | None:
    lex = shlex.shlex(text, posix=True, punctuation_chars=PUNCT)
    lex.whitespace, lex.whitespace_split, lex.commenters = " \t\r", True, ""
    out, start, skip, heredoc = [Segment()], 0, False, False
    try:
        while (tok := lex.get_token()) != lex.eof:
            end = lex.instream.tell() - len(lex._pushback_chars)
            raw, start = text[start:end].strip(" \t\r"), end
            if tok and raw == tok and all(c in PUNCT for c in tok):
                joiner = tok.replace("\n", "")
                redirect = ("<" in tok or ">" in tok) and "(" not in tok and ")" not in tok
                if joiner not in ("", "&&", ";", "||"):
                    out[-1].redirects.append(tok)  # any other operator: not plain
                if not redirect or tok[0] in ";&|\n":
                    out[-1].joiner = joiner or ";"
                    out.append(Segment())
                skip = redirect  # the target or heredoc delimiter
                heredoc = tok.endswith("<<")
            elif skip:
                skip = False
                if heredoc:
                    out[-1].quoted_heredoc = raw.lstrip("-")[:1] in ("'", '"')
            else:
                out[-1].words.append(tok)
                out[-1].raws.append(raw)
    except ValueError:
        return None
    return [seg for seg in out if seg.words or seg.redirects]


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


def _git_segment(tokens: list[str], cur: Path, result: Commit, heredoc: bool) -> None:
    i, cdir = 1, Path()
    while i < len(tokens) and tokens[i].startswith("-"):
        name, eq, value = tokens[i].partition("=")
        if name in GIT_OPTS_WITH_VALUE and not eq:
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            i += 1
        if name == "-C" and not eq and not expands(value):
            cdir = cdir / os.path.expanduser(value)
        elif name != "--no-pager":
            result.plain = False
        i += 1
    sub, rest = (tokens[i], tokens[i + 1 :]) if i < len(tokens) else ("", [])
    target = cur / cdir
    if any(expands(t) for t in rest):
        result.ambiguous = True
    if sub in ("add", "rm", "mv"):
        result.adds = True
    if sub == "add":
        opts = rest[: rest.index("--")] if "--" in rest else rest
        if any(t == "--force" or re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", t) for t in opts):
            specs = [t for t in rest if t != "--" and not t.startswith("-")]
            for spec in specs or ["."]:
                bad = expands(spec) or spec.startswith(":") or any(t.startswith("--pathspec-from-file") for t in rest)
                result.force_paths.append(target if bad else target / spec)
    before = len(result.messages)
    if sub and sub not in NON_COMMITTING:
        result.detected = result.risky = True
        result.dirs.append(target)
        if sub not in COMMIT_LIKE:  # an alias or a command-running subcommand
            result.plain, result.ambiguous = False, True
        if sub != "commit":
            result.worktree = True
        if sub in ("commit", "merge"):
            _commit_args(rest, target, result, sub)
    exempt = result.messages[before:]
    if (any(runs_code(t) and not (t in exempt and (t.startswith("#") or CAT_HEREDOC.fullmatch(t))) for t in rest)
            or (heredoc and "\0stdin" not in exempt)):
        result.plain = False


def _word_segment(words: list[str], cur: Path, result: Commit, dequoted: str) -> None:
    head = words[0]
    gits = [i for i, t in enumerate(words) if Path(t).name in GIT_NAMES]
    runs_command = head in EXECUTORS or any(Path(t).name in SHELLS for t in words)
    if ((gits and any(t in COMMIT_LIKE for t in words[gits[0] + 1 :]))
            or (runs_command and (re.search(r"\bgit\b", dequoted) or any(expands(t) for t in words[1:])))
            or (expands(head) and re.search("git", dequoted, re.I))):
        result.risky = True
    if (ASSIGNMENT.match(head) or head in UNSAFE_HEADS
            or any(expands(t) or runs_code(t) or Path(t).name in (*GIT_NAMES, *SHELLS) for t in words)):
        result.plain = False
    elif names_commit(seg := " ".join(words)):
        # A commit only named inside an argument (grep, echo): directory and message are unknown.
        result.detected = result.ambiguous = result.all_worktrees = True
        result.dirs.append(cur)
        result.messages.append(seg)


def _cd(words: list[str], cur: Path, result: Commit) -> Path:
    args = [t for t in words[1:] if not t.startswith("-")]
    if args and args[0] == "-":
        result.all_worktrees = True
        return cur
    return cur / os.path.expanduser(args[0]) if args else Path.home()


def _substitutions_could_commit(words: list[str], cwd: Path) -> bool:
    """Words split inside an unquoted $(...) or backticks, so the segment is re-read as commands."""
    words = [w for w in words if not CAT_HEREDOC.fullmatch(w)]
    if not any("$(" in w or "`" in w for w in words):
        return False
    body = analyse(re.sub(r"\$\(|[`)]", " ; ", " ".join(words)), cwd)
    return body.risky or body.detected


def analyse(command: str, cwd: Path) -> Commit:
    result = Commit()
    bodies: list[str] = []

    def keep_header(m: re.Match[str]) -> str:
        bodies.append(m.group(4) or "")
        return m.group(1)

    text = HEREDOC.sub(keep_header, command).replace("\\\n", " ")  # line continuations
    dequoted = re.sub(r"[\"'\\]", "", command)
    segs = segments(text)
    if segs is None:
        result.risky, result.plain = True, False
        segs = []
    elif len(bodies) != sum(seg.redirects.count("<<") + sum(bool(CAT_HEREDOC.fullmatch(w)) for w in seg.words)
                            for seg in segs):
        result.plain = False  # a heredoc the guard could not cut out
    cur = cwd
    for i, seg in enumerate(segs):
        heredoc = seg.redirects == ["<<"] and seg.quoted_heredoc
        if any(raw != w and (Path(w).name in GIT_NAMES or w in UNSAFE_HEADS)
               for w, raw in zip(seg.words, seg.raws)):
            result.risky, result.plain = True, False  # quotes or escapes hide what runs
        comment = next((j for j, raw in enumerate(seg.raws) if raw.startswith("#")), None)
        if comment is not None and re.search(r"\bgit\b", " ".join(seg.words[comment:])):
            result.risky, result.plain = True, False  # a joined line continuation after a comment
        if _substitutions_could_commit(seg.words, cur):
            result.risky = True
        if not seg.words or (seg.redirects and not heredoc):
            result.plain = False
        if not seg.words:
            continue
        if seg.words[0] in ("cd", "pushd"):
            if i or seg.joiner != "&&" or heredoc or any(expands(t) or runs_code(t) for t in seg.words):
                result.plain = False
            cur = _cd(seg.words, cur, result)
        elif Path(seg.words[0]).name in GIT_NAMES:
            _git_segment(seg.words, cur, result, heredoc)
        else:
            if heredoc:
                result.plain = False
            _word_segment(seg.words, cur, result, dequoted)
    if result.risky:
        result.detected = True
        if not result.plain:
            result.dirs.append(cwd)
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
    """Redirecting names never get here: main() blocks them first."""
    return {k: v for k, v in os.environ.items() if not (k.startswith("GIT_") if drop_all else k in SCRUBBED_ENV)}


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
        inherited = sorted(k for k in os.environ if redirecting(k))
        if inherited:
            raise Blocked(f"Commit blocked: inherited {', '.join(inherited)} would redirect the commit; unset it.")
        if commit.risky and not commit.plain:
            raise Blocked(NOT_PLAIN)
        own = repo_of(project)
        if own is None:
            raise Blocked("Commit blocked: cannot resolve this project's git repository.")
        targets = list(dict.fromkeys(commit.dirs or [cwd]))
        if commit.all_worktrees:
            targets += worktrees(project)
        roots: dict[Path, None] = {}
        for target in targets:
            repo = repo_of(target)
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
