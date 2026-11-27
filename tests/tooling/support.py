"""Shared helpers for the tooling tests: throwaway git repos and synthetic PII.

Every sample is assembled at runtime so this tree never contains a literal hit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCANNER = REPO / "scripts" / "pii_check.py"
GUARD = REPO / ".claude" / "hooks" / "commit_guard.py"

AT = "@"
EMAIL = "jane.roe" + AT + "mailhost-corp.de"
HOME = "/" + "home/" + "jroe"
ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test" + AT + "example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test" + AT + "example.com",
}


def run(args: list[str], cwd: Path, stdin: str | None = None, env: dict[str, str] | None = None,
        check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, input=stdin, capture_output=True, text=True,
                          env=env or ENV, check=check, timeout=120)


def git(cwd: Path, *args: str) -> str:
    return run(["git", *args], cwd, check=True).stdout


class RepoCase(unittest.TestCase):
    """A fresh repo with the scanner committed, `.env` ignored, and one clean commit."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="mf-tooling-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "scripts").mkdir()
        shutil.copy(SCANNER, self.repo / "scripts" / "pii_check.py")
        (self.repo / ".gitignore").write_text(".env\n.claude/worktrees/\n")
        (self.repo / "README.md").write_text("clean\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "init")

    def write(self, rel: str, content: str | bytes, root: Path | None = None) -> Path:
        path = (root or self.repo) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        return path

    def scan(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return run(["python3", str(SCANNER), *args], cwd or self.repo)

    def assert_clean_output(self, res: subprocess.CompletedProcess[str], *secrets: str) -> None:
        for secret in (EMAIL, HOME, *secrets):
            self.assertNotIn(secret, res.stdout + res.stderr)
