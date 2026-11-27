""".claude/settings.json: JSON validity, the blocking guard, and permission rules.

Permissions are not live in a subprocess, so rules are evaluated here the way Claude Code
matches Bash rules: `*` matches any text, a rule without `*` matches the exact command,
and a deny wins over an allow. Anything not allowed prompts.
"""

from __future__ import annotations

import json
import re
import unittest

from .support import GUARD, REPO

SETTINGS = json.loads((REPO / ".claude" / "settings.json").read_text())
PERMS = SETTINGS["permissions"]


def _matches(rule: str, command: str) -> bool:
    m = re.fullmatch(r"Bash\((.*)\)", rule, re.S)
    if not m:
        return False
    pattern = m.group(1)
    return re.fullmatch(".*".join(map(re.escape, pattern.split("*"))), command, re.S) is not None


def decision(command: str) -> str:
    if any(_matches(r, command) for r in PERMS["deny"]):
        return "deny"
    return "allow" if any(_matches(r, command) for r in PERMS["allow"]) else "ask"


class Settings(unittest.TestCase):
    def test_json_files_parse(self) -> None:
        for name in (".claude/settings.json", ".mcp.json"):
            json.loads((REPO / name).read_text())

    def test_guard_blocks_on_failure_within_budget(self) -> None:
        (entry,) = [h for group in SETTINGS["hooks"]["PreToolUse"] for h in group["hooks"]]
        self.assertEqual(entry["onFailure"], "block")
        m = re.search(r"DEADLINE = time.monotonic\(\) \+ (\d+)", GUARD.read_text())
        assert m is not None
        budget = int(m.group(1))
        self.assertLess(budget, entry["timeout"])

    def test_git_diff_cannot_read_outside_the_repo(self) -> None:
        for command in ("git diff /dev/null /etc/hostname", "git diff --stat /dev/null /etc/hostname",
                        "git diff --staged /dev/null x", "git diff origin/main...HEAD /dev/null x"):
            with self.subTest(command=command):
                self.assertEqual(decision(command), "ask")
        self.assertEqual(decision("git diff --no-index a b"), "deny")
        self.assertEqual(decision("git log -p --no-index"), "deny")
        for command in ("git diff", "git diff --staged", "git diff --stat", "git diff origin/main...HEAD"):
            with self.subTest(command=command):
                self.assertEqual(decision(command), "allow")

    def test_uv_and_mypy_allow_only_safe_forms(self) -> None:
        for command in ("uv sync --python /tmp/x", "uv sync --index-url https://example.com/simple",
                        "uv lock --extra-index-url https://example.com", "uv lock --default-index https://example.com",
                        "uv sync --project ../other", "uv sync --directory /tmp", "uv sync -p /tmp/x",
                        "uv run mypy --python-executable /tmp/x src", "uv run mypy --config-file /tmp/x.ini src",
                        "uv run pytest --python /tmp/x", "uv run ruff --directory /tmp check"):
            with self.subTest(command=command):
                self.assertNotEqual(decision(command), "allow")
        for command in ("uv sync", "uv sync --locked", "uv lock", "uv lock --check", "uv run mypy --strict src",
                        "uv run pytest -q", "uv run ruff check ."):
            with self.subTest(command=command):
                self.assertEqual(decision(command), "allow")

    def test_secret_locations_denied_for_read_and_edit(self) -> None:
        for path in ("~/.ssh/**", "~/.git-credentials", "~/.netrc", "~/.config/gh/hosts.yml", "**/.envrc",
                     "**/.env", "~/.password-store/**", "~/.gnupg/**", "~/.local/share/kwalletd/**",
                     "~/AppData/Local/Microsoft/Vault/**", "~/AppData/Roaming/Microsoft/Vault/**",
                     "//mnt/*/Users/*/AppData/Local/Microsoft/Vault/**", "~/AppData/Roaming/Microsoft/Credentials/**",
                     "~/.local/share/mailferret/**", "~/AppData/Local/mailferret/**",
                     "//mnt/*/Users/*/AppData/Local/mailferret/**", "~/.config/mailferret/**"):
            for tool in ("Read", "Edit"):
                with self.subTest(rule=f"{tool}({path})"):
                    self.assertIn(f"{tool}({path})", PERMS["deny"])


if __name__ == "__main__":
    unittest.main()
