# Status

Phase: 1 (design) drafted, adversarial plugin review folded in, awaiting Checkpoint 1.

## Done

- Phase 0: old setup retired (local clone and old repository archived, no MCP registrations existed).
- Phase 1 drafts: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/PLAN.md`.
- Adversarial plugin review: verdicts applied (ARCHITECTURE §9.7). Ship the `mail-reader` agent and the `doctor` skill; every other candidate is rejected.

## Next

- Checkpoint 1: decide the open decisions below, then start PLAN phase 2a.

## Open decisions (recommendations in ARCHITECTURE §11)

- License: MIT.
- LICENSE copyright holder: the GitHub handle, not a legal name.
- WSL credential backend: `command` backend with a `pass` recipe by default; Secret Service via `keyring` when `doctor` finds a working one.
- Claude Desktop distribution: `register claude-desktop` now; `.mcpb` only after host support for `type: uv` is verified.
- Plugin root in a `plugin/` subdirectory, evals outside it.
- No plugin `userConfig`; keyring (or `command`) is the single credential source.
- Plugin dependency locking via `uvx --constraints` with a generated file.
- `open_world_hint=True` on all tools.
- GreenMail integration on Linux CI only.

## Pending elsewhere

- Remove the `plugins/imap-mail` submodule from the claude-plugins monorepo, in a session started in that repository.
