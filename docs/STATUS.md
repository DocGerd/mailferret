# Status

Phase: 1 (design) drafted, awaiting the adversarial plugin review and Checkpoint 1.

## Done

- Phase 0: old setup retired (local clone and old repository archived, no MCP registrations existed).
- Phase 1 drafts: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/PLAN.md`.

## Next

- Adversarial review of the plugin component table (ARCHITECTURE §9.7).
- Checkpoint 1: decide the open decisions below, then start PLAN phase 2a.

## Open decisions (recommendations in ARCHITECTURE §11)

- License: MIT.
- WSL credential backend: `command` backend with a `pass` recipe by default; Secret Service via `keyring` when `doctor` finds a working one.
- Claude Desktop distribution: `register claude-desktop` now; `.mcpb` only after host support for `type: uv` is verified.
- Plugin root in a `plugin/` subdirectory rather than the repo root.
- No plugin `userConfig`; keyring (or `command`) is the single credential source.
- `open_world_hint=True` on all tools.
- GreenMail integration on Linux CI only.

## Pending elsewhere

- Remove the `plugins/imap-mail` submodule from the claude-plugins monorepo, in a session started in that repository.
