# Claude Code plugin / Desktop extension facts (input to the Phase 1 design)

Taken from the official docs at design time. Statements marked *inference* were not stated in the docs.

## Plugin layout
- Sources: code.claude.com/docs/en/plugins/manifest-reference.md and /plugins/components.md.
- `.claude-plugin/plugin.json`: only `name` is required (kebab-case). Optional fields:
  - metadata: `version`, `description`, `author`, `homepage`, `repository`, `license`, `keywords`, `engines`
  - components: `userConfig`, `mcpServers`, `hooks`, `skills`, `agents`, `outputStyles`, `workflows`, `lspServers`
- Default dirs sit at the plugin root:
  - `skills/<n>/SKILL.md`, `agents/`, `hooks/hooks.json`, `.mcp.json`
  - `commands/` is the older format. **Skills and commands are unified**: a skill can be invoked as `/<plugin>:<dir>`.
- A plugin-root `CLAUDE.md` is NOT loaded. A top-level `bin/` makes the plugin uninstallable on claude.ai/Cowork, so don't ship one.

## Bundled MCP server
- Declare it in root `.mcp.json` or in `plugin.json` `mcpServers`.
- Tool names: `mcp__plugin_<plugin>_<server>__<tool>`. Use this form in permissions, skill `allowed-tools`, agent `tools` and hook matchers.
- Path variables:
  - `${CLAUDE_PLUGIN_ROOT}`: per-version and changes on update. Keep no state there.
  - `${CLAUDE_PLUGIN_DATA}`: survives updates.
  - `${CLAUDE_PROJECT_DIR}`: the project root.
- `userConfig` (type, title, description, required, default, sensitive, …):
  - `sensitive: true` stores the value in the OS secure store. Values reach the server via `${user_config.KEY}` in MCP `env`/`args`.
  - `claude plugin install` never prompts. **Cowork never prompts**: a server referencing an option without a default is ignored.
- Launch: `{"command":"uvx","args":["mailferret==X.Y.Z"]}`, pinned (*inference*: unpinned uvx silently serves cached old versions). **Superseded** by ARCHITECTURE §9.2: this form lacks `serve`, `--from` and `--constraints`.
  - Pitfalls: uv not on PATH means a silent start failure (shown only in the `/plugin` Errors tab). First-run download can exceed the startup timeout (`MCP_TIMEOUT`). An unset `${VAR}` stays literal.
- User/project/local MCP servers outrank plugin servers with the same name. If both `register claude-code` and the plugin are present, they duplicate each other.

## Marketplace / versioning
- Sources: /plugins/publish.md and /plugins/marketplace-reference.md.
- The same repo can be its own marketplace: `.claude-plugin/marketplace.json` with `name`, `owner{name}`, `plugins:[{name, source:"./"}]`. **Superseded** for mailferret by ARCHITECTURE §9.1: the source is `./plugin`.
- Reserved names include `claude-plugins-official`, `agent-skills`, `anthropic-*` and `claudeai-*`.
- Install:
  - `claude plugin marketplace add owner/repo`, then `claude plugin install mailferret@<mkt>`
  - or `claude plugin install mailferret --marketplace owner/repo`
- An explicit `plugin.json` `version` means users update only on a bump. Third-party auto-update is off by default. `claude plugin tag` creates `{name}--v{version}`.
- The PyPI package (`pyproject.toml`, `src/`) and the plugin (`.claude-plugin/`, `skills/`, `.mcp.json`) live side by side in one repo (the root layout is **superseded** by the `plugin/` subdirectory, ARCHITECTURE §9.1). Release order: PyPI first, then bump the plugin pin and its version together.

## Skills
- Source: code.claude.com/docs/en/skills.md.
- Frontmatter: `name`, `description`, `when_to_use`, `argument-hint`, `allowed-tools`, `disallowed-tools`, `disable-model-invocation`, `user-invocable`, `model`, `effort`, `context: fork`, `agent`, `paths`, …
- Description plus when_to_use is limited to ≤1,536 chars, and SKILL.md should stay under about 500 lines.
- **`allowed-tools` only pre-approves; it does not restrict.** `disallowed-tools` removes tools. A hard read-only guarantee needs an agent `tools` allowlist or `permissions.deny`, and ultimately the server itself.

## Hooks
- Source: /hooks.md.
- Plugin hooks can match MCP calls, but only by the scoped name `mcp__plugin_mailferret_<server>__.*`.
- Hooks fail OPEN on timeout or crash unless `onFailure:"block"` is set. Block with exit 2. Hooks run arbitrary commands as the user. They are defense in depth only.

## Plugin agents
- Frontmatter: `name`, `description`, `model`, `effort`, `tools` (allowlist), `disallowedTools`, `skills`, `maxTurns`, …
- Plugin agents IGNORE `permissionMode`, `hooks` and `mcpServers`. They are namespaced `<plugin>:<name>`.

## Claude Desktop
- Desktop Extensions (`.mcpb`, manifest 0.3/0.4):
  - `server.type` is `node`, `python` (bundled deps), `binary` or `uv` (0.4; the host installs deps).
  - **Not verified that Desktop actually runs `type: uv`.**
  - `user_config.sensitive` maps to the OS secure store.
- The Desktop extension directory no longer accepts submissions. Install by double-click or via Settings > Extensions > Install. Hand-editing `claude_desktop_config.json` stays the fallback.
- Cowork consumes plugins (skills, agents, hooks, local stdio MCP) but has no userConfig prompts. claude.ai chat ignores local MCP.

## Validation / evals
- `claude plugin validate --strict .` checks both manifests and `.mcp.json`. Use it in CI.
- `claude plugin eval` runs `evals/` cases with graders, optionally against a baseline. Mock IMAP, because no eval may touch a real mailbox.

## Open design tension
userConfig `sensitive` (a password passed to the server via env) vs. the brief's rule that the user stores credentials with `mailferret auth set` in keyring. The design must pick one source of truth. Prefer keyring, with no secrets in env, and decide whether userConfig carries only non-secret options. **Resolved** in ARCHITECTURE §9.3: keyring (or the `command` backend) only, no userConfig.
