# Status

Phase: RESTART POINT A done (Claude Code project configuration). Restart required.

## Done

- Phase 1 design approved at Checkpoint 1 (`docs/ARCHITECTURE.md` §11).
- Claude Code project configuration: `.claude/agents/mf-*`, `.claude/skills/`, `.claude/settings.json` (permissions, ruff/test/PII hooks), `.mcp.json` (Context7, development only), `scripts/pii_check.py` + `.github/workflows/pii-check.yml`, `.gitattributes`.

## Next

1. Start `claude` in the repo and say: Continue from docs/STATUS.md
2. Phase 2 per `docs/PLAN.md`: first the verification spikes V1–V4 (`mf-researcher`), in parallel with the scaffold F0 (`mf-implementer`).
