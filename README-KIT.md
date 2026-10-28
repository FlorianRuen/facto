# facto agent kit

Drop the content of this folder at the root of the facto repository, then add the spec
as `docs/spec.md`. Start with `docs/agentic/KICKOFF.md`.

| Path | Purpose |
| --- | --- |
| CLAUDE.md, AGENTS.md | Rules for every agent session |
| .claude/settings.json | Permissions and hooks |
| .claude/hooks/ | guard (blocks secrets, network tools, test skipping, force push), format, verify-fast |
| .claude/agents/ | planner, test-writer, implementer, reviewer, security-auditor, red-team, connector-builder, docs-writer |
| .claude/skills/ | go-conventions, add-connector, fixtures-from-har, write-tests, security-checklist, audit-score, goal-session, release |
| docs/agentic/ | GOALS (one /goal per milestone), PROGRESS log, KICKOFF guide |
| security/ | rubric, score schema, audit reports |
| scripts/ | coverage gate, score gate, canary leak check |
| .github/ | ci, security, claude-review, release workflows; PR template |
| Makefile, .golangci.yml | Stable entry points and lint rules |

Verify at setup: action versions (pin to SHAs), the claude-code-action inputs, the
golangci-lint v2 config, and that `/goal` is available in your Claude Code version.
