# Contributing

## Ground rules
- Read `CLAUDE.md`: its hard rules apply to humans and agents alike.
- Never commit real personal data, credentials, cookies or raw HAR files.
- Never copy code from Cozy connectors (AGPL) or Woob modules (LGPL). Credit them as
  inspiration in the connector sheet.

## Adding a connector
1. Record: `facto record <portal-url>` (strips passwords, cookies, auth headers).
2. Sanitize: follow `.claude/skills/fixtures-from-har/SKILL.md`; the PII scan must be clean.
3. Fill `docs/connectors/<id>.md` from `docs/connectors/_template.md`.
4. Implement following `.claude/skills/add-connector/SKILL.md`, offline tests only.
5. Run `facto doctor <id>` with your own account and add the result to the PR.
6. You become the connector's maintainer.

## Workflow
`make verify` before each commit · Conventional Commits · one task per commit ·
PR template filled · CI, security and claude-review checks green.
