# facto — agent rules

facto is a local, serverless Go binary that collects a person's supplier invoices
(Ileo, EDF, Bouygues Telecom, Wecasa, Cooloc…), renames them, and stores them locally
and/or in Google Drive. The spec lives in `docs/spec.md` (exported from the design doc).
Read it before any architectural change.

## Commands (the only entry points)

| Command | What it does |
| --- | --- |
| `make verify` | fmt check, lint, unit tests with `-race`, coverage gates, leakcheck. Must exit 0 before any commit. |
| `make test` | Unit tests only, fast |
| `make e2e` | End-to-end tests against `connectors/fakeprovider` and a Vaultwarden container |
| `make leakcheck` | Canary secret scan over every file, log and report produced by the tests |
| `make audit` | govulncheck, gosec, gitleaks, osv-scanner; writes `security/scanners.json` |
| `make score-check` | Fails if `security/score.json` is missing, stale or under the gate |

Never invent other ways to build or test. If a target is missing, add it to the Makefile.

## Architecture in one screen

- `cmd/facto/` CLI (cobra). No business logic here.
- `internal/orchestrator` runs connectors, never imports a concrete connector.
- `internal/connector` defines `Connector`, `DocumentRef`, `Env`, the registry.
- `internal/browser` hides rod/chromedp. CDP over a pipe when supported, disposable
  0700 profile, launched for login only.
- `internal/httpx` is the ONLY way to do network I/O. It enforces the connector's
  domain allowlist.
- `internal/fsx` is the ONLY way to write files: 0600/0700, atomic writes, path sanitizing.
- `internal/secret` resolves `bw://`, `keyring://`… references. Values are `secret.Secret`.
- `internal/vault` encrypts sessions (AEAD). `internal/store` is the SQLite index.
- `internal/normalize` naming, dedup, Factur-X. `internal/dest/{local,gdrive}` destinations.
- `connectors/<id>/` one package per supplier + `docs/connectors/<id>.md` sheet.
- `connectors/fakeprovider/` test-only supplier simulating every login and failure mode.

## Hard rules (never break, even to make a goal pass)

1. Never weaken, skip, delete or `t.Skip` a test to get green. Fix the code or report the blocker.
2. Never copy code from Cozy connectors (AGPL) or Woob modules (LGPL). Read flows, rewrite.
3. Never ask for, read, print or store real supplier credentials, cookies or tokens.
   Real accounts are only used by Florian during checkpoint H4.
4. Never disable a hook, a linter rule, a scanner or a CI job. Justify a `//nolint` or
   `#nosec` inline with a reason and an issue number.
5. No network call outside `internal/httpx`, no file write outside `internal/fsx`,
   no secret outside `secret.Secret`, no logging outside the redacting `slog` handler.
6. No new dependency without an ADR in `docs/adr/` (why, alternatives, license, maintenance).
7. Fixtures in `testdata/` must be synthetic or sanitized; run the `fixtures-from-har` skill.

## Conventions

Load the `go-conventions` skill before writing Go. Summary: `context.Context` first,
errors wrapped with `%w`, no panics outside `main`, table-driven tests, golden files,
fake clock, constructor injection, small consumer-side interfaces.

Commits: Conventional Commits (`feat(normalize): …`), one task per commit.
PRs: one milestone (or one connector) per PR, template in `.github/pull_request_template.md`.

## Working mode (goal sessions)

- Load the `goal-session` skill when a `/goal` is active.
- Delegate: `planner` → `test-writer` → `implementer` → `reviewer` → `security-auditor`.
  Use `red-team` once per milestone, `connector-builder` for supplier packages,
  `docs-writer` before closing a milestone.
- Append one line per finished or blocked task to `docs/agentic/PROGRESS.md`.
- Blocked on Florian? Write `BLOCKED(H1|H2|H3|H4): <what is needed>` and move to the
  next unblocked task. Do not wait idle.
- Print the proof of your goal condition (command + exit code + key lines) at the end of
  each turn: the goal evaluator only reads what you print.

## Definition of done (per task)

Tests written first and failing, then passing · `make verify` exit 0 · reviewer: no
blocking comment · auditor: no new high/critical · docs and connector sheet updated ·
PROGRESS.md line added.
