# Contributing

## Ground rules

- Read [`CLAUDE.md`](CLAUDE.md). Its hard rules apply to humans and agents alike.
- Never commit real personal data, credentials, cookies or raw HAR files.
- Never copy code from Cozy connectors (AGPL) or Woob modules (LGPL). Read their
  flows, rewrite in Go, and credit them as inspiration in the connector sheet.
- Never weaken, skip or delete a test to get green. Fix the code or report the
  blocker.
- Never disable a hook, a linter rule, a scanner or a CI job. A `//nolint` or
  `#nosec` needs an inline reason and an issue number.
- No new dependency without an ADR in [`docs/adr/`](docs/adr/).
- Network I/O only through `internal/httpx`, file writes only through
  `internal/fsx`, logging only through the redacting `slog` handler
  (`internal/logx`).

## Setup

You need Go (version pinned in `go.mod`), `gofumpt` and `golangci-lint` on your
`PATH`, and Docker for `make e2e`.

Install the pinned security and CI tools (govulncheck, gosec, gitleaks,
osv-scanner, actionlint) into `GOBIN`:

```sh
make tools
```

## Commands

The Makefile is the only entry point. Do not invent other ways to build or test.
If a target is missing, add it to the Makefile.

| Command | What it does |
| --- | --- |
| `make verify` | fmt check, lint, unit tests with `-race`, coverage gates, leakcheck. Must exit 0 before any commit. |
| `make test` | Unit tests only, fast |
| `make e2e` | End-to-end tests against `connectors/fakeprovider` and a Vaultwarden container |
| `make leakcheck` | Canary secret scan over every file, log and report produced by the tests |
| `make audit` | govulncheck, gosec, gitleaks, osv-scanner; writes `security/scanners.json` |
| `make score-check` | Fails if `security/score.json` is missing, stale or under the gate |
| `make tools` | Installs the pinned tools listed above |

Coverage gates: every package needs 70%. `internal/normalize`, `internal/store`,
`internal/secrets`, `internal/vault`, `internal/fsx` and `internal/httpx` need 85%.

The end-to-end harness (`test/`) is not in the repository yet, so `make e2e` fails
today.

## Workflow (test first)

One task per commit. For each task:

1. **Write the tests first** and watch them fail. Table-driven, golden files under
   `testdata/`, fake clock (`internal/clock`), no sleeps.
2. **Implement** until the tests pass, without touching their assertions.
3. Run `make verify`. It must exit 0.
4. Get a review (no blocking comment) and a security audit (no new high or
   critical finding).
5. **Update the docs:** README, `docs/security.md`, the connector sheet or an ADR
   when behaviour changes.
6. Append one line to [`docs/agentic/PROGRESS.md`](docs/agentic/PROGRESS.md).
7. Commit with a [Conventional Commit](https://www.conventionalcommits.org/)
   message, for example `feat(normalize): render amount with currency`.

Go conventions: `context.Context` first on every I/O function, errors wrapped with
`%w`, no `panic` outside `main`, constructor injection, small consumer-side
interfaces. See `.claude/skills/go-conventions/SKILL.md`.

Pull requests: one milestone or one connector per PR. Fill the template in
`.github/pull_request_template.md`. CI (`ci`) and security (`security`) checks
must be green.

## Test fixtures

Fixtures in `testdata/` must be synthetic or sanitized. Follow
`.claude/skills/fixtures-from-har/SKILL.md`; the PII scan must be clean.

## Adding a connector

Connectors are planned from milestone J2. The commands below do not exist yet.

1. Record: `facto record <portal-url>` (strips passwords, cookies, auth headers).
2. Sanitize: follow `.claude/skills/fixtures-from-har/SKILL.md`.
3. Fill `docs/connectors/<id>.md` from `docs/connectors/_template.md`, including
   the allowed domains.
4. Implement following `.claude/skills/add-connector/SKILL.md`, offline tests only.
5. Run `facto doctor <id>` with your own account and add the result to the PR.
6. You become the connector's maintainer.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
