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
`internal/secret`, `internal/vault`, `internal/fsx` and `internal/httpx` need 85%.

## End-to-end tests

`make e2e` needs Docker with Compose v2 (`docker compose`). It:

1. starts the Vaultwarden service of `test/compose.yaml` and waits for its
   healthcheck;
2. runs `go test -tags e2e -count=1 -v ./test/e2e/...`, which builds
   `./cmd/facto` once and runs every `test/e2e/*.yaml` scenario as the subtest
   `TestE2E/<name>`;
3. stops the container and removes its volumes, then exits with the test
   status.

```sh
make e2e
```

A passing scenario prints `--- PASS: TestE2E/<name>`. Stdout, stderr and a copy
of the state dir of each run go to `.cache/test-artifacts/`, where
`make leakcheck` scans them.

Vaultwarden is pinned by tag and digest. It listens on `127.0.0.1:8087` only, in
a tmpfs, with synthetic accounts. No J0 scenario uses it yet: the Bitwarden
provider E2E comes in J1. To bump it, follow the comment at the top of
`test/compose.yaml`.

Each scenario runs the binary in its own sandbox: a temporary `HOME`, an
environment built from scratch (`HOME`, `XDG_*`, `APPDATA`, `TMPDIR`,
`LANG=C.UTF-8`, `TZ=UTC`) and an empty `PATH`, so the binary cannot run any host
tool. Stdin is `/dev/null`, so `collect` never prompts.

### Adding a scenario

1. Create `test/e2e/<name>.yaml`. `name` must equal the file stem and match
   `[a-z0-9]+(-[a-z0-9]+)*`.
2. Describe the setup, the command and the expectations. Decoding is strict:
   an unknown key is an error. The full format is documented at the top of
   `test/e2e/scenario.go`. A minimal scenario:

   ```yaml
   name: inbox-example
   description: >
     A compliant name is filed and removed from the inbox.
   setup:
     - path: config.yaml
       mode: "0600"
       content: |
         output:
           local: ~/Invoices
         state_dir: ~/.facto
         notify: none
         manual:
           - { id: edf, name: "EDF", category: housing }
     - path: Invoices/inbox/2026-03-14_edf_invoice_84-12EUR_10234567.pdf
       fixture: edf-invoice.pdf
   args: [collect, --config, "{{home}}/config.yaml", --year, "2026", --non-interactive]
   expect:
     exit: 0
     stdout:
       contains: ["summary: filed 1"]
     files:
       - path: Invoices/2026/housing/edf/2026-03-14_edf_invoice_84-12EUR_10234567.pdf
         mode: "0600"
         fixture: edf-invoice.pdf
     absent:
       - Invoices/inbox/2026-03-14_edf_invoice_84-12EUR_10234567.pdf
   repeat:
     expect:
       exit: 0
       stdout:
         contains: ["summary: no documents"]
     unchanged: [Invoices]
   ```

3. Run `make e2e` and check for `--- PASS: TestE2E/<name>`.

Format reminders:

- Every path is relative to the sandbox `HOME`, clean, without `..`.
- A setup entry has exactly one of `content`, `fixture`, `symlink` (relative,
  target inside `HOME`) or `dir: true`. `mode` is an octal string; files
  default to `"0600"`, folders to `"0700"`.
- `content` and `args` expand `{{home}}` and `{{canary:<kind>}}`, nothing
  else. Use a canary for any secret-looking value: the harness fails if it
  leaks.
- `expect` needs `exit`. It can check `stdout` and `stderr` (`prefix`,
  `contains`, `not_contains`, `empty`), `files` (regular file, `mode`,
  `fixture` or `content`), `absent` paths, and `trees` (exact `entries`
  listing, folders ending in `/`, symlinks in `@`; `private: true` requires
  `0700` folders and `0600` files).
- `repeat` runs the same command a second time; `unchanged` lists trees that
  must be identical (paths, modes, bytes) after it.
- `state_dir` (default `.facto`) is the folder copied to the artifacts.

Fixtures are files in `test/e2e/testdata/`, referenced by bare name. They must
be synthetic: the existing PDFs are generated byte for byte by
`TestFixtures_SyntheticPDFs` in `test/e2e/fixtures_test.go`, which fails when a
checked-in fixture differs from the generator. To add one, add it to
`fixtures()` there. Rewriting the files needs the test's `-update` flag, which
no Makefile target passes yet.

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
