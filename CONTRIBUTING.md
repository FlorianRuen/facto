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
`PATH`, and Docker for `make e2e`. `make chrome` and `make e2e` also need
network access once, to download the pinned Chrome for Testing (Linux x86-64).

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
| `make verify` | fmt check, lint, `lint-selftest`, unit tests with `-race`, coverage gates, `e2e-unit`, `release-e2e-check`, leakcheck. Must exit 0 before any commit. |
| `make test` | Unit tests only, fast |
| `make chrome` | Runs `facto browser install --dir .cache/chrome`: the pinned Chrome for Testing, verified by size and SHA-256. Idempotent, no network once installed. Prints the executable path |
| `make e2e` | Runs `make chrome`, then the real-Chrome browser tests (`-tags e2e,chrome ./internal/browser/...`), then the scenarios in `test/e2e/` against `connectors/fakeprovider` and a Vaultwarden container |
| `make e2e-unit` | Unit tests with `-race -tags e2e`, in every package that holds a file whose `//go:build` line names `e2e` (`test/e2e` excluded). Never needs Chrome. Run by `verify` |
| `make release-e2e-check` | Builds with the exact `.goreleaser.yaml` flags and fails if `go list -deps` or `go tool nm` finds e2e-only code; a `-tags e2e` self-test must find it. Prints `release-check: release build has no e2e-only code`. Run by `verify` |
| `make lint-selftest` | Proves three guard rules are live: the depguard ban on `golang.org/x/crypto/openpgp`, the `cdploopback` caller rule and the `httpx.NewPinned` caller rule. Prints one `lint-selftest:` line per rule. Run by `verify` |
| `make e2e-browser-windows` | Windows only: the real-Chrome checks `TestChromeWindows_*` (CDP port bound to 127.0.0.1 only, profile removed, browser closed after login). Same command as the `browser-windows` CI job |
| `make cover` | Unit tests with `-race`, then the coverage gates |
| `make leakcheck` | Canary secret scan over every file, log and report produced by the tests |
| `make audit` | govulncheck, gosec, gitleaks, osv-scanner; writes `security/scanners.json` |
| `make score-check` | Fails if `security/score.json` is missing, stale or under the gate |
| `make release-check` | Validates `.goreleaser.yaml` and builds an unsigned snapshot of every target, in the pinned goreleaser image (Docker) |
| `make tools` | Installs the pinned tools listed above |

Coverage gates: every package needs 70%. `internal/normalize`, `internal/store`,
`internal/secret`, `internal/vault`, `internal/fsx`, `internal/httpx`,
`internal/browser` and `internal/browser/cft` need 85%.

### Build tags

- `e2e`: test-only code (the `fakeprovider` registration, e2e secret and key
  stores, loopback and test CA plumbing). Never in a release build:
  `make release-e2e-check` proves it.
- `chrome` (with `e2e`): tests that drive a real Chrome. They read the browser
  path from `FACTO_E2E_CHROME`. On Linux they fall back to the `make chrome`
  copy in `.cache/chrome`; on Windows there is no fallback. Without a browser
  they fail, never skip. Only `make e2e` and `make e2e-browser-windows` pass
  this tag.

## End-to-end tests

`make e2e` needs Docker with Compose v2 (`docker compose`). It:

1. runs `make chrome` (pinned Chrome for Testing in `.cache/chrome`);
2. runs the real-Chrome isolation tests in `internal/browser` with
   `-tags e2e,chrome` and `FACTO_E2E_CHROME` set to that Chrome. They print
   `no listening CDP port` and `profile removed`;
3. starts the Vaultwarden service of `test/compose.yaml` and waits for its
   healthcheck;
4. runs `go test -tags e2e -count=1 -v ./test/e2e/...`, which builds
   `./cmd/facto` once with `-tags e2e` and runs every `test/e2e/*.yaml`
   scenario as the subtest `TestE2E/<name>`;
5. stops the container and removes its volumes, then exits with the test
   status.

```sh
make e2e
```

A passing scenario prints `--- PASS: TestE2E/<name>`. Stdout, stderr and a copy
of the state dir of each run go to `.cache/test-artifacts/`, where
`make leakcheck` scans them.

Vaultwarden is pinned by tag and digest. It listens on `127.0.0.1:8087` only, in
a tmpfs, with synthetic accounts. No scenario uses it yet: the Bitwarden
provider E2E needs the `bw` CLI in the e2e job (BLOCKED(H1)). To bump it,
follow the comment at the top of `test/compose.yaml`.

Each scenario runs the binary in its own sandbox: a temporary `HOME`, an
environment built from scratch (`HOME`, `XDG_*`, `APPDATA`, `TMPDIR`,
`LANG=C.UTF-8`, `TZ=UTC`, and a `DBUS_SESSION_BUS_ADDRESS` inside the sandbox)
and an empty `PATH`, so the binary cannot run any host tool or reach your
keyring. Stdin is `/dev/null`, so `collect` never prompts, unless the scenario
sets `stdin:`.

The `fakeprovider` scenarios start a fake TLS site bound to 127.0.0.1, with a
per-run test CA. facto, built with `-tags e2e`, maps the fake supplier's hosts
to it in httpx and in Chrome. Session keys go to a file store in the sandbox's
state dir, never to the OS keyring.

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
- Fake site keys: `fakesite:` (mode, accepted login and password keys, seeded
  invoices), `secrets:` (`e2e://<item>/<field>` values, outside `HOME`),
  `stdin:` (lines fed to prompts; sets `FACTO_E2E_INTERACTIVE=1`),
  `expect.requests:` (assertions on the site's request log) and
  `expect.browser:` (`no_cdp_port`, `profile_removed`). See
  `test/e2e/scenario.go`.

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

Connectors are planned from milestone J2. The `facto record` and `facto doctor`
commands below do not exist yet. `connectors/fakeprovider` and its sheet
[`docs/connectors/fakeprovider.md`](docs/connectors/fakeprovider.md) show the
shape of a connector with a browser login.

1. Record: `facto record <portal-url>` (strips passwords, cookies, auth headers).
2. Sanitize: follow `.claude/skills/fixtures-from-har/SKILL.md`.
3. Fill `docs/connectors/<id>.md` from `docs/connectors/_template.md`, including
   the allowed domains.
4. Implement following `.claude/skills/add-connector/SKILL.md`, offline tests only.
5. Run `facto doctor <id>` with your own account and add the result to the PR.
6. You become the connector's maintainer.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
