---
name: go-conventions
description: facto's Go coding conventions (package layout, errors, context, logging, secrets, files, network, tests). Load before writing or reviewing any Go code in this repository, even for a one-line change.
---

# Go conventions for facto

## Layout and dependencies
- `internal/` for everything not meant for import; `connectors/<id>` per supplier.
- Interfaces are declared by the consumer, kept small (1 to 3 methods).
- Constructor injection: `func New(deps Deps) *T`. No package-level mutable state, no `init()` side effects except connector registration.
- New dependency = ADR in `docs/adr/NNNN-<slug>.md` (need, alternatives, license, last release, maintainers).

## Functions and errors
- `ctx context.Context` is the first parameter of anything that does I/O or may block.
- Wrap with context: `fmt.Errorf("list invoices: %w", err)`; messages lowercase, no trailing punctuation.
- Sentinel errors per package for states the orchestrator branches on: `connector.ErrNeedsLogin`, `ErrBroken`, `ErrAuthFailed`, `ErrRateLimited`. Use `errors.Is`.
- No `panic` outside `main`. Recover at the orchestrator boundary per connector, log a redacted message, mark the connector `broken`.

## Security-shaped APIs (mandatory)
- Secrets: `secret.Secret` only. Never convert to `string` except at the last call site (`input.Type(sec.Expose())`), never store the exposed value.
- Network: `httpx.Client(info.AllowedDomains)` only. `net/http` default client is forbidden (lint rule `forbidigo`).
- Files: `fsx.WriteAtomic`, `fsx.MkdirPrivate`, `fsx.SafeName`. `os.WriteFile`/`os.Create` are forbidden outside `internal/fsx`.
- Logging: `slog` from `Env.Log` (redacting handler). `fmt.Print*`, `log.*` forbidden outside `cmd/`. Never log request or response bodies.
- Time: inject `clock.Clock`; never call `time.Now()` in business code.

## Naming and style
- `gofumpt` + `goimports`; golangci-lint config in `.golangci.yml` is the source of truth.
- Package names short, no `util`/`common`. Receivers 1 to 2 letters. Exported identifiers documented.
- Money as `int64` cents + ISO currency. Dates as `time.Time` in UTC, rendered `2006-01-02`.

## Tests
- Table-driven, `t.Parallel()` where safe, `-race` always.
- Golden files in `testdata/`, updated only with `go test ./... -update` and reviewed.
- No `time.Sleep`: use the fake clock and channels.
- HTTP: `httptest.Server` or `connectors/fakeprovider`; never the internet.
