# 0004. SQLite driver: `modernc.org/sqlite`

- Status: Accepted
- Date: 2026-10-28
- Deciders: Florian (via J0 plan T5)

## Context
`internal/store` keeps the document index (spec, Normalization: provider, ProviderID,
kind, dates, amount, SHA-256, paths, Drive id). The spec requires one binary built
**without CGO** for Linux, macOS and Windows, cross-compiled from one machine by goreleaser.
We need `database/sql`, transactions, unique constraints and context cancellation.

## Decision
`modernc.org/sqlite` **v1.61.0** (2026-10-21), a C-to-Go translation of SQLite, used
through `database/sql` (driver name `sqlite`) inside `internal/store` only.
Verified: `CGO_ENABLED=0` builds for `linux/amd64`, `windows/amd64`, `darwin/arm64`
succeed; a hello binary importing only the driver is 9.5 MB (linux/amd64).

Modules compiled in (`go list -deps`, CGO_ENABLED=0):

| Module | Version | OS | License |
| --- | --- | --- | --- |
| `modernc.org/sqlite` | v1.61.0 | all | BSD-3-Clause (+ SQLite public domain) |
| `modernc.org/libc` | v1.79.0 | all | BSD-3-Clause |
| `modernc.org/memory` | v1.12.1 | all | BSD-3-Clause |
| `modernc.org/mathutil` | v1.7.1 | all | BSD-3-Clause |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748 | all | BSD-3-Clause |
| `github.com/dustin/go-humanize` | v1.1.0 | all | MIT |
| `golang.org/x/sys` | v0.49.0 | all | BSD-3-Clause |
| `github.com/google/uuid` | v1.6.0 | linux, darwin | BSD-3-Clause |
| `github.com/mattn/go-isatty` | v0.0.24 | darwin, windows | MIT |
| `github.com/ncruces/go-strftime` | v1.1.0 | darwin, windows | MIT |

`go mod graph` also lists build-time-only modules that are not compiled in:
`modernc.org/{fileutil,cc/v4,ccgo/v4,gc/v2,gc/v3,goabi0,opt,sortutil,strutil,token}`,
`github.com/google/pprof`, `golang.org/x/{tools,mod,sync}`.

## Alternatives
| Option | Why not |
| --- | --- |
| `github.com/mattn/go-sqlite3` v1.14.52 (MIT) | Requires CGO: breaks the no-CGO cross-compile rule |
| `github.com/ncruces/go-sqlite3` v0.35.6 (MIT) | CGO-free (Wasm build translated with wasm2go), active; pre-1.0 API, smaller user base. Credible fallback |
| JSON file (spec alternative) | No unique constraints or transactions; dedup rules need them |

## License
See table; all permissive. SQLite itself is public domain (`LICENSE-SQLITE`).

## Maintenance
162 tagged versions; all of the last 15 within the last 12 months. Single main
maintainer (cznic / Jan Mercl, unverified beyond the module path) is the main risk;
libc must track every new Go release and OS/arch.

## Consequences
- `internal/store` hides the driver; switching to ncruces only touches that package.
- Larger binary and slower than C SQLite; irrelevant at a few thousand rows.
- Renovate updates sqlite and libc together (they are released in lockstep).
