# 0001. Pin dev tools in `tools/go.mod` with `tool` directives

- Status: Accepted
- Date: 2026-10-28
- Deciders: Florian (via J0 plan T4)

## Context
`make audit` and `make lint-actions` call actionlint, govulncheck, gosec, gitleaks and
osv-scanner. Unpinned `go install …@latest` gives different results across machines and
CI, and a compromised `latest` would run with the developer's rights. The spec (Supply
chain) asks for minimal, reviewed dependencies; the main `go.mod` must only list what the
binary ships, so `govulncheck ./...` and the SBOM describe the product, not the tooling.

## Decision
A separate module `tools/go.mod` (+ `tools/go.sum`) using Go 1.24+ `tool` directives,
run from the repo root with `-modfile=tools/go.mod` (`make tools` =
`go install -modfile=tools/go.mod tool`). Versions verified on 2026-10-28:

| Tool | Package | Version | Released | License |
| --- | --- | --- | --- | --- |
| actionlint | `github.com/rhysd/actionlint/cmd/actionlint` | v1.7.12 | 2026-03-30 | MIT |
| govulncheck | `golang.org/x/vuln/cmd/govulncheck` | v1.9.0 | 2026-10-11 | BSD-3-Clause |
| gosec | `github.com/securego/gosec/v2/cmd/gosec` | v2.30.0 | 2026-10-23 | Apache-2.0 |
| gitleaks | `github.com/zricethezav/gitleaks/v8` | v8.30.1 | 2026-02-21 | MIT |
| osv-scanner | `github.com/google/osv-scanner/v2/cmd/osv-scanner` | v2.7.0 | 2026-10-12 | Apache-2.0 |

goreleaser joins in J4 under the same rule (its own ADR update).

**Known conflict (verified in a scratch module).** In one shared module, osv-scanner
v2.7.0 raises `go.yaml.in/yaml/v4` to v4.0.0-rc.6 by MVS, and actionlint v1.7.12 (built
against rc.3) then fails to compile (`te.Errors[0].Error undefined`). The four other tools
build together. So actionlint gets its own module `tools/actionlint/go.mod` (same `tool`
directive pattern, `-modfile=tools/actionlint/go.mod`); merge it back once a release of
either tool removes the conflict.

## Alternatives
| Option | Why not |
| --- | --- |
| `tool` directives in the main `go.mod` | ~600 modules (measured: `go list -m all` = 613) pollute the product graph, govulncheck and SBOM |
| `tools.go` with blank imports | Pre-1.24 idiom, same pollution, needs build tags |
| `go install pkg@vX.Y.Z` in the Makefile | Pinned version but no `go.sum` checked in the repo, no Renovate updates |
| Downloaded release binaries | Needs checksum handling per OS; curl is not an entry point here |
| One module per tool for all five | More files; only needed where a conflict exists |

## License
All MIT, BSD-3-Clause or Apache-2.0 (read from each module's LICENSE file). Tools are not
linked into facto, so their transitive licenses do not reach the binary.

## Maintenance
All five are actively released (dates above). Renovate (spec) bumps `tools/**/go.mod`.
`go.sum` gives checksum pinning via the Go checksum database.

## Consequences
- Reproducible tool versions in CI and locally; the product `go.mod` stays minimal.
- `make tools` must install from both modfiles; T7 implements it.
- First `make tools` downloads a large graph (osv-scanner, gitleaks); CI should cache it.
