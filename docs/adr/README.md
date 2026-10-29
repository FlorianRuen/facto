# Architecture Decision Records

CLAUDE.md rule 6: no new dependency without an ADR here (why, alternatives, license,
maintenance). Product decisions that fill a gap in `docs/spec.md` are recorded here too.

One file per decision, `NNNN-short-title.md`, numbered in order, never renumbered.
A superseded ADR stays in place with `Status: Superseded by NNNN`.
Version facts come from `go list -m -json <module>@latest` and licenses from the
module cache; anything not checked that way is marked "unverified".

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-tools-pinning.md) | Pin dev tools in `tools/go.mod` with `tool` directives | Accepted |
| [0002](0002-cli-cobra.md) | CLI framework: `spf13/cobra` | Accepted |
| [0003](0003-yaml.md) | YAML: `go.yaml.in/yaml/v3` | Accepted |
| [0004](0004-sqlite-modernc.md) | SQLite driver: `modernc.org/sqlite` | Accepted |
| [0005](0005-go-keyring.md) | OS keyring: `zalando/go-keyring` | Accepted |
| [0006](0006-pdfcpu.md) | Factur-X PDF attachments: `pdfcpu` | Accepted |
| [0007](0007-j0-product-decisions.md) | J0 product decisions (spec gaps) | Accepted |
| [0009](0009-vault-aead.md) | Session vault: XChaCha20-Poly1305, key per connector in the OS keyring | Accepted |

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD
- Deciders: …

## Context
The need, the constraints (spec section, security rules), what forces a choice.

## Decision
What we use, which version, how it is wrapped (package, interface).

## Alternatives
| Option | Why not |

## License
SPDX id of the module and of every module it adds to the build.

## Maintenance
Latest version and date, release cadence, maintainers, known risks.

## Consequences
What gets easier or harder, follow-ups, when to revisit.
```
