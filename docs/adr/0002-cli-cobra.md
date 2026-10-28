# 0002. CLI framework: `github.com/spf13/cobra`

- Status: Accepted
- Date: 2026-10-28
- Deciders: Florian (via J0 plan T4)

## Context
The spec lists nine subcommands (`init`, `add`, `login`, `collect`, `status`, `doctor`,
`export`, `schedule`, `record`) plus `version`, with per-command flags and help, and fixed
exit codes (0/1/2). `cmd/facto` holds no business logic: `main` only calls
`os.Exit(run(ctx, args, stdin, stdout, stderr))`, so the framework must accept injected
args and writers for tests and must not call `os.Exit` itself.

## Decision
`github.com/spf13/cobra` **v1.10.2** (2025-12-03), as named in the spec "Libraries" table.
Commands are built by a constructor that takes the injected I/O; `SilenceUsage` and
`SilenceErrors` are set and `run` maps errors to exit codes. Only `cmd/facto` imports cobra.

Build graph added (CGO_ENABLED=0, measured with `go list -deps`):
`github.com/spf13/pflag` v1.0.9 on all OSes, `github.com/inconshreveable/mousetrap`
v1.1.0 on Windows only.

## Alternatives
| Option | Why not |
| --- | --- |
| stdlib `flag` | No subcommands, help or completion: we would rewrite a small cobra, more code to test |
| `github.com/urfave/cli/v3` v3.14.0 (2026-10-02, MIT) | Viable and very active (13 of the last 15 tags within a year); less widespread, spec already names cobra |
| `github.com/alecthomas/kong` v1.16.1 (2026-08-09, MIT) | Struct-tag driven, elegant; reflection-heavy, smaller ecosystem |

## License
cobra: Apache-2.0. pflag: BSD-3-Clause. mousetrap: Apache-2.0. All compatible with the
project's Apache-2.0 license.

## Maintenance
27 tagged versions; latest v1.10.2 on 2025-12-03, previous v1.10.1 on 2025-09-01. Slow
cadence for a mature library (only 1 of the last 15 tags within the last 12 months);
used by kubectl, gh, hugo. Maintainer list: unverified.

## Consequences
- Shell completion and generated help for free.
- If cobra stalls, the blast radius is `cmd/facto` only; urfave/cli is the fallback.
