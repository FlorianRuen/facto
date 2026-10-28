# 0005. OS keyring: `github.com/zalando/go-keyring`

- Status: Accepted
- Date: 2026-10-28
- Deciders: Florian (via J0 plan T5)

## Context
The spec (Security, Data at rest) stores credentials, the session-vault key and the Google
refresh token in the OS keyring by default (`keyring://service/key` references). The
binary has no CGO (ADR 0004), so the keyring library must reach macOS Keychain, Windows
Credential Manager and Linux Secret Service without CGO.

## Decision
`github.com/zalando/go-keyring` **v0.2.8** (2026-03-23), wrapped by
`internal/secrets` behind a small interface (`Get(service, user) (string, error)`); the
returned string is converted to `secrets.Secret` immediately. Tests use a fake, never the
real keyring (T18). `ErrNotFound` maps to `secrets.ErrSecretNotFound`.

Backends (read in v0.2.8 sources):
- macOS: runs `/usr/bin/security`; `Set` sends the password on stdin (`security -i`),
  not on argv. `Get` receives it on stdout.
- Linux: Secret Service over D-Bus (`github.com/godbus/dbus/v5` v5.2.2). Without a
  Secret Service daemon (headless server) it fails; spec fallback `secrets.fallback: file`.
- Windows: Credential Manager via `github.com/danieljoos/wincred` v1.2.3.
- Other OSes: `ErrUnsupportedPlatform`.

`CGO_ENABLED=0` build for darwin verified.

## Alternatives
| Option | Why not |
| --- | --- |
| `github.com/99designs/keyring` v1.2.2 (2022-12-19, MIT) | No release since 2022; macOS Keychain backend is `darwin && cgo` only, so absent in a no-CGO build; pulls jose2go, go-libsecret, old godbus |
| Exec `secret-tool` / `security` / PowerShell ourselves | Reimplements go-keyring with more surface |
| Encrypted file only | Spec keeps it as explicit weaker fallback, not the default |

## License
go-keyring: MIT. godbus/dbus/v5: BSD-2-Clause (two-clause LICENSE read). wincred: MIT. `golang.org/x/sys` (Windows): BSD-3-Clause.

## Maintenance
11 tagged versions; 2 of them in the last 12 months (latest v0.2.8, 2026-03-23).
MAINTAINERS file: two Zalando engineers. Small, stable surface.

## Consequences
- Values pass through Go `string` (immutable, cannot be wiped): keep their lifetime short,
  convert to `Secret` at the boundary, document the limit in `docs/security.md`.
- macOS: the secret transits through a child process pipe; acceptable, same user.
- Headless Linux needs the file fallback (J1+).
