---
name: security-checklist
description: The security checklist every change in facto must satisfy (secrets, sessions, browser, network, files, logs, inputs, dependencies). Load when implementing or reviewing anything that touches credentials, cookies, tokens, the browser, HTTP, file writes, parsing, the PWA or the local UI.
---

# Security checklist

Threat model: protect credentials, the Bitwarden session key, supplier cookies/tokens,
the Google refresh token, against other local programs, leaks via files/logs, and
compromised dependencies. Root on the machine is out of scope.

## Secrets
- [ ] Config holds references (`bw://uuid/field`, `keyring://…`), never values.
- [ ] Values live in `secrets.Secret`; exposed only at the last call site; wiped after use.
- [ ] Bitwarden: items by UUID, `--passwordenv` only in the subprocess env, `bw lock` in a `defer`, never `bw serve`.
- [ ] No secret in argv, global env, URL, error message, panic, report.

## Sessions
- [ ] Persisted sessions are AEAD-encrypted, key from keyring/password manager, file 0600.
- [ ] `sessions: ephemeral` writes nothing. Session rotated on each successful login.

## Browser
- [ ] CDP over pipe when available; otherwise random port bound to 127.0.0.1, closed ASAP.
- [ ] Fresh 0700 `--user-data-dir` per run, deleted at the end (also on error).
- [ ] No extensions, sync, password saving, crash reporting. Pinned Chrome for Testing, checksum verified.
- [ ] Credentials typed via CDP into fields, never in URLs or page-evaluated scripts logged.

## Network
- [ ] Only `internal/httpx`; allowlist from `Info().AllowedDomains`; redirects re-checked against it.
- [ ] TLS verification on; no proxy env honoured unless `FACTO_ALLOW_PROXY=1`.

## Files
- [ ] Only `internal/fsx`; 0700 dirs, 0600 files; atomic writes.
- [ ] `fsx.SafeName` on every supplier-provided string used in a path (traversal, reserved names, NUL, length).
- [ ] Refuse to run if `.facto/` is inside the output folder or a synced folder.

## Logs and reports
- [ ] Redacting `slog` handler; no bodies; sensitive keys and token patterns masked.
- [ ] `make leakcheck` covers the new artifact type.

## Inputs
- [ ] Size caps on HTML/JSON/PDF; XML parsed without external entities; timeouts everywhere.

## Dependencies
- [ ] No new dep without ADR; versions pinned; govulncheck clean.
