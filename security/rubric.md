# Security rubric (100 points)

| # | Category | Max | Controls the auditor must find evidence for |
|---|---|---|---|
| 1 | Secret handling | 15 | References only in config; `secrets.Secret` everywhere; Bitwarden by UUID, `--passwordenv` in subprocess env only, `bw lock` deferred, no `bw serve`; no secret in argv/env/URL/errors |
| 2 | Session storage | 10 | AEAD with key from keyring/password manager; 0600; ephemeral mode works; rotation on login |
| 3 | Browser isolation | 15 | Pipe transport or 127.0.0.1 random port; disposable 0700 profile removed on success and error; hardened flags; pinned, checksum-verified Chrome for Testing; browser lifetime limited to login |
| 4 | Logging and redaction | 10 | Redacting handler on every logger; no bodies; key and pattern masking; canary coverage of every artifact type |
| 5 | Network boundary | 10 | `httpx` only (lint-enforced); allowlist incl. redirects; TLS on; proxy env ignored by default; timeouts |
| 6 | File system | 10 | `fsx` only; 0700/0600; atomic writes; `SafeName` on supplier strings; state dir outside synced/output folders |
| 7 | Input handling | 10 | Size caps; XML without external entities; HTML/JSON parsing robust to hostile input; fuzz tests on parsers |
| 8 | Dependencies and build | 10 | ADR per dependency; pinned versions and actions; govulncheck clean; reproducible build; signed artifacts; SBOM |
| 9 | PWA and local UI | 5 | CSP, SRI, no third-party analytics; local UI bound to 127.0.0.1, token, Host/Origin checks, CSRF |
| 10 | Documentation | 5 | Threat model current; SECURITY.md; connector sheets list allowed domains; findings log up to date |

Gate: total >= 85, every category >= 60% of its max, no open critical or high finding,
all scanner gates passing.
