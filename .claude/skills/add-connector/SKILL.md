---
name: add-connector
description: Step-by-step procedure to create or repair a supplier connector (connectors/<id>) from a sanitized recording, with offline tests and a connector sheet. Use whenever the task mentions a supplier (Ileo, EDF, Bouygues, Wecasa, Cooloc, impots) or a new connector, a broken connector, or a site change.
---

# Adding or repairing a connector

Prerequisites: `testdata/<id>/` (sanitized, see `fixtures-from-har`) and
`docs/connectors/<id>.md` (template in `docs/connectors/_template.md`). If missing,
write `BLOCKED(H3)` in PROGRESS.md and stop.

## Steps
1. Read the sheet: login type, 2FA, list endpoint, PDF endpoint, stable id, allowed domains.
2. Create `connectors/<id>/`: `connector.go` (Info, Login, List, Fetch), `parse.go`
   (pure functions over HTML/JSON), `register.go` (`func init() { connector.Register(New) }`).
3. `Info()` declares `AllowedDomains` exactly as in the sheet. Nothing else may be contacted.
4. Login: prefer pure HTTP if the sheet says the form accepts a direct POST; otherwise
   `env.Browser.Login(ctx, LoginScript{…})`, then export cookies into the HTTP jar.
   OTP comes from `env.Prompt` or a `…/totp` secret reference, never hard-coded.
5. List: parse into `[]DocumentRef` with a stable `ProviderID`; handle pagination,
   empty years, and contracts. Fetch: stream the body, check `Content-Type` and size cap.
6. Map failures: login page shown again → `ErrNeedsLogin`; selector/endpoint missing →
   `ErrBroken` with the missing piece in the message; 401/403 with valid session → `ErrAuthFailed`;
   429 or captcha page → `ErrRateLimited`.
7. Tests (offline, from fixtures): happy path, pagination, empty year, expired session,
   wrong password, site changed, oversized PDF, domain outside allowlist.
8. Update the sheet (`Last verified on: offline only`) and the README status table.
9. Hand over to Florian: add `NEEDS(H4): facto doctor <id>` to PROGRESS.md.

## Never
Copy code from Cozy or Woob; contact the real site; commit unsanitized data.
