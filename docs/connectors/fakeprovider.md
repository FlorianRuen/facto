# fakeprovider (test-only)

Synthetic supplier used by unit tests and `make e2e`. It has no real site, no
real account and no recording: every fixture is synthetic, so checkpoints H3
and H4 do not apply. Only e2e builds register it (plan J1 T17: the release binary must not
contain it; `cmd/facto` never imports the package).

- id: `fakeprovider`
- Site / customer portal: `https://www.fakeprovider.test` (API, PDFs) and
  `https://sso.fakeprovider.test` (login pages). Served by `httptest` TLS
  servers in `connectors/fakeprovider/*_test.go`, and by the fake site in
  `test/e2e/*_test.go` bound to 127.0.0.1 (plan J1 A7, T22).
- Login: modes `password` (with CSRF), `sso-redirect`, `totp` (the `otp` ref
  resolves to a code, never a seed: A5), `email-otp` (prompt; non-interactive
  run → `needs_login`), `captcha` (never automated). Implemented in T21 over
  `BrowserPool`; session cookies are then exported into the httpx jar. Until
  T21, `Login` returns `fakeprovider.ErrLoginNotImplemented`.
- Direct POST login possible: no (browser flow on purpose, to exercise the
  browser layer).
- Observed session lifetime: controlled by the fake site (`expired-session`
  mode answers 401 on `/api/me`).
- Session check (`Probe`): `GET /api/me` → 200 `application/json`
  `{"account":"..."}` (strict, 64 KiB cap); 401 or a redirect landing on
  `sso.fakeprovider.test` → `needs_login`.
- Session cookies: `fp_session` on `www.fakeprovider.test`. `NewSession`
  injects `connector.Cookie` values (held as `secret.Secret`, exposed only into
  the httpx jar through `httpx.Client.SetCookies`) and drops every cookie whose
  domain is not one of the two allowed hosts. `Session` never renders a cookie
  (String, GoString, Format, LogValue print a placeholder).
- Persisted session: `Session.Persist` exports what the jar would send to each
  allowed host (server-rotated values included) as a `secret.Secret` blob
  `{"v":1,"cookies":[{name,value,domain,path}]}`, sealed by `internal/vault`.
  `Restore` decodes it strictly, makes no request, and maps a zero, malformed,
  foreign-version or foreign-host blob to `needs_login` without echoing it.
- List endpoint: `GET /api/invoices?from=YYYY-MM-DD&to=YYYY-MM-DD&page=N`
  (N from 1). JSON `{"invoices":[{id, contract, issued_at, period_start?,
  period_end?, amount_cents?, currency?}], "next_page": N+1 | null}`. Strict
  decoding (unknown fields, trailing data, missing or null `invoices` refused;
  `Content-Type` must be `application/json`); caps on page bytes (1 MiB),
  item count (2000) and page count (50), all tunable through `Options`;
  `next_page` must be exactly `page+1`; duplicate ids, invalid id, contract
  (`^[A-Z0-9-]{1,32}$`), dates (strict `YYYY-MM-DD`, period both-or-neither and
  ordered), amount (integer, |cents| <= 100 000 000) and currency
  (`^[A-Z]{3}$`, required with an amount) → `broken`. Items whose `issued_at`
  is outside the half-open period are dropped. Errors name item indexes and
  JSON members, never their values.
- PDF endpoint: `GET /api/invoices/{id}/pdf`, `Content-Type: application/pdf`
  (media type, parameters ignored), body must start with `%PDF-` at offset 0,
  streamed with a size cap (default 20 MiB): a declared `Content-Length` over
  the cap fails before reading, an undeclared oversized body fails the read
  (`httpx.ErrBodyTooLarge`, never truncated). The id is re-validated before
  any request.
- Stable document id: `id` (`^[A-Z0-9][A-Z0-9-]{0,63}$`, e.g. `FP-2025-0001`).
- History available: any year the fake site is seeded with; an empty year
  returns `{"invoices":[],"next_page":null}`.
- Protections: `rate-limit` mode (429, no retry), `captcha` mode,
  `site-changed` mode (404 / changed JSON → `broken`).
- Error mapping (List, Fetch, Probe): 401 or landing on the SSO host →
  `needs_login`; 403 → `auth_failed`; 429 → `rate_limited` after one request
  (no retry, `Retry-After` never slept on); 404 → `broken` naming the endpoint
  path, never its query; any other status, malformed JSON or non-PDF →
  `broken`. A redirect off the allowlist fails with `httpx.ErrDomainNotAllowed`
  before any connection.
- Network: every request goes through the session's `*httpx.Client`; the
  package does not import `net/http` (depguard rule `network`).
- Registration: `Register(*connector.Registry)` exists only in
  `register_e2e.go` (`//go:build e2e`); no `init()`, and the release
  `cmd/facto` never depends on the package (T17).
- Allowed domains: `www.fakeprovider.test`, `sso.fakeprovider.test`
- Inspiration sources: none (synthetic).
- Status: beta (HTTP side done in T20; login lands in T21)
- Last verified on: offline only
- Maintainer: Florian Ruen
