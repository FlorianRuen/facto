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
  `BrowserPool` (see "Login flow"); session cookies are then exported into the
  httpx jar. Every automated browser step is bounded by `Options.StepTimeout`
  (default 30 s), the manual login in a visible window by
  `Options.UserTimeout` (default 10 min).
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
  The blob is written into one exactly sized buffer owned by the returned
  secret (Wipe clears it); jar cookies Restore would refuse are skipped. The
  cookie value strings held by the jar remain, out of Persist's reach.
  `Restore` decodes it strictly, makes no request, and maps a zero, malformed,
  foreign-version or foreign-host blob, or a cookie path other than `/`, to
  `needs_login` without echoing it. When a restored session fails `Probe`,
  `Login` deletes the restored cookies from the jar before the browser login,
  so the new session carries only the browser's cookies.
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
  the cap fails before reading (`httpx.ErrBodyTooLarge` and `broken`, like
  List's cap), an undeclared oversized body fails the read
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
- Status: beta (HTTP side in T20, login flows in T21; e2e fake site in T22)
- Last verified on: offline only
- Maintainer: Florian Ruen

## Login flow

Contract between `Login` (T21), its unit tests
(`connectors/fakeprovider/login_test.go`, scripted fake browser in
`fakebrowser_test.go`) and the e2e fake site (T22, `test/e2e/*_test.go`). The
fake site must serve exactly these URLs and selectors. All pages are on
`https://`, port 443, on one of the two allowed hosts.

| Page | URL (path) | Visible selectors | What the connector does |
| --- | --- | --- | --- |
| Login form | `https://www.fakeprovider.test/login`; in `sso-redirect` mode the site answers 302 to `https://sso.fakeprovider.test/login` | `#login-form`, `#username`, `#password`, `#login-submit`; hidden `input[name=csrf_token]` | `TypeSecret("#username")`, `TypeSecret("#password")`, `Click("#login-submit")`. The CSRF field is never typed into: the browser submits it with the form. |
| Bad credentials | same `/login` URL (same host as the form) | login form + `#login-error` | `auth_failed`, no retry |
| TOTP | `https://www.fakeprovider.test/login/totp` | `#otp-form`, `#otp`, `#otp-submit` (`#otp-error` after a wrong code) | resolve the `otp` ref (a code, never a seed: A5), `TypeSecret("#otp")`, `Click("#otp-submit")`. No `otp` ref: prompt if interactive, else `needs_login`. Wrong code (`/login/totp` again with `#otp-error`) → `auth_failed`. |
| Email OTP | `https://www.fakeprovider.test/login/email` | `#email-code-form`, `#email-code`, `#email-code-submit` (`#email-code-error` after a wrong code) | non-interactive → `needs_login`, `Prompt` never called. Interactive → one `Prompt` with a connector-written label, `TypeSecret("#email-code")`, `Click("#email-code-submit")`. The `otp` ref is never used here. |
| Captcha | `https://www.fakeprovider.test/login/captcha` (served instead of the form in `captcha` mode, or after submit) | `#captcha` | never automated: no typing, no click. Non-interactive → `needs_login`. Interactive → headless browser closed, relaunched with `Visible: true` (same allowlist), navigate to `/login`, wait (bounded) for `#account` while the user completes the whole login by hand. |
| Logged in | `https://www.fakeprovider.test/account` | `#account` | `Cookies(Info().AllowedDomains)` → `NewSession(env.HTTP, cookies)`. The site sets `fp_session` host-only on `www.fakeprovider.test` (parent-domain cookies are dropped by design in J1); no `www` cookie → `broken`. |

Sequence:

1. `Env.Saved` set: `Restore` + `Probe`. Valid → done, no browser, no secret
   resolved. `needs_login` from either → delete the restored cookies from the
   jar and continue. Any other `Probe` error
   (e.g. `rate_limited`) is returned, no browser.
2. Resolve the `login` and `password` refs before launching any browser (a
   resolver failure opens no browser). The `otp` ref is resolved only when the
   TOTP page shows (codes are time-bound).
3. Launch headless with `Info().AllowedDomains`; every launched browser is
   closed exactly once on every path.
4. Navigate once to `https://www.fakeprovider.test/login` (never to the SSO
   host directly), wait for `#login-form, #captcha`, then classify the page
   with `CurrentURL` (host + path, table above).
5. After each submit, wait for the union of the next pages' selectors, then
   classify with `CurrentURL`. A non-https URL, a host outside the allowlist
   (including the parent `fakeprovider.test`) or an unknown path → `broken`,
   and `Cookies` is never called.
6. Every `WaitVisible` runs under a deadline (the browser polls until its
   context ends). A wait, type or click failing while the run's context is
   live → `broken`, the message naming the missing selector. A cancelled
   context is returned as such, never `broken`.
7. No login, password, OTP or email code, cookie or saved blob value ever
   appears in an error, a log record, a prompt label or a rendered session.
