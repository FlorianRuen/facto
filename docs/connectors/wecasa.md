# Wecasa

Household services (cleaning) booked on wecasa.fr. One invoice PDF per
delivered order. Built offline from the fixtures in
`connectors/wecasa/testdata/` (recorded by Florian with `facto record`,
checkpoint H3, sanitized with the `fixtures-from-har` skill).

- id: `wecasa`
- Site / customer portal: `https://www.wecasa.fr/customer-area` (Rails pages)
  and `https://www.wecasa.fr/my-customer-area/...` (a React app whose bundle is
  served from `storage.googleapis.com/wecasa-react-prod/`).
- Login: email + password form on `https://www.wecasa.fr/customer-area/login`
  (`#user_email`, `#user_password`, submit `input[name=commit]`, Rails CSRF
  hidden field filled by the page). No 2FA observed. Cloudflare bot checks
  run in the page (`/cdn-cgi/challenge-platform`), so the login goes through
  the hardened browser, never a direct POST.
  - Success: the browser lands on `/customer-area` and the page shows the
    logout link `a[href="/customer-area/logout"]`.
  - Wrong credentials: the browser stays on `/customer-area/login` with the
    form `#new_user` still shown.
  - Anything else (captcha, unknown page): never automated. An interactive
    run reopens a visible window and waits for the user to finish the
    login by hand (`Options.UserTimeout`, default 10 min). A non-interactive
    run fails with `needs_login`.
- Direct POST login possible: no (Cloudflare checks and Rails CSRF).
- Session after login:
  - the cookies of `www.wecasa.fr` (`_wecasa_session`,
    `remember_user_token`, `_wecasa_signed_in`, `cf_clearance` when
    present), exported from the browser into the httpx jar;
  - the API token: every `/api/v1/` call sends
    `Authorization: Bearer <token>`. The server writes the token into the
    HTML of `GET /my-customer-area/bookings-list`, in the inline script
    `window.wecasa = { token: '<token>', ... }`. The connector reads it over
    HTTPS with the session cookies (no script runs in the browser for it),
    holds it as `secret.Secret`, and never logs or echoes it. A page without
    the token, or with the login form, means the session is gone →
    `needs_login`.
- Observed session lifetime: unknown (H4). `remember_user_token` suggests
  weeks.
- Session check (`Probe`): `GET /api/v1/user` with the bearer token → 200
  `application/json` (64 KiB cap, only `public_id` is read). 401 →
  `needs_login`.
- List endpoint: `GET /api/v1/customer/bookings/delivered` → 200, a JSON
  array, no pagination observed (13 orders over 14 months in the
  recording; 2 MiB cap, 2000 items cap). Each item: `public_id`,
  `appointment` (RFC 3339 with offset), `stage`, `type`, `title`,
  `universe`. Only `type == "order"` and `stage == "Done"` are invoiced
  orders; other items are skipped.
  - Per order, `GET /api/v1/customer/orders/<public_id>` → `{"success":
    true, "data": {...}}` gives `invoices` (true when a PDF exists),
    `total_price` (integer cents), `currency` (ISO 4217). Called only for
    the orders inside the requested period; an order with `invoices: false`
    is skipped.
- PDF endpoint: `GET /api/v1/customer/orders/<public_id>/download_invoices`
  with the bearer token → 200 `application/pdf` (20 MiB cap, must start
  with `%PDF-`).
- Stable document id: the order `public_id` (`^[A-Za-z0-9]{8,32}$`, e.g.
  `aCMmbqzTPFDb`). `IssuedAt` is the appointment date in UTC.
- History available: every delivered order since the account was opened
  (the recording goes back 14 months).
- Protections: Cloudflare in the login page; no rate limit observed. 429 →
  `rate_limited`, never retried.
- Allowed domains: `www.wecasa.fr`.
- Browser static prefixes (app files on shared storage, GET only):
  `https://storage.googleapis.com/wecasa-react-prod/`.
- Not used: `img.wecasa.fr`, `help.wecasa.fr`, `acqui.wecasa.fr`,
  `images.prismic.io`, Intercom, analytics. The browser blocks them; the
  login does not need them.
- Yearly tax certificate (`/customer-area/certificates`): not collected yet
  (spec open question). To add once a recording of that page exists.
- Inspiration sources: none (own reconnaissance with `facto record`).
- Status: beta
- Last verified on: 2026-11-09, offline only (fixtures); the real-site
  browser path (static prefix, session list, invoice request answering 200
  `application/pdf`) checked by Florian with `facto record` the same day.
- Maintainer: Florian
- To confirm at H4 (`facto doctor wecasa`):
  - the Cloudflare challenge selectors. A challenge inside the login form
    is treated as a challenge, never as a wrong password;
  - whether a Cloudflare block answers 403. The connector maps 403 to
    `auth_failed` like every connector, which would delete the saved
    session;
  - the session lifetime;
  - pacing. `List` sends one detail request per order back to back. That
    is fine for about one order a month; add clock-injected delays if the
    site rate-limits.
