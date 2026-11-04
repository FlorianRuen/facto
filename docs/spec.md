# Spec — Personal invoice collector (open source)

Oct 26, 2026 · @Florian

## Context and goals

The project is an open source, serverless Go binary that fetches a person's supplier invoices once a year (or monthly via a scheduled task), renames them to a standard, and stores them in a local folder and/or Google Drive.

**Problem.** For year-end bookkeeping, an individual has to log into each supplier's customer portal one by one, download every PDF, rename it and file it. No standard lets anyone retrieve their consumer (B2C) invoices in a unified way (see "Why there is no standard").

**Initial scope (6 sources).**

| Source | Document | Frequency |
| --- | --- | --- |
| Cooloc | Rent (receipts or invoices) | Monthly |
| Wecasa | Cleaning invoices | Per service |
| Bouygues Telecom | Internet invoices | Monthly |
| EDF | Electricity invoices | Monthly or yearly |
| Ileo (MEL, Lille) | Water invoices | Twice a year or monthly installments |
| impots.gouv | Property tax notice (taxe foncière) | Yearly |

**Goals.**

1. Collect every invoice for a given period in one command (default: the previous year).
2. Rename files to a stable, readable convention.
3. File them locally and/or sync them to Google Drive.
4. Accept manually added documents (inbox folder) with the same processing.
5. Archive a receipt photographed on a phone, with a name and a description, without OCR.
6. Let the community add connectors (Go code, or a declarative file for services that have an API).

**Non-goals (v1).**

- No server and no SaaS: nothing to host.
- No OCR and no amount extraction on receipts.
- No banks (PSD2 access is reserved to licensed providers).
- No captcha or 2FA bypass: the user completes them when asked.
- No accounting export (FEC, accounting software): out of scope, possible later.

## Prior art

Two open source projects already collect French invoices: Cozy (Node.js) and Woob (Python). Neither offers a standalone, serverless binary with standardized renaming and Google Drive sync. We borrow their login flows, not their code.

| Project | Type | License | Coverage | What we reuse |
| --- | --- | --- | --- | --- |
| [Cozy / Twake Workplace](https://www.lafabriquedunet.fr/logiciel/twake) | Self-hostable personal cloud, Node.js connectors | MIT libs, connectors vary (some AGPL v3) | 250+ services advertised (EDF, Bouygues, Ameli, impots…) | Login flows, endpoints, "one connector = one repo" model |
| [Woob](https://gitlab.com/woob/woob) | Python scraping library, CapDocument capability | LGPLv3+ | Modules edfparticulier, impotsgouvfrpar, orange, freemobile, amazon… | Data model (subscriptions → documents → download), HTTP flows |
| Paperless-ngx | Self-hosted DMS with OCR | GPL v3 (from memory) | No supplier collection | The watched ingestion folder idea |
| [Powens (formerly Budget Insight)](https://www.getapp.fr/software/2055757/Powens) | Paid B2B API | Proprietary | Banks (PSD2) + a "Bill" product based on scraping | Nothing (B2B, paid) |
| Pennylane, Dext, Hubdoc | Business accounting SaaS | Proprietary | Varies | Nothing, wrong audience |
| Digiposte | La Poste digital safe | Proprietary | Some suppliers deposit there | Worth exploring as a single source |

**Key points.**

- **Cozy** was taken over by Linagora and merged into Twake, following a deal announced in May 2025. Its [connector libraries](https://github.com/konnectors/libs) are MIT and a connector can run [outside the Cozy stack](https://doc-self-data.apps.grandlyon.com/docs/konnectors/introduction/) (`yarn standalone`), which helps to observe a flow. Several connector repos are old: check the last commit date before relying on one.
- **Woob** is built around the `CapDocument` capability: a module lists subscriptions, then typed documents (`BILL`, `STATEMENT`…), then downloads them ([module examples](https://gitlab.com/woob/woob/-/issues/324)). We adopt this model. Several modules are maintained by Budget Insight employees, and the issue tracker shows regular breakage (for example [EDF and 2FA in 2023](https://gitlab.com/woob/woob/-/issues/661)).
- **Licenses**: copying AGPL or LGPL code into the project brings obligations. We read their flows to understand the steps, then rewrite in Go (see the legal section).

**The open niche**: a single, local, cross-platform binary that orchestrates collection + manual import + renaming + destinations, with connectors that are easy to write.

## Why there is no standard

The French e-invoicing reform only covers B2B: invoices addressed to an individual stay on each supplier's portal.

| Framework | What it requires | Useful here? |
| --- | --- | --- |
| E-invoicing reform (art. 289 bis CGI) | Reception mandatory for every business from 1 September 2026, issuance for large and mid-size companies on that date, then SMEs and micro-businesses on 1 September 2027, through an accredited platform (PDP) ([timeline](https://hayot-expertise.fr/ressources/test-facturation-electronique-2026)) | No for invoices to an individual. Yes if an invoice is addressed to a business activity |
| B2C e-reporting | The seller sends tax data to the administration ([source](https://www.keobiz.fr/le-mag/calendrier-facturation-electronique/)) | No: nothing is delivered to the customer |
| Factur-X | PDF/A-3 with embedded CII XML (one of the reform's formats) | Yes: if a received PDF contains one, we read date, issuer and amount without OCR |
| PSD2 | Bank APIs open to licensed providers | Not in v1 (license required) |
| GDPR data portability | Data provided in a structured format on request | No: manual request, no API |

The public portal (PPF) is no longer an exchange platform: [the ministry dropped its development](https://copeps.fr/actualites/loi-de-finance-dematerialisation-des-factures/) as an invoicing platform and kept it as the directory. For an individual, scraping customer portals remains the only automatable path.

## Product principles and UI choice

Recommendation: a CLI with an interactive terminal wizard for v1, then a local web UI served by the same binary if the project targets non-developers. No dedicated desktop app at first.

**Principles.**

- **Zero hosting**: everything runs on the user's machine. The only remote service is Google Drive, through the user's own account.
- **One binary**: `facto` (working name), downloadable for Linux, macOS and Windows, with no dependency besides a Chromium browser (Chrome for Testing, installed explicitly with `facto browser install`: facto never downloads a browser on its own, ADR 0008).
- **Idempotent**: re-running a collection never creates a duplicate. A yearly run and a monthly schedule produce the same end result.
- **Human in the loop**: when a site asks for a 2FA code or shows a captcha, a browser window opens and the user completes the login. The session is reused afterwards.
- **Graceful degradation**: a broken connector never stops the others, and the final report says what to do ("EDF: download manually and drop it in `inbox/`").
- **Readable without the tool**: output files stay well-named PDFs in clear folders. If the project dies, the archive remains usable.

**Interface options.**

| Option | Pros | Cons | Verdict |
| --- | --- | --- | --- |
| Plain CLI (cobra) | Simple, scriptable, ideal for scheduling | Unwelcoming for non-developers | Mandatory foundation |
| Terminal wizard (charmbracelet/huh, bubbletea) | Guided setup, 2FA entry, progress bar | Still a terminal | **v1** |
| Local web UI (net/http + go:embed, on 127.0.0.1) | Accessible to everyone, no native packaging | Local server to secure (token, localhost bind) | v2 |
| Desktop app (Wails or Fyne) | Native experience, icon, notifications | Per-OS packaging and signing, more maintenance | Later, on demand |

The collection itself needs no UI: the only interactive moment is login (2FA), handled by the browser window. The UI mostly serves first-time setup and reading the report.

**Target user journey.**

1. `facto init`: pick the output folder, connect Google Drive (optional), add suppliers.
2. `facto login edf`: first login in a browser window, session saved.
3. `facto collect --year 2026`: collect, rename, store, report.
4. `facto schedule monthly` (optional): install the OS scheduled task.

## Go architecture

A single Go binary, built without CGO for all three operating systems, orchestrates three kinds of sources, one normalization pipeline and two destinations.

&#91;embedded content: architecture · 3 sources, 1 pipeline, 2 destinations\]

The orchestrator only sees normalized documents: whether a PDF comes from a connector, an API or the `inbox/` folder, it follows the same path.

**Hybrid browser + HTTP strategy.** The browser is used for login only (forms, SSO, 2FA). Once logged in, we take the cookies or the token and list then download invoices with `net/http`, often through the site's internal JSON API. This is faster, more stable than clicking through the UI, and testable with fixtures.

**Libraries.**

| Need | Choice | Alternative | Note |
| --- | --- | --- | --- |
| CLI | `spf13/cobra` | `urfave/cli` | De facto standard |
| Terminal wizard | `charmbracelet/huh` + `bubbletea` | `survey` (archived) | Forms, selection, spinner |
| Browser | In-house CDP client over `--remote-debugging-pipe`, no dependency ([ADR 0008](adr/0008-browser-cdp-pipe.md)) | [`chromedp`](https://www.libhunt.com/compare-chromedp-vs-playwright-go) (MIT), recorded fallback | rod rejected: no pipe support, no release since July 2024, built-in browser downloader. chromedp supports the pipe but its API churns; facto needs about 17 CDP methods. Hidden behind `connector.Browser` |
| Browser (option) | `playwright-go` (MIT) | — | Needs the Playwright driver downloaded at runtime (from memory): less "single binary" |
| HTTP | `net/http` + `net/http/cookiejar` | `resty` | Cookies injected from the browser session |
| Secrets | OS keyring (`zalando/go-keyring`) by default; Bitwarden through the `bw` CLI in v1 | `99designs/keyring` | Other password managers later (see Security) |
| Local state | `modernc.org/sqlite` | JSON file | Pure-Go SQLite, no CGO |
| Google Drive | `google.golang.org/api/drive/v3` + `golang.org/x/oauth2` | — | Desktop OAuth flow (loopback) |
| PDF / Factur-X | `pdfcpu` | — | Extracting XML attachments |
| OpenAPI | `getkin/kin-openapi` | `pb33f/libopenapi` | Reading specs for declarative connectors |
| Config | `gopkg.in/yaml.v3` | `koanf` | One `config.yaml` file |
| Logs | `log/slog` | — | Standard library |
| Release | `goreleaser` | — | Binaries, checksums, Homebrew, Scoop |

Versions and maintenance status of libraries marked "from memory" or unsourced must be checked at kickoff.

**Repository layout.**

```
facto/
  cmd/facto/            # entry point (cobra)
  internal/
    orchestrator/       # run, resume, report
    connector/          # interface, registry, shared helpers
    browser/            # in-house CDP client (ADR 0008), pool, Chrome for Testing install
    normalize/          # naming, dedup, Factur-X
    store/              # SQLite (document index)
    secrets/            # providers: keyring, bitwarden, …
    vault/              # session encryption
    dest/local/         # local folder destination
    dest/gdrive/        # Google Drive destination
    schedule/           # systemd, launchd, Task Scheduler
  connectors/
    ileo/  edf/  bouyguestelecom/  wecasa/  cooloc/
    fakeprovider/       # test-only provider (see Agentic delivery)
    declarative/        # YAML/OpenAPI engine
  web/capture/          # mobile capture PWA
  testdata/             # anonymized HTML/JSON fixtures
  docs/connectors/      # one sheet per connector
  .claude/              # agent kit (see Agent kit)
```

## Connector model

A connector does three things: open a session, list the documents of a period, download a document. Everything else (naming, dedup, destinations, secrets) belongs to the core. The split follows Woob's `CapDocument` model (subscription → document → download). A connector must not start goroutines that can panic: the orchestrator recovers panics on its own goroutine only (the connector is marked `broken`), and a panic in a goroutine the connector started crashes the whole process.

**Go interface.**

```go
package connector

type Connector interface {
    // Static metadata: id, name, config fields, document kinds, allowed domains.
    Info() Info

    // Opens or restores a session. May require interaction (2FA, captcha).
    Login(ctx context.Context, env Env) (Session, error)

    // Lists documents available for the period, without downloading them.
    List(ctx context.Context, s Session, p Period) ([]DocumentRef, error)

    // Downloads one document. The core hashes it and decides whether it is new.
    Fetch(ctx context.Context, s Session, ref DocumentRef) (io.ReadCloser, error)
}

type DocumentRef struct {
    ProviderID   string    // stable supplier-side id (invoice number when possible)
    Contract     string    // contract, line, dwelling
    Kind         DocKind   // Invoice, Receipt, RentReceipt, TaxNotice, Statement
    IssuedAt     time.Time
    PeriodStart  time.Time // optional
    PeriodEnd    time.Time // optional
    AmountCents  *int64    // optional, when the API provides it
    Currency     string
    MimeType     string
    Extra        map[string]string
}

type Env struct {
    Secrets     SecretResolver // resolves bw://, keyring://… references
    Browser     BrowserPool    // headless or visible browser
    HTTP        *httpx.Client  // allowlisted, errors never carry the URL query
    Prompt      Prompter       // asks the user for an OTP code
    Log         *slog.Logger   // redacting handler
    Saved       secret.Secret  // restored session blob; zero when none
    Credentials Credentials    // secret references (bw://…), never values
    Interactive bool           // single source of truth; Prompt.Interactive() matches it
}

// Optional: a Session that implements Persistable is saved encrypted after a
// successful login and handed back as Env.Saved on the next run.
type Persistable interface {
    Persist(ctx context.Context) (secret.Secret, error)
}
```

`SecretResolver.Resolve(ctx, ref)` and `Prompter.Prompt(ctx, PromptRequest)`
return `secret.Secret`; `BrowserPool.Launch` returns a library-neutral `Browser`
(`Navigate`, `WaitVisible`, `TypeSecret`, `Click`, `CurrentURL`, `Cookies`,
`Close`) whose cookie values are `secret.Secret`. A prompt label may come from
the supplier site: Prompters display `PromptRequest.CleanLabel()` (escape
sequences and control characters removed, tokens masked, 128 bytes max).

**Run lifecycle.**

1. Restore the saved session (encrypted cookies). If it is still valid, skip login.
2. Otherwise `Login`: headless first, then a visible window if the site requires interaction and the command is interactive.
3. In scheduled (non-interactive) mode, an expired session that requires interaction puts the connector in `needs_login`. A notification and the report ask the user to run `facto login <id>`.
4. `List` for the period, then drop documents already known by `ProviderID` in the index.
5. `Fetch` new documents, compute SHA-256, dedup, normalize, send to destinations.
6. Save the session and the report.

**Connector states in the report.**

| State | Meaning | User action |
| --- | --- | --- |
| `ok` | Documents collected or nothing new | None |
| `needs_login` | Session expired, 2FA required | `facto login <id>` |
| `broken` | The site changed (selector or endpoint not found) | Update the tool or drop PDFs in `inbox/` |
| `auth_failed` | Credentials rejected | `facto config <id>` |
| `rate_limited` | Too many requests or anti-bot block | Retry later |
| `interrupted` | The run was canceled while the connector was running | Run `facto collect` again |

A restored session rejected with `auth_failed` (or `needs_login`) is reported `needs_login` and dropped: the saved session was refused, the credentials are untouched. Every `needs_login` result carries a fixed report note naming `facto login <id>`, and every `auth_failed` result one naming `facto config <id>`. `facto config` is not implemented yet: until it is, the user fixes the references in `config.yaml`.

**Declarative connectors.** For a service that exposes a real API (key, OAuth2 or JSON login), a YAML file is enough, with no recompilation. The engine can read an OpenAPI spec to validate paths and schemas.

```yaml
id: myservice
name: My service
openapi: ./myservice-openapi.yaml   # optional
allowed_domains: [api.myservice.example]
auth:
  type: oauth2_client_credentials    # or api_key, bearer, login_json
  token_url: https://api.myservice.example/oauth/token
  secrets:
    client_id: bw://<item-uuid>/username
    client_secret: bw://<item-uuid>/password
list:
  operationId: listInvoices          # or method + path
  params: { from: "{{.Period.Start | date}}", to: "{{.Period.End | date}}" }
  pagination: { type: cursor, next: "$.next_cursor" }
  items: "$.data[*]"
  map:
    provider_id: "$.id"
    issued_at: "$.date"
    amount_cents: "$.total_cents"
    kind: invoice
fetch:
  url: "$.pdf_url"                   # or operationId + params
```

None of the six initial sources has a known public API: they will be Go connectors. The declarative engine is therefore a later milestone, tested against a mock OpenAPI server first.

**Tests.** Each connector ships anonymized HTML/JSON fixtures in `testdata/` and an offline test. An optional live test (`facto doctor <id>`) checks the real flow with the user's credentials and flags site changes.

## Connector sheets

Ileo is the first connector to write (simple login), EDF and Bouygues follow, Wecasa and Cooloc need a reconnaissance pass first, and property tax stays a manual import in v1. Difficulty levels are estimates to confirm with a reconnaissance session on each site.

| Source | Login | Documents | Estimated difficulty | Inspiration | v1 |
| --- | --- | --- | --- | --- | --- |
| Ileo | Customer number + password | Invoices, "Mes factures", 10 years | Low | None known | Connector |
| EDF | Email + password, SSO, possible 2FA | Invoices over 5 years | Medium | Woob `edfparticulier`, Cozy | Connector |
| Bouygues Telecom | Login + password, possible 2FA | Internet box invoices | Medium | Cozy (Bouygues Box) | Connector |
| Wecasa | To check | Invoices per service | Unknown | None known | After reconnaissance |
| Cooloc | To check | Rent receipts or rent calls | Unknown | None known | After reconnaissance |
| impots.gouv | FranceConnect or tax number + 2FA | Property tax notice (1 per year) | High | Woob `impotsgouvfrpar` | Manual import |

### Reconnaissance method (for each site)

1. Log in with Chrome DevTools open, Network tab, "Preserve log" checked.
2. Go to the invoice list, download one, then export the HAR.
3. Identify: the authentication endpoint, the session token or cookies, the JSON call that lists invoices, the PDF URL.
4. Note mandatory headers (CSRF, `Authorization`, origin) and session lifetime.
5. Anonymize excerpts into `testdata/` and fill `docs/connectors/<id>.md` (template below).

Internal tool to build: `facto record <url>` opens a controlled browser and records a filtered HAR (no passwords, no cookies), so contributors can prepare a connector without doing it all by hand.

### Ileo (water, Métropole Européenne de Lille)

- **Site**: mel-ileo.fr, personal space. Login with the [customer number and a password](https://eau.selectra.info/ileo-lille/service-client), no 2FA mentioned.
- **Documents**: with e-invoicing, [invoices are archived for 10 years](https://eau.selectra.info/ileo-lille/espace-client-mon-compte) under "Mes factures". An email announces each new invoice.
- **Approach**: direct HTTP login if the form allows it, otherwise the browser for login then `net/http` for the list. A good "reference" connector to validate the architecture.
- **Dedup key**: invoice number.

### EDF (electricity)

- **Site**: espace-client.edf.fr. Woob traces show an OpenAM-style SSO with a `/sso/json/authenticate` endpoint ([Woob issue](https://gitlab.com/woob/woob/-/issues/661)). The same issue shows a login failure caused by a security 2FA in 2023.
- **Documents**: the customer portal lets you [download invoices over 5 years](https://www.fournisseurs-electricite.com/edf/facture/justificatif-domicile-attestation). A yearly collection is more than enough.
- **Approach**: the browser in visible mode for login (email or SMS 2FA typed by the user), save cookies, then internal JSON calls. Read the Woob `edfparticulier` module (LGPLv3+) to understand the flow, without copying it.
- **Risk**: anti-bot and frequent SSO changes. Plan for `facto doctor edf`.

### Bouygues Telecom (internet box)

- **Site**: Bouygues Telecom customer portal. The [Bouygues Open API](https://developer.bouyguestelecom-entreprises.fr/docs/getting-started) targets businesses, not consumers.
- **Documents**: monthly PDF invoices.
- **Inspiration**: Cozy listed [Bouygues Telecom and Bouygues Box connectors](https://github.com/frankrousseau/konnectors) (old repo, check the `konnectors` organization).
- **Approach**: same as EDF. Look in the HAR for a JSON invoice API called by the front end, usually more stable than HTML.

### Wecasa (cleaning)

- **To check**: login method (email + password, magic link, Google or Apple sign-in), whether invoices are on the web or only in the mobile app.
- **If app-only**: inspect the API used by the app (mitmproxy-style proxy) or fall back to manual import. If Google or Apple sign-in is mandatory, stay with manual import.
- **Bookkeeping note**: for household services, the yearly tax certificate may be more useful than each invoice. To confirm.

### Cooloc (rent)

- **Context**: Cooloc is a [fully digital co-living platform](https://nl.trustpilot.com/review/www.cooloc.com) for tenants and owners. It relies on [Swan embedded banking](https://www.swan.io/swan-loves/co) to collect rent.
- **To check**: the user's role (tenant or landlord), available documents (rent receipts, rent calls, statements), and whether the web app exposes a JSON API.
- **Approach**: HAR reconnaissance, then a Go connector.

### impots.gouv (property tax)

- **Why manual**: login through FranceConnect or tax number with a security code, and a single notice per year. Maintenance cost exceeds the benefit.
- **Later**: the Woob [`impotsgouvfrpar`](https://gitlab.com/groups/woob/-/merge_requests) module shows it is feasible. An "assisted" connector could open the documents page in a visible browser, let the user log in, then download the notice.

### Connector sheet template

```markdown
# <Supplier name>
- id:
- Site / customer portal:
- Login: (form, SSO, OAuth, 2FA: type and frequency)
- Observed session lifetime:
- List endpoint: (method, URL, parameters, pagination)
- PDF endpoint:
- Stable document id:
- History available: (years)
- Protections: (captcha, anti-bot, rate limit)
- Allowed domains:
- Inspiration sources: (links, license)
- Last verified on:
- Maintainer:
```

## Normalization and naming

Every document gets a name that sorts by date and reads without the tool, and a path by year then category. The format is configurable through a template, with a stable default.

**Default name.**

```
{date:2006-01-02}_{provider}_{kind}[_{amount}][_{ref}].{ext}

2026-03-14_edf_invoice_84-12EUR_10234567.pdf
2026-04-01_cooloc_rent-receipt_2026-04.pdf
2026-10-02_impots_property-tax-notice.pdf
2026-06-21_receipt_client-lunch-lyon.jpg
```

Rules: lowercase, ASCII (accents transliterated), hyphens between words, `_` between fields, amount with `-` as decimal separator. Missing fields are omitted, never "unknown". Kind labels are configurable (English by default, French available).

**Default layout.**

```
Invoices/
  2026/
    housing/    cooloc/  ileo/  edf/  impots/
    internet/   bouyguestelecom/
    services/   wecasa/
    receipts/
  inbox/        # manual drops, emptied after processing
.facto/         # SQLite index, report, logs (never synced, outside the output folder)
```

The category comes from the connector configuration and can be changed by the user.

**Metadata.** The SQLite index stores, per document: provider, `ProviderID`, kind, dates, amount, SHA-256, local path, Drive file id, collection date. `facto export --year 2026 --csv` produces the bookkeeping summary.

**Dedup.**

1. Before download: `(provider, ProviderID)` already present → skipped.
2. After download: SHA-256 already present → skipped (same PDF through two paths, or a manual drop of an already collected file).
3. Same `ProviderID` but different hash (regenerated corrected invoice) → new version suffixed `_v2`, the old one kept.

**Factur-X.** If a PDF contains a `factur-x.xml` (or `zugferd-invoice.xml`) attachment, we extract issue date, issuer, number and total amount. These values take precedence over the connector's. Mostly useful for files dropped in `inbox/`.

**Manual import (`inbox/`).** A dropped file is processed on the next run. Provider and date are inferred, in order: Factur-X, then an already compliant name (`2026-10-02_impots_...pdf`), then a subfolder (`inbox/impots/`). Otherwise interactive mode asks for provider and date, and scheduled mode leaves the file in `inbox/` with a warning.

## Destinations: local folder and Google Drive

v1 writes to a local folder. The simplest Drive option is to point that folder at one synced by Google Drive for desktop. Native API integration comes next, with the `drive.file` scope.

| Option | Implementation | Pros | Cons |
| --- | --- | --- | --- |
| Local folder | Atomic write (temp file, hard link (never replaces), remove temp; the output folder must support hard links (checked at startup)) | No dependency | No remote copy |
| Google Drive for desktop folder | `output: ~/Google Drive/My Drive/Invoices` | Zero OAuth code, already reliable | Needs the Drive client installed (no official Linux client) |
| Native Drive API v3 | Desktop OAuth + `drive.file` | Works everywhere, including scheduled runs on a home server | OAuth client and token handling |

**Native Drive API.**

- **Scope**: `drive.file` only. It is [non-sensitive and recommended by Google](https://docs.unified.to/skills/google-oauth-app/SKILL.md), and only grants access to files created by the app or picked by the user. The `drive` and `drive.readonly` scopes are restricted and require a yearly security assessment: avoid them.
- **Flow**: "installed app" OAuth with a redirect to `http://127.0.0.1:<port>` and PKCE, `access_type=offline` to get a refresh token, stored in the keyring or password manager.
- **Pitfall 1, Testing mode**: an app in Testing status with an external audience gets [refresh tokens that expire after 7 days](https://nango.dev/docs/api-integrations/google/how-to-register-your-own-google-api-oauth-app.md). The OAuth client must be published to production.
- **Pitfall 2, inactivity**: in production, a refresh token [expires if unused for 6 consecutive months](https://www.unipile.com/google-oauth-refresh-token/). With a yearly run, the user will reconnect every year. The monthly schedule keeps it alive.
- **OAuth client of an open source project**: two options. Either the project publishes a "Desktop" OAuth client (the id ships in the binary, which Google allows for installed apps; check the current rules), or each user creates their own client in Google Cloud and enters it. Recommendation: support both, with the project client as default.
- **Behavior**: the app creates an `Invoices` root folder, then the same layout as locally. Each file's Drive id is stored in the index to avoid duplicates and allow updates.

**Destination interface.**

```go
type Destination interface {
    Name() string
    Put(ctx context.Context, doc NormalizedDoc, r io.Reader) (RemoteRef, error)
    Exists(ctx context.Context, doc NormalizedDoc) (bool, error)
}
```

Other destinations (WebDAV, Nextcloud, S3, OneDrive) can be added through this interface.

## Mobile receipt capture

Recommendation: a static PWA (HTML + JS, no backend) hosted for free on GitHub Pages, which takes the photo, asks for a name and a description, then uploads the file straight to the user's Google Drive. The project stores nothing.

| Option | Effort | Experience | Verdict |
| --- | --- | --- | --- |
| Google Drive app (scan feature, from memory on Android) + manual rename | None | Fine, manual naming, no form | Fallback, to document |
| Static PWA + Drive API | Low (one page) | Guided form, standardized naming | **v1** |
| Native app (Flutter, Kotlin, Swift) | High | Best, but app stores and signing | Out of scope |

**PWA flow.**

1. Open the PWA (added to the home screen). First time: Google sign-in, `drive.file` scope.
2. Take the photo through `<input type="file" accept="image/*" capture="environment">`.
3. Enter a short name (required), a description (optional), the date (prefilled with today).
4. Compress the image in the browser (JPEG, about 2000 px on the long side) and upload it to `Invoices/<YYYY>/receipts/`.
5. File name: `2026-06-21_receipt_client-lunch-lyon.jpg`. The description goes to the Drive file's `description` field, name and date to `appProperties`.

**Technical points.**

- **Authentication**: Google Identity Services (short-lived access token in the browser), no refresh token, no server. The token is requested again when it expires.
- **Same Google Cloud project as the desktop binary**: with `drive.file`, access covers files created by the application. Using the same project for the PWA and the binary lets the binary find receipts and index them (to validate with a test).
- **Offline**: queue in IndexedDB when there is no network, upload when back online.
- **Without GitHub Pages**: the desktop binary can serve the same PWA on the local network (`facto serve`), but the phone must then be on the same Wi-Fi. GitHub Pages stays simpler.
- **Strict CSP**: no third-party script except Google Identity Services, no analytics, Subresource Integrity on every script.

**Integration with the binary.** On each `facto collect`, a "receipts" step lists new files in the Drive `receipts/` folder and adds them to the index and the CSV export, without downloading them again unless the local destination is enabled.

## Security and credentials

Credentials stay in the user's password manager (Bitwarden first): facto never copies them. No session and no token may leave the machine, be read by another process or appear in a log. Security is a design criterion, not a layer added afterwards.

### Password managers

The configuration only holds secret **references**, resolved at run time by a provider.

```yaml
secrets:
  default: bitwarden
connectors:
  edf:
    login:    bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/username
    password: bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/password
    otp:      bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/totp   # only if the site uses a TOTP app
  ileo:
    login:    keyring://facto/ileo/login
    password: keyring://facto/ileo/password
```

```go
type SecretProvider interface {
    Scheme() string                                   // "bw", "op", "keepass", "pass", "keyring"
    Resolve(ctx context.Context, ref SecretRef) (Secret, error)
    Close() error                                     // locks, wipes session keys
}
```

| Provider | Integration | Priority | Notes |
| --- | --- | --- | --- |
| Bitwarden | [`bw` CLI](https://bitwarden.com/help/cli/) as a subprocess, `bw get item <uuid>` | v1 | Unlocking yields a session key that decrypts the whole vault: it stays in memory, never on disk. `bw lock` at the end of the run. Never use `bw serve`, which [exposes the vault on localhost:8087](https://community.bitwarden.com/t/api-support-for-managing-items/42574/5) |
| OS keyring | `go-keyring` | v1 (default) | For users without a password manager |
| 1Password | `op read op://…` CLI or official Go SDK (from memory) | v2 | Same reference model |
| KeePassXC / KeePass | Read the `.kdbx` file through a Go library, or `keepassxc-cli` (from memory) | v2 | Works offline |
| pass | `pass show` (GPG) | v2 | Linux, power users |
| Bitwarden Secrets Manager | `bws` CLI | No | [A separate product](https://fnox.jdx.dev/providers/bitwarden-sm) for machine secrets, not the personal vault |

**Bitwarden unlock.**

1. `facto` reads `bw status`. If the vault is already unlocked by the user in this terminal (`BW_SESSION` present), that key is reused.
2. Locked vault in interactive mode: master password typed without echo, passed only to the `bw unlock` subprocess through `--passwordenv` (subprocess environment only, never the global environment, never a command-line argument).
3. Items are always resolved by UUID, never by name (a same-name item could be substituted).
4. At the end of the run or on error: `bw lock`, then the key is wiped from memory.

**Scheduled mode.** The master password is never stored to allow automatic unlock. The scheduled run reuses the encrypted supplier sessions, so it needs no Bitwarden access while they are valid. An expired session moves the connector to `needs_login`: the user runs `facto login`, which unlocks Bitwarden interactively.

**TOTP.** `bw get totp` can provide the 2FA code for a site that uses an authenticator app. The second factor and the password then sit in the same vault: this is the user's choice, off by default and flagged when enabled. SMS or email 2FA is still typed by hand.

### Threat model

Protected assets: credentials, the Bitwarden session key, supplier cookies and tokens, the Google refresh token. Targeted attackers: another program on the same machine, a leak through a file or a log, or a compromised dependency. An attacker who is already root on the machine is out of scope.

| Threat | Vector | Mitigation |
| --- | --- | --- |
| Cookie theft through the automated browser | A local process connects to the CDP port | CDP over a pipe (no open port) on Linux and macOS; on Windows a random port on 127.0.0.1, browser closed as soon as possible (accepted risk, ADR 0008) |
| Reading the Chromium profile | Cookie database and cache on disk | Temporary 0700 profile per browser launch (`$XDG_RUNTIME_DIR/facto`, else `<state_dir>/tmp`), deleted when the browser exits, stale ones swept at startup, never the personal profile |
| Reading persisted sessions | `.facto/sessions/` file | AEAD encryption, key per connector in the OS keyring (ADR 0009); `sessions: ephemeral` option |
| Leak through sync | State folder inside Google Drive | Refuse to start if `.facto/` is under the output folder or a known synced folder |
| Leak in logs, reports, errors | HTTP request or response logged | Masked `Secret` type, redaction by key and by pattern, HTTP bodies never logged |
| Leak through the command line | `ps`, shell history | No secret in arguments; environment of the single subprocess only |
| Leak through a memory dump | Core dump, debugger attach | Linux: `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`; Chromium crash reports disabled |
| Leak through a bug report | HAR, fixtures, `facto doctor` | Automatic redaction, CI scan, `--report` output clean by construction |
| Exfiltration by a connector | Buggy or malicious code sends a token elsewhere | Per-connector domain allowlist, enforced by the HTTP client (request refused) and monitored in the browser |
| Compromised dependency | Go library, Chromium binary | Minimal dependencies, govulncheck, pinned and verified Chromium version, signed releases |
| Local web UI (v2) hijacked | Malicious web page, DNS rebinding | Listen on 127.0.0.1, random token, `Host` and `Origin` checks, CSRF protection |

### Automated browser

The browser is the most sensitive component: it holds cookies in clear during login.

- **No exposed debugging port.** Any process reaching the CDP port can request the cookies: the technique has [circulated publicly since at least 2018](https://labs.cloudsecurityalliance.org/research/csa-research-note-chrome-devtools-session-hijacking-20260817/). `--remote-debugging-pipe` opens no port. facto uses it on Linux and macOS through its own CDP client ([ADR 0008](adr/0008-browser-cdp-pipe.md)). On Windows, until the pipe works there ([issue #3](https://github.com/FlorianRuen/facto/issues/3)), Chrome gets a random port bound to 127.0.0.1 with minimal lifetime: an accepted medium risk.
- **Dedicated, disposable profile.** Since Chrome 136, remote debugging is [ignored on the default profile](https://developer.chrome.com/blog/remote-debugging-port) and requires a dedicated `--user-data-dir`. facto creates a 0700 profile folder per browser launch under `$XDG_RUNTIME_DIR/facto`, or `<state_dir>/tmp` when `XDG_RUNTIME_DIR` is not set (A12), extracts the useful cookies, encrypts them, then deletes the profile once the browser has exited. Profiles left by a crashed run are swept at startup.
- **Chrome for Testing.** Google [recommends it for automation](https://developer.chrome.com/blog/remote-debugging-port). Pinned version, installed only by `facto browser install` (never downloaded silently), download verified by size and SHA-256. Chrome for Testing publishes no checksum, so the pin is trust on first use (ADR 0008).
- **Minimal browser.** No extensions, no sync, no password saving, no crash reports. Credentials are typed into fields over CDP, never passed in a URL.
- **Short life.** The browser is launched for login only, then closed: everything else goes through `net/http`.

### Data at rest

| Data | Storage | Note |
| --- | --- | --- |
| Supplier credentials | Password manager or OS keyring | Never in `config.yaml` |
| Session cookies and tokens | `.facto/sessions/<connector>.sess` | AEAD XChaCha20-Poly1305, format in [ADR 0009](adr/0009-vault-aead.md), random 256-bit key per connector in the keyring, rotated on every login |
| Google refresh token | OS keyring or password manager | Never in clear |
| Index, reports, logs | `.facto/` | No secret, checked by canary tests |

- Permissions 0700 on folders and 0600 on files, checked at startup: refuse to continue if they are too broad, like `ssh`.
- `sessions: ephemeral` writes no session to disk (login on every run). Recommended for yearly use.
- Scheduled run on Linux without a keyring: encrypted file whose key comes from `systemd-creds`. Explicit mode (`secrets.fallback: file`), documented as weaker (J2; until then sessions are ephemeral with one warning, ADR 0009).

### Data in memory and in output

- **`Secret` type**: `[]byte` whose `String()`, `Format`, `MarshalJSON` and `LogValue` return `***`. Wiped after use, best effort: the Go garbage collector may have copied the value, hence the short lifetime of secrets.
- **Logs**: an `slog` handler that masks by key (`cookie`, `set-cookie`, `authorization`, `token`, `password`, `session`) and by pattern (JWT, long base64 strings). HTTP bodies never logged, errors truncated and cleaned.
- **Canary tests**: CI injects known secrets (password, cookie, token) and checks they never appear in any written file, log, report, HAR or crash output.

### Supply chain and review

- Minimal, justified dependencies, `govulncheck` and `gosec` in CI, assisted updates (Renovate).
- Reproducible builds (`-trimpath`), published SBOM, signed releases (cosign or minisign) and checksums.
- No dynamic plugins: connectors are compiled into the binary and reviewed. YAML connectors run no code and are limited to their declared domains.
- `SECURITY.md` with a reporting address, this threat model in `docs/security.md`, and an external audit before 1.0 if possible.
- No telemetry: the binary only contacts the domains of enabled connectors, Google and the Chrome for Testing repository.

## Configuration, commands and scheduling

One `config.yaml` file, created by `facto init`, and a scheduled task installed by `facto schedule`. The binary never runs as a permanent background process.

**Configuration.**

```yaml
# ~/.config/facto/config.yaml (Linux), ~/Library/Application Support/facto (macOS), %APPDATA%\facto (Windows)
output:
  local: ~/Documents/Invoices
  gdrive:
    enabled: true
    root: Invoices
naming:
  file: "{date:2006-01-02}_{provider}_{kind}[_{amount}][_{ref}]"
  dir: "{year}/{category}/{provider}"
  language: en              # en, fr (kind labels)
secrets:
  default: bitwarden        # keyring, bitwarden; see Security
sessions: persistent        # or ephemeral
connectors:
  ileo:            { enabled: true,  category: housing }
  edf:             { enabled: true,  category: housing }
  bouyguestelecom: { enabled: true,  category: internet }
  wecasa:          { enabled: false, category: services }
  cooloc:          { enabled: false, category: housing }
manual:
  - { id: impots, name: "Impôts", category: housing, reminder: "10-01" }
notify: desktop             # desktop, none
browser:
  path: ~/chrome/chrome     # optional; default: the copy `facto browser install` installed
```

`browser.path` is the only browser setting: absolute or `~/…`, it must name an existing regular file when a browser is needed. No setting changes the browser's launch flags.

**Commands.**

| Command | Role |
| --- | --- |
| `facto init` | First-time setup wizard |
| `facto add <connector>` | Add an account (secret references) |
| `facto login <connector>` | Interactive login, visible browser window when needed; one-time codes are read on the terminal without echo; the session is saved encrypted. Needs an interactive terminal (otherwise exit `2`); exit `1` when the supplier refuses the login |
| `facto browser install` | Download the pinned Chrome for Testing build (linux64 in J1), verify its size and SHA-256, unpack it into `<state_dir>/chrome`. The only way facto downloads a browser; other platforms set `browser.path` |
| `facto collect [--year N \| --since DATE] [--only edf,ileo]` | Collect, normalize, store |
| `facto status` | State of each connector and last collection date |
| `facto doctor <connector>` | Check the real flow and diagnose breakage |
| `facto export --year N --csv` | Document summary for bookkeeping |
| `facto schedule monthly \| off` | Install or remove the scheduled task |
| `facto record <url>` | Record a cleaned HAR to write a connector |

Exit codes: `0` all ok, `1` at least one connector in `needs_login`, `broken`, `auth_failed`, `rate_limited` or `interrupted` (or the run itself failed or was canceled), `2` configuration or usage error (invalid `config.yaml`, unknown command or flag). Useful for scripts.

**Scheduling per OS.**

| OS | Mechanism | Machine asleep at the scheduled time |
| --- | --- | --- |
| Linux | User systemd timer with `Persistent=true` (preferred over cron) | Caught up on wake |
| macOS | LaunchAgent with `StartCalendarInterval` | Caught up on wake (from memory) |
| Windows | Task Scheduler, "run as soon as possible after a missed start" option | Caught up on wake |

The task runs `facto collect --since last --non-interactive` on the 1st of each month. At the end, a system notification summarizes the result ("7 new documents, EDF needs a new login"). Manual connectors (property tax) trigger a reminder on the configured date.

## Legal and open source

The tool retrieves the user's own documents, with the user's own credentials, from the user's own machine. This is the most defensible setup, but some terms of service forbid automated access: this must be clearly documented. This section is not legal advice.

**Scraping and terms of service.**

- Personal use only, by the user, on their own accounts. No third-party service logging in on someone else's behalf.
- Human pace: at most one collection per month, sequential requests, delays between pages, no captcha bypass.
- A warning in the README and when adding a connector: the user remains responsible for complying with each service's terms.
- Supplier names are used descriptively. No logos or trademarks in the UI or the repository.

**Project license.**

| License | Effect | For this project |
| --- | --- | --- |
| Apache-2.0 | Permissive, patent clause | Good default for a tool and a connector library |
| MIT | Permissive, very simple | Possible |
| AGPL-3.0 | Requires publishing modifications, even as SaaS | Only if the goal is to prevent closed commercial reuse |

Recommendation: Apache-2.0. Copy no code from Cozy connectors (often AGPL v3) or Woob modules (LGPLv3+): we read the flows, rewrite in Go, and credit inspiration sources in each connector sheet. Agents follow the same rule (see the agent kit).

**Connector governance.**

- One maintainer per connector, who holds an account with the supplier. Cozy already listed connectors ["looking for a maintainer with credentials"](https://github.com/afanasy/konnectors): this is the real bottleneck of such a project.
- Public status per connector in the README (stable, beta, broken, unmaintained), updated by `facto doctor` runs.
- A connector without a maintainer for 6 months becomes "unmaintained", then is removed from the default build.

**Repository files.** `README.md`, `LICENSE`, `CONTRIBUTING.md` (how to write a connector, sheet template), `SECURITY.md` (vulnerability reporting), `CODE_OF_CONDUCT.md`, `docs/connectors/*.md`, plus the agent kit (`CLAUDE.md`, `AGENTS.md`, `.claude/`).

## Agentic delivery

The whole build runs as Claude Code sessions in goal mode: one `/goal` per milestone, an orchestrating main session that delegates to specialized subagents, and a CI-provable finish line. Florian is only needed at four human checkpoints (repository setup, Google OAuth client, HAR recordings, live acceptance). Agents never receive real supplier credentials.

&#91;embedded content: goal loop · 5 subagents, 1 gate, 4 human checkpoints\]

A failed gate sends the findings back to the implementer; only a green `make verify` plus an audit score of at least 85 closes a milestone.

### How goal mode works (and what it implies)

- [`/goal`](https://code.claude.com/docs/en/goal) sets a completion condition; after each turn, a separate small model checks whether it holds, so completion is not decided by the model doing the work.
- The evaluator [does not run commands or read files](https://code.claude.com/docs/en/goal.md): it judges what the session printed. Every condition is therefore phrased as command output (`make verify` exits 0, a coverage line, a score file).
- A bound goes into the condition itself ("or stop after 80 turns"); it is a soft cap read by the evaluator.
- [While a subagent or background command runs, evaluation is skipped](https://code.claude.com/docs/en/goal?utm_campaignId=18788801) until a turn ends with no background work.
- It works [non-interactively with `-p`](https://code.claude.com/docs/en/goal.md), and only in trusted workspaces with hooks enabled.
- Parallel subagents [multiply token usage](https://dev.to/jessyt/claude-code-stops-pausing-every-turn-goal-loop-batch-background-24nb): parallelism is reserved for independent tasks (implementer and test writer in separate git worktrees).

### What agents do alone, what needs Florian

| Work item | Agents alone | Florian provides | Proof of done |
| --- | --- | --- | --- |
| CLI, config, orchestrator, report | Yes | — | Unit + golden tests |
| Naming, dedup, index, `inbox/` | Yes | — | Property tests on file names (incl. path traversal) |
| Factur-X parsing | Yes (generate sample Factur-X PDFs in tests) | — | Fixture round-trip tests |
| Session encryption, `Secret` type, redaction | Yes | — | Canary leak tests |
| Keyring provider | Yes (CI on Linux, macOS, Windows runners) | — | Integration tests per OS |
| Bitwarden provider | Yes, against a Vaultwarden container in CI | — | E2E with a throwaway vault |
| Browser layer (pipe, disposable profile) | Yes | — | Tests asserting no listening port and profile deleted |
| `fakeprovider` (test-only site: login, CSRF, SSO redirect, TOTP and email OTP, JSON invoice list, PDFs, rate limit, session expiry) | Yes | — | Full E2E of login → collect → store |
| Declarative engine | Yes, against a mock server generated from an OpenAPI spec | — | Contract tests |
| Local destination, scheduler units | Yes | — | Golden files + Linux user-systemd test |
| Drive destination | Yes with a fake Drive API (httptest) | OAuth client for the real E2E (H2) | Fake-API tests, then one live run |
| Capture PWA | Yes with mocked Google APIs (Playwright) | OAuth web client id (H2) | Browser tests, then one phone test |
| CI, release, signing, scanners | Yes (keyless signing via GitHub OIDC) | Repository settings (H1) | Green pipelines |
| Ileo, EDF, Bouygues connectors | Code and parsers from fixtures | Sanitized HARs (H3), live run (H4) | Offline tests, then `facto doctor` |
| Wecasa, Cooloc | Reconnaissance analysis, code from fixtures | HARs and role details (H3), live run (H4) | Same |

### Human checkpoints

- [ ] **H1, repository**: create the GitHub repo, enable Actions, branch protection on `main`, add the Claude Code GitHub Action secret, install Renovate.
- [ ] **H2, Google Cloud**: create the project, the Desktop and Web OAuth clients, publish the consent screen (`drive.file` only).
- [ ] **H3, recordings**: run `facto record` on each supplier and drop the sanitized output in `testdata/`; the redaction agent checks it before commit.
- [ ] **H4, live acceptance**: run `facto doctor` then `facto collect --year 2025` with real accounts and paste the report (it contains no secret by construction).

### Session protocol

1. Start in the repository: `claude`, accept the trust dialog, then run `/goal` with the milestone condition from `docs/agentic/GOALS.md`.
2. The main session reads `CLAUDE.md`, `docs/agentic/PROGRESS.md` and the spec, then delegates through the `planner` subagent.
3. Each task: test writer first, implementer second, reviewer, then security auditor. One Conventional Commit per task.
4. After each turn, `PROGRESS.md` gets one line per finished task; blocked tasks name the checkpoint they wait for (H1 to H4) and the session moves on to the next unblocked task.
5. Rules that no agent may break: never weaken or delete a test to get green, never copy AGPL/LGPL code, never handle real credentials, never disable a hook or a scanner.

**Example goal conditions** (full list in `docs/agentic/GOALS.md`).

```text
/goal `make verify` exits 0 on a clean checkout, `make cover` prints coverage >= 85% for internal/normalize and internal/store, `make e2e` passes the inbox scenario, and PROGRESS.md marks J0 done, or stop after 80 turns

/goal `make e2e` passes every fakeprovider scenario (password, TOTP, email OTP, expired session, rate limit), `make leakcheck` reports 0 canary hits, and `security/score.json` shows total >= 85 with no category below 6, or stop after 120 turns
```

## Agent kit and repository conventions

The repository carries everything an agent needs to stay consistent: one rule file, reusable skills, specialized subagents, hooks that enforce formatting and block risky commands, and CI that rejects anything the rules forbid. The kit is ready to commit at the root of the repository on day one.

### Files

| Path | Role |
| --- | --- |
| `CLAUDE.md` | Project rules loaded in every session: architecture, commands, conventions, forbidden actions, definition of done |
| `AGENTS.md` | Same rules for other agent tools; points to `CLAUDE.md` |
| `.claude/settings.json` | Permissions (allowed and denied commands) and hooks |
| `.claude/hooks/` | `format.sh` (gofumpt + goimports after each edit), `guard.sh` (blocks secret access, force push, network tools), `verify-fast.sh` (quick checks when a turn stops) |
| `.claude/agents/*.md` | Subagents: `planner`, `implementer`, `test-writer`, `reviewer`, `security-auditor`, `red-team`, `connector-builder`, `docs-writer` |
| `.claude/skills/*/SKILL.md` | Skills: `go-conventions`, `add-connector`, `fixtures-from-har`, `write-tests`, `security-checklist`, `audit-score`, `goal-session`, `release` |
| `docs/agentic/GOALS.md` | One goal condition per milestone, copy-paste ready |
| `docs/agentic/PROGRESS.md` | Append-only log of finished and blocked tasks |
| `docs/adr/` | Architecture decision records, one per irreversible choice |
| `.github/workflows/` | `ci.yml`, `security.yml`, `claude-review.yml`, `release.yml` |
| `.golangci.yml`, `Makefile` | Lint configuration and the single entry points (`make verify`, `make e2e`, `make leakcheck`, `make audit`) |

Subagents are [Markdown files with YAML frontmatter](https://code.claude.com/docs/en/sub-agents.md) in `.claude/agents/`; project skills live in [`.claude/skills/<name>/SKILL.md`](https://code.claude.com/docs/en/skills) and load only when used, so long references cost little.

### Subagents

| Agent | Tools | Responsibility |
| --- | --- | --- |
| `planner` | Read-only | Turns a milestone into ordered tasks with acceptance tests; never writes code |
| `test-writer` | Read, Write, Bash | Writes failing tests and fixtures before implementation |
| `implementer` | All, in a worktree | Makes tests pass without touching test assertions |
| `reviewer` | Read-only + `make` | Checks conventions, diff size, error handling, docs; returns blocking and non-blocking comments |
| `security-auditor` | Read-only + scanners | Runs scanners, scores the rubric, writes `security/score.json` and a report |
| `red-team` | Read, Write tests only | Writes attack tests (path traversal, exfiltration, leak canaries, malicious HTML) that must fail closed |
| `connector-builder` | Read, Write, Bash | Builds a connector from a sanitized HAR and its sheet, offline only |
| `docs-writer` | Read, Write docs | Keeps README, connector sheets and ADRs in sync with the code |

### Code conventions (enforced)

- Go version pinned in `go.mod`, `gofumpt` + `goimports`, `golangci-lint` with a fixed rule set; CI fails on any finding.
- `context.Context` first on every I/O function; no global state; constructor injection; small interfaces defined by the consumer.
- Errors wrapped with `%w` and a lowercase message; no `panic` outside `main`; sentinel errors per package for states (`ErrNeedsLogin`).
- Secrets only through the `Secret` type; logging only through the redacting `slog` handler; `fmt.Print*` forbidden outside `cmd/`.
- Network only through `internal/httpx` (domain allowlist); file writes only through `internal/fsx` (permissions, atomic writes, path sanitizing).
- Table-driven tests, golden files under `testdata/`, `-race` always on, no test sleeps (fake clock).
- Conventional Commits, one task per commit, one milestone per PR; `CHANGELOG.md` generated at release.
- Definition of done: tests first, `make verify` green, reviewer and auditor passed, docs updated, `PROGRESS.md` line added.

### CI pipelines

| Workflow | Jobs | Blocks merge |
| --- | --- | --- |
| `ci.yml` | Lint, unit tests on Linux/macOS/Windows with `-race`, coverage, `make e2e` (fakeprovider, Vaultwarden service), `make leakcheck` | Yes |
| `security.yml` | govulncheck, gosec, gitleaks, osv-scanner, CodeQL, OpenSSF Scorecard, SBOM | Yes (except Scorecard, tracked) |
| `claude-review.yml` | Claude Code GitHub Action: reviewer + security-auditor on each PR, comment with score | Yes when score < 85 |
| `release.yml` | goreleaser, keyless cosign signatures, SBOM, checksums, provenance | Release only |

## Security audit agents and scores

Security is measured twice per milestone: objective scanners with zero-tolerance gates, and a rubric scored out of 100 by a dedicated read-only auditor agent, challenged by a red-team agent that writes attack tests. A milestone closes only with scanners clean, rubric total of at least 85, no category below 6 and no open critical finding.

### Objective gates

| Tool | Measures | Gate |
| --- | --- | --- |
| govulncheck | Known vulnerabilities reachable from our code | 0 |
| gosec | Insecure Go patterns | 0 high, medium justified inline |
| gitleaks | Secrets in the repository and history | 0 |
| osv-scanner | Vulnerable dependencies (Go, npm for the PWA) | 0 high or critical |
| CodeQL (Go, JS) | Data-flow vulnerabilities | 0 high |
| `make leakcheck` | Canary secrets in files, logs, reports, HAR, crash output | 0 hits |
| `make e2e` security scenarios | No listening CDP port, profile deleted, allowlist enforced, permissions 0600/0700 | All pass |
| OpenSSF Scorecard | Repository practices (branch protection, pinned actions, signed releases…), 0–10 | Tracked; target 7+ before 1.0 (from memory of the scale) |

### Auditor rubric (100 points)

| Category | Points | What the auditor checks |
| --- | --- | --- |
| Secret handling | 15 | References only, `Secret` type everywhere, Bitwarden lock, no secret in argv or env leaks |
| Session storage | 10 | AEAD, key location, ephemeral mode, rotation on login |
| Browser isolation | 15 | Pipe transport, disposable profile, flags, short life, no personal profile |
| Logging and redaction | 10 | Redacting handler, no bodies, canary coverage |
| Network boundary | 10 | `httpx` allowlist per connector, TLS defaults, no proxy env surprises |
| File system | 10 | Permissions, atomic writes, path sanitizing of supplier-provided names, state outside synced folders |
| Input handling | 10 | HTML/JSON/PDF parsing limits, Factur-X XML (no external entities), size caps |
| Dependencies and build | 10 | Minimal deps, pinned versions, reproducible build, signed artifacts |
| PWA and local UI | 5 | CSP, SRI, token, Host/Origin checks |
| Documentation | 5 | Threat model current, SECURITY.md, connector sheets list allowed domains |

Each finding gets a severity (critical, high, medium, low) and a file:line reference. The auditor writes `security/audit/<date>-<milestone>.md` and `security/score.json`; CI fails if the file is missing, older than the last commit touching `internal/`, or under the gate. Scores are committed, so their evolution is public in the repository.

### Keeping the audit honest

- **Separation**: the auditor has read-only tools and its own instructions; it never fixes code. Fixes go back to the implementer.
- **Adversarial tests**: the red-team agent turns each suspected weakness into a test that must fail closed (for example a supplier returning `../../.ssh/id_rsa` as an invoice number, a connector trying to reach a non-allowed domain, a cookie appearing in a panic message).
- **Regression**: every past finding becomes a permanent test.
- **Limits**: agent scores are a heuristic. They complement, not replace, an external human audit before 1.0.

## Roadmap, risks and open questions

The project moves through milestones that each ship something usable: from J0 on, the `inbox/` folder already files PDFs downloaded by hand. Each gate is the `/goal` condition of its milestone; J2 and J3 also wait for human checkpoints.

&#91;embedded content: roadmap · 5 milestones, 4 gates\]

No dates are set: a gate must be passed before the next milestone opens. J0 and J1 need nothing from Florian beyond H1.

**Risks.**

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| A site changes and breaks a connector | High | Fixtures, `facto doctor`, `inbox/` fallback, explicit `broken` state |
| 2FA required on every login, incompatible with scheduling | Medium | Persistent sessions, `needs_login` state + notification |
| Anti-bot block or account lockout | Medium | Real browser, human pace, no parallelism per site |
| Owning the CDP client (CDP changes between Chrome versions) | Medium | Pinned Chrome for Testing, real-Chrome e2e tests on every pin bump, chromedp recorded as fallback (ADR 0008) |
| Google OAuth client (publishing, token expiry) | Medium | Personal client option, Google Drive for desktop option |
| Lack of maintainers with accounts | High over time | `facto record`, sheet template, public status per connector |
| Agents weaken tests or drift from conventions | Medium | Hooks, reviewer agent, CI rules, test files protected in the implementer's instructions |
| Agent token cost on long goals | Medium | Turn bounds in each goal, parallelism only for independent tasks |
| Personal data in fixtures | Low | Anonymization, redaction agent, CI scan |

**Open questions.**

- [ ] Cooloc: role (tenant or landlord) and available documents (receipts, rent calls, statements)?
- [ ] Wecasa: invoices on the web or only in the app? Yearly tax certificate available?
- [ ] EDF and Bouygues Telecom: type and frequency of 2FA today, session lifetime?
- [ ] Ileo: does the login form accept a direct POST without a browser?
- [ ] Final project name (`facto` is a working name)?
- [ ] Google OAuth client: published by the project, by each user, or both?
- [ ] Are documents addressed to an individual or a business activity (Factur-X and PDP case)?
- [ ] GitHub organization or personal account for the repository?

**Sources consulted (web search, 26 October 2026).** [Woob, edfparticulier issue](https://gitlab.com/woob/woob/-/issues/661), [Woob, CapDocument](https://gitlab.com/woob/woob/-/issues/324), [Cozy konnector libs](https://github.com/konnectors/libs), [Cozy, client-side connectors](https://docs.cozy.io/en/tutorials/client-side-konnector/clisk-creation), [Twake and Cozy](https://www.lafabriquedunet.fr/logiciel/twake), [why rod](https://github.com/go-rod/go-rod.github.io/blob/main/why-rod.md), [Ileo customer space](https://eau.selectra.info/ileo-lille/espace-client-mon-compte), [EDF 5-year history](https://www.fournisseurs-electricite.com/edf/facture/justificatif-domicile-attestation), [Cooloc](https://nl.trustpilot.com/review/www.cooloc.com), [Google Drive scopes](https://docs.unified.to/skills/google-oauth-app/SKILL.md), [refresh token expiry](https://www.unipile.com/google-oauth-refresh-token/), [e-invoicing timeline](https://hayot-expertise.fr/ressources/test-facturation-electronique-2026), [Bitwarden CLI](https://bitwarden.com/help/cli/), [Chrome remote debugging changes](https://developer.chrome.com/blog/remote-debugging-port), [Claude Code /goal](https://code.claude.com/docs/en/goal), [Claude Code subagents](https://code.claude.com/docs/en/sub-agents.md), [Claude Code skills](https://code.claude.com/docs/en/skills).
