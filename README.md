# facto

facto is a local, serverless Go binary. It collects your own supplier invoices
(water, electricity, internet, rent, cleaning…), renames them to a stable scheme,
and files them in a local folder and, later, in Google Drive.

Nothing is hosted. Everything runs on your machine, with your own accounts.

`facto` is a working name. The full design is in [`docs/spec.md`](docs/spec.md).

## Status

**Milestone J0 (foundations) is in progress. There is no `facto` command yet.**

You cannot install or run facto today. The repository holds the internal
packages that the first command will use:

| Package | What it does today |
| --- | --- |
| `internal/fsx` | The only way facto writes files: confined to a directory, 0600 files, 0700 directories, atomic writes that never replace |
| `internal/httpx` | The only way facto talks to the network: per-connector domain allowlist, HTTPS only |
| `internal/logx` | Redacting `slog` handler: secrets never reach a log line |
| `internal/normalize` | File and folder naming, dedup rules |
| `internal/normalize/facturx` | Reads the Factur-X / ZUGFeRD XML embedded in a PDF |
| `internal/inbox` | Manual import: identifies files dropped in `inbox/` |
| `internal/store` | SQLite document index |
| `internal/dest/local` | Local output folder |
| `internal/orchestrator` | Runs connectors and the inbox through hash, dedup, naming, destination and index; writes the run report |
| `internal/connector` | Connector contract and registry |

Still pending in J0:

- `internal/secrets` (the `Secret` type, `bw://` and `keyring://` references).
- `config.yaml` loading and validation.
- The CLI: `facto collect` and `facto version`.
- The end-to-end test harness and the `inbox` scenario.

Login, browser automation, session storage, real connectors, Google Drive and the
mobile receipt capture come in later milestones (J1 to J4).

### Connectors

No connector is implemented yet. Connector sheets will live in
[`docs/connectors/`](docs/connectors/); only the template exists today.

| Connector | Status |
| --- | --- |
| (none yet) | |

## Manual import: the `inbox/` folder

From J0 on, the plan is that you download a PDF by hand, drop it in
`<output>/inbox/`, and the next `facto collect` files it. The `inbox` and
`orchestrator` packages implement this. The command that runs them is not
written yet.

### What is scanned

- Files directly in `inbox/`, and files in one level of subfolders
  (`inbox/impots/notice.pdf`).
- A subfolder name is a provider id hint. It must be a safe name and slug to a
  non-empty id. Otherwise its files stay untouched (`invalid-subfolder`).
- Hidden entries (name starting with `.`) are ignored.
- Symlinks, FIFOs and devices are never followed or opened (`not-regular`).
- Folders below a provider subfolder are not descended (`nested`).
- Files over 32 MiB are not read (`too-large`).

### How a file is identified

Each field is taken from the first source that provides it, in this order:

1. **Factur-X.** If the PDF embeds `factur-x.xml` (or `zugferd-invoice.xml`):
   provider = slug of the seller name, date = issue date, amount and currency =
   grand total, ref = slug of the invoice number, kind = invoice.
2. **A compliant name.** A file already named with the default scheme (see below),
   for example `2026-10-02_impots_property-tax-notice.pdf`.
3. **The subfolder.** `inbox/impots/` gives provider `impots`. The provider's
   configured kind applies when nothing else set it.
4. **One ISO date in the file name** (`YYYY-MM-DD`, valid, not glued to other
   digits). Two different dates give no date.

facto never guesses a date from the file's modification time or from "today"
(ADR 0007, D2).

A file is identified when its name is compliant, or when it has both a provider and
a date. Kind defaults to invoice.

An unidentified file stays in `inbox/` with an `unidentified` warning. In
interactive mode the inbox can ask a `Prompter` for provider, kind and date. No
terminal prompter exists yet.

### What happens after filing

- A file is removed from `inbox/` only after it was filed and indexed, or when it
  is an exact duplicate (same SHA-256) of an indexed document.
- Before removal facto checks that the file is still the one it read (same size,
  same SHA-256, same file). A changed file is kept (`changed`).
- Every other outcome keeps the file in `inbox/`: invalid metadata, name clash at
  the destination, read error, or a filed document whose folder could not be
  synced to disk (`not-durable`).
- A file whose Factur-X attachment was refused (for example unsafe XML) is still
  identified from the other sources and gets an `invalid-facturx` warning.

A document needs a provider to be filed. A compliant name without a provider
(`2026-06-21_receipt_client-lunch-lyon.jpg`) is identified but reported
`invalid`, and stays in `inbox/`.

## Naming scheme

Implemented in `internal/normalize`, with the gaps settled in
[ADR 0007](docs/adr/0007-j0-product-decisions.md).

Default file template and folder template:

```text
{date:2006-01-02}_{provider}_{kind}[_{amount}][_{ref}]
{year}/{category}/{provider}
```

Examples (synthetic; `housing` is the category the spec's sample config gives
these providers):

```text
2026/housing/edf/2026-03-14_edf_invoice_84-12EUR_10234567.pdf
2026/housing/cooloc/2026-04-01_cooloc_rent-receipt_2026-04.pdf
2026/housing/impots/2026-10-02_impots_property-tax-notice.pdf
2026/housing/edf/2026-03-14_edf_invoice_84-12EUR_10234567_v2.pdf
```

Rules:

- Lowercase ASCII. Accents are transliterated with a built-in table (`é` → `e`,
  `œ` → `oe`, `ß` → `ss`). Other characters become a hyphen.
- `-` between words, `_` between fields.
- `[ … ]` is an optional group. It disappears when one of its fields is missing.
  Missing fields are omitted, never written as "unknown".
- Amount: cents with `-` as decimal separator, then the ISO currency, e.g.
  `84-12EUR`. Omitted without a three-letter currency.
- Dates are rendered in UTC.
- A new version of a known document gets `_v2`, `_v3`… before the extension.
- Extension: lowercased, letters and digits only, at most 8 characters.
- A file name is at most 200 bytes. The stem is shortened; `_vN` and the extension
  are kept.
- A provider without a configured category is filed under `other` (ADR 0007, D4).
- Every path component is also passed through `fsx.SafeName`: supplier data can
  never add a separator, a `..` segment or a Windows device name.

Kind labels:

| Kind | English (default) | French |
| --- | --- | --- |
| Invoice | `invoice` | `facture` |
| Receipt | `receipt` | `recu` |
| Rent receipt | `rent-receipt` | `quittance-de-loyer` |
| Tax notice | `property-tax-notice` | `avis-de-taxe-fonciere` |
| Statement | `statement` | `releve` |

The compliant-name parser accepts both languages.

### Dedup

1. Before download (connectors): a `(provider, ProviderID)` already indexed is
   skipped and never fetched.
2. After download: content whose SHA-256 is already indexed, under any provider,
   is skipped.
3. Same `(provider, ProviderID)` with new content: filed as the next version
   (`_v2`…). The old file is kept.

For inbox files, the ProviderID is the document ref (for example the Factur-X
invoice number).

## Terms of service and legal warning

facto retrieves **your own** documents, with **your own** credentials, from
**your own** machine. Some suppliers' terms of service forbid automated access.

- Use it for personal use only, on your own accounts.
- It runs at a human pace: sequential requests, at most one collection per month,
  no captcha or 2FA bypass.
- **You remain responsible for complying with each service's terms.**
- Supplier names are used descriptively. The project ships no logo or trademark.

This is not legal advice.

## License

Apache-2.0 is the intended license. The `LICENSE` file is not in the repository
yet (pending checkpoint H1). Until it is added, no license is granted.

## Security

Do not open public issues for security problems. See [`SECURITY.md`](SECURITY.md)
for how to report a vulnerability. The threat model and what the code enforces
today are in [`docs/security.md`](docs/security.md).

## Development

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CLAUDE.md`](CLAUDE.md) first.
The Makefile is the only entry point:

| Command | What it does |
| --- | --- |
| `make verify` | fmt check, lint, unit tests with `-race`, coverage gates, leakcheck. Must exit 0 before any commit. |
| `make test` | Unit tests only, fast |
| `make e2e` | End-to-end tests against `connectors/fakeprovider` and a Vaultwarden container |
| `make leakcheck` | Canary secret scan over every file, log and report produced by the tests |
| `make audit` | govulncheck, gosec, gitleaks, osv-scanner; writes `security/scanners.json` |
| `make score-check` | Fails if `security/score.json` is missing, stale or under the gate |

The end-to-end harness (`test/`) and `connectors/fakeprovider` are not in the
repository yet, so `make e2e` fails today.
