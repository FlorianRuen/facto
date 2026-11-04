# facto

facto is a local, serverless Go binary. It collects your own supplier invoices
(water, electricity, internet, rent, cleaning…), renames them to a stable scheme,
and files them in a local folder and, later, in Google Drive.

Nothing is hosted. Everything runs on your machine, with your own accounts.

`facto` is a working name. The full design is in [`docs/spec.md`](docs/spec.md).

## Status

**Milestone J1 (browser layer and fake provider).** facto has four commands:
`facto collect`, `facto login`, `facto browser install` and `facto version`.

J1 adds the parts every real connector needs: a hardened browser for login,
encrypted session storage, and the secret resolver wired into `collect` and
`login`. They are tested end to end against `fakeprovider`, a synthetic
supplier that exists in test builds only.

A release build still ships **no supplier connector**. In practice `collect`
files the PDFs you drop by hand in the `inbox/` folder. Real connectors, Google
Drive and the mobile receipt capture come in later milestones (J2 to J4).

### Connectors

Connector sheets live in [`docs/connectors/`](docs/connectors/).

| Connector | Status |
| --- | --- |
| [`fakeprovider`](docs/connectors/fakeprovider.md) (test only, e2e builds) | beta: every login mode (password, TOTP, email OTP, SSO redirect, captcha) and failure mode covered by `make e2e` against a fake site. Not in release builds |

## Install

There is no release yet (signed releases come in J4). Build from a clone with
the Go version pinned in `go.mod`:

```sh
git clone https://github.com/FlorianRuen/facto.git
cd facto
go install ./cmd/facto
facto version
```

`go install` puts the binary in `$(go env GOPATH)/bin` (or `GOBIN`); that folder
must be on your `PATH`. `facto version` prints
`facto <version> (<go version> <os>/<arch>)`. A build from source reports the
version `dev`.

No connector needs a browser yet. When one does, install the pinned browser
once (Linux x86-64), see [`facto browser install`](#facto-browser-install):

```sh
facto browser install
```

## Quick start

1. Create the config file, readable by you only. facto refuses a
   `config.yaml` with any group or world permission bit. The commands below
   are for Linux; see [Configuration file](#configuration-file) for macOS and
   Windows.

   ```sh
   mkdir -p ~/.config/facto
   touch ~/.config/facto/config.yaml
   chmod 600 ~/.config/facto/config.yaml
   ```

2. Put a minimal config in it (synthetic example):

   ```yaml
   output:
     local: ~/Documents/Invoices
   state_dir: ~/.facto
   naming:
     language: en              # en or fr (kind labels)
   manual:
     - { id: edf, name: "EDF", category: housing }
     - { id: impots, name: "Impots", category: housing }
   ```

3. Run once. It creates `~/Documents/Invoices/` (its parent must exist) and
   `~/Documents/Invoices/inbox/`, both `0700`:

   ```sh
   facto collect
   ```

4. Drop PDFs in `~/Documents/Invoices/inbox/` (see below) and run
   `facto collect` again.

The run prints a summary on stdout and writes the same report, as `.txt` and
`.json`, to `<state_dir>/reports/`.

### Configuration file

Default location, when `--config` is not given:

| OS | Path |
| --- | --- |
| Linux and others | `$XDG_CONFIG_HOME/facto/config.yaml`, else `~/.config/facto/config.yaml` |
| macOS | `~/Library/Application Support/facto/config.yaml` |
| Windows | `%APPDATA%\facto\config.yaml` |

A relative `XDG_CONFIG_HOME` or `APPDATA` is ignored.

The file must be a regular file (not a symlink), at most 64 KiB, and owner-only
on Unix (`0600`). Decoding is strict: an unknown key, a duplicate key or a wrong
type is an error. The format follows [`docs/spec.md`](docs/spec.md)
("Configuration"). What facto does with each key today:

| Key | Default | Used today |
| --- | --- | --- |
| `output.local` | `~/Documents/Invoices` | Yes. Absolute path or `~/…`. Created `0700` if missing; its parent must exist. May be a symlink to a folder. |
| `output.gdrive.enabled` | `false` | No. `true` only prints a warning; documents are filed locally. |
| `output.gdrive.root` | `Invoices` | No |
| `naming.file`, `naming.dir` | see [Naming scheme](#naming-scheme) | Yes |
| `naming.language` | `en` | Yes (`en` or `fr`) |
| `state_dir` | `~/.facto` | Yes. Holds `index.db`, `reports/`, `sessions/`, `install-id` and, after `facto browser install`, `chrome/`. Must stay outside `output.local` and outside synced folders. |
| `sessions` | `persistent` | Yes: `persistent` or `ephemeral`. See [Sessions](#sessions). |
| `browser.path` | none | Yes, when a connector needs a browser. See [Browser](#facto-browser-install). |
| `manual` | none | Yes: `id` and `category` of providers you file by hand. `reminder` is checked (`MM-DD`) but no reminder is sent yet. |
| `connectors` | none | Checked. A release build ships no connector, so any `enabled: true` connector is refused (exit `2`, "connector not available in this version"). |
| `secrets.default`, `notify` | `bitwarden`, `desktop` | Checked only. Nothing uses them yet. |

Secret fields (`login`, `password`, `otp` under a connector) must be empty or a
reference (`bw://<uuid>/password`, `keyring://<service>/<key>`). A plaintext
value is refused, and the error never prints it. The `otp` reference must give
a one-time code, never a TOTP seed.

## `facto collect`

```sh
facto collect [--year N] [--config PATH] [--non-interactive]
```

| Flag | Meaning |
| --- | --- |
| `--year N` | Calendar year that connectors collect (four digits). Default: the previous year. It does not filter the inbox: every dropped file is filed, whatever its date. |
| `--config PATH` | Config file. Default: the per-OS path above. |
| `--non-interactive` | Never prompt. Automatic when stdin is not a terminal (pipe, file, `/dev/null`, schedulers). |

Order of a run:

1. Load and check `config.yaml`. Any error stops here: nothing is created.
2. Build the secret resolver (Bitwarden and keyring). It is closed, and the
   password manager locked, at the end of every run.
3. Create `output.local` and `output.local/inbox` if missing. `inbox` must be a
   real folder: a symlinked `inbox` is refused.
4. Check that `state_dir` is not inside `output.local`, with symlinks followed.
5. Open the index (`<state_dir>/index.db`) and the output folder.
6. Prepare the browser pool, which removes stale browser profiles left by a
   crashed run. Open the session store (see [Sessions](#sessions)).
7. Run the enabled connectors (none in a release build).
8. File the `inbox/` content.
9. Write the report to `<state_dir>/reports/` and print it.

Ctrl-C or `SIGTERM` (for example `systemctl stop`) cancels the run. The report
of a canceled run is still written.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run completed and every connector is ok (or there is none). Per-file problems (unidentified, invalid, name clash) do not change the code: read the report. |
| `1` | A connector needs attention, or the run failed or was canceled (unusable output or inbox folder, index or report write error…) |
| `2` | Configuration or usage error: invalid or missing `config.yaml`, `state_dir` inside `output.local` (symlinks followed), unknown command or flag, invalid `--year` |

```sh
facto collect --non-interactive; echo "exit $?"
```

A connector that needs you is reported with a fixed note:
`needs_login` says "login required: run `facto login <id>`", and
`auth_failed` says "credentials rejected: run `facto config <id>`".
`facto config` does not exist yet: fix the references in `config.yaml` instead.

### Interactive questions

On a terminal, without `--non-interactive`, `collect` asks about each
unidentified inbox file, on stderr:

```text
inbox file "scan.pdf" is not identified ("-" skips it)
  provider [impots]:
  date 2006-01-02 [2026-10-02]:
```

Press Enter to keep the value in brackets. Type `-` to skip the file. An empty
date with no default, or an invalid date, also skips it. A skipped file stays in
`inbox/`. The kind is never asked: it stays `invoice` unless the file name says
otherwise.

## `facto login`

```sh
facto login <connector-id> [--config PATH]
```

Logs in to one configured connector and saves its session for the next
`collect` runs. It always does a fresh login, and it never lists or downloads
documents.

- It needs an interactive terminal. With `--non-interactive`, or when stdin is
  not a terminal, it exits `2` before doing anything.
- The connector must be valid, shipped by this build, and present under
  `connectors:` in `config.yaml`. Otherwise it exits `2`. A release build ships
  no connector yet, so today it always stops here.
- When the site needs you (captcha, unusual check), a visible browser window
  opens and you finish the login by hand.
- One-time codes (email or SMS) are asked on the terminal with echo off.
- On success it prints `<id>: logged in`. With `sessions: ephemeral` (or no
  usable keyring) it adds `session not saved: sessions are ephemeral for this
  run`.
- It exits `1` when the supplier refuses the login or the login fails.

## `facto browser install`

```sh
facto browser install [--dir DIR] [--config PATH]
```

facto drives Chrome for Testing for logins, never your own browser profile. It
never downloads a browser by itself: this command is the only way.

- It downloads the Chrome for Testing build pinned in this facto version
  (linux64 only today), checks its exact size and SHA-256, and unpacks it into
  `<state_dir>/chrome/` (or `--dir`). Folders and executables are `0700`, other
  files `0600`.
- `state_dir` is read from `config.yaml`. Without a config file it uses
  `~/.facto`, so you can install before configuring facto.
- A second run with a verified install does nothing and uses no network.
- It never prompts. It prints `Chrome for Testing <version> installed: <path>`.
- On another platform it fails with "no pinned Chrome for Testing build for this
  platform". Set `browser.path` instead.

facto warns at run time when the pinned build is getting old. Update facto to
get a newer pin.

### `browser.path`

```yaml
browser:
  path: ~/chrome/chrome   # synthetic example
```

`browser.path` is the only browser setting. It must be absolute or `~/…`, and
name an existing regular file when a browser is needed. facto does not verify a
browser you supply: it only checks the file and its permissions (owned by you or
root, not group- or world-writable). No setting changes the browser's launch
flags. When `browser.path` is not set, facto uses the copy that
`facto browser install` verified.

The browser only runs during login. Each launch gets a fresh, private (`0700`)
profile under `$XDG_RUNTIME_DIR/facto`, else `<state_dir>/tmp`. It is deleted
when the browser exits. See [`docs/security.md`](docs/security.md) for the full
list of browser protections.

## Sessions

After a login, a connector's session (its cookies) can be saved so the next
runs skip the login while the supplier keeps it valid.

| `sessions:` | What happens |
| --- | --- |
| `persistent` (default) | The session is saved encrypted in `<state_dir>/sessions/<id>.sess` (`0600`). Its key is a random key per connector in your OS keyring (service `facto-session`), replaced at every login. |
| `ephemeral` | Nothing is saved: every run logs in again. At startup facto deletes every saved `.sess` file without reading it, and deletes its key. Recommended for yearly use. |

- Without a usable OS keyring (for example a headless Linux without a Secret
  Service), sessions are ephemeral for the run, with one warning. Nothing is
  written in clear.
- A saved session the supplier rejects is deleted. The connector is then
  `needs_login`: run `facto login <id>`.
- A damaged or unreadable session file just means a new login.

The file format is in [ADR 0009](docs/adr/0009-vault-aead.md).

## Manual import: the `inbox/` folder

Download a PDF by hand, drop it in `<output.local>/inbox/`, and the next
`facto collect` files it.

Example with `output.local: ~/Documents/Invoices` and the config above
(synthetic names):

```text
inbox/2026-03-14_edf_invoice_84-12EUR_10234567.pdf  -> 2026/housing/edf/2026-03-14_edf_invoice_84-12EUR_10234567.pdf
inbox/impots/avis-2026-10-02.pdf                     -> 2026/housing/impots/2026-10-02_impots_invoice.pdf
inbox/scan-fournisseur.pdf (Factur-X)                -> 2026/<category>/<seller-slug>/2026-03-14_<seller-slug>_invoice_84-12EUR_fa-2026-0001.pdf
inbox/document-scanne.pdf (nothing to go on)         -> stays in inbox/, warning "unidentified"
```

Paths on the right are relative to `output.local`. The category comes from the
`manual` or `connectors` entry with the same id; an unknown provider goes to
`other`. Filed files are `0600`, created folders `0700`, whatever the mode of the
dropped file. An existing year, category or provider folder with group or world
permission bits is refused. Provider subfolders (`inbox/impots/`) are kept,
empty, after a run.

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
3. **The subfolder.** `inbox/impots/` gives provider `impots`. The config has
   no per-provider kind yet, so such a file is filed as `invoice`.
4. **One ISO date in the file name** (`YYYY-MM-DD`, valid, not glued to other
   digits). Two different dates give no date.

facto never guesses a date from the file's modification time or from "today"
(ADR 0007, D2).

A file is identified when its name is compliant, or when it has both a provider and
a date. Kind defaults to invoice.

An unidentified file stays in `inbox/` with an `unidentified` warning. In
interactive mode `collect` first asks for its provider and date (see
[Interactive questions](#interactive-questions)).

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
**your own** machine. This is the most defensible setup, but **some suppliers'
terms of service forbid automated access.**

- Personal use only, by you, on your own accounts. No third-party service
  logging in on someone else's behalf.
- Human pace: at most one collection per month, sequential requests, delays
  between pages, no captcha bypass.
- **You remain responsible for complying with each service's terms.** Read
  them before you enable a connector.
- Supplier names are used descriptively. The project ships no logo or trademark.

A release build ships no connector yet: `facto collect` does not contact any
supplier. It only files the documents you downloaded yourself.
`facto browser install` contacts the Chrome for Testing download host only.

This is not legal advice.

## Current limitations (J1)

- **No supplier connector.** Release builds ship none. `collect` files the
  `inbox/` only, an enabled connector in `config.yaml` is a configuration error
  (exit `2`), and `facto login` has nothing to log in to.
- **Pinned browser on Linux x86-64 only.** On macOS, Windows or Linux arm64,
  set `browser.path` to a Chrome you installed. facto does not verify it.
- **Windows browser login is weaker.** Windows uses a loopback debug port
  instead of a pipe, an accepted risk tracked in
  [issue #3](https://github.com/FlorianRuen/facto/issues/3). See
  [`docs/security.md`](docs/security.md#windows-debug-port-accepted-medium).
- **Sessions need an OS keyring.** Without one, sessions are ephemeral for the
  run. A `systemd-creds` key source is planned for J2.
- **No Google Drive.** `output.gdrive.enabled: true` only prints a warning. To
  get a remote copy, point `output.local` at a Google Drive for desktop folder,
  if that folder supports hard links (next item).
- **The output folder must support hard links.** facto never replaces a file
  and publishes with a hard link. FAT, exFAT and some network or FUSE mounts
  are refused when `collect` opens the output folder.
- **Only `collect`, `login`, `browser install` and `version` exist.** `init`,
  `add`, `config`, `status`, `doctor`, `export`, `schedule`, `record`,
  `--since` and `--only` are planned (spec, "Commands"). Write `config.yaml` by
  hand.
- **No per-provider kind.** A file identified only by its subfolder is filed as
  `invoice`. Rename it to a compliant name to choose another kind.
- **No notification and no reminder.** `notify` and `manual[].reminder` are
  accepted and checked, not used.
- **Process hardening is Linux-only.** Core dumps and ptrace attach are
  disabled on Linux only. Permission checks are no-ops on Windows. See
  [`docs/security.md`](docs/security.md) for the full list.

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
| `make verify` | fmt check, lint, lint self-test, unit tests with `-race`, coverage gates, e2e-build unit tests, release e2e check, leakcheck. Must exit 0 before any commit. |
| `make test` | Unit tests only, fast |
| `make chrome` | Installs the pinned Chrome for Testing into `.cache/chrome` (same verified download as `facto browser install`) |
| `make e2e` | Real-Chrome browser tests, then end-to-end scenarios against `connectors/fakeprovider` and a Vaultwarden container |
| `make e2e-unit` | Unit tests built with `-tags e2e`, in every package that has e2e-only files (run by `verify`) |
| `make release-e2e-check` | Proves the release build has no e2e-only code (run by `verify`) |
| `make lint-selftest` | Proves the depguard and forbidigo guard rules are live (run by `verify`) |
| `make e2e-browser-windows` | Real-Chrome Windows checks of the CDP port; needs `FACTO_E2E_CHROME` |
| `make leakcheck` | Canary secret scan over every file, log and report produced by the tests |
| `make audit` | govulncheck, gosec, gitleaks, osv-scanner; writes `security/scanners.json` |
| `make score-check` | Fails if `security/score.json` is missing, stale or under the gate |

`make e2e` needs Docker and, on its first run, network access to download the
pinned Chrome for Testing (Linux x86-64). It drives the real browser against a
fake supplier site on 127.0.0.1. See
[`CONTRIBUTING.md`](CONTRIBUTING.md#end-to-end-tests).
