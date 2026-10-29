# Security

This page has two parts. The threat model is the target design from
[`docs/spec.md`](spec.md) ("Security and credentials"). The rest describes what
the code enforces **today**, at milestone J0, and names the package that does it.

To report a vulnerability, see [`SECURITY.md`](../SECURITY.md).

## Threat model (summary)

**Protected assets:** supplier credentials, the Bitwarden session key, supplier
cookies and tokens, the Google refresh token.

**Attackers in scope:** another program on the same machine, a leak through a
file or a log, a compromised dependency, a buggy or malicious connector.

**Out of scope:** an attacker who is already root on the machine; supplier
websites themselves.

| Threat | Planned mitigation (spec) | State at J0 |
| --- | --- | --- |
| Cookie theft through the automated browser (CDP port) | CDP over a pipe, else random 127.0.0.1 port, short browser life | Not started (J1) |
| Reading the Chromium profile | Disposable 0700 profile, deleted after login | Not started (J1) |
| Reading persisted sessions | AEAD-encrypted sessions, key in keyring or password manager; `sessions: ephemeral` | Not started (J1, `internal/vault`) |
| Leak through sync | Refuse a state dir inside the output folder or a synced folder | Done: `internal/config` (ADR 0007, D1, lexical) and `cmd/facto` (output folder, symlinks followed); synced-folder detection is name-based, see limitations |
| Leak in logs, reports, errors | `Secret` type, redaction by key and pattern, no HTTP bodies logged | Done: redacting logger, clean reports, `secret.Secret` (`internal/secret`), config errors never echo values |
| Leak through the command line | No secret in argv; subprocess-only environment | Done in `internal/secret/bitwarden`; no CLI flag takes a secret. The resolver is not called by `collect` yet (J1) |
| Leak through a memory dump | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux | Done in `internal/proc`, called first by the CLI on every run; Linux only |
| Leak through a bug report | Redaction, CI canary scan, clean `--report` | Canary scan (`make leakcheck`) and clean report done |
| Exfiltration by a connector | Per-connector domain allowlist in the HTTP client | Done in `internal/httpx` and `internal/orchestrator` |
| Compromised dependency | Minimal deps, scanners, pinned tools, signed releases | Scanners and pinned tools done (`make audit`, ADR 0001); releases J4 |
| Hostile input files (inbox, PDFs) | Path sanitizing, parse limits, no XML entities | Done in `internal/fsx`, `internal/inbox`, `internal/normalize/facturx` |

## What J0 enforces today

### Domain allowlist (`internal/httpx`)

`internal/httpx` is the only package that does network I/O. Each client is built
from one allowlist.

- **Entries** are an exact host (`api.example.com`) or `*.` plus a host
  (`*.example.com`). A wildcard matches subdomains only, not the bare host.
- **Refused entries:** empty list, scheme, path, port, userinfo, query, fragment,
  whitespace, control or non-ASCII bytes, any other `*`, leading or trailing `.`.
- **Public suffixes are refused**, exact or after `*.`: any single-label host
  (`com`, `*.fr`, `localhost`) and a built-in list of multi-label suffixes
  (`co.uk`, `com.au`, `gouv.fr`, `asso.fr`…).
- **Shared-hosting suffixes are refused**, exact or after `*.`: `github.io`,
  `pages.dev`, `netlify.app`, `vercel.app`, `herokuapp.com`, `appspot.com`,
  `cloudfront.net`, `amazonaws.com`, S3 endpoints, `blob.core.windows.net`,
  `r2.dev`, `workers.dev`, `storage.googleapis.com` and others. One tenant
  (`myproject.github.io`) stays valid. Wildcards below `amazonaws.com` are refused,
  except one bucket directly below a known S3 endpoint.
- **Every request and every redirect hop** is checked before any connection.
- **HTTPS only**, TLS 1.2 minimum, certificate verification always on.
- **Port 443 only.** A host with any other port, an empty port or `:0443` never
  matches.
- **The `Host` header** is checked too when it differs from the URL host.
- **Opaque URLs are refused** on every request and redirect hop. A URL with a
  non-empty `Opaque` (`//other-host/path` next to an allowlisted `Host`) would make
  `net/http` write an absolute-form request line naming another host, which a
  shared front end may honour (domain fronting). The error names the host only,
  never the opaque part.
- **No proxy from the environment.** httpx never reads `HTTPS_PROXY` and friends.
  A proxy is used only when the caller passes one explicitly; nothing does today.
- **Bounded:** 60 s default timeout (body read included), 10 redirects max, body
  size cap helper (`LimitBody`).
- **Clean errors:** an error never contains a query string, fragment, userinfo or
  header value.

`connector.ValidateInfo` uses the same parser for `Info.AllowedDomains`.

### Connector isolation (`internal/orchestrator`)

- Connectors run **one at a time**, in registry order.
- Each connector gets **its own `httpx` client** built from its own
  `AllowedDomains`. An invalid allowlist marks it `broken` before login.
- Each connector gets a logger that is always wrapped in the redacting handler,
  whatever logger the caller passed.
- A failing connector never stops the others. Its state is `needs_login`,
  `broken`, `auth_failed` or `rate_limited`, from the sentinel error it returns.
- **Panics are recovered** on the orchestrator's goroutine: the connector becomes
  `broken`, a fetched body left open is closed, and the panic value is never
  logged or reported (only its type and the phase).
- **Cancellation:** the connector running when the run is canceled is reported
  `interrupted`, never `ok`.
- Error text never reaches the report. Details go to the redacted log only.
- **ProviderID policy.** Before any lookup, fetch or write, each
  `DocumentRef.ProviderID` is checked. It is refused when it is over 128 bytes,
  is not valid UTF-8, holds `://`, `?` or `=` (a download link or query used as
  the id), whitespace, a control, format or other non-printable character, or has
  the shape of a JWT (three dot-separated base64url segments, the first starting
  with `eyJ`). A refused document is reported `invalid`, without the id, and is
  never fetched, indexed, named or logged; the connector's other documents go on.
  Long alphanumeric ids (`FACTURE2026000123`, `in_1MtHbELkdIwHu7ixl4OzzPMv`) are
  accepted: they look like tokens to the log patterns but are real invoice
  numbers. The empty id (no dedup key) is valid.
- Exit codes (`orchestrator.ExitCode`): `0` all ok or no connector, `1` any
  connector not ok or a failed or canceled run, `2` configuration error. The
  CLI also exits `2` on a usage error (unknown command or flag, invalid
  `--year`).

### Redacting logger (`internal/logx`)

Every facto logger goes through `logx.Handler`.

- **By key**, case-insensitive, at any group depth: `cookie`, `authorization`,
  `token`, `password`, `secret`, `session`, `auth`, `otp`, `csrf`, `sid`, `mdp`,
  `code`, `pin`, `key` and more. Short fragments match whole words only (`auth`
  masks `X-Auth`, not `author`). A sensitive group name masks everything inside.
- **Keys and group names are cleaned too.** Attribute keys, map keys and group
  names (`slog.Group`, `WithGroup`, `With`) go through the same pattern masking
  and lose their control characters, so a secret used as a key is not written.
  Whether a key is sensitive is decided on the original key.
- **Nested values:** maps (any key type), structs, slices and byte values are
  walked; sensitive keys and fields inside them are masked.
- **By pattern**, in messages and strings: JWTs, long base64 strings, and the
  userinfo, query and fragment of URLs of **any scheme**.
- **Free text `key=value`:** in messages, strings and error text, the value after
  a sensitive key is masked, case-insensitively: `password=v`, `password: v`,
  `password = "v"`, JSON `"password":"v"` and re-quoted `\"password\":\"v\"`.
  An unquoted value ends at whitespace or punctuation (`&;,"'<>()[]{}`), a quoted
  one at its closing quote.
- **Authorization schemes:** the credential after a whole word `Bearer` or
  `Basic` is masked (`got Bearer ***`).
- **Header lines:** when an unquoted key holding `cookie` or `authorization`
  (`Set-Cookie`, `Proxy-Authorization`) is followed by `:`, the value runs to the
  end of the line. An authorization line keeps a `Bearer` or `Basic` scheme and
  masks the rest; any other scheme (`Token`, `Digest`, `Negotiate`) or a malformed
  one (`Bearer: x`) is masked whole. A cookie line masks its first value, then
  every later cookie value and bare token, keeping only the Set-Cookie
  attributes (`Path`, `Domain`, `Expires`, `Max-Age`, `SameSite`, `Priority`,
  `Secure`, `HttpOnly`, `Partitioned`). In fmt's one-line rendering of an
  `http.Header` (`map[Cookie:[…] X:[…]]`) the value ends at its `]`. The scan
  runs in linear time.
- **Parse errors:** the raw URL that `net/url` quotes in its errors is masked,
  including the port, escape and `ParseAddr` reasons that repeat password bytes.
- **Standard library types fail closed:** `url.URL` is rendered without userinfo,
  query or fragment; `url.Userinfo` is masked; an `http.Cookie` shows its name
  only; any other type from `net/http`, `net/url`, `net/http/cookiejar` or
  `crypto/...` (requests, responses, clients, jars, TLS configs, keys) is never
  printed, even embedded in another struct or wrapped in a defined type.
- **Bodies are never printed:** a value implementing `io.Reader` or `io.Writer` is
  not rendered.
- Errors are cleaned of control characters (no forged log lines) and capped at
  512 bytes.
- `slog.LogValuer` is resolved first, so a type that masks itself stays masked.

### File safety (`internal/fsx`, `internal/dest/local`)

`internal/fsx` is the only package that writes files.

- **Confinement:** every operation goes through `os.Root`. Neither `..` nor a
  symlink can reach outside the root directory.
- **Permissions:** files are created `0600` and directories `0700`, whatever the
  umask. Appending to, or creating a directory over, an existing entry with group
  or world bits is refused.
- **Atomic writes:** temp file, `fsync`, then publish, then `fsync` of the parent
  directory. No partial file is ever visible. A failed parent `fsync` is reported
  as "written but not durable".
- **Never replace:** documents and reports are published with a hard link, which
  fails if anything already exists at the name (file, directory, even a dangling
  symlink). Of two concurrent writers, exactly one wins.
- **Startup probe:** the local destination checks once, when it opens the output
  folder, that the folder supports hard links. A folder that does not (FAT,
  exFAT, some network or FUSE mounts) is refused.
- **Safe names:** `fsx.SafeName` strips separators, `..`, NUL, control and format
  characters, Windows reserved names and trailing dots or spaces, and caps names
  at 200 bytes.
- **Confined reads:** reads of folders facto does not own (`inbox/`) never follow
  a final symlink and never block on a FIFO; the opened entry is checked to be the
  one listed.

### Inbox hardening (`internal/inbox`)

Files dropped in `inbox/` are untrusted input.

- Symlinks, FIFOs, devices and sockets are never followed or opened.
- Only one level of subfolders is read. Subfolder names must be safe names.
- Files over the size cap (32 MiB by default) are not read.
- Each file is read once and its size and SHA-256 recorded. Before filing and
  before removal, the file must still have the same size and hash, and before
  removal it must still be the same file. Otherwise it is kept (`changed`).
- Only a filed or duplicate file is removed. A directory is never removed.
- Warnings carry a path and a reason, never file content or error text.

### Factur-X parsing (`internal/normalize/facturx`)

- **No DTD, no entities:** any XML directive (`<!DOCTYPE`, `<!ENTITY`) is refused.
  Only the five predefined XML entities are known. Only UTF-8 is accepted.
- Elements are matched by namespace URI and exact path, never by prefix.
- XML is capped at 4 MiB and 64 levels of nesting.
- PDFs are capped at 32 MiB. pdfcpu runs stateless (it writes nothing to disk) with
  its own read and decode limits.
- The attachment stream is inflated by facto through a **capped reader**: a Flate
  bomb never expands past the XML cap.
- The embedded-file tree walk refuses cycles and caps depth and entries.
- One extraction is **bounded to 10 seconds**. Any parser panic is recovered and
  reported as an invalid PDF.

### Run reports (`internal/orchestrator`)

- Written to `<state dir>/reports/` through fsx: `0600` files, `0700` folder,
  never replacing an earlier report. An existing reports folder with group or
  world bits is refused.
- Reports hold no error text, no file content and no secret.
- Origins, provider ids and paths go through the same pattern masking as logs
  (`logx.Clean`) when the report is rendered, as JSON or text. An accepted
  provider id that looks like a token is therefore masked in the report.
- The text report escapes control, format and bidi characters from untrusted file
  names.

### Document index (`internal/store`)

- The state directory is created `0700` and `index.db` `0600` through fsx before
  SQLite opens it. SQLite side files (`-wal`, `-shm`, `-journal`) get `0600` too.
- An existing directory, database or side file with group or world bits is
  refused and left unchanged. A database path that is a symlink or not a regular
  file is refused.
- A database written by a newer facto (newer schema) is refused.

### Secret providers (`internal/secret`)

**The `Secret` type.**

- `secret.Secret` never renders its value. `String`, `GoString`, `Format` (every
  verb, width and flag), `MarshalJSON`, `MarshalText` (used by XML and other text
  encoders) and `LogValue` all produce `***`.
- The value is only reachable through `Expose`, called at the last call site.
- `Wipe` zeroes the bytes and empties the secret. Copies share storage, so wiping
  one copy clears every copy. `Wipe` is idempotent and safe on the zero value.
- `New` takes ownership of a `[]byte` without copying, so `Wipe` clears it.
  `FromString` copies a string, which itself cannot be wiped.
- A provider returns a fresh `Secret` on every call, never a cached one. When a
  provider returns a value together with an error, the resolver wipes it.

**References.**

- Config holds references, never values. Two forms are accepted, nothing else:
  - `bw://<uuid>/<username|password|totp>`: the item is a UUID (8-4-4-4-12 hex,
    lowered). An item name is refused.
  - `keyring://<service>/<key>`: segments of `[A-Za-z0-9._-]`, not `.` or `..`.
- Whitespace, userinfo, port, query, fragment, percent-encoding and empty
  segments are refused. A parse error never quotes the input.
- **Hand-built refs are re-validated.** The resolver and each provider re-parse
  a `Ref` built in code and refuse it unless it matches its canonical form. A
  hand-built Bitwarden ref cannot carry an item name or another field.

**Bitwarden provider (`internal/secret/bitwarden`).**

- The provider runs the Bitwarden CLI through a `Runner`. Arguments are fixed
  subcommands plus a validated UUID. No secret is ever on argv.
- **Master password.** Asked only in interactive mode. It is passed to
  `unlock --raw --passwordenv FACTO_BW_MASTER_PASSWORD` through that one
  subprocess environment, then wiped. A non-interactive run with a locked vault
  fails with `ErrLocked`.
- **Session key.** Lives in a `Secret`. It reaches the CLI only in the
  `BW_SESSION` variable of each subprocess. A session key injected from the
  user's terminal is reused when the vault reports `unlocked`.
- **Minimal environment.** Only a fixed list of non-secret variables is
  inherited: `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`,
  `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, `BITWARDENCLI_APPDATA_DIR`,
  `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, and on Windows
  `SYSTEMROOT`, `WINDIR`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`.
  facto's own `BW_SESSION`, `BW_PASSWORD` and `NODE_OPTIONS` are never passed on.
- `BW_NOINTERACTION=true` is always set, so the CLI never prompts. Stdin is empty.
- **Output cap.** Stdout and stderr are each capped at 64 KiB. A larger output
  fails the command. Buffers are wiped after use, and when they grow.
- **Lock and wipe.** `Close` runs `lock` and wipes the session key. Any fatal
  error (CLI crash, unreadable or oversized output, another item returned,
  canceled command) does the same, and later calls fail with `ErrLocked`. The
  lock runs with a non-cancelled context (30 s timeout), even when the caller's
  context was canceled. A missing item only returns `ErrSecretNotFound`.
- **Never used:** `serve`, `list`, `--session`, `--passwordfile`. Items are
  fetched by UUID only.
- Error messages never contain CLI output or the runner's error text.

**Keyring provider (`internal/secret/keyring`).**

- Reads `keyring://<service>/<key>` through go-keyring (ADR 0005). Tests use a
  fake backend.
- A missing or empty entry wraps `secret.ErrSecretNotFound`.
- **Backend errors are opaque:** the message is always `keyring: backend error`.
  The original error stays reachable through `errors.Is` and `errors.As`, but its
  text, which may echo the value, is never printed.

### Configuration (`internal/config`)

- **Regular file only.** `config.yaml` is opened through fsx. A symlink,
  directory or FIFO is refused, never followed nor read.
- **Owner-only on Unix.** Any group or world bit is refused (want `0600`).
- **64 KiB cap**, checked before decoding and again while reading.
- **Strict decoding.** Unknown keys, duplicate keys, wrong types and a second
  YAML document are errors (exit code `2`).
- **Bounded error list.** At most 20 type errors are reported for one
  document, followed by `and N more`. A file of thousands of wrongly typed
  items gives a short message, in bounded time.
- **Secret fields hold references.** `login`, `password` and `otp` must be empty
  or a valid reference. A plaintext value is refused with a fixed message.
- **No-echo policy.** Errors name the key and the line, never a scalar value,
  an anchor name or a custom YAML tag. This keeps a password pasted in the wrong
  field out of the terminal, logs and reports. Errors may still print user text
  that is not a value: key names (including unknown keys) and connector ids
  (only once known to be a valid slug).
- **CLI errors are cleaned and escaped.** Every error `facto` prints on stderr
  goes through `logx.Clean` (the pattern masking of the redacting logger), then
  each line through `logx.Escape`: control, C1, bidi and other non-printable
  characters (an inbox file name repeated by an I/O error, argv echoed by a
  usage error) are written as Go escapes, and every line starts with `facto: `
  (SEC-J0-19).
- **Naming templates are never quoted.** An invalid `naming.file` or
  `naming.dir` is reported with the key and a fixed description of the allowed
  grammar and placeholders, never with the template text or the placeholder
  that failed.
- **State dir placement, lexical check** (ADR 0007, D1). `state_dir` must not
  equal or sit inside `output.local`, compared as path text. It must not sit
  inside a synced folder: Google Drive, Dropbox, OneDrive, iCloud Drive,
  Nextcloud, ownCloud, pCloud, Box, and any `Library/CloudStorage/` provider on
  macOS. Detection is by folder name, on whole path components,
  case-insensitive. The home directory's own components are not checked.
  Symlinks are not resolved here; see the CLI check below.
- `~` and `~/…` expand with an injected home directory. `~user` and relative
  paths are refused.

### Process hardening (`internal/proc`)

- On Linux, `proc.Harden` sets `RLIMIT_CORE` soft and hard limits to `0`, so the
  process cannot raise them again: no core dump.
- It then sets `PR_SET_DUMPABLE` to `0`: other processes of the same user cannot
  ptrace-attach or read `/proc/<pid>/mem`.
- Outside Linux (macOS, Windows), `Harden` is a no-op today. It is idempotent.
- The CLI calls it first, on every invocation (`facto collect`, `facto
  version`, even a usage error), before reading the config or any secret. If
  it fails, facto prints the error and exits `1` without doing anything else.

### Command line (`cmd/facto`)

- **Config before side effects.** `collect` loads and validates `config.yaml`
  first. A configuration error exits `2` and creates nothing: no output folder,
  no state dir, no report.
- **State dir outside the output folder, physically.** Once the output folder
  exists and before the state dir is created, `collect` resolves both through
  symlinks. `state_dir` may not exist yet: its nearest existing ancestor is
  resolved and the missing part joined back. The resolved state dir and each of
  its ancestors are compared with the output folder by file identity
  (`os.SameFile`). This also catches bind mounts and case-insensitive file
  systems. A match is a configuration error (exit `2`). A `state_dir` path that
  goes through a dangling symlink is refused (exit `1`). The refusal message
  names the keys, never the paths.
- **Symlinks.** `output.local` may be a symlink to a folder (for example a
  synced Drive folder): it is followed, and every write is then confined below
  its target. `<output.local>/inbox` must be a real folder: a symlink there is
  refused (exit `1`), because it would make `collect` move files from anywhere
  into the output. A missing folder is created `0700` through fsx, never
  through a dangling link.
- **Prompts only on a terminal.** `collect` asks questions only when stdin is
  a character device other than the null device, and never with
  `--non-interactive`. Pipes, files and the `/dev/null` stdin of schedulers
  never prompt. Prompts go to stderr; stdout carries the report only.
- **Bounded, inert prompt input.** One answer is capped at 256 bytes; the rest
  of a longer line is read and dropped in fixed-size chunks. The file name in a
  prompt is Go-quoted, so control characters in it cannot drive the terminal.
- **Signals.** `SIGINT` and `SIGTERM` cancel the run. The connector running is
  reported `interrupted`, the report is still written, and the exit code is
  `1`.
- **No connector, no secret.** An enabled connector is refused (exit `2`): none
  ships in J0, and a silently skipped account would hide a missing invoice.
  `collect` never calls a secret provider. `output.gdrive.enabled: true` only
  logs a warning.
- **Logging.** `collect` logs at warning level to stderr, through the redacting
  `logx` handler.

### Canary tests and scanners

- Tests inject unique canary secrets. `make leakcheck` scans every file, log and
  report the tests produce and must print `0 canary hits`.
- End-to-end scenarios (`make e2e`) run the real binary in a sandboxed home with
  an environment built from scratch and an empty `PATH`. Every
  `{{canary:<kind>}}` value must be absent from stdout, stderr and every file
  under that home except the setup file that held it. Security negatives cover
  a plaintext password in `config.yaml`, a group-readable config and symlinks
  dropped in the inbox.
- `make audit` runs govulncheck, gosec, gitleaks and osv-scanner at pinned
  versions (`make tools`, ADR 0001) and writes `security/scanners.json`.

## Known limitations

- **Windows permission checks are no-ops.** Go reports synthetic POSIX modes on
  Windows, so the `0600`/`0700` checks always pass there. An owner-only ACL check
  is planned for J1.
- **Output folders without hard links are refused.** This includes exFAT and
  possibly a Google Drive for desktop folder. A no-replace fallback is waiting
  for a decision (checkpoint H1).
- **Goroutine panics crash the process.** The orchestrator only recovers panics
  on its own goroutine. A panic in a goroutine a connector starts itself ends the
  whole run. Connectors must not start goroutines that can panic.
- **Residual `logx` parse-error edge.** When a password in a URL holds `@`, then
  `/`, then `#`, in that order, the bytes between that `@` and the `#` can stay
  visible in a logged `net/url` parse error. They cannot be told apart from a
  host and path.
- **Free-text masking is lexical and has gaps.** The `key=value` masking in
  messages and error text is a safety net, not a parser. It misses:
  - unquoted values of several words: `password: correct horse battery` keeps
    `horse battery` (only the first word is masked; a quoted value is masked
    whole);
  - a key and its value split across lines (`password\n: hunter`);
  - XML elements (`<password>hunter</password>`), `=>` or `->` separators,
    positional pairs (`'password', 'hunter'`) and keys made of spaced words
    (`mot de passe: hunter`).
  Structured attributes (`slog.String("password", v)`) do not have these gaps:
  they are masked by key.
- **Free-text masking also over-masks.** Some ordinary text loses a word:
  `Basic plan invoice` becomes `Basic *** invoice`, `invalid token: expected 3
  parts` becomes `invalid token: *** 3 parts`, and `status_code=500` becomes
  `status_code=***` (`code` is a sensitive key fragment). Log detail is traded for
  safety.
- **Token-looking provider ids are only masked in reports.** A provider id passes
  the structural checks when it has no `://`, `?`, `=`, whitespace or control
  characters and is not JWT-shaped. A bare token that a buggy connector uses as
  its id is therefore written as-is to the SQLite index and slugged into the
  filed name; only the report masks it. Conversely, long legitimate ids such as
  `in_1MtHbELkdIwHu7ixl4OzzPMv` usually show as `***` in reports.
- **Header-line masking edge cases.** A `Cookie:` line whose first value is
  quoted (`Cookie: "lang"; sid=…`) only masks that first value, and request
  `Cookie:` lines keep values of pairs named like Set-Cookie attributes
  (`path=…`). Text that already contains a literal `***` right after the header
  name is left as is.
- **Inbox removal window.** Between the final identity check and the removal of a
  filed inbox file, a few syscalls remain. A file renamed over it exactly then
  would be removed instead.
- **Go strings cannot be wiped.** `Wipe` clears the bytes a `Secret` owns, not
  the strings around it: the value returned by the keyring backend, the
  username and password decoded from the Bitwarden item JSON, and every value
  exposed into the subprocess environment (`exec.Cmd.Env`). These copies stay in
  memory until the garbage collector reuses it.
- **Subprocess environment is readable by the same user.** While the CLI runs,
  `BW_SESSION` and, during unlock, the master password variable can be read by
  any process of the same uid through `/proc/<pid>/environ` of the CLI
  subprocess. `PR_SET_DUMPABLE` on facto does not cover its children. This is a
  known gap against the "another program on the same machine" attacker.
- **`Close` locks the user's own session.** When a session key from the user's
  terminal is injected, `Close` still runs `lock`. The user's terminal session
  is locked too and must be unlocked again.
- **YAML merge keys and aliases are accepted.** Strict decoding refuses unknown
  and duplicate keys but not `<<` merge keys, anchors or aliases. A merge key
  can therefore set a key twice without a duplicate-key error.
- **State dir sync detection is name-based.** A synced folder with an unusual
  name, or reached through a symlink, is not detected. Only the "inside the
  output folder" rule follows symlinks.
- **Config permissions are not checked on Windows**, like fsx.
- **Process hardening is Linux-only.** On macOS and Windows, core dumps and
  debugger attach are left to the OS defaults.
- **The secret resolver is not wired into collection.** The `Secret` type and
  the Bitwarden and keyring providers exist and are tested, but `collect` never
  resolves a reference in J0. Their CLI path (interactive unlock, session reuse,
  `Close` on exit) is untested end to end until J1.
- **The output folder itself is not permission-checked.** An existing
  `output.local` is used as it is, since it may be shared with other programs.
  Folders facto creates in it are `0700`, and an existing year, category or
  provider folder with group or world bits is refused.
- **The state-dir identity check is a startup check.** A symlink changed after
  the check and before the index opens is not caught.
