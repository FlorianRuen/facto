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
| Leak through sync | Refuse a state dir inside the output folder or a synced folder | Decided (ADR 0007, D1); check pending with config loading |
| Leak in logs, reports, errors | `Secret` type, redaction by key and pattern, no HTTP bodies logged | Redacting logger and clean reports done; `Secret` type pending |
| Leak through the command line | No secret in argv; subprocess-only environment | Pending (`internal/secrets`, CLI) |
| Leak through a memory dump | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux | Pending (`internal/proc`) |
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
- Exit codes (`orchestrator.ExitCode`): `0` all ok or no connector, `1` any
  connector not ok or a failed or canceled run, `2` configuration error.

### Redacting logger (`internal/logx`)

Every facto logger goes through `logx.Handler`.

- **By key**, case-insensitive, at any group depth: `cookie`, `authorization`,
  `token`, `password`, `secret`, `session`, `auth`, `otp`, `csrf`, `sid`, `mdp`,
  `code`, `pin`, `key` and more. Short fragments match whole words only (`auth`
  masks `X-Auth`, not `author`). A sensitive group name masks everything inside.
- **Nested values:** maps (any key type), structs, slices and byte values are
  walked; sensitive keys and fields inside them are masked.
- **By pattern**, in messages and strings: JWTs, long base64 strings, and the
  userinfo, query and fragment of URLs of **any scheme**.
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
- The text report escapes control, format and bidi characters from untrusted file
  names.

### Document index (`internal/store`)

- The state directory is created `0700` and `index.db` `0600` through fsx before
  SQLite opens it. SQLite side files (`-wal`, `-shm`, `-journal`) get `0600` too.
- An existing directory, database or side file with group or world bits is
  refused and left unchanged. A database path that is a symlink or not a regular
  file is refused.
- A database written by a newer facto (newer schema) is refused.

### Canary tests and scanners

- Tests inject unique canary secrets. `make leakcheck` scans every file, log and
  report the tests produce and must print `0 canary hits`.
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
- **Inbox removal window.** Between the final identity check and the removal of a
  filed inbox file, a few syscalls remain. A file renamed over it exactly then
  would be removed instead.
- **Not enforced yet** (pending J0 tasks): the `Secret` type and secret
  references, config validation (state dir outside output and synced folders,
  config file permissions), and core-dump hardening.
