# Security

This page has two parts. The threat model is the target design from
[`docs/spec.md`](spec.md) ("Security and credentials"). The rest describes what
the code enforces **today**, at milestone J1, and names the package that does it.
The latest audit is [`security/audit/2026-10-30-J1.md`](../security/audit/2026-10-30-J1.md).

To report a vulnerability, see [`SECURITY.md`](../SECURITY.md).

## Threat model (summary)

**Protected assets:** supplier credentials, the Bitwarden session key, supplier
cookies and tokens, the Google refresh token.

**Attackers in scope:** another program on the same machine, a leak through a
file or a log, a compromised dependency, a buggy or malicious connector.

**Out of scope:** an attacker who is already root on the machine; supplier
websites themselves.

| Threat | Planned mitigation (spec) | State at J1 |
| --- | --- | --- |
| Cookie theft through the automated browser (CDP port) | CDP over a pipe, else random 127.0.0.1 port, short browser life | Linux and macOS: done. CDP over `--remote-debugging-pipe`, no port is opened ([ADR 0008](adr/0008-browser-cdp-pipe.md), `internal/browser`, real-Chrome test `TestChrome_NoListeningSocket`). **Windows: accepted MEDIUM** (A4, SEC-J1-8): `--remote-debugging-port=0` bound to 127.0.0.1, see [Windows debug port](#windows-debug-port-accepted-medium). The browser runs for login only and is closed before `List` (`internal/orchestrator`) |
| Reading the Chromium profile | Disposable 0700 profile, deleted after login | Done: a fresh 0700 profile per launch under `$XDG_RUNTIME_DIR/facto`, else `<state_dir>/tmp`, removed once the browser has exited. Stale profiles are swept at startup. Chrome's caches and crash database stay in a private per-launch area. Cookies live in an in-memory browser context (`internal/browser`, ADR 0008 "Hardening") |
| Reading persisted sessions | AEAD-encrypted sessions, key in keyring or password manager; `sessions: ephemeral` | Done: XChaCha20-Poly1305, one key per connector in the OS keyring, rotated on every login. Ephemeral mode removes saved sessions without reading them ([ADR 0009](adr/0009-vault-aead.md), `internal/vault`) |
| Exfiltration from the login page | Domain allowlist monitored in the browser | Done: in-browser allowlist on every target (pages, frames, workers, pop-ups), resolver rules and a WebRTC policy (`internal/browser`, ADR 0008 "Hardening") |
| Leak through sync | Refuse a state dir inside the output folder or a synced folder | Done: `internal/config` (ADR 0007, D1, lexical) and `cmd/facto` (output folder and synced folders, symlinks followed, SEC-J0-17); synced-folder detection is name-based, see limitations |
| Leak in logs, reports, errors | `Secret` type, redaction by key and pattern, no HTTP bodies logged | Done: redacting logger, clean reports, `secret.Secret` (`internal/secret`), config errors never echo values. The browser logs counts and classes only, never a CDP payload or Chrome's stderr |
| Leak through the command line | No secret in argv; subprocess-only environment | Done in `internal/secret/bitwarden`; no CLI flag takes a secret. `collect` and `login` build one secret resolver and close it (password manager locked) on success, error and `SIGTERM` (SEC-J0-22, narrowed). Chrome gets an allowlisted environment and no secret on argv |
| Leak through a memory dump | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux | Done in `internal/proc`, called first by the CLI on every run; Linux only. Chrome runs with `--disable-crash-reporter` and `--disable-breakpad` on every OS |
| Leak through a bug report | Redaction, CI canary scan, clean `--report` | Canary scan (`make leakcheck`) and clean report done |
| Exfiltration by a connector | Per-connector domain allowlist in the HTTP client | Done in `internal/httpx` and `internal/orchestrator`; the same matcher decides every browser request |
| Compromised dependency | Minimal deps, scanners, pinned tools, signed releases | Scanners and pinned tools done (`make audit`, ADR 0001). In-house CDP client, no browser library (ADR 0008). Chrome for Testing pinned by URL, size and SHA-256 (trust on first use, see limitations). Releases J4 |
| Hostile input files (inbox, PDFs) | Path sanitizing, parse limits, no XML entities | Done in `internal/fsx`, `internal/inbox`, `internal/normalize/facturx` |

## What the code enforces today

Sections marked J1 were added at milestone J1. The others date from J0 and
still hold.

### Domain allowlist (`internal/httpx`)

`internal/httpx` is the only package that does network I/O. Each client is built
from one allowlist. This is enforced repo-wide (SEC-J0-15), `cmd/` and
`connectors/` included: the depguard `network` rule in `.golangci.yml` and
`internal/httpx/boundary_test.go` both refuse a production import of `net`,
`net/http/...`, `net/rpc`, `net/smtp`, `net/textproto`, `crypto/tls`,
`golang.org/x/net` or gRPC outside `internal/httpx`. The one exception is
`internal/logx/walk.go`, which names `net/http` and `crypto/tls` types for
redaction and does no I/O. Test files are not covered (they run `httptest`
servers).

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
- **Cookie jar (J1).** `Client.SetCookies` stores cookies for an allowlisted host
  only, as host-only cookies of `https://<host>/`, always `Secure`, `HttpOnly`
  and `SameSite=Lax`. Errors never carry a cookie value.
- **Two restricted clients (J1).** `httpx.NewPinned` (exact host and path prefix,
  for the Chrome for Testing download) may be called only from
  `internal/browser/cft`. `internal/httpx/cdploopback` (Windows CDP WebSocket,
  literal `127.0.0.1:<port>` only) may be imported only from `internal/browser`.
  Each rule has a lint rule (forbidigo, depguard), a callers test, and a case in
  `make lint-selftest` that proves the rule is live.

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
- **Browser for login only (J1).** A connector gets the browser pool through a
  wrapper that uses the connector's own `AllowedDomains`. Every browser still
  open is closed before `List`, and any later launch is refused
  (`TestRun_BrowserClosedBeforeList`, `TestRun_BrowserLaunchRefusedAfterLogin`).
- **Sessions (J1).** A saved session is restored before `Login`, and the restored
  blob is wiped afterwards, also on a panic. A session is saved only after a
  successful `Login`, and only when the connector opts in (`Persistable`). A
  restored session that `Login` or `List` rejects (`needs_login` or
  `auth_failed`) is deleted unread, and the state is `needs_login`. Every
  `needs_login` result carries the fixed note naming `facto login <id>`; every
  `auth_failed` result (the credentials were rejected) carries the fixed note
  naming `facto config <id>`.
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
  one at its closing quote. Masks only grow: a masked value that holds a
  sensitive key and its separator (`token: password: v`, `Bearer pwd='v'`,
  `password="a pwd="v"`) is masked together with that key's value, and so on
  down the chain (`token: ***`), so a key-shaped secret (`password=hunter2Token=`)
  stays masked whole (SEC-J0-24, found by `FuzzClean` and review).
- **Authorization schemes:** the credential after a whole word `Bearer` or
  `Basic` is masked (`got Bearer ***`).
- **Header lines:** when an unquoted key holding `cookie` or `authorization`
  (`Set-Cookie`, `Proxy-Authorization`) is followed by `:`, the value runs to the
  end of the line. An authorization line keeps a `Bearer` or `Basic` scheme and
  masks the rest; any other scheme (`Token`, `Digest`, `Negotiate`) or a malformed
  one (`Bearer: x`) is masked whole. A cookie line masks its first value, then
  every later cookie value and bare token, keeping only the Set-Cookie
  attributes (`Path`, `Domain`, `Expires`, `Max-Age`, `SameSite`, `Priority`,
  `Secure`, `HttpOnly`, `Partitioned`), whose values are still scanned for
  sensitive keys (`Path=/ password=v`); a pair whose name is not a cookie name
  (letters, digits, `_`, `-`, `.`) is masked whole, and so is the rest of a
  segment after a value that ran past its `;`. In fmt's one-line rendering of an
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

`internal/fsx` is the only package that writes files. forbidigo in
`.golangci.yml` refuses `os.WriteFile`, `os.Create`, `os.OpenFile`,
`os.MkdirAll` everywhere else, and (SEC-J0-16) every other `os` mutation:
`Mkdir`, `MkdirTemp`, `CreateTemp`, `Rename`, `Remove`, `RemoveAll`, `Symlink`,
`Link`, `Chmod`, `Chown`, `Lchown`, `Chtimes`, `Truncate`. `cmd/` is exempt
only from the `fmt.Print` rule. Test files may use the mutations of the
second list to build hostile fixtures (symlinks, unreadable files).

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
- **J1 additions:** `MkdirTempPrivate` (unique 0700 directory in a private
  parent), `RemoveTree` (never follows a symlink, never leaves its parent),
  `WriteAtomicExec` (0700 executables), `MkdirNew` (exclusive create), `Rename`,
  and `Lock`/`TryLock` (`flock`, `LockFileEx`; the lock file is created
  `O_CREATE|O_EXCL`). All of them go through `os.Root`.

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
- The `otp` reference always resolves to a code, never to a TOTP seed (A5).
- e2e builds also accept `e2e://<item>/<field>` (files written by the test
  harness, `internal/secret/e2efile`). A release build refuses that scheme;
  `make release-e2e-check` proves the package is not in it.

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
- `Get`, `Set` and `Delete` are bounded by the caller's context and a default
  timeout (`ErrTimeout` wraps `context.DeadlineExceeded`, SEC-J0-23). `Delete`
  is idempotent and never reads the entry. The resolver's `CloseAll` is never
  blocked by a hung provider.
- A missing or empty entry wraps `secret.ErrSecretNotFound`.
- **Backend errors are opaque:** the message is always `keyring: backend error`.
  The original error stays reachable through `errors.Is` and `errors.As`, but its
  text, which may echo the value, is never printed.

### Automated browser (J1, `internal/browser`)

Design and evidence: [ADR 0008](adr/0008-browser-cdp-pipe.md). facto has its own
CDP client and no browser library. The browser holds cookies in clear while it
runs, so it runs for login only.

**Transport.**

- **Linux and macOS: pipe only.** Chrome gets `--remote-debugging-pipe` and talks
  CDP on file descriptors 3 and 4, NUL-framed JSON. No debugging-port flag is
  ever passed (`TestFlags_NoDebugPortOutsideWindows`). The real-Chrome test
  `TestChrome_NoListeningSocket` checks the whole Chrome process tree, TCP4 and
  TCP6, per-process network namespaces included, and prints
  `no listening CDP port`.
- **Windows: loopback debug port**, an accepted MEDIUM risk. See
  [Windows debug port](#windows-debug-port-accepted-medium).
- **Bounded messages.** One message is at most 16 MiB, enforced while reading. A
  larger or malformed frame kills the browser. One writer at a time. Responses
  with an unknown id or session are dropped.
- **No payload in logs.** No CDP message, request or response body is logged.
  Errors carry the CDP error code only. Chrome's stderr is capped, counted and
  classified, never logged verbatim.

**Process.**

- Chrome runs in its own process group. facto kills the whole group on close,
  cancel, error or overflow. On Linux, `Pdeathsig` is a backstop if facto dies.
- facto refuses to launch Chrome as root.
- When Chrome reports "No usable sandbox" (AppArmor on Ubuntu 23.10+), the launch
  fails closed with a typed error naming the fix outside facto. facto never
  retries with weaker flags.
- **Executable checks**, before every launch. The path must be absolute. It is
  resolved through every symlink (a dangling one is refused), and the target must
  be a regular file. On unix the target must also be executable by its owner,
  without setuid or setgid, not group- or world-writable, in a parent folder that
  is not group- or world-writable; higher ancestors may be writable only with
  the sticky bit (`/tmp`). The binary and its parent must be owned by the current
  user or root. On Windows only the absolute path and regular-file checks apply
  (SEC-J0-18).
- **Environment.** Chrome gets an allowlisted environment. Proxy variables are
  never passed. `--no-proxy-server` is set unless `FACTO_ALLOW_PROXY=1`.

**Flags.**

- **Never passed** (deny-list checked at launch): `--no-sandbox`,
  `--disable-setuid-sandbox`, `--disable-namespace-sandbox`,
  `--disable-seccomp-filter-sandbox`, `--disable-gpu-sandbox`, `--no-zygote`,
  `--single-process`, `--disable-web-security`, `--ignore-certificate-errors`,
  `--allow-running-insecure-content`, `--remote-allow-origins`,
  `--remote-debugging-address`, `--load-extension`, `--enable-logging`, `--v=`.
- **Mandatory** (the launch is refused without them): `--user-data-dir`,
  `--host-resolver-rules`, the WebRTC policy, `--dns-prefetch-disable`, and the
  pipe (or, on Windows, the port-0 flag). `--use-mock-keychain` is mandatory on
  macOS.
- No extensions, sync, crash reporter, breakpad, component update or background
  networking.
- e2e-only flags (loopback mapping, test CA) are refused by the release
  `CheckFlags`. `make release-e2e-check` proves the code that builds them is not
  in the release binary.

**Profile (A12).**

- **Location.** The base folder is `$XDG_RUNTIME_DIR/facto` when
  `XDG_RUNTIME_DIR` is set and absolute, else `<state_dir>/tmp`. The base must be
  a real folder, `0700`, owned by the current user. On unix, `XDG_RUNTIME_DIR`
  itself must be a real `0700` folder owned by the current user. Otherwise the
  pool refuses to start (`ErrUnsafeProfileDir`), with no fallback. A base inside
  a personal browser profile under `HOME` is refused.
- **One profile per launch:** a fresh `profile-<pid>-<random>` folder, `0700`,
  never reused. It is removed after Chrome's process group is reaped, on every
  path: close, context cancel, browser crash, caller panic and failed launch.
  The real-Chrome test `TestChrome_ProfileRemoved` prints `profile removed`.
- **Startup sweep.** `collect` and `login` build the pool first. That sweeps both
  bases (those that exist): a `profile-<pid>-<random>` entry whose pid is dead is
  removed without following symlinks. Live pids and other names are kept.
- **Private launch area (Linux).** Each launch also gets a `0700` folder
  `t<pid>.<n>` next to its profile. Chrome's `XDG_CONFIG_HOME`,
  `XDG_CACHE_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` point into it, so Chrome
  writes nothing under `~/.config`, `~/.cache` or `~/.local`
  (`TestChrome_NothingWrittenUnderHome`, SEC-J1-7). `TMPDIR` is the area itself
  when Chrome's `SingletonSocket` path fits the 107-byte unix socket limit;
  otherwise the inherited `TMPDIR` is kept. A path over the limit fails the
  launch before Chrome starts (`ErrSocketPathTooLong`). The area is removed with
  the profile and swept like a stale profile.
- **Cookies stay in memory.** The login runs in a fresh browser context, so
  cookies are not written to the profile
  (`TestChrome_NoCookieStoreWrittenAfterLogin`). Downloads and site permissions
  are denied.

**In-browser allowlist (A11).** The connector's `AllowedDomains` apply inside the
browser too.

- The page target is created at `about:blank`. `Fetch` is enabled before the
  first navigation.
- Every new target (cross-site frame, dedicated, nested or shared worker, service
  worker, pop-up) is attached paused. It gets `Fetch.enable` and auto-attach
  before it is resumed. A target that refuses is closed without being resumed.
  Dedicated workers are the one exception: see the limitations.
- A paused request continues only when it is `https`, port 443, and its host is
  allowed by `httpx.Allowlist` (the same matcher as httpx). An IP literal,
  userinfo, another scheme or an unparsable URL is refused. Anything else fails
  with `BlockedByClient`. Blocked hosts are counted, never with their query.
- **Second layer, release builds too:**
  `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE <allowlist>"` (only
  allowlisted names resolve), `--dns-prefetch-disable`, and
  `--webrtc-ip-handling-policy=disable_non_proxied_udp` (the legacy
  `--force-webrtc-ip-handling-policy` is kept too).
- **WebRTC (SEC-J1-1, fixed).** ICE traffic goes straight to an IP the page
  names, past `Fetch` and the resolver rules. The pinned Chrome ignores the
  legacy switch, so the policy now goes through `--webrtc-ip-handling-policy`.
  With `--no-proxy-server`, ICE then gathers no UDP candidate and contacts no
  STUN or TURN server. As a second layer, a constant script on the login page
  target deletes `RTCPeerConnection`, `webkitRTCPeerConnection`,
  `RTCDataChannel` and `RTCIceTransport` from every document of that target
  before page scripts run. Cross-site frames and pop-up realms rely on the
  switch alone (`TestAttack_ChromeWebRTCToIPLiteral`,
  `TestChrome_WebRTCBlockedInCrossSiteFrame`).
- `Navigate` accepts `https` URLs on an allowlisted host and port 443 only. An
  empty port is refused (SEC-J1-5).
- The e2e fake site: `make e2e` runs a hostile login page that tries `img`,
  `fetch`, WebSocket and workers towards `evil.test`. Zero requests reach it
  (`TestE2E/fakeprovider-browser-allowlist`).

**Secret typing.**

- Before typing, facto checks that the focused element is the expected input in
  the main frame, that the page origin is `https` and allowlisted, and that the
  document (loader id and URL) is unchanged before and after.
- Page scripts are frozen (`Emulation.setScriptExecutionDisabled`) on the page and
  every out-of-process frame, from just before the check to just after the
  post-typing check. A session that cannot be frozen refuses the typing. This
  closes a focus swap to a cross-origin frame (SEC-J1-2).
- The value is sent in one `Input.insertText`. Page functions run in an isolated
  world, never with a secret in the script.
- `Cookies(domains)` returns allowlisted cookies only, as `secret.Secret`.

### Windows debug port (accepted MEDIUM)

`os/exec` has no `ExtraFiles` on Windows, so the Windows build does not use the
pipe in J1 (decision A4, ADR 0008 "Windows (A4)", SEC-J1-8).

- **The risk.** While the login runs, any local process, including one of
  another local user, that finds the port gets **full CDP control**: it can read
  the password or one-time code typed into the page, run `Runtime.evaluate`, read
  the cookies and navigate. `/json/version` on the port also reveals the browser
  GUID path.
- **Why it is accepted as MEDIUM:** the port is loopback only and short-lived.
  The fix (the pipe through `SysProcAttr.AdditionalInheritedHandles`) is tracked
  in [issue #3](https://github.com/FlorianRuen/facto/issues/3).
- **Mitigations in code:**
  - `--remote-debugging-port=0` only, so Chrome picks a random port
    (`TestFlags_WindowsPortIsZeroOnly`);
  - fresh profile, checked empty before launch;
  - `DevToolsActivePort` read once, after start, at most 256 bytes, strict parse
    (port, then `/devtools/browser/<GUID>`);
  - exactly one listener on that port, bound to `127.0.0.1` and owned by
    Chrome's pid (`GetExtendedTcpTable`, IPv4 and IPv6);
  - the WebSocket is dialled only through `internal/httpx/cdploopback`, to the
    literal `127.0.0.1:<port>`: no resolver, no proxy, no redirect
    (`TestPortTransport_DialsLoopbackOnly`);
  - a `Browser.getVersion` handshake before any secret;
  - the browser is closed right after login
    (`TestPortTransport_ClosedRightAfterLogin`).
- **Release gate (issue #3).** The browser must run in a Job object
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), so that every Chrome child dies with
  it. J1 kills the browser process only. ADR 0008 says Windows is not released
  until the Job object lands: `.goreleaser.yaml` builds linux and darwin only, and
  `make release-e2e-check` fails if a windows target comes back (SEC-J1-11, fixed).
- **Not run on real Windows yet.** `TestChromeWindows_DebugPortLoopbackOnly`
  (`make e2e-browser-windows`) waits for its CI job (T32, BLOCKED(H1)).

### Chrome for Testing install (J1, `internal/browser/cft`)

- **Explicit only.** `facto browser install` is the only way facto downloads a
  browser. No other command downloads one (decision A10).
- **Pinned.** Chrome for Testing `156.0.8078.80`, linux64 only: exact URL, size
  (201329937 bytes) and SHA-256 in `internal/browser/cft/pinned.go`.
- **Download** through `httpx.NewPinned`: `https`, the exact host
  `storage.googleapis.com` byte for byte, port 443, a canonical path under
  `/chrome-for-testing-public/`, checked on the first request and on every
  redirect hop before dialing.
- **Verified before unpacking.** The size, then the SHA-256 of the stored file,
  must match. On a mismatch nothing is extracted.
- **Safe unzip.** No path escape, symlink, device or duplicate entry. Size and
  entry-count caps. Folders and executables `0700`, other files `0600`, setuid
  bit stripped. `chrome` must be executable by its owner.
- **Layout.** `<state_dir>/chrome/<version>/`, with `.facto-verified` written
  last. A verified install is reused without network I/O. Leftovers of an
  interrupted install are removed first, symlinks unlinked, never followed.
- **At run time** facto uses the installed copy only when the verification
  marker matches, and follows no symlink below the state dir. It warns once per
  run when the pinned build is old.
- **`browser.path`** (any OS) names a user-supplied Chrome. It is unpinned: facto
  checks only that it is an existing regular file, then applies the executable
  and launch rules above.

### Session vault (J1, `internal/vault`)

Design: [ADR 0009](adr/0009-vault-aead.md).

- **File.** `<state_dir>/sessions/<connector-id>.sess`, `0600` in a `0700` folder,
  written atomically through fsx. Symlinks, FIFOs and swapped files are refused.
- **Cipher.** XChaCha20-Poly1305 with a fresh random 24-byte nonce per seal. The
  AAD binds magic, version, install id (`<state_dir>/install-id`) and connector
  id, so a file copied to another connector or another state dir does not open.
  Files are capped at 1 MiB. Any format or authentication failure is the opaque
  `ErrInvalid`, and no partial plaintext is returned.
- **Key.** One random 256-bit key per connector in the OS keyring (service
  `facto-session`, user `<install-id>/<connector-id>`). It never touches disk, a
  log, argv or the environment.
- **Rotation (A2).** Every successful login writes a new key, then the new file,
  under a per-connector lock (`sessions/<id>.lock`). A failed keyring write keeps
  the old pair. The worst outcome of a failure or crash is a new login.
- **No keyring** (persistent mode): the run uses ephemeral sessions and logs one
  warning. Nothing is written or deleted. There is no file key and no derived
  key. A non-interactive run bounds the keyring probe to 2 s, so a locked
  keyring's unlock dialog never hangs a scheduled run.
- **`sessions: ephemeral` (A13).** At startup every `*.sess` file is removed
  without being opened, and its keyring key is deleted without being read. One
  line is logged. Nothing is written during the run.
- **Rejected sessions.** A restored session the supplier rejects is deleted
  (file and key), unread.
- **e2e builds** keep keys in a file store, `<state_dir>/e2e-keys`, and never
  touch the OS keyring or the user's session bus (SEC-J1-6). The release build
  has no file key source: `make release-e2e-check` proves it.

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
- **`browser.path` (J1).** Absolute or `~/…`, no control or format characters,
  never quoted in an error. When a browser is needed, `cmd/facto` checks that it
  names an existing regular file.

### Process hardening (`internal/proc`)

- On Linux, `proc.Harden` sets `RLIMIT_CORE` soft and hard limits to `0`, so the
  process cannot raise them again: no core dump.
- It then sets `PR_SET_DUMPABLE` to `0`: other processes of the same user cannot
  ptrace-attach or read `/proc/<pid>/mem`.
- Outside Linux (macOS, Windows), `Harden` is a no-op today. It is idempotent.
- The CLI calls it first, on every invocation (every command, even a usage
  error), before reading the config or any secret. If it fails, facto prints the
  error and exits `1` without doing anything else.

### Command line (`cmd/facto`)

- **Config before side effects.** `collect` and `login` load and validate
  `config.yaml` first. A configuration error exits `2` and creates nothing: no
  output folder, no state dir, no report.
- **State dir outside the output folder, physically.** Once the output folder
  exists and before the state dir is created, `collect` resolves both through
  symlinks. `state_dir` may not exist yet: its nearest existing ancestor is
  resolved and the missing part joined back. The resolved state dir and each of
  its ancestors are compared with the output folder by file identity
  (`os.SameFile`). This also catches bind mounts and case-insensitive file
  systems. A match is a configuration error (exit `2`). A `state_dir` path that
  goes through a dangling symlink is refused (exit `1`). The refusal message
  names the keys, never the paths. `login` runs the same checks before it
  creates the state dir, and the synced-folder check even when `output.local`
  does not exist yet.
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
- **No-echo code prompts (J1).** One-time codes asked during a login are read
  with terminal echo off (termios, `SetConsoleMode`). Echo is restored on
  cancel and `SIGHUP`. The answer is capped at 256 bytes and wiped after use. A
  prompt label from a supplier site is shown cleaned (`PromptRequest.CleanLabel`:
  escape sequences and control characters removed, tokens masked, 128 bytes
  max). An e2e build reads prompt answers from stdin only with
  `FACTO_E2E_INTERACTIVE=1` (A8).
- **`facto login` (J1)** needs an interactive terminal. Otherwise it exits `2`
  before anything is built. An invalid connector id is never echoed.
- **Signals.** `SIGINT` and `SIGTERM` cancel the run. The connector running is
  reported `interrupted`, the report is still written, and the exit code is
  `1`.
- **No connector in a release build.** A release build ships no supplier
  connector, so an enabled connector is refused (exit `2`, "connector not
  available in this version"). `fakeprovider` is registered in e2e builds only.
  `collect` and `login` build one secret resolver (Bitwarden and keyring) after
  the configuration checks and close it on every path.
  `output.gdrive.enabled: true` only logs a warning.
- **Logging.** `collect` and `login` log at warning level to stderr, through the
  redacting `logx` handler.

### Canary tests and scanners

- Tests inject unique canary secrets. `make leakcheck` scans every file, log and
  report the tests produce and must print `0 canary hits`.
- End-to-end scenarios (`make e2e`) run the real binary in a sandboxed home with
  an environment built from scratch and an empty `PATH`. Every
  `{{canary:<kind>}}` value must be absent from stdout, stderr and every file
  under that home except the setup file that held it. Security negatives cover
  a plaintext password in `config.yaml`, a group-readable config and symlinks
  dropped in the inbox.
- **J1 scenarios** drive `fakeprovider` against a fake TLS site on 127.0.0.1
  with the pinned Chrome: password, TOTP, email OTP, SSO redirect, expired
  session, rate limit, site changed, captcha, bad password, ephemeral sessions,
  browser allowlist and browser isolation. Each checks that no CDP port is open,
  the profile is removed, nothing is written under `HOME`, and `evil.test` is
  never contacted. The sandbox's session bus points inside the sandbox, so a run
  never reaches the user's keyring (SEC-J1-6).
- `make release-e2e-check` (in `make verify`) proves that the release build, with
  the exact `.goreleaser.yaml` flags, has no e2e-only package, file or symbol. It
  prints `release-check: release build has no e2e-only code`.
- `make lint-selftest` (in `make verify`) proves the depguard ban on
  `golang.org/x/crypto/openpgp` and the `cdploopback` and `NewPinned` caller
  rules are live.
- `make audit` runs govulncheck, gosec, gitleaks and osv-scanner at pinned
  versions (`make tools`, ADR 0001) and writes `security/scanners.json`.

## Known limitations

- **Windows permission checks are no-ops.** Go reports synthetic POSIX modes on
  Windows, so the `0600`/`0700` checks always pass there. An owner-only ACL check
  is deferred to J2 (SEC-J0-18).
- **Windows browser login is an accepted MEDIUM risk.** See
  [Windows debug port](#windows-debug-port-accepted-medium). The Job object that
  ADR 0008 makes a release gate is not implemented, so no Windows build is
  released until it is. Nothing has run on real Windows yet (T32).
- **WebRTC through a user proxy.** With `FACTO_ALLOW_PROXY=1`,
  `--no-proxy-server` is dropped. `disable_non_proxied_udp` still allows ICE over
  TCP through that proxy, and cross-site frames and pop-ups have no script
  layer. A hostile frame could then reach a TURN server it chooses. No test
  covers this mode (SEC-J1-14).
- **The visible relaunch is not covered by the `HOME` tree test.**
  `TestChrome_NothingWrittenUnderHome` runs headless. The visible window of an
  interactive `facto login` (GTK, display server, maybe the desktop's dconf) uses
  the same private area, but only unit tests check it.
- **Dedicated workers rely on the parent's `Fetch`.** Chrome 156 has no `Fetch`
  on worker sessions. A dedicated worker attached under a watched page, frame or
  worker is resumed anyway, and its requests are blocked by the parent's
  interception. A Chrome release that stops doing this would open a gap; the
  real-Chrome tests in `make e2e` catch it on every pin bump.
- **The httpx cookie jar is host-only.** Cookies are stored for the exact host,
  path `/`, without expiry. A supplier whose session cookie is set on a parent
  domain or a narrower path is not supported yet (J2). `fakeprovider` drops
  parent-domain cookies on purpose.
- **The Chrome for Testing pin is trust on first use.** Chrome for Testing
  publishes no checksum. Both downloads that computed the pinned SHA-256 came
  from the same machine. An independent recomputation (CI or a second person) is
  pending (SEC-J1-12, BLOCKED(H1)).
- **A user-supplied browser is unpinned.** On macOS and Windows, and whenever
  `browser.path` is set, facto drives a Chrome it did not verify.
- **macOS parent death.** If facto dies on macOS, Chrome exiting on pipe EOF is
  unverified (no `Pdeathsig` there).
- **Same-user access.** Any process of the same user can read the keyring entry
  and the `.sess` file, and can open Chrome's `/proc/<pid>/fd/3` while it runs.
  The vault protects against file leaks, backups and synced folders, not against
  malware running as the user (ADR 0009 "Residual risk").
- **No keyring, no saved session.** Headless Linux without a Secret Service gets
  ephemeral sessions until the `systemd-creds` key source (J2).
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
  the strings around it: the value returned by the keyring backend (session keys
  included), the username and password decoded from the Bitwarden item JSON,
  cookie values held by the httpx jar, and every value exposed into the
  subprocess environment (`exec.Cmd.Env`). These copies stay in memory until the
  garbage collector reuses it.
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
  name is not detected. A known one reached through a symlink is: before the
  state dir is created, `cmd/facto` runs the same name test on the path with
  its symlinks (and those of the home directory) resolved (SEC-J0-17).
- **Config permissions are not checked on Windows**, like fsx.
- **Process hardening is Linux-only.** On macOS and Windows, core dumps and
  debugger attach are left to the OS defaults.
- **No end-to-end proof of the Bitwarden lock.** The resolver is wired into
  `collect` and `login`, and unit tests prove it is closed on success, error and
  `SIGTERM`. No e2e scenario runs the `bw` CLI against the Vaultwarden container
  yet (SEC-J0-22, BLOCKED(H1)).
- **The output folder itself is not permission-checked.** An existing
  `output.local` is used as it is, since it may be shared with other programs.
  Folders facto creates in it are `0700`, and an existing year, category or
  provider folder with group or world bits is refused.
- **The state-dir identity check is a startup check.** A symlink changed after
  the check and before the index opens is not caught.
