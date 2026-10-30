# 0008. Browser library: in-house CDP client over a pipe

- Status: Accepted
- Date: 2026-10-29
- Deciders: Florian (A4, Q1); planner proposal adopted (A10)

## Context
The browser is used for login only (spec, Architecture: hybrid browser + HTTP) and holds
supplier cookies in clear while it runs. Any process that reaches a Chrome DevTools
Protocol (CDP) port can read them (spec, Security, Automated browser). The spec makes
`--remote-debugging-pipe` support a selection criterion: with it Chrome opens no port and
reads CDP messages from file descriptor 3 and writes them to file descriptor 4, each JSON
message ended by one NUL byte.

Constraints from CLAUDE.md: network only through `internal/httpx` (rule 5), files only
through `internal/fsx` (rule 5), secrets only as `secret.Secret`, logs only through the
redacting handler, no new dependency without an ADR (rule 6). The J1 plan fixes the
interface facto needs (T5: `Navigate`, `WaitVisible`, `TypeSecret`, `Click`,
`CurrentURL`, `Cookies(domains)`, `Close`), the browser-side allowlist (T9, A11: block
off-allowlist requests through `Fetch`), the transport tests (T7: framing, oversized
message refused, peer exit, cancel, no payload in errors) and the Windows exception (A4).

Decision criterion, in this order: pipe transport, maintenance, license, dependency count.

Candidates checked: `github.com/go-rod/rod`, `github.com/chromedp/chromedp` (with
`github.com/chromedp/cdproto`), and an in-house client with no dependency. Version facts
come from `go list -m -json <module>@<version>` (proxy timestamps), licenses and code
facts from the module cache (`$GOMODCACHE`, versions named below), module lists
from `go list -deps` in a throwaway module (CGO_ENABLED=0, GOOS linux, darwin, windows).

### rod v0.116.2 (2024-07-12)
- **Pipe: not supported out of the box.** No `remote-debugging-pipe` flag and no
  `ExtraFiles` anywhere in the module; the only hit is a generated comment
  (`lib/proto/extensions.go:10`). The transport is injectable: `cdp.WebSocketable`
  (`Send([]byte)`, `Read() ([]byte, error)`, `lib/cdp/client.go:38`) passed to
  `cdp.Client.Start` (`lib/cdp/client.go:73`) and `Browser.Client` (`browser.go:128`),
  so a pipe adapter would be ours to write.
- **Downloads a browser by itself.** `lib/launcher` races downloads from Google, npm and
  Playwright hosts (`lib/launcher/browser.go:105`, `Download` at `:130`, via
  `github.com/ysmood/fetchup`), and `Browser.Connect` launches (and downloads) when no
  client is set (`browser.go:153`). The root package `github.com/go-rod/rod` imports
  `lib/launcher`, so depguard cannot deny the launcher without denying rod itself.
- **Writes an executable outside fsx.** `github.com/ysmood/leakless` (imported by the
  launcher) extracts an embedded helper binary to `os.TempDir()` and makes it 0755
  (`leakless.go:105`, `:127`).
- **Reads `os.Args` at init.** `lib/defaults/defaults.go:134` (`init`) and `:147`
  (`ResetWith`) parse a `-rod`/`--rod=` flag from `os.Args` unless `DISABLE_ROD_FLAG` is
  set: `cdp` turns on a logger that prints every CDP message with the `log` package
  (`:128`, which would include typed credentials and cookies), `monitor` makes the
  browser serve a monitor HTTP page (`:95`, `dev_helpers.go:49`), `bin` picks the
  browser binary (`:113`).
- Its WebSocket (`lib/cdp/websocket.go:44`) dials `u.Host` with `net` directly.
- Modules added (all OSes): `github.com/ysmood/fetchup` v0.2.3, `goob` v0.4.0,
  `got` v0.40.0, `gson` v0.7.3, `leakless` v0.9.0.

### chromedp v0.21.0 (2026-10-11) + cdproto v0.157.8 (2026-10-05)
- **Pipe: supported out of the box, and the default** since v0.17.0 (2026-10-03; v0.16.0
  has no `pipe.go`). `ExecAllocator` adds `--remote-debugging-pipe` (`allocate.go:250-251`)
  unless a dialer, `KeepOpen` or a port/address flag is set (`usesPipe`,
  `allocate.go:507`). Unix: `cmd.ExtraFiles = {childR, childW}` (`pipe_unix.go:15`).
  Windows: `SysProcAttr.AdditionalInheritedHandles` plus
  `--remote-debugging-io-pipes=<r>,<w>`, parent ends made non-inheritable
  (`pipe_windows.go:27`, `:36-37`). Injectable transport: `Transport` interface
  (`browser.go:42`) and `NewBrowserTransport` (`browser.go:139`), `NewPipeConn`
  (`pipe.go:48`).
- No browser download in the build: the only `http.Get` calls are in
  `//go:build ignore` generators (`device/gen.go`, `kb/gen.go`). The core package imports
  neither `net` nor `net/http`; the WebSocket lives in the package
  `github.com/chromedp/chromedp/remote` (own RFC 6455 client,
  `remote/internal/websocket/handshake.go:273` dials with `net.Dialer`), which imports
  `net`, `net/http`, `crypto/tls`.
- Gaps against T7: `PipeConn.Read` reads up to the NUL with `bufio.Reader.ReadBytes(0)`
  and no size cap (`pipe.go:75`); `ExecAllocator` adds `--no-sandbox` when running as
  root (`allocate.go:242-246`), against `TestFlags_NeverSandboxWeakening`. Both are avoidable
  by launching ourselves and passing our own `Transport`, at which point chromedp only
  supplies the action layer.
- Modules added besides chromedp: `github.com/chromedp/cdproto` v0.157.8 only. That is the
  version chromedp v0.21.0 requires (latest cdproto: v0.158.6). `cdproto` requires
  `github.com/go-json-experiment/json`, but its `cdp/jsonv2` shim uses the standard
  library on Go 1.27 (`json_std.go:3`, build tag
  `(go1.27 || goexperiment.jsonv2) && !cdproto_jsoncompat`), so that module is not
  compiled into facto (go 1.27.3). Size: 9 146 lines in the core
  package, 1 749 in `remote`, about 27 700 in `cdproto` (non-test `.go`).

### In-house client
- Pipe on Linux and macOS: Chrome on fds 3/4 through `os/exec` `ExtraFiles`, NUL-framed
  JSON, our own size cap, `Pdeathsig` on Linux, a re-executed test binary as fake
  browser (T7). Zero modules added; `encoding/json` only.
- CDP surface facto needs (estimate, unverified against a real login): `Browser.getVersion`
  (handshake), `Target.createTarget`, `Target.attachToTarget` (flat sessions),
  `Target.setAutoAttach` (SSO pop-ups), `Page.enable`, `Page.navigate`, events
  `Page.loadEventFired`/`Page.lifecycleEvent`, `Runtime.evaluate` and
  `Runtime.callFunctionOn` (visibility polling, focus, current URL; never with a secret
  in the script), `Input.insertText` (secret typing), `Input.dispatchMouseEvent` (click),
  `Storage.getCookies` or `Network.getCookies`, `Fetch.enable`, event
  `Fetch.requestPaused`, `Fetch.failRequest`, `Fetch.continueRequest`, `Browser.close`:
  about 17 methods and 3 events.
- Size estimate (unverified): framing, client, sessions and events ~400 lines; page
  operations ~350; Fetch allowlist ~150; Windows loopback WebSocket client ~350; process
  launch and flags are written in T6/T7 whatever the choice. About 1 100 to 1 500
  non-test lines.

## Decision
**In-house CDP client over a pipe, no dependency**, in `internal/browser` behind the
library-neutral `connector.Browser` interface (T5).

- Linux and macOS: pipe only. `--remote-debugging-pipe`, Chrome's fds 3/4 from
  `ExtraFiles`, NUL-delimited JSON, the browser process started by facto with the flags
  fixed in T6. No debugging port flag is ever passed
  (`TestFlags_NoDebugPortOutsideWindows`).
- Message cap: 16 MiB per message, pipe and WebSocket alike. Overflow kills the browser.
  One mutex-guarded writer on the pipe, so concurrent sends never interleave. Responses
  with an unknown id or session id are dropped.
- Teardown: Chrome runs in its own process group (`Setpgid`); facto kills the whole group.
  `Pdeathsig` is Linux-only and per thread, so it is a backstop, not the mechanism. On
  macOS, Chrome exiting on pipe EOF is unverified: a parent-death gap is recorded.
- Windows: see "Windows (A4)" below.
- No CDP message, request or response body is logged; transport errors never echo a
  payload (T7 canary test).

Rationale against the criterion:
1. Pipe: chromedp and the in-house client both provide it; rod does not.
2. Maintenance: rod has had no release for 27 months and its root package pulls a browser
   downloader, an executable extractor and an `os.Args` parser that can log every CDP
   message: out. chromedp is active but its pipe code is 26 days old, the API was
   reworked across 7 tags in 8 days (v0.17.0 to v0.21.0), `cdproto` tagged 19 versions in
   October 2026, and `CONTRIBUTING.md` points to a single maintainer (inferred from
   "Ask the maintainer"). facto needs ~17 methods, against a browser version it pins
   through Chrome for Testing: owning ~1 300 lines costs less than reviewing that churn
   under rule 6 (an ADR update per bump of a 27 700-line generated module). Even with
   chromedp, T7 would replace its `PipeConn` (no size cap) and its process launch
   (`--no-sandbox` as root), leaving only the action layer to reuse.
3. License: no third-party license for the in-house client; chromedp and cdproto are MIT.
4. Dependency count: 0 modules, versus 2 (chromedp, cdproto) and 6 (rod and 5 modules).

chromedp v0.21.0 is the recorded fallback if the in-house client proves too costly (see
Consequences). If it is ever adopted, the package `github.com/chromedp/chromedp/remote`
must be denied by depguard (it does network I/O outside `internal/httpx`) and facto keeps
its own launcher and `Transport`.

## Windows (A4)
`os/exec` does not support `ExtraFiles` on Windows, so in J1 the Windows build does not use
the pipe (the io-pipes route below bypasses this):
- Chrome is started with `--remote-debugging-port=0` (`TestFlags_WindowsPortIsZeroOnly`)
  and the disposable profile of A12 as `--user-data-dir`.
- The port is read from `<profile>/DevToolsActivePort`: first line the port, second line
  the browser WebSocket path (format as parsed by chromedp `keepopen.go:248`; the file is
  written by Chrome, behaviour unverified by our own test until T13).
- That file is not trusted by default. On Windows 0700 means nothing (SEC-J0-18
  deferred), so another local process could plant it. Checks:
  - the profile is a fresh random `MkdirTemp` directory, asserted empty before launch;
  - the file is read only after the process has started, at most 256 bytes;
  - strict parse: port 1-65535, path matching `^/devtools/browser/[0-9a-f-]{36}$`;
  - the listening PID must be Chrome's (`GetExtendedTcpTable` through
    `windows.NewLazySystemDLL("iphlpapi.dll")` of `golang.org/x/sys`, already a direct
    dependency, no new module), from both the IPv4 and IPv6 listener tables: exactly
    one listener on the port, bound to `127.0.0.1` (implemented in T7c:
    `internal/browser/portfile.go`, `porttransport.go`, `portstarter.go`,
    `portexec_windows.go`);
  - a `Browser.getVersion` handshake succeeds before any secret is sent.
- The WebSocket is dialled only through `internal/httpx/cdploopback` (Q1, T7.1): the
  literal `127.0.0.1:<port>`, no host name and so no resolver, no proxy (proxy env
  ignored), no redirects, no TLS, bounded message size. The package can be imported only
  from `internal/browser` (depguard rule plus `callers_test.go`).
- WebSocket implementation: in-house minimal RFC 6455 client inside `cdploopback`
  (client handshake, masked text frames, close, ping/pong; no extensions, no
  fragmentation of outgoing frames), sending `Host: 127.0.0.1:<port>` and no `Origin`
  header (how Chrome checks these headers is unverified until T13). Limits: the 64-bit
  frame length is checked against the 16 MiB cap before any allocation; fragments have a
  cumulative cap; masked server frames and set RSV bits are refused; control frames are
  at most 125 bytes and never fragmented; `Sec-WebSocket-Accept` is verified; handshake
  headers are capped at 8 KiB; anything but `101` is refused; the key and masks come
  from `crypto/rand`. For comparison, rod would need its own
  `lib/cdp/websocket.go` replaced through `WebSocketable` (it dials host names with `net`),
  and chromedp's client sits in `remote/internal/websocket`, not importable and doing its
  own `net` dial, so both options would have needed the same in-house client.
- The browser is closed right after login (`TestPortTransport_ClosedRightAfterLogin`), and
  the CDP port is asserted to bind 127.0.0.1 only (`TestPortTransport_DialsLoopbackOnly`,
  then the real-Chrome check `TestChromeWindows_DebugPortLoopbackOnly`, T13/T32).
- **Accepted MEDIUM finding.** While the login runs, any local process, including one
  of another local user, that finds the port gets full CDP control: it can read the
  password or OTP typed into the DOM, run `Runtime.evaluate`, read the cookies and
  navigate. `/json/version` on the port also reveals the browser GUID path. Mitigations:
  random port, loopback only, short lifetime, disposable profile, the port-file checks
  above. Rated MEDIUM under A4 only because the port is loopback and short-lived. The
  fix needs the standard library only (`AdditionalInheritedHandles`,
  `SetHandleInformation`). The J1 audit (T28) re-rates this HIGH if this wording or the
  issue link below is missing. Recorded in the threat model (`docs/security.md`, T29).
- **Release gate for Windows support (issue #3):** the browser must run in a Job object
  (`CreateJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), so that killing the browser
  or facto dying ends every Chrome child process too. J1 kills the browser process only
  (`portexec_windows.go`) and relies on its children exiting with it; Windows is not
  released until the Job object lands, tracked in
  https://github.com/FlorianRuen/facto/issues/3.
- Open point (S1, to confirm on real Chrome in T13/T32): Chrome may be mid-write of
  `DevToolsActivePort` when facto opens it. The file is parsed once and never re-read, so a
  partial file fails the launch closed (`ErrPortFile`) rather than being trusted; if real
  Chrome shows such partial reads, the fix is an atomic-write check or a bounded re-read of a
  short (not malformed) file, decided then.
- Retry the pipe on Windows through `SysProcAttr.AdditionalInheritedHandles` and
  `--remote-debugging-io-pipes=<read>,<write>`:
  https://github.com/FlorianRuen/facto/issues/3. chromedp v0.21.0 does exactly this
  (`pipe_windows.go:27-37`) and its decision record
  (`docs/decisions/2026-10-04-the-pipe-works-on-windows.md`) states that Chrome and
  Edge 154 accept the switch; neither claim is verified by facto (no Windows run yet).

## Chrome for Testing (A10)
- facto drives Chrome for Testing (spec, Security), not the user's browser.
- J1 ships a pinned **linux64** build only; other platforms pass an explicit browser path
  (config `browser` block, T19).
- Installation is explicit: `facto browser install` (and `make chrome` for development,
  T12). facto never downloads a browser silently. This departs from the spec's
  "downloaded automatically if missing" (Product principles), on purpose: no hidden
  network I/O.
- The download goes through `internal/httpx` with an allowlist holding only the Chrome
  for Testing download host, port 443, TLS verified; the SHA-256 is checked before any
  extraction, and extraction is zip-slip, symlink and size safe through `internal/fsx`
  (T11).
- Hash pinning is trust-on-first-use: Chrome for Testing publishes download URLs but no
  checksum (unverified), so the SHA-256 of the pinned archive is computed on the first
  download by a maintainer and committed next to the pinned version (T12). Any later
  mismatch fails the install with nothing extracted.
- **Pin (T12, 2026-10-30).** Chrome for Testing stable `156.0.8078.80`, linux64,
  `https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/linux64/chrome-linux64.zip`,
  201329937 bytes, SHA-256
  `b711c720f774be355197f32edf37e0651418ba036d92446ee2da19ac017540a7`
  (`internal/browser/cft/pinned.go`). Version and URL were read from the "Stable" channel of
  `googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json`;
  size and hash were computed from a download through `internal/httpx`, then recomputed by
  a second, independent download through `facto browser install` (`make chrome`), which
  verified them. A recomputation by CI or a second person is still to be done before the
  milestone closes.
- **Host.** The download host is `storage.googleapis.com`, shared Google Cloud Storage,
  which `httpx.ParseAllowlist` refuses on purpose. The installer uses
  `httpx.NewPinned(host, "/chrome-for-testing-public/")` instead: on the first request
  and on every redirect hop, before dialing, https only, the exact host byte for byte
  (no case change, trailing dot, subdomain or IDN form), port 443, no userinfo, and a
  canonical path (no dot or empty segment, no percent-encoding, no backslash) under the
  prefix. `ParseAllowlist` and connector allowlists are unchanged. Only
  `internal/browser/cft` may call `NewPinned`: a forbidigo rule, backed by
  `internal/httpx/pinned_callers_test.go` and proven live by `make lint-selftest`.
- **Layout.** `facto browser install` unpacks into `<state_dir>/chrome/<version>/`
  (`--dir` to override; `make chrome` uses `.cache/chrome`, gitignored), every directory
  0700, executables 0700, other files 0600, no setuid bit (so the bundled `chrome_sandbox`
  is not SUID), and writes `.facto-verified` (the SHA-256) last. A verified install is
  reused without network I/O. Each install first removes the `.cft-work-*` leftovers of an
  interrupted one (symlinks unlinked, never followed), and refuses an archive whose
  `chrome` is not executable by its owner.
- The first hash is recomputed independently, by CI or by a second person, before it is
  committed. The manifest records the exact URL, size and SHA-256. The allowlist pins the
  exact host and a path prefix, since the download host is shared storage. A size
  mismatch is refused before hashing; a redirect off that host is refused.
- A browser on another OS is user-supplied and unpinned: facto checks nothing about it
  beyond the launch rules below.
- Patching policy: the pin is bumped on every stable Chrome security release and is never
  more than 4 weeks behind. facto warns at run time when the pinned build is older.

## Hardening
- **Launch flags.** Never passed (deny-list checked at launch): `--no-sandbox`,
  `--disable-setuid-sandbox`, `--disable-namespace-sandbox`,
  `--disable-seccomp-filter-sandbox`, `--disable-gpu-sandbox`, `--no-zygote`,
  `--single-process`, `--disable-web-security`, `--ignore-certificate-errors`,
  `--allow-running-insecure-content`, `--remote-allow-origins`,
  `--remote-debugging-address`, `--load-extension`, `--enable-logging`, `--v=`.
- **No root.** facto refuses to launch Chrome as euid 0.
- **No usable sandbox.** Ubuntu 23.10+ and 24.04 restrict unprivileged user namespaces
  through AppArmor, and Chrome then fails with "No usable sandbox". facto fails closed
  with a typed error that names the fix outside facto: an AppArmor profile for the Chrome
  for Testing path, or the SUID `chrome_sandbox` installed with sudo. facto never retries
  with weaker flags. Unzip strips the setuid bit, so the extracted sandbox is not SUID.
- **Environment.** Chrome gets an allowlisted environment, built like `inherited()` in
  `internal/secret/bitwarden/exec.go`. Proxy variables are never passed.
  `--no-proxy-server` is set unless `FACTO_ALLOW_PROXY=1`.
- **Chrome state outside the profile (J1 T23).** On Linux each launch gets a private 0700
  area `t<pid>.<n>` next to its profile under the pool base (removed with the profile, also
  on a failed launch, and swept like a stale profile when its pid is dead).
  `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME` point into it
  (`config/`, `cache/`, `data/`, `state/`), so Chrome writes nothing under the user's
  `~/.config` (its `Crash Reports` database), `~/.cache` (fontconfig, dconf) or `~/.local`;
  `HOME` and the display variables are kept so a visible window keeps working (fonts in
  `~/.fonts` and the system font dirs still load; user fonts under `~/.local/share/fonts`
  do not). The area name is created exclusively (`fsx` `MkdirNew`): an existing
  `t<pid>.<n>` is skipped for the next number, never reused. `TMPDIR` is the area itself when Chrome's SingletonSocket path
  (`<TMPDIR>/org.chromium.Chromium.XXXXXX/SingletonSocket`) fits the 107-byte unix socket
  limit; otherwise the inherited `TMPDIR` (or `/tmp`) is kept. Whichever `TMPDIR` Chrome
  gets, a path over the limit fails the launch before Chrome starts with
  `ErrSocketPathTooLong`, naming the fix (set `XDG_RUNTIME_DIR`, or a shorter `TMPDIR` or
  `state_dir`), never a cryptic "browser gone". `--disable-crash-reporter` and
  `--disable-breakpad` are in the base flags on every OS. Proof:
  `TestChrome_NothingWrittenUnderHome` (tags `e2e,chrome`), `TestPool_PrivateAreaNextToProfile`,
  `TestPool_SocketPathTooLongFailsBeforeStart`. Not covered by that HOME tree test: the
  visible relaunch (`RelaunchVisible`, interactive `facto login`), which reuses the same
  area through the same environment builder but runs headful (GTK, a display server,
  possibly the desktop's dconf); it is checked by unit tests only. macOS keeps its own per-user temp dir
  (Chrome reads `NSTemporaryDirectory`, not `TMPDIR`); Windows is unchanged.
- **In-browser allowlist (A11).** `Fetch` alone misses WebSocket, WebRTC, DNS prefetch and
  requests from other targets (iframes, workers, service workers, pop-ups). So:
  - `Target.setAutoAttach` with `waitForDebuggerOnStart` and `flatten`; each new target
    gets `Fetch.enable` before `Runtime.runIfWaitingForDebugger`;
  - the page target is created at `about:blank`, `Fetch` is enabled, then it navigates;
  - dedicated workers (J1 T13, measured on Chrome for Testing 156.0.8078.80): Chrome has
    no `Fetch` domain on `worker` sessions and answers `Fetch.enable` with `-32601`
    (method not found), while `Target.setAutoAttach` on them succeeds. Their network
    requests are intercepted by the parent page session's `Fetch` (Chrome applies the
    frame's interception to its dedicated workers). So, for `targetInfo.type == "worker"`
    only, and only when the worker is attached under a watched page, frame or worker
    session (never on the browser session, where no parent `Fetch` covers it: there it is
    closed unresumed), a `-32601` to `Fetch.enable` is not a failure: facto still sends
    `setAutoAttach` (a `-32601` there is tolerated too), then
    `runIfWaitingForDebugger`. Any other error, and `-32601` on any other target type
    (iframe, page, service or shared worker), still closes the target unresumed. Proof:
    `TestFetch_OffAllowlistBlockedInPageWorkerAndNestedWorker` (tags `e2e,chrome`) makes
    the page, a dedicated worker and a nested worker each fetch an off-allowlist host and
    the loopback server by IP: all three run, every request is blocked and counted in
    `BlockedHosts`, the loopback server sees no `/leak` request. Unit twin:
    `TestFetch_WorkerWithoutFetchRelyOnParent`. Residual risk: a Chrome release that
    stops applying page interception to dedicated workers; the e2e test catches it on
    every pin bump (`make e2e`).
  - second layer, release builds too, derived from the same allowlist:
    `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE <allowlist>"`,
    `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--dns-prefetch-disable`;
  - host matching is the same code as `internal/httpx`; it fails closed on an
    unparsable URL, userinfo, a non-https scheme or an IP literal.
  - Only the e2e build may map hosts to loopback. The release check forbids the loopback
    mapping and the test CA flags, not the `--host-resolver-rules` flag name.
- **Secret typing.** Just before `TypeSecret` types, facto checks that
  `document.activeElement` is the expected input in the main frame, that focus is not in
  an iframe, and that the page origin is https and allowlisted. Otherwise it refuses.
- **Cookies in memory.** The login runs in a `Target.createBrowserContext` context, so
  cookies are not written to the profile. `--use-mock-keychain` on macOS.
- **Downloads and permissions.** `Browser.setDownloadBehavior` set to deny; site
  permissions denied.
- **Chrome stderr** is captured with a size cap and never logged verbatim.
- **Boundary.** The security boundary is the user account. A process of the same user
  can open `/proc/<pid>/fd/3` and talk CDP; this is out of scope. The pipe only removes
  the port, which other users could reach. `TestChrome_NoListeningSocket` checks the whole
  Chrome process tree, TCP4 and TCP6.

### Tests required
Grouped by J1 task. Names are binding for the test-writer.

- **T6** (flags, launch): `TestFlags_NeverSandboxWeakening` (table over the deny-list),
  `TestFlags_NeverRemoteAllowOrigins`, `TestFlags_NeverRemoteDebuggingAddress`,
  `TestLaunch_RootRefused`, `TestLaunch_NoUsableSandboxFailsClosed`,
  `TestLaunch_EnvAllowlisted`, `TestLaunch_ProxyEnvNotPassed`,
  `TestFlags_NoProxyServerUnlessAllowed`, `TestFlags_MockKeychainOnDarwin`,
  `TestLaunch_StderrNotLoggedVerbatim`.
- **T7** (transport): `TestPipe_ConcurrentSendsNotInterleaved`,
  `TestPipe_SecretWithNULCannotSplitFrame`, `TestClient_UnknownIDAndSessionIgnored`,
  `TestPortFile_PreexistingFileRefused`, `TestPortFile_OversizedRefused`,
  `TestPortFile_PathMustMatchBrowserGUID`, `TestPortTransport_NoSecretBeforeHandshake`.
- **T7.1** (`cdploopback`): `TestWS_LengthOverCapRefusedBeforeAlloc`,
  `TestWS_FragmentedTotalOverCapRefused`, `TestWS_MaskedServerFrameRefused`,
  `TestWS_RSVBitsRefused`, `TestWS_ControlFrameOver125Refused`,
  `TestWS_BadAcceptKeyRefused`, `TestWS_HandshakeHeaderOverCapRefused`,
  `TestWS_Non101Refused`.
- **T8** (page operations): `TestPage_TypeSecretRefusesWhenFocusInCrossOriginFrame`,
  `TestPage_TypeSecretRefusesAfterNavigationOffAllowlist`,
  `TestPage_TypeSecretRefusesNonHTTPSOrigin`.
- **T9** (in-browser allowlist): `TestFetch_BlocksOffAllowlistInOOPIF`,
  `TestFetch_BlocksOffAllowlistInWorker`, `TestFetch_BlocksOffAllowlistInServiceWorker`,
  `TestFetch_BlocksOffAllowlistInPopup`, `TestFetch_BlocksOffAllowlistBeforeFirstNavigation`,
  `TestFlags_HostResolverRulesMirrorAllowlist`, `TestFetch_MatcherSharedWithHttpx`.
- **T10** (pool, teardown): `TestLaunch_KillsWholeProcessGroup` (macOS parent-death gap
  recorded), `TestBrowser_DownloadsDenied`.
- **T11/T12** (Chrome for Testing): `TestInstall_ManifestPinsExactURLAndHost`,
  `TestInstall_RedirectOffHostRefused`, `TestInstall_SizeMismatchRefusedBeforeHash`,
  `TestPinnedChrome_AgeWarning` (fake clock).
- **T13** (real Chrome, `e2e` and `chrome` tags; `make e2e`, never `make verify`): `TestChromeWindows_OriginHeaderRejected`,
  `TestChromeWindows_NonLoopbackHostHeaderRejected`, `TestChromeWindows_ListenerPIDIsChrome`,
  `TestFetch_WebSocketOffAllowlistBlocked`, `TestChrome_NoCookieStoreWrittenAfterLogin`,
  `TestChrome_NoListeningSocket` (whole process tree, TCP4 and TCP6).

## Alternatives
| Option | Why not |
| --- | --- |
| `github.com/go-rod/rod` v0.116.2 (2024-07-12, MIT) | No pipe; no release for 27 months; root package imports the browser downloader (`lib/launcher`, `fetchup`), `leakless` writes a 0755 executable to the temp dir, `init` reads `--rod=cdp` from `os.Args` and can log every CDP message; 5 extra modules |
| `github.com/chromedp/chromedp` v0.21.0 (2026-10-11, MIT) | Good pipe support and no download; but pipe code 26 days old, heavy API churn, single maintainer, `cdproto` re-tagged weekly; T7 would still replace its `PipeConn` and launcher. Recorded fallback |
| `github.com/playwright-community/playwright-go` | Needs the Playwright driver downloaded at runtime (spec, Stack; not rechecked here, unverified) |
| `--remote-debugging-port` on every OS | Opens a port any local process can use: spec makes the pipe a requirement where available |

## License
In-house client: no third-party code, no new module. For the record: rod MIT, its
modules `fetchup` MIT, `goob` MIT, `got` MIT, `gson` MIT, `leakless` MIT; chromedp MIT,
cdproto MIT, `go-json-experiment/json` BSD-3-Clause (not compiled on Go 1.27). All read
from the LICENSE files in the module cache.

## Maintenance
- In-house: maintained by facto. Risk: CDP changes between Chrome versions; contained by
  the pinned Chrome for Testing version and by e2e tests against it (T13, T22-T24).
- rod: 368 tags; latest v0.116.2 (2024-07-12), v0.116.0 (2024-05-06), v0.115.0
  (2024-04-17); 13 tags from v0.114.0 (2023-07-18) to v0.116.2, none since.
- chromedp: 82 tags; v0.14.0 (2025-07-26), v0.15.0 (2026-03-21), v0.16.0 (2026-07-14),
  then v0.17.0 to v0.21.0 between 2026-10-03 and 2026-10-11. cdproto latest v0.158.6
  (2026-10-27), 19 tags since v0.157.0 (2026-10-03). Maintainer count: one, per
  `CONTRIBUTING.md` ("Ask the maintainer"); contributor activity otherwise unverified.

## Consequences
- facto owns the CDP client: ~17 methods, framing, sessions, events, and the Windows
  WebSocket client in `cdploopback`. Tests use a fake browser (re-executed test binary on
  fds 3/4) and, under the `e2e` tag, real Chrome for Testing.
- No browser library in `go.mod`; rule 6 keeps it that way. If one is ever added, its
  downloader or network package is denied by depguard (rod: the whole module, since its
  root imports `lib/launcher`; chromedp: `github.com/chromedp/chromedp/remote`).
- Windows runs with an accepted MEDIUM finding until
  https://github.com/FlorianRuen/facto/issues/3 (pipe retry) is closed.
- `docs/spec.md` (Stack table and the "rod maintenance" risk row) and `docs/security.md`
  are updated at J1 close-out (T29).
- Revisit when: the in-house client exceeds ~2 000 non-test lines, or needs CDP domains
  beyond the list above; or chromedp's API stays stable for six months, at which point
  chromedp with facto's own `Transport` is reconsidered.
