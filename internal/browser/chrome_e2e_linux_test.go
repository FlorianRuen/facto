//go:build e2e && chrome && linux

// Real-Chrome isolation checks (J1 T13, ADR 0008 "Tests required" T13 and
// "Hardening / Boundary"). They drive the pinned Chrome for Testing through
// the production Pool and check, from /proc, what the browser exposes:
//
//   - no TCP socket in LISTEN state (TCP4 and TCP6) held by any process of
//     the browser's process tree, read per process from /proc/<pid>/fd and
//     the process's own /proc/<pid>/net/tcp{,6} (sandboxed children live
//     in another network namespace); no --remote-debugging-port in any
//     argv; no DevToolsActivePort in the profile;
//   - the probe is never vacuous: a listener in a child (and a grandchild)
//     process IS detected by the same code;
//   - the profile is gone after Close; Chrome dies with a SIGKILLed facto
//     and the next pool sweeps the stale profile;
//   - a login in the fresh browser context leaves no cookie, typed value
//     or Cookies row on disk;
//   - off-allowlist requests are blocked in the page, a dedicated worker
//     and a nested worker (BlockedHosts counts them; the loopback server
//     never sees them), and off-allowlist WebSockets never connect.
//
// Chrome: FACTO_E2E_CHROME, else <module>/.cache/chrome/<cft.Pinned()
// version>/chrome-linux64/chrome (make chrome). Neither present = fail,
// never skip. The fake site is an httptest TLS server on 127.0.0.1 with a
// generated CA, reached through FlagsE2E (loopback mapping + test CA SPKI).
//
// Expected production API (missing today):
//
//	// E2EOverrides (flags_e2e.go) gains the port the loopback hosts are
//	// mapped to: the fake site cannot bind 443 unprivileged, while Navigate
//	// only accepts https on 443.
//	type E2EOverrides struct {
//		LoopbackHosts []string // mapped to 127.0.0.1 in --host-resolver-rules
//		LoopbackPort  int      // 0: "MAP <host> 127.0.0.1"; 1-65535: "MAP <host> 127.0.0.1:<port>"
//		TestCASPKI    []string // --ignore-certificate-errors-spki-list
//	}
//	// FlagsE2E refuses LoopbackPort outside 0..65535, and a non-zero
//	// LoopbackPort without LoopbackHosts, with ErrForbiddenFlag.
//
//	// BlockedHosts returns Page.BlockedHosts of the lease's current page
//	// (a copy); empty once the lease is over.
//	func (b *PoolBrowser) BlockedHosts() map[string]int
//
// The e2e flags reach the pool through its Starter: the test wraps the
// production StartPipeProcess and swaps the release argv for FlagsE2E's,
// built from the same profile and allowlist.
package browser_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 Sec-WebSocket-Accept, not a security use
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	// e2eChromeEnv names the Chrome binary for the real-browser tests.
	e2eChromeEnv = "FACTO_E2E_CHROME"
	// e2eTimeout bounds each real-Chrome test.
	e2eTimeout = 90 * time.Second

	// siteHost is the allowlisted host of the fake site (synthetic).
	siteHost = "login.supplier.example"
	// Off-allowlist hosts the fake pages try to reach (synthetic).
	offPageHost   = "page.offlist.example"
	offWorkerHost = "worker.offlist.example"
	offNestedHost = "nested.offlist.example"
	offWSHost     = "ws.offlist.example"

	// sessionCookie is the cookie the fake site sets after a login.
	sessionCookie = "facto_e2e_sid"
	// syntheticUser is the user name typed on the fake login page.
	syntheticUser = "synthetic-e2e-user"

	// Helper modes of this test binary (runE2EMode).
	modeE2EListen      = "e2e-listen"            // listen on FACTO_E2E_ADDR, print "ready port=<n>"
	modeE2EListenChild = "e2e-listen-grandchild" // start an e2e-listen child, wait
	modeE2EDial        = "e2e-dial"              // connect to FACTO_E2E_ADDR, print "ready port=0"
	modeE2EChromeOwner = "e2e-chrome-parent"     // launch Chrome through a Pool, print "profile=<dir>"

	e2eListenEnv = "FACTO_E2E_LISTEN" // listener kind (listenKinds)
	e2ePortEnv   = "FACTO_E2E_PORT"   // 127.0.0.1 port e2e-dial connects to
	e2eStateEnv  = "FACTO_E2E_STATE"
	e2eHomeEnv   = "FACTO_E2E_HOME"
)

// listenKinds are the control listeners a helper can open (network,
// address). Fixed here: the helper takes no address from its environment.
var listenKinds = map[string][2]string{
	"tcp4-loopback": {"tcp4", "127.0.0.1:0"},
	"tcp4-wildcard": {"tcp4", "0.0.0.0:0"},
	"tcp6-wildcard": {"tcp6", "[::]:0"},
}

var siteDomains = []string{siteHost}

// ------------------------------------------------------------ Chrome

// chromeBinary returns the Chrome for Testing binary the tests drive.
func chromeBinary(t *testing.T) string {
	t.Helper()
	if v := os.Getenv(e2eChromeEnv); v != "" {
		if !filepath.IsAbs(v) {
			t.Fatalf("%s must be absolute", e2eChromeEnv)
		}
		return filepath.Clean(v) // the pool's CheckExecutable vets it
	}
	root := moduleRoot(t)
	p := filepath.Join(root, ".cache", "chrome", cft.Pinned().Version, "chrome-linux64", "chrome")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("no Chrome for the e2e tests: set %s or run `make chrome` (%v); this test never skips", e2eChromeEnv, err)
	}
	return p
}

// moduleRoot walks up from the package directory to go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the package directory")
		}
		dir = parent
	}
}

// chromeHost is the Host of a real-Chrome pool: a private HOME, the
// process PATH, no XDG_RUNTIME_DIR (the profile base is <state>/tmp).
func chromeHost(exe, home string) browser.Host {
	return browser.Host{
		Executable: exe,
		Geteuid:    os.Geteuid,
		LookupEnv:  mapLookup(map[string]string{"HOME": home, "PATH": os.Getenv("PATH")}),
		Log:        slog.New(slog.DiscardHandler),
	}
}

// chromeRig is one real-Chrome pool on a private state dir.
type chromeRig struct {
	t     *testing.T
	exe   string
	home  string
	state string
	pool  *browser.Pool

	mu   sync.Mutex
	pids []int // browser pids started through the rig's starter
}

// newChromeRig builds a pool. start nil = the production starter
// (StartPipeProcess through the pool default); otherwise start wraps it.
func newChromeRig(t *testing.T, start func(r *chromeRig) browser.Starter) *chromeRig {
	t.Helper()
	root := t.TempDir()
	r := &chromeRig{t: t, exe: chromeBinary(t)}
	r.home = privateDir(t, root, "home")
	r.state = privateDir(t, root, "state")
	cfg := browser.PoolConfig{Host: chromeHost(r.exe, r.home), StateDir: r.state}
	if start != nil {
		cfg.Start = start(r)
	}
	p, err := browser.NewPool(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	r.pool = p
	return r
}

func (r *chromeRig) record(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pids = append(r.pids, pid)
	r.t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
}

func (r *chromeRig) startedPids() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.pids)
}

// launch leases a headless browser on siteDomains.
func (r *chromeRig) launch(ctx context.Context) *browser.PoolBrowser {
	r.t.Helper()
	b, err := r.pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: siteDomains})
	if err != nil {
		r.t.Fatalf("Launch real Chrome: %v", err)
	}
	pb, ok := b.(*browser.PoolBrowser)
	if !ok {
		r.t.Fatalf("Launch returned %T, want *browser.PoolBrowser", b)
	}
	closeAtCleanup(r.t, pb)
	return pb
}

// e2eStarter wraps the production StartPipeProcess: the release argv the
// pool vetted is replaced by FlagsE2E's for the same profile, allowlist,
// visibility and proxy setting, pointing siteHost at site.
func e2eStarter(site *fakeSite) func(r *chromeRig) browser.Starter {
	return func(r *chromeRig) browser.Starter {
		return func(ctx context.Context, cmd browser.Command) (browser.Process, error) {
			profile, ok := argValue(cmd.Args, "--user-data-dir=")
			if !ok {
				return nil, errors.New("e2e starter: no --user-data-dir in the pool's argv")
			}
			args, err := browser.FlagsE2E(browser.Options{
				ProfileDir:     profile,
				AllowedDomains: siteDomains,
				Visible:        !slices.Contains(cmd.Args, headlessFlag),
				AllowProxy:     !slices.Contains(cmd.Args, "--no-proxy-server"),
			}, browser.E2EOverrides{
				LoopbackHosts: []string{siteHost},
				LoopbackPort:  site.port,
				TestCASPKI:    []string{site.caSPKI},
			})
			if err != nil {
				return nil, fmt.Errorf("e2e starter: %w", err)
			}
			cmd.Args = args
			p, err := browser.StartPipeProcess(ctx, cmd)
			if err != nil {
				return nil, err
			}
			r.record(p.Pid())
			return p, nil
		}
	}
}

func argValue(args []string, prefix string) (string, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, prefix); ok {
			return v, true
		}
	}
	return "", false
}

// ------------------------------------------------------------ /proc probe

// allProcs maps every visible pid to its parent pid.
func allProcs(t *testing.T) map[int]int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	out := map[int]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // exited meanwhile
		}
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		out[pid] = ppid
	}
	return out
}

// processTree returns root and every live descendant of it.
func processTree(t *testing.T, root int) []int {
	t.Helper()
	procs := allProcs(t)
	children := map[int][]int{}
	for pid, ppid := range procs {
		children[ppid] = append(children[ppid], pid)
	}
	tree := []int{root}
	for i := 0; i < len(tree); i++ {
		tree = append(tree, children[tree[i]]...)
	}
	slices.Sort(tree)
	return tree
}

// cmdline returns pid's argv; nil when it exited.
func cmdline(pid int) []string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
}

// browserPidByProfile finds the one process whose argv carries
// --user-data-dir=<profile> and whose parent does not.
func browserPidByProfile(t *testing.T, profile string) int {
	t.Helper()
	want := "--user-data-dir=" + profile
	procs := allProcs(t)
	match := map[int]bool{}
	for pid := range procs {
		if slices.Contains(cmdline(pid), want) {
			match[pid] = true
		}
	}
	var roots []int
	for pid := range match {
		if !match[procs[pid]] {
			roots = append(roots, pid)
		}
	}
	if len(roots) != 1 {
		t.Fatalf("processes started on the profile without a parent on it = %v, want exactly one browser", roots)
	}
	return roots[0]
}

// errFdsUnreadable means a process of the tree hides its descriptors: the
// probe cannot prove anything about it.
var errFdsUnreadable = errors.New("fd table unreadable")

// socketInodes returns the socket inodes pid holds. A process that exited
// meanwhile holds none.
func socketInodes(pid int) (map[uint64]bool, error) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	ents, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("pid %d (%s): %w: %w", pid, procDescription(pid), errFdsUnreadable, err)
	}
	out := map[uint64]bool{}
	for _, e := range ents {
		link, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // closed meanwhile
		}
		v, ok := strings.CutPrefix(link, "socket:[")
		if !ok {
			continue
		}
		ino, err := strconv.ParseUint(strings.TrimSuffix(v, "]"), 10, 64)
		if err == nil {
			out[ino] = true
		}
	}
	return out, nil
}

// procDescription names pid for a probe error: its Chrome process type
// (--type=, "browser" without one), state and parent, from /proc.
func procDescription(pid int) string {
	typ := "browser"
	argv := cmdline(pid)
	if len(argv) == 0 {
		typ = "exited"
	}
	for _, a := range argv {
		if v, ok := strings.CutPrefix(a, "--type="); ok {
			typ = v
		}
	}
	var state, ppid string
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "State:"); ok {
				state = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(l, "PPid:"); ok {
				ppid = strings.TrimSpace(v)
			}
		}
	}
	return fmt.Sprintf("type %s, state %q, ppid %s", typ, state, ppid)
}

// tcpListener is one LISTEN row of /proc/<pid>/net/tcp{,6}.
type tcpListener struct {
	pid    int
	family string // "tcp4" or "tcp6"
	addr   string // local address
	port   int
	inode  uint64
}

func (l tcpListener) String() string {
	return fmt.Sprintf("pid %d %s %s port %d", l.pid, l.family, l.addr, l.port)
}

// listenRows reads the LISTEN rows of pid's network namespace.
func listenRows(pid int) ([]tcpListener, error) {
	var out []tcpListener
	for _, fam := range []struct{ file, name string }{{"tcp", "tcp4"}, {"tcp6", "tcp6"}} {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/net/" + fam.file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, fmt.Errorf("pid %d net/%s: %w", pid, fam.file, err)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Scan() // header
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 10 || f[3] != "0A" { // 0A = TCP_LISTEN
				continue
			}
			ino, err := strconv.ParseUint(f[9], 10, 64)
			if err != nil {
				continue
			}
			addr, port := decodeProcAddr(f[1])
			out = append(out, tcpListener{family: fam.name, addr: addr, port: port, inode: ino})
		}
	}
	return out, nil
}

// decodeProcAddr decodes "0100007F:1F90" (tcp) or the 32-hex-digit tcp6
// form: each 32-bit word is in host (little-endian) order.
func decodeProcAddr(s string) (string, int) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return s, 0
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return h, int(port)
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		for i := range 4 {
			ip[w+i] = raw[w+3-i]
		}
	}
	return ip.String(), int(port)
}

// probeResult is what the probe saw in a process tree.
type probeResult struct {
	pids      []int
	sockets   int // socket descriptors seen across the tree
	listening []tcpListener
}

// Bounds of probeTree's retries when a process of the tree hides its fd
// table (a short-lived helper that is exiting answers EACCES).
const (
	probeAttempts = 50 // 5 s: a sandboxed Chrome child is briefly non-dumpable while it starts, longer under load
	probeInterval = 100 * time.Millisecond
)

// probeTree finds every TCP socket in LISTEN state held by a process of
// root's tree, TCP4 and TCP6, each process read in its own network
// namespace. A walk that meets an unreadable fd table (errFdsUnreadable)
// is redone from scratch, at most probeAttempts times, probeInterval
// apart: a result is accepted only from a walk that read the fd table of
// every live pid of the tree (a pid gone meanwhile has exited and holds
// nothing). A pid still unreadable on the last attempt is returned as the
// error: the probe cannot prove anything about it.
func probeTree(t *testing.T, root int) (probeResult, error) {
	t.Helper()
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for attempt := 1; ; attempt++ {
		res, err := probeTreeOnce(t, root)
		if err == nil || !errors.Is(err, errFdsUnreadable) || attempt == probeAttempts {
			if err != nil {
				err = fmt.Errorf("%w (after %d walks)", err, attempt)
			}
			return res, err
		}
		select {
		case <-tick.C:
		case <-t.Context().Done():
			return res, err
		}
	}
}

// probeTreeOnce is one walk of probeTree.
func probeTreeOnce(t *testing.T, root int) (probeResult, error) {
	t.Helper()
	res := probeResult{pids: processTree(t, root)}
	for _, pid := range res.pids {
		inodes, err := socketInodes(pid)
		if err != nil {
			return res, err
		}
		if len(inodes) == 0 {
			continue
		}
		res.sockets += len(inodes)
		rows, err := listenRows(pid)
		if err != nil {
			return res, err
		}
		for _, l := range rows {
			if inodes[l.inode] {
				l.pid = pid
				res.listening = append(res.listening, l)
			}
		}
	}
	return res, nil
}

// ------------------------------------------------------------ helper modes

// runE2EMode runs the real-Chrome helper modes of this test binary.
func runE2EMode(mode string) int {
	switch mode {
	case modeE2EListen:
		kind, ok := listenKinds[os.Getenv(e2eListenEnv)]
		if !ok {
			return 19
		}
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), kind[0], kind[1])
		if err != nil {
			return 20
		}
		defer func() { _ = ln.Close() }()
		port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // a TCP listener
		if _, err := fmt.Fprintf(os.Stdout, "ready port=%d\n", port); err != nil {
			return 21
		}
		<-time.After(fakeLifetime)
		return 0
	case modeE2EListenChild:
		exe, err := os.Executable()
		if err != nil {
			return 22
		}
		c := exec.Command(exe) //nolint:gosec,noctx // re-executes this test binary; bounded by fakeLifetime
		c.Env = append(os.Environ(), fakeModeEnv+"="+modeE2EListen)
		c.Stdout = os.Stdout // the grandchild's ready line reaches the test
		if err := c.Start(); err != nil {
			return 23
		}
		_ = c.Wait()
		return 0
	case modeE2EDial:
		port, err := strconv.Atoi(os.Getenv(e2ePortEnv))
		if err != nil || port < 1 || port > 65535 {
			return 24
		}
		var d net.Dialer
		conn, err := d.DialContext(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return 24
		}
		defer func() { _ = conn.Close() }()
		if _, err := io.WriteString(os.Stdout, "ready port=0\n"); err != nil {
			return 25
		}
		<-time.After(fakeLifetime)
		return 0
	case modeE2EChromeOwner:
		return runChromeOwner()
	default:
		return 2
	}
}

// runChromeOwner plays facto: a Pool on FACTO_E2E_STATE launches the real
// Chrome with the production starter, prints "profile=<dir>" and waits to
// be SIGKILLed (no cleanup code runs).
func runChromeOwner() int {
	ctx := context.Background()
	p, err := browser.NewPool(ctx, browser.PoolConfig{
		Host:     chromeHost(os.Getenv(e2eChromeEnv), os.Getenv(e2eHomeEnv)),
		StateDir: os.Getenv(e2eStateEnv),
	})
	if err != nil {
		return 30
	}
	b, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: siteDomains})
	if err != nil {
		return 31
	}
	pb, ok := b.(*browser.PoolBrowser)
	if !ok {
		return 32
	}
	if _, err := fmt.Fprintf(os.Stdout, "profile=%s\n", pb.ProfileDir()); err != nil {
		return 33
	}
	<-time.After(fakeLifetime)
	return 0
}

// helperChild starts this binary in mode with env, in its own process
// group, and returns it with its first stdout line.
func helperChild(t *testing.T, mode string, env ...string) (*exec.Cmd, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.CommandContext(t.Context(), exe) //nolint:gosec // re-executes this test binary
	c.Env = append(append(os.Environ(), fakeModeEnv+"="+mode), env...)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("start helper %s: %v", mode, err)
	}
	pid := c.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = c.Wait()
	})
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(l)
	}()
	select {
	case l := <-line:
		if l == "" {
			t.Fatalf("helper %s exited before its ready line", mode)
		}
		return c, l
	case <-time.After(waitLimit):
		t.Fatalf("helper %s: no ready line within %v", mode, waitLimit)
	}
	return nil, ""
}

// ------------------------------------------------------------ fake site

// fakeSite is the synthetic supplier site on 127.0.0.1 (TLS, generated
// CA) plus a plain HTTP listener for ws:// probes. It counts every request
// per path and never logs a form value.
type fakeSite struct {
	tls    *httptest.Server
	plain  *httptest.Server
	port   int    // TLS port
	caSPKI string // base64 SHA-256 of the CA SubjectPublicKeyInfo

	user, pass     string // expected login fields
	cookieValue    string
	mu             sync.Mutex
	hits           map[string]int
	logins         int
	wsAllowedOpens int
}

func newFakeSite(t *testing.T) *fakeSite {
	t.Helper()
	s := &fakeSite{
		hits:        map[string]int{},
		user:        syntheticUser,
		pass:        testsecrets.Canary(t, testsecrets.Password),
		cookieValue: testsecrets.Canary(t, testsecrets.Cookie),
	}
	cert, spki := siteCertificate(t)
	s.caSPKI = spki
	s.tls = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.tls.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.tls.StartTLS()
	t.Cleanup(s.tls.Close)
	s.port = s.tls.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // httptest listens on TCP
	s.plain = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.plain.Close)
	if !strings.HasPrefix(s.tls.Listener.Addr().String(), "127.0.0.1:") {
		t.Fatalf("fake site listens on %s, want 127.0.0.1 only (A7)", s.tls.Listener.Addr())
	}
	return s
}

func (s *fakeSite) plainPort() int {
	return s.plain.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // httptest listens on TCP
}

// siteCertificate generates a CA and a leaf for siteHost and 127.0.0.1;
// the chain served is leaf + CA.
func siteCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed validity: the clock is never read; Chrome accepts the chain
	// through the SPKI list whatever the dates.
	notBefore := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "facto e2e synthetic CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: siteHost},
		DNSNames:     []string{siteHost},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
		base64.StdEncoding.EncodeToString(sum[:])
}

func (s *fakeSite) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *fakeSite) snapshot() (hits map[string]int, logins int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := map[string]int{}
	for k, v := range s.hits {
		h[k] = v
	}
	return h, s.logins
}

func (s *fakeSite) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	s.mu.Unlock()
	html := func(body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><title>facto e2e</title><body>"+body+"</body>")
	}
	js := func(src string) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(w, src)
	}
	switch r.URL.Path {
	case "/":
		html(`<p id="ready">ready</p>`)
	case "/login":
		html(`<form method="post" action="/session">` +
			`<input id="user" name="user" autocomplete="username">` +
			`<input id="pass" name="pass" type="password" autocomplete="current-password">` +
			`<button id="submit" type="submit">Sign in</button></form>`)
	case "/session":
		if r.Method != http.MethodPost || r.PostFormValue("user") != s.user || r.PostFormValue("pass") != s.pass {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		s.logins++
		s.mu.Unlock()
		// A persistent cookie: a profile-backed store would write it.
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: s.cookieValue, Path: "/",
			MaxAge: 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
	case "/welcome":
		html(`<h1 id="welcome">welcome</h1>`)
	case "/workers":
		html(fmt.Sprintf(workersPage, s.port))
	case "/worker.js":
		js(fmt.Sprintf(workerScript, offWorkerHost, s.port, "worker"))
	case "/nested.js":
		js(fmt.Sprintf(nestedScript, offNestedHost, s.port, "nested"))
	case "/ws":
		html(fmt.Sprintf(wsPage, siteHost, offWSHost, s.port, s.plainPort()))
	case "/ws-allowed":
		s.upgrade(w, r)
	default:
		// /leak, /ws-ip, /ws-plain, /ws-off: only counted.
		http.NotFound(w, r)
	}
}

// upgrade answers a WebSocket handshake with 101 and holds the connection
// briefly (control: the allowlisted WebSocket opens).
func (s *fakeSite) upgrade(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	hj, ok := w.(http.Hijacker)
	if key == "" || !ok {
		http.Error(w, "not a websocket handshake", http.StatusBadRequest)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // RFC 6455
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	_ = rw.Flush()
	s.mu.Lock()
	s.wsAllowedOpens++
	s.mu.Unlock()
	// Hold the socket until the page closes it, at most 5 s.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_, _ = io.Copy(io.Discard, conn)
}

// workersPage fetches an off-allowlist host and the loopback server by IP
// from the page, starts a dedicated worker that does the same and starts
// a nested worker that does the same. Once the three have settled it adds
// <p id="done" class="page-settled worker-settled nested-settled">.
// %[1]d: TLS port.
const workersPage = `<script>
const seen = new Set();
function settled(origin) {
  seen.add(origin + "-settled");
  if (seen.size === 3) {
    const p = document.createElement("p");
    p.id = "done"; p.className = [...seen].join(" "); p.textContent = "done";
    document.body.appendChild(p);
  }
}
Promise.allSettled([
  fetch("https://` + offPageHost + `/x"),
  fetch("https://127.0.0.1:%[1]d/leak?from=page"),
]).then(() => settled("page"));
const w = new Worker("/worker.js");
w.onmessage = (e) => settled(e.data);
</script>`

// workerScript: %[1]s off host, %[2]d TLS port, %[3]s origin name.
const workerScript = `const n = new Worker("/nested.js");
n.onmessage = (e) => postMessage(e.data);
Promise.allSettled([
  fetch("https://%[1]s/x"),
  fetch("https://127.0.0.1:%[2]d/leak?from=%[3]s"),
]).then(() => postMessage("%[3]s"));
`

// nestedScript: %[1]s off host, %[2]d TLS port, %[3]s origin name.
const nestedScript = `Promise.allSettled([
  fetch("https://%[1]s/x"),
  fetch("https://127.0.0.1:%[2]d/leak?from=%[3]s"),
]).then(() => postMessage("%[3]s"));
`

// wsPage opens four WebSockets: the allowlisted host (control), an
// off-allowlist host, the loopback TLS server by IP and the plain loopback
// server by IP. Once each has opened or failed it adds <p id="done"
// class="allowed-open offhost-failed …">. %[1]s allowed host, %[2]s off
// host, %[3]d TLS port, %[4]d plain port.
const wsPage = `<script>
const out = {};
function done(k, v) {
  if (k in out) return;
  out[k] = v;
  if (Object.keys(out).length === 4) {
    const p = document.createElement("p");
    p.id = "done"; p.textContent = "done";
    p.className = Object.entries(out).map(([a, b]) => a + "-" + b).join(" ");
    document.body.appendChild(p);
  }
}
function probe(k, url) {
  let ws;
  try { ws = new WebSocket(url); } catch (e) { done(k, "refused"); return; }
  ws.onopen = () => { done(k, "open"); ws.close(); };
  ws.onerror = () => done(k, "failed");
  ws.onclose = () => done(k, "failed");
}
probe("allowed", "wss://%[1]s/ws-allowed");
probe("offhost", "wss://%[2]s/ws-off");
probe("iptls", "wss://127.0.0.1:%[3]d/ws-ip");
probe("ipplain", "ws://127.0.0.1:%[4]d/ws-plain");
</script>`

// openSite navigates b to path on the fake site and waits for selector.
func openSite(ctx context.Context, t *testing.T, b *browser.PoolBrowser, path, selector string) {
	t.Helper()
	if err := b.Navigate(ctx, "https://"+siteHost+path); err != nil {
		t.Fatalf("Navigate %s: %v", path, err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := b.WaitVisible(wctx, selector); err != nil {
		t.Fatalf("WaitVisible(%q) on %s: %v", selector, path, err)
	}
}

// ------------------------------------------------------------ tests

// TestProbe_DetectsARealListener: the probe of TestChrome_NoListeningSocket
// is never vacuous. A listener in a child process, TCP4 and TCP6, loopback
// and wildcard, and one in a grandchild, are found by probing the child's
// tree; an established (non-listening) socket is not reported.
func TestProbe_DetectsARealListener(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	parentLn, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connMu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = parentLn.Close()
		connMu.Lock()
		defer connMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := parentLn.Accept()
			if err != nil {
				return
			}
			connMu.Lock()
			conns = append(conns, c)
			connMu.Unlock()
		}
	}()

	parentPort := strconv.Itoa(parentLn.Addr().(*net.TCPAddr).Port) //nolint:forcetypeassert // a TCP listener

	tests := []struct {
		name       string
		mode       string
		kind       string // listenKinds key
		wantFamily string // "" = nothing listening
		wantAddr   string
		grandchild bool
	}{
		{name: "tcp4 loopback", mode: modeE2EListen, kind: "tcp4-loopback", wantFamily: "tcp4", wantAddr: "127.0.0.1"},
		{name: "tcp4 wildcard", mode: modeE2EListen, kind: "tcp4-wildcard", wantFamily: "tcp4", wantAddr: "0.0.0.0"},
		// No [::1] case: hosts with IPv6 off on lo cannot bind it, while
		// the tcp6 table parsing is the same for [::].
		{name: "tcp6 wildcard", mode: modeE2EListen, kind: "tcp6-wildcard", wantFamily: "tcp6", wantAddr: "::"},
		{name: "listener in a grandchild", mode: modeE2EListenChild, kind: "tcp4-loopback", wantFamily: "tcp4", wantAddr: "127.0.0.1", grandchild: true},
		{name: "established connection only", mode: modeE2EDial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, line := helperChild(t, tt.mode, e2eListenEnv+"="+tt.kind, e2ePortEnv+"="+parentPort)
			v, ok := strings.CutPrefix(line, "ready port=")
			if !ok {
				t.Fatalf("helper line = %q, want ready port=<n>", line)
			}
			port, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("helper port %q: %v", v, err)
			}
			res, err := probeTree(t, c.Process.Pid)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if res.sockets == 0 {
				t.Fatalf("probe saw no socket in the helper tree %v: fd reading is broken", res.pids)
			}
			if tt.wantFamily == "" {
				if len(res.listening) != 0 {
					t.Errorf("probe reported %v for a process with no listener", res.listening)
				}
				return
			}
			if len(res.listening) != 1 {
				t.Fatalf("probe found %v in tree %v, want exactly the helper's listener", res.listening, res.pids)
			}
			got := res.listening[0]
			if got.family != tt.wantFamily || got.addr != tt.wantAddr || got.port != port {
				t.Errorf("probe found %v, want %s %s port %d", got, tt.wantFamily, tt.wantAddr, port)
			}
			if tt.grandchild && got.pid == c.Process.Pid {
				t.Errorf("listener attributed to the child %d, want the grandchild", got.pid)
			}
		})
	}
}

// TestChrome_NoListeningSocket (ADR 0008 Hardening "Boundary", #14): the
// real Chrome launched through the pool over the pipe holds no TCP socket
// in LISTEN state in any process of its tree (TCP4 and TCP6), passes no
// debugging port switch, and writes no DevToolsActivePort. Checked right
// after launch with the production starter, and with a page loaded (the
// renderer and network service running).
func TestChrome_NoListeningSocket(t *testing.T) {
	t.Parallel()
	site := newFakeSite(t)
	tests := []struct {
		name  string
		start func(r *chromeRig) browser.Starter
		load  bool
	}{
		{name: "production starter, blank page"},
		{name: "fake site loaded", start: e2eStarter(site), load: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
			defer cancel()
			r := newChromeRig(t, tt.start)
			b := r.launch(ctx)
			if tt.load {
				openSite(ctx, t, b, "/", "#ready")
			}
			root := browserPidByProfile(t, b.ProfileDir())
			if pids := r.startedPids(); tt.start != nil && !slices.Equal(pids, []int{root}) {
				t.Fatalf("browser on the profile is pid %d, starter started %v", root, pids)
			}

			res, err := probeTree(t, root)
			if err != nil {
				t.Fatalf("probe Chrome's tree: %v (cannot prove there is no listener)", err)
			}
			if len(res.pids) < 2 {
				t.Errorf("Chrome tree = %v, want the browser and its helpers (tree walk broken?)", res.pids)
			}
			if res.sockets == 0 {
				t.Errorf("no socket seen in Chrome's tree %v: the probe is blind", res.pids)
			}
			for _, l := range res.listening {
				t.Errorf("listening TCP socket in Chrome's tree: %v", l)
			}

			if !slices.Contains(cmdline(root), "--remote-debugging-pipe") {
				t.Errorf("browser argv lacks --remote-debugging-pipe")
			}
			for _, pid := range res.pids {
				for _, a := range cmdline(pid) {
					if strings.HasPrefix(a, "--remote-debugging-port") || strings.HasPrefix(a, "--remote-debugging-address") {
						t.Errorf("pid %d argv has %q", pid, a)
					}
				}
			}
			for _, f := range filesNamed(t, b.ProfileDir(), "DevToolsActivePort") {
				t.Errorf("profile holds %s: a debugging port was opened", f)
			}
			if !t.Failed() {
				t.Log("no listening CDP port")
			}
		})
	}
}

// filesNamed lists the paths (relative to dir) of entries called name.
func filesNamed(t *testing.T, dir, name string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // Chrome removed it meanwhile
			}
			return err
		}
		if d.Name() == name {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk profile: %v", err)
	}
	return out
}

// TestChrome_ProfileRemoved: while the real Chrome runs its profile is a
// private 0700 directory under the pool base; after Close it is gone, Done
// is closed and no process of the browser's tree is left.
func TestChrome_ProfileRemoved(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	r := newChromeRig(t, nil)
	b := r.launch(ctx)
	profile := b.ProfileDir()
	if filepath.Dir(profile) != r.pool.Base() {
		t.Errorf("profile %s is not directly under the pool base %s", profile, r.pool.Base())
	}
	assertPrivateDir(t, profile)
	tree := processTree(t, browserPidByProfile(t, profile))

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !isClosed(b.Done()) {
		t.Error("Done not closed when Close returned")
	}
	assertGone(t, profile)
	for _, pid := range tree {
		if !waitGone(pid) {
			t.Errorf("pid %d of Chrome's tree survived Close", pid)
		}
	}
	if left := profileEntries(t, r.pool.Base()); len(left) != 0 {
		t.Errorf("pool base still holds %q", left)
	}
	if !t.Failed() {
		t.Log("profile removed")
	}
}

// TestChrome_RealBrowserExitsWhenParentDies: a facto process SIGKILLed
// while the real Chrome runs (no cleanup code) leaves no Chrome process
// behind, and the next pool on the same state dir sweeps the stale
// profile (A12). The fake-browser twin is TestChrome_ExitsWhenParentDies.
func TestChrome_RealBrowserExitsWhenParentDies(t *testing.T) {
	t.Parallel()
	exe := chromeBinary(t)
	root := t.TempDir()
	home := privateDir(t, root, "home")
	state := privateDir(t, root, "state")
	owner, line := helperChild(t, modeE2EChromeOwner,
		e2eChromeEnv+"="+exe, e2eStateEnv+"="+state, e2eHomeEnv+"="+home)
	profile, ok := strings.CutPrefix(line, "profile=")
	if !ok {
		t.Fatalf("owner line = %q, want profile=<dir>", line)
	}
	browserPid := browserPidByProfile(t, profile)
	tree := processTree(t, browserPid)
	t.Cleanup(func() { _ = syscall.Kill(-browserPid, syscall.SIGKILL) })

	if err := owner.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill owner: %v", err)
	}
	_ = owner.Wait()
	for _, pid := range tree {
		if !waitGone(pid) {
			t.Errorf("pid %d of Chrome's tree survived its parent's SIGKILL", pid)
		}
	}

	p, err := browser.NewPool(t.Context(), browser.PoolConfig{Host: chromeHost(exe, home), StateDir: state})
	if err != nil {
		t.Fatalf("NewPool after the crash: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	assertGone(t, profile)
}

// TestChrome_NoCookieStoreWrittenAfterLogin (ADR 0008 "Cookies in
// memory"): a password login in the fresh browser context sets a
// persistent session cookie, readable through Cookies, yet before Close no
// file of the profile holds the cookie name or value (the Cookies SQLite
// stores host_key and name in clear, so a row would show), the typed user
// name or the typed password. Chrome commits a profile-backed cookie store
// lazily, so this scan is necessary, not sufficient: the in-memory context
// itself is asserted by the T8 unit tests (Target.createBrowserContext).
func TestChrome_NoCookieStoreWrittenAfterLogin(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	site := newFakeSite(t)
	r := newChromeRig(t, e2eStarter(site))
	b := r.launch(ctx)

	openSite(ctx, t, b, "/login", "#user")
	user, pass := secret.FromString(site.user), secret.FromString(site.pass)
	defer user.Wipe()
	defer pass.Wipe()
	if err := b.TypeSecret(ctx, "#user", user); err != nil {
		t.Fatalf("TypeSecret user: %v", err)
	}
	if err := b.TypeSecret(ctx, "#pass", pass); err != nil {
		t.Fatalf("TypeSecret password: %v", err)
	}
	if err := b.Click(ctx, "#submit"); err != nil {
		t.Fatalf("Click submit: %v", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := b.WaitVisible(wctx, "#welcome"); err != nil {
		t.Fatalf("login did not reach the welcome page: %v", err)
	}
	if _, logins := site.snapshot(); logins != 1 {
		t.Fatalf("fake site saw %d valid logins, want 1", logins)
	}
	cookies, err := b.Cookies(ctx, siteDomains)
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookie {
			found = c.Value.Expose() == site.cookieValue
		}
		c.Value.Wipe()
	}
	if !found {
		t.Fatal("session cookie not readable from the browser context: the login did not happen")
	}

	needles := []struct{ what, v string }{
		{"cookie name", sessionCookie},
		{"cookie value", site.cookieValue},
		{"typed user name", site.user},
		{"typed password", site.pass},
	}
	root, err := os.OpenRoot(b.ProfileDir())
	if err != nil {
		t.Fatalf("open profile: %v", err)
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := fs.ReadFile(root.FS(), p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, n := range needles {
			if bytes.Contains(data, []byte(n.v)) {
				t.Errorf("profile file %s holds the %s (never printed)", p, n.what)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk profile: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestFetch_OffAllowlistBlockedInPageWorkerAndNestedWorker (T9 review,
// ADR 0008 "In-browser allowlist"): the page, a dedicated worker and a
// nested worker each fetch an off-allowlist host and the loopback server
// by IP literal. All three run (their scripts load from the allowlisted
// host), every off-allowlist request fails, BlockedHosts names each host,
// and the loopback server never sees a /leak request.
func TestFetch_OffAllowlistBlockedInPageWorkerAndNestedWorker(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	site := newFakeSite(t)
	r := newChromeRig(t, e2eStarter(site))
	b := r.launch(ctx)

	if err := b.Navigate(ctx, "https://"+siteHost+"/workers"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := b.WaitVisible(wctx, "#done.page-settled.worker-settled.nested-settled"); err != nil {
		hits, _ := site.snapshot()
		t.Fatalf("page, worker and nested worker did not all report (a worker not started, or closed because Fetch could not be enabled on it): %v; hits %v; blocked %v",
			err, hits, b.BlockedHosts())
	}

	blocked := b.BlockedHosts()
	for _, tt := range []struct{ origin, host string }{
		{"page", offPageHost},
		{"dedicated worker", offWorkerHost},
		{"nested worker", offNestedHost},
	} {
		if blocked[tt.host] < 1 {
			t.Errorf("BlockedHosts[%q] = %d, want the %s's request counted (blocked = %v)", tt.host, blocked[tt.host], tt.origin, blocked)
		}
	}
	if blocked["127.0.0.1"] < 3 {
		t.Errorf("BlockedHosts[127.0.0.1] = %d, want the 3 IP-literal requests (page, worker, nested)", blocked["127.0.0.1"])
	}
	if n := site.count("/leak"); n != 0 {
		t.Errorf("loopback server got %d /leak requests, want 0: an off-allowlist request went through", n)
	}
	for _, script := range []string{"/worker.js", "/nested.js"} {
		if site.count(script) < 1 {
			t.Errorf("%s never requested: that worker did not start", script)
		}
	}
	if blocked[siteHost] != 0 {
		t.Errorf("allowlisted host counted as blocked %d times", blocked[siteHost])
	}
}

// TestFetch_WebSocketOffAllowlistBlocked (ADR 0008 "In-browser
// allowlist": Fetch alone misses WebSockets): from an allowlisted page, a
// WebSocket to an off-allowlist host, to the loopback TLS server by IP
// literal and to the plain loopback server never connects; the
// allowlisted WebSocket opens (control).
func TestFetch_WebSocketOffAllowlistBlocked(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	site := newFakeSite(t)
	r := newChromeRig(t, e2eStarter(site))
	b := r.launch(ctx)

	openSite(ctx, t, b, "/ws", "#done")
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	if err := b.WaitVisible(cctx, "#done.allowed-open"); err != nil {
		t.Errorf("allowlisted WebSocket did not open (control): %v", err)
	}
	site.mu.Lock()
	opens := site.wsAllowedOpens
	site.mu.Unlock()
	if opens < 1 {
		t.Errorf("fake site completed %d allowlisted WebSocket handshakes, want >= 1 (control)", opens)
	}
	for _, path := range []string{"/ws-off", "/ws-ip", "/ws-plain"} {
		if n := site.count(path); n != 0 {
			t.Errorf("off-allowlist WebSocket reached the loopback server: %d requests on %s", n, path)
		}
	}
}
