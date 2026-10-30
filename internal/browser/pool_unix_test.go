//go:build unix

// Pool tests (J1 T10, ADR 0008 "Teardown", decisions A6 and A12). The pool
// starts the fake browser of fakebrowser_unix_test.go through the real
// StartPipe: real processes, a real profile directory on disk.
//
// Expected API (internal/browser):
//
//	// ErrUnsafeProfileDir: a pool base directory is not private (any group
//	// or world bit), is a symlink or not a directory, cannot be resolved,
//	// or lies in (or is) a personal browser profile; or a profile directory
//	// would fall outside the pool base.
//	var ErrUnsafeProfileDir = errors.New("browser: unsafe profile directory")
//
//	// Process is a started browser. *PipeProcess satisfies it.
//	type Process interface {
//		Client() *Client
//		Pid() int
//		Done() <-chan struct{}
//		Close() error
//	}
//
//	// Starter starts Chrome for the pool. ctx is the browser's lifetime
//	// (the Launch or RelaunchVisible context). On error it returns a nil
//	// Process and has started nothing.
//	type Starter func(ctx context.Context, cmd Command) (Process, error)
//
//	// StartPipeProcess (unix) is the production Starter: StartPipe.
//	func StartPipeProcess(ctx context.Context, cmd Command) (Process, error)
//
//	type PoolConfig struct {
//		Host        Host   // Executable, Geteuid, LookupEnv, Log; HOME and
//		                   // XDG_RUNTIME_DIR are read through Host.LookupEnv
//		StateDir    string // absolute; fallback base <StateDir>/tmp (A12)
//		Interactive bool   // Env.Interactive: Visible honoured only when true (A6)
//		Start       Starter
//		// PidAlive reports whether pid runs (stale-profile sweep). Nil: a
//		// signal-0 probe (EPERM counts as alive). Never called with pid <= 0.
//		PidAlive func(pid int) bool
//	}
//
//	// NewPool picks the base directory: <XDG_RUNTIME_DIR>/facto when
//	// XDG_RUNTIME_DIR is set and absolute, else <StateDir>/tmp. A missing
//	// base is created 0700 through fsx; an existing one must be a real,
//	// private directory, otherwise ErrUnsafeProfileDir (never chmodded,
//	// never followed). A base equal to or inside a personal browser profile
//	// under HOME (~/.config/google-chrome, ~/.config/chromium,
//	// ~/Library/Application Support/Google/Chrome…) is refused with
//	// ErrUnsafeProfileDir. Then it sweeps stale profiles in BOTH
//	// <XDG_RUNTIME_DIR>/facto and <StateDir>/tmp (those that exist): an
//	// entry named profile-<pid>-<random> (pid a positive decimal) whose pid
//	// is not alive is removed with fsx.RemoveTree (symlinks never
//	// followed); live pids and every other name are kept.
//	func NewPool(ctx context.Context, cfg PoolConfig) (*Pool, error)
//
//	func (p *Pool) Base() string
//
//	// Launch implements connector.BrowserPool. Visible && !Interactive
//	// returns an error wrapping connector.ErrNeedsLogin and creates
//	// nothing. Otherwise: a fresh 0700 profile
//	// fsx.MkdirTempPrivate(Base(), "profile-<os.Getpid()>-*"), Prepare
//	// (Options.ProfileDir = profile, headless unless visible), Start(ctx,
//	// cmd), NewPage. Any failure kills the browser (reaped) and removes the
//	// profile before Launch returns. Errors wrap the Prepare / Start / CDP
//	// sentinels (ErrRunAsRoot, ErrInvalidDomain, ErrLaunchFailed, ErrCDP…).
//	func (p *Pool) Launch(ctx context.Context, opts connector.LaunchOptions) (connector.Browser, error)
//
//	// Close tears down every browser still leased (killed, reaped,
//	// profile removed) and waits for it. Idempotent.
//	func (p *Pool) Close() error
//
//	// PoolBrowser is what Launch returns (a connector.Browser).
//	type PoolBrowser struct{ ... }
//	func (b *PoolBrowser) ProfileDir() string
//	// Done is closed once the lease is over: browser reaped and profile
//	// removed, whatever ended it (Close, ctx cancel, crash, Pool.Close).
//	func (b *PoolBrowser) Done() <-chan struct{}
//	// RelaunchVisible kills the current (headless) browser WITHOUT removing
//	// the profile, starts a visible one on the same profile with ctx as
//	// its lifetime and opens a new page. Non-interactive pool: error
//	// wrapping connector.ErrNeedsLogin, nothing changes.
//	func (b *PoolBrowser) RelaunchVisible(ctx context.Context) error
//	// Close: page closed, browser killed and reaped, profile removed,
//	// before it returns. Idempotent.
//	func (b *PoolBrowser) Close() error
package browser_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
)

var (
	_ connector.BrowserPool = (*browser.Pool)(nil)
	_ connector.Browser     = (*browser.PoolBrowser)(nil)
	_ browser.Process       = (*browser.PipeProcess)(nil)
	_ browser.Starter       = browser.StartPipeProcess
)

const headlessFlag = "--headless=new"

// started is one Start call seen by the rig.
type started struct {
	cmd  browser.Command // as the pool built it (before the rig's rewrite)
	proc *browser.PipeProcess
}

// poolRig owns a private temp tree (home, state, run) and a Starter that
// records each Command and runs the fake browser instead of Chrome.
type poolRig struct {
	t           *testing.T
	root, home  string
	state, xdg  string // xdg "" = XDG_RUNTIME_DIR unset
	page        string // fakePageEnv value for the fake
	startErr    error  // returned by Start without starting anything
	euid        int
	executable  string
	interactive bool
	pidAlive    func(int) bool
	mu          sync.Mutex
	starts      []started
}

func newRig(t *testing.T) *poolRig {
	t.Helper()
	root := t.TempDir() // 0700
	r := &poolRig{t: t, root: root, euid: 1000, executable: fakeExecutable(t)}
	r.home = privateDir(t, root, "home")
	r.state = privateDir(t, root, "state")
	r.xdg = privateDir(t, root, "run")
	return r
}

// privateDir creates parent/name with mode 0700 and returns its path.
func privateDir(t *testing.T, parent, name string) string {
	t.Helper()
	root, err := fsx.Open(parent)
	if err != nil {
		t.Fatalf("fsx.Open(%s): %v", parent, err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(filepath.ToSlash(name)); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	return filepath.Join(parent, name)
}

func (r *poolRig) start(ctx context.Context, cmd browser.Command) (browser.Process, error) {
	r.mu.Lock()
	idx := len(r.starts)
	orig := cmd
	orig.Args = slices.Clone(cmd.Args)
	orig.Env = slices.Clone(cmd.Env)
	r.starts = append(r.starts, started{cmd: orig})
	r.mu.Unlock()
	if r.startErr != nil {
		return nil, r.startErr
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("executable: %w", err)
	}
	cmd.Path = exe
	cmd.Env = append(slices.Clone(cmd.Env), fakeModeEnv+"="+modeCDP)
	if r.page != "" {
		cmd.Env = append(cmd.Env, fakePageEnv+"="+r.page)
	}
	p, err := browser.StartPipe(ctx, cmd)
	if err != nil {
		return nil, err
	}
	pid := p.Pid()
	r.t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	r.mu.Lock()
	r.starts[idx].proc = p
	r.mu.Unlock()
	return p, nil
}

func (r *poolRig) startsSnapshot() []started {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.starts)
}

func (r *poolRig) config() browser.PoolConfig {
	env := map[string]string{"HOME": r.home, "PATH": "/usr/bin:/bin"}
	if r.xdg != "" {
		env["XDG_RUNTIME_DIR"] = r.xdg
	}
	euid := r.euid
	return browser.PoolConfig{
		Host: browser.Host{
			Executable: r.executable,
			Geteuid:    func() int { return euid },
			LookupEnv:  mapLookup(env),
			Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		StateDir:    r.state,
		Interactive: r.interactive,
		Start:       r.start,
		PidAlive:    r.pidAlive,
	}
}

func (r *poolRig) pool() *browser.Pool {
	r.t.Helper()
	p, err := browser.NewPool(r.t.Context(), r.config())
	if err != nil {
		r.t.Fatalf("NewPool: %v", err)
	}
	r.t.Cleanup(func() { _ = p.Close() })
	return p
}

func launchOK(ctx context.Context, t *testing.T, p *browser.Pool) *browser.PoolBrowser {
	t.Helper()
	b, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: testDomains})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	pb, ok := b.(*browser.PoolBrowser)
	if !ok {
		t.Fatalf("Launch returned %T, want *browser.PoolBrowser", b)
	}
	closeAtCleanup(t, pb)
	return pb
}

// closeAtCleanup closes b when the test ends (no context in scope: Close
// takes none).
func closeAtCleanup(t *testing.T, b connector.Browser) {
	t.Helper()
	t.Cleanup(func() { _ = b.Close() })
}

// userDataDir returns the single --user-data-dir value of args.
func userDataDir(t *testing.T, args []string) string {
	t.Helper()
	var dirs []string
	for _, a := range args {
		if strings.HasPrefix(strings.ToLower(strings.TrimLeft(a, "-")), "user-data-dir") {
			v, _ := strings.CutPrefix(a, "--user-data-dir=")
			dirs = append(dirs, v)
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("user-data-dir switches = %q, want exactly one", dirs)
	}
	return dirs[0]
}

func lastPid(t *testing.T, r *poolRig) int {
	t.Helper()
	s := r.startsSnapshot()
	if len(s) == 0 || s[len(s)-1].proc == nil {
		t.Fatal("no browser started")
	}
	return s[len(s)-1].proc.Pid()
}

func assertGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s still present (Lstat err = %v), want removed", path, err)
	}
}

func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("%s: %v, want present", path, err)
	}
}

func assertPrivateDir(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("%s mode %v, want a real directory", path, fi.Mode())
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("%s perm %#o, want 0700", path, fi.Mode().Perm())
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(waitLimit):
		t.Fatalf("%s: not done within %v", what, waitLimit)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// profileEntries lists the names in base that look like pool profiles.
func profileEntries(t *testing.T, base string) []string {
	t.Helper()
	ents, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", base, err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "profile-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// outsideTarget creates a private directory outside the pool with one file,
// and returns the directory and the file.
func outsideTarget(t *testing.T, r *poolRig, name string) (dir, file string) {
	t.Helper()
	dir = privateDir(t, r.root, name)
	return dir, writeTestFile(t, dir, "keep", []byte("must survive"))
}

func TestPool_ProfileIs0700WhileRunning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		xdg      bool
		wantBase func(r *poolRig) string
	}{
		{name: "XDG_RUNTIME_DIR set", xdg: true, wantBase: func(r *poolRig) string { return filepath.Join(r.xdg, "facto") }},
		{name: "XDG_RUNTIME_DIR unset", xdg: false, wantBase: func(r *poolRig) string { return filepath.Join(r.state, "tmp") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			if !tc.xdg {
				r.xdg = ""
			}
			p := r.pool()
			want := tc.wantBase(r)
			if p.Base() != want {
				t.Fatalf("Base() = %q, want %q", p.Base(), want)
			}
			assertPrivateDir(t, want)

			b := launchOK(t.Context(), t, p)
			s := r.startsSnapshot()
			if len(s) != 1 {
				t.Fatalf("%d starts, want 1", len(s))
			}
			prof := userDataDir(t, s[0].cmd.Args)
			if b.ProfileDir() != prof {
				t.Errorf("ProfileDir() = %q, Chrome got --user-data-dir=%q", b.ProfileDir(), prof)
			}
			if filepath.Dir(prof) != want {
				t.Errorf("profile %q is not a direct child of the base %q", prof, want)
			}
			prefix := "profile-" + strconv.Itoa(os.Getpid()) + "-"
			if base := filepath.Base(prof); !strings.HasPrefix(base, prefix) || len(base) == len(prefix) {
				t.Errorf("profile name %q, want %s<random>", base, prefix)
			}
			assertPrivateDir(t, prof)
			// The browser really runs on it: the fake wrote its cookie store.
			assertPresent(t, filepath.Join(prof, filepath.FromSlash(fakeProfileFile)))
			if pid := s[0].proc.Pid(); processGone(pid) {
				t.Errorf("browser %d not running after Launch", pid)
			}
			if isClosed(b.Done()) {
				t.Error("Done closed while the browser runs")
			}
		})
	}
}

func TestPool_ProfileRemovedOnClose(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	prof, pid := b.ProfileDir(), lastPid(t, r)

	// Something in the profile points outside: removal must not follow it.
	outDir, outFile := outsideTarget(t, r, "outside")
	if err := os.Symlink(outDir, filepath.Join(prof, "escape")); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Synchronous: no wait, no polling.
	if !processGone(pid) {
		t.Errorf("browser %d still running after Close returned", pid)
	}
	assertGone(t, prof)
	assertPresent(t, outFile)
	assertPrivateDir(t, p.Base())
	if !isClosed(b.Done()) {
		t.Error("Done not closed after Close returned")
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

func TestPool_ProfileRemovedOnContextCancel(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.pool()
	ctx, cancel := context.WithCancel(t.Context())
	b := launchOK(ctx, t, p)
	prof, pid := b.ProfileDir(), lastPid(t, r)

	cancel()
	waitClosed(t, b.Done(), "lease after context cancel")
	if !processGone(pid) {
		t.Errorf("browser %d still running after its context ended", pid)
	}
	assertGone(t, prof)
}

func TestPool_ProfileRemovedOnBrowserCrash(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	prof, pid := b.ProfileDir(), lastPid(t, r)

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, b.Done(), "lease after browser crash")
	assertGone(t, prof)
	if err := b.Navigate(t.Context(), "https://login.supplier.example/"); !errors.Is(err, browser.ErrBrowserGone) {
		t.Errorf("Navigate after crash = %v, want ErrBrowserGone", err)
	}
}

// launchThenPanic runs Launch and then panics inside fn's frame, the way a
// buggy connector would, and recovers like the orchestrator boundary. It
// returns the profile and pid of the leaked-or-not browser.
func launchThenPanic(ctx context.Context, t *testing.T, p *browser.Pool, deferClose bool) (prof string, done <-chan struct{}) {
	t.Helper()
	recovered := func() (rec any) {
		defer func() { rec = recover() }()
		b, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: testDomains})
		if err != nil {
			t.Fatalf("Launch: %v", err)
		}
		pb, ok := b.(*browser.PoolBrowser)
		if !ok {
			t.Fatalf("Launch returned %T", b)
		}
		prof, done = pb.ProfileDir(), pb.Done()
		if deferClose {
			defer func() { _ = b.Close() }()
		}
		panic("connector bug")
	}()
	if recovered == nil {
		t.Fatal("panic not raised")
	}
	return prof, done
}

func TestPool_ProfileRemovedOnPanicInCaller(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		deferClose bool
		// boundary is what the orchestrator does after recovering.
		boundary func(cancel context.CancelFunc, p *browser.Pool) error
		// sync: the profile must be gone as soon as the boundary returns.
		sync bool
	}{
		{name: "caller defers Close", deferClose: true, boundary: func(context.CancelFunc, *browser.Pool) error { return nil }, sync: true},
		{name: "caller leaks, boundary cancels the login context", boundary: func(c context.CancelFunc, _ *browser.Pool) error { c(); return nil }},
		{name: "caller leaks, boundary closes the pool", boundary: func(_ context.CancelFunc, p *browser.Pool) error { return p.Close() }, sync: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			p := r.pool()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			prof, done := launchThenPanic(ctx, t, p, tc.deferClose)
			pid := lastPid(t, r)
			if err := tc.boundary(cancel, p); err != nil {
				t.Fatalf("boundary: %v", err)
			}
			if tc.sync {
				if !isClosed(done) {
					t.Error("lease not over when the boundary returned")
				}
			} else {
				waitClosed(t, done, "lease after panic")
			}
			if !processGone(pid) {
				t.Errorf("browser %d still running after the panic was handled", pid)
			}
			assertGone(t, prof)
		})
	}
}

// deadPid returns the pid of a child that has exited and been reaped.
func deadPid(t *testing.T) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.CommandContext(t.Context(), exe) //nolint:gosec // re-executes this test binary
	c.Env = []string{fakeModeEnv + "=no-such-mode"}
	_ = c.Run() // exits 2
	if c.ProcessState == nil {
		t.Fatal("helper did not run")
	}
	return c.ProcessState.Pid()
}

// staleTree fills base with pool-looking and unrelated entries.
type staleTree struct {
	live, dead, deadLink            string // entry paths in base
	deadInnerTarget, deadLinkFile   string // files outside that must survive
	keepNotes, keepBadPid, keepPid0 string
	keepNegPid                      string
}

func fillStale(t *testing.T, r *poolRig, base string, livePid, deadPidN int) staleTree {
	t.Helper()
	var s staleTree
	s.live = privateDir(t, base, fmt.Sprintf("profile-%d-aaaa", livePid))
	writeTestFile(t, s.live, "Cookies", []byte("live"))

	s.dead = privateDir(t, base, fmt.Sprintf("profile-%d-bbbb", deadPidN))
	privateDir(t, s.dead, "Default")
	writeTestFile(t, filepath.Join(s.dead, "Default"), "Cookies", []byte("stale"))
	innerDir, innerFile := outsideTarget(t, r, "inner-target-"+filepath.Base(filepath.Dir(base))+filepath.Base(base))
	if err := os.Symlink(innerDir, filepath.Join(s.dead, "escape")); err != nil {
		t.Fatal(err)
	}
	s.deadInnerTarget = innerFile

	// A dead-looking entry that is itself a symlink to a directory outside.
	linkDir, linkFile := outsideTarget(t, r, "link-target-"+filepath.Base(filepath.Dir(base))+filepath.Base(base))
	s.deadLink = filepath.Join(base, fmt.Sprintf("profile-%d-cccc", deadPidN))
	if err := os.Symlink(linkDir, s.deadLink); err != nil {
		t.Fatal(err)
	}
	s.deadLinkFile = linkFile

	s.keepNotes = privateDir(t, base, "notes")
	s.keepBadPid = privateDir(t, base, "profile-abc-dddd")
	s.keepPid0 = privateDir(t, base, "profile-0-eeee")
	s.keepNegPid = privateDir(t, base, "profile--1-ffff")
	return s
}

func checkSwept(t *testing.T, s staleTree) {
	t.Helper()
	assertPresent(t, filepath.Join(s.live, "Cookies"))
	assertGone(t, s.dead)
	assertPresent(t, s.deadInnerTarget)
	assertPresent(t, s.deadLinkFile)
	for _, k := range []string{s.keepNotes, s.keepBadPid, s.keepPid0, s.keepNegPid} {
		assertPresent(t, k)
	}
}

func TestPool_StaleProfilesSweptAtStartup(t *testing.T) {
	t.Parallel()
	const live, dead = 4001, 4002

	t.Run("both base dirs swept, live pids kept", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		var mu sync.Mutex
		var asked []int
		r.pidAlive = func(pid int) bool {
			mu.Lock()
			asked = append(asked, pid)
			mu.Unlock()
			return pid == live
		}
		xdgBase := privateDir(t, r.xdg, "facto")
		stateBase := privateDir(t, r.state, "tmp")
		sx := fillStale(t, r, xdgBase, live, dead)
		ss := fillStale(t, r, stateBase, live, dead)

		p := r.pool()
		if p.Base() != xdgBase {
			t.Errorf("Base() = %q, want %q", p.Base(), xdgBase)
		}
		checkSwept(t, sx)
		checkSwept(t, ss)
		mu.Lock()
		defer mu.Unlock()
		for _, pid := range asked {
			if pid <= 0 {
				t.Errorf("PidAlive(%d) called: a non-positive pid probes a process group or every process", pid)
			}
		}
		if !slices.Contains(asked, live) || !slices.Contains(asked, dead) {
			t.Errorf("PidAlive asked %v, want both %d and %d", asked, live, dead)
		}
	})

	t.Run("XDG_RUNTIME_DIR unset: state tmp swept", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.xdg = ""
		r.pidAlive = func(pid int) bool { return pid == live }
		stateBase := privateDir(t, r.state, "tmp")
		ss := fillStale(t, r, stateBase, live, dead)
		r.pool()
		checkSwept(t, ss)
	})

	t.Run("default probe: own pid kept, reaped pid removed", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		base := privateDir(t, r.xdg, "facto")
		mine := privateDir(t, base, fmt.Sprintf("profile-%d-mine", os.Getpid()))
		gone := privateDir(t, base, fmt.Sprintf("profile-%d-gone", deadPid(t)))
		r.pool()
		assertPresent(t, mine)
		assertGone(t, gone)
	})
}

func TestPool_RefusesPersonalProfilePaths(t *testing.T) {
	t.Parallel()
	personal := []string{
		".config/google-chrome",
		".config/google-chrome-beta",
		".config/google-chrome-unstable",
		".config/chromium",
		".config/google-chrome-for-testing",
		".config/BraveSoftware/Brave-Browser",
		".config/microsoft-edge",
		"Library/Application Support/Google/Chrome",
		"Library/Application Support/Chromium",
		"snap/chromium/common/chromium",
		".var/app/com.google.Chrome",
	}
	for _, rel := range personal {
		t.Run("state dir in "+rel, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			r.xdg = ""
			r.state = privateDir(t, r.home, filepath.FromSlash(rel+"/facto-state"))
			p, err := browser.NewPool(t.Context(), r.config())
			if !errors.Is(err, browser.ErrUnsafeProfileDir) || p != nil {
				t.Fatalf("NewPool(state in %s) = %v, %v; want nil, ErrUnsafeProfileDir", rel, p, err)
			}
			assertGone(t, filepath.Join(r.state, "tmp"))
		})
		t.Run("XDG_RUNTIME_DIR is "+rel, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			r.xdg = privateDir(t, r.home, filepath.FromSlash(rel))
			p, err := browser.NewPool(t.Context(), r.config())
			if !errors.Is(err, browser.ErrUnsafeProfileDir) || p != nil {
				t.Fatalf("NewPool(XDG_RUNTIME_DIR=%s) = %v, %v; want nil, ErrUnsafeProfileDir", rel, p, err)
			}
			assertGone(t, filepath.Join(r.xdg, "facto"))
		})
	}

	t.Run("base symlinked into a personal profile", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.xdg = ""
		chrome := privateDir(t, r.home, filepath.FromSlash(".config/google-chrome"))
		writeTestFile(t, chrome, "Local State", []byte("{}"))
		if err := os.Symlink(chrome, filepath.Join(r.state, "tmp")); err != nil {
			t.Fatal(err)
		}
		p, err := browser.NewPool(t.Context(), r.config())
		if !errors.Is(err, browser.ErrUnsafeProfileDir) || p != nil {
			t.Fatalf("NewPool(tmp -> google-chrome) = %v, %v; want nil, ErrUnsafeProfileDir", p, err)
		}
		assertPresent(t, filepath.Join(chrome, "Local State"))
	})

	t.Run("Chrome only ever gets a profile inside the pool base", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.interactive = true
		p := r.pool()
		b := launchOK(t.Context(), t, p)
		if err := b.RelaunchVisible(t.Context()); err != nil {
			t.Fatalf("RelaunchVisible: %v", err)
		}
		for i, s := range r.startsSnapshot() {
			dir := userDataDir(t, s.cmd.Args)
			if filepath.Dir(dir) != p.Base() || !strings.HasPrefix(filepath.Base(dir), "profile-") {
				t.Errorf("start %d: --user-data-dir=%q is not a pool profile under %q", i, dir, p.Base())
			}
			if strings.HasPrefix(dir, r.home+string(filepath.Separator)) {
				t.Errorf("start %d: --user-data-dir=%q under HOME", i, dir)
			}
		}
	})
}

func TestPool_VisibleOnlyWhenInteractive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		interactive, visible bool
		wantHeadless         bool
		wantErr              error
	}{
		{name: "non-interactive headless", wantHeadless: true},
		{name: "interactive headless", interactive: true, wantHeadless: true},
		{name: "interactive visible", interactive: true, visible: true, wantHeadless: false},
		{name: "non-interactive visible needs login", visible: true, wantErr: connector.ErrNeedsLogin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			r.interactive = tc.interactive
			p := r.pool()
			b, err := p.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: testDomains, Visible: tc.visible})
			if b != nil {
				t.Cleanup(func() { _ = b.Close() })
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || b != nil {
					t.Fatalf("Launch = %v, %v; want nil, %v", b, err, tc.wantErr)
				}
				if n := len(r.startsSnapshot()); n != 0 {
					t.Errorf("%d browsers started, want 0", n)
				}
				if e := profileEntries(t, p.Base()); len(e) != 0 {
					t.Errorf("profiles left in base: %q", e)
				}
				return
			}
			if err != nil {
				t.Fatalf("Launch: %v", err)
			}
			s := r.startsSnapshot()
			if len(s) != 1 {
				t.Fatalf("%d starts, want 1", len(s))
			}
			if got := slices.Contains(s[0].cmd.Args, headlessFlag); got != tc.wantHeadless {
				t.Errorf("%s in argv = %v, want %v (argv %q)", headlessFlag, got, tc.wantHeadless, s[0].cmd.Args)
			}
		})
	}
}

func TestPool_RelaunchVisibleKeepsProfile(t *testing.T) {
	t.Parallel()

	t.Run("interactive", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		r.interactive = true
		p := r.pool()
		b := launchOK(t.Context(), t, p)
		prof, pid1 := b.ProfileDir(), lastPid(t, r)
		marker := writeTestFile(t, prof, "login-state", []byte("half-way"))

		if err := b.RelaunchVisible(t.Context()); err != nil {
			t.Fatalf("RelaunchVisible: %v", err)
		}
		if !processGone(pid1) {
			t.Errorf("headless browser %d still running after RelaunchVisible", pid1)
		}
		s := r.startsSnapshot()
		if len(s) != 2 {
			t.Fatalf("%d starts, want 2", len(s))
		}
		if !slices.Contains(s[0].cmd.Args, headlessFlag) {
			t.Errorf("first launch not headless: %q", s[0].cmd.Args)
		}
		if slices.Contains(s[1].cmd.Args, headlessFlag) {
			t.Errorf("relaunch still headless: %q", s[1].cmd.Args)
		}
		if got := userDataDir(t, s[1].cmd.Args); got != prof {
			t.Errorf("relaunch --user-data-dir=%q, want the same profile %q", got, prof)
		}
		if b.ProfileDir() != prof {
			t.Errorf("ProfileDir() = %q after relaunch, want %q", b.ProfileDir(), prof)
		}
		assertPrivateDir(t, prof)
		assertPresent(t, marker)
		pid2 := s[1].proc.Pid()
		if pid2 == pid1 || processGone(pid2) {
			t.Errorf("visible browser pid %d (headless was %d) not running", pid2, pid1)
		}
		if isClosed(b.Done()) {
			t.Error("lease ended by the relaunch")
		}

		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !processGone(pid2) {
			t.Errorf("visible browser %d still running after Close", pid2)
		}
		assertGone(t, prof)
	})

	t.Run("non-interactive needs login", func(t *testing.T) {
		t.Parallel()
		r := newRig(t)
		p := r.pool()
		b := launchOK(t.Context(), t, p)
		prof, pid := b.ProfileDir(), lastPid(t, r)
		if err := b.RelaunchVisible(t.Context()); !errors.Is(err, connector.ErrNeedsLogin) {
			t.Errorf("RelaunchVisible = %v, want ErrNeedsLogin", err)
		}
		if n := len(r.startsSnapshot()); n != 1 {
			t.Errorf("%d starts, want 1", n)
		}
		if processGone(pid) {
			t.Error("headless browser killed by a refused relaunch")
		}
		assertPrivateDir(t, prof)
	})
}

func TestPool_BaseDirMustBePrivate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup prepares r and returns the expected base ("" when refused).
		setup   func(t *testing.T, r *poolRig) string
		wantErr bool
	}{
		{name: "xdg facto missing is created 0700", setup: func(_ *testing.T, r *poolRig) string {
			return filepath.Join(r.xdg, "facto")
		}},
		{name: "state tmp missing is created 0700", setup: func(_ *testing.T, r *poolRig) string {
			r.xdg = ""
			return filepath.Join(r.state, "tmp")
		}},
		{name: "relative XDG_RUNTIME_DIR ignored", setup: func(_ *testing.T, r *poolRig) string {
			r.xdg = "run"
			return filepath.Join(r.state, "tmp")
		}},
		{name: "existing private xdg facto reused", setup: func(t *testing.T, r *poolRig) string {
			return privateDir(t, r.xdg, "facto")
		}},
		{name: "xdg facto 0755", wantErr: true, setup: func(t *testing.T, r *poolRig) string {
			setMode(t, privateDir(t, r.xdg, "facto"), 0o755)
			return ""
		}},
		{name: "xdg facto 0710", wantErr: true, setup: func(t *testing.T, r *poolRig) string {
			setMode(t, privateDir(t, r.xdg, "facto"), 0o710)
			return ""
		}},
		{name: "state tmp 0750", wantErr: true, setup: func(t *testing.T, r *poolRig) string {
			r.xdg = ""
			setMode(t, privateDir(t, r.state, "tmp"), 0o750)
			return ""
		}},
		{name: "xdg facto symlink to a private dir", wantErr: true, setup: func(t *testing.T, r *poolRig) string {
			other := privateDir(t, r.root, "elsewhere")
			if err := os.Symlink(other, filepath.Join(r.xdg, "facto")); err != nil {
				t.Fatal(err)
			}
			return ""
		}},
		{name: "state tmp is a regular file", wantErr: true, setup: func(t *testing.T, r *poolRig) string {
			r.xdg = ""
			writeTestFile(t, r.state, "tmp", []byte("x"))
			return ""
		}},
		{name: "no XDG_RUNTIME_DIR and relative state dir", wantErr: true, setup: func(_ *testing.T, r *poolRig) string {
			r.xdg = ""
			r.state = "state"
			return ""
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			want := tc.setup(t, r)
			p, err := browser.NewPool(t.Context(), r.config())
			if tc.wantErr {
				if !errors.Is(err, browser.ErrUnsafeProfileDir) || p != nil {
					t.Fatalf("NewPool = %v, %v; want nil, ErrUnsafeProfileDir", p, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPool: %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
			if p.Base() != want {
				t.Errorf("Base() = %q, want %q", p.Base(), want)
			}
			assertPrivateDir(t, want)
		})
	}
}

func TestPool_LaunchErrorRemovesProfile(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name    string
		setup   func(r *poolRig)
		ctx     context.Context
		domains []string
		wantErr error
	}{
		{name: "start fails", setup: func(r *poolRig) { r.startErr = errors.New("exec: boom") }, wantErr: browser.ErrLaunchFailed},
		{name: "run as root", setup: func(r *poolRig) { r.euid = 0 }, wantErr: browser.ErrRunAsRoot},
		{name: "unsafe executable", setup: func(r *poolRig) { r.executable = "chrome" }, wantErr: browser.ErrUnsafeExecutable},
		{name: "invalid allowed domain", domains: []string{"127.0.0.1"}, wantErr: browser.ErrInvalidDomain},
		{name: "context already cancelled", ctx: cancelled, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			if tc.setup != nil {
				tc.setup(r)
			}
			p := r.pool()
			ctx := tc.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			domains := tc.domains
			if domains == nil {
				domains = testDomains
			}
			b, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: domains})
			if b != nil {
				_ = b.Close()
				t.Fatalf("Launch returned a browser despite %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Launch = %v, want %v", err, tc.wantErr)
			}
			if e := profileEntries(t, p.Base()); len(e) != 0 {
				t.Errorf("profiles left after a failed Launch: %q", e)
			}
		})
	}
}

func TestPool_BrowserClosedBeforeReturnOnSetupFailure(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.page = pageFailContext
	p := r.pool()
	b, err := p.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: testDomains})
	if b != nil {
		_ = b.Close()
		t.Fatal("Launch returned a browser although page setup failed")
	}
	if !errors.Is(err, browser.ErrCDP) {
		t.Errorf("Launch = %v, want ErrCDP from the page setup", err)
	}
	s := r.startsSnapshot()
	if len(s) != 1 || s[0].proc == nil {
		t.Fatalf("starts = %d, want 1 started browser", len(s))
	}
	// Checked right away: Launch must have killed and reaped it already.
	if pid := s[0].proc.Pid(); !processGone(pid) {
		t.Errorf("browser %d still running when Launch returned", pid)
	}
	if !isClosed(s[0].proc.Done()) {
		t.Error("browser not reaped when Launch returned")
	}
	assertGone(t, userDataDir(t, s[0].cmd.Args))
	if e := profileEntries(t, p.Base()); len(e) != 0 {
		t.Errorf("profiles left: %q", e)
	}
}

func TestPool_ConcurrentLaunchesGetDistinctProfiles(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.pool()
	const n = 3
	var wg sync.WaitGroup
	got := make([]*browser.PoolBrowser, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			b, err := p.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: testDomains})
			errs[i] = err
			if pb, ok := b.(*browser.PoolBrowser); ok {
				got[i] = pb
			}
		})
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := range n {
		if errs[i] != nil || got[i] == nil {
			t.Fatalf("Launch %d: %v", i, errs[i])
		}
		t.Cleanup(func() { _ = got[i].Close() })
		if seen[got[i].ProfileDir()] {
			t.Errorf("profile %q handed out twice", got[i].ProfileDir())
		}
		seen[got[i].ProfileDir()] = true
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Pool.Close: %v", err)
	}
	for i := range n {
		if !isClosed(got[i].Done()) {
			t.Errorf("lease %d not over after Pool.Close", i)
		}
		assertGone(t, got[i].ProfileDir())
	}
}
