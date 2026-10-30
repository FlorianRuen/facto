package browser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// ErrUnsafeProfileDir reports that a pool base directory is not private (any group or
// world bit), is a symlink or not a directory, cannot be resolved, or lies
// in (or is) a personal browser profile; or a profile directory would fall
// outside the pool base.
var ErrUnsafeProfileDir = errors.New("browser: unsafe profile directory")

// Pool base directory names (A12).
const (
	runtimeSubdir = "facto" // <XDG_RUNTIME_DIR>/facto
	stateSubdir   = "tmp"   // <StateDir>/tmp
	profilePrefix = "profile-"
)

// personalProfiles are the browser profile directories, relative to HOME,
// a pool base must never be (or lie in). Prefixes cover the channels and
// vendors next to each (Chrome Beta, Canary, for Testing…).
var personalProfiles = []string{
	".config/google-chrome",
	".config/google-chrome-beta",
	".config/google-chrome-unstable",
	".config/google-chrome-for-testing",
	".config/chromium",
	".config/BraveSoftware",
	".config/microsoft-edge",
	".config/microsoft-edge-beta",
	".config/microsoft-edge-dev",
	".config/vivaldi",
	".config/opera",
	"Library/Application Support/Google",
	"Library/Application Support/Chromium",
	"Library/Application Support/BraveSoftware",
	"Library/Application Support/Microsoft Edge",
	"snap/chromium",
	".var/app/com.google.Chrome",
	".var/app/org.chromium.Chromium",
	"AppData/Local/Google",
	"AppData/Local/Chromium",
	"AppData/Local/Microsoft/Edge",
}

// Process is a started browser. *PipeProcess satisfies it.
type Process interface {
	Client() *Client
	Pid() int
	Done() <-chan struct{}
	Close() error
}

// Starter starts Chrome for the pool. ctx is the browser's lifetime (the
// Launch or RelaunchVisible context). On error it returns a nil Process and
// has started nothing.
type Starter func(ctx context.Context, cmd Command) (Process, error)

// PoolConfig configures NewPool.
type PoolConfig struct {
	// Host: Executable, Geteuid, LookupEnv, Log. HOME and XDG_RUNTIME_DIR
	// are read through Host.LookupEnv.
	Host Host
	// StateDir is absolute; the fallback base is <StateDir>/tmp (A12).
	StateDir string
	// Interactive is Env.Interactive: Visible is honoured only when true (A6).
	Interactive bool
	// Start starts Chrome. Nil: StartPipeProcess where the pipe exists.
	Start Starter
	// PidAlive reports whether pid runs (stale-profile sweep). Nil: a
	// signal-0 probe (EPERM counts as alive). Never called with pid <= 0.
	PidAlive func(pid int) bool
	// CloseGrace is how long Close waits for in-flight Launches before it
	// cancels the pool context that bounds every browser lifetime. Zero:
	// defaultCloseGrace.
	CloseGrace time.Duration
}

// defaultCloseGrace bounds how long Pool.Close lets an in-flight Launch
// finish on its own (the Windows connect is bounded at portConnectTimeout).
const defaultCloseGrace = 10 * time.Second

// Pool hands out browsers, each on a fresh 0700 profile under Base() that
// is removed once the browser is reaped (ADR 0008 "Teardown"). It
// implements connector.BrowserPool.
type Pool struct {
	host        Host
	log         *slog.Logger
	base        string
	interactive bool
	start       Starter

	mu     sync.Mutex
	closed bool
	leases map[*PoolBrowser]struct{}

	// inflight counts the Launches past the closed check; Close waits for
	// them, so no browser outlives the pool.
	inflight sync.WaitGroup
	// ctx bounds every browser lifetime of the pool, whatever the Launch
	// context: Close cancels it once closeGrace has elapsed (and on return).
	ctx        context.Context
	cancel     context.CancelFunc
	closeGrace time.Duration
}

var _ connector.BrowserPool = (*Pool)(nil)

// NewPool picks the base directory: <XDG_RUNTIME_DIR>/facto when
// XDG_RUNTIME_DIR is set and absolute, else <StateDir>/tmp. A missing base
// is created 0700 through fsx; an existing one must be a real, private
// directory, otherwise ErrUnsafeProfileDir (never chmodded, never
// followed). A base equal to or inside a personal browser profile under
// HOME is refused with ErrUnsafeProfileDir. On unix, XDG_RUNTIME_DIR itself,
// when used, must be a real directory (Lstat, not a symlink) without any
// group or world bit, owned by Host.Geteuid(); and the chosen base must be
// owned by Host.Geteuid() exactly (Host.Owner; root is foreign too).
// Otherwise ErrUnsafeProfileDir, with no fallback to <StateDir>/tmp. Then it
// sweeps stale profiles
// in both <XDG_RUNTIME_DIR>/facto and <StateDir>/tmp (those that exist): an
// entry named profile-<pid>-<random> (pid a positive decimal) whose pid is
// not alive is removed with fsx.RemoveTree (symlinks never followed); live
// pids and every other name are kept.
func NewPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("browser pool: %w", err)
	}
	lookup := cfg.Host.LookupEnv
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	if cfg.StateDir == "" || !filepath.IsAbs(cfg.StateDir) {
		return nil, fmt.Errorf("%w: state directory must be absolute", ErrUnsafeProfileDir)
	}
	bases := []string{}
	xdg := ""
	if v, ok := lookup("XDG_RUNTIME_DIR"); ok && v != "" && filepath.IsAbs(v) {
		xdg = filepath.Clean(v)
		bases = append(bases, filepath.Join(xdg, runtimeSubdir))
	}
	bases = append(bases, filepath.Join(cfg.StateDir, stateSubdir))
	home, _ := lookup("HOME")
	for _, b := range bases {
		if err := checkNotPersonal(b, home); err != nil {
			return nil, err
		}
	}
	if xdg != "" {
		if err := checkRuntimeDir(cfg.Host, xdg); err != nil {
			return nil, err
		}
	}
	base := bases[0]
	if err := ensureBase(base); err != nil {
		return nil, err
	}
	if err := checkBaseOwner(cfg.Host, base); err != nil {
		return nil, err
	}
	p := &Pool{
		host:        cfg.Host,
		log:         logger(cfg.Host.Log),
		base:        base,
		interactive: cfg.Interactive,
		start:       cfg.Start,
		leases:      map[*PoolBrowser]struct{}{},
	}
	if p.start == nil {
		p.start = defaultStarter
	}
	p.closeGrace = cfg.CloseGrace
	if p.closeGrace <= 0 {
		p.closeGrace = defaultCloseGrace
	}
	// Not derived from NewPool's ctx, which only bounds the setup and sweep.
	p.ctx, p.cancel = context.WithCancel(context.Background())
	alive := cfg.PidAlive
	if alive == nil {
		alive = pidAlive
	}
	for _, b := range bases {
		p.sweep(ctx, b, alive)
	}
	return p, nil
}

// Base returns the directory profiles are created in.
func (p *Pool) Base() string { return p.base }

// checkNotPersonal refuses a base equal to or inside a personal browser
// profile under home, comparing both the paths as given and with every
// existing symlink resolved.
func checkNotPersonal(base, home string) error {
	if home == "" || !filepath.IsAbs(home) {
		return nil
	}
	homes := []string{filepath.Clean(home)}
	if r, err := filepath.EvalSymlinks(home); err == nil {
		homes = append(homes, r)
	}
	resolved, err := resolveExisting(base)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %w", ErrUnsafeProfileDir, base, err)
	}
	for _, h := range homes {
		for _, rel := range personalProfiles {
			dir := filepath.Join(h, filepath.FromSlash(rel))
			for _, c := range []string{filepath.Clean(base), resolved} {
				if within(c, dir) {
					return fmt.Errorf("%w: %s is in a personal browser profile", ErrUnsafeProfileDir, base)
				}
			}
		}
	}
	return nil
}

// resolveExisting resolves the symlinks of the longest existing prefix of
// path and appends the missing rest.
func resolveExisting(path string) (string, error) {
	path = filepath.Clean(path)
	var rest []string
	for dir := path; ; dir = filepath.Dir(dir) {
		r, err := filepath.EvalSymlinks(dir)
		if err == nil {
			slices.Reverse(rest)
			return filepath.Join(append([]string{r}, rest...)...), nil
		}
		if !errors.Is(err, fs.ErrNotExist) || dir == filepath.Dir(dir) {
			return "", fmt.Errorf("eval symlinks: %w", err)
		}
		rest = append(rest, filepath.Base(dir))
	}
}

// within reports whether p is dir or lies below it. Case is folded where
// the default filesystems are case-insensitive.
func within(p, dir string) bool {
	if runtime.GOOS == goosDarwin || runtime.GOOS == goosWindows {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// ensureBase creates base 0700 when missing, then requires a real private
// directory. An existing base is never chmodded nor followed.
func ensureBase(base string) error {
	if _, err := os.Lstat(base); errors.Is(err, fs.ErrNotExist) {
		parent := filepath.Dir(base)
		r, err := fsx.Open(filepath.Dir(parent))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnsafeProfileDir, err)
		}
		mkErr := r.MkdirPrivate(filepath.Base(parent) + "/" + filepath.Base(base))
		if cerr := r.Close(); mkErr == nil {
			mkErr = cerr
		}
		if mkErr != nil {
			return fmt.Errorf("%w: create %s: %w", ErrUnsafeProfileDir, base, mkErr)
		}
	}
	return checkPrivateDir(base)
}

// checkPrivateDir requires dir to be a directory (not a symlink to one)
// without group or world bits (unix).
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeProfileDir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory (mode %v)", ErrUnsafeProfileDir, dir, fi.Mode().Type())
	}
	if runtime.GOOS != goosWindows && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %#o, want 0700", ErrUnsafeProfileDir, dir, fi.Mode().Perm())
	}
	return nil
}

// sweep removes the stale profiles of base: profile-<pid>-<random>
// directories whose pid is not alive. Symlinks and other names are kept. A
// base that is missing or unsafe is left alone; failures are logged, never
// fatal.
func (p *Pool) sweep(ctx context.Context, base string, alive func(int) bool) {
	if _, err := os.Lstat(base); errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := checkPrivateDir(base); err != nil {
		p.log.WarnContext(ctx, "browser: stale profile sweep skipped", slog.String("reason", "unsafe base"))
		return
	}
	r, err := fsx.Open(base)
	if err != nil {
		p.log.WarnContext(ctx, "browser: stale profile sweep skipped", slog.String("reason", "open"))
		return
	}
	ents, err := r.ReadDir()
	_ = r.Close() // read-only root
	if err != nil {
		p.log.WarnContext(ctx, "browser: stale profile sweep skipped", slog.String("reason", "read"))
		return
	}
	removed, failed := 0, 0
	for _, e := range ents {
		pid, ok := profilePid(e.Name())
		if !ok || e.Type()&fs.ModeSymlink != 0 || !e.IsDir() || alive(pid) {
			continue
		}
		if err := fsx.RemoveTree(base, e.Name()); err != nil {
			failed++
			continue
		}
		removed++
	}
	if removed+failed > 0 {
		p.log.InfoContext(ctx, "browser: stale profiles swept",
			slog.Int("removed", removed), slog.Int("failed", failed))
	}
}

// profilePid parses profile-<pid>-<random>: pid is a positive decimal
// without sign, and the random part is not empty.
func profilePid(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, profilePrefix)
	if !ok {
		return 0, false
	}
	digits, random, ok := strings.Cut(rest, "-")
	if !ok || digits == "" || random == "" {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(digits)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// Launch implements connector.BrowserPool. Visible in a non-interactive run
// returns an error wrapping connector.ErrNeedsLogin and creates nothing.
// Otherwise: a fresh 0700 profile profile-<pid>-<random> under Base(),
// Prepare (headless unless visible), Start, NewPage. Any failure kills the
// browser (reaped) and removes the profile before Launch returns.
func (p *Pool) Launch(ctx context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	if opts.Visible && !p.interactive {
		return nil, fmt.Errorf("browser: visible launch in a non-interactive run: %w", connector.ErrNeedsLogin)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: pool closed", ErrLaunchFailed)
	}
	p.inflight.Add(1)
	p.mu.Unlock()
	defer p.inflight.Done()
	profile, err := p.newProfile()
	if err != nil {
		return nil, err
	}
	b, err := p.launchOn(ctx, profile, opts)
	if err != nil {
		return nil, errors.Join(err, p.removeProfile(profile))
	}
	p.mu.Lock()
	closed := p.closed
	if !closed {
		p.leases[b] = struct{}{}
	}
	p.mu.Unlock()
	if closed {
		return nil, errors.Join(fmt.Errorf("%w: pool closed", ErrLaunchFailed), b.teardown(ctx))
	}
	return b, nil
}

// launchOn starts the first browser of a lease on profile. On error nothing
// runs; the caller removes the profile.
func (p *Pool) launchOn(ctx context.Context, profile string, opts connector.LaunchOptions) (*PoolBrowser, error) {
	domains := slices.Clone(opts.AllowedDomains)
	cmd, err := p.prepare(profile, domains, opts.Visible)
	if err != nil {
		return nil, err
	}
	lctx, cancel := linkedContext(ctx, p.ctx)
	proc, page, err := p.startPage(lctx, cmd, domains)
	if err != nil {
		cancel()
		return nil, err
	}
	b := &PoolBrowser{
		pool: p, profile: profile, domains: domains, launchCtx: ctx,
		proc: proc, page: page, cancel: cancel,
		done: make(chan struct{}),
	}
	go b.watch(lctx, proc)
	return b, nil
}

// newProfile creates a fresh 0700 profile directory directly under the base.
func (p *Pool) newProfile() (string, error) {
	dir, err := fsx.MkdirTempPrivate(p.base, profilePrefix+strconv.Itoa(os.Getpid())+"-*")
	if err != nil {
		return "", fmt.Errorf("%w: new profile: %w", ErrUnsafeProfileDir, err)
	}
	if filepath.Dir(dir) != p.base {
		return "", errors.Join(fmt.Errorf("%w: profile outside the pool base", ErrUnsafeProfileDir), p.removeProfile(dir))
	}
	return dir, nil
}

// removeProfile deletes a profile of the base, never following a symlink.
func (p *Pool) removeProfile(dir string) error {
	if filepath.Dir(dir) != p.base {
		return fmt.Errorf("%w: profile outside the pool base", ErrUnsafeProfileDir)
	}
	if err := fsx.RemoveTree(p.base, filepath.Base(dir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.log.Warn("browser: profile removal failed")
		return fmt.Errorf("remove browser profile: %w", err)
	}
	return nil
}

// prepare builds the vetted Command for profile.
func (p *Pool) prepare(profile string, domains []string, visible bool) (Command, error) {
	return Prepare(p.host, Options{
		ProfileDir:     profile,
		AllowedDomains: domains,
		Visible:        visible,
		AllowProxy:     ProxyAllowed(p.host.LookupEnv),
	})
}

// startPage starts the browser with ctx as its lifetime and opens the login
// page. On error the browser is killed and reaped before it returns.
func (p *Pool) startPage(ctx context.Context, cmd Command, domains []string) (Process, *Page, error) {
	if p.start == nil {
		return nil, nil, fmt.Errorf("%w: no browser starter on %s", ErrLaunchFailed, runtime.GOOS)
	}
	stderr := &capWriter{max: MaxStderrBytes}
	cmd.Stderr = stderr
	proc, err := p.start(ctx, cmd)
	if err != nil {
		return nil, nil, p.classify(ctx, stderr, fmt.Errorf("%w: %w", ErrLaunchFailed, err))
	}
	page, err := NewPage(ctx, proc.Client(), PageOptions{AllowedDomains: domains, Log: p.log})
	if err != nil {
		_ = proc.Close() // kill and reap; the setup error is the one reported
		return nil, nil, p.classify(ctx, stderr, err)
	}
	return proc, page, nil
}

// classify logs a launch failure summary (never Chrome's output) and turns
// a missing sandbox into ErrNoUsableSandbox.
func (p *Pool) classify(ctx context.Context, stderr *capWriter, err error) error {
	total, sandbox := stderr.summary()
	class := "other"
	if sandbox {
		class = "no_usable_sandbox"
	}
	p.log.WarnContext(ctx, "browser: chrome launch failed",
		slog.Int64("stderr_bytes", total), slog.String("class", class))
	if sandbox {
		return fmt.Errorf("%w: %s: %w", ErrNoUsableSandbox, noSandboxFix, err)
	}
	return err
}

// Close tears down every browser still leased (killed, reaped, profile
// removed) and waits for it. It also waits for every Launch in flight: a
// browser such a Launch started is torn down by that Launch, which then
// fails with ErrLaunchFailed ("pool closed"). After CloseGrace the pool
// context is cancelled, so a Launch whose own context never ends is aborted
// rather than waited for forever. Later launches fail. Idempotent.
func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	leases := make([]*PoolBrowser, 0, len(p.leases))
	for b := range p.leases {
		leases = append(leases, b)
	}
	p.mu.Unlock()
	var errs []error
	for _, b := range leases {
		errs = append(errs, b.teardown(context.Background()))
	}
	p.waitInflight()
	p.cancel()
	return errors.Join(errs...)
}

// waitInflight waits for the in-flight Launches, cancelling the pool
// context once closeGrace has elapsed.
func (p *Pool) waitInflight() {
	done := make(chan struct{})
	go func() {
		p.inflight.Wait()
		close(done)
	}()
	grace := time.NewTimer(p.closeGrace)
	defer grace.Stop()
	select {
	case <-done:
	case <-grace.C:
		p.cancel()
		<-done
	}
}

func (p *Pool) forget(b *PoolBrowser) {
	p.mu.Lock()
	delete(p.leases, b)
	p.mu.Unlock()
}

// PoolBrowser is what Launch returns: a connector.Browser leased on one
// disposable profile.
type PoolBrowser struct {
	pool    *Pool
	profile string
	domains []string
	// launchCtx is the Launch context: it bounds every browser of the
	// lease, the visible one of RelaunchVisible included.
	launchCtx context.Context

	// opMu serializes RelaunchVisible and teardown.
	opMu sync.Mutex

	mu     sync.Mutex // guards the fields below
	proc   Process
	page   *Page
	cancel context.CancelFunc // ends the current browser's lifetime
	ended  bool

	endOnce  sync.Once
	closeErr error
	done     chan struct{}
}

var _ connector.Browser = (*PoolBrowser)(nil)

// ProfileDir returns the profile directory of the lease.
func (b *PoolBrowser) ProfileDir() string { return b.profile }

// Done is closed once the lease is over: browser reaped and profile removed,
// whatever ended it (Close, context cancel, crash, Pool.Close).
func (b *PoolBrowser) Done() <-chan struct{} { return b.done }

// watch ends the lease when proc exits or ctx ends, unless proc is no
// longer the lease's browser (relaunched) or the lease is already over.
func (b *PoolBrowser) watch(ctx context.Context, proc Process) {
	select {
	case <-proc.Done():
	case <-ctx.Done():
	}
	b.mu.Lock()
	current := !b.ended && b.proc == proc
	b.mu.Unlock()
	if current {
		_ = b.teardown(ctx) // Done reports the end; the error is the lease's Close result
	}
}

// teardown ends the lease once: it aborts a relaunch in flight, kills and
// reaps the browser, closes the page, then removes the profile, and closes
// Done. Concurrent callers wait for it to finish. ctx carries values only:
// the teardown runs to the end even when it is cancelled.
func (b *PoolBrowser) teardown(ctx context.Context) error {
	b.endOnce.Do(func() {
		b.mu.Lock()
		b.ended = true
		cancel := b.cancel
		b.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		b.opMu.Lock()
		b.mu.Lock()
		proc, page, cancel := b.proc, b.page, b.cancel
		b.proc, b.page = nil, nil
		b.mu.Unlock()
		if proc != nil {
			_ = proc.Close() // kill and reap: always nil after a kill
		}
		if page != nil {
			page.dispose(ctx) // the client is gone: fails fast, nothing to report
		}
		if cancel != nil {
			cancel()
		}
		b.closeErr = b.pool.removeProfile(b.profile)
		b.opMu.Unlock()
		b.pool.forget(b)
		close(b.done)
	})
	return b.closeErr
}

// Close kills and reaps the browser, closes the page and removes the
// profile, before it returns. Idempotent.
func (b *PoolBrowser) Close() error {
	return b.teardown(context.Background())
}

// RelaunchVisible kills the current (headless) browser without removing the
// profile, starts a visible one on the same profile and opens a new page.
// The visible browser's lifetime is bound to both ctx and the Launch
// context: either ending tears the lease down. In a non-interactive pool it returns an
// error wrapping connector.ErrNeedsLogin and nothing changes. If the
// visible browser cannot be started the lease is over.
func (b *PoolBrowser) RelaunchVisible(ctx context.Context) error {
	if !b.pool.interactive {
		return fmt.Errorf("browser: visible relaunch in a non-interactive run: %w", connector.ErrNeedsLogin)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("relaunch browser: %w", err)
	}
	cmd, err := b.pool.prepare(b.profile, b.domains, true)
	if err != nil {
		return err
	}
	b.opMu.Lock()
	replaced, err := b.relaunchLocked(ctx, cmd)
	b.opMu.Unlock()
	if err != nil && replaced {
		return errors.Join(err, b.teardown(ctx))
	}
	return err
}

// relaunchLocked runs under opMu. replaced reports whether the headless
// browser was killed.
func (b *PoolBrowser) relaunchLocked(ctx context.Context, cmd Command) (replaced bool, err error) {
	b.mu.Lock()
	if b.ended {
		b.mu.Unlock()
		return false, fmt.Errorf("%w: lease over", ErrBrowserGone)
	}
	oldProc, oldPage, oldCancel := b.proc, b.page, b.cancel
	rctx, rcancel := linkedContext(ctx, b.launchCtx, b.pool.ctx)
	b.proc, b.page, b.cancel = nil, nil, rcancel
	b.mu.Unlock()

	if oldProc != nil {
		_ = oldProc.Close() // kill and reap
	}
	if oldPage != nil {
		oldPage.dispose(ctx)
	}
	if oldCancel != nil {
		oldCancel()
	}
	if err := clearSingletons(b.profile); err != nil {
		rcancel()
		return true, err
	}
	proc, page, err := b.pool.startPage(rctx, cmd, b.domains)
	if err != nil {
		rcancel()
		return true, err
	}
	b.mu.Lock()
	b.proc, b.page = proc, page
	b.mu.Unlock()
	go b.watch(rctx, proc)
	return true, nil
}

// linkedContext returns a context derived from ctx that also ends when any
// of others ends (context.AfterFunc). Its cancel releases those links.
func linkedContext(ctx context.Context, others ...context.Context) (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancel(ctx)
	stops := make([]func() bool, 0, len(others))
	for _, o := range others {
		if o != nil {
			stops = append(stops, context.AfterFunc(o, cancel))
		}
	}
	return c, func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
	}
}

// singletonNames are the links Chrome keeps in a running profile
// (SingletonLock -> "<host>-<pid>"). Left by a killed browser, they could
// make the relaunch refuse the profile once the pid is reused.
var singletonNames = []string{"SingletonLock", "SingletonSocket", "SingletonCookie"}

// clearSingletons unlinks the Singleton* entries of a profile whose browser
// has been reaped. Symlinks are removed, never followed.
func clearSingletons(profile string) error {
	r, err := fsx.Open(profile)
	if err != nil {
		return fmt.Errorf("relaunch browser: %w", err)
	}
	var errs []error
	for _, n := range singletonNames {
		if err := r.Remove(n); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	errs = append(errs, r.Close())
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("relaunch browser: clear profile lock: %w", err)
	}
	return nil
}

// current returns the lease's page, or ErrBrowserGone.
func (b *PoolBrowser) current() (*Page, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ended || b.page == nil {
		return nil, fmt.Errorf("%w: no running browser", ErrBrowserGone)
	}
	return b.page, nil
}

// BlockedHosts returns Page.BlockedHosts of the lease's current page (a
// copy); empty once the lease is over.
func (b *PoolBrowser) BlockedHosts() map[string]int {
	pg, err := b.current()
	if err != nil {
		return map[string]int{}
	}
	return pg.BlockedHosts()
}

// Navigate implements connector.Browser.
func (b *PoolBrowser) Navigate(ctx context.Context, url string) error {
	pg, err := b.current()
	if err != nil {
		return err
	}
	return pg.Navigate(ctx, url)
}

// WaitVisible implements connector.Browser.
func (b *PoolBrowser) WaitVisible(ctx context.Context, selector string) error {
	pg, err := b.current()
	if err != nil {
		return err
	}
	return pg.WaitVisible(ctx, selector)
}

// TypeSecret implements connector.Browser.
func (b *PoolBrowser) TypeSecret(ctx context.Context, selector string, value secret.Secret) error {
	pg, err := b.current()
	if err != nil {
		return err
	}
	return pg.TypeSecret(ctx, selector, value)
}

// Click implements connector.Browser.
func (b *PoolBrowser) Click(ctx context.Context, selector string) error {
	pg, err := b.current()
	if err != nil {
		return err
	}
	return pg.Click(ctx, selector)
}

// CurrentURL implements connector.Browser.
func (b *PoolBrowser) CurrentURL(ctx context.Context) (string, error) {
	pg, err := b.current()
	if err != nil {
		return "", err
	}
	return pg.CurrentURL(ctx)
}

// Cookies implements connector.Browser.
func (b *PoolBrowser) Cookies(ctx context.Context, domains []string) ([]connector.Cookie, error) {
	pg, err := b.current()
	if err != nil {
		return nil, err
	}
	return pg.Cookies(ctx, domains)
}
