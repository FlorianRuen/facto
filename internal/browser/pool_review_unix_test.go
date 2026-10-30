//go:build unix

// Pool hardening from the T10 review, done in T7c (J1 plan, T7c bullets).
//
// Expected API (internal/browser), on top of pool_unix_test.go:
//
//	type Host struct {
//		...
//		// Owner returns the owner uid of an already resolved path (unix).
//		// Nil: a stat-based lookup. Used by Prepare (CheckExecutableAs with
//		// Geteuid()) and by NewPool. An error fails closed.
//		Owner func(path string) (uid int, err error)
//	}
//
//	NewPool, unix only, before creating or reusing a base:
//	  - XDG_RUNTIME_DIR, when used, is Lstat-checked: a real directory
//	    (not a symlink), mode without any group/world bit (0700), owned by
//	    Host.Geteuid() (Host.Owner). Otherwise ErrUnsafeProfileDir (no
//	    silent fallback to <StateDir>/tmp).
//	  - the chosen base (created or reused) must be owned by
//	    Host.Geteuid() exactly (root is foreign too); an Owner error is
//	    ErrUnsafeProfileDir.
//
//	Pool.Close waits for every Launch in flight (sync.WaitGroup): when it
//	returns, a browser started by such a Launch has been killed and reaped
//	and its profile removed; that Launch returns an error (ErrLaunchFailed
//	"pool closed", or the context error if Close cancels it).
//
//	PoolBrowser.RelaunchVisible(ctx2): the visible browser's lifetime is
//	bound to BOTH the Launch context and ctx2 (context.AfterFunc): either
//	ending tears the lease down (browser killed, profile removed, Done
//	closed).
package browser_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

// fakeProc is a Process over the in-memory fakeCDP peer: no OS process.
type fakeProc struct {
	pid    int
	client *browser.Client
	done   chan struct{}
	once   sync.Once
	closes atomic.Int32
}

func newFakeProc(t *testing.T, pid int) *fakeProc {
	t.Helper()
	c := browser.NewClient(newFakeCDP(t))
	p := &fakeProc{pid: pid, client: c, done: make(chan struct{})}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func (p *fakeProc) Client() *browser.Client { return p.client }
func (p *fakeProc) Pid() int                { return p.pid }
func (p *fakeProc) Done() <-chan struct{}   { return p.done }
func (p *fakeProc) Close() error {
	p.closes.Add(1)
	_ = p.client.Close()
	p.once.Do(func() { close(p.done) })
	return nil
}

// procStarter hands out fakeProcs. With gate set, the first start blocks
// until the gate closes or its ctx ends; later starts fail at once
// (probe launches).
type procStarter struct {
	t       *testing.T
	gate    chan struct{}
	entered chan struct{}

	mu    sync.Mutex
	calls int
	procs []*fakeProc
}

func newProcStarter(t *testing.T) *procStarter {
	return &procStarter{t: t, entered: make(chan struct{}, 64)}
}

func (s *procStarter) start(ctx context.Context, _ browser.Command) (browser.Process, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	s.entered <- struct{}{}
	if s.gate != nil {
		if n > 1 {
			return nil, errors.New("probe start refused")
		}
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, fmt.Errorf("gated start: %w", ctx.Err())
		}
	}
	p := newFakeProc(s.t, 5000+n)
	s.mu.Lock()
	s.procs = append(s.procs, p)
	s.mu.Unlock()
	return p, nil
}

func (s *procStarter) snapshot() (int, []*fakeProc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, slices.Clone(s.procs)
}

func TestPool_BaseDirForeignOwnerRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup returns the Owner double; base is the expected base on success.
		setup   func(t *testing.T, r *poolRig) (owner func(string) (int, error), base string)
		wantErr bool
	}{
		{name: "everything owned by euid", setup: func(_ *testing.T, r *poolRig) (func(string) (int, error), string) {
			return nil, filepath.Join(r.xdg, "facto")
		}},
		{name: "existing xdg facto owned by another user", wantErr: true, setup: func(t *testing.T, r *poolRig) (func(string) (int, error), string) {
			foreign := privateDir(t, r.xdg, "facto")
			return ownedBy(r.euid, foreign, r.euid+1, nil), ""
		}},
		{name: "existing xdg facto owned by root", wantErr: true, setup: func(t *testing.T, r *poolRig) (func(string) (int, error), string) {
			foreign := privateDir(t, r.xdg, "facto")
			return ownedBy(r.euid, foreign, 0, nil), ""
		}},
		{name: "XDG_RUNTIME_DIR owned by another user", wantErr: true, setup: func(_ *testing.T, r *poolRig) (func(string) (int, error), string) {
			return ownedBy(r.euid, r.xdg, r.euid+1, nil), ""
		}},
		{name: "existing state tmp owned by another user", wantErr: true, setup: func(t *testing.T, r *poolRig) (func(string) (int, error), string) {
			r.xdg = ""
			foreign := privateDir(t, r.state, "tmp")
			return ownedBy(r.euid, foreign, r.euid+1, nil), ""
		}},
		{name: "owner lookup fails on the base", wantErr: true, setup: func(_ *testing.T, r *poolRig) (func(string) (int, error), string) {
			return ownedBy(r.euid, filepath.Join(r.xdg, "facto"), r.euid, errors.New("stat failed")), ""
		}},
		{name: "owner lookup fails on XDG_RUNTIME_DIR", wantErr: true, setup: func(_ *testing.T, r *poolRig) (func(string) (int, error), string) {
			return ownedBy(r.euid, r.xdg, r.euid, errors.New("stat failed")), ""
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			owner, want := tc.setup(t, r)
			var seen pathLog
			r.owner = seen.wrap(owner, r.euid)
			p, err := browser.NewPool(t.Context(), r.config())
			if tc.wantErr {
				if p != nil || !errors.Is(err, browser.ErrUnsafeProfileDir) {
					t.Fatalf("NewPool = %v, %v; want nil, ErrUnsafeProfileDir", p, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPool = %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
			if p.Base() != want {
				t.Errorf("Base() = %q, want %q", p.Base(), want)
			}
			if !seen.has(want) || !seen.has(r.xdg) {
				t.Errorf("owner consulted for %q, want the base %q and XDG_RUNTIME_DIR %q", seen.list(), want, r.xdg)
			}
		})
	}
}

// ownedBy returns an Owner double: path target is owned by uid (or fails
// with err), every other path by euid.
func ownedBy(euid int, target string, uid int, err error) func(string) (int, error) {
	target = filepath.Clean(target)
	return func(p string) (int, error) {
		if filepath.Clean(p) == target {
			return uid, err
		}
		return euid, nil
	}
}

// pathLog records the paths an Owner double was asked about.
type pathLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *pathLog) wrap(owner func(string) (int, error), euid int) func(string) (int, error) {
	return func(p string) (int, error) {
		l.mu.Lock()
		l.paths = append(l.paths, filepath.Clean(p))
		l.mu.Unlock()
		if owner == nil {
			return euid, nil
		}
		return owner(p)
	}
}

func (l *pathLog) has(p string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Contains(l.paths, filepath.Clean(p))
}

func (l *pathLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.paths)
}

func TestPool_XDGRuntimeDirSymlinkOrWorldWritableRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, r *poolRig)
		wantErr bool
	}{
		{name: "private 0700 accepted", setup: func(*testing.T, *poolRig) {}},
		{name: "symlink to a private dir", wantErr: true, setup: func(t *testing.T, r *poolRig) {
			link := filepath.Join(r.root, "run-link")
			if err := os.Symlink(r.xdg, link); err != nil {
				t.Fatal(err)
			}
			r.xdg = link
		}},
		{name: "world writable 0777", wantErr: true, setup: func(t *testing.T, r *poolRig) { setMode(t, r.xdg, 0o777) }},
		{name: "world writable sticky 1777", wantErr: true, setup: func(t *testing.T, r *poolRig) {
			setMode(t, r.xdg, 0o777|fs.ModeSticky)
		}},
		{name: "group writable 0770", wantErr: true, setup: func(t *testing.T, r *poolRig) { setMode(t, r.xdg, 0o770) }},
		{name: "group readable 0750", wantErr: true, setup: func(t *testing.T, r *poolRig) { setMode(t, r.xdg, 0o750) }},
		{name: "traversable by others 0711", wantErr: true, setup: func(t *testing.T, r *poolRig) { setMode(t, r.xdg, 0o711) }},
		{name: "regular file", wantErr: true, setup: func(t *testing.T, r *poolRig) {
			r.xdg = writeTestFile(t, r.root, "run-file", []byte("x"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			tc.setup(t, r)
			p, err := browser.NewPool(t.Context(), r.config())
			if tc.wantErr {
				if p != nil || !errors.Is(err, browser.ErrUnsafeProfileDir) {
					t.Fatalf("NewPool(XDG_RUNTIME_DIR %s) = %v, %v; want nil, ErrUnsafeProfileDir", tc.name, p, err)
				}
				// Nothing created through the unsafe directory.
				if _, err := os.Lstat(filepath.Join(r.xdg, "facto")); !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrInvalid) && !isNotDir(err) {
					t.Errorf("%s/facto created through an unsafe XDG_RUNTIME_DIR (Lstat err %v)", r.xdg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPool = %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
			if want := filepath.Join(r.xdg, "facto"); p.Base() != want {
				t.Errorf("Base() = %q, want %q", p.Base(), want)
			}
		})
	}
}

// isNotDir reports an ENOTDIR from Lstat under a regular file.
func isNotDir(err error) bool {
	return errors.Is(err, syscall.ENOTDIR)
}

func TestPool_CloseWaitsForInFlightLaunch(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := newProcStarter(t)
	s.gate = make(chan struct{})
	cfg := r.config()
	cfg.Start = s.start
	p, err := browser.NewPool(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewPool = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	opts := connector.LaunchOptions{AllowedDomains: testDomains}

	type launchResult struct {
		b   connector.Browser
		err error
	}
	launched := make(chan launchResult, 1)
	go func() {
		b, err := p.Launch(t.Context(), opts)
		launched <- launchResult{b, err}
	}()
	waitChan(t, chanOf(s.entered), "first start")

	// What the world looks like at the instant Close returns.
	type snap struct {
		err      error
		profiles []string
		procs    []*fakeProc
	}
	closed := make(chan snap, 1)
	go func() {
		err := p.Close()
		_, procs := s.snapshot()
		closed <- snap{err: err, profiles: profileEntries(t, p.Base()), procs: procs}
	}()

	// Wait until Close has marked the pool closed: a probe Launch is then
	// refused without reaching the starter.
	deadline := time.NewTimer(portWait)
	defer deadline.Stop()
	for {
		before, _ := s.snapshot()
		b, err := p.Launch(t.Context(), opts)
		if b != nil {
			_ = b.Close()
		}
		after, _ := s.snapshot()
		if errors.Is(err, browser.ErrLaunchFailed) && after == before {
			break
		}
		if after != before {
			<-s.entered // drain the probe's signal
		}
		select {
		case <-deadline.C:
			t.Fatal("pool never refused launches after Close")
		default:
		}
	}
	if len(closed) != 0 {
		t.Fatal("Pool.Close returned while a Launch was still starting a browser")
	}

	close(s.gate) // the in-flight start completes
	var got snap
	select {
	case got = <-closed:
	case <-time.After(portWait):
		t.Fatal("Pool.Close did not return after the in-flight Launch ended")
	}
	if got.err != nil {
		t.Errorf("Close = %v", got.err)
	}
	for i, pr := range got.procs {
		if pr.closes.Load() == 0 {
			t.Errorf("browser %d started by the in-flight Launch still running when Close returned", i)
		}
	}
	if len(got.profiles) != 0 {
		t.Errorf("profiles left when Close returned: %q", got.profiles)
	}
	res := <-launched
	if res.b != nil || res.err == nil {
		t.Errorf("in-flight Launch = %v, %v; want nil and an error (pool closed)", res.b, res.err)
	}
}

// chanOf turns one receive on a signal channel into a closed channel.
func chanOf(sig <-chan struct{}) <-chan struct{} {
	out := make(chan struct{})
	go func() {
		<-sig
		close(out)
	}()
	return out
}

func TestPool_RelaunchVisibleLifetimeBoundByLoginCtx(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"launch ctx", "relaunch ctx"} {
		t.Run(which+" cancelled ends the visible browser", func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			r.interactive = true
			s := newProcStarter(t)
			cfg := r.config()
			cfg.Start = s.start
			p, err := browser.NewPool(t.Context(), cfg)
			if err != nil {
				t.Fatalf("NewPool = %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })

			lctx, lcancel := context.WithCancel(t.Context())
			defer lcancel()
			b, err := p.Launch(lctx, connector.LaunchOptions{AllowedDomains: testDomains})
			if err != nil {
				t.Fatalf("Launch = %v", err)
			}
			pb, ok := b.(*browser.PoolBrowser)
			if !ok {
				t.Fatalf("Launch returned %T", b)
			}
			closeAtCleanup(t, pb)
			rctx, rcancel := context.WithCancel(t.Context())
			defer rcancel()
			if err := pb.RelaunchVisible(rctx); err != nil {
				t.Fatalf("RelaunchVisible = %v", err)
			}
			_, procs := s.snapshot()
			if len(procs) != 2 {
				t.Fatalf("%d browsers started, want 2", len(procs))
			}
			if isClosed(pb.Done()) {
				t.Fatal("lease ended by the relaunch")
			}
			if which == "launch ctx" {
				lcancel()
			} else {
				rcancel()
			}
			waitClosed(t, pb.Done(), "lease after "+which+" cancel")
			if procs[1].closes.Load() == 0 {
				t.Error("visible browser still running after the lease ended")
			}
			assertGone(t, pb.ProfileDir())
		})
	}
}
