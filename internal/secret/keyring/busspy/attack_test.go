//go:build e2e && linux

// Red-team seam spy (J1 task T27, ADR 0009 A3): an e2e build of facto
// never reaches the OS keyring, for session keys (persistent sessions, and
// the key deletion of the ephemeral sweep). The spy is a fake D-Bus
// session bus: a unix socket in the test's temp dir named by
// DBUS_SESSION_BUS_ADDRESS, counting every connection. The real session
// bus and keyring are never touched: both binaries only ever see the fake
// address. Control: the release build of the same commit, run the same
// way, does connect to the spy (so the spy is not blind). Everything is
// synthetic.
package busspy_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

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
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// build compiles cmd/facto with tags into dir and returns the binary.
func build(ctx context.Context, t *testing.T, dir, name string, tags ...string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	args := []string{"build", "-trimpath", "-o", out}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "./cmd/facto")
	c := exec.CommandContext(ctx, "go", args...) //nolint:gosec // fixed arguments, test build
	c.Dir = moduleRoot(t)
	c.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "CGO_ENABLED=0")
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("go build %v: %v\n%s", tags, err, b)
	}
	return out
}

// spyBus listens on a unix socket and counts connections.
type spyBus struct {
	addr string
	mu   sync.Mutex
	n    int
}

func newSpyBus(ctx context.Context, t *testing.T, dir string) *spyBus {
	t.Helper()
	path := filepath.Join(dir, "bus")
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &spyBus{addr: "unix:path=" + path}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.n++
			s.mu.Unlock()
			_ = c.Close()
		}
	}()
	return s
}

func (s *spyBus) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	r, err := fsx.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate(name); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, name)
}

func write(ctx context.Context, t *testing.T, dir, name, content string) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(ctx, name, []byte(content)); err != nil {
		t.Fatal(err)
	}
}

// sandbox makes a private HOME with a config using sessions mode and, when
// staleSess, a session file left by an earlier run (the ephemeral sweep
// then deletes its key).
func sandbox(ctx context.Context, t *testing.T, mode string, staleSess bool) (home, cfg string) {
	t.Helper()
	home = mkdir(t, t.TempDir(), "home")
	mkdir(t, home, "Invoices")
	mkdir(t, filepath.Join(home, "Invoices"), "inbox")
	state := mkdir(t, home, ".facto")
	if staleSess {
		sessions := mkdir(t, state, "sessions")
		write(ctx, t, sessions, "fakeprovider.sess", "FACTOSES synthetic stale session file")
		write(ctx, t, state, "install-id", "0123456789abcdef0123456789abcdef")
	}
	write(ctx, t, home, "config.yaml", "output:\n  local: ~/Invoices\nstate_dir: ~/.facto\nnotify: none\nsessions: "+mode+"\n")
	return home, filepath.Join(home, "config.yaml")
}

func run(ctx context.Context, t *testing.T, bin, home, cfg, bus string) string {
	t.Helper()
	c := exec.CommandContext(ctx, bin, "collect", "--config", cfg, "--year", "2026", "--non-interactive") //nolint:gosec // test binary
	c.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"DBUS_SESSION_BUS_ADDRESS=" + bus,
		"LANG=C",
	}
	out, err := c.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("run %s: %v", filepath.Base(bin), err)
	}
	return string(out)
}

// TestAttack_E2EBuildNeverReachesTheSessionBus: `facto collect` of the e2e
// build, with persistent sessions and with the ephemeral sweep of a stale
// session file, never connects to the session bus; the release build run
// the same way does (control).
func TestAttack_E2EBuildNeverReachesTheSessionBus(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	bins := mkdir(t, t.TempDir(), "bin")
	e2eBin := build(ctx, t, bins, "facto-e2e", "e2e")
	relBin := build(ctx, t, bins, "facto-release")

	for _, tc := range []struct {
		mode  string
		stale bool
	}{{"persistent", false}, {"persistent", true}, {"ephemeral", true}} {
		name := tc.mode
		if tc.stale {
			name += "+stale"
		}
		t.Run(name, func(t *testing.T) {
			spy := newSpyBus(ctx, t, t.TempDir())
			home, cfg := sandbox(ctx, t, tc.mode, tc.stale)
			out := run(ctx, t, e2eBin, home, cfg, spy.addr)
			if n := spy.count(); n != 0 {
				t.Errorf("e2e build connected %d times to the session bus (output %q)", n, out)
			}
			// Non-vacuous: the run reached the session store.
			switch tc.mode {
			case "persistent":
				if _, err := os.Stat(filepath.Join(home, ".facto", "install-id")); err != nil || strings.Contains(out, "keyring unavailable") {
					t.Errorf("e2e run did not open a persistent store (install-id: %v; output %q)", err, out)
				}
			case "ephemeral":
				if _, err := os.Stat(filepath.Join(home, ".facto", "sessions", "fakeprovider.sess")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("e2e ephemeral sweep did not run (stale file: %v)", err)
				}
			}

			ctrl := newSpyBus(ctx, t, t.TempDir())
			home2, cfg2 := sandbox(ctx, t, tc.mode, tc.stale)
			_ = run(ctx, t, relBin, home2, cfg2, ctrl.addr)
			if ctrl.count() == 0 {
				t.Errorf("control: the release build never reached the spy bus: the spy is blind")
			}
		})
	}
}

// TestAttack_E2EBuildKeyringRefsNeverReachTheSessionBus: in the e2e build,
// a connector whose credentials are keyring:// references resolves them
// from the e2e file store (none here, so the login fails before any
// network I/O: fakeprovider resolves its credentials first) and never
// connects to the session bus.
func TestAttack_E2EBuildKeyringRefsNeverReachTheSessionBus(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	e2eBin := build(ctx, t, mkdir(t, t.TempDir(), "bin"), "facto-e2e", "e2e")
	spy := newSpyBus(ctx, t, t.TempDir())
	home, cfg := sandbox(ctx, t, "ephemeral", false)
	write(ctx, t, home, "config.yaml", "output:\n  local: ~/Invoices\nstate_dir: ~/.facto\nnotify: none\nsessions: ephemeral\n"+
		"connectors:\n  fakeprovider:\n    enabled: true\n    category: services\n"+
		"    login: keyring://facto/fp-login\n    password: keyring://facto/fp-secret\n")
	out := run(ctx, t, e2eBin, home, cfg, spy.addr)
	t.Logf("collect output: %q", out)
	if n := spy.count(); n != 0 {
		t.Errorf("e2e build connected %d times to the session bus while resolving keyring:// refs", n)
	}
	if !strings.Contains(out, "fakeprovider") || strings.Contains(out, "- ok fakeprovider") {
		t.Errorf("the connector did not run and fail on its unresolvable refs (output %q)", out)
	}
}
