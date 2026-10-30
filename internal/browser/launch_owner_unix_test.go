//go:build unix

package browser_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestLaunch_ExecutableCheckUsesHostEuid (J1 T7c, from the T10 review):
// Prepare and Launch check the executable owner against Host.Geteuid(), the
// injected effective uid, never the test process' own os.Geteuid().
//
// Expected API: Host gains
//
//	// Owner returns the owner uid of an already resolved path (unix). Nil:
//	// a stat-based lookup. An error fails closed.
//	Owner func(path string) (uid int, err error)
//
// and Prepare calls CheckExecutableAs(h.Executable, h.Geteuid(), owner)
// (owner = h.Owner, or the stat lookup when nil).
func TestLaunch_ExecutableCheckUsesHostEuid(t *testing.T) {
	t.Parallel()
	const hostEuid = 4242
	tests := []struct {
		name    string
		owner   func(string) (int, error)
		wantErr bool
	}{
		{name: "owned by the host euid", owner: func(string) (int, error) { return hostEuid, nil }},
		{name: "owned by root", owner: func(string) (int, error) { return 0, nil }},
		{name: "owned by another user", wantErr: true, owner: func(string) (int, error) { return hostEuid + 1, nil }},
		{name: "owner lookup fails", wantErr: true, owner: func(string) (int, error) { return hostEuid, errors.New("stat failed") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := testHost(t, nil)
			h.Geteuid = func() int { return hostEuid }
			var mu sync.Mutex
			var asked []string
			h.Owner = func(p string) (int, error) {
				mu.Lock()
				asked = append(asked, p)
				mu.Unlock()
				return tc.owner(p)
			}
			_, perr := browser.Prepare(h, launchOpts(t))
			spy := &startSpy{}
			lerr := browser.Launch(context.Background(), h, launchOpts(t), spy.start)
			if tc.wantErr {
				if !errors.Is(perr, browser.ErrUnsafeExecutable) || !errors.Is(lerr, browser.ErrUnsafeExecutable) {
					t.Errorf("Prepare = %v, Launch = %v; want ErrUnsafeExecutable", perr, lerr)
				}
				if len(spy.calls) != 0 {
					t.Errorf("start called %d times for a foreign executable", len(spy.calls))
				}
				return
			}
			if perr != nil || lerr != nil {
				t.Fatalf("Prepare = %v, Launch = %v; want nil", perr, lerr)
			}
			resolved, err := filepath.EvalSymlinks(h.Executable)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Contains(asked, resolved) {
				t.Errorf("Host.Owner asked about %q, want the resolved executable %q", asked, resolved)
			}
		})
	}

	t.Run("nil Owner uses the real owner against the host euid", func(t *testing.T) {
		t.Parallel()
		h := testHost(t, nil)
		h.Owner = nil
		realEuid := os.Geteuid()
		h.Geteuid = func() int { return realEuid + 1 } // the fixture belongs to real
		_, err := browser.Prepare(h, launchOpts(t))
		if realEuid == 0 {
			// A root-owned file is always accepted: nothing to refuse.
			if err != nil {
				t.Errorf("Prepare(root-owned fixture) = %v, want nil", err)
			}
			return
		}
		if !errors.Is(err, browser.ErrUnsafeExecutable) {
			t.Errorf("Prepare(executable owned by uid %d, host euid %d) = %v, want ErrUnsafeExecutable", realEuid, realEuid+1, err)
		}
	})
}
