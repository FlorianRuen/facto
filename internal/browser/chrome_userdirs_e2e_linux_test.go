//go:build e2e && chrome && linux

package browser_test

// Real-Chrome check of the private launch area (J1 T23): with a sandbox
// HOME, a launch writes nothing under HOME (no ~/.config/google-chrome-for-
// testing with its Crash Reports, no ~/.cache fontconfig or dconf files);
// Chrome's per-user state lands in the area next to the profile instead,
// TMPDIR (SingletonSocket) included when the base is short, and the area
// is gone after Close.

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

// homeEntries lists every path under home, slash-separated.
func homeEntries(t *testing.T, home string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(home, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != home {
			rel, _ := filepath.Rel(home, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", home, err)
	}
	return out
}

func TestChrome_NothingWrittenUnderHome(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		short       bool // root short enough for a private TMPDIR
		wantPrivTMP bool
	}{
		{name: "short base: private TMPDIR", short: true, wantPrivTMP: true},
		{name: "long base: inherited TMPDIR", short: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
			defer cancel()
			root := t.TempDir()
			if tt.short {
				var err error
				root, err = os.MkdirTemp("", "fc") // test fixture, 0700
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(root) })
			}
			home := privateDir(t, root, "h")
			state := privateDir(t, root, "s")
			site := newFakeSite(t)
			r := &chromeRig{t: t, exe: chromeBinary(t), home: home, state: state}
			p, err := browser.NewPool(t.Context(), browser.PoolConfig{
				Host: chromeHost(r.exe, home), StateDir: state, Start: e2eStarter(site)(r),
			})
			if err != nil {
				t.Fatalf("NewPool: %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
			lb, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: siteDomains})
			if err != nil {
				t.Fatalf("Launch: %v", err)
			}
			b := lb.(*browser.PoolBrowser)
			closeAtCleanup(t, b)
			openSite(ctx, t, b, "/login", "#user")

			var area string
			ents, err := os.ReadDir(p.Base())
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), "t") {
					area = filepath.Join(p.Base(), e.Name())
				}
			}
			if area == "" {
				t.Fatalf("no private area under %s", p.Base())
			}
			// Not vacuous: Chrome's per-user config (crash reports dir)
			// exists, in the area.
			if _, err := os.Lstat(filepath.Join(area, "config", "google-chrome-for-testing")); err != nil {
				t.Errorf("Chrome wrote no config in the private area: %v", err)
			}
			socketDirs, _ := filepath.Glob(filepath.Join(area, "org.chromium.Chromium.*"))
			if tt.wantPrivTMP && len(socketDirs) == 0 {
				t.Error("no org.chromium.Chromium.* socket dir in the private TMPDIR")
			}
			if !tt.wantPrivTMP && len(socketDirs) != 0 {
				t.Errorf("socket dirs %q in the area although its path is too long", socketDirs)
			}
			if left := homeEntries(t, home); len(left) != 0 {
				t.Errorf("Chrome wrote under HOME while running: %q", left)
			}
			if err := b.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if left := homeEntries(t, home); len(left) != 0 {
				t.Errorf("Chrome left files under HOME: %q", left)
			}
			for _, rel := range []string{".config/google-chrome-for-testing", ".cache"} {
				assertGone(t, filepath.Join(home, filepath.FromSlash(rel)))
			}
			assertGone(t, area)
			if !t.Failed() {
				t.Log("nothing written under HOME, private area removed")
			}
		})
	}
}
