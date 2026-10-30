//go:build linux

package browser_test

// Per-launch private area of the pool (J1 T23): next to the profile under
// the pool base, a 0700 directory t<pid>.<n> holds Chrome's XDG config and
// cache dirs and, when the SingletonSocket path fits, its TMPDIR. It is
// removed with the profile (also when the launch fails) and swept like a
// stale profile.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

// shortRig is a rig whose root is short enough for a private TMPDIR under
// the pool base (t.TempDir paths embed the test name and are too long).
func shortRig(t *testing.T) *poolRig {
	t.Helper()
	root, err := os.MkdirTemp("", "fb") // 0700; test-only fixture
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	r := &poolRig{t: t, root: root, euid: 1000, executable: fakeExecutable(t)}
	r.home = privateDir(t, root, "h")
	r.state = privateDir(t, root, "s")
	r.xdg = privateDir(t, root, "r")
	return r
}

// areaOf returns the private area named by the XDG_CONFIG_HOME of env.
func areaOf(t *testing.T, env map[string]string) string {
	t.Helper()
	cfg, ok := env["XDG_CONFIG_HOME"]
	if !ok {
		t.Fatalf("no XDG_CONFIG_HOME in Chrome's env %q", env)
	}
	return filepath.Dir(cfg)
}

func TestPool_PrivateAreaNextToProfile(t *testing.T) {
	t.Parallel()
	r := shortRig(t)
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	s := r.startsSnapshot()
	env := envKeys(t, s[0].cmd.Env)
	area := areaOf(t, env)
	if filepath.Dir(area) != p.Base() || area == b.ProfileDir() {
		t.Errorf("area %s is not a sibling of the profile %s under %s", area, b.ProfileDir(), p.Base())
	}
	if !strings.HasPrefix(filepath.Base(area), fmt.Sprintf("t%d.", os.Getpid())) {
		t.Errorf("area name %q, want t<pid>.<n>", filepath.Base(area))
	}
	assertPrivateDir(t, area)
	if env["TMPDIR"] != area {
		t.Errorf("TMPDIR = %q, want the private area %q", env["TMPDIR"], area)
	}
	for k, sub := range map[string]string{"XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state"} {
		if env[k] != filepath.Join(area, sub) {
			t.Errorf("%s = %q, want %q", k, env[k], filepath.Join(area, sub))
		}
		assertPrivateDir(t, filepath.Join(area, sub))
	}
	if env["HOME"] != r.home {
		t.Errorf("HOME = %q, want the user's %q (fonts, display)", env["HOME"], r.home)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertGone(t, area)
	assertGone(t, b.ProfileDir())
}

func TestPool_LongBaseKeepsInheritedTMPDIR(t *testing.T) {
	t.Parallel()
	r := newRig(t) // t.TempDir: base too long for the socket
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	env := envKeys(t, r.startsSnapshot()[0].cmd.Env)
	area := areaOf(t, env)
	if filepath.Dir(area) != p.Base() {
		t.Errorf("area %s not under the pool base %s", area, p.Base())
	}
	if _, ok := env["TMPDIR"]; ok {
		t.Errorf("TMPDIR = %q, want none (the host has none, the area is too long)", env["TMPDIR"])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	assertGone(t, area)
}

func TestPool_SocketPathTooLongFailsBeforeStart(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	cfg := r.config()
	env := map[string]string{"HOME": r.home, "XDG_RUNTIME_DIR": r.xdg, "TMPDIR": "/" + strings.Repeat("x", 120)}
	cfg.Host.LookupEnv = mapLookup(env)
	p, err := browser.NewPool(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	b, err := p.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: testDomains})
	if !errors.Is(err, browser.ErrSocketPathTooLong) || b != nil {
		t.Fatalf("Launch = %v, %v; want nil, ErrSocketPathTooLong", b, err)
	}
	if errors.Is(err, browser.ErrBrowserGone) {
		t.Errorf("error %v reads as a browser crash", err)
	}
	if n := len(r.startsSnapshot()); n != 0 {
		t.Errorf("%d Start calls, want none", n)
	}
	ents, err := os.ReadDir(p.Base())
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("pool base holds %d entries after the failed launch, want none", len(ents))
	}
}

func TestPool_StaleAreasSwept(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	base := privateDir(t, r.xdg, "facto")
	dead := deadPid(t)
	gone := privateDir(t, base, fmt.Sprintf("t%d.1", dead))
	privateDir(t, gone, "config")
	mine := privateDir(t, base, fmt.Sprintf("t%d.7", os.Getpid()))
	keep := []string{
		mine,
		privateDir(t, base, "t0.1"),
		privateDir(t, base, "tabc.1"),
		privateDir(t, base, fmt.Sprintf("t%d", dead)),
		privateDir(t, base, fmt.Sprintf("t%d.x", dead)),
	}
	// A dead-looking area that is a symlink to a directory outside the
	// base: the link is left alone and its target is never touched.
	outside := privateDir(t, r.root, "outside-area-target")
	writeTestFile(t, outside, "keep", []byte("outside"))
	link := filepath.Join(base, fmt.Sprintf("t%d.2", dead))
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	r.pool()
	assertGone(t, gone)
	for _, k := range keep {
		assertPresent(t, k)
	}
	assertPresent(t, filepath.Join(outside, "keep"))
	assertPresent(t, link)
}

// TestPool_AreaNameNeverReused: a t<pid>.<n> that already exists (a live
// entry of this pid, or one planted there) is skipped for the next number;
// its content is untouched and it is not removed with the lease.
func TestPool_AreaNameNeverReused(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	base := privateDir(t, r.xdg, "facto")
	taken := privateDir(t, base, fmt.Sprintf("t%d.1", os.Getpid()))
	writeTestFile(t, taken, "mine", []byte("other lease"))
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	area := areaOf(t, envKeys(t, r.startsSnapshot()[0].cmd.Env))
	if area == taken {
		t.Fatalf("area %s reuses an existing directory", area)
	}
	if want := filepath.Join(base, fmt.Sprintf("t%d.2", os.Getpid())); area != want {
		t.Errorf("area = %s, want the next number %s", area, want)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	assertPresent(t, filepath.Join(taken, "mine"))
}
