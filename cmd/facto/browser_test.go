// Tests for "facto browser install" (J1 task T12, decision A10, ADR 0008
// "Chrome for Testing (A10)"): the command installs exactly cft.Pinned(),
// with production HTTP options, into a private directory, never prompts,
// and maps failures to exit 1. The installer is injected (env.InstallBrowser):
// nothing touches the network or downloads Chrome.
package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
)

// fakeInstaller records the options of every call and returns exe, err.
type fakeInstaller struct {
	mu    sync.Mutex
	calls []cft.Options
	err   error
}

func (f *fakeInstaller) install(_ context.Context, opts cft.Options) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, opts)
	if f.err != nil {
		return "", f.err
	}
	return filepath.Join(opts.Dir, opts.Manifest.Version, "chrome-linux64", "chrome"), nil
}

func (f *fakeInstaller) recorded() []cft.Options {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]cft.Options(nil), f.calls...)
}

func browserEnv(s *sandbox, fi *fakeInstaller) env {
	e := s.env()
	e.Clock = clock.NewFake(cft.Pinned().PinnedAt.Add(24 * time.Hour))
	e.InstallBrowser = fi.install
	return e
}

func assertPrivateDir(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", dir, err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%s mode = %v, want a 0700 directory", dir, fi.Mode())
	}
}

func TestBrowserInstall_UsesPinnedManifest(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	fi := &fakeInstaller{}
	dir := filepath.Join(s.home, "browsers")

	r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "--dir", dir)

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	calls := fi.recorded()
	if len(calls) != 1 {
		t.Fatalf("installer called %d times, want 1", len(calls))
	}
	got := calls[0]
	if !reflect.DeepEqual(got.Manifest, cft.Pinned()) {
		t.Fatalf("manifest = %+v, want cft.Pinned() %+v", got.Manifest, cft.Pinned())
	}
	if err := got.Manifest.Validate(); err != nil {
		t.Fatalf("installed manifest invalid: %v", err)
	}
	if got.Dir != dir {
		t.Fatalf("dir = %q, want %q", got.Dir, dir)
	}
	// Production HTTP options: system roots, real dialer, no proxy.
	if got.HTTP.RootCAs != nil || got.HTTP.DialContext != nil || got.HTTP.Proxy != nil || got.HTTP.Jar != nil {
		t.Fatalf("HTTP options = %+v, want the zero (production) value", got.HTTP)
	}
	if got.Log == nil {
		t.Fatal("no logger passed: progress must be logged through the redacting handler")
	}
	if got.Limits != (cft.Limits{}) {
		t.Fatalf("limits = %+v, want zero (cft defaults)", got.Limits)
	}
	assertPrivateDir(t, dir)
	wantExe := filepath.Join(dir, cft.Pinned().Version, "chrome-linux64", "chrome")
	if !strings.Contains(r.stdout, wantExe) || !strings.Contains(r.stdout, cft.Pinned().Version) {
		t.Fatalf("stdout = %q, want the version and the executable path %q", r.stdout, wantExe)
	}
}

func TestBrowserInstall_NonInteractiveOK(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	fi := &fakeInstaller{}

	// stdin is not a terminal and holds nothing: no prompt may block.
	r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install")

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	want := filepath.Join(s.state, "chrome")
	calls := fi.recorded()
	if len(calls) != 1 || calls[0].Dir != want {
		t.Fatalf("installer calls = %+v, want one into %q (default state dir, no config yet)", calls, want)
	}
	assertPrivateDir(t, s.state)
	assertPrivateDir(t, want)
	if strings.Contains(strings.ToLower(r.stderr), "?") {
		t.Fatalf("stderr = %q, want no prompt", r.stderr)
	}
}

func TestBrowserInstall_StateDirFromConfig(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	fi := &fakeInstaller{}
	cfgPath := s.writeConfig(t, strings.Replace(validConfig, "state_dir: ~/.facto", "state_dir: ~/state", 1))

	r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "--config", cfgPath)

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	want := filepath.Join(s.home, "state", "chrome")
	if calls := fi.recorded(); len(calls) != 1 || calls[0].Dir != want {
		t.Fatalf("installer calls = %+v, want one into %q", calls, want)
	}
	assertPrivateDir(t, want)
}

func TestBrowserInstall_Errors(t *testing.T) {
	t.Parallel()

	t.Run("install failure exits 1", func(t *testing.T) {
		t.Parallel()
		s := newSandbox(t)
		fi := &fakeInstaller{err: cft.ErrChecksumMismatch}
		r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "--dir", filepath.Join(s.home, "b"))
		if r.code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", r.code, r.stderr)
		}
		if !strings.Contains(r.stderr, "checksum mismatch") {
			t.Fatalf("stderr = %q, want the cause", r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("stdout = %q, want nothing on failure", r.stdout)
		}
	})

	t.Run("explicit missing config exits 2", func(t *testing.T) {
		t.Parallel()
		s := newSandbox(t)
		fi := &fakeInstaller{}
		r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "--config", filepath.Join(s.home, "missing.yaml"))
		if r.code != 2 {
			t.Fatalf("exit code = %d, want 2\nstderr:\n%s", r.code, r.stderr)
		}
		if len(fi.recorded()) != 0 {
			t.Fatal("installer called despite a configuration error")
		}
	})

	t.Run("dir through a symlink refused", func(t *testing.T) {
		t.Parallel()
		s := newSandbox(t)
		fi := &fakeInstaller{}
		link := filepath.Join(s.home, "link")
		if err := os.Symlink(s.out, link); err != nil {
			t.Fatalf("setup Symlink: %v", err)
		}
		r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "--dir", link)
		if r.code != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", r.code, r.stderr)
		}
		if len(fi.recorded()) != 0 {
			t.Fatal("installer called with a symlinked directory")
		}
	})

	t.Run("extra argument is a usage error", func(t *testing.T) {
		t.Parallel()
		s := newSandbox(t)
		fi := &fakeInstaller{}
		r := invoke(t.Context(), browserEnv(s, fi), "", "browser", "install", "now")
		if r.code != 2 || len(fi.recorded()) != 0 {
			t.Fatalf("exit code = %d, calls %d; want 2 and no install", r.code, len(fi.recorded()))
		}
	})
}

func TestBrowserInstall_WarnsWhenPinIsStale(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	fi := &fakeInstaller{}
	e := browserEnv(s, fi)
	e.Clock = clock.NewFake(cft.Pinned().PinnedAt.Add(cft.MaxPinAge + 24*time.Hour))

	r := invoke(t.Context(), e, "", "browser", "install", "--dir", filepath.Join(s.home, "b"))

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0 (a stale pin warns, it does not fail)\nstderr:\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "WARN") || !strings.Contains(r.stderr, cft.Pinned().Version) {
		t.Fatalf("stderr = %q, want a warning naming the pinned version", r.stderr)
	}
}

func TestInstallPinnedBrowser_RefusesBadDirWithoutNetwork(t *testing.T) {
	t.Parallel()
	_, err := installPinnedBrowser(t.Context(), cft.Options{Manifest: cft.Pinned(), Dir: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("installPinnedBrowser = nil, want an error for a missing directory")
	}
	if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errUnpinnedPlatform) {
		t.Fatalf("err = %v, want fs.ErrNotExist (or errUnpinnedPlatform off linux64)", err)
	}
}
