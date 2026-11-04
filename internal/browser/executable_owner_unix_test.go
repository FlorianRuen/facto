//go:build unix

package browser_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// Expected API (J1 T10, from the T6 review):
//
//	// CheckExecutableAs is CheckExecutable with the ownership check made
//	// injectable: on unix the resolved binary and its parent directory
//	// must each be owned by euid or by root (uid 0). owner returns the uid
//	// of a path that is already fully resolved (it is never asked about a
//	// symlink). A nil owner or an owner error fails closed with
//	// ErrUnsafeExecutable. CheckExecutable(path) is
//	// CheckExecutableAs(path, os.Geteuid(), <stat owner>).
//	func CheckExecutableAs(path string, euid int, owner func(path string) (uid int, err error)) error

// ownerSpy answers uids by resolved path (default: euid) and records the
// paths it was asked about.
type ownerSpy struct {
	mu    sync.Mutex
	euid  int
	uids  map[string]int
	fail  bool
	asked []string
}

func (s *ownerSpy) owner(p string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, p)
	if s.fail {
		return 0, errors.New("stat: no owner")
	}
	if uid, ok := s.uids[p]; ok {
		return uid, nil
	}
	return s.euid, nil
}

func TestExecutable_RefusesForeignOwner(t *testing.T) {
	t.Parallel()
	const euid, foreign = 1000, 1001
	tests := []struct {
		name    string
		link    bool // pass a symlink to the binary instead of the binary
		uids    func(file, dir string) map[string]int
		fail    bool
		nilFn   bool
		wantErr bool
	}{
		{name: "file and dir owned by euid", uids: func(string, string) map[string]int { return nil }},
		{name: "file and dir owned by root", uids: func(f, d string) map[string]int { return map[string]int{f: 0, d: 0} }},
		{name: "file foreign", uids: func(f, _ string) map[string]int { return map[string]int{f: foreign} }, wantErr: true},
		{name: "parent dir foreign", uids: func(_, d string) map[string]int { return map[string]int{d: foreign} }, wantErr: true},
		{name: "symlink to a foreign file", link: true, uids: func(f, _ string) map[string]int { return map[string]int{f: foreign} }, wantErr: true},
		{name: "owner lookup fails", uids: func(string, string) map[string]int { return nil }, fail: true, wantErr: true},
		{name: "no owner lookup", uids: func(string, string) map[string]int { return nil }, nilFn: true, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exe := writeExe(t, 0o700, 0o700)
			file, err := filepath.EvalSymlinks(exe)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Dir(file)
			spy := &ownerSpy{euid: euid, uids: tc.uids(file, dir), fail: tc.fail}
			path := exe
			if tc.link {
				path = symlinkTo(t, exe)
			}
			var fn func(string) (int, error)
			if !tc.nilFn {
				fn = spy.owner
			}
			err = browser.CheckExecutableAs(path, euid, fn)
			if tc.wantErr && !errors.Is(err, browser.ErrUnsafeExecutable) {
				t.Errorf("CheckExecutableAs(%s) = %v, want ErrUnsafeExecutable", tc.name, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CheckExecutableAs(%s) = %v, want nil", tc.name, err)
			}
			if tc.wantErr || tc.nilFn {
				return
			}
			spy.mu.Lock()
			defer spy.mu.Unlock()
			for _, p := range []string{file, dir} {
				if !slices.Contains(spy.asked, p) {
					t.Errorf("owner never asked about %s (asked %q): the check is vacuous", p, spy.asked)
				}
			}
			for _, p := range spy.asked {
				if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					t.Errorf("owner asked about symlink %s", p)
				}
			}
		})
	}

	// The real lookup accepts our own fixture.
	if err := browser.CheckExecutable(writeExe(t, 0o700, 0o700)); err != nil {
		t.Errorf("CheckExecutable(own private binary) = %v, want nil", err)
	}
}
