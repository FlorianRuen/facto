//go:build unix

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Insecure config modes the CLI must refuse (named so gosec G302 does not
// flag a deliberately broad test mode).
const (
	worldReadable os.FileMode = 0o644
	groupReadable os.FileMode = 0o640
)

// TestRun_ConfigFileRefusedExit2: a config readable by group/world or a
// symlinked config is refused as a configuration error, before anything
// is filed.
func TestRun_ConfigFileRefusedExit2(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *sandbox) string // returns the --config path
	}{
		{
			name: "world-readable 0644",
			setup: func(t *testing.T, s *sandbox) string {
				p := s.writeConfig(t, validConfig)
				if err := os.Chmod(p, worldReadable); err != nil {
					t.Fatalf("setup chmod: %v", err)
				}
				return p
			},
		},
		{
			name: "group-readable 0640",
			setup: func(t *testing.T, s *sandbox) string {
				p := s.writeConfig(t, validConfig)
				if err := os.Chmod(p, groupReadable); err != nil {
					t.Fatalf("setup chmod: %v", err)
				}
				return p
			},
		},
		{
			name: "symlink to a valid config",
			setup: func(t *testing.T, s *sandbox) string {
				target := s.writeConfig(t, validConfig)
				link := filepath.Join(s.home, "link.yaml")
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
				return link
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			cfg := tc.setup(t, s)
			writeFile(t, s.inbox, compliantName, syntheticPDF(t))

			r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)

			if r.code != 2 {
				t.Fatalf("exit code = %d, want 2\nstderr:\n%s", r.code, r.stderr)
			}
			if got := regularFiles(t, s.inbox); !slices.Equal(got, []string{compliantName}) {
				t.Errorf("inbox = %q, want untouched", got)
			}
		})
	}
}

// TestRun_CollectFiledModesPrivate: filed documents are 0600 under 0700
// directories, and the state dir is 0700.
func TestRun_CollectFiledModesPrivate(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	writeFile(t, s.inbox, compliantName, syntheticPDF(t))

	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	check := func(p string, want os.FileMode) {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Errorf("lstat %s: %v", p, err)
			return
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	check(filepath.Join(s.out, filepath.FromSlash(filedPath)), 0o600)
	for _, d := range []string{"2026", "2026/energy", "2026/energy/edf"} {
		check(filepath.Join(s.out, filepath.FromSlash(d)), 0o700)
	}
	check(s.state, 0o700)
	check(filepath.Join(s.state, "reports", reportBase+".json"), 0o600)
}

// TestRun_CollectSymlinkedOutputFolder: output.local may be a symlink (e.g.
// to a folder synced by Google Drive for desktop, docs/spec.md); collect
// follows it and files the document in the target.
func TestRun_CollectSymlinkedOutputFolder(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	link := filepath.Join(s.home, "Linked")
	if err := os.Symlink(s.out, link); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}
	cfg := s.writeConfig(t, strings.Replace(validConfig, "local: ~/Invoices", "local: ~/Linked", 1))
	writeFile(t, s.inbox, compliantName, syntheticPDF(t))

	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	if got := regularFiles(t, filepath.Join(s.out, "2026")); !slices.Equal(got, []string{strings.TrimPrefix(filedPath, "2026/")}) {
		t.Errorf("filed in target = %q, want %q", got, filedPath)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("output link replaced (lstat mode %v, err %v)", fi.Mode(), err)
	}
}

// TestRun_CollectSymlinkedInboxRefusedExit1: unlike output.local, the inbox
// folder inside it must be a real directory: a symlinked inbox could make
// collect move files from anywhere into the output folder.
func TestRun_CollectSymlinkedInboxRefusedExit1(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	elsewhere := filepath.Join(s.home, "Elsewhere")
	writeFile(t, s.home, "Elsewhere/"+compliantName, syntheticPDF(t))
	if err := os.Remove(s.inbox); err != nil {
		t.Fatalf("setup remove inbox: %v", err)
	}
	if err := os.Symlink(elsewhere, s.inbox); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}
	cfg := s.writeConfig(t, validConfig)

	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "inbox folder") {
		t.Fatalf("exit code = %d, stderr = %q; want 1 naming the inbox folder", r.code, r.stderr)
	}
	if got := regularFiles(t, elsewhere); !slices.Equal(got, []string{compliantName}) {
		t.Errorf("link target = %q, want untouched", got)
	}
}
