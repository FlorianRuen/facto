//go:build unix

package main

import (
	"os"
	"path/filepath"
	"slices"
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
