//go:build !windows

package config_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/fsx"
)

// TestLoad_RefusesWorldReadableConfig: config.yaml reveals which suppliers
// and vault items the user has; any group or world bit is refused (the file
// is not read further), owner-only modes are accepted.
func TestLoad_RefusesWorldReadableConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode fs.FileMode
		ok   bool
	}{
		{"owner read write", 0o600, true},
		{"owner read only", 0o400, true},
		{"world readable", 0o644, false},
		{"world readable only", 0o604, false},
		{"group readable", 0o640, false},
		{"group writable", 0o620, false},
		{"world writable", 0o602, false},
		{"everyone", 0o666, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := writeConfig(t, []byte("sessions: persistent\n"))
			if err := os.Chmod(p, tt.mode); err != nil {
				t.Fatalf("setup Chmod: %v", err)
			}
			cfg, err := config.Load(t.Context(), p, opts(fakeHome(t)))
			if tt.ok {
				if err != nil {
					t.Fatalf("Load() mode %#o error = %v, want nil", tt.mode, err)
				}
				return
			}
			if !errors.Is(err, fsx.ErrInsecurePerms) || !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Load() mode %#o error = %v, want fsx.ErrInsecurePerms and ErrInvalid", tt.mode, err)
			}
			if cfg != nil {
				t.Errorf("Load() returned a config along with an error")
			}
		})
	}
}

// TestLoad_RefusesSymlinkedConfig: config.yaml is opened with
// fsx.OpenRegular, so a symlink (which could point at a file another user
// controls, or swap targets between check and read) is refused.
func TestLoad_RefusesSymlinkedConfig(t *testing.T) {
	t.Parallel()
	target := writeConfig(t, []byte("sessions: persistent\n"))
	link := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup Symlink: %v", err)
	}
	_, err := config.Load(t.Context(), link, opts(fakeHome(t)))
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Fatalf("Load() error = %v, want fsx.ErrNotRegular", err)
	}
}

// TestLoad_RefusesFIFO: a FIFO planted at the config path must neither block
// Load nor be read.
func TestLoad_RefusesFIFO(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatalf("setup mkfifo: %v", err)
	}
	_, err := config.Load(t.Context(), p, opts(fakeHome(t)))
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Fatalf("Load() error = %v, want fsx.ErrNotRegular", err)
	}
}
