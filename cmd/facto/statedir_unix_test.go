//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// TestCheckStateDirOutside covers the physical state dir check on its own:
// accepted layouts, symlinks resolved on either side, and a dangling link.
func TestCheckStateDirOutside(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup returns state_dir and output.local inside root.
		setup   func(t *testing.T, root string) (state, out string)
		refused bool  // config error wrapping ErrStateDirInOutput
		wantErr error // other expected error, or nil
	}{
		{
			name: "siblings, state dir missing",
			setup: func(t *testing.T, root string) (string, string) {
				return filepath.Join(root, "state", "deep"), mkdir(t, root, "out")
			},
		},
		{
			name: "state dir is an existing link into the output folder",
			setup: func(t *testing.T, root string) (string, string) {
				out := mkdir(t, root, "out")
				link(t, filepath.Join(out, "sub"), filepath.Join(root, "state"))
				mkdir(t, out, "sub")
				return filepath.Join(root, "state"), out
			},
			refused: true,
		},
		{
			name: "state dir equals the output folder through a link",
			setup: func(t *testing.T, root string) (string, string) {
				out := mkdir(t, root, "out")
				link(t, out, filepath.Join(root, "alias"))
				return filepath.Join(root, "alias"), out
			},
			refused: true,
		},
		{
			name: "output folder is a link to a sibling of the state dir",
			setup: func(t *testing.T, root string) (string, string) {
				target := mkdir(t, root, "real")
				link(t, target, filepath.Join(root, "out"))
				return filepath.Join(root, "state"), filepath.Join(root, "out")
			},
		},
		{
			name: "dangling link in the state dir path",
			setup: func(t *testing.T, root string) (string, string) {
				link(t, filepath.Join(root, "nowhere"), filepath.Join(root, "st"))
				return filepath.Join(root, "st", "state"), mkdir(t, root, "out")
			},
			wantErr: errDanglingStateLink,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			state, out := tt.setup(t, t.TempDir())
			err := checkStateDirOutside(state, out)
			switch {
			case tt.refused:
				if !errors.Is(err, config.ErrStateDirInOutput) || !errors.Is(err, orchestrator.ErrConfig) || !errors.Is(err, config.ErrInvalid) {
					t.Fatalf("checkStateDirOutside() = %v, want ErrStateDirInOutput, ErrInvalid and ErrConfig", err)
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("checkStateDirOutside() = %v, want %v", err, tt.wantErr)
				}
			case err != nil:
				t.Fatalf("checkStateDirOutside() = %v, want nil", err)
			}
			if !tt.refused && tt.wantErr == nil {
				if _, err := os.Lstat(state); err == nil {
					t.Fatalf("state dir %s created by the check", state)
				}
			}
		})
	}
}

func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	p := filepath.Join(parent, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return p
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatalf("symlink: %v", err)
	}
}
