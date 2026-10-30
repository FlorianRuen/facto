//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// TestCheckStateDirOutside_SymlinkIntoDropboxRefused (SEC-J0-17): config
// only tests the state_dir text for synced-folder names, so a state dir that
// is a symlink, or sits under a symlinked ancestor, resolving into a folder a
// sync client uploads (Dropbox, OneDrive, Google Drive, iCloud Drive…) gets
// through. checkStateDirOutside must run the synced-folder test on the
// resolved path too. As in config, the home directory's own components are
// not tested (a user may be named like a sync client), and home is compared
// once resolved as well, since home itself may be reached through a link.
//
// Every layout lives in a temp dir: root/home plays the injected home,
// root/out the output folder. Folder names are synthetic.
func TestCheckStateDirOutside_SymlinkIntoDropboxRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup builds the layout under root and returns state_dir and home.
		setup   func(t *testing.T, root string) (state, home string)
		refused bool // config error wrapping ErrStateDirSynced
	}{
		// Refused: the resolved path is inside a synced folder.
		{
			name: "state dir is a link into Dropbox",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Dropbox", "facto")
				link(t, target, filepath.Join(home, ".facto-state"))
				return filepath.Join(home, ".facto-state"), home
			},
			refused: true,
		},
		{
			name: "missing state dir under a linked ancestor into Dropbox",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				mkdirAll(t, home, "Dropbox")
				link(t, filepath.Join(home, "Dropbox"), filepath.Join(home, "data"))
				return filepath.Join(home, "data", "facto", "state"), home
			},
			refused: true,
		},
		{
			name: "link to a lower case dropbox folder",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "dropbox", "x")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "chain of links ending in Dropbox",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Dropbox", "deep")
				link(t, target, filepath.Join(home, "hop2"))
				link(t, filepath.Join(home, "hop2"), filepath.Join(home, "hop1"))
				return filepath.Join(home, "hop1", "state"), home
			},
			refused: true,
		},
		{
			name: "link into a Dropbox team folder",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Dropbox (Synthetic Team)", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "link into OneDrive",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "OneDrive", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "linked ancestor into OneDrive for business",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "OneDrive - Synthetic Org", "x")
				link(t, target, filepath.Join(home, "work"))
				return filepath.Join(home, "work", "state"), home
			},
			refused: true,
		},
		{
			name: "link into Google Drive",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Google Drive", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "link into Drive for desktop CloudStorage",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Library", "CloudStorage", "GoogleDrive-synthetic", "My Drive", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "link into iCloud Drive",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "Library", "Mobile Documents", "com~apple~CloudDocs", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "link to a synced folder outside home",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, root, "mnt", "Dropbox", "facto")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
			refused: true,
		},
		{
			name: "no link, state dir inside Dropbox",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				mkdirAll(t, home, "Dropbox")
				return filepath.Join(home, "Dropbox", "facto"), home
			},
			refused: true,
		},

		// Accepted.
		{
			name: "no link, plain state dir under home",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				return filepath.Join(home, ".local", "state", "facto"), home
			},
		},
		{
			name: "link resolving outside any synced folder",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, root, "elsewhere")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st", "facto"), home
			},
		},
		{
			name: "link to a folder whose name only contains a sync client name",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "home")
				target := mkdirAll(t, home, "dropbox-notes")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st", "facto"), home
			},
		},
		{
			name: "home named like a sync client and reached through a link",
			setup: func(t *testing.T, root string) (string, string) {
				realHome := mkdir(t, root, "Box")
				home := filepath.Join(root, "homelink")
				link(t, realHome, home)
				return filepath.Join(home, ".facto-state"), home
			},
		},
		{
			name: "home named like a sync client, state dir a link inside it",
			setup: func(t *testing.T, root string) (string, string) {
				home := mkdir(t, root, "Dropbox")
				target := mkdirAll(t, home, "private")
				link(t, target, filepath.Join(home, "st"))
				return filepath.Join(home, "st"), home
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			out := mkdir(t, root, "out")
			state, home := tt.setup(t, root)
			stateExisted := exists(state)

			err := checkStateDirOutside(state, out, home)
			if tt.refused {
				if !errors.Is(err, config.ErrStateDirSynced) || !errors.Is(err, config.ErrInvalid) || !errors.Is(err, orchestrator.ErrConfig) {
					t.Fatalf("checkStateDirOutside() = %v, want ErrStateDirSynced, ErrInvalid and ErrConfig", err)
				}
				if errors.Is(err, config.ErrStateDirInOutput) {
					t.Errorf("checkStateDirOutside() = %v, must not claim the state dir is in the output folder", err)
				}
				msg := err.Error()
				if !strings.Contains(msg, "state_dir") {
					t.Errorf("error %q does not name the state_dir key", msg)
				}
				// Keys, never paths: neither the configured nor the resolved one.
				if strings.Contains(msg, root) {
					t.Errorf("error %q quotes a path", msg)
				}
			} else if err != nil {
				t.Fatalf("checkStateDirOutside() = %v, want nil", err)
			}
			if !stateExisted && exists(state) {
				t.Fatalf("state dir %s created by the check", state)
			}
		})
	}
}

// TestPrepareStateDir_SyncedTargetRefusedWithoutOutputFolder (SEC-J0-17):
// `facto login` prepares the state dir before the output folder exists. The
// resolved-path synced-folder check must still run then (today the whole
// physical check is skipped when output.local is missing), and nothing may be
// created in the synced folder.
func TestPrepareStateDir_SyncedTargetRefusedWithoutOutputFolder(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	home := mkdir(t, root, "home")
	synced := mkdirAll(t, home, "Dropbox", "x")
	link(t, synced, filepath.Join(home, "st"))
	yaml := "output:\n  local: '" + filepath.Join(root, "out-missing") + "'\n" +
		"state_dir: '~/st/facto'\n"
	cfg, err := config.Parse([]byte(yaml), config.Options{Home: home})
	if err != nil {
		t.Fatalf("setup Parse() = %v (the lexical check must not see the link)", err)
	}

	err = prepareStateDir(cfg)
	if !errors.Is(err, config.ErrStateDirSynced) || !errors.Is(err, orchestrator.ErrConfig) {
		t.Fatalf("prepareStateDir() = %v, want ErrStateDirSynced and ErrConfig", err)
	}
	if exists(filepath.Join(synced, "facto")) {
		t.Fatal("state dir created inside the synced folder")
	}
}

// mkdirAll creates parent/elems... 0700 and returns it.
func mkdirAll(t *testing.T, parent string, elems ...string) string {
	t.Helper()
	p := parent
	for _, e := range elems {
		p = filepath.Join(p, e)
		if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			t.Fatalf("mkdir: %v", err)
		}
	}
	return p
}

// exists reports whether p exists, without following a final link.
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
