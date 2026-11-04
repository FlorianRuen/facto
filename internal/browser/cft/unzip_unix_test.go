//go:build unix

// Unix mode and symlink tests for Unzip and Install (J1 task T11, ADR 0008:
// "Unzip strips the setuid bit, so the extracted sandbox is not SUID"). See
// helpers_test.go for the expected API.
package cft_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestUnzip_ModesSanitized(t *testing.T) {
	t.Parallel()

	entries := []zent{
		{name: "bin/", mode: fs.ModeDir | 0o777},
		{name: "bin/x755", mode: 0o755, body: []byte("x")},
		{name: "bin/x777", mode: 0o777, body: []byte("x")},
		{name: "bin/x100", mode: 0o100, body: []byte("x")},
		{name: "bin/x744", mode: 0o744, body: []byte("x")},
		{name: "bin/x010", mode: 0o010, body: []byte("x")},
		{name: "bin/x001", mode: 0o001, body: []byte("x")},
		{name: "bin/suid", mode: 0o755 | fs.ModeSetuid, body: []byte("x")},
		{name: "bin/sgid", mode: 0o755 | fs.ModeSetgid, body: []byte("x")},
		{name: "bin/sticky", mode: 0o755 | fs.ModeSticky, body: []byte("x")},
		{name: "data/", mode: fs.ModeDir | 0o755},
		{name: "data/f644", mode: 0o644, body: []byte("x")},
		{name: "data/f666", mode: 0o666, body: []byte("x")},
		{name: "data/f400", mode: 0o400, body: []byte("x")},
		{name: "data/suid-noexec", mode: 0o644 | fs.ModeSetuid, body: []byte("x")},
		{name: "data/sgid-noexec", mode: 0o644 | fs.ModeSetgid, body: []byte("x")},
		{name: "shared/", mode: fs.ModeDir | 0o777 | fs.ModeSticky},
		{name: "setgid-dir/", mode: fs.ModeDir | 0o2775},
		{name: "implied/deep/file", mode: 0o644, body: []byte("x")},
	}
	want := map[string]fs.FileMode{
		"bin":               fs.ModeDir | 0o700,
		"bin/x755":          0o700,
		"bin/x777":          0o700,
		"bin/x100":          0o700,
		"bin/x744":          0o700,
		"bin/x010":          0o700,
		"bin/x001":          0o700,
		"bin/suid":          0o700,
		"bin/sgid":          0o700,
		"bin/sticky":        0o700,
		"data":              fs.ModeDir | 0o700,
		"data/f644":         0o600,
		"data/f666":         0o600,
		"data/f400":         0o600,
		"data/suid-noexec":  0o600,
		"data/sgid-noexec":  0o600,
		"shared":            fs.ModeDir | 0o700,
		"setgid-dir":        fs.ModeDir | 0o700,
		"implied":           fs.ModeDir | 0o700,
		"implied/deep":      fs.ModeDir | 0o700,
		"implied/deep/file": 0o600,
	}

	e := newUnzipEnv(t)
	if err := e.unzip(t.Context(), buildZip(t, entries), cft.Limits{}); err != nil {
		t.Fatalf("Unzip: %v", err)
	}
	const mask = fs.ModeType | fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
	for name, wantMode := range want {
		t.Run(name, func(t *testing.T) {
			fi, err := os.Lstat(filepath.Join(e.dst, filepath.FromSlash(name)))
			if err != nil {
				t.Fatalf("Lstat: %v", err)
			}
			if got := fi.Mode() & mask; got != wantMode {
				t.Fatalf("mode = %v, want %v", got, wantMode)
			}
		})
	}
}

func TestUnzip_PreexistingSymlinkInInstallDirNotFollowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		link string // created in dst, pointing at outside
		// wantErr: writing below a directory symlink must fail; a file
		// symlink may be refused or replaced, never written through.
		wantErr bool
	}{
		{name: "directory symlink on an entry's parent", link: "chrome-linux64", wantErr: true},
		{name: "file symlink on an entry", link: "ok.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			target := e.outside
			if tt.link == "ok.txt" {
				target = filepath.Join(e.outside, "sentinel")
			}
			if err := os.Symlink(target, filepath.Join(e.dst, tt.link)); err != nil {
				t.Fatalf("setup Symlink: %v", err)
			}
			archive := buildZip(t, append(chromeEntries(), zent{name: "ok.txt", body: []byte("pwned")}))
			err := e.unzip(t.Context(), archive, cft.Limits{})
			if tt.wantErr && err == nil {
				t.Fatal("Unzip = nil, want an error: a pre-existing directory symlink must not be written through")
			}
			e.assertOutsideUntouched(t)
		})
	}
}

func TestInstall_ExtractedTreeIsPrivate(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	s := newServer(t, serveBytes(archive))
	dir := privateDir(t)
	if _, err := newInstaller(t, s, manifestFor(archive), dir, nil).Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m := fi.Mode()
		if m&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || m.Perm()&0o077 != 0 {
			t.Errorf("%s mode %v: want no setuid/setgid/sticky and no group/world bits", p, m)
		}
		if m.Type() != 0 && !m.IsDir() {
			t.Errorf("%s type %v: want only regular files and directories", p, m.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sandbox := filepath.Join(dir, testVersion, "chrome-linux64", "chrome_sandbox")
	fi, err := os.Lstat(sandbox)
	if err != nil {
		t.Fatalf("Lstat(chrome_sandbox): %v", err)
	}
	if fi.Mode()&fs.ModeSetuid != 0 {
		t.Fatal("chrome_sandbox is setuid after install, want the bit stripped")
	}
}

func TestNew_RefusesBadInstallDir(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	tests := []struct {
		name    string
		dir     func(t *testing.T) string
		wantErr error // nil: any error
	}{
		{
			name:    "missing directory",
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantErr: fs.ErrNotExist,
		},
		{
			name: "group and world readable directory",
			dir: func(t *testing.T) string {
				d := privateDir(t)
				chmodRaw(t, d, 0o755)
				return d
			},
			wantErr: fsx.ErrInsecurePerms,
		},
		{
			name: "world writable directory",
			dir: func(t *testing.T) string {
				d := privateDir(t)
				chmodRaw(t, d, 0o777)
				return d
			},
			wantErr: fsx.ErrInsecurePerms,
		},
		{
			name:    "empty path",
			dir:     func(*testing.T) string { return "" },
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, serveBytes(archive))
			_, err := cft.New(cft.Options{Manifest: manifestFor(archive), Dir: tt.dir(t), HTTP: s.httpOpts(), Log: discardLog()})
			if err == nil {
				t.Fatal("New = nil error, want a refusal")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("New = %v, want errors.Is %v", err, tt.wantErr)
			}
			if got := s.requests(); len(got) != 0 {
				t.Fatalf("server got %v, want no request", got)
			}
		})
	}
}
