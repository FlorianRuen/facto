//go:build unix

// Review follow-ups (J1 task T11): Install sweeps the work directories an
// interrupted earlier install left in Dir (never following a symlink), and
// refuses an archive whose chrome entry is not executable by its owner.
package cft_test

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// plantLeftovers creates what a killed install leaves behind, plus a
// symlinked look-alike pointing outside Dir and an unrelated entry.
// It returns the outside directory, whose content must survive.
func plantLeftovers(t *testing.T, dir string) string {
	t.Helper()
	outside := filepath.Join(filepath.Dir(dir), "outside")
	mkdirRaw(t, outside, 0o700)
	writeRaw(t, filepath.Join(outside, "sentinel"), "outside sentinel")

	work := filepath.Join(dir, ".cft-work-LEFTOVER1")
	mkdirRaw(t, work, 0o700)
	mkdirRaw(t, filepath.Join(work, "staging"), 0o700)
	writeRaw(t, filepath.Join(work, "archive.zip"), "partial archive")
	writeRaw(t, filepath.Join(work, "staging", "half"), "half extracted")
	writeRaw(t, filepath.Join(dir, ".cft-work-STRAYFILE"), "stray")
	if err := os.Symlink(outside, filepath.Join(dir, ".cft-work-LINK")); err != nil {
		t.Fatalf("setup Symlink: %v", err)
	}
	// An unrelated entry, even a shared one, is not the sweep's business.
	mkdirRaw(t, filepath.Join(dir, "keep-me"), 0o755)
	return outside
}

func assertSwept(t *testing.T, dir, outside string) {
	t.Helper()
	if got, want := dirEntries(t, dir), []string{testVersion, "keep-me"}; !slices.Equal(got, want) {
		t.Fatalf("install root holds %v, want %v (leftover work entries swept, others kept)", got, want)
	}
	if got := dirEntries(t, outside); !slices.Equal(got, []string{"sentinel"}) {
		t.Fatalf("outside holds %v, want [sentinel]: the symlinked leftover was followed", got)
	}
	b, err := os.ReadFile(filepath.Clean(filepath.Join(outside, "sentinel")))
	if err != nil || string(b) != "outside sentinel" {
		t.Fatalf("outside sentinel = %q, %v; want untouched", b, err)
	}
}

func TestInstall_SweepsLeftoverWorkDirs(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)

	t.Run("before a download", func(t *testing.T) {
		t.Parallel()
		s := newServer(t, serveBytes(archive))
		dir := privateDir(t)
		outside := plantLeftovers(t, dir)
		if _, err := newInstaller(t, s, manifestFor(archive), dir, nil).Install(t.Context()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		assertSwept(t, dir, outside)
	})

	t.Run("when already installed", func(t *testing.T) {
		t.Parallel()
		s := newServer(t, serveBytes(archive))
		dir := privateDir(t)
		in := newInstaller(t, s, manifestFor(archive), dir, nil)
		if _, err := in.Install(t.Context()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		outside := plantLeftovers(t, dir)
		if _, err := in.Install(t.Context()); err != nil {
			t.Fatalf("second Install: %v", err)
		}
		if got := len(s.requests()); got != 1 {
			t.Fatalf("server got %d requests, want 1 (verified install reused)", got)
		}
		assertSwept(t, dir, outside)
	})
}

// fatZip builds a zip whose entries carry no Unix mode (as written by a
// non-Unix archiver): archive/zip reports them 0666 files and 0777 dirs.
func fatZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"chrome-linux64/", ""},
		{"chrome-linux64/chrome", "#!/bin/sh\n# synthetic chrome, no mode bits\n"},
		{"chrome-linux64/resources.pak", "synthetic resources"},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: pinDate})
		if err != nil {
			t.Fatalf("zip CreateHeader(%q): %v", e.name, err)
		}
		if e.body != "" {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatalf("zip write: %v", err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestInstall_RefusesNonExecutableChrome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
	}{
		{name: "entry without mode bits", archive: fatZip},
		{name: "entry 0644", archive: func(t *testing.T) []byte {
			return buildZip(t, []zent{
				{name: "chrome-linux64/", mode: fs.ModeDir | 0o755},
				{name: "chrome-linux64/chrome", mode: 0o644, body: []byte("#!/bin/sh\n")},
			})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := tt.archive(t)
			s := newServer(t, serveBytes(archive))
			dir := privateDir(t)
			exe, err := newInstaller(t, s, manifestFor(archive), dir, nil).Install(t.Context())
			if err == nil {
				t.Fatalf("Install() = %q, nil; want a refusal: chrome is not executable by its owner", exe)
			}
			assertEmpty(t, dir)
		})
	}
}
