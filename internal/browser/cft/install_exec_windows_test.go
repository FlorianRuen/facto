//go:build windows

// Windows variant of TestInstall_RefusesNonExecutableChrome
// (install_sweep_unix_test.go): Windows keeps no POSIX mode bits on the
// extracted file (SEC-J0-18), so the refusal rests on the archive mode of
// the chrome entry. It must hold all the same: an archive whose chrome
// entry has no execute bit, or no Unix mode at all, is not the pinned
// build and leaves the install root empty.
package cft_test

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"testing"
)

func TestInstall_RefusesNonExecutableChromeWindows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
	}{
		{name: "entry without mode bits", archive: func(t *testing.T) []byte {
			t.Helper()
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, e := range []struct{ name, body string }{
				{"chrome-linux64/", ""},
				{"chrome-linux64/chrome", "#!/bin/sh\n# synthetic chrome, no mode bits\n"},
			} {
				w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: pinDate})
				if err != nil {
					t.Fatalf("zip CreateHeader(%q): %v", e.name, err)
				}
				if _, err := w.Write([]byte(e.body)); err != nil {
					t.Fatalf("zip write: %v", err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("zip close: %v", err)
			}
			return buf.Bytes()
		}},
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
				t.Fatalf("Install() = %q, nil; want a refusal: chrome entry has no execute bit", exe)
			}
			assertEmpty(t, dir)
		})
	}
}
