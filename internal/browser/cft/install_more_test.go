// Extra install tests (J1 task T11): failures after a verified download, and
// HTTP failures, leave the install root as it was.
package cft_test

import (
	"io/fs"
	"net/http"
	"testing"
)

func TestInstall_VerifiedArchiveWithoutExecutableRefused(t *testing.T) {
	t.Parallel()

	archive := buildZip(t, []zent{
		{name: "chrome-linux64/", mode: fs.ModeDir | 0o755},
		{name: "chrome-linux64/resources.pak", body: []byte("synthetic resources")},
	})
	s := newServer(t, serveBytes(archive))
	dir := privateDir(t)
	in := newInstaller(t, s, manifestFor(archive), dir, nil)
	exe, err := in.Install(t.Context())
	if err == nil {
		t.Fatalf("Install() = %q, nil; want an error for an archive without chrome", exe)
	}
	assertEmpty(t, dir)
}

func TestInstall_HTTPErrorLeavesNothing(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	for _, code := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			s := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "synthetic failure", code)
			})
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)
			if _, err := in.Install(t.Context()); err == nil {
				t.Fatalf("Install() = nil, want an error for status %d", code)
			}
			assertEmpty(t, dir)
		})
	}
}
