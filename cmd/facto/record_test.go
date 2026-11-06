// Tests of `facto record` (J2): every refusal happens before any browser
// starts, and nothing is written for a refused run. The recording itself
// runs against real Chrome and the fake site in make e2e
// (test/e2e/record-fakeprovider.yaml).
package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
)

// recordEnv is the sandbox env with a terminal on stdin and a pool seam
// that fails the test if a browser is ever asked for.
func recordEnv(t *testing.T, s *sandbox) env {
	t.Helper()
	e := s.env()
	e.Terminal = &fakeTerminal{tty: true}
	e.NewPool = func(context.Context, env, poolParams) (browserPool, error) {
		t.Error("a browser pool was built for a refused record run")
		return nil, os.ErrInvalid
	}
	return e
}

// outsideDir is a private directory that is not in any git work tree.
func outsideDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if inGitWorkTree(d) {
		t.Fatalf("t.TempDir %s is inside a git work tree: the test needs one outside", d)
	}
	return d
}

func TestRecord_RefusesBeforeAnyBrowser(t *testing.T) {
	t.Parallel()
	repo, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(outsideDir(t), "site.har")
	existing := filepath.Join(outsideDir(t), "old.har")
	writeFile(t, filepath.Dir(existing), "old.har", []byte("{}"))
	// A home holding a Dropbox folder, outside any git work tree.
	dropbox := filepath.Join(outsideDir(t), "home")
	writeFile(t, filepath.Dir(dropbox), "home/Dropbox/.keep", nil)

	tests := []struct {
		name  string
		args  []string
		tty   bool
		home  string
		code  int
		inErr string
	}{
		{"not a terminal", []string{"record", "https://www.example.test/", "-o", out, "--allow", "www.example.test"}, false, "", 2, "interactive terminal"},
		{"no out", []string{"record", "https://www.example.test/", "--allow", "www.example.test"}, true, "", 2, "--out"},
		{"out not .har", []string{"record", "https://www.example.test/", "-o", out + ".json", "--allow", "www.example.test"}, true, "", 2, "--out"},
		{"out inside the repository", []string{"record", "https://www.example.test/", "-o", filepath.Join(repo, "x.har"), "--allow", "www.example.test"}, true, "", 2, "git work tree"},
		{"out exists", []string{"record", "https://www.example.test/", "-o", existing, "--allow", "www.example.test"}, true, "", 2, "--force"},
		{"no allowed domain", []string{"record", "https://www.example.test/", "-o", out}, true, "", 2, "--allow"},
		{"bad allowed domain", []string{"record", "https://www.example.test/", "-o", out, "--allow", "*.com"}, true, "", 2, "--allow"},
		{"unknown connector", []string{"record", "https://www.example.test/", "-o", out, "--connector", "nope"}, true, "", 2, "not available"},
		{"http url", []string{"record", "http://www.example.test/", "-o", out, "--allow", "www.example.test"}, true, "", 2, "https"},
		{"url off allowlist", []string{"record", "https://evil.test/", "-o", out, "--allow", "www.example.test"}, true, "", 2, "allowed domain"},
		{"url with userinfo", []string{"record", "https://u:p@www.example.test/", "-o", out, "--allow", "www.example.test"}, true, "", 2, "user info"},
		{"url other port", []string{"record", "https://www.example.test:8443/", "-o", out, "--allow", "www.example.test"}, true, "", 2, "port 443"},
		{"static whole host", []string{"record", "https://www.example.test/", "-o", out, "--allow", "www.example.test", "--allow-static", "https://storage.googleapis.com/"}, true, "", 2, "--allow-static"},
		{"static http", []string{"record", "https://www.example.test/", "-o", out, "--allow", "www.example.test", "--allow-static", "http://cdn.example.test/app/"}, true, "", 2, "--allow-static"},
		{"bad timeout", []string{"record", "https://www.example.test/", "-o", out, "--allow", "www.example.test", "--timeout", "-1s"}, true, "", 2, "--timeout"},
		{"synced folder", []string{"record", "https://www.example.test/", "-o", filepath.Join(dropbox, "Dropbox", "x.har"), "--allow", "www.example.test"}, true, dropbox, 2, "sync"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			e := recordEnv(t, s)
			e.Terminal = &fakeTerminal{tty: tt.tty}
			if tt.home != "" {
				e.Home = tt.home
			}
			r := invoke(t.Context(), e, "", tt.args...)
			if r.code != tt.code || !strings.Contains(r.stderr, tt.inErr) {
				t.Fatalf("code %d stderr %q, want code %d mentioning %q", r.code, r.stderr, tt.code, tt.inErr)
			}
			if strings.Contains(r.stderr, "u:p@") || strings.Contains(r.stderr, "evil.test") {
				t.Errorf("error quotes the URL: %q", r.stderr)
			}
			if _, err := os.Lstat(out); err == nil {
				t.Errorf("%s written by a refused run", out)
			}
		})
	}
}

func TestRecordDomains_ConnectorAndAllowMerged(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	e := s.env()
	e.Connectors = (&synthConn{}).catalog()
	got, err := recordDomains(e, recordFlags{connector: synthID, allow: []string{" CDN.synthlogin.example "}})
	if err != nil {
		t.Fatalf("recordDomains: %v", err)
	}
	want := append(slices.Clone(synthDomains), "cdn.synthlogin.example")
	if !slices.Equal(got, want) {
		t.Fatalf("domains = %q, want %q", got, want)
	}
}

func TestWriteRecording_Private(t *testing.T) {
	t.Parallel()
	dir := outsideDir(t)
	p := filepath.Join(dir, "r.har")
	if err := writeRecording(t.Context(), p, har.New("facto", "test")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := fsx.CheckPrivate(p); err != nil || fi.Size() == 0 {
		t.Fatalf("recording %v size %d: %v", fi.Mode(), fi.Size(), err)
	}
}

func TestRecordStatic_FlagAndConnectorMerged(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	e := s.env()
	c := &synthConn{}
	e.Connectors = c.catalog()
	got, err := recordStatic(e, recordFlags{connector: synthID, static: []string{"https://cdn.synthlogin.example/app/"}})
	if err != nil {
		t.Fatalf("recordStatic: %v", err)
	}
	if !slices.Equal(got, []string{"https://cdn.synthlogin.example/app/"}) {
		t.Fatalf("static = %q", got)
	}
}
