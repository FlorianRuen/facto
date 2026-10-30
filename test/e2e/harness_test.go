//go:build e2e

package e2e

// End-to-end checks of the harness plumbing against the real facto binary
// (built with -tags e2e) and Chrome for Testing (J1 T22). They need the
// production FACTO_E2E_* wiring of cmd/facto: FACTO_E2E_CHROME,
// FACTO_E2E_LOOPBACK and FACTO_E2E_CA (see scenario.go).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// probeConfig enables fakeprovider with e2e:// references. Sessions are
// ephemeral: the sandbox has no keyring.
const probeConfig = `output:
  local: ~/Invoices
state_dir: ~/.facto
notify: none
sessions: ephemeral
connectors:
  fakeprovider:
    enabled: true
    category: services
    login: e2e://fp/login
    password: e2e://fp/password
`

// harnessProbeScenario logs in through the fake site in password mode with
// collect (non-interactive) and runs both browser probes.
var harnessProbeScenario = `name: harness-probes
description: T22 self-test of the login-page hook, the request log and the browser probes
setup:
  - path: config.yaml
    content: |
` + indent(probeConfig, "      ") + `
args: [collect, --config, "{{home}}/config.yaml", --year, "2026", --non-interactive]
fakesite:
  mode: password
  login: fp/login
  password: fp/password
  invoices:
    - { id: FP-2026-0001, contract: C-1, issued_at: 2026-03-14, amount_cents: 8412, currency: EUR, fixture: edf-invoice.pdf }
secrets:
  fp/login: "user-{{canary:token}}"
  fp/password: "{{canary:password}}"
expect:
  exit: 0
  requests:
    - { method: GET, host: www.fakeprovider.test, path: /login, min: 1 }
    - { method: POST, host: www.fakeprovider.test, path: /login, count: 1 }
    - { method: GET, host: www.fakeprovider.test, path: /account, min: 1 }
    - { host: evil.test, count: 0 }
    - { host: sso.fakeprovider.test, count: 0 }
    - { method: GET, host: www.fakeprovider.test, path: /api/invoices, min: 1 }
    - { method: GET, host: www.fakeprovider.test, path: /api/invoices/FP-2026-0001/pdf, count: 1 }
  browser: { no_cdp_port: true, profile_removed: true }
`

func indent(s, pfx string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pfx + l
	}
	return strings.Join(lines, "\n")
}

// TestHarness_LoginPageProbes runs the login-page hook end to end: while
// Chrome renders the login form, the probe finds no TCP listener in facto's
// process tree; after the run, the Chrome profile is gone; the request log
// shows the login and no off-allowlist host.
func TestHarness_LoginPageProbes(t *testing.T) {
	t.Parallel()
	sc, err := Parse([]byte(harnessProbeScenario))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bin := buildFacto(t)
	runScenario(t, bin, sc)
}

// TestE2EEnv_RefusesUnsafeLoopbackAndCA: the e2e build accepts only
// 127.0.0.1:<port> as FACTO_E2E_LOOPBACK and only a private regular PEM
// certificate file as FACTO_E2E_CA, both or neither. Anything else is a
// usage error (exit 2) naming the variable, before any connection: the
// fake site sees no request.
func TestE2EEnv_RefusesUnsafeLoopbackAndCA(t *testing.T) {
	t.Parallel()
	bin := buildFacto(t)
	site := unitSite(t, ModePassword)
	port := fmt.Sprint(site.Addr().Port())
	valid := "127.0.0.1:" + port
	tests := []struct {
		name     string
		loopback string // "" = unset
		ca       func(t *testing.T, dir string) string
		chrome   func(t *testing.T) string // nil = chromePath(t)
		wantVar  string
	}{
		{name: "localhost name", loopback: "localhost:" + port, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "wildcard address", loopback: "0.0.0.0:" + port, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "other loopback address", loopback: "127.0.0.2:" + port, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "ipv6 loopback", loopback: "[::1]:" + port, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "ipv4-mapped loopback", loopback: "[::ffff:127.0.0.1]:" + port, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "private address", loopback: "10.0.0.1:443", wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "port zero", loopback: "127.0.0.1:0", wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "no port", loopback: "127.0.0.1", wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "port out of range", loopback: "127.0.0.1:70000", wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "two targets", loopback: valid + ",127.0.0.1:1", wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "url form", loopback: "https://" + valid, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "loopback without CA", loopback: valid, ca: func(*testing.T, string) string { return "" }, wantVar: "FACTO_E2E_CA"},
		{name: "CA without loopback", ca: func(t *testing.T, dir string) string { return writeCA(t, site, dir, "ca.pem", 0o600) }, wantVar: "FACTO_E2E_LOOPBACK"},
		{name: "CA group readable", loopback: valid, ca: func(t *testing.T, dir string) string { return writeCA(t, site, dir, "ca.pem", 0o640) }, wantVar: "FACTO_E2E_CA"},
		{name: "CA relative path", loopback: valid, ca: func(*testing.T, string) string { return "ca.pem" }, wantVar: "FACTO_E2E_CA"},
		{name: "CA missing", loopback: valid, ca: func(_ *testing.T, dir string) string { return filepath.Join(dir, "none.pem") }, wantVar: "FACTO_E2E_CA"},
		{name: "CA not PEM", loopback: valid, ca: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "ca.pem", []byte("not a certificate\n"), 0o600)
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA symlink", loopback: valid, ca: func(t *testing.T, dir string) string {
			target := writeCA(t, site, dir, "real.pem", 0o600)
			link := filepath.Join(dir, "link.pem")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA is a private key", loopback: valid, ca: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "ca.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA dir group readable", loopback: valid, ca: func(t *testing.T, dir string) string {
			sub := filepath.Join(dir, "shared")
			mkPrivate(t, sub)
			p := writeCA(t, site, sub, "ca.pem", 0o600)
			// #nosec G302 -- a group-readable CA dir is the refusal under test (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
			if err := os.Chmod(sub, 0o750); err != nil {
				t.Fatal(err)
			}
			return p
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA over 64 KiB", loopback: valid, ca: func(t *testing.T, dir string) string {
			pemCA := site.CAPEM()
			big := bytes.Repeat(pemCA, 64<<10/len(pemCA)+1) // valid certificates only, just too many bytes
			return writeFile(t, dir, "ca.pem", big, 0o600)
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA PEM with headers", loopback: valid, ca: func(t *testing.T, dir string) string {
			first, rest, _ := bytes.Cut(site.CAPEM(), []byte("\n"))
			withHeader := append(append(first, []byte("\nProc-Type: 4,ENCRYPTED\n\n")...), rest...)
			return writeFile(t, dir, "ca.pem", withHeader, 0o600)
		}, wantVar: "FACTO_E2E_CA"},
		{name: "CA trailing junk", loopback: valid, ca: func(t *testing.T, dir string) string {
			return writeFile(t, dir, "ca.pem", append(site.CAPEM(), []byte("not a certificate\n")...), 0o600)
		}, wantVar: "FACTO_E2E_CA"},
		{name: "chrome relative path", loopback: valid, chrome: func(*testing.T) string { return "chrome" }, wantVar: "FACTO_E2E_CHROME"},
		{name: "chrome unclean path", loopback: valid, chrome: func(t *testing.T) string {
			c := chromePath(t)
			return filepath.Dir(c) + "/./" + filepath.Base(c)
		}, wantVar: "FACTO_E2E_CHROME"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			cfg := probeConfig
			sc := &Scenario{Setup: []SetupFile{{Path: "config.yaml", Content: &cfg}}}
			s.setup(t, sc)
			sec := filepath.Join(s.root, "secrets")
			if err := writeSecrets(t.Context(), sec, map[string]string{"fp/login": unitLogin, "fp/password": unitPassword}); err != nil {
				t.Fatal(err)
			}
			caDir := filepath.Join(s.root, "ca")
			mkPrivate(t, caDir)
			ca := writeCA(t, site, caDir, "default.pem", 0o600)
			if tt.ca != nil {
				ca = tt.ca(t, caDir)
			}
			chrome := chromePath(t)
			if tt.chrome != nil {
				chrome = tt.chrome(t)
			}
			s.extraEnv = map[string]string{
				"FACTO_E2E_SECRETS_DIR": sec,
				"FACTO_E2E_CHROME":      chrome,
				"FACTO_E2E_LOOPBACK":    tt.loopback,
				"FACTO_E2E_CA":          ca,
			}
			site.ResetLog()
			r := s.run(t, bin, []string{"collect", "--config", "{{home}}/config.yaml", "--year", "2026", "--non-interactive"})
			if r.code != 2 {
				t.Errorf("exit code = %d, want 2 (usage error)\nstderr:\n%s", r.code, r.stderr)
			}
			if !strings.Contains(string(r.stderr), tt.wantVar) {
				t.Errorf("stderr does not name %s:\n%s", tt.wantVar, r.stderr)
			}
			if strings.Contains(string(r.stderr), "BEGIN") {
				t.Errorf("stderr echoes file content:\n%s", r.stderr)
			}
			if got := site.Requests(); len(got) != 0 {
				t.Errorf("the fake site was contacted despite the refused variable: %+v", got)
			}
		})
	}
}

func mkPrivate(t *testing.T, dir string) {
	t.Helper()
	r, err := fsx.Open(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate(filepath.Base(dir)); err != nil {
		t.Fatal(err)
	}
}

// writeFile writes data to dir/name through fsx, then sets mode.
func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(context.Background(), name, data); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeCA(t *testing.T, s *fakeSite, dir, name string, mode os.FileMode) string {
	t.Helper()
	return writeFile(t, dir, name, s.CAPEM(), mode)
}
