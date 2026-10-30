//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// validScenario uses every field of the format once.
const validScenario = `name: full-example
description: every field once
state_dir: state
setup:
  - path: config.yaml
    mode: "0600"
    content: "home={{home}} secret={{canary:password}}\n"
  - path: Invoices/inbox/a.pdf
    fixture: edf-invoice.pdf
  - path: Invoices/inbox/sub
    dir: true
    mode: "0700"
  - path: Invoices/inbox/link.pdf
    symlink: ../../config.yaml
args: [collect, --config, "{{home}}/config.yaml"]
expect:
  exit: 0
  stdout: { prefix: "facto ", contains: [filed], not_contains: [panic] }
  stderr: { empty: true }
  files:
    - { path: Invoices/2026/a.pdf, mode: "0600", fixture: edf-invoice.pdf }
    - { path: notes.txt, content: "x\n" }
  absent: [Invoices/inbox/a.pdf]
  trees:
    - { path: Invoices, private: true, entries: [inbox/, inbox/sub/] }
repeat:
  expect: { exit: 0 }
  unchanged: [Invoices]
`

// validSiteScenario uses every fake site key once (J1 T22).
const validSiteScenario = `name: site-example
args: [collect, --config, "{{home}}/config.yaml"]
fakesite:
  mode: totp
  login: fp/login
  password: fp/password
  invoices:
    - { id: FP-2026-0001, contract: C-1, issued_at: 2026-03-14, amount_cents: 8412, currency: EUR, fixture: edf-invoice.pdf }
    - { id: FP-2026-0002, contract: C-1, issued_at: 2026-04-14, fixture: impots-notice.pdf }
secrets:
  fp/login: "user-{{canary:token}}"
  fp/password: "{{canary:password}}"
  fp/otp: "{{totp}}"
stdin: ["{{totp}}", "again {{canary:token}}"]
expect:
  exit: 0
  requests:
    - { method: POST, host: www.fakeprovider.test, path: /login, count: 1 }
    - { host: evil.test, count: 0 }
    - { path: /api/*, min: 1 }
    - { status: 200, last: true }
  browser: { no_cdp_port: true, profile_removed: true }
repeat:
  expect:
    exit: 0
    requests: [{ host: www.fakeprovider.test, path: /login, count: 0 }]
`

func TestScenarioParse(t *testing.T) {
	t.Parallel()
	// mutate replaces old with new in validScenario (old must be present).
	mutate := func(from, to string) string {
		if !strings.Contains(validScenario, from) {
			t.Fatalf("test bug: %q not in validScenario", from)
		}
		return strings.Replace(validScenario, from, to, 1)
	}
	tests := []struct {
		name    string
		in      string
		wantErr bool
		check   func(t *testing.T, s *Scenario)
	}{
		{name: "full example", in: validScenario, check: func(t *testing.T, s *Scenario) {
			if s.Name != "full-example" || s.StateDir != "state" {
				t.Errorf("name/state_dir = %q/%q", s.Name, s.StateDir)
			}
			if want := []string{"collect", "--config", "{{home}}/config.yaml"}; !slices.Equal(s.Args, want) {
				t.Errorf("args = %q, want %q", s.Args, want)
			}
			if len(s.Setup) != 4 || s.Setup[0].Content == nil || s.Setup[1].Fixture != "edf-invoice.pdf" ||
				!s.Setup[2].Dir || s.Setup[3].Symlink != "../../config.yaml" {
				t.Errorf("setup = %+v", s.Setup)
			}
			if s.Expect.Exit == nil || *s.Expect.Exit != 0 || s.Expect.Stdout.Prefix != "facto " || !s.Expect.Stderr.Empty {
				t.Errorf("expect = %+v", s.Expect)
			}
			if len(s.Expect.Files) != 2 || s.Expect.Files[0].Mode != "0600" || s.Expect.Files[1].Content == nil {
				t.Errorf("expect.files = %+v", s.Expect.Files)
			}
			if len(s.Expect.Trees) != 1 || !s.Expect.Trees[0].Private || len(s.Expect.Trees[0].Entries) != 2 {
				t.Errorf("expect.trees = %+v", s.Expect.Trees)
			}
			if s.Repeat == nil || s.Repeat.Expect.Exit == nil || !slices.Equal(s.Repeat.Unchanged, []string{"Invoices"}) {
				t.Errorf("repeat = %+v", s.Repeat)
			}
		}},
		{name: "state dir defaults to .facto", in: mutate("state_dir: state\n", ""), check: func(t *testing.T, s *Scenario) {
			if s.StateDir != DefaultStateDir {
				t.Errorf("state_dir = %q, want %q", s.StateDir, DefaultStateDir)
			}
		}},
		{name: "nonzero exit", in: mutate("  exit: 0\n  stdout", "  exit: 2\n  stdout"), check: func(t *testing.T, s *Scenario) {
			if *s.Expect.Exit != 2 {
				t.Errorf("exit = %d, want 2", *s.Expect.Exit)
			}
		}},

		// Format errors.
		{name: "unknown top-level key", in: validScenario + "timeout: 5s\n", wantErr: true},
		{name: "unknown nested key", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: edf-invoice.pdf\n    owner: root\n"), wantErr: true},
		{name: "second document", in: validScenario + "---\nname: other\n", wantErr: true},
		{name: "missing exit", in: mutate("  exit: 0\n  stdout", "  stdout"), wantErr: true},
		{name: "missing repeat exit", in: mutate("expect: { exit: 0 }", "expect: {}"), wantErr: true},
		{name: "empty args", in: mutate(`args: [collect, --config, "{{home}}/config.yaml"]`, "args: []"), wantErr: true},
		{name: "bad name", in: mutate("name: full-example", "name: Full_Example"), wantErr: true},
		{name: "unknown placeholder", in: mutate(`"{{home}}/config.yaml"]`, `"{{env:HOME}}/config.yaml"]`), wantErr: true},
		{name: "bad canary kind", in: mutate("{{canary:password}}", "{{canary:Pass word}}"), wantErr: true},
		{name: "two content sources", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: edf-invoice.pdf\n    content: x\n"), wantErr: true},
		{name: "no content source", in: mutate("  - path: Invoices/inbox/sub\n    dir: true\n", "  - path: Invoices/inbox/sub\n"), wantErr: true},
		{name: "mode not octal", in: mutate(`mode: "0600"`+"\n    content", `mode: "0800"`+"\n    content"), wantErr: true},
		{name: "mode with setuid", in: mutate(`mode: "0600"`+"\n    content", `mode: "4755"`+"\n    content"), wantErr: true},
		{name: "mode on a symlink", in: mutate("    symlink: ../../config.yaml\n", "    symlink: ../../config.yaml\n    mode: \"0600\"\n"), wantErr: true},
		{name: "expected file with fixture and content", in: mutate(`fixture: edf-invoice.pdf }`, `fixture: edf-invoice.pdf, content: x }`), wantErr: true},

		// Security negatives: nothing may point outside the sandboxed HOME.
		{name: "setup path traversal", in: mutate("path: Invoices/inbox/a.pdf", "path: ../escape.pdf"), wantErr: true},
		{name: "setup path traversal inside", in: mutate("path: Invoices/inbox/a.pdf", "path: Invoices/../../escape.pdf"), wantErr: true},
		{name: "setup absolute path", in: mutate("path: Invoices/inbox/a.pdf", "path: /tmp/escape.pdf"), wantErr: true},
		{name: "setup backslash path", in: mutate("path: Invoices/inbox/a.pdf", `path: 'Invoices\..\..\escape.pdf'`), wantErr: true},
		{name: "setup unclean path", in: mutate("path: Invoices/inbox/a.pdf", "path: Invoices//inbox/./a.pdf"), wantErr: true},
		{name: "fixture with separator", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: ../../../go.mod\n"), wantErr: true},
		{name: "hidden fixture", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: .env\n"), wantErr: true},
		{name: "symlink escaping home", in: mutate("symlink: ../../config.yaml", "symlink: ../../../outside"), wantErr: true},
		{name: "absolute symlink", in: mutate("symlink: ../../config.yaml", "symlink: /etc/passwd"), wantErr: true},
		{name: "state dir outside home", in: mutate("state_dir: state", "state_dir: ../state"), wantErr: true},
		{name: "expected file outside home", in: mutate("path: Invoices/2026/a.pdf", "path: ../a.pdf"), wantErr: true},
		{name: "absent outside home", in: mutate("absent: [Invoices/inbox/a.pdf]", "absent: [/etc]"), wantErr: true},
		{name: "tree outside home", in: mutate("{ path: Invoices, private", "{ path: .., private"), wantErr: true},
		{name: "unchanged outside home", in: mutate("unchanged: [Invoices]", "unchanged: [../Invoices]"), wantErr: true},
	}
	// J1 T22: fakesite, secrets, stdin, expect.requests, expect.browser.
	site := func(from, to string) string {
		if !strings.Contains(validSiteScenario, from) {
			t.Fatalf("test bug: %q not in validSiteScenario", from)
		}
		return strings.Replace(validSiteScenario, from, to, 1)
	}
	tests = append(tests, []struct {
		name    string
		in      string
		wantErr bool
		check   func(t *testing.T, s *Scenario)
	}{
		{name: "fake site example", in: validSiteScenario, check: func(t *testing.T, s *Scenario) {
			f := s.FakeSite
			if f == nil || f.Mode != ModeTOTP || f.Login != "fp/login" || f.Password != "fp/password" {
				t.Fatalf("fakesite = %+v", f)
			}
			if len(f.Invoices) != 2 || f.Invoices[0].ID != "FP-2026-0001" || f.Invoices[0].AmountCents == nil ||
				*f.Invoices[0].AmountCents != 8412 || f.Invoices[1].AmountCents != nil || f.Invoices[1].Fixture != "impots-notice.pdf" {
				t.Errorf("fakesite.invoices = %+v", f.Invoices)
			}
			if len(s.Secrets) != 3 || s.Secrets["fp/otp"] != "{{totp}}" || s.Secrets["fp/password"] != "{{canary:password}}" {
				t.Errorf("secrets = %q", s.Secrets)
			}
			if !slices.Equal(s.Stdin, []string{"{{totp}}", "again {{canary:token}}"}) {
				t.Errorf("stdin = %q", s.Stdin)
			}
			r := s.Expect.Requests
			if len(r) != 4 || r[0].Method != http.MethodPost || r[0].Host != HostWWW || r[0].Path != "/login" || r[0].Count == nil || *r[0].Count != 1 ||
				r[1].Host != EvilHost || r[1].Count == nil || *r[1].Count != 0 ||
				r[2].Path != "/api/*" || r[2].Min == nil || *r[2].Min != 1 ||
				r[3].Status != 200 || !r[3].Last {
				t.Errorf("expect.requests = %+v", r)
			}
			if b := s.Expect.Browser; b == nil || !b.NoCDPPort || !b.ProfileRemoved {
				t.Errorf("expect.browser = %+v", b)
			}
			if s.Repeat == nil || len(s.Repeat.Expect.Requests) != 1 {
				t.Errorf("repeat.expect.requests = %+v", s.Repeat)
			}
		}},
		{name: "every mode accepted", in: validSiteScenario, check: func(t *testing.T, _ *Scenario) {
			for _, m := range []string{"password", "totp", "email-otp", "sso-redirect", "expired-session", "rate-limit", "site-changed", "captcha", "bad-password"} {
				in := strings.Replace(validSiteScenario, "mode: totp", "mode: "+m, 1)
				in = strings.Replace(in, `fp/otp: "{{totp}}"`, `fp/otp: "123456"`, 1)
				in = strings.Replace(in, `stdin: ["{{totp}}", `, `stdin: [`, 1)
				if m == ModeExpiredSession {
					in = strings.Replace(in, "  login: fp/login\n", "  login: fp/login\n  expire_after: 1\n", 1)
				}
				if m == ModeRateLimit {
					in = strings.Replace(in, "  login: fp/login\n", "  login: fp/login\n  rate_limit_after: 2\n", 1)
				}
				if _, err := Parse([]byte(in)); err != nil {
					t.Errorf("mode %s: %v", m, err)
				}
			}
		}},
		{name: "totp placeholder in email-otp mode", in: site("mode: totp", "mode: email-otp"), wantErr: true},
		{
			name: "outbox placeholder allowed in email-otp", in: strings.Replace(strings.Replace(strings.Replace(validSiteScenario,
				"mode: totp", "mode: email-otp", 1), `"{{totp}}"`, `"123456"`, 1), `"{{totp}}"`, `"{{outbox}}"`, 1),
			check: func(t *testing.T, s *Scenario) {
				if s.Stdin[0] != "{{outbox}}" {
					t.Errorf("stdin = %q", s.Stdin)
				}
			},
		},
		{
			name: "secrets and stdin without a site", in: validScenario + "secrets: { fp/password: \"{{canary:password}}\" }\nstdin: [\"{{canary:token}}\"]\n",
			check: func(t *testing.T, s *Scenario) {
				if s.FakeSite != nil || len(s.Secrets) != 1 || len(s.Stdin) != 1 {
					t.Errorf("scenario = %+v", s)
				}
			},
		},

		// fakesite errors.
		{name: "unknown mode", in: site("mode: totp", "mode: oauth"), wantErr: true},
		{name: "missing mode", in: site("  mode: totp\n", ""), wantErr: true},
		{name: "unknown fakesite key", in: site("  login: fp/login\n", "  login: fp/login\n  port: 443\n"), wantErr: true},
		{name: "login not a secrets key", in: site("login: fp/login", "login: fp/other"), wantErr: true},
		{name: "missing password ref", in: site("  password: fp/password\n", ""), wantErr: true},
		{name: "expire_after outside expired-session", in: site("  login: fp/login\n", "  login: fp/login\n  expire_after: 1\n"), wantErr: true},
		{name: "expired-session without expire_after", in: strings.Replace(strings.Replace(site("mode: totp", "mode: expired-session"),
			`"{{totp}}"`, `"1"`, 2), `"{{totp}}"`, `"1"`, 1), wantErr: true},
		{name: "rate_limit_after outside rate-limit", in: site("  login: fp/login\n", "  login: fp/login\n  rate_limit_after: 1\n"), wantErr: true},
		{name: "invoice bad id", in: site("id: FP-2026-0001", "id: fp/../x"), wantErr: true},
		{name: "invoice duplicate id", in: site("id: FP-2026-0002", "id: FP-2026-0001"), wantErr: true},
		{name: "invoice bad date", in: site("issued_at: 2026-03-14", "issued_at: 2026-13-40"), wantErr: true},
		{name: "invoice amount without currency", in: site(", currency: EUR", ""), wantErr: true},
		{name: "invoice fixture traversal", in: site("fixture: edf-invoice.pdf }", "fixture: ../../go.mod }"), wantErr: true},
		{name: "invoice without fixture", in: site(", fixture: impots-notice.pdf", ""), wantErr: true},

		// secrets errors (security: the dir is written by the harness).
		{name: "secret key traversal", in: site("fp/otp:", "../otp:"), wantErr: true},
		{name: "secret key dot segment", in: site("fp/otp:", "fp/..:"), wantErr: true},
		{name: "secret key three segments", in: site("fp/otp:", "fp/a/b:"), wantErr: true},
		{name: "secret key absolute", in: site("fp/otp:", "/etc/passwd:"), wantErr: true},
		{name: "secret empty value", in: site(`fp/otp: "{{totp}}"`, `fp/otp: ""`), wantErr: true},
		{name: "secret home placeholder", in: site(`fp/otp: "{{totp}}"`, `fp/otp: "{{home}}/x"`), wantErr: true},
		{name: "secret outbox placeholder", in: site(`fp/otp: "{{totp}}"`, `fp/otp: "{{outbox}}"`), wantErr: true},
		{name: "totp placeholder outside totp mode", in: site("mode: totp", "mode: password"), wantErr: true},

		// stdin errors.
		{name: "stdin line with newline", in: site(`"again {{canary:token}}"`, `"a\nb"`), wantErr: true},
		{name: "stdin line with CR", in: site(`"again {{canary:token}}"`, `"a\rb"`), wantErr: true},
		{name: "stdin unknown placeholder", in: site(`"again {{canary:token}}"`, `"{{env:HOME}}"`), wantErr: true},
		{name: "stdin outbox outside email-otp", in: site(`"again {{canary:token}}"`, `"{{outbox}}"`), wantErr: true},

		// expect.requests and expect.browser errors.
		{name: "requests without a site", in: validScenario + "", wantErr: false, check: func(t *testing.T, _ *Scenario) {
			in := strings.Replace(validScenario, "  absent:", "  requests: [{ host: evil.test, count: 0 }]\n  absent:", 1)
			if _, err := Parse([]byte(in)); !errors.Is(err, ErrInvalidScenario) {
				t.Errorf("requests without fakesite: err = %v, want ErrInvalidScenario", err)
			}
			in = strings.Replace(validScenario, "  absent:", "  browser: { no_cdp_port: true }\n  absent:", 1)
			if _, err := Parse([]byte(in)); !errors.Is(err, ErrInvalidScenario) {
				t.Errorf("browser without fakesite: err = %v, want ErrInvalidScenario", err)
			}
		}},
		{name: "request with count and min", in: site("path: /login, count: 1 }", "path: /login, count: 1, min: 1 }"), wantErr: true},
		{name: "request with no quantifier", in: site("{ host: evil.test, count: 0 }", "{ host: evil.test }"), wantErr: true},
		{name: "request negative count", in: site("{ host: evil.test, count: 0 }", "{ host: evil.test, count: -1 }"), wantErr: true},
		{name: "request unserved host", in: site("{ host: evil.test, count: 0 }", "{ host: example.com, count: 0 }"), wantErr: true},
		{name: "request bad method", in: site("method: POST", "method: DELETE"), wantErr: true},
		{name: "request bad status", in: site("status: 200", "status: 999"), wantErr: true},
		{name: "request path with query", in: site("path: /login, count", `path: "/login?u=x", count`), wantErr: true},
		{name: "request relative path", in: site("path: /login, count", "path: login, count"), wantErr: true},
		{name: "request unclean path", in: site("path: /login, count", "path: /a/../login, count"), wantErr: true},
		{name: "request unknown key", in: site("{ host: evil.test, count: 0 }", "{ host: evil.test, count: 0, body: x }"), wantErr: true},
		{name: "browser probes all off", in: site("browser: { no_cdp_port: true, profile_removed: true }", "browser: {}"), wantErr: true},
		{name: "browser unknown probe", in: site("profile_removed: true }", "profile_removed: true, keep_profile: true }"), wantErr: true},
		{name: "repeat request unserved host", in: site("repeat:\n  expect:\n    exit: 0\n    requests: [{ host: www.fakeprovider.test",
			"repeat:\n  expect:\n    exit: 0\n    requests: [{ host: localhost"), wantErr: true},
	}...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := Parse([]byte(tt.in))
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidScenario) {
					t.Fatalf("Parse err = %v, want ErrInvalidScenario", err)
				}
				t.Logf("rejected: %v", err)
				if s != nil {
					t.Errorf("Parse returned a scenario with an error: %+v", s)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tt.check != nil {
				tt.check(t, s)
			}
		})
	}
}

func TestExpand(t *testing.T) {
	t.Parallel()
	calls := map[string]int{}
	canary := func(kind string) string { calls[kind]++; return "C-" + kind }
	got := Expand("{{home}}/c.yaml pw={{canary:password}} {{other}}", "/h", canary)
	if want := "/h/c.yaml pw=C-password {{other}}"; got != want {
		t.Errorf("Expand = %q, want %q", got, want)
	}
	if calls["password"] != 1 {
		t.Errorf("canary(password) called %d times, want 1", calls["password"])
	}
}

// TestScenarioFiles_Parse checks every checked-in scenario parses, is named
// after its file and uses only fixtures that exist.
func TestScenarioFiles_Parse(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		data, err := readIn(".", f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s, err := Parse(data)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if stem := strings.TrimSuffix(f, ".yaml"); s.Name != stem {
			t.Errorf("%s: name %q, want %q", f, s.Name, stem)
		}
		var fixtures []string
		for _, sf := range s.Setup {
			fixtures = append(fixtures, sf.Fixture)
		}
		for _, e := range append([]Expect{s.Expect}, repeatExpect(s)...) {
			for _, ef := range e.Files {
				fixtures = append(fixtures, ef.Fixture)
			}
		}
		for _, fx := range fixtures {
			if fx == "" {
				continue
			}
			if _, err := readIn("testdata", fx); err != nil {
				t.Errorf("%s: fixture %s: %v", f, fx, err)
			}
		}
	}
}

func repeatExpect(s *Scenario) []Expect {
	if s.Repeat == nil {
		return nil
	}
	return []Expect{s.Repeat.Expect}
}
