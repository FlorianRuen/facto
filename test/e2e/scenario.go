//go:build e2e

// Package e2e drives the real facto binary through the scenarios in
// test/e2e/*.yaml (J0 T27). Each scenario runs in a sandboxed HOME: setup
// files are created there, the command runs with an environment built from
// scratch, and the expectations are checked against that HOME only.
//
// Scenario format (strict YAML: unknown keys are errors):
//
//	name: inbox                  # must equal the file stem; [a-z0-9-]+
//	description: free text
//	state_dir: .facto            # relative to HOME; copied to the artifacts (default .facto)
//	setup:                       # created in order, relative to HOME, parents 0700
//	  - path: config.yaml
//	    mode: "0600"             # octal string; default "0600" (files), "0700" (dirs)
//	    content: |               # inline; {{home}} and {{canary:<kind>}} expanded
//	      ...
//	  - path: Invoices/inbox/a.pdf
//	    fixture: edf-invoice.pdf # test/e2e/testdata/<fixture>, copied byte for byte
//	  - path: Invoices/inbox/link.pdf
//	    symlink: ../../config.yaml # relative, must stay inside HOME
//	  - path: Invoices/inbox/sub
//	    dir: true
//	args: [collect, --config, "{{home}}/config.yaml"]
//	expect: <Expect>
//	repeat:                      # optional second run of the same args
//	  expect: <Expect>
//	  unchanged: [Invoices]      # trees identical (paths, modes, bytes) to after run 1
//
// Every {{canary:<kind>}} value is checked absent from stdout, stderr and
// every file under HOME except the setup files that contained it.
//
// Fake site keys (J1 T22; the site lives in fakesite_test.go, bound to
// 127.0.0.1 only, plan A7):
//
//	fakesite:                    # starts the fake TLS site for this scenario
//	  mode: password             # password, totp, email-otp, sso-redirect,
//	                             # expired-session, rate-limit, site-changed,
//	                             # captcha, bad-password (CSRF is enforced in
//	                             # every mode that serves a form)
//	  login: fp/login            # secrets key whose value the site accepts as login
//	  password: fp/password      # secrets key whose value the site accepts as password
//	  expire_after: 2            # expired-session only (>= 1): authenticated API
//	                             # requests one session serves before 401
//	  rate_limit_after: 0        # rate-limit only (>= 0): API requests before 429
//	  invoices:                  # seeded documents (list + PDF endpoints)
//	    - { id: FP-2026-0001, contract: C-1, issued_at: 2026-03-14,
//	        amount_cents: 8412, currency: EUR, fixture: edf-invoice.pdf }
//	secrets:                     # e2e://<item>/<field> files, 0600 in a 0700 dir
//	  fp/login: "user-{{canary:token}}"   # outside HOME; FACTO_E2E_SECRETS_DIR
//	  fp/password: "{{canary:password}}"
//	  fp/otp: "{{totp}}"         # current TOTP code of the site (mode totp only)
//	stdin:                       # lines fed one by one; sets FACTO_E2E_INTERACTIVE=1
//	  - "{{outbox}}"             # waits for the next email code (mode email-otp only)
//	expect:
//	  requests:                  # assertions on the site's request log of the run
//	    - { method: POST, host: www.fakeprovider.test, path: /login, count: 1 }
//	    - { host: evil.test, count: 0 }
//	    - { path: /api/*, min: 1 }        # trailing * = path prefix
//	    - { status: 429, last: true }     # the last logged request matches
//	  browser:                   # probes on the Chrome that loads the login page
//	    no_cdp_port: true        # no TCP listener in facto's process tree
//	    profile_removed: true    # every --user-data-dir is gone after the run
//
// When fakesite is set, facto (built with -tags e2e) gets FACTO_E2E_CHROME
// (the harness's own FACTO_E2E_CHROME, set by make e2e), FACTO_E2E_LOOPBACK
// (127.0.0.1:<site port>: the dial target of every allowed host, for httpx
// and Chrome's --host-resolver-rules) and FACTO_E2E_CA (PEM file of the
// site's test CA: httpx roots and Chrome SPKI allowlist). secrets sets
// FACTO_E2E_SECRETS_DIR, stdin sets FACTO_E2E_INTERACTIVE=1 (A8).
package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ErrInvalidScenario reports a scenario file the harness refuses.
var ErrInvalidScenario = errors.New("e2e: invalid scenario")

// DefaultStateDir is the state dir (relative to HOME) when a scenario sets none.
const DefaultStateDir = ".facto"

// Scenario is one test/e2e/<name>.yaml file.
type Scenario struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	StateDir    string      `yaml:"state_dir"`
	Setup       []SetupFile `yaml:"setup"`
	Args        []string    `yaml:"args"`
	Expect      Expect      `yaml:"expect"`
	Repeat      *Repeat     `yaml:"repeat"`

	FakeSite *FakeSite         `yaml:"fakesite"`
	Secrets  map[string]string `yaml:"secrets"`
	Stdin    []string          `yaml:"stdin"`
}

// Fake site modes.
const (
	ModePassword       = "password"
	ModeTOTP           = "totp"
	ModeEmailOTP       = "email-otp"
	ModeSSORedirect    = "sso-redirect"
	ModeExpiredSession = "expired-session"
	ModeRateLimit      = "rate-limit"
	ModeSiteChanged    = "site-changed"
	ModeCaptcha        = "captcha"
	ModeBadPassword    = "bad-password"
)

// Modes lists every fake site mode.
var Modes = []string{
	ModePassword, ModeTOTP, ModeEmailOTP, ModeSSORedirect, ModeExpiredSession,
	ModeRateLimit, ModeSiteChanged, ModeCaptcha, ModeBadPassword,
}

// Hosts served by the fake site. EvilHost is off every allowlist: the login
// page references it so that a browser leak shows in the request log.
const (
	HostWWW  = "www.fakeprovider.test"
	HostSSO  = "sso.fakeprovider.test"
	EvilHost = "evil.test"
)

// FakeSite configures the scenario's fake site.
type FakeSite struct {
	Mode           string        `yaml:"mode"`
	Login          string        `yaml:"login"`
	Password       string        `yaml:"password"`
	ExpireAfter    int           `yaml:"expire_after"`
	RateLimitAfter int           `yaml:"rate_limit_after"`
	Invoices       []FakeInvoice `yaml:"invoices"`
}

// FakeInvoice is one document the site lists and serves.
type FakeInvoice struct {
	ID          string `yaml:"id"`
	Contract    string `yaml:"contract"`
	IssuedAt    string `yaml:"issued_at"`
	AmountCents *int64 `yaml:"amount_cents"`
	Currency    string `yaml:"currency"`
	Fixture     string `yaml:"fixture"`
}

// RequestExpect counts the logged requests matching every set filter.
// Exactly one of Count, Min or Last is set.
type RequestExpect struct {
	Method string `yaml:"method"`
	Host   string `yaml:"host"`
	Path   string `yaml:"path"` // exact, or a prefix when it ends with "*"
	Status int    `yaml:"status"`
	Count  *int   `yaml:"count"`
	Min    *int   `yaml:"min"`
	Last   bool   `yaml:"last"`
}

// BrowserExpect enables the browser probes of one run.
type BrowserExpect struct {
	NoCDPPort      bool `yaml:"no_cdp_port"`
	ProfileRemoved bool `yaml:"profile_removed"`
}

// SetupFile is one entry created in HOME before the first run. Exactly one
// of Content, Fixture, Symlink or Dir is set.
type SetupFile struct {
	Path    string  `yaml:"path"`
	Mode    string  `yaml:"mode"`
	Content *string `yaml:"content"`
	Fixture string  `yaml:"fixture"`
	Symlink string  `yaml:"symlink"`
	Dir     bool    `yaml:"dir"`
}

// Expect is what one run must produce.
type Expect struct {
	Exit   *int         `yaml:"exit"`
	Stdout Output       `yaml:"stdout"`
	Stderr Output       `yaml:"stderr"`
	Files  []ExpectFile `yaml:"files"`
	Absent []string     `yaml:"absent"`
	Trees  []Tree       `yaml:"trees"`

	Requests []RequestExpect `yaml:"requests"`
	Browser  *BrowserExpect  `yaml:"browser"`
}

// Output holds checks on stdout or stderr.
type Output struct {
	Prefix      string   `yaml:"prefix"`
	Contains    []string `yaml:"contains"`
	NotContains []string `yaml:"not_contains"`
	Empty       bool     `yaml:"empty"`
}

// ExpectFile is a regular file (never a symlink) that must exist, with an
// optional mode and content.
type ExpectFile struct {
	Path    string  `yaml:"path"`
	Mode    string  `yaml:"mode"`
	Fixture string  `yaml:"fixture"`
	Content *string `yaml:"content"`
}

// Tree checks a whole directory. Entries, when set, is the exact sorted
// listing of everything below Path (directories end with "/"). Private
// requires every directory (Path included) to be 0700 and every file 0600.
type Tree struct {
	Path    string   `yaml:"path"`
	Entries []string `yaml:"entries"`
	Private bool     `yaml:"private"`
}

// Repeat is a second run of the same args after the first one.
type Repeat struct {
	Expect    Expect   `yaml:"expect"`
	Unchanged []string `yaml:"unchanged"`
}

var (
	nameRE        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	placeholderRE = regexp.MustCompile(`\{\{([^{}]*)\}\}`)
	canaryKindRE  = regexp.MustCompile(`^canary:[a-z0-9]+$`)
	secretKeyRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	invoiceIDRE   = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,63}$`)
	contractRE    = regexp.MustCompile(`^[A-Z0-9-]{1,32}$`)
	currencyRE    = regexp.MustCompile(`^[A-Z]{3}$`)
	reqPathRE     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*\*?$`)
)

// Harness limits.
const (
	maxSecrets   = 32
	maxStdin     = 16
	maxInvoices  = 100
	maxRateLimit = 1000
)

// Parse decodes and validates one scenario. Unknown keys, a second YAML
// document, paths leaving HOME and ambiguous setup entries are refused with
// an error wrapping ErrInvalidScenario.
func Parse(data []byte) (*Scenario, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidScenario, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%w: more than one YAML document", ErrInvalidScenario)
	}
	if s.StateDir == "" {
		s.StateDir = DefaultStateDir
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidScenario, s.Name, err)
	}
	return &s, nil
}

func (s *Scenario) validate() error {
	if !nameRE.MatchString(s.Name) {
		return errors.New("name: want [a-z0-9] words joined by single hyphens")
	}
	if len(s.Args) == 0 {
		return errors.New("args: empty")
	}
	for i, a := range s.Args {
		if err := checkPlaceholders(a); err != nil {
			return fmt.Errorf("args[%d]: %w", i, err)
		}
	}
	if err := checkRel("state_dir", s.StateDir); err != nil {
		return err
	}
	for i, f := range s.Setup {
		if err := f.validate(fmt.Sprintf("setup[%d]", i)); err != nil {
			return err
		}
	}
	if err := s.validateFakeSite(); err != nil {
		return err
	}
	if err := s.Expect.validate("expect"); err != nil {
		return err
	}
	if err := s.Expect.validateSite("expect", s.FakeSite != nil); err != nil {
		return err
	}
	if s.Repeat != nil {
		if err := s.Repeat.Expect.validate("repeat.expect"); err != nil {
			return err
		}
		if err := s.Repeat.Expect.validateSite("repeat.expect", s.FakeSite != nil); err != nil {
			return err
		}
		for i, p := range s.Repeat.Unchanged {
			if err := checkRel(fmt.Sprintf("repeat.unchanged[%d]", i), p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f SetupFile) validate(key string) error {
	if err := checkRel(key+".path", f.Path); err != nil {
		return err
	}
	sources := 0
	for _, set := range []bool{f.Content != nil, f.Fixture != "", f.Symlink != "", f.Dir} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("%s: want exactly one of content, fixture, symlink, dir", key)
	}
	if f.Mode != "" {
		if f.Symlink != "" {
			return fmt.Errorf("%s.mode: a symlink has no mode", key)
		}
		if _, err := ParseMode(f.Mode); err != nil {
			return fmt.Errorf("%s.mode: %w", key, err)
		}
	}
	if f.Fixture != "" {
		if err := checkFixture(key+".fixture", f.Fixture); err != nil {
			return err
		}
	}
	if f.Content != nil {
		if err := checkPlaceholders(*f.Content); err != nil {
			return fmt.Errorf("%s.content: %w", key, err)
		}
	}
	if f.Symlink != "" {
		// The target, resolved from the link's directory, must stay in HOME:
		// a scenario never points the binary outside its sandbox.
		if path.IsAbs(f.Symlink) || strings.Contains(f.Symlink, `\`) {
			return fmt.Errorf("%s.symlink: must be relative", key)
		}
		if err := checkRel(key+".symlink", path.Join(path.Dir(f.Path), f.Symlink)); err != nil {
			return err
		}
	}
	return nil
}

func (e Expect) validate(key string) error {
	if e.Exit == nil {
		return fmt.Errorf("%s.exit: required", key)
	}
	if *e.Exit < 0 || *e.Exit > 125 {
		return fmt.Errorf("%s.exit: out of range", key)
	}
	for i, f := range e.Files {
		k := fmt.Sprintf("%s.files[%d]", key, i)
		if err := checkRel(k+".path", f.Path); err != nil {
			return err
		}
		if f.Mode != "" {
			if _, err := ParseMode(f.Mode); err != nil {
				return fmt.Errorf("%s.mode: %w", k, err)
			}
		}
		if f.Fixture != "" && f.Content != nil {
			return fmt.Errorf("%s: fixture and content are exclusive", k)
		}
		if f.Fixture != "" {
			if err := checkFixture(k+".fixture", f.Fixture); err != nil {
				return err
			}
		}
	}
	for i, p := range e.Absent {
		if err := checkRel(fmt.Sprintf("%s.absent[%d]", key, i), p); err != nil {
			return err
		}
	}
	for i, t := range e.Trees {
		k := fmt.Sprintf("%s.trees[%d]", key, i)
		if err := checkRel(k+".path", t.Path); err != nil {
			return err
		}
		for j, ent := range t.Entries {
			if err := checkRel(fmt.Sprintf("%s.entries[%d]", k, j), strings.TrimSuffix(ent, "/")); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkRel accepts a non-empty, clean, slash-separated path that stays below
// HOME: no absolute path, no "..", no backslash, no NUL.
func checkRel(key, p string) error {
	if p == "" || strings.ContainsAny(p, "\\\x00") || path.IsAbs(p) || path.Clean(p) != p ||
		p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("%s: %q must be a clean relative path inside HOME", key, p)
	}
	return nil
}

// checkFixture accepts a bare file name in test/e2e/testdata.
func checkFixture(key, name string) error {
	if strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("%s: %q must be a file name in test/e2e/testdata", key, name)
	}
	return nil
}

// checkPlaceholders accepts {{home}} and {{canary:<kind>}} only.
func checkPlaceholders(s string) error {
	for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
		if m[1] != "home" && !canaryKindRE.MatchString(m[1]) {
			return fmt.Errorf("unknown placeholder {{%s}}", m[1])
		}
	}
	return nil
}

// ParseMode parses an octal permission string such as "0600" (at most 0777).
func ParseMode(s string) (uint32, error) {
	if len(s) < 3 || len(s) > 4 {
		return 0, fmt.Errorf("mode %q: want 3 or 4 octal digits", s)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v > 0o777 {
		return 0, fmt.Errorf("mode %q: want an octal permission up to 0777", s)
	}
	return uint32(v), nil
}

// Expand replaces {{home}} with home and every {{canary:<kind>}} with
// canary(kind) (the same value for every occurrence of a kind within one
// scenario is the caller's choice: canary is called once per occurrence).
func Expand(s, home string, canary func(kind string) string) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[2 : len(m)-2]
		if inner == "home" {
			return home
		}
		if kind, ok := strings.CutPrefix(inner, "canary:"); ok {
			return canary(kind)
		}
		return m
	})
}
