//go:build e2e

package e2e

// Scenario wiring of the fake site keys (J1 T22): starts the site, writes
// the e2e:// secrets and the CA file outside HOME, builds the FACTO_E2E_*
// environment, feeds stdin lines and checks the request log and the
// browser probes of each run.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// chromeEnv names the Chrome for Testing executable, set by make e2e for
// the harness and passed on to facto.
const chromeEnv = "FACTO_E2E_CHROME"

// outboxTimeout bounds the wait for an email code before a stdin line.
const outboxTimeout = 60 * time.Second

// chromePath returns $FACTO_E2E_CHROME, failing (never skipping) when it is
// unset: run make e2e, which installs Chrome for Testing first.
func chromePath(t *testing.T) string {
	t.Helper()
	p := os.Getenv(chromeEnv)
	if p == "" || !filepath.IsAbs(p) {
		t.Fatalf("%s must be the absolute path of Chrome for Testing (run make e2e)", chromeEnv)
	}
	return p
}

// writeSecrets writes every <item>/<field> value to dir/<item>/<field>:
// dir and item directories 0700, files 0600, content byte for byte. A key
// that is not exactly two safe segments is refused before anything is
// written.
func writeSecrets(ctx context.Context, dir string, secrets map[string]string) error {
	for k := range secrets {
		if err := checkSecretKey(k); err != nil {
			return err
		}
	}
	parent, err := fsx.Open(filepath.Dir(dir))
	if err != nil {
		return fmt.Errorf("secrets dir: %w", err)
	}
	defer func() { _ = parent.Close() }()
	base := filepath.Base(dir)
	if err := parent.MkdirPrivate(base); err != nil {
		return fmt.Errorf("secrets dir: %w", err)
	}
	r, err := fsx.Open(dir)
	if err != nil {
		return fmt.Errorf("secrets dir: %w", err)
	}
	defer func() { _ = r.Close() }()
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := r.MkdirPrivate(path.Dir(k)); err != nil {
			return fmt.Errorf("secret %s: %w", k, err)
		}
		if err := r.WriteAtomic(ctx, k, []byte(secrets[k])); err != nil {
			return fmt.Errorf("secret %s: %w", k, err)
		}
	}
	return nil
}

// siteRun is the per-scenario fake site state of a sandbox.
type siteRun struct {
	site *fakeSite

	mu          sync.Mutex
	probes      []browserProbe
	baseline    hostListeners // host LISTEN rows before the current run
	baselineErr error
}

// armProbes records the host-namespace LISTEN baseline; run calls it just
// before starting facto.
func (s *sandbox) armProbes() {
	if s.site == nil {
		return
	}
	base, err := snapshotHostListeners()
	s.site.mu.Lock()
	s.site.baseline, s.site.baselineErr = base, err
	s.site.mu.Unlock()
}

func (r *siteRun) takeProbes() []browserProbe {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.probes
	r.probes = nil
	return p
}

// startSite starts the scenario's fake site and prepares the FACTO_E2E_*
// environment of the runs. Secrets and CA live in the sandbox root, outside
// HOME.
func (s *sandbox) startSite(t *testing.T, sc *Scenario) {
	t.Helper()
	env := map[string]string{}
	seed := randomBytes(t, 20)
	now := clock.Real{}.Now
	expand := func(v string) string {
		return ExpandFunc(v, func(name string) string {
			if name == "totp" {
				return totpCode(seed, now())
			}
			if kind, ok := strings.CutPrefix(name, "canary:"); ok {
				return s.canary(t)(kind)
			}
			return "{{" + name + "}}"
		})
	}
	values := make(map[string]string, len(sc.Secrets))
	for k, v := range sc.Secrets {
		values[k] = expand(v)
		if strings.Contains(v, "{{totp}}") {
			s.addTOTP(values[k])
		}
	}
	if len(values) > 0 {
		dir := filepath.Join(s.root, "secrets")
		if err := writeSecrets(t.Context(), dir, values); err != nil {
			t.Fatalf("secrets: %v", err)
		}
		env["FACTO_E2E_SECRETS_DIR"] = dir
	}
	if len(sc.Stdin) > 0 {
		env["FACTO_E2E_INTERACTIVE"] = "1"
	}
	if sc.FakeSite != nil {
		f := sc.FakeSite
		run := &siteRun{}
		invs := make([]siteInvoice, 0, len(f.Invoices))
		for _, inv := range f.Invoices {
			invs = append(invs, siteInvoice{FakeInvoice: inv, PDF: readFixture(t, inv.Fixture)})
		}
		run.site = startFakeSite(t, siteOptions{
			Mode: f.Mode, Login: values[f.Login], Password: values[f.Password],
			ExpireAfter: f.ExpireAfter, RateLimitAfter: f.RateLimitAfter,
			Invoices: invs, TOTPSeed: seed, Now: now,
			SessionValue: cookieCanaries(t),
			OnLoginPage: func(*http.Request) {
				pid := s.factoPID()
				if pid == 0 {
					return
				}
				run.mu.Lock()
				base, baseErr := run.baseline, run.baselineErr
				run.mu.Unlock()
				var p browserProbe
				if baseErr != nil {
					p.Err = fmt.Errorf("host listener baseline: %w", baseErr)
				} else {
					// facto is hardened (PR_SET_DUMPABLE=0): its own fds and
					// netns are unreadable, so the host-namespace diff
					// covers it; Chrome below it gets the full check.
					p = probeBrowserTree(pid, probeOptions{
						HardenedRoot:   true,
						HostBaseline:   base,
						AllowListeners: []string{siteListener(run.site.Addr().Port())},
					})
				}
				run.mu.Lock()
				run.probes = append(run.probes, p)
				run.mu.Unlock()
			},
		})
		caDir := filepath.Join(s.root, "ca")
		mkPrivate(t, caDir)
		env["FACTO_E2E_CA"] = writeCA(t, run.site, caDir, "ca.pem", 0o600)
		env["FACTO_E2E_LOOPBACK"] = run.site.Addr().String()
		env["FACTO_E2E_CHROME"] = chromePath(t)
		s.site = run
	}
	s.extraEnv = env
}

// cookieCanaries returns a SessionValue minting cookie canaries (a pool
// made now, on the test goroutine; random tokens once it is used up: those
// are still hunted by siteLeaks, through IssuedSessions).
func cookieCanaries(t *testing.T) func() string {
	t.Helper()
	const n = 8
	var mu sync.Mutex
	pool := make([]string, n)
	for i := range pool {
		pool[i] = testsecrets.Canary(t, testsecrets.Cookie)
	}
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(pool) == 0 {
			return randomToken()
		}
		v := pool[0]
		pool = pool[1:]
		return v
	}
}

// feedStdin writes the scenario's stdin lines to w, expanding {{totp}}
// (at write time), {{outbox}} (the next email code sent from outbox index
// from on, i.e. during this run, waited for) and canaries, then closes w.
// ctx is cancelled when facto exits: a wait still pending then ends
// without an error (facto did not ask, e.g. its session was restored).
// An outbox wait that times out while facto runs is an error.
func (s *sandbox) feedStdin(ctx context.Context, w io.WriteCloser, lines []string, from int) error {
	defer func() { _ = w.Close() }()
	next := from
	for _, line := range lines {
		var failed error
		v := ExpandFunc(line, func(name string) string {
			switch {
			case name == "totp" && s.site != nil:
				code := s.site.site.TOTP(clock.Real{}.Now())
				s.addTOTP(code)
				return code
			case name == "outbox" && s.site != nil:
				wctx, cancel := context.WithTimeout(ctx, outboxTimeout)
				defer cancel()
				code, err := s.site.site.WaitOutbox(wctx, next)
				next++
				failed = err
				return code
			}
			return "" // canaries were expanded by run; Parse refused the rest
		})
		if failed != nil {
			if ctx.Err() != nil {
				return nil // facto exited without asking
			}
			return fmt.Errorf("stdin: %w", failed)
		}
		if _, err := io.WriteString(w, v+"\n"); err != nil {
			return nil // facto exited or closed stdin
		}
	}
	return nil
}

// addTOTP records a TOTP code handed to facto, hunted by siteLeaks.
func (s *sandbox) addTOTP(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totpSecrets = append(s.totpSecrets, code)
}

// siteSecrets are the values the fake site minted for facto, or the TOTP
// codes the harness handed it: none may appear in facto's output.
type siteSecrets struct {
	cookies    []string // fp_session values
	emailCodes []string // outbox codes
	totpCodes  []string // TOTP codes in secrets or stdin
}

// siteSecrets collects the current scan set.
func (s *sandbox) siteSecrets() siteSecrets {
	var out siteSecrets
	if s.site != nil {
		out.cookies = s.site.site.IssuedSessions()
		out.emailCodes = s.site.site.Outbox()
	}
	s.mu.Lock()
	out.totpCodes = slices.Clone(s.totpSecrets)
	s.mu.Unlock()
	return out
}

// textArtifact reports whether a file is text facto writes for people or
// tools (logs, reports, config): the only files hunted for 6-digit codes,
// where a hit cannot be a coincidence of binary data (PDF, SQLite, sealed
// sessions).
func textArtifact(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".txt", ".json", ".jsonl", ".log", ".yaml", ".yml":
		return true
	}
	return false
}

// containsNumber reports whether code occurs in data as a whole number
// (no ASCII digit right before or after it).
func containsNumber(data []byte, code string) bool {
	c := []byte(code)
	for off := 0; ; {
		i := bytes.Index(data[off:], c)
		if i < 0 {
			return false
		}
		i += off
		end := i + len(c)
		before := i > 0 && data[i-1] >= '0' && data[i-1] <= '9'
		after := end < len(data) && data[end] >= '0' && data[end] <= '9'
		if !before && !after {
			return true
		}
		off = i + 1
	}
}

// siteLeaks returns one finding per (kind, place) where a value of sec
// appears: session cookies in stdout, stderr or any file under HOME; codes
// in stdout, stderr or text artifacts only (textArtifact). Findings name
// the kind and the place, never the value.
func (s *sandbox) siteLeaks(sec siteSecrets, r result) []string {
	var out []string
	scan := func(place string, data []byte, text bool) {
		for _, c := range sec.cookies {
			if c != "" && bytes.Contains(data, []byte(c)) {
				out = append(out, "session cookie leaked to "+place)
				break
			}
		}
		if !text {
			return
		}
		for _, k := range []struct {
			kind  string
			codes []string
		}{{"email code", sec.emailCodes}, {"TOTP code", sec.totpCodes}} {
			for _, c := range k.codes {
				if c != "" && containsNumber(data, c) {
					out = append(out, k.kind+" leaked to "+place)
					break
				}
			}
		}
	}
	scan("stdout", r.stdout, true)
	scan("stderr", r.stderr, true)
	err := filepath.WalkDir(s.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(s.home, p)
		if err != nil {
			return err
		}
		data, err := readIn(s.home, rel)
		if err != nil {
			return err
		}
		slashed := filepath.ToSlash(rel)
		scan(slashed, data, textArtifact(slashed))
		return nil
	})
	if err != nil {
		out = append(out, "site secret scan failed: "+err.Error())
	}
	return out
}

// resetSite empties the request log and the probes before a run.
func (s *sandbox) resetSite() {
	if s.site == nil {
		return
	}
	s.site.site.ResetLog()
	s.site.takeProbes()
}

// checkSite checks the request log and the browser probes of one run.
func (s *sandbox) checkSite(t *testing.T, run string, e Expect) {
	t.Helper()
	if s.site == nil {
		return
	}
	log := s.site.site.Requests()
	if err := checkRequests(log, e.Requests); err != nil {
		t.Errorf("%s: request log: %v\nlog: %+v", run, err, log)
	}
	probes := s.site.takeProbes()
	if e.Browser == nil {
		return
	}
	if len(probes) == 0 {
		t.Errorf("%s: browser probes: the login page was never served to a browser of facto (no probe ran)", run)
		return
	}
	if e.Browser.NoCDPPort {
		ok := true
		procs, browsers, hardened := 0, 0, 0
		for i, p := range probes {
			procs += p.Processes
			browsers += p.InspectedBrowsers
			if p.RootHardened {
				hardened++
			}
			if err := p.clean(); err != nil {
				ok = false
				t.Errorf("%s: browser probe %d: %v", run, i, err)
			}
		}
		if ok {
			t.Logf("%s: no listening CDP port (%d probes, %d processes and %d Chrome processes inspected, hardened facto covered by the host netns diff in %d)", run, len(probes), procs, browsers, hardened)
		}
	}
	if e.Browser.ProfileRemoved {
		var dirs []string
		for _, p := range probes {
			for _, d := range p.Profiles {
				if d != "" && !slices.Contains(dirs, d) {
					dirs = append(dirs, d)
				}
			}
		}
		if len(dirs) == 0 {
			t.Errorf("%s: profile_removed: no browser profile was seen", run)
		}
		for _, d := range dirs {
			if !filepath.IsAbs(d) {
				t.Errorf("%s: browser profile %q is not absolute", run, d)
				continue
			}
			if _, err := os.Lstat(d); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: browser profile %s still exists after the run (err %v)", run, d, err)
				continue
			}
			t.Logf("%s: profile removed (%s)", run, d)
		}
	}
}

// saveRequestLog stores the run's request log with the artifacts, so make
// leakcheck also greps it.
func (s *sandbox) saveRequestLog(t *testing.T, art, run string) {
	t.Helper()
	if s.site == nil {
		return
	}
	b, err := json.MarshalIndent(s.site.site.Requests(), "", "  ")
	if err != nil {
		t.Fatalf("request log: %v", err)
	}
	r, err := fsx.Open(art)
	if err != nil {
		t.Fatalf("artifacts: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), run+".requests.json", b); err != nil {
		t.Fatalf("artifacts: %v", err)
	}
}
