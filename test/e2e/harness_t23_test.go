//go:build e2e

package e2e

// Unit tests of the harness pieces the fakeprovider login scenarios need
// (J1 T23). They need no browser and no facto binary. All values are
// synthetic (testsecrets canaries or codes minted by the fake site).

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestSandboxEnv_NeverReachesTheUserSessionBus: facto's environment names a
// session bus socket inside the sandbox that does not exist, so the OS
// keyring client can never fall back to the developer's real
// /run/user/<uid>/bus (and write session keys into a real keyring). The
// e2e build must persist sessions through its own e2e key source instead.
func TestSandboxEnv_NeverReachesTheUserSessionBus(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	var bus []string
	for _, kv := range s.env() {
		if strings.HasPrefix(kv, "DBUS_") {
			bus = append(bus, kv)
		}
	}
	if len(bus) != 1 || !strings.HasPrefix(bus[0], "DBUS_SESSION_BUS_ADDRESS=unix:path=") {
		t.Fatalf("DBUS_* variables = %q, want exactly DBUS_SESSION_BUS_ADDRESS=unix:path=<inside the sandbox>", bus)
	}
	sock := strings.TrimPrefix(bus[0], "DBUS_SESSION_BUS_ADDRESS=unix:path=")
	rel, err := filepath.Rel(s.root, sock)
	if err != nil || !filepath.IsAbs(sock) || rel == "." || strings.HasPrefix(rel, "..") {
		t.Errorf("session bus socket %q is not strictly inside the sandbox root %q", sock, s.root)
	}
	if strings.HasPrefix(rel, "home") {
		t.Errorf("session bus socket %q is under HOME: it must stay outside what facto may write", sock)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("session bus socket %q exists (err %v): nothing may listen there", sock, err)
	}
}

// emailCodes drives n logins on an email-otp site and returns the n codes
// the outbox received, in order.
func emailCodes(t *testing.T, s *fakeSite, n int) []string {
	t.Helper()
	codes := make([]string, 0, n)
	for i := range n {
		submitLogin(t, s.Client(t), HostWWW, unitPassword)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		code, err := s.WaitOutbox(ctx, i)
		cancel()
		if err != nil {
			t.Fatalf("outbox[%d]: %v", i, err)
		}
		codes = append(codes, code)
	}
	return codes
}

// pipeBuf is an io.WriteCloser recording what feedStdin wrote.
type pipeBuf struct {
	mu     sync.Mutex
	b      bytes.Buffer
	closed bool
}

func (p *pipeBuf) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.b.Write(b)
}

func (p *pipeBuf) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func (p *pipeBuf) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.b.String()
}

var _ io.WriteCloser = (*pipeBuf)(nil)

// TestFeedStdin_OutboxIsPerRun: {{outbox}} in a run is the first email
// code sent during that run, never a code of an earlier run (the second run
// of a scenario must not type run 1's stale code).
func TestFeedStdin_OutboxIsPerRun(t *testing.T) {
	t.Parallel()
	site := unitSite(t, ModeEmailOTP)
	s := newSandbox(t)
	s.site = &siteRun{site: site}
	codes := emailCodes(t, site, 2)
	tests := []struct {
		name  string
		from  int // outbox length when the run started
		lines []string
		want  string
	}{
		{name: "first run", from: 0, lines: []string{"{{outbox}}"}, want: codes[0] + "\n"},
		{name: "second run skips run 1 code", from: 1, lines: []string{"{{outbox}}"}, want: codes[1] + "\n"},
		{name: "two codes in one run", from: 0, lines: []string{"{{outbox}}", "{{outbox}}"}, want: codes[0] + "\n" + codes[1] + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &pipeBuf{}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := s.feedStdin(ctx, w, tt.lines, tt.from); err != nil {
				t.Fatalf("feedStdin: %v", err)
			}
			if got := w.String(); got != tt.want {
				t.Errorf("fed %q, want %q", got, tt.want)
			}
			if !w.closed {
				t.Error("stdin not closed after the last line")
			}
		})
	}
}

// TestFeedStdin_FactoExitEndsTheWait: when facto exits without asking for
// an email code (a restored session needs no login), the feeder stops at
// once without an error and writes nothing; it never waits for the outbox
// timeout.
func TestFeedStdin_FactoExitEndsTheWait(t *testing.T) {
	t.Parallel()
	site := unitSite(t, ModeEmailOTP)
	s := newSandbox(t)
	s.site = &siteRun{site: site}
	ctx, exited := context.WithCancel(t.Context())
	exited() // facto has exited: the run cancels the feed context
	w := &pipeBuf{}
	start := clock.Real{}.Now()
	if err := s.feedStdin(ctx, w, []string{"{{outbox}}"}, 0); err != nil {
		t.Errorf("feedStdin after facto exited = %v, want nil", err)
	}
	if d := (clock.Real{}).Now().Sub(start); d > 2*time.Second {
		t.Errorf("feedStdin took %v after facto exited, want an immediate return", d)
	}
	if got := w.String(); got != "" {
		t.Errorf("fed %q after facto exited, want nothing", got)
	}
	if !w.closed {
		t.Error("stdin not closed")
	}
}

// TestFakeSite_SessionValuesFromOption: the session cookie values come from
// siteOptions.SessionValue when set (the harness passes cookie canaries, so
// make leakcheck also hunts them), and every issued value is reported by
// IssuedSessions.
func TestFakeSite_SessionValuesFromOption(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Cookie)
	site := unitSite(t, ModePassword, func(o *siteOptions) {
		o.SessionValue = func() string { return canary }
	})
	c := site.Client(t)
	submitLogin(t, c, HostWWW, unitPassword)
	if got := sessionCookie(c); got != canary {
		t.Errorf("fp_session is not the SessionValue canary (got %d bytes)", len(got))
	}
	if got := site.IssuedSessions(); len(got) != 1 || got[0] != canary {
		t.Errorf("IssuedSessions() returned %d values, want exactly the canary", len(got))
	}
}

// TestSiteLeaks: values the fake site minted for facto (session cookies,
// email codes) and the TOTP code it accepted must not appear in facto's
// output. Cookie values are hunted in every file under HOME; 6-digit codes
// only in stdout, stderr and text artifacts (logs, reports, config), where
// a hit cannot be a coincidence of binary data, and only as a whole number.
// A finding names the kind and the place, never the value.
func TestSiteLeaks(t *testing.T) {
	t.Parallel()
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	const code = "482915" // synthetic email code
	const totp = "730264" // synthetic TOTP code
	tests := []struct {
		name           string
		stdout, stderr string
		files          map[string]string // HOME-relative path -> content
		wantKinds      []string          // nil: no finding; else exactly one finding containing each
	}{
		{name: "clean", stdout: "summary: filed 1\n", files: map[string]string{".facto/reports/r.txt": "ok\n"}},
		{name: "cookie in stderr", stderr: "cookie=" + cookie, wantKinds: []string{"session cookie", "stderr"}},
		{name: "cookie in a binary state file", files: map[string]string{".facto/sessions/fakeprovider.sess": "\x00\x01" + cookie + "\xff"}, wantKinds: []string{"session cookie", ".facto/sessions/fakeprovider.sess"}},
		{name: "cookie in an output pdf", files: map[string]string{"Invoices/a.pdf": "%PDF-1.7 " + cookie}, wantKinds: []string{"session cookie", "Invoices/a.pdf"}},
		{name: "email code in stdout", stdout: "code " + code + "\n", wantKinds: []string{"email code", "stdout"}},
		{name: "email code in a report", files: map[string]string{".facto/reports/r.json": `{"msg":"code ` + code + `"}`}, wantKinds: []string{"email code", ".facto/reports/r.json"}},
		{name: "totp code in a log", files: map[string]string{".facto/logs/run.log": "otp=" + totp}, wantKinds: []string{"TOTP code", ".facto/logs/run.log"}},
		{name: "code inside a longer number is not a hit", stdout: "ts=1" + code + "7\n"},
		{name: "code in a binary file is not hunted", files: map[string]string{".facto/index.db": "SQLite" + code}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			r, err := fsx.Open(s.home)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			for rel, content := range tt.files {
				if err := r.MkdirPrivate(path.Dir(rel)); err != nil {
					t.Fatal(err)
				}
				if err := r.WriteAtomic(t.Context(), rel, []byte(content)); err != nil {
					t.Fatal(err)
				}
			}
			sec := siteSecrets{cookies: []string{cookie}, emailCodes: []string{code}, totpCodes: []string{totp}}
			got := s.siteLeaks(sec, result{stdout: []byte(tt.stdout), stderr: []byte(tt.stderr)})
			if want := min(len(tt.wantKinds), 1); len(got) != want {
				t.Fatalf("findings = %q, want %d finding(s) mentioning %q", got, want, tt.wantKinds)
			}
			for _, want := range tt.wantKinds {
				if !strings.Contains(strings.Join(got, "\n"), want) {
					t.Errorf("findings %q do not mention %q", got, want)
				}
			}
			for _, f := range got {
				for _, v := range []string{cookie, code, totp} {
					if strings.Contains(f, v) {
						t.Errorf("finding %q echoes the leaked value", f)
					}
				}
			}
		})
	}
}

// TestSiteSecrets_CollectsWhatTheSiteMinted: the scan set holds every
// session value and email code the site issued, and the TOTP code values
// the scenario's secrets held.
func TestSiteSecrets_CollectsWhatTheSiteMinted(t *testing.T) {
	t.Parallel()
	site := unitSite(t, ModeEmailOTP)
	s := newSandbox(t)
	s.site = &siteRun{site: site}
	codes := emailCodes(t, site, 1)
	c := site.Client(t)
	submitLogin(t, c, HostWWW, unitPassword)
	_, form := get(t, c, "https://"+HostWWW+"/login/email")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	second, err := site.WaitOutbox(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	postForm(t, c, "https://"+HostWWW+"/login/email", url.Values{"email_code": {second}, "csrf_token": {csrfToken(t, form)}})
	sess := sessionCookie(c)
	if sess == "" {
		t.Fatal("no session after the email code")
	}
	s.totpSecrets = []string{"123456"}
	got := s.siteSecrets()
	if !containsAll(got.cookies, sess) {
		t.Errorf("cookies: issued session missing (%d values)", len(got.cookies))
	}
	if !containsAll(got.emailCodes, codes[0], second) {
		t.Errorf("email codes: %d values, want both outbox codes", len(got.emailCodes))
	}
	if !containsAll(got.totpCodes, "123456") {
		t.Errorf("totp codes: %d values, want the scenario's code", len(got.totpCodes))
	}
}

func containsAll(have []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			found = found || h == w
		}
		if !found {
			return false
		}
	}
	return true
}
