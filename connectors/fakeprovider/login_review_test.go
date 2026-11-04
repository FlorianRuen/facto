package fakeprovider_test

// Plan J1 T21, review round: entry pages off the allowlist or on another
// port, stale restored cookies, wiping of resolved and prompted secrets, a
// browser handed back together with a Launch error, and the path quoted by
// an ErrBroken message.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
)

func TestLogin_EntryOutsideAllowlistNeverTyped(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, url string }{
		{name: "host outside the allowlist", url: "https://" + evilHost + "/login"},
		{name: "allowed host on another port", url: "https://" + wwwHost + ":8443/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.use(newScript([]connector.Cookie{h.wwwCookie()},
				withPage("foreign-login", fakePage{
					url:     tc.url,
					visible: []string{selLoginForm, selUsername, selPassword, selSubmit},
					next:    map[string]string{selSubmit: pgAccount},
				}),
				entry("foreign-login")))

			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("Login error = %v, want ErrBroken", err)
			}
			if sess != nil {
				t.Errorf("Login returned a session (%v) with an error", sess)
			}
			b := h.browser(0)
			if n := b.count("type"); n != 0 {
				t.Errorf("TypeSecret called %d times on a login form served by %s", n, tc.url)
			}
			if n := b.count("click"); n != 0 {
				t.Errorf("Click called %d times on a login form served by %s", n, tc.url)
			}
			if n := b.count("cookies"); n != 0 {
				t.Errorf("Cookies called %d times", n)
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, err)
		})
	}
}

func TestLogin_ExpiredSavedSessionCookiesNotKept(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	staleSession := canaryCookie(t)
	staleExtra := canaryCookie(t)
	extra := sessionCookie(staleExtra)
	extra.Name = "fp_old"
	old, err := fakeprovider.NewSession(h.site.client(t), []connector.Cookie{sessionCookie(staleSession), extra})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	saved, err := old.Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	h.env.Saved = saved
	h.use(newScript([]connector.Cookie{h.wwwCookie()}))

	sess, err := h.run(t.Context())
	if err != nil {
		t.Fatalf("Login after an expired saved session: %v", err)
	}
	h.mustProbe(sess)
	blob, err := sess.(*fakeprovider.Session).Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	got := blob.Expose()
	if !strings.Contains(got, h.cookie) {
		t.Error("the new Persist blob lacks the cookie the browser login produced")
	}
	for name, v := range map[string]string{"stale fp_session": staleSession, "stale fp_old": staleExtra} {
		if strings.Contains(got, v) {
			t.Errorf("%s value from the expired saved session is in the new Persist blob", name)
		}
	}
	if strings.Contains(got, `"fp_old"`) {
		t.Error("cookie fp_old from the expired saved session survived the browser login")
	}
	h.assertNoLeak(sess, err, staleSession, staleExtra, saved.Expose())
}

// keepResolver keeps every Secret it hands out.
type keepResolver struct {
	inner connector.SecretResolver
	mu    sync.Mutex
	got   []secret.Secret
}

func (r *keepResolver) Resolve(ctx context.Context, ref string) (secret.Secret, error) {
	s, err := r.inner.Resolve(ctx, ref)
	r.mu.Lock()
	r.got = append(r.got, s)
	r.mu.Unlock()
	return s, err //nolint:wrapcheck // test double: passes the inner error through
}

// keepPrompter keeps every Secret it hands out.
type keepPrompter struct {
	inner connector.Prompter
	mu    sync.Mutex
	got   []secret.Secret
}

func (p *keepPrompter) Prompt(ctx context.Context, req connector.PromptRequest) (secret.Secret, error) {
	s, err := p.inner.Prompt(ctx, req)
	p.mu.Lock()
	p.got = append(p.got, s)
	p.mu.Unlock()
	return s, err //nolint:wrapcheck // test double: passes the inner error through
}

func (p *keepPrompter) Interactive() bool { return p.inner.Interactive() }

func TestLogin_SecretsWipedAfterLogin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		setup      func(h *harness)
		wantOK     bool
		minSecrets int // resolved + prompted secrets the scenario must hand out
	}{
		{name: "password", wantOK: true, minSecrets: 2, setup: func(h *harness) {
			h.use(newScript([]connector.Cookie{h.wwwCookie()}))
		}},
		{name: "totp from the otp ref", wantOK: true, minSecrets: 3, setup: func(h *harness) {
			h.env.Credentials.OTP = refOTP
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))
		}},
		{name: "totp prompted", wantOK: true, minSecrets: 3, setup: func(h *harness) {
			h.interactive(true)
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))
		}},
		{name: "email code prompted", wantOK: true, minSecrets: 3, setup: func(h *harness) {
			h.interactive(true)
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgEmail)))
		}},
		{name: "bad password", minSecrets: 2, setup: func(h *harness) {
			h.use(newScript(nil, afterSubmit(pgBadCreds)))
		}},
		{name: "wrong totp", minSecrets: 3, setup: func(h *harness) {
			h.env.Credentials.OTP = refOTP
			h.use(newScript(nil, afterSubmit(pgTOTP), func(s *script) {
				p := s.pages[pgTOTP]
				p.next = map[string]string{selOTPSubmit: pgTOTPErr}
				s.pages[pgTOTP] = p
			}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tc.setup(h)
			res := &keepResolver{inner: h.env.Secrets}
			pr := &keepPrompter{inner: h.env.Prompt}
			h.env.Secrets, h.env.Prompt = res, pr

			_, err := h.run(t.Context())
			if tc.wantOK != (err == nil) {
				t.Fatalf("Login error = %v, want success %v", err, tc.wantOK)
			}
			all := append(append([]secret.Secret{}, res.got...), pr.got...)
			if len(all) < tc.minSecrets {
				t.Fatalf("%d secrets handed out, want at least %d (scenario did not run)", len(all), tc.minSecrets)
			}
			for i, s := range all {
				if !s.IsZero() {
					t.Errorf("secret #%d (resolved or prompted) not wiped after Login", i+1)
				}
			}
		})
	}
}

// closeCounter is a Browser a Launch hands back together with an error:
// only Close may be called on it.
type closeCounter struct {
	connector.Browser // nil: any other call panics
	mu                sync.Mutex
	n                 int
}

func (c *closeCounter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

// halfPool returns a browser and an error from Launch.
type halfPool struct {
	b   *closeCounter
	err error
}

func (p *halfPool) Launch(context.Context, connector.LaunchOptions) (connector.Browser, error) {
	return p.b, p.err
}

func TestLogin_LaunchErrorClosesReturnedBrowser(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	errInjected := errors.New("synthetic launch failure")
	pool := &halfPool{b: &closeCounter{}, err: errInjected}
	h.env.Browser = pool

	sess, err := h.run(t.Context())
	if !errors.Is(err, errInjected) {
		t.Fatalf("Login error = %v, want the launch error", err)
	}
	if sess != nil {
		t.Errorf("Login returned a session (%v) with an error", sess)
	}
	pool.b.mu.Lock()
	n := pool.b.n
	pool.b.mu.Unlock()
	if n != 1 {
		t.Errorf("browser returned with the Launch error closed %d times, want 1", n)
	}
}

func TestLogin_BrokenPathQuotedSafely(t *testing.T) {
	t.Parallel()
	// "/%0Aa" then 2-byte runes starting on odd offsets once decoded: a
	// byte cut of the decoded path at 64 lands inside a rune.
	raw := "https://" + wwwHost + "/%0Aa" + strings.Repeat("é", 40)
	h := newHarness(t)
	h.use(newScript([]connector.Cookie{h.wwwCookie()},
		withPage("odd", fakePage{url: raw, visible: []string{selAccount}}),
		afterSubmit("odd")))

	_, err := h.run(t.Context())
	if !errors.Is(err, connector.ErrBroken) {
		t.Fatalf("Login error = %v, want ErrBroken", err)
	}
	msg := err.Error()
	if !utf8.ValidString(msg) {
		t.Errorf("error %q is not valid UTF-8 (cut inside a rune)", msg)
	}
	if strings.ContainsAny(msg, "\n\r") {
		t.Errorf("error %q carries a raw line break from the supplier path", msg)
	}
	if strings.Contains(msg, "?") {
		t.Errorf("error %q carries a query string", msg)
	}
	h.assertAllClosed()
}
