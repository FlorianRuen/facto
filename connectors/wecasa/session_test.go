package wecasa_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// rendered returns every way a value can end up in a log or an error.
func rendered(v any) string {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("x", "v", v)
	jl := slog.New(slog.NewJSONHandler(&buf, nil))
	jl.Info("x", "v", v)
	return fmt.Sprintf("%v|%+v|%#v|%s|%q|", v, v, v, v, v) + buf.String()
}

// TestNewSession_ReadsTokenFromBookingsPage: cookies go into the jar, the
// bookings page is fetched with them, the token is held as a secret and
// sent as a bearer token; nothing renders a secret.
func TestNewSession_ReadsTokenFromBookingsPage(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	sess := s.session(t)
	s.noSecretIn(t, "session", rendered(sess))
	if got := s.hitList(); len(got) != 1 || got[0] != "GET "+pathPage {
		t.Errorf("requests = %v, want only GET %s", got, pathPage)
	}
	if err := wecasa.New(wecasa.Options{}).Probe(t.Context(), sess); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if n := s.badAuthCount(); n != 0 {
		t.Errorf("%d API requests without the bearer token", n)
	}
}

// TestNewSession_PageWithoutTokenNeedsLogin: a bookings page without the
// token, or the login page it redirects to, means the session is gone.
func TestNewSession_PageWithoutTokenNeedsLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mod    func(*site)
		cookie string // "" → the site's cookie
		want   error
	}{
		{name: "no token in page", mod: func(s *site) {
			s.setPage(bytes.Replace(s.page, []byte("token: '"+s.token+"',"), nil, 1))
		}, want: connector.ErrNeedsLogin},
		{name: "redirect to login (wrong cookie)", cookie: "stale-cookie-value", want: connector.ErrNeedsLogin},
		{name: "401", mod: func(s *site) { s.route(pathPage, status(http.StatusUnauthorized)) }, want: connector.ErrNeedsLogin},
		{name: "404", mod: func(s *site) { s.route(pathPage, status(http.StatusNotFound)) }, want: connector.ErrBroken},
		{name: "429", mod: func(s *site) { s.route(pathPage, status(http.StatusTooManyRequests)) }, want: connector.ErrRateLimited},
		{name: "not html", mod: func(s *site) { s.route(pathPage, serve("application/json", []byte("{}"), false)) }, want: connector.ErrBroken},
		{name: "page over cap", mod: func(s *site) {
			s.route(pathPage, serve("text/html", bytes.Repeat([]byte("a"), 3<<20), false))
		}, want: connector.ErrBroken},
		{name: "token of the wrong shape", mod: func(s *site) {
			s.setPage(bytes.Replace(s.page, []byte(s.token), []byte("not a token!"), 1))
		}, want: connector.ErrBroken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			if tt.mod != nil {
				tt.mod(s)
			}
			ck := tt.cookie
			if ck == "" {
				ck = s.cookie
			}
			sess, err := wecasa.NewSession(t.Context(), s.client(t), []connector.Cookie{sessionCookie(sessionKey, ck)})
			if !errors.Is(err, tt.want) || sess != nil {
				t.Fatalf("NewSession = %v, %v; want %v", sess, err, tt.want)
			}
			s.noSecretIn(t, "NewSession error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
			if strings.Contains(err.Error(), "<") {
				t.Errorf("error quotes the page: %v", err)
			}
		})
	}
}

// TestNewSession_DropsForeignCookies: a cookie of another domain never
// reaches the jar nor a Persist blob; an invalid cookie is refused by
// index.
func TestNewSession_DropsForeignCookies(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	foreign := sessionCookie("tracker", "FOREIGNVALUE")
	foreign.Domain = ".evil.test"
	sess, err := wecasa.NewSession(t.Context(), s.client(t), []connector.Cookie{foreign, sessionCookie(sessionKey, s.cookie)})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	blob, err := sess.Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if strings.Contains(blob.Expose(), "FOREIGNVALUE") || strings.Contains(blob.Expose(), "tracker") {
		t.Error("foreign cookie persisted")
	}

	for _, bad := range []connector.Cookie{
		sessionCookie("bad name", "v"),
		sessionCookie(sessionKey, "bad;value"),
		{Name: sessionKey, Value: secret.FromString("v"), Domain: wwwHost, Path: "relative"},
	} {
		_, err := wecasa.NewSession(t.Context(), s.client(t), []connector.Cookie{bad})
		if err == nil || !strings.Contains(err.Error(), "cookie 0") {
			t.Errorf("NewSession(invalid cookie) = %v, want an error naming cookie 0", err)
		}
	}
	if _, err := wecasa.NewSession(t.Context(), nil, nil); err == nil {
		t.Error("NewSession(nil client) succeeded")
	}
}

// TestPersist_RoundTrip: the blob carries cookies and token; a fresh
// client restored from it passes Probe and lists without reading the
// bookings page again. Neither the blob nor the sessions render a secret.
func TestPersist_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	c := wecasa.New(wecasa.Options{})
	var p connector.Persistable = s.session(t)
	blob, err := p.Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if blob.IsZero() {
		t.Fatal("Persist returned an empty blob")
	}
	if !strings.Contains(blob.Expose(), s.token) || !strings.Contains(blob.Expose(), s.cookie) {
		t.Error("blob lacks the token or the cookie")
	}
	s.noSecretIn(t, "blob", rendered(blob))
	s.noSecretIn(t, "session", rendered(p))

	pages := s.hitsWithPrefix("GET " + pathPage)
	restored, err := wecasa.Restore(s.client(t), blob)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	s.noSecretIn(t, "restored session", rendered(restored))
	if err := c.Probe(t.Context(), restored); err != nil {
		t.Fatalf("Probe on the restored session: %v", err)
	}
	if _, err := c.List(t.Context(), restored, connector.Year(2026)); err != nil {
		t.Fatalf("List on the restored session: %v", err)
	}
	if n := s.hitsWithPrefix("GET " + pathPage); n != pages {
		t.Errorf("Restore read the bookings page again (%d times)", n-pages)
	}
	// The restored client sends the cookie too.
	again, err := restored.Persist(t.Context())
	if err != nil || again.Expose() != blob.Expose() {
		t.Errorf("Persist after Restore = %v; blob changed", err)
	}
}

// TestPersist_RotatedCookieIsPersisted: a cookie the server rotates is the
// one the blob carries.
func TestPersist_RotatedCookieIsPersisted(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	rotated := "rotated-" + s.cookie
	s.route(pathUser, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: sessionKey, Value: rotated, Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Expires: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		writeJSON(w, fixture(t, fxUser))
	})
	sess := s.session(t)
	if err := wecasa.New(wecasa.Options{}).Probe(t.Context(), sess); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	blob, err := sess.Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if !strings.Contains(blob.Expose(), rotated) {
		t.Error("blob lacks the rotated cookie")
	}
}

// TestPersist_RefusesUnusableSessions: no cookie or no token → ErrNeedsLogin;
// nil session → error. No error renders a secret.
func TestPersist_RefusesUnusableSessions(t *testing.T) {
	t.Parallel()
	if _, err := (*wecasa.Session)(nil).Persist(t.Context()); err == nil {
		t.Error("Persist(nil) succeeded")
	}
	if _, err := (&wecasa.Session{}).Persist(t.Context()); err == nil {
		t.Error("Persist(zero) succeeded")
	}
	s := newSite(t)
	blob, err := s.session(t).Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	// Restore into a client, then expire the cookie in its jar: Persist
	// has a token but no cookie.
	hc := s.client(t)
	sess, err := wecasa.Restore(hc, blob)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := hc.SetCookies(wwwHost, []httpx.Cookie{{Name: sessionKey, Value: "x", Path: "/", Expires: time.Unix(1, 0)}}); err != nil {
		t.Fatalf("SetCookies: %v", err)
	}
	_, err = sess.Persist(t.Context())
	if !errors.Is(err, connector.ErrNeedsLogin) {
		t.Errorf("Persist without cookie = %v, want ErrNeedsLogin", err)
	}
	s.noSecretIn(t, "Persist error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
}

// TestRestore_RefusesMalformedBlobs: every unusable blob wraps
// ErrNeedsLogin, never echoes the blob, and sends no request.
func TestRestore_RefusesMalformedBlobs(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	good, err := s.session(t).Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	g := good.Expose()
	before := len(s.hitList())
	ck := `{"name":"_wecasa_session","value":"` + s.cookie + `","domain":"www.wecasa.fr","path":"/"}`
	tok := `"token":"` + s.token + `"`
	blobs := map[string]string{
		"empty":           "",
		"not json":        "garbage " + s.token,
		"truncated":       g[:len(g)/2],
		"trailing":        g + "{}",
		"version 2":       strings.Replace(g, `"v":1`, `"v":2`, 1),
		"unknown field":   `{"v":1,` + tok + `,"cookies":[` + ck + `],"x":1}`,
		"no token":        `{"v":1,"cookies":[` + ck + `]}`,
		"bad token":       `{"v":1,"token":"bad token","cookies":[` + ck + `]}`,
		"no cookies":      `{"v":1,` + tok + `,"cookies":[]}`,
		"foreign host":    `{"v":1,` + tok + `,"cookies":[` + strings.Replace(ck, wwwHost, evilHost, 1) + `]}`,
		"dotted host":     `{"v":1,` + tok + `,"cookies":[` + strings.Replace(ck, `"www.wecasa.fr"`, `".www.wecasa.fr"`, 1) + `]}`,
		"other path":      `{"v":1,` + tok + `,"cookies":[` + strings.Replace(ck, `"path":"/"`, `"path":"/api"`, 1) + `]}`,
		"bad cookie name": `{"v":1,` + tok + `,"cookies":[` + strings.Replace(ck, "_wecasa_session", "bad name", 1) + `]}`,
	}
	for name, b := range blobs {
		sess, err := wecasa.Restore(s.client(t), secret.FromString(b))
		if !errors.Is(err, connector.ErrNeedsLogin) || sess != nil {
			t.Errorf("%s: Restore = %v, %v; want ErrNeedsLogin", name, sess, err)
			continue
		}
		s.noSecretIn(t, name+": Restore error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
	}
	if _, err := wecasa.Restore(nil, good); err == nil {
		t.Error("Restore(nil client) succeeded")
	}
	if n := len(s.hitList()); n != before {
		t.Errorf("Restore sent %d requests", n-before)
	}
}

// TestProbe_StatusAndBody: 401 → ErrNeedsLogin, 429 → ErrRateLimited (one
// request), malformed body or empty public_id → ErrBroken.
func TestProbe_StatusAndBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		h    http.HandlerFunc
		want error
	}{
		{name: "401", h: status(http.StatusUnauthorized), want: connector.ErrNeedsLogin},
		{name: "429", h: status(http.StatusTooManyRequests), want: connector.ErrRateLimited},
		{name: "html", h: serve("text/html", []byte("<html>"), false), want: connector.ErrBroken},
		{name: "malformed", h: serve("application/json", []byte("{"), false), want: connector.ErrBroken},
		{name: "no public_id", h: serve("application/json", []byte(`{"email":"x"}`), false), want: connector.ErrBroken},
		{name: "over cap", h: serve("application/json", append([]byte(`{"public_id":"abc","x":"`), bytes.Repeat([]byte("a"), 70<<10)...), false), want: connector.ErrBroken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			s.route(pathUser, tt.h)
			err := wecasa.New(wecasa.Options{}).Probe(t.Context(), s.session(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Probe = %v, want %v", err, tt.want)
			}
			if n := s.hitsWithPrefix("GET " + pathUser); n != 1 {
				t.Errorf("%s requested %d times, want 1", pathUser, n)
			}
		})
	}
	if err := wecasa.New(wecasa.Options{}).Probe(t.Context(), "x"); err == nil {
		t.Error("Probe(foreign session) succeeded")
	}
}
