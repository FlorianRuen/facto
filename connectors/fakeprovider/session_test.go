package fakeprovider_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
)

// meSite answers /api/me with 200 for the current cookie value; when rotate
// is non-empty the first successful /api/me sets it as the new value and
// the old one stops working.
type meSite struct {
	mu      sync.Mutex
	current string
	rotate  string
}

func (m *meSite) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/me" {
		http.NotFound(w, r)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := r.Cookie(cookieKey)
	if err != nil || c.Value != m.current {
		http.Error(w, "expired", http.StatusUnauthorized)
		return
	}
	if m.rotate != "" {
		m.current, m.rotate = m.rotate, ""
		http.SetCookie(w, &http.Cookie{
			Name: cookieKey, Value: m.current, Path: "/", Domain: wwwHost,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Expires: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"account":"ACC-0001"}`))
}

// rendered returns every way a value can end up in a log or an error.
func rendered(v any) string {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("x", "v", v)
	jl := slog.New(slog.NewJSONHandler(&buf, nil))
	jl.Info("x", "v", v)
	return fmt.Sprintf("%v|%+v|%#v|%s|%q|", v, v, v, v, v) + buf.String()
}

func TestPersist_CookiesAsSecretRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("restored session is accepted by the site", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		m := &meSite{current: ck}
		s := newSite(t, m.handler)
		c := fakeprovider.New(fakeprovider.Options{})

		var p connector.Persistable = s.session(t, ck) // compile-time: Session is Persistable
		blob, err := p.Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		if blob.IsZero() {
			t.Fatal("Persist returned an empty blob")
		}
		if out := rendered(blob); strings.Contains(out, ck) {
			t.Fatalf("blob renders the cookie value: %s", out)
		}
		if out := rendered(p); strings.Contains(out, ck) {
			t.Fatalf("session renders the cookie value: %s", out)
		}

		// Fresh client, fresh jar: only the blob carries the session.
		restored, err := fakeprovider.Restore(s.client(t), blob)
		if err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if out := rendered(restored); strings.Contains(out, ck) {
			t.Fatalf("restored session renders the cookie value: %s", out)
		}
		if err := c.Probe(t.Context(), restored); err != nil {
			t.Fatalf("Probe on the restored session: %v", err)
		}
	})

	t.Run("server-rotated cookie is what gets persisted", func(t *testing.T) {
		t.Parallel()
		oldCk, newCk := canaryCookie(t), canaryCookie(t)
		m := &meSite{current: oldCk, rotate: newCk}
		s := newSite(t, m.handler)
		c := fakeprovider.New(fakeprovider.Options{})

		sess := s.session(t, oldCk)
		if err := c.Probe(t.Context(), sess); err != nil {
			t.Fatalf("first Probe: %v", err)
		}
		blob, err := sess.Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		restored, err := fakeprovider.Restore(s.client(t), blob)
		if err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if err := c.Probe(t.Context(), restored); err != nil {
			t.Fatalf("Probe after rotation: %v (the persisted blob must carry the rotated cookie)", err)
		}
	})

	t.Run("cookies outside the allowlist are never persisted", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		foreign := canaryCookie(t)
		m := &meSite{current: ck}
		s := newSite(t, m.handler)
		evil := sessionCookie(foreign)
		evil.Name = "tracker"
		evil.Domain = evilHost
		sess, err := fakeprovider.NewSession(s.client(t), []connector.Cookie{sessionCookie(ck), evil})
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		blob, err := sess.Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		// Expose only to inspect what would be stored; never logged.
		if exposed := blob.Expose(); strings.Contains(exposed, foreign) || strings.Contains(exposed, evilHost) {
			t.Fatal("persisted blob carries a cookie for a host outside the allowlist")
		}
	})

	t.Run("bad blobs need a login and are never echoed", func(t *testing.T) {
		t.Parallel()
		s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unexpected request", http.StatusTeapot)
		})
		tok := canaryCookie(t)
		cases := map[string]secret.Secret{
			"zero":        {},
			"garbage":     secret.FromString("garbage " + tok),
			"wrong json":  secret.FromString(`{"cookies":"` + tok + `"}`),
			"truncated":   secret.FromString(`{"v":1,"cookies":[{"name":"fp_session","value":"` + tok),
			"evil domain": secret.FromString(`{"v":1,"cookies":[{"name":"x","value":"` + tok + `","domain":"evil.test","path":"/"}]}`),
		}
		for name, blob := range cases {
			sess, err := fakeprovider.Restore(s.client(t), blob)
			if !errors.Is(err, connector.ErrNeedsLogin) {
				t.Errorf("%s: Restore = %v, %v; want ErrNeedsLogin", name, sess, err)
				continue
			}
			if strings.Contains(rendered(err), tok) {
				t.Errorf("%s: Restore error echoes the blob: %v", name, err)
			}
		}
		if hits := s.hitList(); len(hits) != 0 {
			t.Fatalf("Restore contacted the site: %q", hits)
		}
	})
}

func TestProbe_ExpiredSessionNeedsLogin(t *testing.T) {
	t.Parallel()

	t.Run("valid session", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		s := newSite(t, (&meSite{current: ck}).handler)
		if err := fakeprovider.New(fakeprovider.Options{}).Probe(t.Context(), s.session(t, ck)); err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if hits := s.hitList(); len(hits) != 1 || hits[0] != "GET "+wwwHost+" /api/me" {
			t.Fatalf("requests = %q, want one GET /api/me on %s", hits, wwwHost)
		}
	})

	cases := []struct {
		name string
		h    http.HandlerFunc
		want error
	}{
		{
			name: "401",
			h:    (&meSite{current: "another-session"}).handler,
			want: connector.ErrNeedsLogin,
		},
		{
			name: "redirect to the sso login page",
			h: func(w http.ResponseWriter, r *http.Request) {
				if r.Host == ssoHost && r.URL.Path == "/login" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write([]byte(`<html><form id="login"></form></html>`))
					return
				}
				http.Redirect(w, r, "https://"+ssoHost+"/login?next=%2Fapi%2Fme", http.StatusFound)
			},
			want: connector.ErrNeedsLogin,
		},
		{
			name: "403",
			h:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) },
			want: connector.ErrAuthFailed,
		},
		{
			name: "429",
			h:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "slow down", http.StatusTooManyRequests) },
			want: connector.ErrRateLimited,
		},
		{
			name: "404",
			h:    http.NotFound,
			want: connector.ErrBroken,
		},
		{
			name: "200 but html instead of json",
			h: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(`<html>Welcome</html>`))
			},
			want: connector.ErrBroken,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ck := canaryCookie(t)
			s := newSite(t, tc.h)
			err := fakeprovider.New(fakeprovider.Options{}).Probe(t.Context(), s.session(t, ck))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Probe error = %v, want %v", err, tc.want)
			}
			if strings.Contains(rendered(err), ck) {
				t.Errorf("Probe error renders the session cookie")
			}
			noQueryInError(t, err)
		})
	}

	t.Run("foreign session", func(t *testing.T) {
		t.Parallel()
		if err := fakeprovider.New(fakeprovider.Options{}).Probe(t.Context(), "not a session"); err == nil {
			t.Fatal("Probe accepted a foreign session type")
		}
	})
}
