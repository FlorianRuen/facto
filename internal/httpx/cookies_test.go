package httpx_test

// Cookie helpers for packages that may not import net/http (connectors):
// plan J1 T20, fakeprovider session injection and export.

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/httpx"
)

func TestClient_SetCookiesSentToHostOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			http.Error(w, "no cookie", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, c.Value)
	})
	c := e.client(t, "fournisseur.test", "sso.fournisseur.test")
	err := c.SetCookies("Fournisseur.test:443", []httpx.Cookie{{
		Name: "sid", Value: "synthetic-cookie",
		Expires: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}})
	if err != nil {
		t.Fatalf("SetCookies: %v", err)
	}
	status, body, err := get(t, c, "https://fournisseur.test/api/me")
	if err != nil || status != http.StatusOK || body != "synthetic-cookie" {
		t.Fatalf("GET = %d %q %v, want the injected cookie sent", status, body, err)
	}
	// Host-only: another allowed host never receives it.
	if status, _, err := get(t, c, "https://sso.fournisseur.test/"); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("GET sso = %d %v, want 401 (host-only cookie)", status, err)
	}

	got, err := c.Cookies("fournisseur.test")
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	if len(got) != 1 || got[0].Name != "sid" || got[0].Value != "synthetic-cookie" || got[0].Path != "/" {
		t.Fatalf("Cookies = %+v, want the one sid cookie", got)
	}
	if other, err := c.Cookies("sso.fournisseur.test"); err != nil || len(other) != 0 {
		t.Fatalf("Cookies(sso) = %d cookies, %v; want none", len(other), err)
	}
}

func TestClient_CookiesRefuseHostsOutsideAllowlist(t *testing.T) {
	t.Parallel()
	c := mustNew(t, []string{"fournisseur.test"}, httpx.Options{})
	for _, host := range []string{"evil.test", "fournisseur.test:8443", "", "x.fournisseur.test"} {
		err := c.SetCookies(host, []httpx.Cookie{{Name: "sid", Value: "synthetic-secret-value"}})
		if !errors.Is(err, httpx.ErrDomainNotAllowed) {
			t.Errorf("SetCookies(%q) = %v, want ErrDomainNotAllowed", host, err)
		}
		if err != nil && strings.Contains(err.Error(), "synthetic-secret-value") {
			t.Errorf("SetCookies(%q) error echoes the cookie value", host)
		}
		if _, err := c.Cookies(host); !errors.Is(err, httpx.ErrDomainNotAllowed) {
			t.Errorf("Cookies(%q) = %v, want ErrDomainNotAllowed", host, err)
		}
	}
	if got, err := c.Cookies("fournisseur.test"); err != nil || len(got) != 0 {
		t.Fatalf("a refused SetCookies stored something: %d cookies, %v", len(got), err)
	}
}
