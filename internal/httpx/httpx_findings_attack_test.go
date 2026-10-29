// Red-team finding (J0 T30) against internal/httpx, now defended: Client
// refuses any request or redirect hop whose URL has a non-empty Opaque.
// Uses newEnv and ok from httpx_test.go.
package httpx_test

import (
	"net/http"
	"sync"
	"testing"
)

// TestAttack_HttpxOpaqueAbsoluteFormTargetsOtherHost: a connector keeps an
// allowlisted URL.Host but sets URL.Opaque to "//other-host/path". The
// guard checks URL.Host (allowed) and dials it, but net/http then writes
// the request line in absolute form, "GET https://autre.test/x HTTP/1.1".
// RFC 9112 3.2.2 makes the server use that authority and ignore Host, so a
// shared front end (CDN, reverse proxy) routes the request, cookies
// included, to a host outside the allowlist (domain fronting).
func TestAttack_HttpxOpaqueAbsoluteFormTargetsOtherHost(t *testing.T) {
	t.Parallel()
	var (
		mu   sync.Mutex
		seen []string
	)
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+" "+r.RequestURI)
		mu.Unlock()
		ok(w, r)
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://fournisseur.test/x", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Opaque = "//autre.test/steal"
	resp, err := e.client(t, "fournisseur.test").Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if s != "fournisseur.test /x" {
			t.Errorf("server saw request %q: the effective target host is outside the allowlist", s)
		}
	}
}
