package httpx_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// TestClient_RefusesOpaqueURL: a non-empty URL.Opaque makes net/http write
// an absolute-form request line whose authority is not the dialled host, so
// it is refused before any dial, the body is closed once and the error never
// echoes the opaque part.
func TestClient_RefusesOpaqueURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		opaque string
	}{
		{name: "absolute form other host", opaque: "//autre.test/steal?canary-q=1"},
		{name: "absolute form same host", opaque: "//fournisseur.test/x"},
		{name: "relative opaque", opaque: "steal-canary"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			c := e.client(t, "fournisseur.test")
			body := &closeRecorder{Reader: strings.NewReader("synthetic-form=1")}
			u := &url.URL{Scheme: "https", Host: "fournisseur.test", Opaque: tc.opaque}
			req := (&http.Request{Method: http.MethodPost, URL: u, Header: http.Header{}, Body: body}).WithContext(t.Context())
			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, httpx.ErrDomainNotAllowed) {
				t.Fatalf("Do error = %v, want ErrDomainNotAllowed", err)
			}
			if strings.Contains(err.Error(), tc.opaque) {
				t.Errorf("error %q echoes the opaque part", err)
			}
			if body.closes != 1 {
				t.Errorf("request body closed %d times, want 1", body.closes)
			}
			if d := e.dialed(); len(d) != 0 {
				t.Errorf("dialed %q, want no connection", d)
			}
		})
	}
}

// TestClient_RefusesOpaqueRedirectHop: a Location that parses to an opaque
// URL is refused at the hop, after only the first allowed dial.
func TestClient_RefusesOpaqueRedirectHop(t *testing.T) {
	t.Parallel()
	var hits int
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Location", "https:fournisseur.test/next")
		w.WriteHeader(http.StatusFound)
	})
	c := e.client(t, "fournisseur.test")
	resp, err := c.Get(t.Context(), "https://fournisseur.test/start")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, httpx.ErrDomainNotAllowed) {
		t.Fatalf("Do error = %v, want ErrDomainNotAllowed", err)
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1", hits)
	}
}
