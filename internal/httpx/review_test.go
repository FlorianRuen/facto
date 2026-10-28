// Tests for blocking review findings on package httpx (J0 follow-up).
//
// Expected behaviour (implementer: follow exactly, and document it in the
// ParseAllowlist and Do doc comments):
//
//   - Shared-hosting private suffixes. Besides the ICANN public suffixes of
//     hardening_test.go, ParseAllowlist (and so connector.ValidateInfo)
//     refuses, wrapping ErrInvalidAllowlist and case-insensitively, any
//     entry equal to, or "*." followed by, one of these suffixes where
//     unrelated tenants get sibling subdomains: github.io, pages.dev,
//     netlify.app, vercel.app, herokuapp.com, appspot.com, blogspot.com,
//     cloudfront.net, amazonaws.com, azurewebsites.net, web.app,
//     firebaseapp.com. One tenant's host stays valid, exact
//     ("myproject.github.io") or as a wildcard below it
//     ("*.myproject.github.io"): only the bare suffix is refused.
//   - The guard RoundTripper closes req.Body (when non-nil) whenever it
//     rejects a hop, as the http.RoundTripper contract requires. This covers
//     a 307/308 redirect to a disallowed host or to plain http: net/http
//     replays the body through req.GetBody, and that replayed body must be
//     closed exactly once by the time Client.Do returns.
package httpx_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

var sharedHostingSuffixes = []string{
	"github.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com",
	"appspot.com", "blogspot.com", "cloudfront.net", "amazonaws.com",
	"azurewebsites.net", "web.app", "firebaseapp.com",
}

var tenantAllowlists = [][]string{
	{"myproject.github.io"},
	{"*.myproject.github.io"},
	{"monprojet.pages.dev"},
	{"facto-demo.netlify.app"},
	{"d111111abcdef8.cloudfront.net"},
	{"fournisseur.azurewebsites.net"},
	{"fournisseur.example", "*.fournisseur.example", "myproject.github.io"},
}

func sharedHostingAllowlists() [][]string {
	var out [][]string
	for _, s := range sharedHostingSuffixes {
		out = append(out, []string{s}, []string{"*." + s}, []string{"*." + strings.ToUpper(s)})
	}
	return append(out,
		[]string{"*.GitHub.Io"},
		[]string{"fournisseur.example", "*.github.io"},
		[]string{"myproject.github.io", "*.netlify.app"},
	)
}

func TestParseAllowlist_RejectsSharedHostingSuffixes(t *testing.T) {
	t.Parallel()
	for _, list := range sharedHostingAllowlists() {
		if _, err := httpx.ParseAllowlist(list); !errors.Is(err, httpx.ErrInvalidAllowlist) {
			t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", list, err)
		}
		c, err := httpx.New(list, httpx.Options{})
		if !errors.Is(err, httpx.ErrInvalidAllowlist) || c != nil {
			t.Errorf("New(%q) = %v, %v; want nil, ErrInvalidAllowlist", list, c, err)
		}
	}
	for _, list := range tenantAllowlists {
		if _, err := httpx.ParseAllowlist(list); err != nil {
			t.Errorf("ParseAllowlist(%q) error = %v, want valid", list, err)
		}
	}
}

func TestParseAllowlist_SharedHostingAgreesWithConnectorValidateInfo(t *testing.T) {
	t.Parallel()
	check := func(list []string, wantValid bool) {
		t.Helper()
		cerr := connector.ValidateInfo(connector.Info{ID: "fournisseur", Name: "Fournisseur", AllowedDomains: list})
		if (cerr == nil) != wantValid {
			t.Errorf("connector.ValidateInfo(AllowedDomains %q) error = %v, want valid=%v", list, cerr, wantValid)
		}
	}
	for _, l := range tenantAllowlists {
		check(l, true)
	}
	for _, l := range sharedHostingAllowlists() {
		check(l, false)
	}
}

// syncCloser counts Close calls; safe across the transport's goroutines.
type syncCloser struct {
	io.Reader
	closes atomic.Int32
}

func (c *syncCloser) Close() error {
	c.closes.Add(1)
	return nil
}

func TestClient_GuardClosesReplayedBodyOnRejectedRedirect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		code     int
		location string
		wantErr  error
	}{
		{name: "307 to disallowed host", code: http.StatusTemporaryRedirect, location: "https://evil.test/steal", wantErr: httpx.ErrDomainNotAllowed},
		{name: "308 to disallowed host", code: http.StatusPermanentRedirect, location: "https://evil.test/steal", wantErr: httpx.ErrDomainNotAllowed},
		{name: "307 to disallowed subdomain", code: http.StatusTemporaryRedirect, location: "https://cdn.fournisseur.test/x", wantErr: httpx.ErrDomainNotAllowed},
		{name: "307 to refused port", code: http.StatusTemporaryRedirect, location: "https://fournisseur.test:8443/x", wantErr: httpx.ErrDomainNotAllowed},
		{name: "308 downgrade to http", code: http.StatusPermanentRedirect, location: "http://fournisseur.test/x", wantErr: httpx.ErrInsecureScheme},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				http.Redirect(w, r, tc.location, tc.code)
			})
			c := e.client(t, "fournisseur.test")

			const form = "synthetic-form=1"
			var (
				mu       sync.Mutex
				replayed []*syncCloser
			)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://fournisseur.test/upload", &syncCloser{Reader: strings.NewReader(form)})
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(len(form))
			req.GetBody = func() (io.ReadCloser, error) {
				b := &syncCloser{Reader: strings.NewReader(form)}
				mu.Lock()
				replayed = append(replayed, b)
				mu.Unlock()
				return b, nil
			}

			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do error = %v, want %v", err, tc.wantErr)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(replayed) == 0 {
				t.Fatal("GetBody never called: the redirect did not replay the body")
			}
			last := replayed[len(replayed)-1]
			if n := last.closes.Load(); n != 1 {
				t.Errorf("replayed body for the rejected hop closed %d times, want 1", n)
			}
			if d := e.dialed(); len(d) != 1 || d[0] != "fournisseur.test:443" {
				t.Errorf("dialed %q, want only the first allowed hop", d)
			}
		})
	}
}
