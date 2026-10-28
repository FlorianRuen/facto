// Tests for review suggestions on package httpx (J0 follow-up).
//
// Expected behaviour (implementer: follow exactly, and document it in the
// ParseAllowlist / Allows / Do / Get doc comments):
//
//   - Public-suffix guard, no public-suffix-list dependency. ParseAllowlist
//     (and so connector.ValidateInfo) refuses, wrapping ErrInvalidAllowlist:
//     (a) any entry (exact or after "*.") with a single label ("com",
//     "*.com", "*.fr", "localhost");
//     (b) any entry (exact or after "*.") equal to a small built-in list of
//     multi-label public suffixes. At least: co.uk, org.uk, gov.uk, ac.uk,
//     com.au, net.au, co.nz, co.jp, com.br, com.cn, gouv.fr, asso.fr.
//     Comparison is case-insensitive. "*.example.co.uk", "*.edf.fr" and
//     "example.co.uk" stay valid.
//   - Ports: entries never carry a port (already refused). Allows accepts a
//     host with no port or with exactly ":443" and refuses every other port
//     (":8443", ":80", ":0443", an empty port). Client.Do therefore refuses,
//     before dialing and wrapping ErrDomainNotAllowed, a URL, a Host header
//     or a redirect hop with another port.
//   - Client.Do closes req.Body (when non-nil) on every early rejection, as
//     net/http.Client.Do does: nil URL, insecure scheme, disallowed host,
//     disallowed Host header, refused port.
//   - Client.Get(nil ctx, …) returns an error that mentions the context and
//     is not the "malformed url" error; nothing is dialed.
package httpx_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

var publicSuffixAllowlists = [][]string{
	{"com"},
	{"fr"},
	{"localhost"},
	{"*.com"},
	{"*.COM"},
	{"*.fr"},
	{"*.test"},
	{"*.co.uk"},
	{"*.org.uk"},
	{"*.gov.uk"},
	{"*.ac.uk"},
	{"*.com.au"},
	{"*.net.au"},
	{"*.co.nz"},
	{"*.co.jp"},
	{"*.com.br"},
	{"*.com.cn"},
	{"*.gouv.fr"},
	{"*.asso.fr"},
	{"*.Co.Uk"},
	{"co.uk"},
	{"gouv.fr"},
	{"example.com", "*.com"},
	{"*.example.com", "*.co.uk"},
}

var registrableAllowlists = [][]string{
	{"*.example.co.uk"},
	{"example.co.uk"},
	{"*.edf.fr"},
	{"*.impots.gouv.fr"},
	{"*.fournisseur.test"},
	{"espace-client.fournisseur.example", "*.cdn.fournisseur.example"},
}

func TestParseAllowlist_RejectsPublicSuffixWildcards(t *testing.T) {
	t.Parallel()
	for _, list := range publicSuffixAllowlists {
		if _, err := httpx.ParseAllowlist(list); !errors.Is(err, httpx.ErrInvalidAllowlist) {
			t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", list, err)
		}
		c, err := httpx.New(list, httpx.Options{})
		if !errors.Is(err, httpx.ErrInvalidAllowlist) || c != nil {
			t.Errorf("New(%q) = %v, %v; want nil, ErrInvalidAllowlist", list, c, err)
		}
	}
	for _, list := range registrableAllowlists {
		if _, err := httpx.ParseAllowlist(list); err != nil {
			t.Errorf("ParseAllowlist(%q) error = %v, want valid", list, err)
		}
	}
}

// The public-suffix guard must hold at registration too: connector and
// httpx share a single allowlist syntax.
func TestParseAllowlist_PublicSuffixAgreesWithConnectorValidateInfo(t *testing.T) {
	t.Parallel()
	check := func(list []string, wantValid bool) {
		t.Helper()
		_, herr := httpx.ParseAllowlist(list)
		cerr := connector.ValidateInfo(connector.Info{ID: "fournisseur", Name: "Fournisseur", AllowedDomains: list})
		if (herr == nil) != wantValid {
			t.Errorf("httpx.ParseAllowlist(%q) error = %v, want valid=%v", list, herr, wantValid)
		}
		if (cerr == nil) != wantValid {
			t.Errorf("connector.ValidateInfo(AllowedDomains %q) error = %v, want valid=%v", list, cerr, wantValid)
		}
	}
	for _, l := range registrableAllowlists {
		check(l, true)
	}
	for _, l := range publicSuffixAllowlists {
		check(l, false)
	}
}

func TestAllowlist_AllowsOnlyDefaultHTTPSPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		allowed string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "example.com:443", true},
		{"example.com", "EXAMPLE.com:443", true},
		{"example.com", "example.com:8443", false},
		{"example.com", "example.com:80", false},
		{"example.com", "example.com:0443", false},
		{"example.com", "example.com:", false},
		{"example.com", "example.com:65979", false},
		{"*.example.com", "a.example.com:443", true},
		{"*.example.com", "a.example.com:8080", false},
		{"127.0.0.1", "127.0.0.1:443", true},
		{"127.0.0.1", "127.0.0.1:8443", false},
	}
	for _, tc := range tests {
		a, err := httpx.ParseAllowlist([]string{tc.allowed})
		if err != nil {
			t.Fatalf("ParseAllowlist(%q): %v", tc.allowed, err)
		}
		if got := a.Allows(tc.host); got != tc.want {
			t.Errorf("ParseAllowlist(%q).Allows(%q) = %v, want %v", tc.allowed, tc.host, got, tc.want)
		}
	}
}

func TestClient_RefusesNonDefaultPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		url       string
		hostHdr   string
		location  string
		wantDials int
	}{
		{name: "url port", url: "https://fournisseur.test:8443/"},
		{name: "host header port", url: "https://fournisseur.test/", hostHdr: "fournisseur.test:8443"},
		{name: "redirect to other port", url: "https://fournisseur.test/start", location: "https://fournisseur.test:8443/final", wantDials: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" && r.URL.Path == "/start" {
					http.Redirect(w, r, tc.location, http.StatusFound)
					return
				}
				ok(w, r)
			})
			c := e.client(t, "fournisseur.test")
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.hostHdr
			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, httpx.ErrDomainNotAllowed) {
				t.Errorf("Do(%s, Host %q) error = %v, want ErrDomainNotAllowed", tc.url, tc.hostHdr, err)
			}
			if d := e.dialed(); len(d) != tc.wantDials {
				t.Errorf("dialed %q, want %d connection(s)", d, tc.wantDials)
			}
		})
	}
}

func TestClient_DoClosesBodyOnRejection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string // "" means a nil req.URL
		hostHdr string
		wantErr error // nil: any error
	}{
		{name: "nil url"},
		{name: "insecure scheme", url: "http://fournisseur.test/upload", wantErr: httpx.ErrInsecureScheme},
		{name: "disallowed host", url: "https://evil.test/upload", wantErr: httpx.ErrDomainNotAllowed},
		{name: "disallowed host header", url: "https://fournisseur.test/upload", hostHdr: "evil.test", wantErr: httpx.ErrDomainNotAllowed},
		{name: "refused port", url: "https://fournisseur.test:8443/upload", wantErr: httpx.ErrDomainNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			c := e.client(t, "fournisseur.test")
			body := &closeRecorder{Reader: strings.NewReader("synthetic-form=1")}
			req := &http.Request{Method: http.MethodPost, Header: http.Header{}, Body: body}
			req = req.WithContext(t.Context())
			if tc.url != "" {
				u, err := url.Parse(tc.url)
				if err != nil {
					t.Fatal(err)
				}
				req.URL = u
				req.Host = tc.hostHdr
			}
			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatal("Do: nil error, want a rejection")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Do error = %v, want %v", err, tc.wantErr)
			}
			if body.closes != 1 {
				t.Errorf("request body closed %d times, want 1 (net/http parity)", body.closes)
			}
			if d := e.dialed(); len(d) != 0 {
				t.Errorf("dialed %q, want no connection", d)
			}
		})
	}
}

func TestClient_GetNilContext(t *testing.T) {
	t.Parallel()
	e := newEnv(t, ok)
	c := e.client(t, "fournisseur.test")
	var ctx context.Context // nil on purpose
	resp, err := c.Get(ctx, "https://fournisseur.test/")
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("Get(nil ctx): nil error")
	}
	if strings.Contains(err.Error(), "malformed url") {
		t.Errorf("Get(nil ctx) error = %q, want a nil-context error, not malformed url", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "context") {
		t.Errorf("Get(nil ctx) error = %q, want it to mention the context", err)
	}
	if d := e.dialed(); len(d) != 0 {
		t.Errorf("dialed %q, want no connection", d)
	}
}
