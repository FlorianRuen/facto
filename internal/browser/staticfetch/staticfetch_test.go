package staticfetch_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/browser/staticfetch"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// pinHost is a name the httptest certificate covers.
const (
	pinHost   = "example.com"
	pinPrefix = "/app/"
)

// server starts a TLS test server and returns httpx options reaching it as
// pinHost:443, trusting its certificate only.
func server(t *testing.T, h http.HandlerFunc) httpx.Options {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	return httpx.Options{
		RootCAs: roots,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func get(t *testing.T, opts httpx.Options, method, rawURL string, header map[string][]string) (browser.StaticResponse, error) {
	t.Helper()
	g, err := staticfetch.Pinned(opts)(pinHost, pinPrefix)
	if err != nil {
		t.Fatalf("Pinned: %v", err)
	}
	return g(t.Context(), method, rawURL, header)
}

func TestPinned_DownloadsUnderPrefixWithForwardedHeaders(t *testing.T) {
	t.Parallel()
	var gotOrigin, gotMethod string
	opts := server(t, func(w http.ResponseWriter, r *http.Request) {
		gotOrigin, gotMethod = r.Header.Get("Origin"), r.Method
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte("console.log(1)"))
	})
	res, err := get(t, opts, "GET", "https://"+pinHost+pinPrefix+"main.js", map[string][]string{"Origin": {"https://login.example"}})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Status != 200 || string(res.Body) != "console.log(1)" || res.Header["Content-Type"][0] != "text/javascript" {
		t.Fatalf("response = %d %q %v", res.Status, res.Body, res.Header)
	}
	if gotOrigin != "https://login.example" || gotMethod != "GET" {
		t.Fatalf("server saw %s with Origin %q", gotMethod, gotOrigin)
	}
	res, err = get(t, opts, "HEAD", "https://"+pinHost+pinPrefix+"main.js", nil)
	if err != nil || res.Status != 200 || len(res.Body) != 0 || gotMethod != "HEAD" {
		t.Fatalf("HEAD = %d %q %v (server saw %s)", res.Status, res.Body, err, gotMethod)
	}
}

func TestPinned_RefusesOffPrefixAndRedirectOut(t *testing.T) {
	t.Parallel()
	hits := 0
	opts := server(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/other-bucket/evil.js", http.StatusFound)
	})
	if _, err := get(t, opts, "GET", "https://"+pinHost+"/other-bucket/x.js", nil); !errors.Is(err, httpx.ErrPathNotAllowed) {
		t.Fatalf("off-prefix download = %v, want ErrPathNotAllowed", err)
	}
	if hits != 0 {
		t.Fatalf("off-prefix request reached the server")
	}
	if _, err := get(t, opts, "GET", "https://"+pinHost+pinPrefix+"r.js", nil); !errors.Is(err, httpx.ErrPathNotAllowed) {
		t.Fatalf("redirect off the prefix = %v, want ErrPathNotAllowed", err)
	}
	if _, err := get(t, opts, "GET", "https://other.example.com"+pinPrefix+"x.js", nil); !errors.Is(err, httpx.ErrDomainNotAllowed) {
		t.Fatalf("other host = %v, want ErrDomainNotAllowed", err)
	}
	if _, err := get(t, opts, "POST", "https://"+pinHost+pinPrefix+"x.js", nil); err == nil {
		t.Fatal("POST accepted")
	}
}

func TestPinned_RefusesBodyOverCap(t *testing.T) {
	t.Parallel()
	opts := server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", browser.MaxStaticBody+1)))
	})
	if _, err := get(t, opts, "GET", "https://"+pinHost+pinPrefix+"big.js", nil); err == nil {
		t.Fatal("body over MaxStaticBody accepted")
	}
}

func TestPinned_RefusesBadEntry(t *testing.T) {
	t.Parallel()
	for _, e := range [][2]string{{"*.example.com", pinPrefix}, {pinHost, "/"}, {pinHost, "/a/../b/"}, {"127.0.0.1", pinPrefix}} {
		if _, err := staticfetch.Pinned(httpx.Options{})(e[0], e[1]); !errors.Is(err, httpx.ErrInvalidAllowlist) {
			t.Errorf("Pinned(%q, %q) = %v, want ErrInvalidAllowlist", e[0], e[1], err)
		}
	}
}

// TestPinned_NoCookieJar (SEC-J2-7): a Set-Cookie from the static host is
// never sent back on a later download.
func TestPinned_NoCookieJar(t *testing.T) {
	t.Parallel()
	var cookies []string
	opts := server(t, func(w http.ResponseWriter, r *http.Request) {
		cookies = append(cookies, r.Header.Get("Cookie"))
		http.SetCookie(w, &http.Cookie{Name: "tracker", Value: "abc123", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		_, _ = w.Write([]byte("x"))
	})
	g, err := staticfetch.Pinned(opts)(pinHost, pinPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := g(t.Context(), "GET", "https://"+pinHost+pinPrefix+"a.js", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(cookies) != 2 || cookies[1] != "" {
		t.Fatalf("Cookie headers sent = %q, want none", cookies)
	}
}
