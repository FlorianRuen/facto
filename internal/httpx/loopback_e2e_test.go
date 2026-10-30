//go:build e2e

package httpx_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// loopbackServer is a TLS server on 127.0.0.1 whose certificate names
// example.com; it counts the requests it serves.
func loopbackServer(t *testing.T) (netip.AddrPort, *x509.CertPool, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	ap, err := netip.ParseAddrPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return ap, roots, &hits
}

// TestNewLoopback_DialsAllowedHostsAtTarget (J1 T22): an allowed host on
// 443 reaches the loopback target with the test roots verifying TLS; any
// other host is refused before a connection.
func TestNewLoopback_DialsAllowedHostsAtTarget(t *testing.T) {
	t.Parallel()
	target, roots, hits := loopbackServer(t)
	c, err := httpx.NewLoopback([]string{"example.com"}, target, roots, httpx.Options{})
	if err != nil {
		t.Fatalf("NewLoopback: %v", err)
	}
	resp, err := c.Get(t.Context(), "https://example.com/")
	if err != nil {
		t.Fatalf("GET allowed host: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("status %d, hits %d; want 200 and 1", resp.StatusCode, hits.Load())
	}
	if resp, err := c.Get(t.Context(), "https://evil.test/"); err == nil {
		_ = resp.Body.Close()
		t.Error("GET off-allowlist host succeeded")
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, the off-allowlist request reached the server", hits.Load())
	}
}

// TestNewLoopback_SystemRootsNeverApply: without the test CA in roots the
// handshake fails: verification stays on.
func TestNewLoopback_SystemRootsNeverApply(t *testing.T) {
	t.Parallel()
	target, _, hits := loopbackServer(t)
	c, err := httpx.NewLoopback([]string{"example.com"}, target, x509.NewCertPool(), httpx.Options{})
	if err != nil {
		t.Fatalf("NewLoopback: %v", err)
	}
	if resp, err := c.Get(t.Context(), "https://example.com/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("GET succeeded without the test CA")
	}
	if hits.Load() != 0 {
		t.Errorf("hits = %d, want 0", hits.Load())
	}
}

// TestNewLoopback_RefusesBadArguments: target off 127.0.0.1 or port 0, no
// roots, or caller-supplied roots or dialer.
func TestNewLoopback_RefusesBadArguments(t *testing.T) {
	t.Parallel()
	roots := x509.NewCertPool()
	good := netip.MustParseAddrPort("127.0.0.1:8443")
	tests := []struct {
		name   string
		target netip.AddrPort
		roots  *x509.CertPool
		opts   httpx.Options
	}{
		{"other loopback", netip.MustParseAddrPort("127.0.0.2:8443"), roots, httpx.Options{}},
		{"ipv6 loopback", netip.MustParseAddrPort("[::1]:8443"), roots, httpx.Options{}},
		{"mapped loopback", netip.MustParseAddrPort("[::ffff:127.0.0.1]:8443"), roots, httpx.Options{}},
		{"private address", netip.MustParseAddrPort("10.0.0.1:443"), roots, httpx.Options{}},
		{"port zero", netip.MustParseAddrPort("127.0.0.1:0"), roots, httpx.Options{}},
		{"no roots", good, nil, httpx.Options{}},
		{"roots in options", good, roots, httpx.Options{RootCAs: roots}},
		{"dialer in options", good, roots, httpx.Options{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("never") }}},
	}
	for _, tt := range tests {
		if _, err := httpx.NewLoopback([]string{"example.com"}, tt.target, tt.roots, tt.opts); !errors.Is(err, httpx.ErrLoopbackDial) {
			t.Errorf("%s: err = %v, want ErrLoopbackDial", tt.name, err)
		}
	}
}

// TestNewLoopback_NonDefaultPortRefusedAtDial: an allowed host on a port
// other than 443 never reaches the loopback target through the client
// (TestLoopbackDial_RefusesAtDialLevel shows the dialer alone refuses it
// too).
func TestNewLoopback_NonDefaultPortRefusedAtDial(t *testing.T) {
	t.Parallel()
	target, roots, hits := loopbackServer(t)
	c, err := httpx.NewLoopback([]string{"example.com"}, target, roots, httpx.Options{})
	if err != nil {
		t.Fatalf("NewLoopback: %v", err)
	}
	if resp, err := c.Get(t.Context(), "https://example.com:8443/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("GET on port 8443 succeeded")
	}
	if hits.Load() != 0 {
		t.Errorf("hits = %d, want 0", hits.Load())
	}
}
