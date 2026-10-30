//go:build e2e

package httpx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// TestLoopbackDial_RefusesAtDialLevel (J1 T22): the dialer itself, called
// directly (no client allowlist in front of it), refuses every address but
// an allowed host on 443 over tcp/tcp4, and never connects for those.
func TestLoopbackDial_RefusesAtDialLevel(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	target := netip.MustParseAddrPort(ln.Addr().String())
	allow, err := ParseAllowlist([]string{"www.supplier.example", "*.cdn.supplier.example"})
	if err != nil {
		t.Fatal(err)
	}
	dial := loopbackDial(allow, target)
	refused := []struct{ name, network, addr string }{
		{"off-allowlist host", "tcp", "evil.test:443"},
		{"allowlist parent of wildcard", "tcp", "cdn.supplier.example:443"},
		{"allowed host, other port", "tcp", "www.supplier.example:8443"},
		{"allowed host, port 80", "tcp", "www.supplier.example:80"},
		{"allowed host, no port", "tcp", "www.supplier.example"},
		{"loopback literal", "tcp", "127.0.0.1:443"},
		{"target itself", "tcp", target.String()},
		{"udp", "udp", "www.supplier.example:443"},
		{"tcp6", "tcp6", "www.supplier.example:443"},
	}
	for _, r := range refused {
		c, err := dial(context.Background(), r.network, r.addr)
		if c != nil {
			_ = c.Close()
		}
		if !errors.Is(err, ErrLoopbackDial) {
			t.Errorf("%s: dial(%s, %s) = %v, want ErrLoopbackDial", r.name, r.network, r.addr, err)
		}
	}
	for _, addr := range []string{"www.supplier.example:443", "a.cdn.supplier.example:443"} {
		c, err := dial(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("dial(%s): %v", addr, err)
		}
		_ = c.Close()
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if got := accepted.Load(); got > 2 {
		t.Errorf("listener accepted %d connections, want at most the 2 allowed dials", got)
	}
}
