//go:build e2e

package httpx

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrLoopbackDial reports a connection the e2e loopback client refuses to
// redirect (wrong network, port or host).
var ErrLoopbackDial = errors.New("httpx: e2e loopback dial refused")

// NewLoopback is New for the e2e build only (J1 T22): every connection to
// an allowed host on port 443 goes to target, which must be 127.0.0.1 with
// a non-zero port, and certificates are verified against roots alone
// (replacing the system roots, which never apply). Anything else is never
// dialed. TLS verification, the allowlist, redirect checks and every other
// option of New still apply; opts.RootCAs and opts.DialContext must be nil.
func NewLoopback(allowed []string, target netip.AddrPort, roots *x509.CertPool, opts Options) (*Client, error) {
	allow, err := ParseAllowlist(allowed)
	if err != nil {
		return nil, err
	}
	if target.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || target.Port() == 0 {
		return nil, fmt.Errorf("%w: target must be 127.0.0.1:<port>", ErrLoopbackDial)
	}
	if roots == nil {
		return nil, fmt.Errorf("%w: no test roots", ErrLoopbackDial)
	}
	if opts.RootCAs != nil || opts.DialContext != nil {
		return nil, fmt.Errorf("%w: roots and dialer are set by NewLoopback", ErrLoopbackDial)
	}
	opts.RootCAs = roots
	opts.DialContext = loopbackDial(allow, target)
	return newClient(allow, nil, opts)
}

// loopbackDial returns the dialer of NewLoopback: a "tcp"/"tcp4"
// connection to <host>:443 with host allowed by allow goes to target;
// anything else is refused with ErrLoopbackDial before any I/O, whatever
// the client's own checks did.
func loopbackDial(allow Allowlist, target netip.AddrPort) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: dialTimeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port != defaultHTTPSPort || (network != "tcp" && network != "tcp4") || !allow.Allows(host) {
			return nil, ErrLoopbackDial
		}
		c, err := d.DialContext(ctx, "tcp4", target.String())
		if err != nil {
			return nil, fmt.Errorf("httpx: e2e loopback dial: %w", err)
		}
		return c, nil
	}
}
