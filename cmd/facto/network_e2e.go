//go:build e2e

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// The e2e network variables (J1 T22, test/e2e/scenario.go). Release builds
// never link this file (`make release-e2e-check`).
const (
	e2eChromeEnv   = "FACTO_E2E_CHROME"   // absolute Chrome for Testing executable
	e2eLoopbackEnv = "FACTO_E2E_LOOPBACK" // exactly 127.0.0.1:<1-65535>
	e2eCAEnv       = "FACTO_E2E_CA"       // private PEM file of the fake site's test CA
)

// maxCABytes caps the FACTO_E2E_CA file.
const maxCABytes = 64 << 10

func init() {
	testRunHooks = e2eRunHooks
}

// e2eRunHooks reads FACTO_E2E_CHROME, FACTO_E2E_LOOPBACK and FACTO_E2E_CA
// (unset and empty are the same). FACTO_E2E_LOOPBACK and FACTO_E2E_CA come
// together or not at all; with them, connector clients dial every allowed
// host on port 443 at the loopback address and trust the test CA only, and
// the browser pool maps the connector's exact hosts there and trusts the
// CA's SPKI. Every error names the variable and never quotes its value or
// the file's content.
func e2eRunHooks(e env) (runHooks, error) {
	var h runHooks
	if exe := e.lookupEnv(e2eChromeEnv); exe != "" {
		if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe {
			return runHooks{}, fmt.Errorf("%s: want an absolute clean path", e2eChromeEnv)
		}
		h.Browser = exe
	}
	loop, caPath := e.lookupEnv(e2eLoopbackEnv), e.lookupEnv(e2eCAEnv)
	if loop == "" && caPath == "" {
		return h, nil
	}
	if loop == "" {
		return runHooks{}, fmt.Errorf("%s: required with %s", e2eLoopbackEnv, e2eCAEnv)
	}
	target, err := parseLoopback(loop)
	if err != nil {
		return runHooks{}, err
	}
	if caPath == "" {
		return runHooks{}, fmt.Errorf("%s: required with %s", e2eCAEnv, e2eLoopbackEnv)
	}
	certs, err := readTestCA(caPath)
	if err != nil {
		return runHooks{}, fmt.Errorf("%s: %w", e2eCAEnv, err)
	}
	roots := x509.NewCertPool()
	spki := make([]string, 0, len(certs))
	for _, c := range certs {
		roots.AddCert(c)
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		spki = append(spki, base64.StdEncoding.EncodeToString(sum[:]))
	}
	h.NewHTTP = func(allowed []string) (*httpx.Client, error) {
		c, err := httpx.NewLoopback(allowed, target, roots, httpx.Options{})
		if err != nil {
			return nil, fmt.Errorf("e2e http client: %w", err)
		}
		return c, nil
	}
	pe := browser.PoolE2E{LoopbackPort: int(target.Port()), TestCASPKI: spki}
	h.Pool = func(cfg browser.PoolConfig) (browser.PoolConfig, error) {
		out, err := browser.WithE2E(cfg, pe)
		if err != nil {
			return browser.PoolConfig{}, fmt.Errorf("e2e pool: %w", err)
		}
		return out, nil
	}
	return h, nil
}

// parseLoopback accepts exactly "127.0.0.1:<port>", port 1-65535 in
// canonical decimal form.
func parseLoopback(v string) (netip.AddrPort, error) {
	bad := fmt.Errorf("%s: want 127.0.0.1:<port>, port 1-65535", e2eLoopbackEnv)
	digits, ok := strings.CutPrefix(v, "127.0.0.1:")
	if !ok {
		return netip.AddrPort{}, bad
	}
	port, err := strconv.Atoi(digits)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != digits {
		return netip.AddrPort{}, bad
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)), nil
}

// readTestCA reads the CA file at p through fsx: p absolute and clean, its
// directory private (no group or world bit), the file itself a regular
// file (never a symlink), private, at most maxCABytes, holding only PEM
// CERTIFICATE blocks (at least one, no headers, nothing else but
// whitespace). Errors never carry the content.
func readTestCA(p string) ([]*x509.Certificate, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, errors.New("want an absolute clean path")
	}
	dir, name := filepath.Split(p)
	if err := fsx.CheckPrivate(dir); err != nil {
		return nil, errors.New("directory missing or not private")
	}
	root, err := fsx.Open(dir)
	if err != nil {
		return nil, errors.New("directory cannot be opened")
	}
	defer func() { _ = root.Close() }() // read-only
	fi, err := root.Lstat(name)
	switch {
	case err != nil:
		return nil, errors.New("no such file")
	case !fi.Mode().IsRegular():
		return nil, errors.New("not a regular file")
	case fi.Mode().Perm()&0o077 != 0:
		return nil, errors.New("file is group or world accessible (want 0600)")
	}
	f, err := root.OpenRegular(name)
	if err != nil {
		return nil, errors.New("not a regular file")
	}
	defer func() { _ = f.Close() }() // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxCABytes+1))
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	if len(data) > maxCABytes {
		return nil, fmt.Errorf("larger than %d bytes", maxCABytes)
	}
	return parseCertificates(data)
}

// parseCertificates decodes PEM CERTIFICATE blocks only.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return nil, errors.New("not a PEM certificate file")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate")
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not a PEM certificate file")
	}
	return certs, nil
}
