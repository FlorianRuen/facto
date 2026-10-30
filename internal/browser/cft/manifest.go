// Package cft installs the pinned Chrome for Testing build facto drives
// (ADR 0008, "Chrome for Testing (A10)"). The archive is pinned by exact
// URL, size and SHA-256 (trust-on-first-use), downloaded through
// internal/httpx with a client limited to one exact host and one path
// prefix, checked for size and then hash before anything is extracted, and
// unzipped through internal/fsx with zip-slip, symlink, duplicate, size and
// mode checks. Installation is explicit (facto browser install): nothing in
// this package runs on its own.
package cft

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors (errors.Is).
var (
	// ErrInvalidManifest reports a manifest that Validate refuses.
	ErrInvalidManifest = errors.New("cft: invalid manifest")
	// ErrSizeMismatch reports a declared Content-Length or a streamed size
	// different from Manifest.Size.
	ErrSizeMismatch = errors.New("cft: archive size mismatch")
	// ErrChecksumMismatch reports an archive whose SHA-256 is not
	// Manifest.SHA256.
	ErrChecksumMismatch = errors.New("cft: archive checksum mismatch")
	// ErrRedirectRefused reports a redirect that left the pinned host,
	// port, scheme or path prefix.
	ErrRedirectRefused = errors.New("cft: redirect refused")
	// ErrUnsafeEntry reports a zip entry with an escaping, absolute or
	// non-portable name, a type other than file or directory, or a
	// duplicate path.
	ErrUnsafeEntry = errors.New("cft: unsafe archive entry")
	// ErrArchiveTooLarge reports an archive over one of the Limits caps.
	ErrArchiveTooLarge = errors.New("cft: archive too large")
)

// MaxPinAge is how old the pinned build may get before WarnIfStale warns
// (ADR 0008: never more than 4 weeks behind).
const MaxPinAge = 28 * 24 * time.Hour

// MarkerName is the file written, last, in <Dir>/<Version>/ once the
// archive was verified and fully extracted. Its content is Manifest.SHA256.
const MarkerName = ".facto-verified"

// platformLinux64 is the only platform J1 ships (decision A10).
const platformLinux64 = "linux64"

var (
	versionRE = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// Manifest pins one Chrome for Testing archive.
type Manifest struct {
	Version    string    // dotted numeric, four parts: "999.0.0.1"
	Platform   string    // "linux64" only (J1)
	URL        string    // exact https URL of the archive
	Host       string    // exact host of URL, no wildcard, no port
	PathPrefix string    // "/a/b/": URL.Path starts with it; starts and ends with "/", is not "/"
	Size       int64     // exact archive size in bytes, > 0
	SHA256     string    // 64 lowercase hex
	PinnedAt   time.Time // date the pin was set, non-zero
}

// Validate returns an error wrapping ErrInvalidManifest unless: Version is
// four dot-separated decimal numbers; Platform is "linux64"; URL parses
// with scheme "https", host exactly equal to Host (byte for byte, no port,
// no userinfo), no query, no fragment, a clean path (no "." or ".."
// segment, no percent-encoding, no backslash) that starts with PathPrefix,
// contains "/"+Version+"/"+Platform+"/" and ends with ".zip"; Host is a
// bare lowercase host name (not an IP literal) without "*"; PathPrefix
// starts and ends with "/" and is longer than "/"; Size > 0; SHA256 is 64
// lowercase hex; PinnedAt is not zero.
func (m Manifest) Validate() error {
	if err := m.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	return nil
}

func (m Manifest) validate() error {
	switch {
	case !versionRE.MatchString(m.Version):
		return fmt.Errorf("version %q is not four dot-separated numbers", m.Version)
	case m.Platform != platformLinux64:
		return fmt.Errorf("platform %q: only %s is pinned", m.Platform, platformLinux64)
	case !hostRE.MatchString(m.Host) || isIP(m.Host):
		return fmt.Errorf("host %q is not a bare lowercase host name", m.Host)
	case !cleanPrefix(m.PathPrefix):
		return fmt.Errorf("path prefix %q is not a clean /dir/ prefix", m.PathPrefix)
	case m.Size <= 0:
		return fmt.Errorf("size %d is not positive", m.Size)
	case !sha256RE.MatchString(m.SHA256):
		return errors.New("sha256 is not 64 lowercase hex digits")
	case m.PinnedAt.IsZero():
		return errors.New("pin date is missing")
	}
	return m.validateURL()
}

// validateURL checks URL against Host, PathPrefix, Version and Platform.
// Messages name the host only: the URL is never echoed.
func (m Manifest) validateURL() error {
	if strings.ContainsAny(m.URL, `?#%\`) {
		return errors.New("url holds a query, fragment, percent-encoding or backslash")
	}
	u, err := url.Parse(m.URL)
	if err != nil {
		return errors.New("url does not parse")
	}
	switch {
	case u.Scheme != "https" || !strings.HasPrefix(m.URL, "https://"):
		return errors.New("url is not https")
	case u.Opaque != "" || u.User != nil:
		return errors.New("url is opaque or carries credentials")
	case u.Host != m.Host:
		return fmt.Errorf("url host is not exactly %s", m.Host)
	case u.RawPath != "" || u.EscapedPath() != u.Path || !cleanPath(u.Path):
		return errors.New("url path is not clean")
	case !strings.HasPrefix(u.Path, m.PathPrefix):
		return errors.New("url path is outside the path prefix")
	case !strings.Contains(u.Path, "/"+m.Version+"/"+m.Platform+"/"):
		return errors.New("url is not the archive of this version and platform")
	case !strings.HasSuffix(u.Path, ".zip"):
		return errors.New("url is not a zip archive")
	}
	return nil
}

// isIP reports whether h is an IP literal (hostRE alone accepts
// "192.0.2.1").
func isIP(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// cleanPrefix reports whether p is "/" + clean path + "/", longer than "/".
func cleanPrefix(p string) bool {
	return len(p) >= 3 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") && cleanPath(p)
}

// cleanPath reports whether p is an absolute printable ASCII path with no
// encoding, backslash or wildcard and no ".", ".." or empty segment (one
// trailing "/" allowed).
func cleanPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for i := range len(p) {
		if c := p[i]; c <= ' ' || c >= 0x7f || strings.IndexByte(`%\*?#`, c) >= 0 {
			return false
		}
	}
	trimmed := strings.TrimSuffix(p, "/")
	return trimmed == "" || path.Clean(trimmed) == trimmed
}
