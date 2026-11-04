// Manifest tests (J1 task T11, ADR 0008 "Chrome for Testing (A10)"). See
// helpers_test.go for the expected API.
package cft_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// validManifest is a synthetic, valid manifest (no archive behind it).
func validManifest() cft.Manifest {
	return cft.Manifest{
		Version:    testVersion,
		Platform:   "linux64",
		URL:        testURL,
		Host:       testHost,
		PathPrefix: testPrefix,
		Size:       123456,
		SHA256:     strings.Repeat("ab", 32),
		PinnedAt:   pinDate,
	}
}

func TestManifest_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(m *cft.Manifest)
		wantErr bool
	}{
		{name: "valid synthetic manifest", mutate: func(*cft.Manifest) {}},
		{name: "empty version", mutate: func(m *cft.Manifest) { m.Version = "" }, wantErr: true},
		{name: "non numeric version", mutate: func(m *cft.Manifest) { m.Version = "latest" }, wantErr: true},
		{name: "three part version", mutate: func(m *cft.Manifest) { m.Version = "999.0.0" }, wantErr: true},
		{name: "version with a path segment", mutate: func(m *cft.Manifest) { m.Version = "999.0.0.1/../x" }, wantErr: true},
		{name: "version with a leading space", mutate: func(m *cft.Manifest) { m.Version = " 999.0.0.1" }, wantErr: true},
		{name: "empty platform", mutate: func(m *cft.Manifest) { m.Platform = "" }, wantErr: true},
		{name: "mac platform", mutate: func(m *cft.Manifest) { m.Platform = "mac-arm64" }, wantErr: true},
		{name: "win platform", mutate: func(m *cft.Manifest) { m.Platform = "win64" }, wantErr: true},
		{name: "platform in another case", mutate: func(m *cft.Manifest) { m.Platform = "Linux64" }, wantErr: true},
		{name: "zero size", mutate: func(m *cft.Manifest) { m.Size = 0 }, wantErr: true},
		{name: "negative size", mutate: func(m *cft.Manifest) { m.Size = -1 }, wantErr: true},
		{name: "empty sha256", mutate: func(m *cft.Manifest) { m.SHA256 = "" }, wantErr: true},
		{name: "sha256 63 hex", mutate: func(m *cft.Manifest) { m.SHA256 = strings.Repeat("a", 63) }, wantErr: true},
		{name: "sha256 65 hex", mutate: func(m *cft.Manifest) { m.SHA256 = strings.Repeat("a", 65) }, wantErr: true},
		{name: "sha256 uppercase", mutate: func(m *cft.Manifest) { m.SHA256 = strings.Repeat("AB", 32) }, wantErr: true},
		{name: "sha256 not hex", mutate: func(m *cft.Manifest) { m.SHA256 = strings.Repeat("zz", 32) }, wantErr: true},
		{name: "sha1 length", mutate: func(m *cft.Manifest) { m.SHA256 = strings.Repeat("ab", 20) }, wantErr: true},
		{name: "zero pin date", mutate: func(m *cft.Manifest) { m.PinnedAt = time.Time{} }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := validManifest()
			tt.mutate(&m)
			err := m.Validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, cft.ErrInvalidManifest) {
				t.Fatalf("Validate() = %v, want errors.Is ErrInvalidManifest", err)
			}
		})
	}
}

func TestManifest_PinsExactURLAndHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(m *cft.Manifest)
		wantErr bool
	}{
		{name: "exact host and path under prefix", mutate: func(*cft.Manifest) {}},
		// Host pinning: exact, never a pattern.
		{name: "wildcard host", mutate: func(m *cft.Manifest) { m.Host = "*.cft.test"; m.URL = "https://x.cft.test" + testPath }, wantErr: true},
		{name: "wildcard host matching the url", mutate: func(m *cft.Manifest) { m.Host = "*.cft.test" }, wantErr: true},
		{name: "empty host", mutate: func(m *cft.Manifest) { m.Host = "" }, wantErr: true},
		{name: "host with a port", mutate: func(m *cft.Manifest) { m.Host = testHost + ":443" }, wantErr: true},
		{name: "url on another host", mutate: func(m *cft.Manifest) { m.URL = "https://" + evilHost + testPath }, wantErr: true},
		{name: "url on a subdomain of the host", mutate: func(m *cft.Manifest) { m.URL = "https://x." + testHost + testPath }, wantErr: true},
		{name: "url on the parent of the host", mutate: func(m *cft.Manifest) { m.URL = "https://cft.test" + testPath }, wantErr: true},
		{name: "url host in another case", mutate: func(m *cft.Manifest) { m.URL = "https://DL.cft.test" + testPath }, wantErr: true},
		{name: "url host with a trailing dot", mutate: func(m *cft.Manifest) { m.URL = "https://" + testHost + "." + testPath }, wantErr: true},
		{name: "url with explicit port 443", mutate: func(m *cft.Manifest) { m.URL = "https://" + testHost + ":443" + testPath }, wantErr: true},
		{name: "url with another port", mutate: func(m *cft.Manifest) { m.URL = "https://" + testHost + ":8443" + testPath }, wantErr: true},
		{name: "url with userinfo", mutate: func(m *cft.Manifest) { m.URL = "https://user@" + testHost + testPath }, wantErr: true},
		{name: "url with an IP literal", mutate: func(m *cft.Manifest) { m.Host = "192.0.2.1"; m.URL = "https://192.0.2.1" + testPath }, wantErr: true},
		{name: "http scheme", mutate: func(m *cft.Manifest) { m.URL = "http://" + testHost + testPath }, wantErr: true},
		{name: "no scheme", mutate: func(m *cft.Manifest) { m.URL = "//" + testHost + testPath }, wantErr: true},
		{name: "url with a query", mutate: func(m *cft.Manifest) { m.URL = testURL + "?x=1" }, wantErr: true},
		{name: "url with a fragment", mutate: func(m *cft.Manifest) { m.URL = testURL + "#x" }, wantErr: true},
		// Path prefix pinning: the host is shared storage.
		{name: "path outside the prefix", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + "/other/" + testVersion + "/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "path sharing the prefix without its slash", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + "/cft-publicx/" + testVersion + "/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "dot-dot segment leaving the prefix", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + "../other/" + testVersion + "/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "percent-encoded dot-dot", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + "%2e%2e/other/" + testVersion + "/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "percent-encoded slash", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + testVersion + "%2flinux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "backslash in path", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + testVersion + `\linux64\chrome-linux64.zip`
		}, wantErr: true},
		{name: "dot segment", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + "./" + testVersion + "/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "prefix is the root", mutate: func(m *cft.Manifest) { m.PathPrefix = "/" }, wantErr: true},
		{name: "empty prefix", mutate: func(m *cft.Manifest) { m.PathPrefix = "" }, wantErr: true},
		{name: "prefix without trailing slash", mutate: func(m *cft.Manifest) { m.PathPrefix = "/cft-public" }, wantErr: true},
		{name: "prefix without leading slash", mutate: func(m *cft.Manifest) { m.PathPrefix = "cft-public/" }, wantErr: true},
		{name: "prefix with a wildcard", mutate: func(m *cft.Manifest) { m.PathPrefix = "/cft-*/" }, wantErr: true},
		// The URL must be the archive of this exact version and platform.
		{name: "url of another version", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + "998.0.0.1/linux64/chrome-linux64.zip"
		}, wantErr: true},
		{name: "url of another platform", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + testVersion + "/win64/chrome-win64.zip"
		}, wantErr: true},
		{name: "url not a zip", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + testPrefix + testVersion + "/linux64/chrome-linux64.sh"
		}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := validManifest()
			tt.mutate(&m)
			err := m.Validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, cft.ErrInvalidManifest) {
				t.Fatalf("Validate() = %v, want errors.Is ErrInvalidManifest", err)
			}
		})
	}
}

// TestInstall_ManifestPinsExactURLAndHost is the ADR 0008 binding name: an
// installer is never built from a manifest that does not pin an exact URL
// under an exact host and path prefix, and building one does no network I/O.
func TestInstall_ManifestPinsExactURLAndHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(m *cft.Manifest)
	}{
		{name: "wildcard host", mutate: func(m *cft.Manifest) { m.Host = "*.cft.test" }},
		{name: "url off the pinned host", mutate: func(m *cft.Manifest) { m.URL = "https://" + evilHost + testPath }},
		{name: "url outside the path prefix", mutate: func(m *cft.Manifest) {
			m.URL = "https://" + testHost + "/other/" + testVersion + "/linux64/chrome-linux64.zip"
		}},
		{name: "http url", mutate: func(m *cft.Manifest) { m.URL = "http://" + testHost + testPath }},
		{name: "missing sha256", mutate: func(m *cft.Manifest) { m.SHA256 = "" }},
		{name: "missing size", mutate: func(m *cft.Manifest) { m.Size = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, serveBytes([]byte("never served")))
			m := manifestFor(chromeZip(t))
			tt.mutate(&m)
			dir := privateDir(t)
			in, err := cft.New(cft.Options{Manifest: m, Dir: dir, HTTP: s.httpOpts(), Log: discardLog()})
			if !errors.Is(err, cft.ErrInvalidManifest) {
				t.Fatalf("New() = %v, %v; want errors.Is ErrInvalidManifest", in, err)
			}
			if got := s.requests(); len(got) != 0 {
				t.Fatalf("server got %v, want no request", got)
			}
			assertEmpty(t, dir)
		})
	}
}

// TestManifest_PinnedIsValid checks the manifest compiled into facto. Its
// version, URL, size and hash are set in T12 (trust-on-first-use, hash
// recomputed independently, ADR 0008): this test stays red until then.
func TestManifest_PinnedIsValid(t *testing.T) {
	t.Parallel()

	m := cft.Pinned()
	if err := m.Validate(); err != nil {
		t.Fatalf("Pinned().Validate() = %v, want nil", err)
	}
	if m.Platform != "linux64" {
		t.Fatalf("Pinned().Platform = %q, want linux64 (J1 ships linux64 only)", m.Platform)
	}
	if strings.Contains(m.Host, "*") {
		t.Fatalf("Pinned().Host = %q, want an exact host", m.Host)
	}
	u, err := url.Parse(m.URL)
	if err != nil {
		t.Fatalf("Pinned().URL does not parse: %v", err)
	}
	if u.Scheme != "https" || u.Host != m.Host || !strings.HasPrefix(u.Path, m.PathPrefix) {
		t.Fatalf("Pinned().URL = %q not https on exactly %q under %q", m.URL, m.Host, m.PathPrefix)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.SHA256) {
		t.Fatalf("Pinned().SHA256 = %q, want 64 lowercase hex", m.SHA256)
	}

	// The real download host is shared storage, which a plain httpx
	// allowlist refuses: New must still build its exact-host, path-prefix
	// client for the pinned manifest, without any network I/O.
	t.Run("New accepts the pinned manifest without network", func(t *testing.T) {
		t.Parallel()
		dialed := make(chan string, 1)
		noDial := func(_ context.Context, _, addr string) (net.Conn, error) {
			select {
			case dialed <- addr:
			default:
			}
			return nil, errors.New("synthetic: dialing is not allowed in this test")
		}
		in, err := cft.New(cft.Options{
			Manifest: m,
			Dir:      privateDir(t),
			HTTP:     httpx.Options{DialContext: noDial},
			Log:      discardLog(),
		})
		if err != nil {
			t.Fatalf("New(Pinned()) = %v, want nil", err)
		}
		if in == nil {
			t.Fatal("New(Pinned()) returned a nil installer")
		}
		select {
		case addr := <-dialed:
			t.Fatalf("New dialed %q, want no network I/O", addr)
		default:
		}
	})
}
