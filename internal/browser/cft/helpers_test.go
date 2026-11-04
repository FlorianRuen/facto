// Tests for package cft (J1 task T11): the pinned Chrome for Testing download,
// verified and safely unzipped. Decision A10 and ADR 0008 "Chrome for Testing
// (A10)": pinned linux64 version + SHA-256 (trust-on-first-use), the manifest
// records the exact URL, size and hash, the client pins the exact host and a
// path prefix (the real host is shared storage), the size is checked before
// the hash, a redirect off that host or prefix is refused, the download goes
// through internal/httpx only and the extraction through internal/fsx only.
//
// No test touches the real network or downloads Chrome: servers are httptest
// TLS servers with a certificate generated here for *.test names, reached
// through httpx with Options.RootCAs and Options.DialContext; archives are
// small synthetic zips built in the tests. All host names, versions and
// contents are synthetic.
//
// Expected API (implementer: follow exactly):
//
//	package cft // import "github.com/FlorianRuen/facto/internal/browser/cft"
//
//	// Sentinel errors (errors.Is).
//	var (
//	    ErrInvalidManifest  error // Manifest.Validate failed
//	    ErrSizeMismatch     error // declared Content-Length or streamed size != Manifest.Size
//	    ErrChecksumMismatch error // SHA-256 of the archive != Manifest.SHA256
//	    ErrRedirectRefused  error // a redirect left the pinned host, port, scheme or path prefix
//	    ErrUnsafeEntry      error // zip entry: path escape, absolute, backslash, drive letter,
//	                              // NUL, symlink or other non-regular type, duplicate
//	    ErrArchiveTooLarge  error // a Limits cap was exceeded (zip bomb)
//	)
//
//	// MaxPinAge is how old the pinned build may get before WarnIfStale warns
//	// (ADR 0008: never more than 4 weeks behind).
//	const MaxPinAge = 28 * 24 * time.Hour
//
//	// MarkerName is the file written, last, in <Dir>/<Version>/ once the
//	// archive was verified and fully extracted. Its content is Manifest.SHA256.
//	const MarkerName = ".facto-verified"
//
//	// Manifest pins one Chrome for Testing archive.
//	type Manifest struct {
//	    Version    string    // dotted numeric, four parts: "999.0.0.1"
//	    Platform   string    // "linux64" only (J1)
//	    URL        string    // exact https URL of the archive
//	    Host       string    // exact host of URL, no wildcard, no port
//	    PathPrefix string    // "/a/b/": URL.Path starts with it; starts and ends with "/", is not "/"
//	    Size       int64     // exact archive size in bytes, > 0
//	    SHA256     string    // 64 lowercase hex
//	    PinnedAt   time.Time // date the pin was set, non-zero
//	}
//
//	// Validate returns an error wrapping ErrInvalidManifest unless: Version is
//	// four dot-separated decimal numbers; Platform is "linux64"; URL parses
//	// with scheme "https", host exactly equal to Host (byte for byte, no port,
//	// no userinfo), no query, no fragment, a clean path (no "." or ".."
//	// segment, no percent-encoding, no backslash) that starts with
//	// PathPrefix, contains "/"+Version+"/"+Platform+"/" and ends with ".zip";
//	// Host is a bare host name without "*"; PathPrefix starts and ends with
//	// "/" and is longer than "/"; Size > 0; SHA256 is 64 lowercase hex;
//	// PinnedAt is not zero.
//	func (m Manifest) Validate() error
//
//	// Pinned returns the manifest compiled into facto (values set in T12).
//	func Pinned() Manifest
//
//	// Limits caps an extraction. DefaultLimits is used for every zero field.
//	type Limits struct {
//	    MaxTotal   int64 // total uncompressed bytes
//	    MaxFile    int64 // uncompressed bytes of one entry
//	    MaxEntries int   // number of entries, directories included
//	    MaxRatio   int64 // uncompressed/compressed of one entry
//	}
//	func DefaultLimits() Limits // every field > 0
//
//	// Unzip extracts the zip (ra, size) into dst through fsx. It validates
//	// every header first (names, types, duplicates, entry count, declared
//	// sizes, ratio) and writes nothing when any is refused. Names are
//	// slash-separated and relative; an entry whose name is absolute, holds a
//	// ".." segment, a backslash, a drive letter ("C:"), a NUL, or that is a
//	// symlink, device, FIFO, socket or irregular file wraps ErrUnsafeEntry. Two
//	// entries naming the same path after cleaning, case-insensitively, or a
//	// path used both as a file and as a directory, wrap ErrUnsafeEntry.
//	// Exceeding a cap wraps ErrArchiveTooLarge; the caps are also enforced
//	// while streaming, so lying headers cannot bypass them. Modes are
//	// sanitized: an entry with any execute bit is written 0700 (through
//	// fsx.WriteAtomicExec), any other file 0600, every directory (explicit or
//	// implied) 0700; setuid, setgid and sticky bits are never set. Nothing is
//	// ever written outside dst (fsx.Root confinement): a pre-existing symlink
//	// inside dst is never followed.
//	func Unzip(ctx context.Context, ra io.ReaderAt, size int64, dst *fsx.Root, lim Limits) error
//
//	// Options configures an Installer.
//	type Options struct {
//	    Manifest Manifest
//	    Dir      string        // install root: must exist and be private (0700)
//	    HTTP     httpx.Options // test seam (RootCAs, DialContext); zero in production
//	    Log      *slog.Logger  // nil: discard
//	    Limits   Limits        // zero fields: DefaultLimits
//	}
//
//	// New validates opts.Manifest (ErrInvalidManifest), checks Dir with
//	// fsx.CheckPrivate (fs.ErrNotExist, fsx.ErrInsecurePerms), and builds an
//	// httpx client allowing only Manifest.Host on 443 and only paths under
//	// Manifest.PathPrefix, for every hop. It accepts the Pinned() manifest
//	// even though the real host is shared storage (the path prefix is what
//	// narrows it). New does no network I/O.
//	type Installer struct{ /* ... */ }
//	func New(opts Options) (*Installer, error)
//
//	// Install makes sure the pinned build is extracted under
//	// <Dir>/<Version>/ and returns the absolute path of the executable,
//	// filepath.Join(Dir, Version, "chrome-"+Platform, "chrome").
//	// If <Dir>/<Version>/MarkerName is a regular file holding Manifest.SHA256
//	// and the executable is a regular file, it returns at once with no
//	// network I/O. Otherwise it downloads Manifest.URL through httpx into a
//	// private temp location: a Content-Length different from Size is refused
//	// before reading the body, the stream is cut at Size+1 bytes, a streamed
//	// size different from Size wraps ErrSizeMismatch and is checked before the
//	// hash; a hash mismatch wraps ErrChecksumMismatch; only then is the
//	// archive unzipped (Unzip) into a staging directory that replaces
//	// <Dir>/<Version>/ and gets the marker last. On any error (including a
//	// canceled ctx or a cut connection) Dir is left exactly as it was before
//	// the call: no temp file, no staging or version directory. Progress is
//	// logged through Log (at least one record per download) and never
//	// contains a URL query, a fragment, or a header value; neither does any
//	// returned error.
//	func (in *Installer) Install(ctx context.Context) (string, error)
//
//	// WarnIfStale logs exactly one Warn record (naming m.Version) and
//	// returns true when clk.Now() is more than MaxPinAge after m.PinnedAt;
//	// otherwise it logs nothing and returns false.
//	func WarnIfStale(ctx context.Context, log *slog.Logger, clk clock.Clock, m Manifest) bool
package cft_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"hash/crc32"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// Synthetic pin used by every install test.
const (
	testHost    = "dl.cft.test"
	evilHost    = "evil.test"
	testPrefix  = "/cft-public/"
	testVersion = "999.0.0.1"
	testPath    = testPrefix + testVersion + "/linux64/chrome-linux64.zip"
	testURL     = "https://" + testHost + testPath
)

// pinDate is the synthetic PinnedAt of every test manifest.
var pinDate = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// manifestFor returns a valid manifest pinning archive at testURL.
func manifestFor(archive []byte) cft.Manifest {
	return cft.Manifest{
		Version:    testVersion,
		Platform:   "linux64",
		URL:        testURL,
		Host:       testHost,
		PathPrefix: testPrefix,
		Size:       int64(len(archive)),
		SHA256:     sha256Hex(archive),
		PinnedAt:   pinDate,
	}
}

// zent is one entry of a synthetic zip.
type zent struct {
	name string
	mode fs.FileMode // 0: regular 0644 file
	body []byte
	// declared, when > 0, lies about the uncompressed size in the headers
	// (raw entry, real deflate data of body).
	declared uint64
}

// buildZip builds a zip from entries, in order, duplicates and hostile names
// included (archive/zip's writer does not validate names).
func buildZip(t *testing.T, entries []zent) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		fh := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		fh.SetMode(mode)
		fh.Modified = pinDate
		if e.declared > 0 {
			var comp bytes.Buffer
			fw, err := flate.NewWriter(&comp, flate.BestCompression)
			if err != nil {
				t.Fatalf("flate writer: %v", err)
			}
			if _, err := fw.Write(e.body); err != nil {
				t.Fatalf("flate write: %v", err)
			}
			if err := fw.Close(); err != nil {
				t.Fatalf("flate close: %v", err)
			}
			fh.CRC32 = crc32.ChecksumIEEE(e.body)
			compLen := comp.Len()
			if compLen < 0 {
				t.Fatalf("flate output length %d is negative", compLen)
				return nil
			}
			fh.CompressedSize64 = uint64(compLen)
			fh.UncompressedSize64 = e.declared
			w, err := zw.CreateRaw(fh)
			if err != nil {
				t.Fatalf("zip CreateRaw(%q): %v", e.name, err)
			}
			if _, err := w.Write(comp.Bytes()); err != nil {
				t.Fatalf("zip raw write: %v", err)
			}
			continue
		}
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("zip CreateHeader(%q): %v", e.name, err)
		}
		// archive/zip refuses data for a name ending in "/" (a directory).
		if len(e.body) > 0 && !strings.HasSuffix(e.name, "/") {
			if _, err := w.Write(e.body); err != nil {
				t.Fatalf("zip write: %v", err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// chromeEntries is a tiny synthetic stand-in for chrome-linux64.zip.
func chromeEntries() []zent {
	return []zent{
		{name: "chrome-linux64/", mode: fs.ModeDir | 0o755},
		{name: "chrome-linux64/chrome", mode: 0o755, body: []byte("#!/bin/sh\n# synthetic chrome\n")},
		{name: "chrome-linux64/chrome_sandbox", mode: 0o4755, body: []byte("synthetic sandbox")},
		{name: "chrome-linux64/locales/en-US.pak", mode: 0o644, body: []byte("synthetic locale")},
		{name: "chrome-linux64/resources.pak", mode: 0o644, body: bytes.Repeat([]byte("synthetic resources "), 64)},
	}
}

func chromeZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, chromeEntries())
}

// certHosts are the names the test certificate is valid for: the pinned host
// and an off-host target, so a refused hop is refused by policy, not by TLS.
var certHosts = []string{testHost, evilHost}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "facto cft test server"},
		DNSNames:              certHosts,
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// hit is one request the test server received.
type hit struct {
	host, path, rawQuery string
}

// server is one TLS test server; every client connection is routed to it,
// whatever host the client dials, and every request is recorded.
type server struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu   sync.Mutex
	hits []hit
}

func newServer(t *testing.T, h http.HandlerFunc) *server {
	t.Helper()
	s := &server{}
	cert, pool := testCert(t)
	s.pool = pool
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, hit{host: r.Host, path: r.URL.Path, rawQuery: r.URL.RawQuery})
		s.mu.Unlock()
		h(w, r)
	}))
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *server) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", s.srv.Listener.Addr().String())
}

func (s *server) httpOpts() httpx.Options {
	return httpx.Options{RootCAs: s.pool, DialContext: s.dial}
}

func (s *server) requests() []hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hits)
}

// serveBytes answers every request with b and an exact Content-Length.
func serveBytes(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
	}
}

// privateDir returns a fresh 0700 directory (the install root).
func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cft")
	mkdirRaw(t, dir, 0o700)
	return dir
}

// mkdirRaw creates path with exactly mode (whatever the umask).
func mkdirRaw(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatalf("setup Mkdir(%q): %v", path, err)
	}
	chmodRaw(t, path, mode)
}

// chmodRaw sets exactly mode on path (hostile fixtures included).
func chmodRaw(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setup Chmod(%q): %v", path, err)
	}
}

// dirEntries lists the names in dir, sorted.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	slices.Sort(names)
	return names
}

// assertEmpty fails unless dir exists and holds nothing at all.
func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Fatalf("%s holds %v, want nothing (no temp, staging or extracted file)", dir, got)
	}
}

// discardLog returns a logger that drops everything.
func discardLog() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newInstaller builds an Installer for m reaching s, failing the test on error.
func newInstaller(t *testing.T, s *server, m cft.Manifest, dir string, log *slog.Logger) *cft.Installer {
	t.Helper()
	if log == nil {
		log = discardLog()
	}
	in, err := cft.New(cft.Options{Manifest: m, Dir: dir, HTTP: s.httpOpts(), Log: log})
	if err != nil {
		t.Fatalf("cft.New: %v", err)
	}
	return in
}

// openFsx opens dir as an fsx.Root closed at test end.
func openFsx(t *testing.T, dir string) *fsx.Root {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
