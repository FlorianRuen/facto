// Install tests (J1 task T11, ADR 0008 "Chrome for Testing (A10)"): download
// through httpx, size before hash, hash before extraction, redirects pinned,
// idempotent, nothing left behind on failure, no URL query in logs. See
// helpers_test.go for the expected API.
package cft_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// wantExe is the executable path Install returns for the test manifest.
func wantExe(dir string) string {
	return filepath.Join(dir, testVersion, "chrome-linux64", "chrome")
}

func TestInstall_ExtractsVerifiedArchive(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	s := newServer(t, serveBytes(archive))
	dir := privateDir(t)
	in := newInstaller(t, s, manifestFor(archive), dir, nil)

	exe, err := in.Install(t.Context())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if exe != wantExe(dir) {
		t.Fatalf("Install() = %q, want %q", exe, wantExe(dir))
	}
	fi, err := os.Lstat(exe)
	if err != nil {
		t.Fatalf("Lstat(executable): %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("executable mode = %v, want a regular 0700 file", fi.Mode())
	}
	marker, err := os.ReadFile(filepath.Clean(filepath.Join(dir, testVersion, cft.MarkerName)))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if got := strings.TrimSpace(string(marker)); got != sha256Hex(archive) {
		t.Fatalf("marker = %q, want the manifest SHA-256", got)
	}
	if got := dirEntries(t, dir); len(got) != 1 || got[0] != testVersion {
		t.Fatalf("install root holds %v, want only [%s] (no temp left)", got, testVersion)
	}
	reqs := s.requests()
	if len(reqs) != 1 || reqs[0].host != testHost || reqs[0].path != testPath {
		t.Fatalf("requests = %+v, want exactly one GET of the pinned URL", reqs)
	}
}

func TestInstall_ChecksumMismatchExtractsNothing(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	tests := []struct {
		name   string
		serve  []byte
		mutate func(m *cft.Manifest)
	}{
		{
			name:  "served archive tampered, same size",
			serve: tamper(archive),
		},
		{
			name:   "manifest hash differs by one hex digit",
			serve:  archive,
			mutate: func(m *cft.Manifest) { m.SHA256 = flipHex(m.SHA256) },
		},
		{
			name:  "another valid zip of the same size",
			serve: sameSizeOtherZip(t, archive),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, serveBytes(tt.serve))
			m := manifestFor(archive)
			if tt.mutate != nil {
				tt.mutate(&m)
			}
			dir := privateDir(t)
			in := newInstaller(t, s, m, dir, nil)

			exe, err := in.Install(t.Context())
			if !errors.Is(err, cft.ErrChecksumMismatch) {
				t.Fatalf("Install() = %q, %v; want errors.Is ErrChecksumMismatch", exe, err)
			}
			if exe != "" {
				t.Fatalf("Install() path = %q on error, want empty", exe)
			}
			assertEmpty(t, dir)
		})
	}
}

// tamper flips one byte in the middle of b (a copy).
func tamper(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)/2] ^= 0xff
	return c
}

// flipHex changes the first hex digit of h, keeping it valid lowercase hex.
func flipHex(h string) string {
	if h[0] == '0' {
		return "1" + h[1:]
	}
	return "0" + h[1:]
}

// sameSizeOtherZip returns a valid zip, different from archive, padded with
// a zip comment to exactly len(archive) bytes.
func sameSizeOtherZip(t *testing.T, archive []byte) []byte {
	t.Helper()
	other := buildZip(t, []zent{{name: "chrome-linux64/chrome", mode: 0o755, body: []byte("#!/bin/sh\n# other\n")}})
	if len(other) >= len(archive) {
		t.Fatalf("setup: other zip (%d) not smaller than archive (%d)", len(other), len(archive))
	}
	pad := len(archive) - len(other)
	if pad <= 0 || pad > math.MaxUint16 {
		t.Fatalf("setup: padding %d does not fit a zip comment", pad)
		return nil
	}
	// End of central directory: the comment length is the last 2 bytes of
	// a comment-less zip; append the comment and patch the length.
	out := bytes.Clone(other)
	binary.LittleEndian.PutUint16(out[len(out)-2:], uint16(pad))
	out = append(out, bytes.Repeat([]byte("p"), pad)...)
	return out
}

func TestInstall_SizeMismatchRefusedBeforeHash(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	size := len(archive)
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "declared Content-Length larger than pinned size",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				body := append(bytes.Clone(archive), bytes.Repeat([]byte{0}, 4096)...)
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				_, _ = w.Write(body)
			},
		},
		{
			name: "declared Content-Length smaller than pinned size",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				body := archive[:size-1]
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				_, _ = w.Write(body)
			},
		},
		{
			name:    "streamed (no Content-Length) one byte more",
			handler: chunked(append(bytes.Clone(archive), 'x')),
		},
		{
			name:    "streamed (no Content-Length) one byte less",
			handler: chunked(archive[:size-1]),
		},
		{
			name:    "streamed (no Content-Length) far more than pinned",
			handler: chunked(append(bytes.Clone(archive), bytes.Repeat([]byte{0}, 8<<20)...)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, tt.handler)
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)

			_, err := in.Install(t.Context())
			if !errors.Is(err, cft.ErrSizeMismatch) {
				t.Fatalf("Install() = %v, want errors.Is ErrSizeMismatch", err)
			}
			// Every body here also hashes wrong: reporting a checksum
			// mismatch would mean the hash ran before the size check.
			if errors.Is(err, cft.ErrChecksumMismatch) {
				t.Fatalf("Install() = %v, also ErrChecksumMismatch: size must be refused before hashing", err)
			}
			assertEmpty(t, dir)
		})
	}
}

// chunked answers with body, without Content-Length (flushed in two parts so
// the server uses chunked encoding).
func chunked(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		half := len(body) / 2
		_, _ = w.Write(body[:half])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write(body[half:])
	}
}

func TestInstall_RedirectOffHostRefused(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	const mirror = testPrefix + "mirror/" + testVersion + "/linux64/chrome-linux64.zip"
	tests := []struct {
		name     string
		location string
		// sent is the path of the redirect target: it must never reach the
		// server when the redirect is refused.
		sentHost, sentPath string
		wantOK             bool
	}{
		{name: "another host", location: "https://" + evilHost + testPath, sentHost: evilHost, sentPath: testPath},
		{name: "another port on the pinned host", location: "https://" + testHost + ":8443" + testPath, sentHost: testHost + ":8443", sentPath: testPath},
		{name: "downgrade to http", location: "http://" + testHost + mirror, sentHost: testHost, sentPath: mirror},
		{name: "pinned host outside the path prefix", location: "https://" + testHost + "/other-bucket/chrome-linux64.zip", sentHost: testHost, sentPath: "/other-bucket/chrome-linux64.zip"},
		{name: "relative redirect outside the path prefix", location: "/other-bucket/chrome-linux64.zip", sentHost: testHost, sentPath: "/other-bucket/chrome-linux64.zip"},
		{name: "dot-dot out of the path prefix", location: testPrefix + "../other-bucket/chrome-linux64.zip", sentHost: testHost, sentPath: "/other-bucket/chrome-linux64.zip"},
		{name: "subdomain of the pinned host", location: "https://x." + testHost + testPath, sentHost: "x." + testHost, sentPath: testPath},
		{name: "same host and prefix is followed", location: mirror, sentHost: testHost, sentPath: mirror, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == testHost && r.URL.Path == testPath {
					http.Redirect(w, r, tt.location, http.StatusFound)
					return
				}
				serveBytes(archive)(w, r)
			})
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)

			exe, err := in.Install(t.Context())
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Install: %v", err)
				}
				if exe != wantExe(dir) {
					t.Fatalf("Install() = %q, want %q", exe, wantExe(dir))
				}
				return
			}
			if !errors.Is(err, cft.ErrRedirectRefused) &&
				!errors.Is(err, httpx.ErrDomainNotAllowed) &&
				!errors.Is(err, httpx.ErrInsecureScheme) {
				t.Fatalf("Install() = %v, want a refused redirect (ErrRedirectRefused, httpx.ErrDomainNotAllowed or httpx.ErrInsecureScheme)", err)
			}
			for _, h := range s.requests() {
				if h.host == tt.sentHost && h.path == tt.sentPath {
					t.Fatalf("redirect target %s%s was requested, want the hop refused before sending", h.host, h.path)
				}
				if h.host != testHost {
					t.Fatalf("server got a request for host %q, want only %q", h.host, testHost)
				}
			}
			assertEmpty(t, dir)
		})
	}
}

func TestInstall_Idempotent(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)

	t.Run("verified install does no network I/O", func(t *testing.T) {
		t.Parallel()
		s := newServer(t, serveBytes(archive))
		dir := privateDir(t)
		in := newInstaller(t, s, manifestFor(archive), dir, nil)
		first, err := in.Install(t.Context())
		if err != nil {
			t.Fatalf("first Install: %v", err)
		}
		// A fresh installer (a later run of facto) must also skip.
		again := newInstaller(t, s, manifestFor(archive), dir, nil)
		second, err := again.Install(t.Context())
		if err != nil {
			t.Fatalf("second Install: %v", err)
		}
		if second != first {
			t.Fatalf("second Install() = %q, want %q", second, first)
		}
		if got := len(s.requests()); got != 1 {
			t.Fatalf("server got %d requests, want 1 (the second install must not download)", got)
		}
	})

	// A marker that does not prove a complete verified install of this
	// exact archive triggers a fresh, verified download.
	tests := []struct {
		name    string
		corrupt func(t *testing.T, dir string)
	}{
		{
			name: "marker holds another hash",
			corrupt: func(t *testing.T, dir string) {
				writeRaw(t, filepath.Join(dir, testVersion, cft.MarkerName), strings.Repeat("0", 64))
			},
		},
		{
			name: "marker missing (interrupted earlier extraction)",
			corrupt: func(t *testing.T, dir string) {
				removeRaw(t, filepath.Join(dir, testVersion, cft.MarkerName))
			},
		},
		{
			name: "executable missing",
			corrupt: func(t *testing.T, dir string) {
				removeRaw(t, wantExe(dir))
			},
		},
		{
			name: "marker is a symlink to a file holding the hash",
			corrupt: func(t *testing.T, dir string) {
				marker := filepath.Join(dir, testVersion, cft.MarkerName)
				outside := filepath.Join(filepath.Dir(dir), "planted-marker")
				writeRaw(t, outside, sha256Hex(archive))
				removeRaw(t, marker)
				if err := os.Symlink(outside, marker); err != nil {
					t.Fatalf("setup Symlink: %v", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, serveBytes(archive))
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)
			if _, err := in.Install(t.Context()); err != nil {
				t.Fatalf("first Install: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, testVersion, cft.MarkerName)); err != nil {
				t.Fatalf("first Install wrote no marker: %v", err)
			}
			tt.corrupt(t, dir)

			exe, err := in.Install(t.Context())
			if err != nil {
				t.Fatalf("second Install: %v", err)
			}
			if got := len(s.requests()); got != 2 {
				t.Fatalf("server got %d requests, want 2 (an unverified install must be downloaded again)", got)
			}
			if exe != wantExe(dir) {
				t.Fatalf("Install() = %q, want %q", exe, wantExe(dir))
			}
			fi, err := os.Lstat(filepath.Join(dir, testVersion, cft.MarkerName))
			if err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("marker after reinstall: %v, %v; want a regular file", fi, err)
			}
		})
	}
}

// writeRaw writes content to path (0600) through fsx.
func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	r := openFsx(t, filepath.Dir(path))
	if err := r.WriteAtomic(t.Context(), filepath.Base(path), []byte(content)); err != nil {
		t.Fatalf("setup WriteAtomic(%q): %v", path, err)
	}
}

func removeRaw(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("setup Remove: %v", err)
	}
}

func TestInstall_InterruptedLeavesNothing(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)

	t.Run("connection cut mid-body", func(t *testing.T) {
		t.Parallel()
		s := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
			_, _ = w.Write(archive[:len(archive)/2])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler) // closes the connection mid-body
		})
		dir := privateDir(t)
		in := newInstaller(t, s, manifestFor(archive), dir, nil)
		if _, err := in.Install(t.Context()); err == nil {
			t.Fatal("Install() = nil, want an error for a cut download")
		}
		assertEmpty(t, dir)
	})

	t.Run("context canceled mid-body", func(t *testing.T) {
		t.Parallel()
		started := make(chan struct{})
		var once sync.Once
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
			_, _ = w.Write(archive[:len(archive)/2])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			once.Do(func() { close(started) })
			<-r.Context().Done() // hold the rest until the client gives up
		})
		dir := privateDir(t)
		in := newInstaller(t, s, manifestFor(archive), dir, nil)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := in.Install(ctx)
			errc <- err
		}()
		select {
		case <-started:
		case err := <-errc:
			t.Fatalf("Install() = %v before the download started, want it to start downloading", err)
		}
		cancel()
		if err := <-errc; !errors.Is(err, context.Canceled) {
			t.Fatalf("Install() = %v, want errors.Is context.Canceled", err)
		}
		assertEmpty(t, dir)
	})

	t.Run("failed reinstall keeps the root free of leftovers", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		served := 0
		s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			served++
			n := served
			mu.Unlock()
			if n == 1 {
				serveBytes(archive)(w, r)
				return
			}
			serveBytes(tamper(archive))(w, r)
		})
		dir := privateDir(t)
		in := newInstaller(t, s, manifestFor(archive), dir, nil)
		if _, err := in.Install(t.Context()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, testVersion, cft.MarkerName)); err != nil {
			t.Fatalf("first Install wrote no marker: %v", err)
		}
		removeRaw(t, filepath.Join(dir, testVersion, cft.MarkerName))
		if _, err := in.Install(t.Context()); !errors.Is(err, cft.ErrChecksumMismatch) {
			t.Fatalf("second Install() = %v, want errors.Is ErrChecksumMismatch", err)
		}
		for _, name := range dirEntries(t, dir) {
			if name != testVersion {
				t.Fatalf("install root holds %q after a failed reinstall, want no temp or staging entry", name)
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, testVersion, cft.MarkerName)); err == nil {
			t.Fatal("marker present after a failed reinstall: an unverified tree must never be marked verified")
		}
	})
}

func TestInstall_ProgressNeverLogsURLQuery(t *testing.T) {
	t.Parallel()

	archive := chromeZip(t)
	signature := testsecrets.Canary(t, testsecrets.Token)
	signed := testPrefix + "signed/" + testVersion + "/linux64/chrome-linux64.zip"
	query := "X-Goog-Signature=" + signature + "&X-Goog-Credential=" + signature
	location := signed + "?" + query + "#frag-" + signature

	tests := []struct {
		name  string
		serve []byte
		ok    bool
	}{
		{name: "successful download via a signed redirect", serve: archive, ok: true},
		{name: "failed download via a signed redirect", serve: tamper(archive)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == testPath {
					http.Redirect(w, r, location, http.StatusFound)
					return
				}
				serveBytes(tt.serve)(w, r)
			})
			var buf syncBuffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, log)

			_, err := in.Install(t.Context())
			if tt.ok && err != nil {
				t.Fatalf("Install: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("Install() = nil, want an error")
			}
			// The redirect really carried the signed query.
			signedHit := false
			for _, h := range s.requests() {
				if h.path == signed && strings.Contains(h.rawQuery, signature) {
					signedHit = true
				}
			}
			if !signedHit {
				t.Fatal("the signed redirect target was not requested: Install must follow a same-prefix redirect")
			}

			logs := buf.String()
			writeArtifact(t, "install.log", logs)
			if logs == "" {
				t.Fatal("no log record: Install must log its progress")
			}
			for _, bad := range []string{signature, "X-Goog-Signature", "X-Goog-Credential", "frag-"} {
				if strings.Contains(logs, bad) {
					t.Fatalf("logs contain %q (URL query or fragment):\n%s", bad, logs)
				}
				if err != nil && strings.Contains(err.Error(), bad) {
					t.Fatalf("error contains %q (URL query or fragment): %v", bad, err)
				}
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writes (progress may be
// logged from another goroutine).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ io.Writer = (*syncBuffer)(nil)

// writeArtifact stores content under the test's artifact dir for make
// leakcheck.
func writeArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}
