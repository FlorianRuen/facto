//go:build unix

// Red-team attacks on the Chrome for Testing installer (J1 task T27):
// zip-slip through lookalike and encoded names, symlink and special
// entries, checksum and size games, redirects off the pinned host in
// every URL form, and a forged "verified" install planted through
// symlinks. A test passes when the attack is defeated. Everything is
// synthetic (helpers_test.go builds the archives and the TLS server).
package cft_test

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// assertInside fails unless every path under e.base is e.outside's
// untouched sentinel or lies under e.dst (no symlink anywhere in dst).
func assertInside(t *testing.T, e unzipEnv) {
	t.Helper()
	e.assertOutsideUntouched(t)
	err := filepath.WalkDir(e.dst, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("extraction created a symlink %s", p)
		}
		if d.Type()&(fs.ModeNamedPipe|fs.ModeDevice|fs.ModeSocket|fs.ModeSetuid|fs.ModeSetgid) != 0 {
			t.Errorf("extraction created a special entry %s (%v)", p, d.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dst: %v", err)
	}
}

// TestAttack_CFTZipSlipLookalikeAndEncodedNames: names that look like a
// parent reference to some layer (Unicode dots, percent encoding, doubled
// separators, trailing dots, overlong names) are either refused with
// ErrUnsafeEntry before anything is written, or written strictly inside
// the install directory as plain names.
func TestAttack_CFTZipSlipLookalikeAndEncodedNames(t *testing.T) {
	t.Parallel()
	names := []string{
		"\u2025/evil.txt",               // two dot leader
		"\uff0e\uff0e/evil.txt",         // fullwidth full stops
		"%2e%2e/evil.txt",               // percent-encoded dot-dot
		"%2e%2e%2fevil.txt",             // percent-encoded slash
		"..%2fevil.txt",                 // half-encoded
		"a//../../evil.txt",             // doubled separator then escape
		"a/.../evil.txt",                // three dots
		"a/..\u200b/evil.txt",           // zero-width after dot-dot
		"a/../\x2e./evil.txt",           // hex-escaped dot-dot
		"./a/./../../evil.txt",          // dot segments then escape
		"a/b/c/../../../../evil.txt",    // deep escape
		strings.Repeat("a/", 600) + "x", // deep nesting
		strings.Repeat("n", 4096),       // overlong name
		"chrome-linux64/chrome/..",      // escape the executable
		"a\x7f/../../evil.txt",          // DEL in a segment
	}
	for i, n := range names {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			archive := buildZip(t, okFirst(zent{name: n, body: []byte("pwned")}))
			err := e.unzip(t.Context(), archive, cft.Limits{})
			if err != nil && !errors.Is(err, cft.ErrUnsafeEntry) {
				// A name the filesystem refuses (too long) is fine as long
				// as nothing escaped.
				t.Logf("Unzip(%.40q) refused by the filesystem (%d-byte error)", n, len(err.Error()))
			}
			if errors.Is(err, cft.ErrUnsafeEntry) {
				e.assertNothingWritten(t)
				return
			}
			assertInside(t, e)
		})
	}
}

// TestAttack_CFTSpecialEntryModesRefused: entries whose mode combines a
// type bit with the directory bit, a setuid symlink, a device, a socket or
// an irregular file are refused before anything is written, or come out as
// a plain directory or file; setuid, setgid and sticky bits never reach
// the disk.
func TestAttack_CFTSpecialEntryModesRefused(t *testing.T) {
	t.Parallel()
	refused := []zent{
		{name: "lnkdir/", mode: fs.ModeDir | fs.ModeSymlink | 0o777},
		{name: "lnk", mode: fs.ModeSymlink | fs.ModeSetuid | 0o777, body: []byte("/")},
		{name: "dev", mode: fs.ModeDevice | fs.ModeCharDevice | 0o666},
		{name: "sock", mode: fs.ModeSocket | 0o666},
		{name: "irr", mode: fs.ModeIrregular | 0o644, body: []byte("x")},
	}
	for i, z := range refused {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			err := e.unzip(t.Context(), buildZip(t, okFirst(z)), cft.Limits{})
			if err == nil {
				// archive/zip cannot encode some combinations (a symlink
				// directory, an irregular file): they come out as a plain
				// directory or file, which is harmless if nothing special
				// reached the disk.
				assertInside(t, e)
				return
			}
			if !errors.Is(err, cft.ErrUnsafeEntry) {
				t.Fatalf("Unzip(%s %v) = %v, want ErrUnsafeEntry", z.name, z.mode, err)
			}
			e.assertNothingWritten(t)
		})
	}
	t.Run("setuid and setgid stripped", func(t *testing.T) {
		t.Parallel()
		e := newUnzipEnv(t)
		archive := buildZip(t, []zent{
			{name: "d/", mode: fs.ModeDir | fs.ModeSetgid | fs.ModeSticky | 0o2777},
			{name: "d/suid", mode: fs.ModeSetuid | fs.ModeSetgid | 0o6755, body: []byte("#!/bin/sh\n")},
		})
		if err := e.unzip(t.Context(), archive, cft.Limits{}); err != nil {
			t.Fatalf("Unzip: %v", err)
		}
		for _, p := range []string{"d", "d/suid"} {
			fi, err := os.Lstat(filepath.Join(e.dst, p))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s mode %v, want no setuid/setgid/sticky and owner-only", p, fi.Mode())
			}
		}
		assertInside(t, e)
	})
}

// TestAttack_CFTChecksumAndSizeGames: a server that pads, truncates,
// chunks or swaps the archive never gets anything extracted.
func TestAttack_CFTChecksumAndSizeGames(t *testing.T) {
	t.Parallel()
	archive := chromeZip(t)
	evil := buildZip(t, []zent{{name: "chrome-linux64/chrome", mode: 0o755, body: []byte("#!/bin/sh\n# evil\n")}})
	for _, tt := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{name: "archive then trailing bytes, no length", h: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(append(bytes.Clone(archive), []byte("trailing")...))
		}},
		{name: "true length header, longer body", h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(archive)+8))
			_, _ = w.Write(append(bytes.Clone(archive), []byte("trailing")...))
		}},
		{name: "truncated by one byte", h: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(archive[:len(archive)-1])
		}},
		{name: "another archive, chunked", h: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(evil)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}},
		{name: "same size, other content, gzip claimed", h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(tamper(archive))
		}},
		{name: "error status with the archive as body", h: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(archive)
		}},
		{name: "partial content", h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Range", "bytes 0-9/"+strconv.Itoa(len(archive)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(archive[:10])
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, tt.h)
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)
			exe, err := in.Install(t.Context())
			if err == nil {
				t.Fatalf("Install() = %q, nil; want refused", exe)
			}
			assertEmpty(t, dir)
		})
	}
}

// TestAttack_CFTRedirectURLFormsOffHostRefused: redirects naming another
// host through userinfo, encodings, case, trailing dots, backslashes or a
// scheme-relative form are refused before any request leaves for them.
func TestAttack_CFTRedirectURLFormsOffHostRefused(t *testing.T) {
	t.Parallel()
	archive := chromeZip(t)
	locs := []string{
		"https://" + testHost + "@" + evilHost + testPath,
		"https://" + evilHost + "%2f@" + testHost + testPath,
		"https://" + evilHost + "#@" + testHost + testPath,
		"https://" + testHost + "." + testPath,
		"https://" + strings.ToUpper(testHost) + testPath,
		"https://" + testHost + ":443@" + evilHost + testPath,
		"https://" + testHost + "%2e" + testPath,
		"//" + evilHost + testPath,
		"https:///" + evilHost + testPath,
		"https:" + evilHost + testPath,
		testPrefix + "%2e%2e/other/chrome-linux64.zip",
		testPrefix + "..%2fother/chrome-linux64.zip",
		testPrefix + "x\\..\\..\\other/chrome-linux64.zip",
		testPrefix + "x/%252e%252e/chrome-linux64.zip",
		"/" + strings.TrimPrefix(testPrefix, "/") + "./x.zip",
		"https://" + testHost + testPath + "?redirect=https://" + evilHost + "/",
		"file:///etc/passwd",
		"http://" + testHost + testPath,
		"https://[::1]" + testPath,
		"https://127.0.0.1" + testPath,
	}
	for i, loc := range locs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			var redirected atomic.Bool
			s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Host == testHost && r.URL.Path == testPath && redirected.CompareAndSwap(false, true) {
					w.Header().Set("Location", loc)
					w.WriteHeader(http.StatusFound)
					return
				}
				serveBytes(archive)(w, r)
			})
			dir := privateDir(t)
			in := newInstaller(t, s, manifestFor(archive), dir, nil)
			_, err := in.Install(t.Context())
			reqs := s.requests()
			for _, h := range reqs[1:] {
				if h.host != testHost {
					t.Errorf("redirect %q: request sent to host %q", loc, h.host)
				}
				if !strings.HasPrefix(h.path, testPrefix) || strings.Contains(h.path, "..") {
					t.Errorf("redirect %q: request sent for path %q outside the pinned prefix", loc, h.path)
				}
			}
			if err != nil {
				if !errors.Is(err, cft.ErrRedirectRefused) && !errors.Is(err, httpx.ErrDomainNotAllowed) &&
					!errors.Is(err, httpx.ErrInsecureScheme) && !errors.Is(err, cft.ErrSizeMismatch) {
					t.Logf("redirect %q refused with %v", loc, err)
				}
				assertEmpty(t, dir)
			}
		})
	}
}

// TestAttack_CFTForgedVerifiedInstallThroughSymlinks: a "verified" install
// assembled from symlinks (the version directory, the platform directory,
// the executable or the marker pointing at a forged tree that holds the
// right hash, which is public) is never reported verified, so the pool is
// never handed its executable.
func TestAttack_CFTForgedVerifiedInstallThroughSymlinks(t *testing.T) {
	t.Parallel()
	archive := chromeZip(t)
	m := manifestFor(archive)
	plat := "chrome-" + m.Platform
	forge := func(t *testing.T, dir string) string {
		t.Helper()
		f := filepath.Join(dir, "forged")
		mkdirRaw(t, f, 0o700)
		mkdirRaw(t, filepath.Join(f, plat), 0o700)
		writeRaw(t, filepath.Join(f, plat, "chrome"), "#!/bin/sh\n# forged\n")
		writeRaw(t, filepath.Join(f, cft.MarkerName), m.SHA256+"\n")
		return f
	}
	for _, tt := range []struct {
		name  string
		plant func(t *testing.T, dir, forged string)
	}{
		{name: "version dir is a symlink", plant: func(t *testing.T, dir, forged string) {
			if err := os.Symlink(forged, filepath.Join(dir, m.Version)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "platform dir is a symlink", plant: func(t *testing.T, dir, forged string) {
			mkdirRaw(t, filepath.Join(dir, m.Version), 0o700)
			writeRaw(t, filepath.Join(dir, m.Version, cft.MarkerName), m.SHA256)
			if err := os.Symlink(filepath.Join(forged, plat), filepath.Join(dir, m.Version, plat)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "executable is a symlink", plant: func(t *testing.T, dir, forged string) {
			mkdirRaw(t, filepath.Join(dir, m.Version), 0o700)
			mkdirRaw(t, filepath.Join(dir, m.Version, plat), 0o700)
			writeRaw(t, filepath.Join(dir, m.Version, cft.MarkerName), m.SHA256)
			if err := os.Symlink(filepath.Join(forged, plat, "chrome"), filepath.Join(dir, m.Version, plat, "chrome")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "marker is a symlink", plant: func(t *testing.T, dir, forged string) {
			mkdirRaw(t, filepath.Join(dir, m.Version), 0o700)
			mkdirRaw(t, filepath.Join(dir, m.Version, plat), 0o700)
			writeRaw(t, filepath.Join(dir, m.Version, plat, "chrome"), "#!/bin/sh\n")
			if err := os.Symlink(filepath.Join(forged, cft.MarkerName), filepath.Join(dir, m.Version, cft.MarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "marker is a FIFO", plant: func(t *testing.T, dir, _ string) {
			mkdirRaw(t, filepath.Join(dir, m.Version), 0o700)
			mkdirRaw(t, filepath.Join(dir, m.Version, plat), 0o700)
			writeRaw(t, filepath.Join(dir, m.Version, plat, "chrome"), "#!/bin/sh\n")
			if err := mkfifo(filepath.Join(dir, m.Version, cft.MarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := privateDir(t)
			forged := forge(t, dir)
			tt.plant(t, dir, forged)
			if cft.Verified(openFsx(t, dir), m) {
				t.Fatalf("%s: Verified() = true for a forged tree", tt.name)
			}
		})
	}
}

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o600) //nolint:wrapcheck // test fixture
}
