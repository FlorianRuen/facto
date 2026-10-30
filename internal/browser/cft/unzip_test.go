// Unzip tests (J1 task T11, ADR 0008 "Chrome for Testing (A10)"): zip-slip,
// symlink, non-regular, duplicate and zip-bomb entries are refused; nothing
// is ever written outside the install directory. Mode tests live in
// unzip_unix_test.go. See helpers_test.go for the expected API.
package cft_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/fsx"
)

const sentinel = "outside sentinel, untouched"

// unzipEnv is base/ holding dst (base/install, 0700, the extraction root)
// and a sibling base/outside holding one sentinel file.
type unzipEnv struct {
	base, dst, outside string
	root               *fsx.Root
}

func newUnzipEnv(t *testing.T) unzipEnv {
	t.Helper()
	base := t.TempDir()
	e := unzipEnv{base: base, dst: filepath.Join(base, "install"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{e.dst, e.outside} {
		mkdirRaw(t, d, 0o700)
	}
	writeRaw(t, filepath.Join(e.outside, "sentinel"), sentinel)
	e.root = openFsx(t, e.dst)
	return e
}

func (e unzipEnv) unzip(ctx context.Context, archive []byte, lim cft.Limits) error {
	return cft.Unzip(ctx, bytes.NewReader(archive), int64(len(archive)), e.root, lim)
}

// assertOutsideUntouched fails if anything appeared next to dst or in outside.
func (e unzipEnv) assertOutsideUntouched(t *testing.T) {
	t.Helper()
	if got := dirEntries(t, e.base); !slices.Equal(got, []string{"install", "outside"}) {
		t.Fatalf("base holds %v, want [install outside]", got)
	}
	if got := dirEntries(t, e.outside); !slices.Equal(got, []string{"sentinel"}) {
		t.Fatalf("outside holds %v, want [sentinel]", got)
	}
	b, err := os.ReadFile(filepath.Join(e.outside, "sentinel"))
	if err != nil || string(b) != sentinel {
		t.Fatalf("sentinel = %q, %v; want untouched", b, err)
	}
}

// assertNothingWritten fails unless dst is still empty and outside untouched.
func (e unzipEnv) assertNothingWritten(t *testing.T) {
	t.Helper()
	assertEmpty(t, e.dst)
	e.assertOutsideUntouched(t)
}

// okFirst puts a harmless entry before the hostile ones, so a refusal after
// writing it would show: headers are validated before anything is written.
func okFirst(bad ...zent) []zent {
	return append([]zent{{name: "ok.txt", body: []byte("harmless")}}, bad...)
}

func TestUnzip_ZipSlipRefused(t *testing.T) {
	t.Parallel()

	names := []struct{ name, entry string }{
		{"parent", "../evil.txt"},
		{"two parents", "../../evil.txt"},
		{"parent into sibling", "../outside/evil.txt"},
		{"nested escape", "a/../../evil.txt"},
		{"deep nested escape", "a/b/../../../evil.txt"},
		{"dot then parent", "./../evil.txt"},
		{"dot-dot segment staying inside", "a/../b.txt"},
		{"bare dot-dot", ".."},
		{"dot-dot directory", "../"},
		{"absolute", "/evil.txt"},
		{"absolute nested", "/tmp/evil.txt"},
		{"absolute double slash", "//server/share/evil.txt"},
		{"backslash parent", `..\evil.txt`},
		{"backslash nested escape", `a\..\..\evil.txt`},
		{"backslash harmless looking", `a\b.txt`},
		{"drive letter backslash", `C:\evil.txt`},
		{"drive letter slash", "C:/evil.txt"},
		{"drive relative", "c:evil.txt"},
		{"UNC path", `\\server\share\evil.txt`},
		{"NUL byte", "evil\x00.txt"},
		{"empty name", ""},
	}
	for _, tt := range names {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			archive := buildZip(t, okFirst(zent{name: tt.entry, body: []byte("pwned")}))
			err := e.unzip(t.Context(), archive, cft.Limits{})
			if !errors.Is(err, cft.ErrUnsafeEntry) {
				t.Fatalf("Unzip(%q) = %v, want errors.Is ErrUnsafeEntry", tt.entry, err)
			}
			e.assertNothingWritten(t)
		})
	}
}

func TestUnzip_SymlinkEntryRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []zent
	}{
		{name: "symlink to a relative path outside", entries: okFirst(zent{name: "lnk", mode: fs.ModeSymlink | 0o777, body: []byte("../outside/sentinel")})},
		{name: "symlink to an absolute path", entries: okFirst(zent{name: "lnk", mode: fs.ModeSymlink | 0o777, body: []byte("/nonexistent/synthetic/target")})},
		{name: "symlink to a file inside", entries: okFirst(zent{name: "lnk", mode: fs.ModeSymlink | 0o777, body: []byte("ok.txt")})},
		{name: "symlink then a file written through it", entries: okFirst(
			zent{name: "lnk", mode: fs.ModeSymlink | 0o777, body: []byte("../outside")},
			zent{name: "lnk/evil.txt", body: []byte("pwned")},
		)},
		{name: "named pipe", entries: okFirst(zent{name: "fifo", mode: fs.ModeNamedPipe | 0o644})},
		{name: "block device", entries: okFirst(zent{name: "dev", mode: fs.ModeDevice | 0o644})},
		{name: "char device", entries: okFirst(zent{name: "cdev", mode: fs.ModeDevice | fs.ModeCharDevice | 0o644})},
		{name: "socket", entries: okFirst(zent{name: "sock", mode: fs.ModeSocket | 0o644})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			err := e.unzip(t.Context(), buildZip(t, tt.entries), cft.Limits{})
			if !errors.Is(err, cft.ErrUnsafeEntry) {
				t.Fatalf("Unzip = %v, want errors.Is ErrUnsafeEntry", err)
			}
			e.assertNothingWritten(t)
		})
	}
}

// noise returns n deterministic, incompressible bytes.
func noise(n int, seed byte) []byte {
	out := make([]byte, 0, n+sha256.Size)
	block := sha256.Sum256([]byte{seed})
	for len(out) < n {
		out = append(out, block[:]...)
		block = sha256.Sum256(block[:])
	}
	return out[:n]
}

func TestUnzip_SizeAndCountCaps(t *testing.T) {
	t.Parallel()

	small := cft.Limits{MaxTotal: 1000, MaxFile: 600, MaxEntries: 4, MaxRatio: 50}
	roomy := cft.Limits{MaxTotal: 4 << 20, MaxFile: 4 << 20, MaxEntries: 16, MaxRatio: 50}
	tests := []struct {
		name    string
		lim     cft.Limits
		entries []zent
		// wantErr: nil means success; errAny means any error (stdlib may
		// catch a lying header first).
		wantErr error
	}{
		{
			name: "exactly at every cap",
			lim:  small,
			entries: []zent{
				{name: "d/", mode: fs.ModeDir | 0o755},
				{name: "d/a.bin", body: noise(600, 1)},
				{name: "d/b.bin", body: noise(400, 2)},
				{name: "d/empty", body: nil},
			},
		},
		{
			name: "total uncompressed over cap",
			lim:  small,
			entries: []zent{
				{name: "a.bin", body: noise(400, 1)},
				{name: "b.bin", body: noise(400, 2)},
				{name: "c.bin", body: noise(201, 3)},
			},
			wantErr: cft.ErrArchiveTooLarge,
		},
		{
			name:    "one file over per-file cap",
			lim:     small,
			entries: []zent{{name: "big.bin", body: noise(601, 1)}},
			wantErr: cft.ErrArchiveTooLarge,
		},
		{
			name: "too many entries",
			lim:  small,
			entries: []zent{
				{name: "1", body: []byte("1")},
				{name: "2", body: []byte("2")},
				{name: "3", body: []byte("3")},
				{name: "4", body: []byte("4")},
				{name: "5", body: []byte("5")},
			},
			wantErr: cft.ErrArchiveTooLarge,
		},
		{
			name: "directories count as entries",
			lim:  small,
			entries: []zent{
				{name: "d1/", mode: fs.ModeDir | 0o755},
				{name: "d2/", mode: fs.ModeDir | 0o755},
				{name: "d3/", mode: fs.ModeDir | 0o755},
				{name: "d4/", mode: fs.ModeDir | 0o755},
				{name: "d5/", mode: fs.ModeDir | 0o755},
			},
			wantErr: cft.ErrArchiveTooLarge,
		},
		{
			name:    "compression ratio over cap",
			lim:     roomy,
			entries: []zent{{name: "zeros.bin", body: make([]byte, 1<<20)}},
			wantErr: cft.ErrArchiveTooLarge,
		},
		{
			name:    "header understates size of incompressible data",
			lim:     cft.Limits{MaxTotal: 4096, MaxFile: 4096, MaxEntries: 4, MaxRatio: 50},
			entries: []zent{{name: "liar.bin", body: noise(64<<10, 9), declared: 100}},
			wantErr: errAny,
		},
		{
			name:    "header understates size of a zip bomb",
			lim:     cft.Limits{MaxTotal: 4096, MaxFile: 4096, MaxEntries: 4, MaxRatio: 50},
			entries: []zent{{name: "bomb.bin", body: make([]byte, 8<<20), declared: 100}},
			wantErr: errAny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			err := e.unzip(t.Context(), buildZip(t, tt.entries), tt.lim)
			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("Unzip = %v, want nil", err)
				}
			case errors.Is(tt.wantErr, errAny):
				if err == nil {
					t.Fatal("Unzip = nil, want an error")
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Unzip = %v, want errors.Is %v", err, tt.wantErr)
				}
				e.assertNothingWritten(t)
			}
			if got := treeBytes(t, e.dst); got > tt.lim.MaxTotal {
				t.Fatalf("extracted %d bytes, over MaxTotal %d", got, tt.lim.MaxTotal)
			}
			e.assertOutsideUntouched(t)
		})
	}

	t.Run("default limits are all set", func(t *testing.T) {
		t.Parallel()
		d := cft.DefaultLimits()
		if d.MaxTotal <= 0 || d.MaxFile <= 0 || d.MaxEntries <= 0 || d.MaxRatio <= 0 {
			t.Fatalf("DefaultLimits() = %+v, want every cap > 0", d)
		}
		if d.MaxFile > d.MaxTotal {
			t.Fatalf("DefaultLimits() = %+v, want MaxFile <= MaxTotal", d)
		}
	})
}

// errAny is a marker for "any non-nil error".
var errAny = errors.New("any error")

// treeBytes sums the sizes of the regular files under dir.
func treeBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			total += fi.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return total
}

func TestUnzip_DuplicateEntriesRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []zent
	}{
		{name: "same name twice", entries: []zent{{name: "a.txt", body: []byte("first")}, {name: "a.txt", body: []byte("second")}}},
		{name: "same name after cleaning a double slash", entries: []zent{{name: "d/a.txt", body: []byte("1")}, {name: "d//a.txt", body: []byte("2")}}},
		{name: "same name after cleaning a dot segment", entries: []zent{{name: "a.txt", body: []byte("1")}, {name: "./a.txt", body: []byte("2")}}},
		{name: "names differing only in case", entries: []zent{{name: "A.txt", body: []byte("1")}, {name: "a.txt", body: []byte("2")}}},
		{name: "file then directory of the same path", entries: []zent{{name: "a", body: []byte("1")}, {name: "a/b.txt", body: []byte("2")}}},
		{name: "directory then file of the same path", entries: []zent{{name: "a/b.txt", body: []byte("1")}, {name: "a", body: []byte("2")}}},
		{name: "directory entry then file entry", entries: []zent{{name: "d/", mode: fs.ModeDir | 0o755}, {name: "d", body: []byte("2")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			err := e.unzip(t.Context(), buildZip(t, tt.entries), cft.Limits{})
			if !errors.Is(err, cft.ErrUnsafeEntry) {
				t.Fatalf("Unzip = %v, want errors.Is ErrUnsafeEntry", err)
			}
			e.assertNothingWritten(t)
		})
	}
}

func TestUnzip_OnlyUnderInstallDir(t *testing.T) {
	t.Parallel()

	e := newUnzipEnv(t)
	entries := chromeEntries()
	if err := e.unzip(t.Context(), buildZip(t, entries), cft.Limits{}); err != nil {
		t.Fatalf("Unzip: %v", err)
	}
	e.assertOutsideUntouched(t)

	var got []string
	err := filepath.WalkDir(e.dst, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(e.dst, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Errorf("%s is outside the install dir", p)
		}
		if d.IsDir() {
			rel += "/"
		}
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	want := []string{
		"chrome-linux64/",
		"chrome-linux64/chrome",
		"chrome-linux64/chrome_sandbox",
		"chrome-linux64/locales/",
		"chrome-linux64/locales/en-US.pak",
		"chrome-linux64/resources.pak",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("extracted tree = %v, want %v", got, want)
	}
	for _, ent := range entries {
		if strings.HasSuffix(ent.name, "/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.dst, filepath.FromSlash(ent.name)))
		if err != nil {
			t.Fatalf("read %s: %v", ent.name, err)
		}
		if !bytes.Equal(b, ent.body) {
			t.Fatalf("%s content differs from the archive", ent.name)
		}
	}
}

func TestUnzip_CanceledContextWritesNothing(t *testing.T) {
	t.Parallel()

	e := newUnzipEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.unzip(ctx, chromeZip(t), cft.Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Unzip = %v, want errors.Is context.Canceled", err)
	}
	e.assertNothingWritten(t)
}

func TestUnzip_NotAZipRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "random bytes", data: noise(4096, 7)},
		{name: "truncated zip", data: chromeZip(t)[:200]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newUnzipEnv(t)
			if err := e.unzip(t.Context(), tt.data, cft.Limits{}); err == nil {
				t.Fatal("Unzip = nil, want an error")
			}
			e.assertNothingWritten(t)
		})
	}
}
