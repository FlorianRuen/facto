package cft

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// Limits caps an extraction. DefaultLimits is used for every zero field.
type Limits struct {
	MaxTotal   int64 // total uncompressed bytes
	MaxFile    int64 // uncompressed bytes of one entry
	MaxEntries int   // number of entries, directories included
	MaxRatio   int64 // uncompressed/compressed of one entry
}

// DefaultLimits are sized for chrome-linux64.zip with a wide margin (about
// 170 MB compressed, 450 MB extracted, a few hundred entries, no file over
// 400 MB, ratios well under 100) while keeping a zip bomb from filling the
// disk.
func DefaultLimits() Limits {
	return Limits{
		MaxTotal:   2 << 30,
		MaxFile:    1 << 30,
		MaxEntries: 10000,
		MaxRatio:   200,
	}
}

// withDefaults replaces every non-positive field with its default.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxTotal <= 0 {
		l.MaxTotal = d.MaxTotal
	}
	if l.MaxFile <= 0 {
		l.MaxFile = d.MaxFile
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = d.MaxRatio
	}
	return l
}

// entry is one validated zip entry.
type entry struct {
	f    *zip.File
	name string // cleaned, slash-separated, relative
	dir  bool
	size int64 // declared uncompressed size (0 for a directory)
	exec bool
}

// Unzip extracts the zip (ra, size) into dst through fsx. It validates
// every header first (names, types, duplicates, entry count, declared
// sizes, ratio) and writes nothing when any is refused. Names are
// slash-separated and relative; an entry whose name is empty, absolute,
// holds a ".." segment, a backslash, a colon (drive letter, alternate data
// stream), a NUL, or that is a symlink, device, FIFO, socket or irregular
// file wraps ErrUnsafeEntry. Two entries naming the same path after
// cleaning, case-insensitively, or a path used both as a file and as a
// directory, wrap ErrUnsafeEntry. Exceeding a cap wraps ErrArchiveTooLarge;
// the caps are also enforced while streaming, so lying headers cannot
// bypass them. Modes are sanitized: an entry with any execute bit is
// written 0700 (through fsx.WriteAtomicExec), any other file 0600, every
// directory (explicit or implied) 0700; setuid, setgid and sticky bits are
// never set. Nothing is ever written outside dst (fsx.Root confinement): a
// pre-existing symlink inside dst is never followed.
//
// An error while streaming (corrupt data, a lying header, a canceled ctx)
// may leave the entries already written in dst: callers extract into a
// staging directory they discard on error.
func Unzip(ctx context.Context, ra io.ReaderAt, size int64, dst *fsx.Root, lim Limits) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cft unzip: %w", err)
	}
	lim = lim.withDefaults()
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		if errors.Is(err, zip.ErrInsecurePath) {
			return fmt.Errorf("cft unzip: %w: %w", ErrUnsafeEntry, err)
		}
		return fmt.Errorf("cft unzip: open archive: %w", err)
	}
	plan, err := planEntries(zr.File, lim)
	if err != nil {
		return fmt.Errorf("cft unzip: %w", err)
	}
	rem := &budget{left: lim.MaxTotal}
	for _, e := range plan {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("cft unzip: %w", err)
		}
		if err := extract(ctx, dst, e, rem); err != nil {
			return fmt.Errorf("cft unzip %q: %w", e.name, err)
		}
	}
	return nil
}

// planEntries validates every header and returns the entries to extract,
// in archive order. Nothing is written.
func planEntries(files []*zip.File, lim Limits) ([]entry, error) {
	if len(files) > lim.MaxEntries {
		return nil, fmt.Errorf("%w: %d entries, cap %d", ErrArchiveTooLarge, len(files), lim.MaxEntries)
	}
	kinds := map[string]kind{} // lowercased cleaned path -> kind
	plan := make([]entry, 0, len(files))
	var total int64
	for _, f := range files {
		e, err := checkEntry(f, lim)
		if err != nil {
			return nil, err
		}
		if err := claim(kinds, e); err != nil {
			return nil, err
		}
		if total += e.size; total > lim.MaxTotal {
			return nil, fmt.Errorf("%w: more than %d bytes uncompressed", ErrArchiveTooLarge, lim.MaxTotal)
		}
		plan = append(plan, e)
	}
	return plan, nil
}

// kind is what a path is used as in the archive.
type kind int

const (
	kindImpliedDir kind = iota + 1
	kindDir
	kindFile
)

// claim records e's path and its parents in kinds, refusing a path named
// twice (case-insensitively) or used both as a file and as a directory.
func claim(kinds map[string]kind, e entry) error {
	key := strings.ToLower(e.name)
	prev, seen := kinds[key]
	switch {
	case seen && (prev != kindImpliedDir || !e.dir):
		return fmt.Errorf("%w: %q named twice or as both file and directory", ErrUnsafeEntry, e.name)
	case e.dir:
		kinds[key] = kindDir
	default:
		kinds[key] = kindFile
	}
	for p := path.Dir(key); p != "."; p = path.Dir(p) {
		if kinds[p] == kindFile {
			return fmt.Errorf("%w: %q is under a file entry", ErrUnsafeEntry, e.name)
		}
		if _, ok := kinds[p]; !ok {
			kinds[p] = kindImpliedDir
		}
	}
	return nil
}

// checkEntry validates one header: name, type, declared size and ratio.
func checkEntry(f *zip.File, lim Limits) (entry, error) {
	name, err := cleanEntryName(f.Name)
	if err != nil {
		return entry{}, err
	}
	mode := f.Mode()
	typ := mode.Type()
	if typ != 0 && typ != fs.ModeDir {
		return entry{}, fmt.Errorf("%w: %q has type %v", ErrUnsafeEntry, name, typ)
	}
	isDir := typ == fs.ModeDir || strings.HasSuffix(f.Name, "/")
	e := entry{f: f, name: name, dir: isDir, exec: mode.Perm()&0o111 != 0}
	if isDir {
		return e, nil
	}
	declared := toInt64(f.UncompressedSize64)
	if declared > lim.MaxFile {
		return entry{}, fmt.Errorf("%w: %q declares more than %d bytes", ErrArchiveTooLarge, name, lim.MaxFile)
	}
	e.size = declared
	if declared > 0 {
		comp := toInt64(f.CompressedSize64)
		if comp == 0 || declared/comp > lim.MaxRatio {
			return entry{}, fmt.Errorf("%w: %q compression ratio over %d", ErrArchiveTooLarge, name, lim.MaxRatio)
		}
	}
	return e, nil
}

// toInt64 converts a zip header size, saturating at math.MaxInt64 (which
// every cap refuses).
func toInt64(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// cleanEntryName validates a zip entry name and returns it cleaned.
func cleanEntryName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\\:") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: name %q", ErrUnsafeEntry, name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: name %q has a .. segment", ErrUnsafeEntry, name)
		}
	}
	clean := path.Clean(name)
	if clean == "." || !fs.ValidPath(clean) {
		return "", fmt.Errorf("%w: name %q", ErrUnsafeEntry, name)
	}
	return clean, nil
}

// budget is the total number of uncompressed bytes still allowed.
type budget struct{ left int64 }

// extract writes one validated entry.
func extract(ctx context.Context, dst *fsx.Root, e entry, b *budget) error {
	if e.dir {
		if err := dst.MkdirPrivate(e.name); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		return nil
	}
	if parent := path.Dir(e.name); parent != "." {
		if err := dst.MkdirPrivate(parent); err != nil {
			return fmt.Errorf("create parent: %w", err)
		}
	}
	rc, err := e.f.Open()
	if err != nil {
		return fmt.Errorf("open entry: %w", err)
	}
	defer func() { _ = rc.Close() }() // read-only; the extraction error is the one reported
	src := &capReader{r: rc, left: min(e.size, b.left), b: b}
	write := dst.WriteAtomicFrom
	if e.exec {
		write = dst.WriteAtomicExec
	}
	if err := write(ctx, e.name, src); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// capReader yields at most left bytes of r and fails with
// ErrArchiveTooLarge on the first byte beyond: a header understating the
// size, or a total over the budget, is caught while streaming.
type capReader struct {
	r    io.Reader
	left int64
	b    *budget
}

func (c *capReader) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	if int64(n) > c.left {
		return 0, fmt.Errorf("%w: entry larger than declared or over the total cap", ErrArchiveTooLarge)
	}
	c.left -= int64(n)
	c.b.left -= int64(n)
	switch {
	case errors.Is(err, io.EOF):
		return n, io.EOF
	case err != nil:
		return n, fmt.Errorf("read entry: %w", err)
	}
	return n, nil
}
