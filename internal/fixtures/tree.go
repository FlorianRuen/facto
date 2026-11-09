package fixtures

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
)

// MaxFixtureFile caps one file read by ScanTree and SanitizeTree.
const MaxFixtureFile = 16 << 20

// ErrSymlink reports a symbolic link in a fixture tree: never followed.
var ErrSymlink = errors.New("fixtures: symbolic link in the fixture tree")

// textExts are the files sanitized and scanned as text. Anything else is
// scanned only for the canary prefix and refused by sanitize unless it is
// a PDF (replaced by scripts/fakepdf, never edited).
var textExts = []string{".html", ".htm", ".json", ".xml", ".txt", ".js", ".csv", ".har", ".md", ".yaml", ".yml", ".golden", ".eml"}

// walk lists the regular files under dir (slash paths, sorted). A symlink
// anywhere is an error.
func walk(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlink, p)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		if rel == ManifestName {
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("fixtures: walk: %w", err)
	}
	slices.Sort(files)
	return files, nil
}

// readIn reads rel under dir through an os.Root (no escape), at most
// MaxFixtureFile bytes.
func readIn(dir, rel string) ([]byte, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("fixtures: open %s: %w", dir, err)
	}
	defer func() { _ = r.Close() }()
	f, err := r.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, fmt.Errorf("fixtures: open %s: %w", rel, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxFixtureFile+1))
	if err != nil {
		return nil, fmt.Errorf("fixtures: read %s: %w", rel, err)
	}
	if len(b) > MaxFixtureFile {
		return nil, fmt.Errorf("fixtures: %s: larger than %d bytes", rel, MaxFixtureFile)
	}
	return b, nil
}

func isText(rel string, data []byte) bool {
	ext := strings.ToLower(path.Ext(rel))
	return (slices.Contains(textExts, ext) || ext == "") && utf8.Valid(data)
}

// ScanTree scans every file under dir: text files with ScanText, any other
// file for the canary prefix and secrets in its printable runs, and *.har
// files with har.Check too.
func ScanTree(dir string) ([]Finding, error) {
	files, err := walk(dir)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, rel := range files {
		data, err := readIn(dir, rel)
		if err != nil {
			return nil, err
		}
		if isText(rel, data) {
			out = append(out, ScanText(rel, string(data))...)
		} else {
			out = append(out, scanBinary(rel, data)...)
		}
		if strings.EqualFold(path.Ext(rel), ".har") {
			if f, err := har.Decode(strings.NewReader(string(data))); err == nil {
				for range har.Check(f) {
					out = append(out, Finding{File: rel, Line: 0, Kind: "unredacted-har"})
				}
			}
		}
	}
	return out, nil
}

// scanBinary scans the printable runs of a binary file (PDF text, metadata).
func scanBinary(rel string, data []byte) []Finding {
	var out []Finding
	var run []byte
	flush := func() {
		if len(run) >= 6 {
			for _, k := range scanLine(string(run)) {
				out = append(out, Finding{File: rel, Kind: k})
			}
		}
		run = run[:0]
	}
	for _, c := range data {
		if c >= 0x20 && c < 0x7f {
			run = append(run, c)
			continue
		}
		flush()
	}
	flush()
	return out
}

// SanitizeResult reports what SanitizeTree did.
type SanitizeResult struct {
	Rewritten []string // text files changed
	Unchanged []string // text files already clean
	Skipped   []string // PDFs (left to scripts/fakepdf)
}

// ErrNotText reports a file SanitizeTree cannot handle (binary, not PDF).
var ErrNotText = errors.New("fixtures: not a text file (only text and PDF files belong in a fixture tree)")

// SanitizeTree rewrites every text file under dir with one Sanitizer:
// first every file is learned (names found in one file are replaced in
// all), then each file is rewritten atomically (0600) through fsx. PDFs
// are listed in Skipped. Any other binary file is an error before
// anything is written.
func SanitizeTree(ctx context.Context, dir string, key []byte) (SanitizeResult, error) {
	var res SanitizeResult
	files, err := walk(dir)
	if err != nil {
		return res, err
	}
	texts := map[string]string{}
	for _, rel := range files {
		data, err := readIn(dir, rel)
		if err != nil {
			return res, err
		}
		switch {
		case isText(rel, data):
			texts[rel] = string(data)
		case strings.EqualFold(path.Ext(rel), ".pdf"):
			res.Skipped = append(res.Skipped, rel)
		default:
			return res, fmt.Errorf("%w: %s", ErrNotText, rel)
		}
	}
	done, err := readManifest(dir)
	if err != nil {
		return res, err
	}
	s := NewSanitizer(key)
	for _, rel := range files {
		if t, ok := texts[rel]; ok {
			s.Learn(t)
		}
	}
	root, err := fsx.Open(dir)
	if err != nil {
		return res, fmt.Errorf("fixtures: %w", err)
	}
	defer func() { _ = root.Close() }()
	for _, rel := range files {
		t, ok := texts[rel]
		if !ok {
			continue
		}
		if done[rel] == hashOf(t) {
			res.Unchanged = append(res.Unchanged, rel)
			continue
		}
		out := s.Text(t)
		if out == t {
			res.Unchanged = append(res.Unchanged, rel)
			continue
		}
		if err := root.WriteAtomic(ctx, rel, []byte(out)); err != nil {
			return res, fmt.Errorf("fixtures: write %s: %w", rel, err)
		}
		res.Rewritten = append(res.Rewritten, rel)
	}
	if err := writeManifest(ctx, root, dir, files, texts); err != nil {
		return res, err
	}
	return res, nil
}

// WriteSlimmed writes flow.json and the body files of s into dir (which
// must exist), each 0600 through fsx. Existing files are replaced.
func WriteSlimmed(ctx context.Context, dir string, s *Slimmed, flowJSON []byte) error {
	root, err := fsx.Open(dir)
	if err != nil {
		return fmt.Errorf("fixtures: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(ctx, "flow.json", flowJSON); err != nil {
		return fmt.Errorf("fixtures: write flow.json: %w", err)
	}
	names := make([]string, 0, len(s.Files))
	for n := range s.Files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if n != fsx.SafeName(n) {
			return fmt.Errorf("fixtures: unsafe body name %q", n)
		}
		if err := root.WriteAtomic(ctx, n, s.Files[n]); err != nil {
			return fmt.Errorf("fixtures: write %s: %w", n, err)
		}
	}
	return nil
}

// MkdirPrivate creates dir (0700) through fsx; its parent must exist.
func MkdirPrivate(dir string) error {
	root, err := fsx.Open(filepath.Dir(dir))
	if err != nil {
		return fmt.Errorf("fixtures: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(filepath.Base(dir)); err != nil {
		return fmt.Errorf("fixtures: %w", err)
	}
	return nil
}

// ManifestName is the file sanitize.sh writes next to the fixtures: one
// "<sha256>  <file>" line per sanitized text file. A file whose content
// still has that hash is not sanitized again: keyed replacements are not
// recognisable by a new process, and a rerun would shift dates and
// amounts once more.
const ManifestName = ".sanitized"

func hashOf(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// readManifest returns file -> hash; a missing manifest is empty.
func readManifest(dir string) (map[string]string, error) {
	out := map[string]string{}
	data, err := readIn(dir, ManifestName)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		h, name, ok := strings.Cut(line, "  ")
		if ok && len(h) == 64 {
			out[name] = h
		}
	}
	return out, nil
}

// writeManifest records the hash of every text file as it is now on disk.
func writeManifest(ctx context.Context, root *fsx.Root, dir string, files []string, texts map[string]string) error {
	var b strings.Builder
	for _, rel := range files {
		if _, ok := texts[rel]; !ok {
			continue
		}
		data, err := readIn(dir, rel)
		if err != nil {
			return err
		}
		b.WriteString(hashOf(string(data)) + "  " + rel + "\n")
	}
	if err := root.WriteAtomic(ctx, ManifestName, []byte(b.String())); err != nil {
		return fmt.Errorf("fixtures: write %s: %w", ManifestName, err)
	}
	return nil
}
