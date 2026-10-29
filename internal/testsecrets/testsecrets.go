// Package testsecrets provides canary secrets for leak tests and the artifact
// directories that scripts/leakcheck.sh greps after the test suite.
//
// A canary is a synthetic, unique value that impersonates a password, cookie,
// token or session. Tests hand canaries to the code under test and write every
// log, report or database they produce under ArtifactDir. When FACTO_CANARY=1
// (set by the Makefile) every canary is recorded in CanaryFile, and
// `make leakcheck` fails if any recorded canary appears in an artifact.
//
// It is a test helper package: only _test.go files import it.
package testsecrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// Kind names what a canary impersonates. Must match ^[a-z0-9]+$.
type Kind string

// Canary kinds.
const (
	Password Kind = "password"
	Cookie   Kind = "cookie"
	Token    Kind = "token"
	Session  Kind = "session"
)

// Prefix starts every canary value.
const Prefix = "FACTO-CANARY-"

const (
	envEnabled     = "FACTO_CANARY"
	envCanaryFile  = "CANARY_FILE"
	envArtifactDir = "ART_DIR"

	defaultCanaryFile  = ".cache/canaries.txt"
	defaultArtifactDir = ".cache/test-artifacts"

	// maxDirName caps an ArtifactDir component well under NAME_MAX (255).
	maxDirName = 120
)

var kindRe = regexp.MustCompile(`^[a-z0-9]+$`)

// Canary returns a fresh synthetic secret: Prefix + kind + "-" + 26 random
// characters from crypto/rand ([A-Z2-7]). Values are unique per call and safe
// to generate concurrently. When FACTO_CANARY is exactly "1" the value is
// appended, followed by "\n", to CanaryFile() through fsx (file 0600, missing
// parent directories created 0700, an existing parent used as is). An existing
// canary file with group/world permissions is refused. An invalid kind or any
// I/O error fails tb.
func Canary(tb testing.TB, kind Kind) string {
	tb.Helper()
	if !kindRe.MatchString(string(kind)) {
		tb.Fatalf("testsecrets: invalid canary kind %q", kind)
		return ""
	}
	v := Prefix + string(kind) + "-" + rand.Text()
	if os.Getenv(envEnabled) != "1" {
		return v
	}
	if err := record(v); err != nil {
		tb.Fatalf("testsecrets: record canary: %v", err)
		return ""
	}
	return v
}

// record appends one canary line to the canary file. O_APPEND plus a single
// small write keeps concurrent writers (goroutines or test binaries) from
// interleaving.
func record(v string) error {
	file, err := CanaryFile()
	if err != nil {
		return err
	}
	dir, name := filepath.Split(file)
	r, err := openCreating(dir)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }() // read-only handle on a directory
	if err := r.AppendPrivate(name, []byte(v+"\n")); err != nil {
		return fmt.Errorf("append %s: %w", file, err)
	}
	return nil
}

// ArtifactDir returns a directory, created 0700, under ArtifactRoot() (itself
// created 0700 if missing; an existing one is accepted as is). Each test gets
// its own directory derived from tb.Name(), sanitized so that it always stays
// strictly inside ArtifactRoot(). The directory is not removed at the end of
// the test: leakcheck greps it afterwards. Any error fails tb.
func ArtifactDir(tb testing.TB) string {
	tb.Helper()
	root, err := ArtifactRoot()
	if err != nil {
		tb.Fatalf("testsecrets: %v", err)
		return ""
	}
	r, err := openCreating(root)
	if err != nil {
		tb.Fatalf("testsecrets: %v", err)
		return ""
	}
	defer func() { _ = r.Close() }() // read-only handle on a directory
	name := dirName(tb.Name())
	if err := r.MkdirPrivate(name); err != nil {
		tb.Fatalf("testsecrets: artifact dir: %v", err)
		return ""
	}
	return filepath.Join(root, name)
}

// dirName maps a test name to one path component made of [A-Za-z0-9_-]:
// separators, dots and anything else become '_', so neither "/" nor ".."
// survive. Long names are cut and suffixed with a hash of the full name to
// stay distinct.
func dirName(testName string) string {
	var b strings.Builder
	for _, r := range testName {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "_"
	}
	if len(s) > maxDirName {
		sum := sha256.Sum256([]byte(testName))
		s = s[:maxDirName-17] + "-" + hex.EncodeToString(sum[:8])
	}
	return s
}

// CanaryFile resolves $CANARY_FILE; unset or empty means
// <module root>/.cache/canaries.txt; a relative value is resolved against the
// module root (the directory holding go.mod, found by walking up from the
// working directory). The result is absolute and clean.
func CanaryFile() (string, error) {
	return resolve(envCanaryFile, defaultCanaryFile)
}

// ArtifactRoot resolves $ART_DIR the same way as CanaryFile, defaulting to
// <module root>/.cache/test-artifacts.
func ArtifactRoot() (string, error) {
	return resolve(envArtifactDir, defaultArtifactDir)
}

func resolve(env, def string) (string, error) {
	v := os.Getenv(env)
	if v == "" {
		v = filepath.FromSlash(def)
	}
	if filepath.IsAbs(v) {
		return filepath.Clean(v), nil
	}
	root, err := moduleRoot()
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", env, err)
	}
	return filepath.Join(root, v), nil
}

// moduleRoot walks up from the working directory to the directory holding
// go.mod.
func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("module root: %w", err)
	}
	for dir := wd; ; {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("module root: no go.mod above %s", wd)
		}
		dir = parent
	}
}

// openCreating opens dir as an fsx.Root, creating it and its missing parents
// 0700 first. Existing directories are used as they are (the Makefile creates
// .cache with the default umask).
func openCreating(dir string) (*fsx.Root, error) {
	dir = filepath.Clean(dir)
	base := dir
	for {
		fi, err := os.Stat(base)
		if err == nil {
			if !fi.IsDir() {
				return nil, fmt.Errorf("%s is not a directory", base)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", base, err)
		}
		parent := filepath.Dir(base)
		if parent == base {
			return nil, fmt.Errorf("no existing ancestor for %s", dir)
		}
		base = parent
	}
	if base != dir {
		rel, err := filepath.Rel(base, dir)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
		br, err := fsx.Open(base)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
		err = br.MkdirPrivate(filepath.ToSlash(rel))
		_ = br.Close() // read-only handle on a directory
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	r, err := fsx.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	return r, nil
}
