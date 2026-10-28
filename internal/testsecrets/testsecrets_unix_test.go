//go:build unix

// Permission tests for package testsecrets (J0 task T3). See
// testsecrets_test.go for the expected API.
package testsecrets_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestCanary_FilePrivate(t *testing.T) {
	canaryFile, _ := isolate(t, "1")

	testsecrets.Canary(t, testsecrets.Password)
	if got := mode(t, canaryFile); got != 0o600 {
		t.Fatalf("canary file mode = %#o, want 0600", got)
	}
	if got := mode(t, filepath.Dir(canaryFile)); got != 0o700 {
		t.Fatalf("created canary dir mode = %#o, want 0700", got)
	}
}

func TestCanary_RefusesWorldReadableFile(t *testing.T) {
	canaryFile, _ := isolate(t, "1")
	mkdirPrivate(t, filepath.Dir(filepath.Dir(canaryFile)), filepath.Base(filepath.Dir(canaryFile)))
	const previous = "FACTO-CANARY-token-recordedbyanotherpackage\n"
	writePrivate(t, canaryFile, []byte(previous))
	chmodRaw(t, canaryFile, 0o644)

	if !runFake(t, func(tb testing.TB) { testsecrets.Canary(tb, testsecrets.Password) }) {
		t.Fatal("Canary appended to a 0644 canary file without failing the test")
	}
	if got := string(readFileRaw(t, canaryFile)); got != previous {
		t.Fatalf("canary file changed to %q, want untouched", got)
	}
	if got := mode(t, canaryFile); got != 0o644 {
		t.Fatalf("canary file mode silently changed to %#o", got)
	}
}

func TestArtifactDir_Private(t *testing.T) {
	_, artRoot := isolate(t, "0")

	dir := testsecrets.ArtifactDir(t)
	if got := mode(t, dir); got != 0o700 {
		t.Fatalf("ArtifactDir mode = %#o, want 0700", got)
	}
	if got := mode(t, artRoot); got != 0o700 {
		t.Fatalf("created artifact root mode = %#o, want 0700", got)
	}
}

func TestArtifactDir_AcceptsExistingMakefileRoot(t *testing.T) {
	_, artRoot := isolate(t, "0")
	// make race does `mkdir -p "$(ART_DIR)"`: 0755 under the usual umask.
	mkdirRaw(t, filepath.Dir(artRoot), 0o700)
	mkdirRaw(t, artRoot, 0o755)

	dir := testsecrets.ArtifactDir(t)
	if !within(artRoot, dir) {
		t.Fatalf("ArtifactDir = %q, want inside %q", dir, artRoot)
	}
	if got := mode(t, dir); got != 0o700 {
		t.Fatalf("ArtifactDir mode = %#o, want 0700", got)
	}
}

func readFileRaw(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// chmodRaw and mkdirRaw set up deliberately broad modes for negative tests.
func chmodRaw(t *testing.T, path string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatalf("setup Chmod(%s): %v", path, err)
	}
}

func mkdirRaw(t *testing.T, path string, m fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, m); err != nil {
		t.Fatalf("setup Mkdir(%s): %v", path, err)
	}
	chmodRaw(t, path, m) // Mkdir is subject to umask
}
