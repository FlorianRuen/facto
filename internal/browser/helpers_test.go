package browser_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// exeMode is the mode of a private executable fixture.
var exeMode = fs.FileMode(0o700)

// writeTestFile writes dir/name (0600) through fsx and returns its path.
func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open(%s): %v", dir, err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return filepath.Join(dir, name)
}

// setMode sets an exact mode (the umask never decides the mode under test).
func setMode(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// checkGolden compares got with path, rewriting it through fsx when -update
// is set.
func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		dir := filepath.Dir(path)
		r, err := fsx.Open(".")
		if err != nil {
			t.Fatalf("update golden: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.MkdirPrivate(filepath.ToSlash(dir)); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		if err := r.WriteAtomic(t.Context(), filepath.ToSlash(path), got); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test -update and review)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s mismatch (run go test -update and review the diff)\n--- got\n%s--- want\n%s", path, got, want)
	}
}
