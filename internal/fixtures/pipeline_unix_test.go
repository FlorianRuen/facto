//go:build unix

package fixtures_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
)

func TestSanitizeTree_RefusesSymlinksAndBinaries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "a.json", `{}`)
	if err := os.Symlink(filepath.Join(dir, "a.json"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := fixtures.SanitizeTree(t.Context(), dir, nil); !errors.Is(err, fixtures.ErrSymlink) {
		t.Fatalf("SanitizeTree with a symlink = %v, want ErrSymlink", err)
	}
	if _, err := fixtures.ScanTree(dir); !errors.Is(err, fixtures.ErrSymlink) {
		t.Fatalf("ScanTree with a symlink = %v, want ErrSymlink", err)
	}
	bin := t.TempDir()
	write(t, bin, "x.bin", "\x00\x01\x02")
	if _, err := fixtures.SanitizeTree(t.Context(), bin, nil); !errors.Is(err, fixtures.ErrNotText) {
		t.Fatalf("SanitizeTree with a binary = %v, want ErrNotText", err)
	}
}
