package testsecrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestCanary_SuiteSelfCheck uses the real CANARY_FILE and ART_DIR (no
// isolation): under `make race` it records a canary and writes a clean
// artifact, so `make leakcheck` always has something to check and proves an
// artifact free of canaries passes.
func TestCanary_SuiteSelfCheck(t *testing.T) {
	v := testsecrets.Canary(t, testsecrets.Token)
	dir := testsecrets.ArtifactDir(t)
	writePrivate(t, filepath.Join(dir, "log.txt"), []byte("level=INFO msg=login token=***\n"))

	if os.Getenv("FACTO_CANARY") != "1" {
		return
	}
	file, err := testsecrets.CanaryFile()
	if err != nil {
		t.Fatalf("CanaryFile: %v", err)
	}
	b, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		t.Fatalf("read canary file: %v", err)
	}
	if !strings.Contains(string(b), v+"\n") {
		t.Fatalf("canary %q not recorded in %s", v, file)
	}
}
