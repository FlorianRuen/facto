package vault_test

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

var update = flag.Bool("update", false, "rewrite golden files")

func readTestdata(path string) ([]byte, error) {
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

// decodeHexLines decodes a golden file holding lowercase hex, 64 chars per
// line, so that format diffs stay reviewable.
func decodeHexLines(data []byte) ([]byte, error) {
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(data)), ""))
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return b, nil
}

func encodeHexLines(b []byte) []byte {
	s := hex.EncodeToString(b)
	var sb strings.Builder
	for len(s) > 64 {
		sb.WriteString(s[:64])
		sb.WriteByte('\n')
		s = s[64:]
	}
	sb.WriteString(s)
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// writeGolden rewrites testdata/<dir>/<name> through fsx when -update is set.
func writeGolden(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if !*update {
		return
	}
	root, err := fsx.Open(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), name, encodeHexLines(b)); err != nil {
		t.Fatalf("update golden: %v", err)
	}
}

// writeArtifact stores rendered output under testsecrets.ArtifactDir so that
// make leakcheck greps it for canaries.
func writeArtifact(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("open artifact dir: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), name, b); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
}
