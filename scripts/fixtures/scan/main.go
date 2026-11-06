// Command scan checks a fixture tree for personal data or secrets left
// behind (.claude/skills/fixtures-from-har step 3); run it through
// scripts/fixtures/scan.sh <dir>.
//
// It prints one line per finding (file:line: kind, never the value), then
// "PII scan: <n> findings". Kinds: email (outside example domains), phone,
// iban, card (Luhn and issuer range), nir, token (JWT, bearer), secret-field
// (a password, token or session field with a value), canary, address,
// unredacted-har. Any finding blocks the commit: fix the sanitization
// rules, never the scanner.
//
// Exit status: 0 no finding, 1 findings, 2 usage or I/O error.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/FlorianRuen/facto/internal/fixtures"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "" || args[0][0] == '-' {
		_, _ = fmt.Fprintln(stderr, "usage: scan.sh <fixture-dir>")
		return 2
	}
	if !isDir(args[0]) {
		_, _ = fmt.Fprintln(stderr, "scan: not a directory")
		return 2
	}
	findings, err := fixtures.ScanTree(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan: %v\n", err)
		return 2
	}
	for _, f := range findings {
		_, _ = fmt.Fprintln(stdout, f.String())
	}
	_, _ = fmt.Fprintf(stdout, "PII scan: %d findings\n", len(findings))
	if len(findings) > 0 {
		return 1
	}
	return 0
}

// isDir reports whether p is a directory (symlinks not followed).
func isDir(p string) bool {
	r, err := os.OpenRoot(filepath.Dir(p))
	if err != nil {
		return false
	}
	defer func() { _ = r.Close() }()
	fi, err := r.Lstat(filepath.Base(p))
	return err == nil && fi.IsDir()
}
