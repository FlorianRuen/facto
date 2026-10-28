// Command scanners-json turns the per-scanner exit statuses recorded by
// `make audit` into security/scanners.json, the "scanners" part of
// security/score.schema.json: {"<name>": "pass" | "fail"}.
//
// `make audit` runs every scanner even when one fails and writes its exit
// status to <status-dir>/<name>.status. A scanner passes only if that file is
// a regular file (not a symlink) of at most 64 bytes whose content, trimmed
// of ASCII whitespace, is exactly "0". Anything else fails, including a
// missing file. The output is written atomically, 0600, through fsx.
//
// Exit status: 0 every scanner passed, 1 at least one failed (the file is
// still written), 2 usage or I/O error (nothing written).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// defaultScanners is the expected list when -scanners is not given.
var defaultScanners = []string{"govulncheck", "gosec", "gitleaks", "osv-scanner"}

// scannerName keeps names usable as plain file names: no separator, no dot.
var scannerName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

const (
	maxStatusSize = 64
	statusSuffix  = ".status"
	pass          = "pass"
	fail          = "fail"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// run is main without os.Exit.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scanners-json", flag.ContinueOnError)
	fl.SetOutput(stderr)
	statusDir := fl.String("status-dir", ".cache/audit", "directory holding <scanner>.status files")
	out := fl.String("out", "security/scanners.json", "JSON file to write (its directory must exist)")
	list := fl.String("scanners", strings.Join(defaultScanners, ","), "comma-separated expected scanners")
	if err := fl.Parse(args); err != nil {
		return 2 // flag already printed the error and usage
	}
	if fl.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "scanners-json: unexpected arguments %q\n", fl.Args())
		return 2
	}
	names, err := parseList(*list)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scanners-json: %v\n", err)
		return 2
	}

	results := make(map[string]string, len(names))
	failed := false
	for _, n := range names {
		results[n] = fail
		if passed(*statusDir, n) {
			results[n] = pass
		} else {
			failed = true
		}
	}

	if err := write(ctx, *out, results); err != nil {
		_, _ = fmt.Fprintf(stderr, "scanners-json: %v\n", err)
		return 2
	}
	slices.Sort(names)
	for _, n := range names {
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", n, results[n])
	}
	if failed {
		return 1
	}
	return 0
}

// parseList splits a comma-separated scanner list and validates every name.
func parseList(s string) ([]string, error) {
	if s == "" {
		return nil, errors.New("empty scanner list")
	}
	names := strings.Split(s, ",")
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !scannerName.MatchString(n) {
			return nil, fmt.Errorf("invalid scanner name %q", n)
		}
		if seen[n] {
			return nil, fmt.Errorf("duplicate scanner %q", n)
		}
		seen[n] = true
	}
	return names, nil
}

// passed reports whether dir/<name>.status records a zero exit status. Any
// error (missing dir or file, symlink, not regular, too big) is a failure.
func passed(dir, name string) bool {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }() // read only
	file := name + statusSuffix
	lfi, err := root.Lstat(file)
	if err != nil || !lfi.Mode().IsRegular() {
		return false
	}
	f, err := root.Open(file)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read only
	// The file opened must be the one checked, not a swapped-in symlink.
	if fi, err := f.Stat(); err != nil || !os.SameFile(lfi, fi) {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStatusSize+1))
	if err != nil || len(b) > maxStatusSize {
		return false
	}
	return strings.Trim(string(b), " \t\r\n\v\f") == "0"
}

// write stores results as indented JSON at out, atomically and 0600.
func write(ctx context.Context, out string, results map[string]string) error {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	b = append(b, '\n')
	r, err := fsx.Open(filepath.Dir(out))
	if err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	defer func() { _ = r.Close() }() // directory handle, nothing to flush
	if err := r.WriteAtomic(ctx, filepath.Base(out), b); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}
