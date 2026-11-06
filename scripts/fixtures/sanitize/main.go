// Command sanitize replaces personal data in a fixture tree with synthetic,
// format-preserving values (.claude/skills/fixtures-from-har step 2); run
// it through scripts/fixtures/sanitize.sh <dir>.
//
// Every text file under <dir> is rewritten in place (atomic, 0600):
// emails, phone numbers, IBANs, card numbers, NIR, street addresses,
// postcodes and cities, names (JSON name fields, after a civility or a
// greeting, then everywhere they appear), long reference numbers, the
// cents of amounts and dates (one offset for the whole tree, so order and
// intervals hold). The same value maps to the same synthetic value in
// every file. The key is FACTO_SANITIZE_KEY (default: a fixed key, so a
// re-run gives the same output). PDFs are listed, never edited: replace
// them with go run ./scripts/fakepdf. Any other binary file, or a
// symbolic link, stops the run before anything is written.
//
// Exit status: 0 done, 2 usage or I/O error.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/FlorianRuen/facto/internal/fixtures"
)

// defaultKey keeps sanitize deterministic across runs and machines.
const defaultKey = "facto-fixtures-v1"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv("FACTO_SANITIZE_KEY"), os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, key string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "" || args[0][0] == '-' {
		_, _ = fmt.Fprintln(stderr, "usage: sanitize.sh <fixture-dir>")
		return 2
	}
	if key == "" {
		key = defaultKey
	}
	res, err := fixtures.SanitizeTree(ctx, args[0], []byte(key))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sanitize: %v\n", err)
		return 2
	}
	for _, f := range res.Rewritten {
		_, _ = fmt.Fprintf(stdout, "sanitized %s\n", f)
	}
	for _, f := range res.Skipped {
		_, _ = fmt.Fprintf(stdout, "skipped %s (PDF: replace it with go run ./scripts/fakepdf)\n", f)
	}
	_, _ = fmt.Fprintf(stdout, "sanitize: %d rewritten, %d unchanged, %d PDF skipped; next: scripts/fixtures/scan.sh %s\n",
		len(res.Rewritten), len(res.Unchanged), len(res.Skipped), args[0])
	return 0
}
