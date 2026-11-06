// Command harslim turns a redacted recording (`facto record`) into minimal
// fixture files (.claude/skills/fixtures-from-har step 1):
//
//	go run ./scripts/harslim <recording.har> -o testdata/<id>/ [--host h]... [--pdfs n]
//
// It keeps the documents, XHR/fetch calls and PDFs of the supplier hosts
// (default: the host of the first page) and writes one file per response
// body plus flow.json describing the sequence, every file 0600. The PDF is
// a synthetic placeholder: replace it with go run ./scripts/fakepdf. A HAR
// that still holds a cookie, password or token is refused (exit 1): only
// files written by `facto record` are accepted.
//
// Exit status: 0 written, 1 refused input, 2 usage or I/O error.
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
	"strings"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/har"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

type hostList []string

func (h *hostList) String() string { return strings.Join(*h, ",") }
func (h *hostList) Set(v string) error {
	*h = append(*h, strings.ToLower(strings.TrimSpace(v)))
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("harslim", flag.ContinueOnError)
	fl.SetOutput(stderr)
	out := fl.String("o", "", "output directory (created 0700 if missing; its parent must exist)")
	pdfs := fl.Int("pdfs", 1, "PDF responses to keep")
	var hosts hostList
	fl.Var(&hosts, "host", "supplier host to keep (repeatable; default: the first page's host)")
	// The HAR path may come before the flags (as in the skill).
	var in string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		in, args = args[0], args[1:]
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if in == "" && fl.NArg() == 1 {
		in = fl.Arg(0)
	} else if fl.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "harslim: want exactly one HAR file")
		return 2
	}
	if in == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "usage: harslim <recording.har> -o <dir> [--host h]... [--pdfs n]")
		return 2
	}
	f, err := readHAR(in)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 2
	}
	slim, err := fixtures.Slim(f, fixtures.SlimOptions{Hosts: hosts, PDFs: *pdfs})
	if errors.Is(err, fixtures.ErrUnredacted) {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 2
	}
	flow, err := json.MarshalIndent(slim.Flow, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 2
	}
	if err := ensureDir(*out); err != nil {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 2
	}
	if err := fixtures.WriteSlimmed(ctx, *out, slim, append(flow, '\n')); err != nil {
		_, _ = fmt.Fprintf(stderr, "harslim: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "harslim: %d steps, %d body files in %s (flow.json)\n", len(slim.Flow.Steps), len(slim.Files), *out)
	_, _ = fmt.Fprintln(stdout, "harslim: next: scripts/fixtures/sanitize.sh "+*out)
	return 0
}

func readHAR(p string) (*har.File, error) {
	r, err := os.OpenRoot(filepath.Dir(p))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = r.Close() }()
	fi, err := r.Lstat(filepath.Base(p))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	fh, err := r.Open(filepath.Base(p))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = fh.Close() }()
	f, err := har.Decode(fh)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return f, nil
}

// ensureDir creates dir (0700) when missing; its parent must exist.
func ensureDir(dir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case err == nil && fi.IsDir():
		return nil
	case err == nil:
		return errors.New("output is not a directory")
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("output: %w", err)
	}
	if err := fixtures.MkdirPrivate(dir); err != nil {
		return fmt.Errorf("output: %w", err)
	}
	return nil
}
