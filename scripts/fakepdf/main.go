// Command fakepdf writes a synthetic PDF for a fixture tree
// (.claude/skills/fixtures-from-har step 4):
//
//	go run ./scripts/fakepdf -o testdata/<id>/005-get-invoice-pdf.pdf \
//	    [--like real.pdf] [--line "Facture FA-2026-0001"]... [--facturx invoice.xml]
//
// --like copies the layout class of a real PDF (page count and first page
// size) and nothing else: no text, image, font or metadata is read into
// the output. --line adds a text line (default: a generic synthetic
// invoice). --facturx embeds a synthetic CII XML as factur-x.xml. The
// output is deterministic and written atomically, 0600.
//
// Exit status: 0 written, 2 usage or I/O error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/fsx"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

type lines []string

func (l *lines) String() string     { return strings.Join(*l, "|") }
func (l *lines) Set(v string) error { *l = append(*l, v); return nil }

// defaultLines is the generic synthetic invoice text.
var defaultLines = []string{
	"Fournisseur Exemple SAS",
	"1 rue de l'Exemple, 00000 VILLE-EXEMPLE",
	"Facture FA-0000-0001",
	"Client : NomA NomB",
	"Total TTC : 00,00 EUR",
	"Document synthetique (scripts/fakepdf)",
}

// maxXML caps --facturx.
const maxXML = 1 << 20

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fakepdf", flag.ContinueOnError)
	fl.SetOutput(stderr)
	out := fl.String("o", "", "PDF to write (its directory must exist)")
	like := fl.String("like", "", "real PDF whose page count and page size are copied (nothing else)")
	xml := fl.String("facturx", "", "synthetic CII XML embedded as factur-x.xml")
	var ls lines
	fl.Var(&ls, "line", "text line (repeatable)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fl.NArg() != 0 || !strings.EqualFold(filepath.Ext(*out), ".pdf") {
		_, _ = fmt.Fprintln(stderr, "usage: fakepdf -o <out.pdf> [--like real.pdf] [--line text]... [--facturx file.xml]")
		return 2
	}
	spec := fixtures.PDFSpec{Lines: ls}
	if len(spec.Lines) == 0 {
		spec.Lines = defaultLines
	}
	if *like != "" {
		l, err := readLayout(ctx, *like)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "fakepdf: --like: %v\n", err)
			return 2
		}
		spec.Pages, spec.Width, spec.Height = l.Pages, l.Width, l.Height
	}
	if *xml != "" {
		b, err := readSmall(*xml, maxXML)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "fakepdf: --facturx: %v\n", err)
			return 2
		}
		spec.FacturX = b
	}
	pdf := fixtures.BuildPDF(spec)
	root, err := fsx.Open(filepath.Dir(*out))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "fakepdf: %v\n", err)
		return 2
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(ctx, filepath.Base(*out), pdf); err != nil {
		_, _ = fmt.Fprintf(stderr, "fakepdf: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "fakepdf: wrote %s (%d pages, %gx%g pt, %d bytes)\n", *out, max(spec.Pages, 1), orA4(spec.Width, 595), orA4(spec.Height, 842), len(pdf))
	return 0
}

func orA4(v, d float64) float64 {
	if v <= 0 {
		return d
	}
	return v
}

func readLayout(ctx context.Context, p string) (fixtures.Layout, error) {
	b, err := readSmall(p, fixtures.MaxLayoutPDF)
	if err != nil {
		return fixtures.Layout{}, err
	}
	l, err := fixtures.ReadLayout(ctx, strings.NewReader(string(b)))
	if err != nil {
		return fixtures.Layout{}, fmt.Errorf("read layout: %w", err)
	}
	return l, nil
}

// readSmall reads a regular file (never a symlink) of at most n bytes.
func readSmall(p string, n int64) ([]byte, error) {
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
		return nil, errors.New("not a regular file")
	}
	f, err := r.Open(filepath.Base(p))
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, n+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("larger than %d bytes", n)
	}
	return b, nil
}
