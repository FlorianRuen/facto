//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

var update = flag.Bool("update", false, "rewrite test/e2e/testdata fixtures")

// facturXSource is the synthetic MINIMUM-profile CII invoice of the facturx
// golden tests ("Fournisseur Exemple SAS", FA-2026-0001, 2026-03-14, 84.12 EUR),
// relative to the module root.
var facturXSource = filepath.Join("internal", "normalize", "facturx", "testdata",
	"TestParseCII_ProfilesGolden", "minimum.xml")

// fixture is one synthetic PDF of test/e2e/testdata. Every byte is
// generated here: no real party, account, address or amount.
type fixture struct {
	name     string
	label    string // written in a PDF comment so that every fixture hashes differently
	facturX  bool   // embed facturXSource as factur-x.xml
	wantDoc  *facturx.Invoice
	wantNone bool // facturx.Extract must report ErrNoFacturX
}

func fixtures() []fixture {
	total := int64(8412)
	return []fixture{
		{name: "edf-invoice.pdf", label: "synthetic edf invoice", wantNone: true},
		{name: "impots-notice.pdf", label: "synthetic property tax notice", wantNone: true},
		{name: "unknown-scan.pdf", label: "synthetic unidentifiable scan", wantNone: true},
		{name: "facturx-invoice.pdf", label: "synthetic factur-x invoice", facturX: true, wantDoc: &facturx.Invoice{
			Number:          "FA-2026-0001",
			IssueDate:       time.Date(2026, time.March, 14, 0, 0, 0, 0, time.UTC),
			SellerName:      "Fournisseur Exemple SAS",
			Currency:        "EUR",
			GrandTotalCents: &total,
		}},
	}
}

// TestFixtures_SyntheticPDFs keeps test/e2e/testdata in sync with the
// generator (-update rewrites it) and proves the Factur-X fixture yields the
// fields the inbox scenario expects, and the others carry no Factur-X.
func TestFixtures_SyntheticPDFs(t *testing.T) {
	mod, err := moduleRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	xml, err := readIn(mod, facturXSource)
	if err != nil {
		t.Fatalf("read factur-x source: %v", err)
	}
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			var att []byte
			if f.facturX {
				att = xml
			}
			want := buildPDF(f.label, att)
			if *update {
				writeTestdata(t, f.name, want)
			}
			got, err := readIn("testdata", f.name)
			if err != nil {
				t.Fatalf("read fixture (run with -update to create it): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("testdata/%s differs from the generator; run go test -tags e2e ./test/e2e -run TestFixtures -update and review", f.name)
			}

			inv, err := facturx.Extract(t.Context(), bytes.NewReader(got))
			switch {
			case f.wantNone:
				if !errors.Is(err, facturx.ErrNoFacturX) {
					t.Fatalf("Extract err = %v, want ErrNoFacturX", err)
				}
			case err != nil:
				t.Fatalf("Extract: %v", err)
			default:
				w := f.wantDoc
				if inv.Number != w.Number || !inv.IssueDate.Equal(w.IssueDate) || inv.SellerName != w.SellerName ||
					inv.Currency != w.Currency || inv.GrandTotalCents == nil || *inv.GrandTotalCents != *w.GrandTotalCents {
					t.Fatalf("Extract = %+v, want number %q date %s seller %q total %d %s",
						inv, w.Number, w.IssueDate.Format(time.DateOnly), w.SellerName, *w.GrandTotalCents, w.Currency)
				}
			}
		})
	}
}

func writeTestdata(t *testing.T, name string, data []byte) {
	t.Helper()
	root, err := fsx.Open("testdata")
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatalf("write testdata/%s: %v", name, err)
	}
}

// buildPDF writes a minimal valid one-page PDF 1.7 by hand (correct xref
// offsets). With att, it embeds att as factur-x.xml in the EmbeddedFiles
// name tree and /AF, as Factur-X does.
func buildPDF(label string, att []byte) []byte {
	var objs []string
	add := func(body string) int {
		objs = append(objs, body)
		return len(objs)
	}
	catalog := add("")
	pages := add("")
	page := add(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] >>", pages))
	objs[pages-1] = fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)
	cat := fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R", pages)
	if att != nil {
		stream := add(fmt.Sprintf("<< /Type /EmbeddedFile /Subtype /text#2Fxml /Length %d >>\nstream\n%s\nendstream", len(att), att))
		spec := add(fmt.Sprintf("<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /Desc (Factur-X) "+
			"/AFRelationship /Data /EF << /F %d 0 R /UF %d 0 R >> >>", stream, stream))
		cat += fmt.Sprintf(" /Names << /EmbeddedFiles << /Names [(factur-x.xml) %d 0 R] >> >> /AF [%d 0 R]", spec, spec)
	}
	objs[catalog-1] = cat + " >>"

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n% facto e2e fixture: " + strings.ReplaceAll(label, "\n", " ") + "\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, catalog, xref)
	return b.Bytes()
}
