package fixtures_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

func TestBuildPDF_ValidAndReadableLayout(t *testing.T) {
	t.Parallel()
	b := fixtures.BuildPDF(fixtures.PDFSpec{
		Pages: 2, Width: 612, Height: 792,
		Lines: []string{"Facture FA-2026-0001", "Total 84,12 EUR", "parens ( ) and \\ backslash"},
	})
	if !bytes.HasPrefix(b, []byte("%PDF-1.7")) || !bytes.HasSuffix(bytes.TrimSpace(b), []byte("%%EOF")) {
		t.Fatalf("not a PDF:\n%s", b)
	}
	l, err := fixtures.ReadLayout(t.Context(), bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadLayout of our own PDF: %v", err)
	}
	if l.Pages != 2 || l.Width != 612 || l.Height != 792 {
		t.Fatalf("layout = %+v, want 2 pages 612x792", l)
	}
}

func TestBuildPDF_Deterministic(t *testing.T) {
	t.Parallel()
	spec := fixtures.PDFSpec{Lines: []string{"a"}}
	if !bytes.Equal(fixtures.BuildPDF(spec), fixtures.BuildPDF(spec)) {
		t.Fatal("BuildPDF is not deterministic")
	}
}

func TestBuildPDF_FacturXAttachmentExtracts(t *testing.T) {
	t.Parallel()
	xml, err := os.ReadFile(filepath.Join("..", "normalize", "facturx", "testdata", "TestParseCII_ProfilesGolden", "minimum.xml"))
	if err != nil {
		t.Fatal(err)
	}
	b := fixtures.BuildPDF(fixtures.PDFSpec{Lines: []string{"x"}, FacturX: xml})
	inv, err := facturx.Extract(t.Context(), bytes.NewReader(b))
	if err != nil || inv.Number != "FA-2026-0001" {
		t.Fatalf("Extract = %+v, %v", inv, err)
	}
	plain := fixtures.BuildPDF(fixtures.PDFSpec{Lines: []string{"x"}})
	if _, err := facturx.Extract(t.Context(), bytes.NewReader(plain)); !errors.Is(err, facturx.ErrNoFacturX) {
		t.Fatalf("plain PDF Extract err = %v, want ErrNoFacturX", err)
	}
}

func TestReadLayout_RefusesGarbageAndCopiesNoText(t *testing.T) {
	t.Parallel()
	if _, err := fixtures.ReadLayout(t.Context(), strings.NewReader("not a pdf")); err == nil {
		t.Fatal("ReadLayout accepted garbage")
	}
	private := "Jean Personne 12 rue Privee"
	src := fixtures.BuildPDF(fixtures.PDFSpec{Pages: 3, Width: 595, Height: 842, Lines: []string{private}})
	l, err := fixtures.ReadLayout(t.Context(), bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	out := fixtures.BuildPDF(fixtures.PDFSpec{Pages: l.Pages, Width: l.Width, Height: l.Height, Lines: []string{"synthetic"}})
	if bytes.Contains(out, []byte("Personne")) {
		t.Fatal("layout copy carried text of the source")
	}
}
