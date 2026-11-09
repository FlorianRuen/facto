package fixtures

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// PDFSpec describes a synthetic PDF (scripts/fakepdf).
type PDFSpec struct {
	Pages         int     // default 1
	Width, Height float64 // points; default A4 595x842
	Lines         []string
	// FacturX, when set, is embedded as factur-x.xml (EmbeddedFiles + /AF).
	FacturX []byte
}

// BuildPDF writes a minimal valid PDF 1.7 by hand (deterministic: no date,
// no id): every page shows Lines in Helvetica from the top left.
func BuildPDF(spec PDFSpec) []byte {
	if spec.Pages <= 0 {
		spec.Pages = 1
	}
	if spec.Width <= 0 || spec.Height <= 0 {
		spec.Width, spec.Height = 595, 842
	}
	var objs []string
	add := func(body string) int {
		objs = append(objs, body)
		return len(objs)
	}
	catalog := add("")
	pages := add("")
	font := add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	var content strings.Builder
	content.WriteString("BT /F1 11 Tf 14 TL ")
	fmt.Fprintf(&content, "50 %s Td ", num(spec.Height-60))
	for _, l := range spec.Lines {
		content.WriteString("(" + pdfString(l) + ") Tj T* ")
	}
	content.WriteString("ET")
	stream := add(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", content.Len(), content.String()))
	var kids []string
	for range spec.Pages {
		p := add(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>",
			pages, num(spec.Width), num(spec.Height), font, stream))
		kids = append(kids, fmt.Sprintf("%d 0 R", p))
	}
	objs[pages-1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), spec.Pages)
	cat := fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R", pages)
	if spec.FacturX != nil {
		ef := add(fmt.Sprintf("<< /Type /EmbeddedFile /Subtype /text#2Fxml /Length %d >>\nstream\n%s\nendstream", len(spec.FacturX), spec.FacturX))
		fs := add(fmt.Sprintf("<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /Desc (Factur-X) /AFRelationship /Data /EF << /F %d 0 R /UF %d 0 R >> >>", ef, ef))
		cat += fmt.Sprintf(" /Names << /EmbeddedFiles << /Names [(factur-x.xml) %d 0 R] >> >> /AF [%d 0 R]", fs, fs)
	}
	objs[catalog-1] = cat + " >>"

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n% facto synthetic fixture (scripts/fakepdf)\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, catalog, xref)
	return b.Bytes()
}

func num(f float64) string {
	s := fmt.Sprintf("%.2f", f)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s
}

// pdfString escapes a literal string; non-Latin-1 runes become '?'.
func pdfString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r > 0xff:
			b.WriteByte('?')
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

// Layout is the layout class of a PDF: what fakepdf copies from a real
// one (never any text, image or metadata).
type Layout struct {
	Pages         int
	Width, Height float64 // first page MediaBox, points
}

// MaxLayoutPDF caps the PDF ReadLayout reads.
const MaxLayoutPDF = 32 << 20

// ErrNotPDF reports an input ReadLayout cannot read.
var ErrNotPDF = errors.New("fixtures: not a readable PDF")

// ReadLayout reads the page count and the first page size of a PDF, with
// pdfcpu's resource limits, in memory, bounded in time.
func ReadLayout(ctx context.Context, r io.Reader) (l Layout, err error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxLayoutPDF+1))
	if err != nil {
		return Layout{}, fmt.Errorf("fixtures: read pdf: %w", err)
	}
	if len(data) > MaxLayoutPDF {
		return Layout{}, fmt.Errorf("%w: larger than %d bytes", ErrNotPDF, MaxLayoutPDF)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	defer func() {
		if recover() != nil {
			l, err = Layout{}, fmt.Errorf("%w: parser failure", ErrNotPDF)
		}
	}()
	conf := model.NewStatelessConfiguration()
	conf.Limits = model.DefaultResourceLimits()
	conf.Limits.MaxInputBytes = MaxLayoutPDF
	conf.Limits.MaxStreamBytes = MaxLayoutPDF
	conf.Limits.MaxDecodeBytes = MaxLayoutPDF
	pc, err := api.ReadContext(ctx, bytes.NewReader(data), conf)
	if err != nil || pc == nil || pc.XRefTable == nil {
		return Layout{}, ErrNotPDF
	}
	if err := pc.EnsurePageCount(); err != nil || pc.PageCount < 1 {
		return Layout{}, ErrNotPDF
	}
	dims, err := pc.PageDims(ctx)
	if err != nil || len(dims) == 0 {
		return Layout{}, ErrNotPDF
	}
	return Layout{Pages: pc.PageCount, Width: dims[0].Width, Height: dims[0].Height}, nil
}
