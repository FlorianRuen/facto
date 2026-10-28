// Hardening tests for Extract beyond the T17 contract (extract_test.go):
// hand-built PDF structures exercising the EmbeddedFiles name-tree walk, the
// attachment stream decoder and the Flate bomb cap. Everything is synthetic.
package facturx_test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

// rawPDF writes objs as objects 1..n with a correct xref table; object 1 must
// be the catalog. Objects 2 and 3 are conventionally the page tree.
func rawPDF(t testing.TB, objs ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n% synthetic facto test fixture\n")
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
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

const (
	catalogWithTree = "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>"
	pagesObj        = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	pageObj         = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"
)

// streamObj is an EmbeddedFile stream object with extra dictionary entries.
func streamObj(extra string, data []byte) string {
	return fmt.Sprintf("<< /Type /EmbeddedFile%s /Length %d >>\nstream\n%s\nendstream", extra, len(data), data)
}

func zlibBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib: %v", err)
	}
	return z.Bytes()
}

// utf16Hex is s as a PDF hex text string in UTF-16BE with a BOM.
func utf16Hex(s string) string {
	b := binary.BigEndian.AppendUint16(nil, 0xfeff)
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.BigEndian.AppendUint16(b, u)
	}
	return "<" + hex.EncodeToString(b) + ">"
}

func TestExtract_NameTreeAndFileSpecShapes(t *testing.T) {
	t.Parallel()

	xml := basicXML(t)
	spec := func(ef string) string { return "<< /Type /Filespec /F (factur-x.xml) /EF " + ef + " >>" }
	tests := []struct {
		name string
		objs []string // objects 4.. (1-3 are catalog, pages, page)
		want []error  // nil: success with basicView
	}{
		{
			name: "intermediate Kids node",
			objs: []string{
				"<< /Kids [5 0 R] >>",
				"<< /Limits [(a) (z)] /Names [(factur-x.xml) 6 0 R] >>",
				spec("<< /F 7 0 R >>"),
				streamObj("", xml),
			},
		},
		{
			name: "EF with UF only",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /UF 6 0 R >>"), streamObj("", xml)},
		},
		{
			name: "UF as a UTF-16 hex string",
			objs: []string{
				"<< /Names [(k) 5 0 R] >>",
				"<< /Type /Filespec /UF " + utf16Hex("factur-x.xml") + " /EF << /F 6 0 R >> >>",
				streamObj("", xml),
			},
		},
		{
			name: "filter given as an array",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /F 6 0 R >>"), streamObj(" /Filter [/FlateDecode]", zlibBytes(t, xml))},
		},
		{
			name: "non dictionary values are skipped",
			objs: []string{"<< /Names [(a) 42 (b) (str) (factur-x.xml) 5 0 R] >>", spec("<< /F 6 0 R >>"), streamObj("", xml)},
		},
		{
			name: "file spec without a name is skipped",
			objs: []string{"<< /Names [(factur-x.xml) 5 0 R] >>", "<< /Type /Filespec /EF << /F 6 0 R >> >>", streamObj("", xml)},
			want: []error{facturx.ErrNoFacturX},
		},
		{
			name: "empty tree",
			objs: []string{"<< /Names [] >>"},
			want: []error{facturx.ErrNoFacturX},
		},
		{
			name: "cycle in Kids",
			objs: []string{"<< /Kids [5 0 R] >>", "<< /Kids [4 0 R] >>"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "kid is not a reference",
			objs: []string{"<< /Kids [<< /Names [] >>] >>"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "kid is not a dictionary",
			objs: []string{"<< /Kids [5 0 R] >>", "(not a node)"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "Kids is not an array",
			objs: []string{"<< /Kids (5 0 R) >>"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "EF missing",
			objs: []string{"<< /Names [(k) 5 0 R] >>", "<< /Type /Filespec /F (factur-x.xml) >>"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "EF is not a dictionary",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("(x)")},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "EF without a stream",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /RF 6 0 R >>"), streamObj("", xml)},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "EF F is not a stream",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /F 6 0 R >>"), "<< /Type /EmbeddedFile >>"},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "unsupported filter",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /F 6 0 R >>"), streamObj(" /Filter /ASCIIHexDecode", []byte(hex.EncodeToString(xml)+">"))},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "filter chain",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /F 6 0 R >>"), streamObj(" /Filter [/FlateDecode /FlateDecode]", zlibBytes(t, zlibBytes(t, xml)))},
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "flate predictor",
			objs: []string{"<< /Names [(k) 5 0 R] >>", spec("<< /F 6 0 R >>"), streamObj(" /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>", zlibBytes(t, xml))},
			want: []error{facturx.ErrInvalidPDF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pdf := rawPDF(t, append([]string{catalogWithTree, pagesObj, pageObj}, tt.objs...)...)
			inv, err := extract(t, pdf)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Extract: %v", err)
				}
				checkView(t, inv, basicView)
				return
			}
			wantErr(t, inv, err, tt.want...)
		})
	}
}

func TestExtract_CatalogShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		catalog string
		extra   []string
		want    error
	}{
		{name: "Names without EmbeddedFiles", catalog: "<< /Type /Catalog /Pages 2 0 R /Names << /Dests 4 0 R >> >>", extra: []string{"<< /Names [] >>"}, want: facturx.ErrNoFacturX},
		{name: "Names is not a dictionary", catalog: "<< /Type /Catalog /Pages 2 0 R /Names 4 0 R >>", extra: []string{"(not a dict)"}, want: facturx.ErrInvalidPDF},
		{name: "EmbeddedFiles is not a dictionary", catalog: catalogWithTree, extra: []string{"[1 2 3]"}, want: facturx.ErrInvalidPDF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := extract(t, rawPDF(t, append([]string{tt.catalog, pagesObj, pageObj}, tt.extra...)...))
			wantErr(t, inv, err, tt.want)
		})
	}
}

func TestExtract_DeepNameTree(t *testing.T) {
	t.Parallel()

	// 4 -> 5 -> ... -> 4+depth, each a single-kid node: deeper than any
	// real tree, refused instead of walked.
	const depth = 64
	objs := []string{catalogWithTree, pagesObj, pageObj}
	for i := range depth {
		objs = append(objs, fmt.Sprintf("<< /Kids [%d 0 R] >>", 5+i))
	}
	objs = append(objs, "<< /Names [] >>")
	inv, err := extract(t, rawPDF(t, objs...))
	wantErr(t, inv, err, facturx.ErrInvalidPDF)
}

func TestExtract_WideNameTree(t *testing.T) {
	t.Parallel()

	var names strings.Builder
	for i := range 10_001 {
		fmt.Fprintf(&names, "(k%05d) 1 ", i)
	}
	pdf := rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Names ["+names.String()+"] >>")
	inv, err := extract(t, pdf)
	wantErr(t, inv, err, facturx.ErrInvalidPDF)
}

// TestExtract_FlateBomb proves the attachment is inflated by Extract through
// a size-limited reader, not by pdfcpu: a stream inflating to 16x MaxSize
// (twice the decode limit Extract gives pdfcpu) is ErrTooLarge, whereas
// pdfcpu's own decode limit would surface as ErrInvalidPDF.
func TestExtract_FlateBomb(t *testing.T) {
	t.Parallel()

	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.BestSpeed)
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	zeros := make([]byte, 1<<20)
	for range 16 * facturx.MaxSize >> 20 {
		if _, err := zw.Write(zeros); err != nil {
			t.Fatalf("zlib: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib: %v", err)
	}
	pdf := rawPDF(t, catalogWithTree, pagesObj, pageObj,
		"<< /Names [(factur-x.xml) 5 0 R] >>",
		"<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /EF << /F 6 0 R >> >>",
		streamObj(" /Filter /FlateDecode", z.Bytes()))
	inv, err := extract(t, pdf)
	wantErr(t, inv, err, facturx.ErrTooLarge)
}
