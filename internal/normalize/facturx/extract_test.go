// Tests for Factur-X PDF extraction (J0 task T17): find the CII XML embedded
// in a Factur-X / ZUGFeRD PDF and parse it with ParseCII (T16). pdfcpu
// (ADR 0006) is used only inside this package, in memory, never writing to
// disk. Spec: docs/spec.md "Normalization and naming" (Factur-X) and "Threat
// model" (untrusted PDFs dropped in inbox/: size caps, no panics).
//
// Expected API (implementer: follow exactly; ParseCII, Invoice, MaxSize,
// ErrTooLarge, ErrUnsafeXML, ErrNotCII, ErrInvalid are unchanged from T16):
//
//	// MaxPDFSize is the largest PDF Extract accepts, in bytes
//	// (MaxSize < MaxPDFSize <= 64 MiB; 32 MiB suggested). Extract never reads
//	// more than MaxPDFSize+1 bytes from r (plus at most one read buffer).
//	const MaxPDFSize = …
//
//	var (
//	    // ErrNoFacturX: a readable PDF that has no embedded file named
//	    // "factur-x.xml" or "zugferd-invoice.xml" (including a PDF without any
//	    // embedded file at all: pdfcpu reports that as an error, map it).
//	    ErrNoFacturX error
//	    // ErrInvalidPDF: the input cannot be read as a PDF, including any panic
//	    // recovered while pdfcpu parses it (pdfcpu's fault.Catch re-panics
//	    // foreign panics: Extract must recover them itself).
//	    ErrInvalidPDF error
//	)
//
//	// Extract reads the whole PDF from r (at most MaxPDFSize+1 bytes; more is
//	// ErrTooLarge, checked before any parsing), extracts the CII attachment
//	// in memory with api.ExtractAttachmentsRaw and returns ParseCII's result.
//	//
//	// Attachment selection: the embedded file's own name (/UF, else /F) must
//	// equal "factur-x.xml" or "zugferd-invoice.xml" exactly. A matching
//	// name-tree key or /Desc alone does not count (pdfcpu's selected-name
//	// search matches both: filter on Attachment.FileName). When both names
//	// are present, "factur-x.xml" wins.
//	//
//	// Each attachment is read through io.LimitReader: more than MaxSize
//	// decoded bytes is ErrTooLarge. ParseCII errors are returned wrapped
//	// (ErrUnsafeXML, ErrNotCII, ErrInvalid, ErrTooLarge). On any error the
//	// returned Invoice is the zero value. A canceled ctx is checked before
//	// parsing and returns an error wrapping ctx.Err().
//	//
//	// pdfcpu must be given an explicit stateless configuration
//	// (model.NewStatelessConfiguration()): a nil conf makes pdfcpu create a
//	// config directory under os.UserConfigDir, i.e. write files outside fsx.
//	// Extract writes no file anywhere.
//	func Extract(ctx context.Context, r io.Reader) (Invoice, error)
package facturx_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

const (
	nameFacturX = "factur-x.xml"
	nameZUGFeRD = "zugferd-invoice.xml"
)

// basicXML is the synthetic BASIC profile CII from T16's golden fixtures.
func basicXML(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "TestParseCII_ProfilesGolden", "basic.xml"))
	if err != nil {
		t.Fatalf("read basic.xml: %v", err)
	}
	return b
}

var basicView = view{
	Profile: "basic", TypeCode: "380", Number: "FA-2026-0002", IssueDate: "2026-04-01",
	SellerName: "Fournisseur Exemple SAS", Currency: "CHF", GrandTotalCents: cents(123450),
}

// minimalPDF is testdata/minimal.pdf: a hand-written one-page PDF without any
// embedded file.
func minimalPDF(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "minimal.pdf"))
	if err != nil {
		t.Fatalf("read minimal.pdf: %v", err)
	}
	return b
}

func extract(t *testing.T, pdf []byte) (facturx.Invoice, error) {
	t.Helper()
	return facturx.Extract(t.Context(), bytes.NewReader(pdf))
}

// wantErr fails unless err wraps one of the sentinels and inv is zero.
func wantErr(t *testing.T, inv facturx.Invoice, err error, sentinels ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("Extract succeeded (%+v), want one of %v", inv, sentinels)
	}
	if inv != (facturx.Invoice{}) {
		t.Fatalf("Extract returned data alongside %v: %+v", err, inv)
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return
		}
	}
	t.Fatalf("Extract: err = %v, want one of %v", err, sentinels)
}

func TestExtract_Sentinels(t *testing.T) {
	t.Parallel()

	if facturx.MaxPDFSize <= facturx.MaxSize || facturx.MaxPDFSize > 64<<20 {
		t.Fatalf("MaxPDFSize = %d, want in (MaxSize=%d, 64 MiB]", facturx.MaxPDFSize, facturx.MaxSize)
	}
	all := map[string]error{
		"ErrNoFacturX":  facturx.ErrNoFacturX,
		"ErrInvalidPDF": facturx.ErrInvalidPDF,
		"ErrTooLarge":   facturx.ErrTooLarge,
		"ErrUnsafeXML":  facturx.ErrUnsafeXML,
		"ErrNotCII":     facturx.ErrNotCII,
		"ErrInvalid":    facturx.ErrInvalid,
	}
	for name, err := range all {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		for other, oerr := range all {
			if name != other && errors.Is(err, oerr) {
				t.Errorf("errors.Is(%s, %s) = true, want distinct sentinels", name, other)
			}
		}
	}
}

func TestExtract_FacturX(t *testing.T) {
	t.Parallel()

	xml := basicXML(t)
	tests := []struct {
		name string
		atts []synthAttachment
		want view
	}{
		{
			name: "single factur-x.xml",
			atts: []synthAttachment{{file: nameFacturX, data: xml}},
			want: basicView,
		},
		{
			name: "flate compressed",
			atts: []synthAttachment{{file: nameFacturX, data: xml, flate: true}},
			want: basicView,
		},
		{
			name: "next to unrelated attachments",
			atts: []synthAttachment{
				{file: "annexe.txt", data: []byte("annexe synthetique")},
				{file: nameFacturX, data: xml},
				{file: "logo.xml", data: []byte("<logo/>")},
			},
			want: basicView,
		},
		{
			name: "name-tree key differs from file name",
			atts: []synthAttachment{{key: "Attachment1", file: nameFacturX, data: xml}},
			want: basicView,
		},
		{
			name: "factur-x.xml wins over zugferd-invoice.xml",
			atts: []synthAttachment{
				{file: nameZUGFeRD, data: []byte(full())},
				{file: nameFacturX, data: xml},
			},
			want: basicView,
		},
		{
			name: "minimum profile",
			atts: []synthAttachment{{file: nameFacturX, data: []byte(full())}},
			want: fullView,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := extract(t, buildPDF(t, tt.atts...))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			checkView(t, inv, tt.want)
		})
	}
}

func TestExtract_ZUGFeRDName(t *testing.T) {
	t.Parallel()

	for _, flate := range []bool{false, true} {
		inv, err := extract(t, buildPDF(t, synthAttachment{file: nameZUGFeRD, data: basicXML(t), flate: flate}))
		if err != nil {
			t.Fatalf("Extract(zugferd-invoice.xml, flate=%v): %v", flate, err)
		}
		checkView(t, inv, basicView)
	}
}

func TestExtract_NoAttachment(t *testing.T) {
	t.Parallel()

	xml := basicXML(t)
	tests := []struct {
		name string
		pdf  func(t *testing.T) []byte
	}{
		{name: "hand-written minimal pdf", pdf: func(t *testing.T) []byte { return minimalPDF(t) }},
		{name: "built pdf without attachments", pdf: func(t *testing.T) []byte { return buildPDF(t) }},
		{name: "only unrelated attachments", pdf: func(t *testing.T) []byte {
			return buildPDF(t,
				synthAttachment{file: "annexe.txt", data: []byte("annexe synthetique")},
				synthAttachment{file: "invoice.xml", data: xml})
		}},
		{name: "matching Desc only", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{key: "a1", file: "notes.xml", desc: nameFacturX, data: xml})
		}},
		{name: "matching name-tree key only", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{key: nameFacturX, file: "notes.xml", data: xml})
		}},
		{name: "traversal-shaped name", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{file: "../" + nameFacturX, data: xml})
		}},
		{name: "name with a directory", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{file: "x/" + nameFacturX, data: xml})
		}},
		{name: "suffix match only", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{file: "old-" + nameFacturX, data: xml})
		}},
		{name: "extra extension", pdf: func(t *testing.T) []byte {
			return buildPDF(t, synthAttachment{file: nameFacturX + ".bak", data: xml})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := extract(t, tt.pdf(t))
			wantErr(t, inv, err, facturx.ErrNoFacturX)
		})
	}
}

func TestExtract_Oversized(t *testing.T) {
	t.Parallel()

	t.Run("attachment of exactly MaxSize is accepted", func(t *testing.T) {
		t.Parallel()
		for _, flate := range []bool{false, true} {
			inv, err := extract(t, buildPDF(t, synthAttachment{file: nameFacturX, data: padTo(t, facturx.MaxSize), flate: flate}))
			if err != nil {
				t.Fatalf("Extract(MaxSize attachment, flate=%v): %v", flate, err)
			}
			checkView(t, inv, fullView)
		}
	})

	t.Run("attachment of MaxSize+1 is rejected", func(t *testing.T) {
		t.Parallel()
		inv, err := extract(t, buildPDF(t, synthAttachment{file: nameFacturX, data: padTo(t, facturx.MaxSize+1)}))
		wantErr(t, inv, err, facturx.ErrTooLarge)
	})

	t.Run("compressed attachment decoding past MaxSize is rejected", func(t *testing.T) {
		t.Parallel()
		// A few KiB of Flate that decodes to 4x MaxSize: the cap applies to
		// decoded bytes, not to the stream length in the PDF.
		pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: padTo(t, 4*facturx.MaxSize), flate: true})
		if len(pdf) > facturx.MaxSize/16 {
			t.Fatalf("fixture is %d bytes, expected a small compressed PDF", len(pdf))
		}
		inv, err := extract(t, pdf)
		wantErr(t, inv, err, facturx.ErrTooLarge)
	})

	t.Run("pdf larger than MaxPDFSize is rejected", func(t *testing.T) {
		t.Parallel()
		// A valid Factur-X PDF followed by padding: only the size matters.
		pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
		big := slices.Concat(pdf, bytes.Repeat([]byte("\n"), facturx.MaxPDFSize+1-len(pdf)))
		inv, err := extract(t, big)
		wantErr(t, inv, err, facturx.ErrTooLarge)
	})

	t.Run("endless reader stops after MaxPDFSize", func(t *testing.T) {
		t.Parallel()
		cr := &countingReader{r: &endless{prefix: []byte("%PDF-1.7\n")}}
		inv, err := facturx.Extract(t.Context(), cr)
		wantErr(t, inv, err, facturx.ErrTooLarge)
		if limit := int64(facturx.MaxPDFSize) + 64<<10; cr.n > limit {
			t.Fatalf("Extract read %d bytes, want <= %d", cr.n, limit)
		}
	})
}

func TestExtract_Malformed(t *testing.T) {
	t.Parallel()

	good := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
	stream := bytes.Index(good, []byte("stream\n"))
	trailer := bytes.Index(good, []byte("trailer"))
	if stream < 0 || trailer < 0 {
		t.Fatal("fixture has no stream or no trailer")
	}

	// repairable: pdfcpu reconstructs broken xref tables and stream
	// lengths, so these may also succeed, but then with the right data.
	tests := []struct {
		name       string
		pdf        []byte
		want       []error // any of
		repairable bool
	}{
		{name: "empty", pdf: nil, want: []error{facturx.ErrInvalidPDF}},
		{name: "not a pdf", pdf: []byte("Facture synthetique en texte brut\n"), want: []error{facturx.ErrInvalidPDF}},
		{name: "header only", pdf: []byte("%PDF-1.7\n"), want: []error{facturx.ErrInvalidPDF}},
		{name: "header and eof only", pdf: []byte("%PDF-1.7\n%%EOF\n"), want: []error{facturx.ErrInvalidPDF}},
		{name: "cii xml instead of a pdf", pdf: basicXML(t), want: []error{facturx.ErrInvalidPDF}},
		{name: "random binary", pdf: bytes.Repeat([]byte{0x00, 0xff, 0x13, 0x37}, 512), want: []error{facturx.ErrInvalidPDF}},
		{
			name: "truncated in the attachment stream",
			pdf:  good[:stream+64],
			want: []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX},
		},
		{
			name:       "truncated before trailer",
			pdf:        good[:trailer],
			want:       []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX, facturx.ErrNotCII, facturx.ErrInvalid},
			repairable: true,
		},
		{
			name:       "startxref points past the end",
			pdf:        bytes.Replace(good, []byte("startxref\n"), []byte("startxref\n99999999"), 1),
			want:       []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX, facturx.ErrNotCII, facturx.ErrInvalid},
			repairable: true,
		},
		{
			name: "Root is not a dictionary",
			pdf:  bytes.Replace(good, []byte("/Root 1 0 R"), []byte("/Root 42   "), 1),
			want: []error{facturx.ErrInvalidPDF},
		},
		{
			name: "EmbeddedFiles Names is not an array",
			pdf:  bytes.Replace(good, []byte("/EmbeddedFiles << /Names ["), []byte("/EmbeddedFiles << /Names (["), 1),
			want: []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX},
		},
		{
			name: "EF entry points to a missing object",
			pdf:  bytes.Replace(good, []byte("/EF << /F 4 0 R /UF 4 0 R"), []byte("/EF << /F 9 0 R /UF 9 0 R"), 1),
			want: []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX},
		},
		{
			name:       "stream Length larger than the file",
			pdf:        replaceLength(t, good, "99999999"),
			want:       []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX, facturx.ErrNotCII, facturx.ErrInvalid},
			repairable: true,
		},
		{
			name:       "negative stream Length",
			pdf:        replaceLength(t, good, "-5"),
			want:       []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX, facturx.ErrNotCII, facturx.ErrInvalid},
			repairable: true,
		},
		{
			name: "corrupt flate data",
			pdf:  buildPDFCorruptFlate(t),
			want: []error{facturx.ErrInvalidPDF, facturx.ErrNoFacturX},
		},
		{
			name: "attachment is not CII",
			pdf:  buildPDF(t, synthAttachment{file: nameFacturX, data: []byte(`<?xml version="1.0"?><facture>synthetique</facture>`)}),
			want: []error{facturx.ErrNotCII},
		},
		{
			name: "attachment with DOCTYPE",
			pdf: buildPDF(t, synthAttachment{file: nameFacturX, data: []byte(
				`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]>` + strings.TrimPrefix(full(), `<?xml version="1.0" encoding="UTF-8"?>`))}),
			want: []error{facturx.ErrUnsafeXML},
		},
		{
			name: "attachment is empty",
			pdf:  buildPDF(t, synthAttachment{file: nameFacturX, data: nil}),
			want: []error{facturx.ErrInvalid, facturx.ErrInvalidPDF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var (
				inv facturx.Invoice
				err error
			)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Extract panicked: %v", r)
					}
				}()
				inv, err = extract(t, tt.pdf)
			}()
			if tt.repairable && err == nil {
				checkView(t, inv, basicView)
				return
			}
			wantErr(t, inv, err, tt.want...)
		})
	}
}

// replaceLength rewrites the /Length of the first EmbeddedFile stream.
func replaceLength(t *testing.T, pdf []byte, length string) []byte {
	t.Helper()
	i := bytes.Index(pdf, []byte("/Type /EmbeddedFile"))
	if i < 0 {
		t.Fatal("fixture has no EmbeddedFile")
	}
	j := bytes.Index(pdf[i:], []byte("/Length "))
	if j < 0 {
		t.Fatal("fixture has no /Length")
	}
	start := i + j + len("/Length ")
	end := start
	for end < len(pdf) && pdf[end] >= '0' && pdf[end] <= '9' {
		end++
	}
	out := append([]byte{}, pdf[:start]...)
	out = append(out, length...)
	return append(out, pdf[end:]...)
}

// buildPDFCorruptFlate declares FlateDecode on bytes that are not zlib.
func buildPDFCorruptFlate(t *testing.T) []byte {
	t.Helper()
	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: []byte("not zlib at all, synthetic")})
	return bytes.Replace(pdf, []byte("/Subtype /text#2Fxml"), []byte("/Filter /FlateDecode /Subtype /text#2Fxml"), 1)
}

func TestExtract_ReaderErrorIsWrapped(t *testing.T) {
	t.Parallel()

	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
	inv, err := facturx.Extract(t.Context(), &failingReader{prefix: pdf[:100]})
	if !errors.Is(err, errReader) {
		t.Fatalf("Extract: err = %v, want it to wrap the reader error", err)
	}
	if inv != (facturx.Invoice{}) {
		t.Fatalf("Extract returned data alongside %v: %+v", err, inv)
	}
}

func TestExtract_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
	inv, err := facturx.Extract(ctx, bytes.NewReader(pdf))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Extract(canceled ctx): err = %v, want context.Canceled", err)
	}
	if inv != (facturx.Invoice{}) {
		t.Fatalf("Extract returned data alongside %v: %+v", err, inv)
	}
}

func TestExtract_ConcurrentUse(t *testing.T) {
	t.Parallel()

	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			inv, err := facturx.Extract(context.Background(), bytes.NewReader(pdf))
			if err == nil && inv.Number != basicView.Number {
				err = errors.New("wrong number " + inv.Number)
			}
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Extract: %v", err)
		}
	}
}

// TestExtract_WritesNoFiles proves pdfcpu runs with a stateless configuration:
// with a nil conf it creates <UserConfigDir>/pdfcpu (config.yml, fonts), a
// file write outside internal/fsx. Not parallel: it points the user config
// and temp directories at empty test directories (t.Setenv). It must stay the
// only sequential Extract test so that it runs before pdfcpu caches a config.
func TestExtract_WritesNoFiles(t *testing.T) {
	cfg, tmp := t.TempDir(), t.TempDir()
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "AppData", "LocalAppData", "USERPROFILE"} {
		t.Setenv(k, cfg)
	}
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)

	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t)})
	inv, err := facturx.Extract(t.Context(), bytes.NewReader(pdf))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	checkView(t, inv, basicView)
	if _, err := facturx.Extract(t.Context(), bytes.NewReader(minimalPDF(t))); !errors.Is(err, facturx.ErrNoFacturX) {
		t.Fatalf("Extract(minimal.pdf): err = %v, want ErrNoFacturX", err)
	}

	for _, dir := range []string{cfg, tmp} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("Extract wrote %v under %s, want no file written", names, dir)
		}
	}
}

// Compile-time check of Extract's signature.
var _ func(context.Context, io.Reader) (facturx.Invoice, error) = facturx.Extract
