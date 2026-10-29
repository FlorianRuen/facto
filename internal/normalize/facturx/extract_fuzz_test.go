package facturx_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

// FuzzExtract feeds arbitrary bytes to Extract: it must never panic, never
// return data alongside an error, and every error must wrap a documented
// sentinel (or the context error).
func FuzzExtract(f *testing.F) {
	xml := []byte(full())
	good := buildPDF(f, synthAttachment{file: "factur-x.xml", data: xml})
	seeds := [][]byte{
		readTestdataF(f, filepath.Join("testdata", "minimal.pdf")),
		good,
		buildPDF(f, synthAttachment{file: "factur-x.xml", data: xml, flate: true}),
		buildPDF(f, synthAttachment{file: "zugferd-invoice.xml", data: xml}),
		buildPDF(f, synthAttachment{key: "a1", file: "notes.xml", desc: "factur-x.xml", data: xml}),
		buildPDF(f, synthAttachment{file: "factur-x.xml", data: []byte(`<!DOCTYPE x [<!ENTITY a "b">]><x/>`)}),
		buildPDF(f),
		good[:len(good)/2],
		bytes.Replace(good, []byte("/Root 1 0 R"), []byte("/Root 9 0 R"), 1),
		[]byte("%PDF-1.7\n"),
		[]byte("%PDF-1.7\n1 0 obj\n<< /Length 999999 >>\nstream\n"),
		[]byte("%PDF-1.7\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root << >> >>\nstartxref\n9\n%%EOF\n"),
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	sentinels := []error{
		facturx.ErrNoFacturX, facturx.ErrInvalidPDF, facturx.ErrTooLarge,
		facturx.ErrUnsafeXML, facturx.ErrNotCII, facturx.ErrInvalid,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		inv, err := facturx.Extract(context.Background(), bytes.NewReader(data))
		if err == nil {
			return
		}
		if inv != (facturx.Invoice{}) {
			t.Fatalf("data returned alongside %v: %+v", err, inv)
		}
		for _, s := range sentinels {
			if errors.Is(err, s) {
				return
			}
		}
		t.Fatalf("error wraps no sentinel: %v", err)
	})
}
