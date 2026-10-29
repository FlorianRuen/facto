package normalize_test

// ParseName contract (see the API in naming_test.go):
//   - name is ONE base name; anything with '/', '\\' or NUL is refused;
//   - grammar (DefaultFileTemplate, en or fr labels):
//     <date 2006-01-02>[_<provider>]_<kind label>[_<amount>][_<ref>][_v<n>][.<ext>]
//     provider and ref are non-empty slugs, amount is ^-?(0|[1-9][0-9]*)-[0-9]{2}[A-Z]{3}$,
//     n >= 2 (a final "_v<digits>" field is always the version marker, so
//     "_v0", "_v1", "_v02" are refused), ext is 1–8 ASCII letters/digits (any case, returned lowercase);
//   - when the field after the date is a kind label and the next one is not,
//     there is no provider (spec example "2026-06-21_receipt_client-lunch-lyon.jpg");
//   - returned Doc: Date at 00:00 UTC, Currency "" when there is no amount,
//     Category "", Version 1 when there is no "_vN" suffix, Ext without dot;
//   - every refusal wraps ErrNotCompliant and returns a zero Doc.

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/normalize"
)

func TestParseName_SpecExamples(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want normalize.Doc
	}{
		{"2026-03-14_edf_invoice_84-12EUR_10234567.pdf", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14),
			AmountCents: cents(8412), Currency: "EUR", Ref: "10234567", Ext: "pdf", Version: 1,
		}},
		{"2026-04-01_cooloc_rent-receipt_2026-04.pdf", normalize.Doc{
			Provider: "cooloc", Kind: connector.RentReceipt, Date: day(2026, time.April, 1), Ref: "2026-04", Ext: "pdf", Version: 1,
		}},
		{"2026-10-02_impots_property-tax-notice.pdf", normalize.Doc{
			Provider: "impots", Kind: connector.TaxNotice, Date: day(2026, time.October, 2), Ext: "pdf", Version: 1,
		}},
		{"2026-06-21_receipt_client-lunch-lyon.jpg", normalize.Doc{
			Kind: connector.Receipt, Date: day(2026, time.June, 21), Ref: "client-lunch-lyon", Ext: "jpg", Version: 1,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalize.ParseName(tc.name)
			if err != nil {
				t.Fatalf("ParseName(%q): %v", tc.name, err)
			}
			assertDoc(t, got, tc.want)
		})
	}
}

func TestParseName_Accepts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want normalize.Doc
	}{
		{"2026-04-01_cooloc_quittance-de-loyer_2026-04.pdf", normalize.Doc{
			Provider: "cooloc", Kind: connector.RentReceipt, Date: day(2026, time.April, 1), Ref: "2026-04", Ext: "pdf", Version: 1,
		}},
		{"2026-10-02_impots_avis-de-taxe-fonciere.pdf", normalize.Doc{
			Provider: "impots", Kind: connector.TaxNotice, Date: day(2026, time.October, 2), Ext: "pdf", Version: 1,
		}},
		{"2026-03-14_edf_invoice_84-12EUR_10234567_v2.pdf", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14),
			AmountCents: cents(8412), Currency: "EUR", Ref: "10234567", Ext: "pdf", Version: 2,
		}},
		{"2026-03-14_edf_invoice.PDF", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "pdf", Version: 1,
		}},
		{"2026-03-14_edf_invoice", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14), Version: 1,
		}},
		{"2026-03-14_edf_facture_-10-50EUR.pdf", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14),
			AmountCents: cents(-1050), Currency: "EUR", Ext: "pdf", Version: 1,
		}},
		{"2026-03-14_invoice_0-05EUR.pdf", normalize.Doc{
			Kind: connector.Invoice, Date: day(2026, time.March, 14), AmountCents: cents(5), Currency: "EUR", Ext: "pdf", Version: 1,
		}},
		{"2025-12-31_edf_invoice.pdf", normalize.Doc{
			Provider: "edf", Kind: connector.Invoice, Date: day(2025, time.December, 31), Ext: "pdf", Version: 1,
		}},
		{"2026-03-14_releve.pdf", normalize.Doc{
			Kind: connector.Statement, Date: day(2026, time.March, 14), Ext: "pdf", Version: 1,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalize.ParseName(tc.name)
			if err != nil {
				t.Fatalf("ParseName(%q): %v", tc.name, err)
			}
			assertDoc(t, got, tc.want)
		})
	}
}

// TestParseName_RoundTrip: ParseName(Render(d).File) gives back the
// normalized fields of d, in both languages.
func TestParseName_RoundTrip(t *testing.T) {
	t.Parallel()
	docs := []normalize.Doc{
		{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: day(2026, time.March, 14), AmountCents: cents(8412), Currency: "EUR", Ref: "10234567", Ext: "pdf", Version: 1},
		{Provider: "Bouygues Télécom", Category: "internet", Kind: connector.Invoice, Date: day(2026, time.February, 3), AmountCents: cents(3999), Currency: "eur", Ref: "FA/2026/0042", Ext: ".PDF", Version: 1},
		{Provider: "cooloc", Kind: connector.RentReceipt, Date: day(2026, time.April, 1), Ref: "2026-04", Ext: "pdf", Version: 3},
		{Provider: "impots", Kind: connector.TaxNotice, Date: day(2026, time.October, 2), Ext: "pdf", Version: 1},
		{Kind: connector.Receipt, Date: day(2026, time.June, 21), Ref: "Client lunch, Lyon", Ext: "jpg", Version: 1},
		{Provider: "wecasa", Kind: connector.Receipt, Date: day(2026, time.July, 9), AmountCents: cents(0), Currency: "EUR", Ext: "pdf", Version: 2},
		{Provider: "fournisseur-exemple", Kind: connector.Statement, Date: time.Date(2026, time.August, 31, 22, 15, 0, 0, time.FixedZone("UTC-4", -4*3600)), AmountCents: cents(-250), Currency: "USD", Version: 1},
	}
	for _, lang := range []string{"en", "fr"} {
		n := newNamer(t, normalize.Config{Language: lang})
		for _, d := range docs {
			file := render(t, n, d).File
			t.Run(lang+"/"+file, func(t *testing.T) {
				t.Parallel()
				got, err := normalize.ParseName(file)
				if err != nil {
					t.Fatalf("ParseName(%q): %v", file, err)
				}
				assertDoc(t, got, normalizedDoc(d))
			})
		}
	}
}

// normalizedDoc is what a rendered name keeps of d.
func normalizedDoc(d normalize.Doc) normalize.Doc {
	want := normalize.Doc{
		Provider: normalize.Slug(d.Provider),
		Kind:     d.Kind,
		Date:     d.Date.UTC().Truncate(24 * time.Hour),
		Ref:      normalize.Slug(d.Ref),
		Version:  max(d.Version, 1),
	}
	if d.AmountCents != nil {
		want.AmountCents = cents(*d.AmountCents)
		want.Currency = upperASCII(d.Currency)
	}
	for _, r := range d.Ext {
		if r != '.' {
			want.Ext += string(upperToLower(r))
		}
	}
	return want
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func upperToLower(r rune) rune {
	if 'A' <= r && r <= 'Z' {
		return r - 'A' + 'a'
	}
	return r
}

// TestParseName_RejectsNonCompliant: inbox file names that are not ours, or
// that try to smuggle a path, are refused.
func TestParseName_RejectsNonCompliant(t *testing.T) {
	t.Parallel()
	tests := []string{
		"",
		"scan.pdf",
		"facture EDF mars.pdf",
		"2026-13-01_edf_invoice.pdf",     // month 13
		"2026-02-30_edf_invoice.pdf",     // no such day
		"26-03-14_edf_invoice.pdf",       // short year
		"2026-03-14.pdf",                 // date only
		"2026-03-14_edf.pdf",             // no kind
		"2026-03-14_edf_bogus.pdf",       // unknown kind label
		"2026-03-14_edf_tax-notice.pdf",  // DocKind id, not a label
		"2026-03-14_EDF_invoice.pdf",     // not a slug
		"2026-03-14_edf_invoice_A-B.pdf", // ref not a slug
		"2026-03-14__invoice.pdf",        // empty field
		"2026-03-14_edf_invoice_.pdf",    // trailing empty field
		"_2026-03-14_edf_invoice.pdf",    // leading separator
		"2026-03-14_edf_invoice_a_b.pdf", // too many fields
		"2026-03-14_edf_invoice_84-12EUR_a_b.pdf",
		"2026-03-14_edf_invoice_84-1EUR.pdf",   // amount needs two decimals
		"2026-03-14_edf_invoice_084-12EUR.pdf", // leading zero
		"2026-03-14_edf_invoice_v1.pdf",        // a final _v<n> is always a version; n must be >= 2
		"2026-03-14_edf_invoice_v0.pdf",
		"2026-03-14_edf_invoice.v2.pdf",      // dot in stem
		"2026-03-14_edf_invoice..pdf",        // empty extension segment
		"2026-03-14_edf_invoice.",            // empty extension
		"2026-03-14_edf_invoice.p-f",         // extension not alnum
		"2026-03-14_edf_invoice.abcdefghi",   // extension > 8
		".2026-03-14_edf_invoice.pdf",        // hidden file
		"../2026-03-14_edf_invoice.pdf",      // traversal
		"2026/2026-03-14_edf_invoice.pdf",    // path, not a name
		`x\2026-03-14_edf_invoice.pdf`,       // windows path
		"2026-03-14_edf_invoice\x00.pdf",     // NUL
		"2026-03-14_edf_invoice.pdf\x00.jpg", // NUL extension trick
		"2026-03-14_édf_invoice.pdf",         // non-ASCII
		"2026-03-14 _edf_invoice.pdf",        // space
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := normalize.ParseName(name)
			if !errors.Is(err, normalize.ErrNotCompliant) {
				t.Fatalf("ParseName(%q) err = %v, want ErrNotCompliant", name, err)
			}
			if !reflect.DeepEqual(got, normalize.Doc{}) {
				t.Fatalf("ParseName(%q) returned %+v alongside an error", name, got)
			}
		})
	}
	// "84-12eur" is a valid ref slug: it parses as a ref, never as an amount.
	t.Run("lowercase amount is a ref", func(t *testing.T) {
		t.Parallel()
		last := "2026-03-14_edf_invoice_84-12eur.pdf"
		got, err := normalize.ParseName(last)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", last, err)
		}
		if got.AmountCents != nil || got.Ref != "84-12eur" {
			t.Fatalf("ParseName(%q) = %+v, want Ref 84-12eur and no amount", last, got)
		}
	})
}

func assertDoc(t *testing.T, got, want normalize.Doc) {
	t.Helper()
	if (got.AmountCents == nil) != (want.AmountCents == nil) ||
		(got.AmountCents != nil && *got.AmountCents != *want.AmountCents) {
		t.Errorf("AmountCents = %v, want %v", deref(got.AmountCents), deref(want.AmountCents))
	}
	if !got.Date.Equal(want.Date) || got.Date.Location() != time.UTC {
		t.Errorf("Date = %v, want %v (UTC)", got.Date, want.Date)
	}
	got.AmountCents, want.AmountCents = nil, nil
	got.Date, want.Date = time.Time{}, time.Time{}
	if got != want {
		t.Errorf("Doc = %+v, want %+v", got, want)
	}
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
