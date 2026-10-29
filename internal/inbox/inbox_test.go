// Tests for package inbox (J0 task T22): the manual-import source. Spec:
// docs/spec.md "Normalization" > "Manual import (inbox/)" and "Factur-X";
// docs/adr/0007-j0-product-decisions.md D2 (no date guess; interactive asks
// via a Prompter; non-interactive leaves the file with a warning), D3
// (Factur-X provider = slug of the seller name), D4 (category "other" is
// rendered by normalize from an empty Category). Unix-only symlink and FIFO
// cases live in inbox_unix_test.go.
//
// Expected API (implementer: follow exactly):
//
//	// MaxFileSize is the default size cap of an inbox file (== facturx.MaxPDFSize).
//	const MaxFileSize = facturx.MaxPDFSize
//
//	// ErrChanged: the file at an Item's path is no longer the scanned one
//	// (other content, other size, or no longer a regular file).
//	var ErrChanged = errors.New("inbox: file changed since scan")
//
//	// Prompter is the consumer-side view of connector.Prompter used in
//	// interactive mode. file is the item path (slash-separated, relative to
//	// the inbox); guess holds what was inferred so far (Ext set, Kind set,
//	// Provider/Category/Date when known). ok=false means "skip this file".
//	type Prompter interface {
//		AskDoc(ctx context.Context, file string, guess normalize.Doc) (normalize.Doc, bool, error)
//	}
//
//	// ProviderDefaults is the manual-provider configuration ("manual:" and
//	// connector entries of the config): Category for every document of that
//	// provider; Kind for documents identified only by subfolder (zero = Invoice).
//	type ProviderDefaults struct {
//		Category string
//		Kind     connector.DocKind
//	}
//
//	type Options struct {
//		Prompter  Prompter                    // nil = non-interactive
//		Providers map[string]ProviderDefaults // keyed by provider id (slug)
//		MaxSize   int64                       // <= 0 means MaxFileSize
//	}
//
//	// Source names the highest-precedence source that identified an Item.
//	type Source string
//	const (
//		SourceFacturX   Source = "facturx"
//		SourceName      Source = "name"
//		SourceSubfolder Source = "subfolder"
//		SourcePrompt    Source = "prompt"
//	)
//
//	// Reason says why a path is not (or not cleanly) an Item.
//	type Reason string
//	const (
//		ReasonUnidentified     Reason = "unidentified"      // no provider+date; file stays
//		ReasonSkipped          Reason = "skipped"           // prompter answered ok=false; file stays
//		ReasonTooLarge         Reason = "too-large"         // > MaxSize; file stays, not read
//		ReasonNotRegular       Reason = "not-regular"       // symlink (file or dir), FIFO, device…; never followed or opened
//		ReasonInvalidSubfolder Reason = "invalid-subfolder" // subfolder name refused; its files stay
//		ReasonNested           Reason = "nested"            // directory below a provider subfolder; not descended
//		ReasonInvalidFacturX   Reason = "invalid-facturx"   // Factur-X present but refused (unsafe XML…); other sources used
//	)
//
//	// Warning carries no file content and no error text, only a path and a reason.
//	type Warning struct {
//		Path   string // slash-separated, relative to the inbox
//		Reason Reason
//	}
//
//	type Item struct {
//		Path   string        // slash-separated, relative to the inbox ("impots/avis.pdf")
//		Size   int64
//		SHA256 [32]byte      // of the scanned content
//		Doc    normalize.Doc // inferred; Version always 0 (dedup decides)
//		Source Source
//	}
//
//	type Result struct {
//		Items    []Item    // sorted by Path
//		Warnings []Warning // sorted by Path, at most one per path
//	}
//	// A path that is not an Item gets the reason it stays (unidentified,
//	// skipped, too-large…), never ReasonInvalidFacturX, which is only
//	// reported alongside an Item.
//
//	// New opens the existing inbox directory dir (os.Root confinement, as
//	// fsx). It does not create it: a missing dir wraps fs.ErrNotExist.
//	func New(dir string, opts Options) (*Inbox, error)
//	func (ib *Inbox) Close() error // later calls fail
//
//	// Scan lists dir and its direct subfolders (one level), never following
//	// a symlink and never opening a non-regular file. Hidden entries (name
//	// starting with '.') are ignored silently. A subfolder is refused
//	// (ReasonInvalidSubfolder) when fsx.SafeName(name) != name or
//	// normalize.Slug(name) == ""; otherwise its provider id is Slug(name).
//	// Inference per file, field by field, in precedence order:
//	//   1. Factur-X (facturx.Extract): Provider = Slug(SellerName) (D3),
//	//      Date = IssueDate, AmountCents/Currency = GrandTotal, Ref =
//	//      Slug(Number), Kind = connector.Invoice. ErrNoFacturX/ErrInvalidPDF
//	//      are silent; other extraction errors add ReasonInvalidFacturX and
//	//      the file is inferred from the other sources.
//	//   2. compliant name (normalize.ParseName of the base name).
//	//   3. subfolder: Provider when still empty, Kind from ProviderDefaults.
//	//   4. a single ISO date (YYYY-MM-DD, valid calendar date, not adjacent
//	//      to other digits) in the base name, when Date is still empty; two
//	//      different dates are ambiguous and give no date. Never mtime or "today".
//	// Kind defaults to Invoice; Ext = lowercased extension of the file;
//	// Category = Providers[Provider].Category ("" when unknown, D4);
//	// Version = 0. A file is identified when it has a Date and a Provider, or
//	// when its name is compliant (the grammar allows no provider).
//	// Unidentified: non-interactive -> ReasonUnidentified; interactive ->
//	// Prompter.AskDoc; its answer gets Provider = Slug(answer.Provider),
//	// Ext forced to the file's, Version 0, Category from Providers when
//	// empty; an answer without Date, Provider or valid Kind ->
//	// ReasonUnidentified; ok=false -> ReasonSkipped. The Prompter is called
//	// only for unidentified regular files. A Prompter error or ctx
//	// cancellation aborts Scan with an error wrapping it. Scan never
//	// modifies, moves or removes anything.
//	func (ib *Inbox) Scan(ctx context.Context) (Result, error)
//
//	// Open returns the item's content, read through the confined root
//	// without following symlinks. If the file is no longer the scanned one,
//	// Open or a Read (at the latest the one returning EOF) fails with an
//	// error wrapping ErrChanged. Paths that are not local (absolute, "..")
//	// are refused.
//	func (ib *Inbox) Open(ctx context.Context, it Item) (io.ReadCloser, error)
//
//	// Done removes the item's file after successful filing, only if it is
//	// still the scanned regular file (else ErrChanged, nothing removed).
//	// Missing: wraps fs.ErrNotExist. Never removes a subfolder. Paths that
//	// are not local are refused.
//	func (ib *Inbox) Done(ctx context.Context, it Item) error
package inbox_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// --- synthetic Factur-X ------------------------------------------------------

const (
	nsRSM = "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
	nsRAM = "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100"
	nsUDT = "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100"
)

// ciiXML builds a synthetic CII document; empty fields are omitted.
func ciiXML(number, date, sellerName, currency, total string) []byte {
	s := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<rsm:CrossIndustryInvoice xmlns:rsm="` + nsRSM + `" xmlns:ram="` + nsRAM + `" xmlns:udt="` + nsUDT + `">` +
		`<rsm:ExchangedDocumentContext><ram:GuidelineSpecifiedDocumentContextParameter><ram:ID>urn:factur-x.eu:1p0:minimum</ram:ID></ram:GuidelineSpecifiedDocumentContextParameter></rsm:ExchangedDocumentContext>` +
		`<rsm:ExchangedDocument>`
	if number != "" {
		s += `<ram:ID>` + number + `</ram:ID>`
	}
	s += `<ram:TypeCode>380</ram:TypeCode>`
	if date != "" {
		s += `<ram:IssueDateTime><udt:DateTimeString format="102">` + date + `</udt:DateTimeString></ram:IssueDateTime>`
	}
	s += `</rsm:ExchangedDocument><rsm:SupplyChainTradeTransaction><ram:ApplicableHeaderTradeAgreement>`
	if sellerName != "" {
		s += `<ram:SellerTradeParty><ram:Name>` + sellerName + `</ram:Name></ram:SellerTradeParty>`
	}
	s += `<ram:BuyerTradeParty><ram:Name>Client Exemple</ram:Name></ram:BuyerTradeParty>` +
		`</ram:ApplicableHeaderTradeAgreement><ram:ApplicableHeaderTradeDelivery/><ram:ApplicableHeaderTradeSettlement>`
	if currency != "" {
		s += `<ram:InvoiceCurrencyCode>` + currency + `</ram:InvoiceCurrencyCode>`
	}
	s += `<ram:SpecifiedTradeSettlementHeaderMonetarySummation>`
	if total != "" {
		s += `<ram:GrandTotalAmount>` + total + `</ram:GrandTotalAmount>`
	}
	s += `<ram:DuePayableAmount>1.00</ram:DuePayableAmount></ram:SpecifiedTradeSettlementHeaderMonetarySummation>` +
		`</ram:ApplicableHeaderTradeSettlement></rsm:SupplyChainTradeTransaction></rsm:CrossIndustryInvoice>`
	return []byte(s)
}

// facturXPDF embeds xml as factur-x.xml in a synthetic PDF.
func facturXPDF(t *testing.T, xml []byte) []byte {
	t.Helper()
	return buildPDF(t, synthAttachment{file: "factur-x.xml", data: xml})
}

// fullFacturX is a complete synthetic invoice: seller "Fournisseur Exemple
// SAS", 2026-03-14, 84.12 EUR, number FA-2026-0001.
func fullFacturX(t *testing.T) []byte {
	t.Helper()
	return facturXPDF(t, ciiXML("FA-2026-0001", "20260314", "Fournisseur Exemple SAS", "EUR", "84.12"))
}

// plainPDF is a synthetic PDF without attachment, unique per tag.
func plainPDF(t *testing.T, tag string) []byte {
	t.Helper()
	return append(buildPDF(t), []byte("% "+tag+"\n")...)
}

// --- fake prompter -----------------------------------------------------------

type ask struct {
	file  string
	guess string // docString(guess)
}

type answer struct {
	doc normalize.Doc
	ok  bool
	err error
}

// fakePrompter records every AskDoc call and replies from answers (keyed by
// file); a file without an answer fails the test.
type fakePrompter struct {
	t       *testing.T
	mu      sync.Mutex
	answers map[string]answer
	asks    []ask
	hook    func() // optional, run before replying
}

func (p *fakePrompter) AskDoc(_ context.Context, file string, guess normalize.Doc) (normalize.Doc, bool, error) {
	p.mu.Lock()
	p.asks = append(p.asks, ask{file: file, guess: docString(guess)})
	a, found := p.answers[file]
	hook := p.hook
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if !found {
		p.t.Errorf("unexpected AskDoc(%q)", file)
		return normalize.Doc{}, false, nil
	}
	return a.doc, a.ok, a.err
}

func (p *fakePrompter) calls() []ask {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.asks)
}

// --- helpers -----------------------------------------------------------------

// day returns a date of 2026 at 00:00 UTC.
func day(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }

// docString renders a Doc deterministically for comparisons and diffs.
func docString(d normalize.Doc) string {
	date := "-"
	if !d.Date.IsZero() {
		date = d.Date.UTC().Format(time.DateOnly)
		if !d.Date.Equal(d.Date.UTC().Truncate(24 * time.Hour)) {
			date += "+" + d.Date.UTC().Format(time.TimeOnly)
		}
	}
	amount := "-"
	if d.AmountCents != nil {
		amount = fmt.Sprintf("%d", *d.AmountCents)
	}
	return fmt.Sprintf("provider=%q category=%q kind=%v date=%s amount=%s currency=%q ref=%q ext=%q version=%d",
		d.Provider, d.Category, d.Kind, date, amount, d.Currency, d.Ref, d.Ext, d.Version)
}

var providers = map[string]inbox.ProviderDefaults{
	"impots":          {Category: "housing", Kind: connector.TaxNotice},
	"edf":             {Category: "housing"},
	"bouyguestelecom": {Category: "internet"},
}

// makeInbox creates base/out/inbox holding files (slash paths relative to
// the inbox; parent directories created 0700) and returns the inbox path.
func makeInbox(t *testing.T, files map[string][]byte) (dir string) {
	t.Helper()
	base := t.TempDir()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	for _, d := range []string{"out", "out/inbox"} {
		if err := r.MkdirPrivate(d); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	for name, data := range files {
		full := path.Join("out/inbox", name)
		if err := mkdirAll(r, path.Dir(full)); err != nil {
			t.Fatalf("mkdir for %q: %v", name, err)
		}
		if err := r.WriteAtomic(t.Context(), full, data); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	return filepath.Join(base, "out", "inbox")
}

func mkdirAll(r *fsx.Root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	if _, err := r.Lstat(dir); err == nil {
		return nil
	}
	if err := mkdirAll(r, path.Dir(dir)); err != nil {
		return err
	}
	return r.MkdirPrivate(dir)
}

// writeIn writes (or atomically replaces) one file under dir.
func writeIn(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := mkdirAll(r, path.Dir(name)); err != nil {
		t.Fatalf("mkdir for %q: %v", name, err)
	}
	if err := r.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatalf("write %q: %v", name, err)
	}
}

func newInbox(t *testing.T, dir string, opts inbox.Options) *inbox.Inbox {
	t.Helper()
	ib, err := inbox.New(dir, opts)
	if err != nil {
		t.Fatalf("New(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = ib.Close() })
	return ib
}

func scan(t *testing.T, ib *inbox.Inbox) inbox.Result {
	t.Helper()
	res, err := ib.Scan(t.Context())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return res
}

// snapshot lists every entry under dir (relative slash path -> content, or
// "<dir>" / "<symlink:target>") to prove nothing was modified. It reads
// through os.Root so a symlink can never make it read outside dir.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root %s: %v", dir, err)
	}
	defer func() { _ = root.Close() }()
	fsys := root.FS()
	out := map[string]string{}
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(fsys, p)
			if err != nil {
				return err
			}
			out[p] = "<symlink:" + target + ">"
		case d.IsDir():
			out[p] = "<dir>"
		case d.Type().IsRegular():
			b, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			out[p] = string(b)
		default:
			out[p] = "<" + d.Type().String() + ">"
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func wantSnapshot(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	if after := snapshot(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("directory %s modified\nbefore: %v\n after: %v", dir, keys(before), keys(after))
	}
}

func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

type itemView struct {
	path   string
	source inbox.Source
	doc    string
}

func itemViews(items []inbox.Item) []itemView {
	out := make([]itemView, 0, len(items))
	for _, it := range items {
		out = append(out, itemView{path: it.Path, source: it.Source, doc: docString(it.Doc)})
	}
	return out
}

// checkItemContent verifies Size and SHA256 against the files written.
func checkItemContent(t *testing.T, items []inbox.Item, files map[string][]byte) {
	t.Helper()
	for _, it := range items {
		data, ok := files[it.Path]
		if !ok {
			t.Errorf("item %q is not one of the written files", it.Path)
			continue
		}
		if it.Size != int64(len(data)) {
			t.Errorf("item %q: Size = %d, want %d", it.Path, it.Size, len(data))
		}
		if it.SHA256 != sha256.Sum256(data) {
			t.Errorf("item %q: SHA256 mismatch", it.Path)
		}
	}
}

func readAll(t *testing.T, ib *inbox.Inbox, it inbox.Item) ([]byte, error) {
	t.Helper()
	rc, err := ib.Open(t.Context(), it)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

func findItem(t *testing.T, res inbox.Result, p string) inbox.Item {
	t.Helper()
	for _, it := range res.Items {
		if it.Path == p {
			return it
		}
	}
	t.Fatalf("no item %q in %v", p, itemViews(res.Items))
	return inbox.Item{}
}

// --- TestInfer -----------------------------------------------------------------

func TestInfer(t *testing.T) {
	t.Parallel()

	const (
		fxDoc = `provider="fournisseur-exemple-sas" category="" kind=invoice date=2026-03-14 amount=8412 currency="EUR" ref="fa-2026-0001" ext="pdf" version=0`
	)
	type tcase struct {
		name         string
		files        func(t *testing.T) map[string][]byte
		prompter     map[string]answer // nil = non-interactive
		wantItems    []itemView
		wantWarnings []inbox.Warning
		wantAsks     []ask
	}
	one := func(p string, data func(t *testing.T) []byte) func(t *testing.T) map[string][]byte {
		return func(t *testing.T) map[string][]byte { return map[string][]byte{p: data(t)} }
	}
	plain := func(tag string) func(t *testing.T) []byte {
		return func(t *testing.T) []byte { return plainPDF(t, tag) }
	}

	tests := []tcase{
		// 1. Factur-X beats everything else, field by field.
		{
			name:      "factur-x beats a compliant file name",
			files:     one("2026-01-01_autre-fournisseur_receipt_ref9.pdf", fullFacturX),
			wantItems: []itemView{{"2026-01-01_autre-fournisseur_receipt_ref9.pdf", inbox.SourceFacturX, fxDoc}},
		},
		{
			name:      "factur-x beats the subfolder, category of the seller (unknown, D4)",
			files:     one("impots/scan.pdf", fullFacturX),
			wantItems: []itemView{{"impots/scan.pdf", inbox.SourceFacturX, fxDoc}},
		},
		{
			name: "factur-x without seller: provider from subfolder, rest from xml",
			files: one("impots/scan.pdf", func(t *testing.T) []byte {
				return facturXPDF(t, ciiXML("FA-2026-0002", "20261002", "", "EUR", "1234.00"))
			}),
			wantItems: []itemView{{
				"impots/scan.pdf", inbox.SourceFacturX,
				`provider="impots" category="housing" kind=invoice date=2026-10-02 amount=123400 currency="EUR" ref="fa-2026-0002" ext="pdf" version=0`,
			}},
		},
		{
			name: "factur-x seller that slugs to empty falls back to subfolder",
			files: one("edf/scan.pdf", func(t *testing.T) []byte {
				return facturXPDF(t, ciiXML("N1", "20260314", "???", "EUR", "10.00"))
			}),
			wantItems: []itemView{{
				"edf/scan.pdf", inbox.SourceFacturX,
				`provider="edf" category="housing" kind=invoice date=2026-03-14 amount=1000 currency="EUR" ref="n1" ext="pdf" version=0`,
			}},
		},
		{
			name: "factur-x without date: date from compliant name, seller from xml",
			files: one("2026-05-01_autre_invoice.pdf", func(t *testing.T) []byte {
				return facturXPDF(t, ciiXML("FA-9", "", "Fournisseur Exemple SAS", "EUR", "5.00"))
			}),
			wantItems: []itemView{{
				"2026-05-01_autre_invoice.pdf", inbox.SourceFacturX,
				`provider="fournisseur-exemple-sas" category="" kind=invoice date=2026-05-01 amount=500 currency="EUR" ref="fa-9" ext="pdf" version=0`,
			}},
		},
		{
			name: "factur-x seller with accents is slugged (D3)",
			files: one("x.pdf", func(t *testing.T) []byte {
				return facturXPDF(t, ciiXML("FA-1", "20260314", "Électricité Exemple &amp; Fils", "", ""))
			}),
			wantItems: []itemView{{
				"x.pdf", inbox.SourceFacturX,
				`provider="electricite-exemple-fils" category="" kind=invoice date=2026-03-14 amount=- currency="" ref="fa-1" ext="pdf" version=0`,
			}},
		},
		{
			name: "unsafe factur-x xml is ignored with a warning, the compliant name is used",
			files: one("2026-03-14_edf_invoice.pdf", func(t *testing.T) []byte {
				return facturXPDF(t, []byte(`<?xml version="1.0"?><!DOCTYPE rsm:CrossIndustryInvoice [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><rsm:CrossIndustryInvoice xmlns:rsm="`+nsRSM+`">&xxe;</rsm:CrossIndustryInvoice>`))
			}),
			wantItems: []itemView{{
				"2026-03-14_edf_invoice.pdf", inbox.SourceName,
				`provider="edf" category="housing" kind=invoice date=2026-03-14 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
			wantWarnings: []inbox.Warning{{Path: "2026-03-14_edf_invoice.pdf", Reason: inbox.ReasonInvalidFacturX}},
		},

		// 2. Compliant name.
		{
			name:  "compliant name at the root, category from config",
			files: one("2026-03-14_edf_invoice_84-12EUR_10234567.pdf", plain("a")),
			wantItems: []itemView{{
				"2026-03-14_edf_invoice_84-12EUR_10234567.pdf", inbox.SourceName,
				`provider="edf" category="housing" kind=invoice date=2026-03-14 amount=8412 currency="EUR" ref="10234567" ext="pdf" version=0`,
			}},
		},
		{
			name:  "compliant name with a version suffix: version left to dedup",
			files: one("2026-03-14_edf_invoice_10234567_v2.pdf", plain("b")),
			wantItems: []itemView{{
				"2026-03-14_edf_invoice_10234567_v2.pdf", inbox.SourceName,
				`provider="edf" category="housing" kind=invoice date=2026-03-14 amount=- currency="" ref="10234567" ext="pdf" version=0`,
			}},
		},
		{
			name:  "compliant name without provider is enough",
			files: one("2026-06-21_receipt_client-lunch-lyon.jpg", func(*testing.T) []byte { return []byte("synthetic jpeg bytes") }),
			wantItems: []itemView{{
				"2026-06-21_receipt_client-lunch-lyon.jpg", inbox.SourceName,
				`provider="" category="" kind=receipt date=2026-06-21 amount=- currency="" ref="client-lunch-lyon" ext="jpg" version=0`,
			}},
		},
		{
			name:  "compliant name without provider takes the subfolder",
			files: one("impots/2026-10-02_property-tax-notice.pdf", plain("c")),
			wantItems: []itemView{{
				"impots/2026-10-02_property-tax-notice.pdf", inbox.SourceName,
				`provider="impots" category="housing" kind=tax-notice date=2026-10-02 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:  "provider in a compliant name beats the subfolder",
			files: one("impots/2026-03-14_bouyguestelecom_invoice.pdf", plain("d")),
			wantItems: []itemView{{
				"impots/2026-03-14_bouyguestelecom_invoice.pdf", inbox.SourceName,
				`provider="bouyguestelecom" category="internet" kind=invoice date=2026-03-14 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},

		// 3. Subfolder + date in the name.
		{
			name:  "subfolder plus ISO date in name, kind from provider defaults",
			files: one("impots/avis-taxe-fonciere-2026-10-02.pdf", plain("e")),
			wantItems: []itemView{{
				"impots/avis-taxe-fonciere-2026-10-02.pdf", inbox.SourceSubfolder,
				`provider="impots" category="housing" kind=tax-notice date=2026-10-02 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:  "accented subfolder is slugged, extension lowercased",
			files: one("Impôts/avis 2026-10-02.PDF", plain("f")),
			wantItems: []itemView{{
				"Impôts/avis 2026-10-02.PDF", inbox.SourceSubfolder,
				`provider="impots" category="housing" kind=tax-notice date=2026-10-02 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:  "subfolder unknown to config: category empty (other), kind invoice",
			files: one("wecasa/facture-2026-04-03.pdf", plain("g")),
			wantItems: []itemView{{
				"wecasa/facture-2026-04-03.pdf", inbox.SourceSubfolder,
				`provider="wecasa" category="" kind=invoice date=2026-04-03 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:  "same date twice is not ambiguous",
			files: one("edf/2026-03-14-copie-2026-03-14.pdf", plain("h")),
			wantItems: []itemView{{
				"edf/2026-03-14-copie-2026-03-14.pdf", inbox.SourceSubfolder,
				`provider="edf" category="housing" kind=invoice date=2026-03-14 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},

		// 4. Not identified, non-interactive: stays with a warning (D2).
		{
			name:         "subfolder only, non-interactive: stays with a warning",
			files:        one("impots/avis.pdf", plain("i")),
			wantWarnings: []inbox.Warning{{Path: "impots/avis.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "subfolder plus impossible calendar date: no date",
			files:        one("impots/releve-2026-02-30.pdf", plain("j")),
			wantWarnings: []inbox.Warning{{Path: "impots/releve-2026-02-30.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "subfolder plus two different dates: ambiguous, no guess",
			files:        one("edf/du-2026-01-01-au-2026-02-01.pdf", plain("k")),
			wantWarnings: []inbox.Warning{{Path: "edf/du-2026-01-01-au-2026-02-01.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "subfolder plus digits glued to a date: not a date",
			files:        one("edf/n12026-03-149.pdf", plain("l")),
			wantWarnings: []inbox.Warning{{Path: "edf/n12026-03-149.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "unknown file at the root stays",
			files:        one("scan.pdf", plain("m")),
			wantWarnings: []inbox.Warning{{Path: "scan.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "date but no provider at the root stays",
			files:        one("scan-2026-03-01.pdf", plain("n")),
			wantWarnings: []inbox.Warning{{Path: "scan-2026-03-01.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:         "non-pdf unknown file stays",
			files:        one("notes.txt", func(*testing.T) []byte { return []byte("synthetic note") }),
			wantWarnings: []inbox.Warning{{Path: "notes.txt", Reason: inbox.ReasonUnidentified}},
		},

		// 5. Interactive: the Prompter completes what is missing.
		{
			name:  "interactive subfolder only: prompter answer is normalized",
			files: one("impots/avis.pdf", plain("o")),
			prompter: map[string]answer{"impots/avis.pdf": {ok: true, doc: normalize.Doc{
				Provider: "Impôts", Kind: connector.TaxNotice, Date: day(10, 2), Ext: "exe", Version: 5,
			}}},
			wantAsks: []ask{{
				"impots/avis.pdf",
				`provider="impots" category="housing" kind=tax-notice date=- amount=- currency="" ref="" ext="pdf" version=0`,
			}},
			wantItems: []itemView{{
				"impots/avis.pdf", inbox.SourcePrompt,
				`provider="impots" category="housing" kind=tax-notice date=2026-10-02 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:  "interactive unknown root file: guess carries the date found",
			files: one("scan-2026-03-01.pdf", plain("p")),
			prompter: map[string]answer{"scan-2026-03-01.pdf": {ok: true, doc: normalize.Doc{
				Provider: "bouyguestelecom", Kind: connector.Invoice, Date: day(3, 1),
			}}},
			wantAsks: []ask{{
				"scan-2026-03-01.pdf",
				`provider="" category="" kind=invoice date=2026-03-01 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
			wantItems: []itemView{{
				"scan-2026-03-01.pdf", inbox.SourcePrompt,
				`provider="bouyguestelecom" category="internet" kind=invoice date=2026-03-01 amount=- currency="" ref="" ext="pdf" version=0`,
			}},
		},
		{
			name:         "interactive skip: stays with a warning",
			files:        one("scan.pdf", plain("q")),
			prompter:     map[string]answer{"scan.pdf": {ok: false}},
			wantAsks:     []ask{{"scan.pdf", `provider="" category="" kind=invoice date=- amount=- currency="" ref="" ext="pdf" version=0`}},
			wantWarnings: []inbox.Warning{{Path: "scan.pdf", Reason: inbox.ReasonSkipped}},
		},
		{
			name:  "interactive answer without date: still unidentified, no guess",
			files: one("impots/avis.pdf", plain("r")),
			prompter: map[string]answer{"impots/avis.pdf": {ok: true, doc: normalize.Doc{
				Provider: "impots", Kind: connector.TaxNotice,
			}}},
			wantAsks: []ask{{
				"impots/avis.pdf",
				`provider="impots" category="housing" kind=tax-notice date=- amount=- currency="" ref="" ext="pdf" version=0`,
			}},
			wantWarnings: []inbox.Warning{{Path: "impots/avis.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:  "interactive answer whose provider slugs to empty: unidentified",
			files: one("scan.pdf", plain("s")),
			prompter: map[string]answer{"scan.pdf": {ok: true, doc: normalize.Doc{
				Provider: "../..", Kind: connector.Invoice, Date: day(3, 1),
			}}},
			wantAsks:     []ask{{"scan.pdf", `provider="" category="" kind=invoice date=- amount=- currency="" ref="" ext="pdf" version=0`}},
			wantWarnings: []inbox.Warning{{Path: "scan.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name:  "interactive answer with an invalid kind: unidentified",
			files: one("scan.pdf", plain("t")),
			prompter: map[string]answer{"scan.pdf": {ok: true, doc: normalize.Doc{
				Provider: "edf", Date: day(3, 1),
			}}},
			wantAsks:     []ask{{"scan.pdf", `provider="" category="" kind=invoice date=- amount=- currency="" ref="" ext="pdf" version=0`}},
			wantWarnings: []inbox.Warning{{Path: "scan.pdf", Reason: inbox.ReasonUnidentified}},
		},
		{
			name: "interactive: identified files are never asked about",
			files: func(t *testing.T) map[string][]byte {
				return map[string][]byte{
					"2026-03-14_edf_invoice.pdf":   plainPDF(t, "u"),
					"impots/avis-2026-10-02.pdf":   plainPDF(t, "v"),
					"facturx.pdf":                  fullFacturX(t),
					"2026-06-21_receipt_lunch.jpg": []byte("synthetic jpeg"),
				}
			},
			prompter: map[string]answer{},
			wantItems: []itemView{
				{"2026-03-14_edf_invoice.pdf", inbox.SourceName, `provider="edf" category="housing" kind=invoice date=2026-03-14 amount=- currency="" ref="" ext="pdf" version=0`},
				{"2026-06-21_receipt_lunch.jpg", inbox.SourceName, `provider="" category="" kind=receipt date=2026-06-21 amount=- currency="" ref="lunch" ext="jpg" version=0`},
				{"facturx.pdf", inbox.SourceFacturX, fxDoc},
				{"impots/avis-2026-10-02.pdf", inbox.SourceSubfolder, `provider="impots" category="housing" kind=tax-notice date=2026-10-02 amount=- currency="" ref="" ext="pdf" version=0`},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files := tt.files(t)
			dir := makeInbox(t, files)
			before := snapshot(t, dir)

			opts := inbox.Options{Providers: providers}
			var fp *fakePrompter
			if tt.prompter != nil {
				fp = &fakePrompter{t: t, answers: tt.prompter}
				opts.Prompter = fp
			}
			res := scan(t, newInbox(t, dir, opts))

			if got := itemViews(res.Items); !reflect.DeepEqual(got, nonNil(tt.wantItems)) {
				t.Errorf("items mismatch\n got: %+v\nwant: %+v", got, tt.wantItems)
			}
			checkItemContent(t, res.Items, files)
			if !reflect.DeepEqual(nonNilW(res.Warnings), nonNilW(tt.wantWarnings)) {
				t.Errorf("warnings = %+v, want %+v", res.Warnings, tt.wantWarnings)
			}
			if fp != nil {
				if got := fp.calls(); !reflect.DeepEqual(nonNilA(got), nonNilA(tt.wantAsks)) {
					t.Errorf("prompter asks\n got: %+v\nwant: %+v", got, tt.wantAsks)
				}
			}
			wantSnapshot(t, dir, before) // Scan never touches the inbox
		})
	}
}

func nonNil(v []itemView) []itemView {
	if v == nil {
		return []itemView{}
	}
	return v
}

func nonNilW(v []inbox.Warning) []inbox.Warning {
	if v == nil {
		return []inbox.Warning{}
	}
	return v
}

func nonNilA(v []ask) []ask {
	if v == nil {
		return []ask{}
	}
	return v
}

// --- Scan --------------------------------------------------------------------

func TestNew_MissingDir(t *testing.T) {
	t.Parallel()
	_, err := inbox.New(filepath.Join(t.TempDir(), "missing"), inbox.Options{})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("New(missing) error = %v, want fs.ErrNotExist", err)
	}
}

func TestMaxFileSize_IsFacturXCap(t *testing.T) {
	t.Parallel()
	if inbox.MaxFileSize != facturx.MaxPDFSize {
		t.Fatalf("MaxFileSize = %d, want facturx.MaxPDFSize (%d)", inbox.MaxFileSize, facturx.MaxPDFSize)
	}
}

func TestScan_EmptyInbox(t *testing.T) {
	t.Parallel()
	res := scan(t, newInbox(t, makeInbox(t, nil), inbox.Options{}))
	if len(res.Items) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("empty inbox: %+v", res)
	}
}

func TestScan_SortedAndRepeatable(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"edf/2026-03-14_edf_invoice.pdf": plainPDF(t, "1"),
		"2026-03-15_edf_invoice.pdf":     plainPDF(t, "2"),
		"b-unknown.pdf":                  plainPDF(t, "3"),
		"a-unknown.pdf":                  plainPDF(t, "4"),
		"bouyguestelecom/2026-01-01.pdf": plainPDF(t, "5"),
	}
	ib := newInbox(t, makeInbox(t, files), inbox.Options{Providers: providers})
	first := scan(t, ib)
	var paths []string
	for _, it := range first.Items {
		paths = append(paths, it.Path)
	}
	wantPaths := []string{"2026-03-15_edf_invoice.pdf", "bouyguestelecom/2026-01-01.pdf", "edf/2026-03-14_edf_invoice.pdf"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("item paths = %v, want %v", paths, wantPaths)
	}
	wantW := []inbox.Warning{
		{Path: "a-unknown.pdf", Reason: inbox.ReasonUnidentified},
		{Path: "b-unknown.pdf", Reason: inbox.ReasonUnidentified},
	}
	if !reflect.DeepEqual(first.Warnings, wantW) {
		t.Fatalf("warnings = %+v, want %+v", first.Warnings, wantW)
	}
	if second := scan(t, ib); !reflect.DeepEqual(first, second) {
		t.Fatalf("second scan differs\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

func TestScan_IgnoresHiddenEntries(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		".hidden-2026-03-14_edf_invoice.pdf": plainPDF(t, "1"),
		".fsx-tmp-123":                       []byte("in-flight temp"),
		".git/2026-03-14_edf_invoice.pdf":    plainPDF(t, "2"),
		"edf/.DS_Store":                      []byte("synthetic"),
		"2026-03-14_edf_invoice.pdf":         plainPDF(t, "3"),
	}
	dir := makeInbox(t, files)
	fp := &fakePrompter{t: t, answers: map[string]answer{}}
	res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp}))
	if len(res.Items) != 1 || res.Items[0].Path != "2026-03-14_edf_invoice.pdf" {
		t.Fatalf("items = %+v, want only the visible file", itemViews(res.Items))
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("hidden entries must be ignored silently, got warnings %+v", res.Warnings)
	}
	if n := len(fp.calls()); n != 0 {
		t.Fatalf("prompter called %d times for hidden entries", n)
	}
}

func TestScan_NestedDirectoriesNotDescended(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"impots/2026/2026-10-02_impots_tax-notice.pdf": plainPDF(t, "1"),
		"impots/2026-10-01_impots_tax-notice.pdf":      plainPDF(t, "2"),
	}
	dir := makeInbox(t, files)
	before := snapshot(t, dir)
	fp := &fakePrompter{t: t, answers: map[string]answer{}}
	res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp}))
	if len(res.Items) != 1 || res.Items[0].Path != "impots/2026-10-01_impots_tax-notice.pdf" {
		t.Fatalf("items = %+v, want only the first-level file", itemViews(res.Items))
	}
	want := []inbox.Warning{{Path: "impots/2026", Reason: inbox.ReasonNested}}
	if !reflect.DeepEqual(res.Warnings, want) {
		t.Fatalf("warnings = %+v, want %+v", res.Warnings, want)
	}
	if n := len(fp.calls()); n != 0 {
		t.Fatalf("prompter called %d times", n)
	}
	wantSnapshot(t, dir, before)
}

// TestScan_RejectsTraversalSubfolder: a subfolder name becomes a provider id
// and then a path segment of the output; names that are not already safe are
// refused as a whole (files stay, never asked about, never items).
func TestScan_RejectsTraversalSubfolder(t *testing.T) {
	t.Parallel()

	// Names starting with '.' (including ".." tricks) are hidden and ignored
	// silently: see TestScan_IgnoresHiddenEntries.
	names := []string{
		"___",  // slugs to ""
		"a..b", // dot run (SafeName collapses it)
		"-.-",  // slugs to ""
	}
	if runtime.GOOS != "windows" {
		names = append(names,
			`x\..\..\evil`, // Windows separators and dot-dot
			`a\..\outside`, // idem
			"x.",           // trailing dot
			"NUL",          // Windows device name
			"evil\nname",   // control character
			"a:b",          // Windows-forbidden character
			"tab\tname",    // control character
			"bad\x7fname",  // DEL
			"pipe|name",    // Windows-forbidden character
			"star*name",    // Windows-forbidden character
			"quote\"name",  // Windows-forbidden character
			"lt<gt>name",   // Windows-forbidden character
			"question?mrk", // Windows-forbidden character
		)
	}
	for _, sub := range names {
		t.Run(fmt.Sprintf("%q", sub), func(t *testing.T) {
			t.Parallel()
			files := map[string][]byte{
				sub + "/avis-2026-10-02.pdf":         plainPDF(t, "1"),
				sub + "/2026-03-14_edf_invoice.pdf":  plainPDF(t, "2"),
				sub + "/scan.pdf":                    plainPDF(t, "3"),
				"2026-03-14_edf_invoice_control.pdf": plainPDF(t, "4"),
			}
			dir := makeInbox(t, files)
			before := snapshot(t, dir)
			fp := &fakePrompter{t: t, answers: map[string]answer{}}
			ib := newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp})
			res := scan(t, ib)

			if len(res.Items) != 1 || res.Items[0].Path != "2026-03-14_edf_invoice_control.pdf" {
				t.Fatalf("items = %+v, want only the root control file", itemViews(res.Items))
			}
			want := []inbox.Warning{{Path: sub, Reason: inbox.ReasonInvalidSubfolder}}
			if !reflect.DeepEqual(res.Warnings, want) {
				t.Fatalf("warnings = %+v, want %+v", res.Warnings, want)
			}
			if n := len(fp.calls()); n != 0 {
				t.Fatalf("prompter asked %d times about files of a refused subfolder", n)
			}
			wantSnapshot(t, dir, before)
		})
	}
}

func TestScan_SizeCap(t *testing.T) {
	t.Parallel()

	t.Run("custom cap", func(t *testing.T) {
		t.Parallel()
		at := bytes.Repeat([]byte("a"), 1024)
		over := bytes.Repeat([]byte("b"), 1025)
		files := map[string][]byte{
			"2026-03-14_edf_invoice_at.pdf":   at,
			"2026-03-14_edf_invoice_over.pdf": over,
			"unknown-over.pdf":                over,
		}
		dir := makeInbox(t, files)
		before := snapshot(t, dir)
		fp := &fakePrompter{t: t, answers: map[string]answer{}}
		res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp, MaxSize: 1024}))
		if len(res.Items) != 1 || res.Items[0].Path != "2026-03-14_edf_invoice_at.pdf" {
			t.Fatalf("items = %+v, want only the file at the cap", itemViews(res.Items))
		}
		checkItemContent(t, res.Items, files)
		want := []inbox.Warning{
			{Path: "2026-03-14_edf_invoice_over.pdf", Reason: inbox.ReasonTooLarge},
			{Path: "unknown-over.pdf", Reason: inbox.ReasonTooLarge},
		}
		if !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("warnings = %+v, want %+v", res.Warnings, want)
		}
		if n := len(fp.calls()); n != 0 {
			t.Fatalf("prompter asked %d times about oversized files", n)
		}
		wantSnapshot(t, dir, before)
	})

	t.Run("default cap", func(t *testing.T) {
		t.Parallel()
		dir := makeInbox(t, map[string][]byte{"2026-03-14_edf_invoice.pdf": []byte("x")})
		// Grow the file sparsely to one byte over the default cap.
		if err := os.Truncate(filepath.Join(dir, "2026-03-14_edf_invoice.pdf"), inbox.MaxFileSize+1); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers}))
		want := []inbox.Warning{{Path: "2026-03-14_edf_invoice.pdf", Reason: inbox.ReasonTooLarge}}
		if len(res.Items) != 0 || !reflect.DeepEqual(res.Warnings, want) {
			t.Fatalf("result = items %+v warnings %+v, want only %+v", itemViews(res.Items), res.Warnings, want)
		}
	})
}

func TestScan_ContextCanceled(t *testing.T) {
	t.Parallel()
	dir := makeInbox(t, map[string][]byte{"scan.pdf": plainPDF(t, "1"), "2026-03-14_edf_invoice.pdf": plainPDF(t, "2")})
	before := snapshot(t, dir)
	fp := &fakePrompter{t: t, answers: map[string]answer{}}
	ib := newInbox(t, dir, inbox.Options{Prompter: fp})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ib.Scan(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan(canceled) error = %v, want context.Canceled", err)
	}
	if n := len(fp.calls()); n != 0 {
		t.Fatalf("prompter called %d times after cancellation", n)
	}
	wantSnapshot(t, dir, before)
}

func TestScan_PrompterCancelsMidScan(t *testing.T) {
	t.Parallel()
	dir := makeInbox(t, map[string][]byte{"a.pdf": plainPDF(t, "1"), "b.pdf": plainPDF(t, "2")})
	before := snapshot(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fp := &fakePrompter{t: t, hook: cancel, answers: map[string]answer{
		"a.pdf": {err: context.Canceled},
		"b.pdf": {err: context.Canceled},
	}}
	_, err := newInbox(t, dir, inbox.Options{Prompter: fp}).Scan(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
	if n := len(fp.calls()); n != 1 {
		t.Fatalf("prompter called %d times, want 1 (stop at the first cancellation)", n)
	}
	wantSnapshot(t, dir, before)
}

func TestScan_PrompterErrorAborts(t *testing.T) {
	t.Parallel()
	errTTY := errors.New("synthetic terminal failure")
	dir := makeInbox(t, map[string][]byte{"scan.pdf": plainPDF(t, "1")})
	fp := &fakePrompter{t: t, answers: map[string]answer{"scan.pdf": {err: errTTY}}}
	_, err := newInbox(t, dir, inbox.Options{Prompter: fp}).Scan(t.Context())
	if !errors.Is(err, errTTY) {
		t.Fatalf("Scan error = %v, want it to wrap the prompter error", err)
	}
}

func TestScan_ClosedFails(t *testing.T) {
	t.Parallel()
	ib, err := inbox.New(makeInbox(t, nil), inbox.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ib.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := ib.Scan(t.Context()); err == nil {
		t.Fatal("Scan after Close succeeded")
	}
}

// TestScan_CanaryNotInResult: neither file content (including a refused
// Factur-X XML) nor extraction error text ends up in the Result, which the
// orchestrator copies into the report.
func TestScan_CanaryNotInResult(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	files := map[string][]byte{
		"2026-03-14_edf_invoice.pdf": facturXPDF(t, []byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY c "`+canary+`">]><rsm:CrossIndustryInvoice xmlns:rsm="`+nsRSM+`">&c;</rsm:CrossIndustryInvoice>`)),
		"notes.txt":                  []byte("synthetic note " + canary),
		"impots/scan.pdf":            facturXPDF(t, []byte(`<not-cii>`+canary+`</not-cii>`)),
	}
	dir := makeInbox(t, files)
	res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers}))

	dump := fmt.Sprintf("%+v\n%#v\n", res, res)
	for _, w := range res.Warnings {
		dump += fmt.Sprintf("%v %s\n", w, w.Reason)
	}
	art := testsecrets.ArtifactDir(t)
	r, err := fsx.Open(art)
	if err != nil {
		t.Fatalf("fsx.Open(artifacts): %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), "scan-result.txt", []byte(dump)); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if strings.Contains(dump, canary) {
		t.Fatalf("canary leaked into the scan result:\n%s", dump)
	}
	if len(res.Items) != 1 || res.Items[0].Source != inbox.SourceName {
		t.Fatalf("items = %+v, want the compliant name used despite the refused Factur-X", itemViews(res.Items))
	}
}

// --- Open / Done -------------------------------------------------------------

func TestOpen_ReturnsScannedContent(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{"impots/avis-2026-10-02.pdf": plainPDF(t, "1")}
	ib := newInbox(t, makeInbox(t, files), inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), "impots/avis-2026-10-02.pdf")
	got, err := readAll(t, ib, it)
	if err != nil {
		t.Fatalf("Open/read: %v", err)
	}
	if !bytes.Equal(got, files[it.Path]) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(files[it.Path]))
	}
}

func TestOpen_DetectsChangedContent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		replace []byte
	}{
		{name: "same size, other bytes", replace: plainPDF(t, "Y")},
		{name: "longer", replace: append(plainPDF(t, "1"), []byte("appended")...)},
		{name: "shorter", replace: []byte("%PDF")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			const p = "2026-03-14_edf_invoice.pdf"
			dir := makeInbox(t, map[string][]byte{p: plainPDF(t, "1")})
			ib := newInbox(t, dir, inbox.Options{Providers: providers})
			it := findItem(t, scan(t, ib), p)
			writeIn(t, dir, p, tt.replace)

			_, err := readAll(t, ib, it)
			if !errors.Is(err, inbox.ErrChanged) {
				t.Fatalf("reading a changed file: error = %v, want ErrChanged", err)
			}
		})
	}
}

func TestDone_RemovesOnlyThatFile(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"impots/avis-2026-10-02.pdf": plainPDF(t, "1"),
		"impots/avis-2026-10-03.pdf": plainPDF(t, "2"),
		"2026-03-14_edf_invoice.pdf": plainPDF(t, "3"),
	}
	dir := makeInbox(t, files)
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	res := scan(t, ib)
	it := findItem(t, res, "impots/avis-2026-10-02.pdf")
	if err := ib.Done(t.Context(), it); err != nil {
		t.Fatalf("Done: %v", err)
	}
	want := map[string]string{
		".":                          "<dir>",
		"impots":                     "<dir>",
		"impots/avis-2026-10-03.pdf": string(files["impots/avis-2026-10-03.pdf"]),
		"2026-03-14_edf_invoice.pdf": string(files["2026-03-14_edf_invoice.pdf"]),
	}
	wantSnapshot(t, dir, want)

	// The emptied subfolder stays: it is the user's drop target.
	other := findItem(t, res, "impots/avis-2026-10-03.pdf")
	if err := ib.Done(t.Context(), other); err != nil {
		t.Fatalf("Done(second): %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "impots")); err != nil || !fi.IsDir() {
		t.Fatalf("subfolder removed or changed: %v", err)
	}
}

func TestDone_KeepsChangedFile(t *testing.T) {
	t.Parallel()
	const p = "2026-03-14_edf_invoice.pdf"
	dir := makeInbox(t, map[string][]byte{p: plainPDF(t, "1")})
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)
	// A new drop under the same name after the scan must survive.
	newer := plainPDF(t, "2")
	writeIn(t, dir, p, newer)
	before := snapshot(t, dir)

	if err := ib.Done(t.Context(), it); !errors.Is(err, inbox.ErrChanged) {
		t.Fatalf("Done(changed) error = %v, want ErrChanged", err)
	}
	wantSnapshot(t, dir, before)
}

func TestDone_Missing(t *testing.T) {
	t.Parallel()
	const p = "2026-03-14_edf_invoice.pdf"
	dir := makeInbox(t, map[string][]byte{p: plainPDF(t, "1")})
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)
	if err := ib.Done(t.Context(), it); err != nil {
		t.Fatalf("Done: %v", err)
	}
	if err := ib.Done(t.Context(), it); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second Done error = %v, want fs.ErrNotExist", err)
	}
}

func TestDone_ContextCanceled(t *testing.T) {
	t.Parallel()
	const p = "2026-03-14_edf_invoice.pdf"
	dir := makeInbox(t, map[string][]byte{p: plainPDF(t, "1")})
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)
	before := snapshot(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ib.Done(ctx, it); !errors.Is(err, context.Canceled) {
		t.Fatalf("Done(canceled) error = %v, want context.Canceled", err)
	}
	wantSnapshot(t, dir, before)
}

// TestOpenDone_RejectForgedPaths: an Item is plain data; one forged (or
// corrupted) to point outside the inbox must not read or remove anything
// there, even when its hash matches the outside file.
func TestOpenDone_RejectForgedPaths(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	for _, d := range []string{"inbox", "inbox/edf"} {
		if err := r.MkdirPrivate(d); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	victim := []byte("outside the inbox, must stay")
	if err := r.WriteAtomic(t.Context(), "victim.pdf", victim); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	ib := newInbox(t, filepath.Join(base, "inbox"), inbox.Options{})

	for _, p := range []string{
		"../victim.pdf",
		"edf/../../victim.pdf",
		filepath.ToSlash(filepath.Join(base, "victim.pdf")), // absolute
		"",
		".",
		"edf",
		"edf/\x00victim.pdf",
	} {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			before := snapshot(t, base)
			it := inbox.Item{Path: p, Size: int64(len(victim)), SHA256: sha256.Sum256(victim)}
			if got, err := readAll(t, ib, it); err == nil {
				t.Fatalf("Open(%q) succeeded, read %q", p, got)
			}
			if err := ib.Done(t.Context(), it); err == nil {
				t.Fatalf("Done(%q) succeeded", p)
			}
			wantSnapshot(t, base, before)
		})
	}
}
