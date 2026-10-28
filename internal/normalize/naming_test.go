// Tests for package normalize (J0 tasks T14 naming and T15 dedup decision).
// Spec: docs/spec.md "Normalization and naming"; ADR 0007 D3 (seller slug) and
// D4 (unknown category = "other"). Stdlib + internal/connector + internal/fsx
// only: transliteration is a hand-written table (no golang.org/x/text).
//
// Test files: naming_test.go (Render, templates), slug_test.go (Slug),
// parse_test.go (ParseName), fuzz_test.go (path safety), dedup_test.go (Decide).
//
// Expected API (implementer: follow exactly):
//
//	// Default templates (docs/spec.md "Configuration").
//	const (
//	    DefaultFileTemplate = "{date:2006-01-02}_{provider}_{kind}[_{amount}][_{ref}]"
//	    DefaultDirTemplate  = "{year}/{category}/{provider}"
//	)
//
//	var (
//	    ErrBadTemplate     error // template syntax or content refused by NewNamer
//	    ErrUnknownLanguage error // Config.Language not "", "en" or "fr"
//	    ErrInvalidDoc      error // Render: zero Date, invalid Kind, empty rendered file stem
//	    ErrNotCompliant    error // ParseName: not a default-template name
//	)
//
//	// Slug: lowercase ASCII words joined by single hyphens, i.e. it matches
//	// ^([a-z0-9]+(-[a-z0-9]+)*)?$. Steps: transliterate with a hand-written
//	// table (é→e, à→a, ç→c, ñ→n, œ→oe, æ→ae, ß/ẞ→ss, ø→o, ł→l, İ→i, upper
//	// and lower case, Latin-1 + Latin Extended-A letters used in Europe);
//	// combining marks (unicode.Mn, NFD input) are dropped; then every run of
//	// other characters (space, punctuation, '_', '/', '.', NUL, controls,
//	// symbols, non-Latin scripts) becomes ONE hyphen; leading/trailing hyphens
//	// are trimmed. May return "". Idempotent.
//	func Slug(s string) string
//
//	// Doc holds the fields a name is rendered from. Render never mutates it.
//	type Doc struct {
//	    Provider    string            // connector id or Factur-X seller; optional; slugged
//	    Category    string            // dir only; slugged; "" renders as "other" (ADR 0007 D4)
//	    Kind        connector.DocKind // required; rendered as its language label
//	    Date        time.Time         // required (IssuedAt); rendered in UTC
//	    AmountCents *int64            // optional
//	    Currency    string            // ISO 4217; uppercased; amount omitted unless ^[A-Z]{3}$
//	    Ref         string            // optional (ProviderID or receipt description); slugged
//	    Ext         string            // "pdf", ".pdf", "PDF"; lowercased, only [a-z0-9] kept,
//	                                  // at most 8 bytes; "" = no extension
//	    Version     int               // 0 or 1: no suffix; n >= 2: "_v<n>" before the extension
//	}
//
//	// Path is a rendered location relative to the output root.
//	type Path struct {
//	    Dir  string // slash-separated, no empty / "." / ".." segment, each segment == fsx.SafeName(segment)
//	    File string // one component, == fsx.SafeName(File), len <= fsx.MaxNameLen
//	}
//	// Rel returns path.Join(Dir, File).
//	func (p Path) Rel() string
//
//	type Config struct {
//	    File     string // file template; "" = DefaultFileTemplate
//	    Dir      string // dir template;  "" = DefaultDirTemplate
//	    Language string // "en" (default when "") or "fr": kind labels
//	}
//
//	// Namer renders names; immutable and safe for concurrent use.
//	type Namer struct{ … }
//	func NewNamer(cfg Config) (*Namer, error) // ErrBadTemplate, ErrUnknownLanguage
//	func (n *Namer) Render(d Doc) (Path, error)
//
//	// ParseName parses a base file name rendered with DefaultFileTemplate in
//	// either language (used by inbox inference). See parse_test.go.
//	func ParseName(name string) (Doc, error)
//
//	// Dedup (spec rules 1–3), see dedup_test.go:
//	type Index interface {
//	    // LatestVersion returns the highest version stored for
//	    // (provider, providerID); found is false when there is none.
//	    LatestVersion(ctx context.Context, provider, providerID string) (version int, found bool, err error)
//	    // HasSHA256 reports whether any indexed document (any provider) has this content hash.
//	    HasSHA256(ctx context.Context, sum [32]byte) (bool, error)
//	}
//	type Action int
//	const (
//	    _ Action = iota
//	    New          // String() "new"
//	    NewVersion   // String() "new-version"
//	    SkipKnownID  // String() "skip-known-id"
//	    SkipSameHash // String() "skip-same-hash"
//	)
//	type Decision struct {
//	    Action  Action
//	    Version int // New: 1; NewVersion: latest+1 (>= 2); skips: 0
//	}
//	// BeforeFetch applies rule 1 from the listing alone.
//	func BeforeFetch(ctx context.Context, idx Index, provider string, ref connector.DocumentRef) (Decision, error)
//	// Decide applies rules 2 then 3 to downloaded content.
//	func Decide(ctx context.Context, idx Index, provider string, ref connector.DocumentRef, sum [32]byte) (Decision, error)
//
// Template language (NewNamer):
//   - placeholders: {date} (layout "2006-01-02"), {date:<Go layout>},
//     {year}, {provider}, {category}, {kind}, {amount}, {ref}; any other name
//     is ErrBadTemplate. Every rendered value is a Slug, except {amount}
//     ("84-12EUR": cents with '-' as decimal separator, uppercase currency,
//     leading '-' for negative amounts) and {year} (decimal year).
//   - "[ … ]" is an optional group: rendered only when every placeholder in it
//     is non-empty. Groups do not nest. Unbalanced '{', '}', '[' or ']' is
//     ErrBadTemplate.
//   - literal text: [a-z0-9_-] in file templates; dir templates also allow
//     '/' between segments (no leading, trailing or doubled '/'). Anything
//     else ('.', uppercase, spaces, '\\') is ErrBadTemplate.
//   - missing fields are omitted, never "unknown": in a file name, runs of
//     '_' left by empty placeholders collapse to one and leading/trailing '_'
//     are trimmed; in a dir, empty segments are dropped.
//   - every dir segment and the final file name go through fsx.SafeName
//     (Windows device names: provider "con" → dir segment "_con"). A file name
//     longer than fsx.MaxNameLen is shortened by truncating the stem; the
//     "_vN" suffix and the extension are always kept.
package normalize_test

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

var update = flag.Bool("update", false, "rewrite golden files")

func cents(v int64) *int64 { return &v }

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func newNamer(t *testing.T, cfg normalize.Config) *normalize.Namer {
	t.Helper()
	n, err := normalize.NewNamer(cfg)
	if err != nil {
		t.Fatalf("NewNamer(%+v): %v", cfg, err)
	}
	return n
}

func render(t *testing.T, n *normalize.Namer, d normalize.Doc) normalize.Path {
	t.Helper()
	p, err := n.Render(d)
	if err != nil {
		t.Fatalf("Render(%+v): %v", d, err)
	}
	return p
}

func readTestdata(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestRender_SpecExamplesGolden reproduces every example name of docs/spec.md
// "Normalization and naming" byte for byte with the default configuration,
// and pins the default layout (year/category/provider, receipts without a
// provider) in golden files. The literal spec name is asserted in the table
// too, so -update cannot hide a naming regression.
func TestRender_SpecExamplesGolden(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	tests := []struct {
		name     string
		doc      normalize.Doc
		specName string
	}{
		{
			name: "edf-invoice",
			doc: normalize.Doc{
				Provider: "edf", Category: "housing", Kind: connector.Invoice,
				Date: day(2026, time.March, 14), AmountCents: cents(8412), Currency: "EUR",
				Ref: "10234567", Ext: "pdf",
			},
			specName: "2026-03-14_edf_invoice_84-12EUR_10234567.pdf",
		},
		{
			name: "cooloc-rent-receipt",
			doc: normalize.Doc{
				Provider: "cooloc", Category: "housing", Kind: connector.RentReceipt,
				Date: day(2026, time.April, 1), Ref: "2026-04", Ext: "pdf",
			},
			specName: "2026-04-01_cooloc_rent-receipt_2026-04.pdf",
		},
		{
			name: "impots-property-tax-notice",
			doc: normalize.Doc{
				Provider: "impots", Category: "housing", Kind: connector.TaxNotice,
				Date: day(2026, time.October, 2), Ext: "pdf",
			},
			specName: "2026-10-02_impots_property-tax-notice.pdf",
		},
		{
			name: "mobile-receipt",
			doc: normalize.Doc{
				Category: "receipts", Kind: connector.Receipt,
				Date: day(2026, time.June, 21), Ref: "Client lunch, Lyon", Ext: "jpg",
			},
			specName: "2026-06-21_receipt_client-lunch-lyon.jpg",
		},
	}
	dir := filepath.Join("testdata", t.Name())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := render(t, n, tc.doc)
			if p.File != tc.specName {
				t.Fatalf("File = %q, want spec name %q", p.File, tc.specName)
			}
			got := []byte(p.Rel() + "\n")
			golden := tc.name + ".golden"
			if *update {
				root, err := fsx.Open(dir)
				if err != nil {
					t.Fatalf("open golden dir: %v", err)
				}
				defer func() { _ = root.Close() }()
				if err := root.WriteAtomic(t.Context(), golden, got); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			want := readTestdata(t, filepath.Join(dir, golden))
			if string(got) != string(want) {
				t.Fatalf("Rel() mismatch (run go test -update and review)\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestRender_OmitsMissingFields: a missing field disappears together with its
// separator; nothing is ever rendered as "unknown" or as an empty field.
func TestRender_OmitsMissingFields(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	base := normalize.Doc{
		Provider: "edf", Category: "housing", Kind: connector.Invoice,
		Date: day(2026, time.March, 14), AmountCents: cents(8412), Currency: "EUR",
		Ref: "10234567", Ext: "pdf",
	}
	tests := []struct {
		name     string
		mutate   func(*normalize.Doc)
		wantFile string
		wantDir  string
	}{
		{"all fields", func(*normalize.Doc) {}, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "2026/housing/edf"},
		{"no amount", func(d *normalize.Doc) { d.AmountCents = nil }, "2026-03-14_edf_invoice_10234567.pdf", "2026/housing/edf"},
		{"no ref", func(d *normalize.Doc) { d.Ref = "" }, "2026-03-14_edf_invoice_84-12EUR.pdf", "2026/housing/edf"},
		{"no amount no ref", func(d *normalize.Doc) { d.AmountCents, d.Ref = nil, "" }, "2026-03-14_edf_invoice.pdf", "2026/housing/edf"},
		{"no provider", func(d *normalize.Doc) { d.Provider = "" }, "2026-03-14_invoice_84-12EUR_10234567.pdf", "2026/housing"},
		{
			"no provider no amount no ref",
			func(d *normalize.Doc) { d.Provider, d.AmountCents, d.Ref = "", nil, "" },
			"2026-03-14_invoice.pdf", "2026/housing",
		},
		{"amount without currency", func(d *normalize.Doc) { d.Currency = "" }, "2026-03-14_edf_invoice_10234567.pdf", "2026/housing/edf"},
		{"amount with invalid currency", func(d *normalize.Doc) { d.Currency = "€" }, "2026-03-14_edf_invoice_10234567.pdf", "2026/housing/edf"},
		{"ref that slugs to empty", func(d *normalize.Doc) { d.Ref = " /// ... " }, "2026-03-14_edf_invoice_84-12EUR.pdf", "2026/housing/edf"},
		{"provider that slugs to empty", func(d *normalize.Doc) { d.Provider = "東京" }, "2026-03-14_invoice_84-12EUR_10234567.pdf", "2026/housing"},
		{"no extension", func(d *normalize.Doc) { d.Ext = "" }, "2026-03-14_edf_invoice_84-12EUR_10234567", "2026/housing/edf"},
		{"no category is other (ADR 0007 D4)", func(d *normalize.Doc) { d.Category = "" }, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "2026/other/edf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := base
			tc.mutate(&d)
			p := render(t, n, d)
			if p.File != tc.wantFile || p.Dir != tc.wantDir {
				t.Fatalf("Render = {Dir:%q File:%q}, want {Dir:%q File:%q}", p.Dir, p.File, tc.wantDir, tc.wantFile)
			}
			for _, bad := range []string{"unknown", "__", "//"} {
				if strings.Contains(p.Rel(), bad) {
					t.Fatalf("Rel() %q contains %q", p.Rel(), bad)
				}
			}
		})
	}
}

// TestRender_FrenchLabels pins every kind label in both languages. The
// connector.DocKind ids stay English; labels are normalize's (TaxNotice is
// "property-tax-notice" in names).
func TestRender_FrenchLabels(t *testing.T) {
	t.Parallel()
	en := newNamer(t, normalize.Config{Language: "en"})
	fr := newNamer(t, normalize.Config{Language: "fr"})
	def := newNamer(t, normalize.Config{})
	tests := []struct {
		kind   connector.DocKind
		wantEN string
		wantFR string
	}{
		{connector.Invoice, "invoice", "facture"},
		{connector.Receipt, "receipt", "recu"},
		{connector.RentReceipt, "rent-receipt", "quittance-de-loyer"},
		{connector.TaxNotice, "property-tax-notice", "avis-de-taxe-fonciere"},
		{connector.Statement, "statement", "releve"},
	}
	for _, tc := range tests {
		t.Run(tc.kind.String(), func(t *testing.T) {
			t.Parallel()
			d := normalize.Doc{Provider: "fournisseur-exemple", Kind: tc.kind, Date: day(2026, time.May, 2), Ext: "pdf"}
			for _, c := range []struct {
				lang string
				n    *normalize.Namer
				want string
			}{{"en", en, tc.wantEN}, {"default", def, tc.wantEN}, {"fr", fr, tc.wantFR}} {
				want := "2026-05-02_fournisseur-exemple_" + c.want + ".pdf"
				if got := render(t, c.n, d).File; got != want {
					t.Errorf("%s: File = %q, want %q", c.lang, got, want)
				}
			}
		})
	}
}

// TestRender_AmountFormat: cents with '-' as decimal separator, no thousands
// separator, ISO currency uppercased.
func TestRender_AmountFormat(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{File: "{amount}"})
	tests := []struct {
		name     string
		cents    int64
		currency string
		want     string
	}{
		{"spec example", 8412, "EUR", "84-12EUR"},
		{"cents only", 5, "EUR", "0-05EUR"},
		{"zero", 0, "EUR", "0-00EUR"},
		{"round", 100000, "EUR", "1000-00EUR"},
		{"large", 123456789, "EUR", "1234567-89EUR"},
		{"credit note", -1050, "EUR", "-10-50EUR"},
		{"lowercase currency", 990, "chf", "9-90CHF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := normalize.Doc{Kind: connector.Invoice, Date: day(2026, time.January, 5), AmountCents: cents(tc.cents), Currency: tc.currency}
			if got := render(t, n, d).File; got != tc.want {
				t.Fatalf("File = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRender_DateInUTC: the date and the year come from the UTC instant.
func TestRender_DateInUTC(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	east := time.FixedZone("UTC+3", 3*3600)
	west := time.FixedZone("UTC-5", -5*3600)
	tests := []struct {
		name     string
		date     time.Time
		wantFile string
		wantDir  string
	}{
		{"west evening is next day UTC", time.Date(2026, time.December, 31, 23, 30, 0, 0, west), "2027-01-01_edf_invoice.pdf", "2027/housing/edf"},
		{"east early morning is previous day UTC", time.Date(2026, time.January, 1, 1, 0, 0, 0, east), "2025-12-31_edf_invoice.pdf", "2025/housing/edf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := render(t, n, normalize.Doc{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: tc.date, Ext: "pdf"})
			if p.File != tc.wantFile || p.Dir != tc.wantDir {
				t.Fatalf("Render = {Dir:%q File:%q}, want {Dir:%q File:%q}", p.Dir, p.File, tc.wantDir, tc.wantFile)
			}
		})
	}
}

// TestRender_SanitizesSupplierProvidedFields: every field is slugged or made
// safe, whatever the supplier sends.
func TestRender_SanitizesSupplierProvidedFields(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	tests := []struct {
		name     string
		doc      normalize.Doc
		wantFile string
		wantDir  string
	}{
		{
			name:     "traversal in provider and ref",
			doc:      normalize.Doc{Provider: "../../.ssh", Category: "../etc", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ref: "a/b", Ext: "pdf"},
			wantFile: "2026-03-14_ssh_invoice_a-b.pdf", wantDir: "2026/etc/ssh",
		},
		{
			name:     "NUL and controls",
			doc:      normalize.Doc{Provider: "ed\x00f", Category: "hous\ning", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ref: "F\x00-1\r\n", Ext: "pdf"},
			wantFile: "2026-03-14_ed-f_invoice_f-1.pdf", wantDir: "2026/hous-ing/ed-f",
		},
		{
			name:     "underscore in ref cannot forge a field",
			doc:      normalize.Doc{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ref: "x_99-00EUR_y", Ext: "pdf"},
			wantFile: "2026-03-14_edf_invoice_x-99-00eur-y.pdf", wantDir: "2026/housing/edf",
		},
		{
			name:     "windows device names",
			doc:      normalize.Doc{Provider: "CON", Category: "nul", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "pdf"},
			wantFile: "2026-03-14_con_invoice.pdf", wantDir: "2026/_nul/_con",
		},
		{
			name:     "extension is normalized",
			doc:      normalize.Doc{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: ".PDF"},
			wantFile: "2026-03-14_edf_invoice.pdf", wantDir: "2026/housing/edf",
		},
		{
			name:     "extension cannot smuggle a path",
			doc:      normalize.Doc{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "/../sh"},
			wantFile: "2026-03-14_edf_invoice.sh", wantDir: "2026/housing/edf",
		},
		{
			name:     "extension capped at 8 bytes",
			doc:      normalize.Doc{Provider: "edf", Category: "housing", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "abcdefghijkl"},
			wantFile: "2026-03-14_edf_invoice.abcdefgh", wantDir: "2026/housing/edf",
		},
		{
			name:     "accented seller and category",
			doc:      normalize.Doc{Provider: "Régie des Eaux d'Exemple", Category: "Logement", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "pdf"},
			wantFile: "2026-03-14_regie-des-eaux-d-exemple_invoice.pdf", wantDir: "2026/logement/regie-des-eaux-d-exemple",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := render(t, n, tc.doc)
			if p.File != tc.wantFile || p.Dir != tc.wantDir {
				t.Fatalf("Render = {Dir:%q File:%q}, want {Dir:%q File:%q}", p.Dir, p.File, tc.wantDir, tc.wantFile)
			}
		})
	}
}

// TestRender_Version: "_vN" goes before the extension (spec dedup rule 3),
// version 0 and 1 have no suffix.
func TestRender_Version(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	base := normalize.Doc{
		Provider: "edf", Category: "housing", Kind: connector.Invoice,
		Date: day(2026, time.March, 14), AmountCents: cents(8412), Currency: "EUR", Ref: "10234567", Ext: "pdf",
	}
	tests := []struct {
		version int
		want    string
	}{
		{0, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf"},
		{1, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf"},
		{2, "2026-03-14_edf_invoice_84-12EUR_10234567_v2.pdf"},
		{3, "2026-03-14_edf_invoice_84-12EUR_10234567_v3.pdf"},
		{12, "2026-03-14_edf_invoice_84-12EUR_10234567_v12.pdf"},
	}
	for _, tc := range tests {
		d := base
		d.Version = tc.version
		if got := render(t, n, d).File; got != tc.want {
			t.Errorf("Version %d: File = %q, want %q", tc.version, got, tc.want)
		}
	}
	noExt := base
	noExt.Ext, noExt.Version = "", 2
	if got, want := render(t, n, noExt).File, "2026-03-14_edf_invoice_84-12EUR_10234567_v2"; got != want {
		t.Errorf("no extension: File = %q, want %q", got, want)
	}
}

// TestRender_LongNamesKeepVersionAndExtension: a supplier-provided ref that
// is far too long is cut from the stem; the result fits fsx.MaxNameLen and
// versions 1 and 2 never collide.
func TestRender_LongNamesKeepVersionAndExtension(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	d := normalize.Doc{
		Provider: "edf", Category: "housing", Kind: connector.Invoice,
		Date: day(2026, time.March, 14), Ref: strings.Repeat("ab-", 200), Ext: "pdf",
	}
	v1 := render(t, n, d).File
	d.Version = 2
	v2 := render(t, n, d).File
	for _, f := range []string{v1, v2} {
		if len(f) > fsx.MaxNameLen {
			t.Errorf("len(%q) = %d > %d", f, len(f), fsx.MaxNameLen)
		}
		if !strings.HasPrefix(f, "2026-03-14_edf_invoice_ab-ab") {
			t.Errorf("File %q lost its leading fields", f)
		}
		if strings.Contains(f, "-.") || strings.Contains(f, "-_") || strings.Contains(f, "_.") {
			t.Errorf("File %q has a dangling separator after truncation", f)
		}
	}
	if !strings.HasSuffix(v1, ".pdf") || strings.Contains(v1, "_v") {
		t.Errorf("v1 = %q, want .pdf and no version suffix", v1)
	}
	if !strings.HasSuffix(v2, "_v2.pdf") {
		t.Errorf("v2 = %q, want suffix _v2.pdf", v2)
	}
	if v1 == v2 {
		t.Errorf("versions 1 and 2 collide: %q", v1)
	}
}

// TestRender_InvalidDoc: required fields are date and a known kind; a
// template that renders an empty stem is refused rather than producing ".pdf".
func TestRender_InvalidDoc(t *testing.T) {
	t.Parallel()
	def := newNamer(t, normalize.Config{})
	refOnly := newNamer(t, normalize.Config{File: "{ref}"})
	tests := []struct {
		name string
		n    *normalize.Namer
		doc  normalize.Doc
	}{
		{"zero date", def, normalize.Doc{Provider: "edf", Kind: connector.Invoice, Ext: "pdf"}},
		{"zero kind", def, normalize.Doc{Provider: "edf", Date: day(2026, time.March, 14), Ext: "pdf"}},
		{"out of range kind", def, normalize.Doc{Provider: "edf", Kind: connector.DocKind(99), Date: day(2026, time.March, 14), Ext: "pdf"}},
		{"negative kind", def, normalize.Doc{Provider: "edf", Kind: connector.DocKind(-1), Date: day(2026, time.March, 14), Ext: "pdf"}},
		{"empty stem", refOnly, normalize.Doc{Kind: connector.Invoice, Date: day(2026, time.March, 14), Ext: "pdf"}},
		{"stem slugs to empty", refOnly, normalize.Doc{Kind: connector.Invoice, Date: day(2026, time.March, 14), Ref: "../..", Ext: "pdf"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := tc.n.Render(tc.doc)
			if !errors.Is(err, normalize.ErrInvalidDoc) {
				t.Fatalf("Render err = %v, want ErrInvalidDoc", err)
			}
			if p != (normalize.Path{}) {
				t.Fatalf("Render returned %+v alongside an error", p)
			}
		})
	}
}

// TestNewNamer_RejectsBadConfig: template and language validation (used by
// config validation, T13).
func TestNewNamer_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     normalize.Config
		wantErr error
	}{
		{"unknown language", normalize.Config{Language: "de"}, normalize.ErrUnknownLanguage},
		{"uppercase language", normalize.Config{Language: "FR"}, normalize.ErrUnknownLanguage},
		{"unclosed brace", normalize.Config{File: "{date"}, normalize.ErrBadTemplate},
		{"stray closing brace", normalize.Config{File: "date}"}, normalize.ErrBadTemplate},
		{"unknown placeholder", normalize.Config{File: "{date}_{password}"}, normalize.ErrBadTemplate},
		{"empty placeholder", normalize.Config{File: "{}"}, normalize.ErrBadTemplate},
		{"unclosed group", normalize.Config{File: "{date}[_{ref}"}, normalize.ErrBadTemplate},
		{"stray closing group", normalize.Config{File: "{date}_{ref}]"}, normalize.ErrBadTemplate},
		{"nested group", normalize.Config{File: "{date}[_{amount}[_{ref}]]"}, normalize.ErrBadTemplate},
		{"slash in file template", normalize.Config{File: "{year}/{date}"}, normalize.ErrBadTemplate},
		{"dot in file template", normalize.Config{File: "{date}.{ref}"}, normalize.ErrBadTemplate},
		{"uppercase literal", normalize.Config{File: "Facture_{date}"}, normalize.ErrBadTemplate},
		{"space literal", normalize.Config{File: "{date} {ref}"}, normalize.ErrBadTemplate},
		{"backslash literal", normalize.Config{File: `{date}\{ref}`}, normalize.ErrBadTemplate},
		{"dir traversal", normalize.Config{Dir: "../{year}"}, normalize.ErrBadTemplate},
		{"dir absolute", normalize.Config{Dir: "/{year}/{provider}"}, normalize.ErrBadTemplate},
		{"dir trailing slash", normalize.Config{Dir: "{year}/"}, normalize.ErrBadTemplate},
		{"dir double slash", normalize.Config{Dir: "{year}//{provider}"}, normalize.ErrBadTemplate},
		{"dir unknown placeholder", normalize.Config{Dir: "{year}/{home}"}, normalize.ErrBadTemplate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := normalize.NewNamer(tc.cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewNamer(%+v) err = %v, want %v", tc.cfg, err, tc.wantErr)
			}
			if n != nil {
				t.Fatalf("NewNamer returned a Namer alongside an error")
			}
		})
	}
}

// TestRender_CustomTemplates: user templates from config.yaml.
func TestRender_CustomTemplates(t *testing.T) {
	t.Parallel()
	d := normalize.Doc{
		Provider: "edf", Category: "housing", Kind: connector.Invoice,
		Date: day(2026, time.March, 14), AmountCents: cents(8412), Currency: "EUR", Ref: "10234567", Ext: "pdf",
	}
	tests := []struct {
		name     string
		cfg      normalize.Config
		doc      normalize.Doc
		wantFile string
		wantDir  string
	}{
		{"defaults spelled out", normalize.Config{File: normalize.DefaultFileTemplate, Dir: normalize.DefaultDirTemplate, Language: "en"}, d, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "2026/housing/edf"},
		{"kind first, month layout", normalize.Config{File: "{kind}_{date:2006-01}_{ref}"}, d, "invoice_2026-03_10234567.pdf", "2026/housing/edf"},
		{"layout output is slugged", normalize.Config{File: "{date:Jan 2006}_{provider}"}, d, "mar-2026_edf.pdf", "2026/housing/edf"},
		{"literal in optional group", normalize.Config{File: "{date}[_no-{ref}]"}, d, "2026-03-14_no-10234567.pdf", "2026/housing/edf"},
		{"optional group dropped", normalize.Config{File: "{date}[_no-{ref}]"}, normalize.Doc{Kind: connector.Invoice, Date: d.Date, Ext: "pdf"}, "2026-03-14.pdf", "2026/other"},
		{"category first dir", normalize.Config{Dir: "{category}/{year}"}, d, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "housing/2026"},
		{"flat dir by provider", normalize.Config{Dir: "factures/{provider}"}, d, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "factures/edf"},
		{"french with custom file", normalize.Config{File: "{date}_{kind}", Language: "fr"}, d, "2026-03-14_facture.pdf", "2026/housing/edf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := render(t, newNamer(t, tc.cfg), tc.doc)
			if p.File != tc.wantFile || p.Dir != tc.wantDir {
				t.Fatalf("Render = {Dir:%q File:%q}, want {Dir:%q File:%q}", p.Dir, p.File, tc.wantDir, tc.wantFile)
			}
		})
	}
}

// TestRender_DoesNotMutateDoc: Render works on a copy (AmountCents is shared
// by pointer).
func TestRender_DoesNotMutateDoc(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	amount := int64(8412)
	d := normalize.Doc{Provider: "Bouygues Télécom", Kind: connector.Invoice, Date: day(2026, time.March, 14), AmountCents: &amount, Currency: "eur", Ref: "A/B", Ext: ".PDF"}
	before := d
	render(t, n, d)
	if d != before || amount != 8412 {
		t.Fatalf("Render mutated its input: %+v (amount %d)", d, amount)
	}
}

// TestPath_Rel joins with a slash and handles an empty Dir.
func TestPath_Rel(t *testing.T) {
	t.Parallel()
	if got := (normalize.Path{Dir: "2026/housing/edf", File: "a.pdf"}).Rel(); got != "2026/housing/edf/a.pdf" {
		t.Errorf("Rel = %q", got)
	}
	if got := (normalize.Path{File: "a.pdf"}).Rel(); got != "a.pdf" {
		t.Errorf("Rel with empty Dir = %q", got)
	}
}
