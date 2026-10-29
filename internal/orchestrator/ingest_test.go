// Tests for the orchestrator ingest pipeline (J0 task T23): sha256 → dedup
// (normalize.Decide) → name (Namer) → destination Put → index Insert, then,
// for inbox items, inbox Done. Spec: docs/spec.md "Run lifecycle" step 5,
// "Normalization and naming" > "Dedup" and "Manual import (inbox/)",
// "Destinations"; docs/adr/0007-j0-product-decisions.md (D2: unidentified
// inbox files stay with a warning in the report). CLAUDE.md: the
// orchestrator never imports a concrete connector or destination.
//
// Expected API (implementer: follow exactly):
//
//	// Index is the document index the pipeline reads and writes
//	// (*store.Store implements it).
//	type Index interface {
//		normalize.Index
//		Insert(ctx context.Context, d store.Document) (store.Document, error)
//	}
//
//	// Destination is the part of dest.Destination the pipeline uses.
//	type Destination interface {
//		Name() string
//		Put(ctx context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error)
//	}
//
//	// Namer renders the normalized path (*normalize.Namer implements it).
//	type Namer interface {
//		Render(d normalize.Doc) (normalize.Path, error)
//	}
//
//	// InboxSource is the manual-import source (*inbox.Inbox implements it).
//	type InboxSource interface {
//		Scan(ctx context.Context) (inbox.Result, error)
//		Open(ctx context.Context, it inbox.Item) (io.ReadCloser, error)
//		Done(ctx context.Context, it inbox.Item) error
//	}
//
//	// DefaultMaxSize caps a document read by Ingest (== inbox.MaxFileSize).
//	const DefaultMaxSize = inbox.MaxFileSize
//
//	var ErrTooLarge = errors.New("orchestrator: document too large")
//	var ErrInvalidDeps = errors.New("orchestrator: invalid dependencies")
//
//	type Deps struct {
//		Index   Index        // required
//		Dest    Destination  // required
//		Namer   Namer        // required
//		Log     *slog.Logger // nil = discard; New always wraps its handler in logx.NewHandler
//		MaxSize int64        // <= 0 = DefaultMaxSize
//	}
//	func New(d Deps) (*Orchestrator, error) // missing Index/Dest/Namer: wraps ErrInvalidDeps
//
//	// Input is one downloaded or dropped document.
//	type Input struct {
//		Source      string        // "inbox" or the connector id; reported
//		Origin      string        // inbox item path; "" for connectors; reported
//		ProviderID  string        // dedup key; "" = none (never versioned)
//		Doc         normalize.Doc // naming metadata; Version is ignored (dedup decides)
//		PeriodStart time.Time     // optional, indexed
//		PeriodEnd   time.Time     // optional, indexed
//		Content     io.Reader
//	}
//
//	// Ingest reads Content (at most MaxSize bytes, else ErrTooLarge),
//	// hashes it, applies normalize.Decide with provider =
//	// normalize.Slug(Doc.Provider), renders the path with Doc.Version set
//	// to the decided version, Puts it, then Inserts the index row:
//	// Provider (slug), ProviderID, Kind, IssuedAt = Doc.Date, Period*,
//	// AmountCents, Currency, SHA256, Version, and RemoteRef.ID as LocalPath
//	// when Dest.Name() == "local", else as DriveID. The DocResult status
//	// is always set; the error is nil only for StatusFiled and
//	// StatusSkippedDuplicate. A document is validated (non-empty provider
//	// slug, renderable) before anything is written. No error text, file
//	// content or secret ever lands in a DocResult; failures are logged
//	// through the logx-wrapped logger.
//	func (o *Orchestrator) Ingest(ctx context.Context, in Input) (DocResult, error)
//
//	// IngestInbox scans src and ingests every item in order (Source
//	// "inbox", Origin = item path, ProviderID = item.Doc.Ref). An item is
//	// Done (removed) only after StatusFiled (Put AND Insert succeeded) or
//	// StatusSkippedDuplicate; every other status leaves the file. A per-item
//	// failure does not stop the loop; a canceled ctx does (error wraps
//	// ctx.Err()). Scan warnings are reported with Source "inbox".
//	func (o *Orchestrator) IngestInbox(ctx context.Context, src InboxSource) (InboxResult, error)
//	type InboxResult struct {
//		Documents []DocResult
//		Warnings  []Warning
//	}
//
// Report types and statuses are listed in report_test.go.
package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func TestNew_RequiresDependencies(t *testing.T) {
	t.Parallel()
	ev := &events{}
	full := orchestrator.Deps{Index: newFakeIndex(ev), Dest: newFakeDest(ev), Namer: namer(t)}
	tests := []struct {
		name   string
		mutate func(*orchestrator.Deps)
	}{
		{"no index", func(d *orchestrator.Deps) { d.Index = nil }},
		{"no destination", func(d *orchestrator.Deps) { d.Dest = nil }},
		{"no namer", func(d *orchestrator.Deps) { d.Namer = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := full
			tt.mutate(&d)
			if _, err := orchestrator.New(d); !errors.Is(err, orchestrator.ErrInvalidDeps) {
				t.Fatalf("New() error = %v, want ErrInvalidDeps", err)
			}
		})
	}
	t.Run("nil logger is allowed", func(t *testing.T) {
		t.Parallel()
		if _, err := orchestrator.New(full); err != nil {
			t.Fatalf("New() error = %v", err)
		}
	})
}

func TestDefaultMaxSize_IsInboxCap(t *testing.T) {
	t.Parallel()
	if orchestrator.DefaultMaxSize != inbox.MaxFileSize {
		t.Fatalf("DefaultMaxSize = %d, want inbox.MaxFileSize %d", orchestrator.DefaultMaxSize, inbox.MaxFileSize)
	}
}

func TestIngest_NewDocumentFiledAndIndexed(t *testing.T) {
	t.Parallel()
	content := pdf("new")
	noRef := edfDoc()
	noRef.Ref = ""
	seller := normalize.Doc{Provider: "Fournisseur Exemple SAS", Kind: connector.Invoice, Date: day(time.March, 14), Ext: "pdf"}

	tests := []struct {
		name       string
		destName   string
		in         orchestrator.Input
		wantResult orchestrator.DocResult
		wantDoc    store.Document // SHA256 and CollectedAt not compared here
	}{
		{
			name: "connector document with provider id",
			in:   orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc()},
			wantResult: orchestrator.DocResult{
				Source: "edf", Provider: "edf", ProviderID: "10234567",
				Status: orchestrator.StatusFiled, Version: 1, Path: edfPath,
			},
			wantDoc: store.Document{
				Provider: "edf", ProviderID: "10234567", Kind: connector.Invoice,
				IssuedAt: day(time.March, 14), AmountCents: cents(8412), Currency: "EUR",
				LocalPath: edfPath, Version: 1,
			},
		},
		{
			name: "inbox document without provider id",
			in:   orchestrator.Input{Source: "inbox", Origin: "edf/scan.pdf", Doc: noRef},
			wantResult: orchestrator.DocResult{
				Source: "inbox", Origin: "edf/scan.pdf", Provider: "edf",
				Status: orchestrator.StatusFiled, Version: 1,
				Path: "2026/energy/edf/2026-03-14_edf_invoice_84-12EUR.pdf",
			},
			wantDoc: store.Document{
				Provider: "edf", Kind: connector.Invoice, IssuedAt: day(time.March, 14),
				AmountCents: cents(8412), Currency: "EUR",
				LocalPath: "2026/energy/edf/2026-03-14_edf_invoice_84-12EUR.pdf", Version: 1,
			},
		},
		{
			name: "provider is indexed as its slug",
			in:   orchestrator.Input{Source: "inbox", Origin: "facture.pdf", Doc: seller},
			wantResult: orchestrator.DocResult{
				Source: "inbox", Origin: "facture.pdf", Provider: "fournisseur-exemple-sas",
				Status: orchestrator.StatusFiled, Version: 1,
				Path: "2026/other/fournisseur-exemple-sas/2026-03-14_fournisseur-exemple-sas_invoice.pdf",
			},
			wantDoc: store.Document{
				Provider: "fournisseur-exemple-sas", Kind: connector.Invoice, IssuedAt: day(time.March, 14),
				LocalPath: "2026/other/fournisseur-exemple-sas/2026-03-14_fournisseur-exemple-sas_invoice.pdf", Version: 1,
			},
		},
		{
			name: "period is indexed",
			in: orchestrator.Input{
				Source: "edf", ProviderID: "10234567", Doc: edfDoc(),
				PeriodStart: day(time.February, 1), PeriodEnd: day(time.February, 28),
			},
			wantResult: orchestrator.DocResult{
				Source: "edf", Provider: "edf", ProviderID: "10234567",
				Status: orchestrator.StatusFiled, Version: 1, Path: edfPath,
			},
			wantDoc: store.Document{
				Provider: "edf", ProviderID: "10234567", Kind: connector.Invoice,
				IssuedAt: day(time.March, 14), PeriodStart: day(time.February, 1),
				PeriodEnd: day(time.February, 28), AmountCents: cents(8412), Currency: "EUR",
				LocalPath: edfPath, Version: 1,
			},
		},
		{
			name:     "non-local destination id is indexed as drive id",
			destName: "gdrive",
			in:       orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc()},
			wantResult: orchestrator.DocResult{
				Source: "edf", Provider: "edf", ProviderID: "10234567",
				Status: orchestrator.StatusFiled, Version: 1, Path: edfPath,
			},
			wantDoc: store.Document{
				Provider: "edf", ProviderID: "10234567", Kind: connector.Invoice,
				IssuedAt: day(time.March, 14), AmountCents: cents(8412), Currency: "EUR",
				DriveID: "drive-file-0001", Version: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil)
			if tt.destName != "" {
				r.dst.name = tt.destName
				r.dst.id = func(dest.NormalizedDoc) string { return "drive-file-0001" }
			}
			in := tt.in
			in.Content = bytes.NewReader(content)

			got, err := r.o.Ingest(t.Context(), in)
			if err != nil {
				t.Fatalf("Ingest() error = %v", err)
			}
			if !equalResult(got, tt.wantResult) {
				t.Fatalf("Ingest() result\n got %+v\nwant %+v", got, tt.wantResult)
			}

			puts := r.dst.put()
			if len(puts) != 1 {
				t.Fatalf("Put calls = %d, want 1", len(puts))
			}
			if puts[0].Path.Rel() != tt.wantResult.Path || puts[0].Doc.Version != 1 {
				t.Errorf("Put path %q version %d, want %q version 1", puts[0].Path.Rel(), puts[0].Doc.Version, tt.wantResult.Path)
			}
			if b := r.dst.file(tt.wantResult.Path); !bytes.Equal(b, content) {
				t.Errorf("destination content = %q, want %q", b, content)
			}

			docs := r.idx.all()
			if len(docs) != 1 {
				t.Fatalf("indexed %d documents, want 1", len(docs))
			}
			want := tt.wantDoc
			want.SHA256 = sum(content)
			if !equalDoc(docs[0], want) {
				t.Errorf("indexed\n got %s\nwant %s", docString(docs[0]), docString(want))
			}
		})
	}
}

func TestIngest_DuplicateHashSkipped(t *testing.T) {
	t.Parallel()
	content := pdf("known")
	tests := []struct {
		name  string
		known store.Document
		in    orchestrator.Input
	}{
		{
			name:  "same provider id and content",
			known: indexed(1, content),
			in:    orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc()},
		},
		{
			name:  "same content dropped in the inbox without id",
			known: indexed(1, content),
			in:    orchestrator.Input{Source: "inbox", Origin: "copy.pdf", Doc: edfDoc()},
		},
		{
			name:  "same content under another provider",
			known: store.Document{Provider: "other", ProviderID: "X-1", Kind: connector.Invoice, SHA256: sum(content), Version: 1},
			in:    orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, []store.Document{tt.known})
			in := tt.in
			in.Content = bytes.NewReader(content)
			got, err := r.o.Ingest(t.Context(), in)
			if err != nil {
				t.Fatalf("Ingest() error = %v", err)
			}
			if got.Status != orchestrator.StatusSkippedDuplicate || got.Path != "" || got.Version != 0 {
				t.Fatalf("Ingest() = %+v, want status %q, no path, no version", got, orchestrator.StatusSkippedDuplicate)
			}
			if n := len(r.dst.put()); n != 0 {
				t.Errorf("Put called %d times for a duplicate", n)
			}
			if n := len(r.idx.all()); n != 1 {
				t.Errorf("index holds %d documents, want the 1 known", n)
			}
		})
	}

	t.Run("inbox duplicate is removed from the inbox", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, []store.Document{indexed(1, content)})
		src := newFakeInbox(r.ev, []inbox.Item{item("edf/copy.pdf", edfDoc(), content)},
			map[string][]byte{"edf/copy.pdf": content})
		res, err := r.o.IngestInbox(t.Context(), src)
		if err != nil {
			t.Fatalf("IngestInbox() error = %v", err)
		}
		if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusSkippedDuplicate {
			t.Fatalf("documents = %+v, want one %q", res.Documents, orchestrator.StatusSkippedDuplicate)
		}
		if got := src.doneList(); !slices.Equal(got, []string{"edf/copy.pdf"}) {
			t.Fatalf("Done = %q, want the duplicate removed", got)
		}
		if n := len(r.dst.put()); n != 0 {
			t.Errorf("Put called %d times for a duplicate", n)
		}
	})
}

func TestIngest_SameIDNewHashCreatesV2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		known       []store.Document
		wantVersion int
		wantPath    string
	}{
		{
			name:        "v1 known",
			known:       []store.Document{indexed(1, pdf("v1"))},
			wantVersion: 2,
			wantPath:    edfPathV2,
		},
		{
			name:        "v1 to v3 known",
			known:       []store.Document{indexed(1, pdf("v1")), indexed(2, pdf("v2")), indexed(3, pdf("v3"))},
			wantVersion: 4,
			wantPath:    "2026/energy/edf/2026-03-14_edf_invoice_84-12EUR_10234567_v4.pdf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, tt.known)
			content := pdf("corrected")
			got, err := r.o.Ingest(t.Context(), orchestrator.Input{
				Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(content),
			})
			if err != nil {
				t.Fatalf("Ingest() error = %v", err)
			}
			if got.Status != orchestrator.StatusFiled || got.Version != tt.wantVersion || got.Path != tt.wantPath {
				t.Fatalf("Ingest() = %+v, want filed v%d at %q", got, tt.wantVersion, tt.wantPath)
			}
			puts := r.dst.put()
			if len(puts) != 1 || puts[0].Doc.Version != tt.wantVersion || puts[0].Path.Rel() != tt.wantPath {
				t.Fatalf("Put = %+v, want one Put of v%d at %q", puts, tt.wantVersion, tt.wantPath)
			}
			docs := r.idx.all()
			if len(docs) != len(tt.known)+1 {
				t.Fatalf("index holds %d documents, want %d (old versions kept)", len(docs), len(tt.known)+1)
			}
			last := docs[len(docs)-1]
			if last.Version != tt.wantVersion || last.ProviderID != "10234567" || last.SHA256 != sum(content) || last.LocalPath != tt.wantPath {
				t.Errorf("new row = %s", docString(last))
			}
		})
	}
}

func TestIngest_DestinationExistsIsNotSuccess(t *testing.T) {
	t.Parallel()
	content := pdf("clash")

	t.Run("ingest", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, nil)
		r.dst.files[edfPath] = pdf("someone else's file")
		got, err := r.o.Ingest(t.Context(), orchestrator.Input{
			Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(content),
		})
		if !errors.Is(err, dest.ErrExists) {
			t.Fatalf("Ingest() error = %v, want dest.ErrExists", err)
		}
		if got.Status != orchestrator.StatusExists || got.Status == orchestrator.StatusSkippedDuplicate {
			t.Fatalf("status = %q, want %q (not a duplicate, not filed)", got.Status, orchestrator.StatusExists)
		}
		if got.Path != edfPath {
			t.Errorf("Path = %q, want the clashing path %q", got.Path, edfPath)
		}
		if n := len(r.idx.all()); n != 0 {
			t.Errorf("index holds %d documents, want 0: nothing was filed", n)
		}
		if b := r.dst.file(edfPath); !bytes.Equal(b, pdf("someone else's file")) {
			t.Error("existing destination file was replaced")
		}
	})

	t.Run("inbox file stays", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, nil)
		r.dst.files[edfPath] = pdf("someone else's file")
		src := newFakeInbox(r.ev, []inbox.Item{item("drop.pdf", edfDoc(), content)}, map[string][]byte{"drop.pdf": content})
		res, err := r.o.IngestInbox(t.Context(), src)
		if err != nil {
			t.Fatalf("IngestInbox() error = %v (per-item failures are reported, not returned)", err)
		}
		if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusExists {
			t.Fatalf("documents = %+v, want one %q", res.Documents, orchestrator.StatusExists)
		}
		if d := src.doneList(); len(d) != 0 {
			t.Fatalf("Done = %q, want the inbox file kept", d)
		}
	})
}

func TestIngest_NotDurableIsIndexedButInboxKept(t *testing.T) {
	t.Parallel()
	content := pdf("not durable")
	r := newRig(t, nil)
	r.dst.err = fmt.Errorf("publish: %w", fsx.ErrNotDurable)
	r.dst.ref = &dest.RemoteRef{Destination: "local", ID: edfPath}
	src := newFakeInbox(r.ev, []inbox.Item{item("drop.pdf", edfDoc(), content)}, map[string][]byte{"drop.pdf": content})

	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	if len(res.Documents) != 1 {
		t.Fatalf("documents = %+v, want 1", res.Documents)
	}
	got := res.Documents[0]
	if got.Status != orchestrator.StatusNotDurable || got.Path != edfPath || got.Version != 1 {
		t.Fatalf("result = %+v, want %q at %q v1", got, orchestrator.StatusNotDurable, edfPath)
	}
	// The document is published: index it, or the next run would hit ErrExists forever.
	docs := r.idx.all()
	if len(docs) != 1 || docs[0].LocalPath != edfPath || docs[0].SHA256 != sum(content) {
		t.Fatalf("index = %+v, want the published document indexed", docs)
	}
	// Its directory entry may not survive a crash: keep the only other copy.
	if d := src.doneList(); len(d) != 0 {
		t.Fatalf("Done = %q, want the inbox file kept until the copy is durable", d)
	}

	t.Run("ingest returns the error", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, nil)
		r.dst.err = fmt.Errorf("publish: %w", fsx.ErrNotDurable)
		r.dst.ref = &dest.RemoteRef{Destination: "local", ID: edfPath}
		got, err := r.o.Ingest(t.Context(), orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(content)})
		if !errors.Is(err, fsx.ErrNotDurable) || got.Status != orchestrator.StatusNotDurable {
			t.Fatalf("Ingest() = %+v, %v; want %q and ErrNotDurable", got, err, orchestrator.StatusNotDurable)
		}
	})
}

func TestIngestInbox_DoneOnlyAfterPutAndInsert(t *testing.T) {
	t.Parallel()
	content := pdf("drop")
	boom := errors.New("synthetic failure")
	tests := []struct {
		name       string
		breakIt    func(*rig)
		wantStatus orchestrator.Status
		wantEvents []string
	}{
		{
			name:       "success",
			breakIt:    func(*rig) {},
			wantStatus: orchestrator.StatusFiled,
			wantEvents: []string{"put:" + edfPath, "insert:edf/10234567/v1", "done:drop.pdf"},
		},
		{
			name:       "put fails",
			breakIt:    func(r *rig) { r.dst.err = boom },
			wantStatus: orchestrator.StatusFailed,
			wantEvents: []string{"put-fail:" + edfPath},
		},
		{
			name:       "insert fails",
			breakIt:    func(r *rig) { r.idx.insertErr = boom },
			wantStatus: orchestrator.StatusFailed,
			wantEvents: []string{"put:" + edfPath, "insert-fail:" + edfPath},
		},
		{
			name:       "insert hits a concurrent duplicate",
			breakIt:    func(r *rig) { r.idx.insertErr = store.ErrDuplicate },
			wantStatus: orchestrator.StatusFailed,
			wantEvents: []string{"put:" + edfPath, "insert-fail:" + edfPath},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil)
			tt.breakIt(r)
			src := newFakeInbox(r.ev, []inbox.Item{item("drop.pdf", edfDoc(), content)}, map[string][]byte{"drop.pdf": content})
			res, err := r.o.IngestInbox(t.Context(), src)
			if err != nil {
				t.Fatalf("IngestInbox() error = %v (per-item failures are reported, not returned)", err)
			}
			if len(res.Documents) != 1 || res.Documents[0].Status != tt.wantStatus {
				t.Fatalf("documents = %+v, want one %q", res.Documents, tt.wantStatus)
			}
			if got := r.ev.list(); !slices.Equal(got, tt.wantEvents) {
				t.Fatalf("events = %q, want %q", got, tt.wantEvents)
			}
		})
	}
}

func TestIngest_IndexErrorNeverFiles(t *testing.T) {
	t.Parallel()
	boom := errors.New("synthetic index failure")
	tests := []struct {
		name    string
		breakIt func(*fakeIndex)
	}{
		{"hash lookup fails", func(f *fakeIndex) { f.hasErr = boom }},
		{"version lookup fails", func(f *fakeIndex) { f.latestErr = boom }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil)
			tt.breakIt(r.idx)
			got, err := r.o.Ingest(t.Context(), orchestrator.Input{
				Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(pdf("x")),
			})
			if !errors.Is(err, boom) {
				t.Fatalf("Ingest() error = %v, want it to wrap the index error", err)
			}
			if got.Status != orchestrator.StatusFailed {
				t.Fatalf("status = %q, want %q (never new, never skipped)", got.Status, orchestrator.StatusFailed)
			}
			if n := len(r.dst.put()); n != 0 {
				t.Errorf("Put called %d times after an index error", n)
			}
		})
	}
}

func TestIngest_SizeCap(t *testing.T) {
	t.Parallel()
	const capBytes = 64
	tests := []struct {
		name       string
		size       int
		wantStatus orchestrator.Status
		wantErr    error
	}{
		{"at the cap", capBytes, orchestrator.StatusFiled, nil},
		{"one byte over", capBytes + 1, orchestrator.StatusTooLarge, orchestrator.ErrTooLarge},
		{"far over", 10 * capBytes, orchestrator.StatusTooLarge, orchestrator.ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil, withMaxSize(capBytes))
			got, err := r.o.Ingest(t.Context(), orchestrator.Input{
				Source: "edf", ProviderID: "10234567", Doc: edfDoc(),
				Content: bytes.NewReader(bytes.Repeat([]byte("a"), tt.size)),
			})
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("Ingest() error = %v, want %v", err, tt.wantErr)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if tt.wantErr != nil && (len(r.dst.put()) != 0 || len(r.idx.all()) != 0) {
				t.Error("oversized document was filed or indexed")
			}
		})
	}
}

func TestIngest_InvalidDocumentRefusedBeforeWrite(t *testing.T) {
	t.Parallel()
	mutate := func(f func(*normalize.Doc)) normalize.Doc {
		d := edfDoc()
		f(&d)
		return d
	}
	tests := []struct {
		name string
		doc  normalize.Doc
	}{
		{"zero date", mutate(func(d *normalize.Doc) { d.Date = time.Time{} })},
		{"invalid kind", mutate(func(d *normalize.Doc) { d.Kind = connector.DocKind(99) })},
		{"empty provider", mutate(func(d *normalize.Doc) { d.Provider = "" })},
		{"provider with no slug", mutate(func(d *normalize.Doc) { d.Provider = "../.." })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil)
			got, err := r.o.Ingest(t.Context(), orchestrator.Input{
				Source: "inbox", Origin: "bad.pdf", Doc: tt.doc, Content: bytes.NewReader(pdf("bad")),
			})
			if err == nil {
				t.Fatal("Ingest() error = nil, want a refusal")
			}
			if got.Status != orchestrator.StatusInvalid {
				t.Fatalf("status = %q, want %q", got.Status, orchestrator.StatusInvalid)
			}
			if len(r.dst.put()) != 0 || len(r.idx.all()) != 0 {
				t.Fatal("invalid document was filed or indexed")
			}
		})
	}
}

func TestIngest_UnsafeMetadataStaysConfined(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	d := normalize.Doc{
		Provider: "../../etc", Category: "..", Kind: connector.Invoice,
		Date: day(time.March, 14), Ref: "../../../passwd", Ext: "pdf/../../x",
	}
	got, err := r.o.Ingest(t.Context(), orchestrator.Input{
		Source: "inbox", Origin: "evil.pdf", ProviderID: "../../../passwd", Doc: d, Content: bytes.NewReader(pdf("evil")),
	})
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	puts := r.dst.put()
	if len(puts) != 1 {
		t.Fatalf("Put calls = %d, want 1", len(puts))
	}
	if err := dest.ValidatePath(puts[0].Path); err != nil {
		t.Fatalf("Put path %+v is not canonical: %v", puts[0].Path, err)
	}
	want, err := namer(t).Render(withVersion(d, 1))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if puts[0].Path != want || got.Path != want.Rel() {
		t.Fatalf("Put path %+v / result path %q, want exactly the Namer's %+v", puts[0].Path, got.Path, want)
	}
	for seg := range strings.SplitSeq(got.Path, "/") {
		if seg == ".." || seg == "." {
			t.Fatalf("result path %q has a dot segment", got.Path)
		}
	}
}

func TestIngest_ReaderErrorFails(t *testing.T) {
	t.Parallel()
	boom := errors.New("synthetic read failure")
	r := newRig(t, nil)
	got, err := r.o.Ingest(t.Context(), orchestrator.Input{
		Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: &errReader{data: pdf("partial"), err: boom},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Ingest() error = %v, want it to wrap the reader error", err)
	}
	if got.Status != orchestrator.StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, orchestrator.StatusFailed)
	}
	if len(r.dst.put()) != 0 || len(r.idx.all()) != 0 {
		t.Fatal("a partial read was filed or indexed")
	}
}

func TestIngest_ContextCanceled(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := r.o.Ingest(ctx, orchestrator.Input{
		Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(pdf("x")),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ingest() error = %v, want context.Canceled", err)
	}
	if len(r.dst.put()) != 0 || len(r.idx.all()) != 0 {
		t.Fatal("document filed or indexed under a canceled context")
	}
}

func TestIngestInbox_MapsItemsAndWarnings(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	a, b := pdf("a"), pdf("b")
	noRef := edfDoc()
	noRef.Ref = ""
	noRef.Date = day(time.April, 2)
	src := newFakeInbox(r.ev,
		[]inbox.Item{item("2026-03-14_edf_invoice_84-12EUR_10234567.pdf", edfDoc(), a), item("edf/scan.pdf", noRef, b)},
		map[string][]byte{"2026-03-14_edf_invoice_84-12EUR_10234567.pdf": a, "edf/scan.pdf": b},
		inbox.Warning{Path: "big.pdf", Reason: inbox.ReasonTooLarge},
		inbox.Warning{Path: "unknown.pdf", Reason: inbox.ReasonUnidentified},
	)
	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	wantDocs := []orchestrator.DocResult{
		{Source: "inbox", Origin: "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", Provider: "edf", ProviderID: "10234567", Status: orchestrator.StatusFiled, Version: 1, Path: edfPath},
		{Source: "inbox", Origin: "edf/scan.pdf", Provider: "edf", Status: orchestrator.StatusFiled, Version: 1, Path: "2026/energy/edf/2026-04-02_edf_invoice_84-12EUR.pdf"},
	}
	if !slices.EqualFunc(res.Documents, wantDocs, equalResult) {
		t.Fatalf("documents\n got %+v\nwant %+v", res.Documents, wantDocs)
	}
	wantWarn := []orchestrator.Warning{
		{Source: "inbox", Path: "big.pdf", Reason: "too-large"},
		{Source: "inbox", Path: "unknown.pdf", Reason: "unidentified"},
	}
	if !slices.Equal(res.Warnings, wantWarn) {
		t.Fatalf("warnings = %+v, want %+v", res.Warnings, wantWarn)
	}
	if got := src.doneList(); !slices.Equal(got, []string{"2026-03-14_edf_invoice_84-12EUR_10234567.pdf", "edf/scan.pdf"}) {
		t.Fatalf("Done = %q, want both filed items", got)
	}
}

func TestIngestInbox_ChangedFileNotFiled(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	a, b := pdf("a"), pdf("b")
	other := edfDoc()
	other.Ref = "10234568"
	src := newFakeInbox(r.ev,
		[]inbox.Item{item("a.pdf", edfDoc(), a), item("b.pdf", other, b)},
		map[string][]byte{"a.pdf": a, "b.pdf": b})
	src.openErr["a.pdf"] = fmt.Errorf("inbox open %q: %w", "a.pdf", inbox.ErrChanged)

	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	if len(res.Documents) != 2 || res.Documents[0].Status != orchestrator.StatusChanged || res.Documents[1].Status != orchestrator.StatusFiled {
		t.Fatalf("documents = %+v, want [changed, filed]", res.Documents)
	}
	if got := src.doneList(); !slices.Equal(got, []string{"b.pdf"}) {
		t.Fatalf("Done = %q, want only b.pdf", got)
	}
	if got := r.ev.withPrefix("put"); len(got) != 1 {
		t.Fatalf("puts = %q, want only b.pdf filed", got)
	}
}

func TestIngestInbox_ScanErrorReturned(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	boom := errors.New("synthetic scan failure")
	src := newFakeInbox(r.ev, nil, nil)
	src.scanErr = boom
	res, err := r.o.IngestInbox(t.Context(), src)
	if !errors.Is(err, boom) {
		t.Fatalf("IngestInbox() error = %v, want the scan error", err)
	}
	if len(res.Documents) != 0 {
		t.Fatalf("documents = %+v, want none", res.Documents)
	}
}

func TestIngestInbox_ContextCanceled(t *testing.T) {
	t.Parallel()
	contents := map[string][]byte{"a.pdf": pdf("a"), "b.pdf": pdf("b"), "c.pdf": pdf("c")}
	items := func() []inbox.Item {
		var out []inbox.Item
		for i, p := range []string{"a.pdf", "b.pdf", "c.pdf"} {
			d := edfDoc()
			d.Ref = "ref-" + string(rune('a'+i))
			out = append(out, item(p, d, contents[p]))
		}
		return out
	}

	t.Run("before start", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, nil)
		src := newFakeInbox(r.ev, items(), contents)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := r.o.IngestInbox(ctx, src)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("IngestInbox() error = %v, want context.Canceled", err)
		}
		if len(r.dst.put()) != 0 || len(src.doneList()) != 0 {
			t.Fatal("filed or removed something under a canceled context")
		}
	})

	t.Run("mid run stops the loop", func(t *testing.T) {
		t.Parallel()
		r := newRig(t, nil)
		src := newFakeInbox(r.ev, items(), contents)
		ctx, cancel := context.WithCancel(t.Context())
		r.dst.after = cancel // canceled right after the first Put
		res, err := r.o.IngestInbox(ctx, src)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("IngestInbox() error = %v, want context.Canceled", err)
		}
		if got := src.openedList(); !slices.Equal(got, []string{"a.pdf"}) {
			t.Fatalf("opened = %q, want the loop to stop after a.pdf", got)
		}
		// The Put of a.pdf succeeded: its index row must be written anyway,
		// or the stored file would clash (ErrExists) on every later run.
		if got := r.ev.withPrefix("insert:"); !slices.Equal(got, []string{"insert:edf/ref-a/v1"}) {
			t.Fatalf("inserts = %q, want a.pdf indexed after its Put", got)
		}
		if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusFiled || res.Documents[0].Path == "" {
			t.Fatalf("documents = %+v, want a.pdf filed with its path", res.Documents)
		}
		docs := r.idx.all()
		if len(docs) != 1 || docs[0].ProviderID != "ref-a" || docs[0].LocalPath != res.Documents[0].Path {
			t.Fatalf("index = %+v, want a.pdf recorded at %q", docs, res.Documents[0].Path)
		}
		if d := src.doneList(); len(d) != 0 {
			t.Fatalf("Done = %q, want nothing removed after cancellation", d)
		}
		if len(res.Warnings) != 0 {
			t.Fatalf("warnings = %+v, want none (removal skipped, not failed)", res.Warnings)
		}
	})
}

func TestIngest_LogsAreRedacted(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	tests := []struct {
		name    string
		breakIt func(*rig)
	}{
		{"destination error carries a token in a url", func(r *rig) {
			r.dst.err = errors.New("upload https://upload.example.invalid/files?access_token=" + canary + ": synthetic failure")
		}},
		{"destination error carries a bare token", func(r *rig) {
			r.dst.err = errors.New("synthetic failure, token " + canary)
		}},
		{"index error carries a token", func(r *rig) {
			r.idx.hasErr = errors.New("synthetic index failure: " + canary)
		}},
		{"insert error carries a token", func(r *rig) {
			r.idx.insertErr = errors.New("synthetic insert failure: session=" + canary)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, nil)
			tt.breakIt(r)
			content := pdf("logged")
			src := newFakeInbox(r.ev, []inbox.Item{item("drop.pdf", edfDoc(), content)}, map[string][]byte{"drop.pdf": content})
			res, err := r.o.IngestInbox(t.Context(), src)
			if err != nil {
				t.Fatalf("IngestInbox() error = %v", err)
			}
			if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusFailed {
				t.Fatalf("documents = %+v, want one failed", res.Documents)
			}
			out := r.log.String()
			if !strings.Contains(out, `"level":"WARN"`) && !strings.Contains(out, `"level":"ERROR"`) {
				t.Fatalf("failure not logged at warn or error level; log:\n%s", out)
			}
			if strings.Contains(out, canary) {
				t.Fatalf("canary leaked into the log:\n%s", out)
			}
			if strings.Contains(out, strings.TrimSpace(string(content))) {
				t.Fatalf("document content leaked into the log:\n%s", out)
			}
		})
	}
}

// --- helpers ------------------------------------------------------------------

func withVersion(d normalize.Doc, v int) normalize.Doc {
	d.Version = v
	return d
}

// equalResult compares DocResults field by field.
func equalResult(a, b orchestrator.DocResult) bool { return a == b }

// equalDoc compares two index rows, ignoring CollectedAt.
func equalDoc(a, b store.Document) bool {
	return docString(a) == docString(b) && a.SHA256 == b.SHA256
}

func docString(d store.Document) string {
	amount := "nil"
	if d.AmountCents != nil {
		amount = fmt.Sprint(*d.AmountCents)
	}
	return fmt.Sprintf("provider=%q id=%q kind=%v issued=%s start=%s end=%s amount=%s currency=%q local=%q drive=%q v%d",
		d.Provider, d.ProviderID, d.Kind, d.IssuedAt.UTC().Format(time.RFC3339), d.PeriodStart.UTC().Format(time.RFC3339),
		d.PeriodEnd.UTC().Format(time.RFC3339), amount, d.Currency, d.LocalPath, d.DriveID, d.Version)
}
