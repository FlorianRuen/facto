// Tests for package store, the SQLite document index (J0 task T20). Permission
// tests live in store_unix_test.go. The driver is modernc.org/sqlite (ADR 0004),
// imported by store itself: these tests never import it.
//
// Expected API (implementer: follow exactly):
//
//	// FileName is the database file created inside the state directory.
//	const FileName = "index.db"
//
//	// Sentinel errors.
//	var ErrDuplicate       error // (provider, provider_id, version) already stored
//	var ErrInvalidDocument error // Insert input fails validation (see Insert)
//
//	// Document is one row of the documents table. Times are UTC.
//	type Document struct {
//		Provider    string            // connector id or inbox provider slug, required
//		ProviderID  string            // "" for documents without a supplier id (stored NULL)
//		Kind        connector.DocKind // must be a valid kind
//		IssuedAt    time.Time
//		PeriodStart time.Time         // zero = unknown, round-trips as zero
//		PeriodEnd   time.Time         // zero = unknown, round-trips as zero
//		AmountCents *int64            // nil = unknown; nil and 0 are distinct
//		Currency    string            // ISO 4217, "" allowed when AmountCents is nil
//		SHA256      [32]byte          // content hash, must not be all zero
//		LocalPath   string            // path under the output folder, "" if Drive only
//		DriveID     string            // Drive file id, "" if local only
//		CollectedAt time.Time         // set by Insert from the clock; input ignored
//		Version     int               // >= 1
//	}
//
//	// Store is the SQLite index. Safe for concurrent use. It implements
//	// normalize.Index.
//	type Store struct{ /* *sql.DB, clock.Clock */ }
//
//	// Open creates dir (mode 0700, through fsx; its parent must exist) if it
//	// is missing, pre-creates dir/FileName 0600 through fsx before SQLite
//	// opens it, opens the database and runs Migrate. An existing dir or
//	// database file with group/world bits is refused with an error wrapping
//	// fsx.ErrInsecurePerms. A missing parent wraps fs.ErrNotExist. Every
//	// file SQLite creates next to the database (-wal, -shm, -journal) is 0600.
//	func Open(ctx context.Context, dir string, clk clock.Clock) (*Store, error)
//	func (s *Store) Close() error // later calls return a non-nil error, never panic
//
//	// Migrate applies the embedded migrations not yet applied. Idempotent.
//	// Schema: documents(provider, provider_id, kind, issued_at, period_start,
//	// period_end, amount_cents, currency, sha256, local_path, drive_id,
//	// collected_at, version), UNIQUE(provider, provider_id, version),
//	// index on sha256.
//	func (s *Store) Migrate(ctx context.Context) error
//
//	// Insert stores d with CollectedAt = clk.Now() and returns the stored
//	// document. Invalid input (empty Provider, Version < 1, invalid Kind,
//	// all-zero SHA256) wraps ErrInvalidDocument and stores nothing. An
//	// existing (Provider, ProviderID, Version) wraps ErrDuplicate and stores
//	// nothing. Documents with an empty ProviderID never collide.
//	func (s *Store) Insert(ctx context.Context, d Document) (Document, error)
//
//	// FindByProviderID returns every version of (provider, providerID),
//	// ordered by Version ascending; an empty (non-nil error free) slice when
//	// none. An empty providerID matches nothing.
//	func (s *Store) FindByProviderID(ctx context.Context, provider, providerID string) ([]Document, error)
//
//	// FindBySHA256 returns the first stored document (insertion order) with
//	// this hash, whatever its provider; found is false when there is none.
//	func (s *Store) FindBySHA256(ctx context.Context, sum [32]byte) (doc Document, found bool, err error)
//
//	// normalize.Index.
//	func (s *Store) LatestVersion(ctx context.Context, provider, providerID string) (version int, found bool, err error)
//	func (s *Store) HasSHA256(ctx context.Context, sum [32]byte) (bool, error)
//
//	// NextVersion returns 1 when (provider, providerID) is unknown or
//	// providerID is empty, latest+1 otherwise.
//	func (s *Store) NextVersion(ctx context.Context, provider, providerID string) (int, error)
//
// Every method wraps a canceled or expired context (errors.Is works) and
// stores nothing in that case.
package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/store"
)

// Compile-time check: the store is the index the dedup rules read.
var _ normalize.Index = (*store.Store)(nil)

var t0 = time.Date(2026, 10, 28, 9, 30, 0, 0, time.UTC)

func newClock() *clock.Fake { return clock.NewFake(t0) }

// stateDir returns a not-yet-existing state directory inside a private temp dir.
func stateDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

func openStore(t *testing.T, dir string, clk clock.Clock) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), dir, clk)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newStore(t *testing.T) (*store.Store, *clock.Fake) {
	t.Helper()
	clk := newClock()
	return openStore(t, stateDir(t), clk), clk
}

func sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func cents(v int64) *int64 { return &v }

// doc returns a valid synthetic document.
func doc(provider, id string, version int, content string) store.Document {
	return store.Document{
		Provider:    provider,
		ProviderID:  id,
		Kind:        connector.Invoice,
		IssuedAt:    time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
		PeriodStart: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		AmountCents: cents(8412),
		Currency:    "EUR",
		SHA256:      sum(content),
		LocalPath:   "2026/housing/" + provider + "/2026-03-14_" + provider + "_invoice.pdf",
		DriveID:     "",
		Version:     version,
	}
}

func mustInsert(t *testing.T, s *store.Store, d store.Document) store.Document {
	t.Helper()
	got, err := s.Insert(context.Background(), d)
	if err != nil {
		t.Fatalf("Insert(%s/%s v%d): %v", d.Provider, d.ProviderID, d.Version, err)
	}
	return got
}

// sameDoc compares every field, times with Equal and in UTC, the amount by
// value with nil distinct from 0.
func sameDoc(t *testing.T, got, want store.Document) {
	t.Helper()
	if got.Provider != want.Provider || got.ProviderID != want.ProviderID ||
		got.Kind != want.Kind || got.Currency != want.Currency ||
		got.SHA256 != want.SHA256 || got.LocalPath != want.LocalPath ||
		got.DriveID != want.DriveID || got.Version != want.Version {
		t.Errorf("document mismatch:\n got  %+v\n want %+v", got, want)
	}
	times := []struct {
		name      string
		got, want time.Time
	}{
		{"IssuedAt", got.IssuedAt, want.IssuedAt},
		{"PeriodStart", got.PeriodStart, want.PeriodStart},
		{"PeriodEnd", got.PeriodEnd, want.PeriodEnd},
		{"CollectedAt", got.CollectedAt, want.CollectedAt},
	}
	for _, tt := range times {
		if tt.want.IsZero() {
			if !tt.got.IsZero() {
				t.Errorf("%s = %v, want zero time", tt.name, tt.got)
			}
			continue
		}
		if !tt.got.Equal(tt.want) {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
		if tt.got.Location() != time.UTC {
			t.Errorf("%s location = %v, want UTC", tt.name, tt.got.Location())
		}
	}
	switch {
	case got.AmountCents == nil && want.AmountCents == nil:
	case got.AmountCents == nil || want.AmountCents == nil:
		t.Errorf("AmountCents = %v, want %v (nil and 0 are distinct)", got.AmountCents, want.AmountCents)
	case *got.AmountCents != *want.AmountCents:
		t.Errorf("AmountCents = %d, want %d", *got.AmountCents, *want.AmountCents)
	}
}

func TestStore_InsertFindByProviderID(t *testing.T) {
	t.Parallel()
	paris := time.FixedZone("UTC+2", 2*60*60)

	full := doc("ileo", "F-2026-0001", 1, "pdf-full")

	noOptionals := doc("edf", "10234567", 1, "pdf-minimal")
	noOptionals.PeriodStart = time.Time{}
	noOptionals.PeriodEnd = time.Time{}
	noOptionals.AmountCents = nil
	noOptionals.Currency = ""
	noOptionals.DriveID = "drive-file-synthetic-01"
	noOptionals.LocalPath = ""
	noOptionals.Kind = connector.Statement

	zeroAmount := doc("wecasa", "W-7", 1, "pdf-zero")
	zeroAmount.AmountCents = cents(0)

	negativeAmount := doc("cooloc", "C-credit-1", 1, "pdf-credit")
	negativeAmount.Kind = connector.RentReceipt
	negativeAmount.AmountCents = cents(-1250)

	nonUTC := doc("fournisseur-exemple", "X-1", 1, "pdf-tz")
	nonUTC.IssuedAt = time.Date(2026, 5, 2, 1, 15, 0, 0, paris)

	// Hostile values are data, never SQL.
	injection := doc("ileo", `x'); DROP TABLE documents;--`, 1, "pdf-inject")
	injection.LocalPath = `2026/housing/ileo/a'b"c;--.pdf`

	unicode := doc("bouyguestelecom", "Facture n°42 été", 1, "pdf-unicode")

	tests := []struct {
		name string
		in   store.Document
	}{
		{"all fields", full},
		{"optional fields empty", noOptionals},
		{"zero amount is not nil", zeroAmount},
		{"negative amount", negativeAmount},
		{"non UTC input stored as same instant", nonUTC},
		{"sql metacharacters are data", injection},
		{"unicode provider id", unicode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, clk := newStore(t)
			in := tt.in
			in.CollectedAt = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) // must be ignored

			want := tt.in
			want.CollectedAt = clk.Now()

			got, err := s.Insert(context.Background(), in)
			if err != nil {
				t.Fatalf("Insert: %v", err)
			}
			sameDoc(t, got, want)

			found, err := s.FindByProviderID(context.Background(), tt.in.Provider, tt.in.ProviderID)
			if err != nil {
				t.Fatalf("FindByProviderID: %v", err)
			}
			if len(found) != 1 {
				t.Fatalf("FindByProviderID returned %d documents, want 1", len(found))
			}
			sameDoc(t, found[0], want)
		})
	}
}

func TestStore_FindByProviderID_VersionsAndScope(t *testing.T) {
	t.Parallel()
	s, clk := newStore(t)

	v1 := mustInsert(t, s, doc("edf", "10234567", 1, "v1"))
	clk.Advance(24 * time.Hour)
	v2 := mustInsert(t, s, doc("edf", "10234567", 2, "v2"))
	mustInsert(t, s, doc("edf", "other", 1, "other"))
	mustInsert(t, s, doc("ileo", "10234567", 1, "same id other provider"))

	if !v2.CollectedAt.Equal(t0.Add(24 * time.Hour)) {
		t.Errorf("v2 CollectedAt = %v, want fake clock %v", v2.CollectedAt, t0.Add(24*time.Hour))
	}

	got, err := s.FindByProviderID(context.Background(), "edf", "10234567")
	if err != nil {
		t.Fatalf("FindByProviderID: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d documents, want 2 (v1, v2 of edf only)", len(got))
	}
	sameDoc(t, got[0], v1)
	sameDoc(t, got[1], v2)

	for _, q := range []struct{ provider, id string }{
		{"edf", "missing"},
		{"unknown", "10234567"},
		{"EDF", "10234567"}, // provider ids are exact, no case folding
		{"edf", ""},         // empty id matches nothing
	} {
		got, err := s.FindByProviderID(context.Background(), q.provider, q.id)
		if err != nil {
			t.Errorf("FindByProviderID(%q, %q): %v", q.provider, q.id, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("FindByProviderID(%q, %q) = %d documents, want 0", q.provider, q.id, len(got))
		}
	}
}

func TestStore_FindBySHA(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()

	edf := mustInsert(t, s, doc("edf", "10234567", 1, "edf-pdf"))
	inbox := doc("impots", "", 1, "inbox-pdf")
	inbox = mustInsert(t, s, inbox)

	tests := []struct {
		name      string
		sum       [32]byte
		wantFound bool
		want      store.Document
	}{
		{"connector document", sum("edf-pdf"), true, edf},
		{"document without provider id", sum("inbox-pdf"), true, inbox},
		{"unknown hash", sum("never stored"), false, store.Document{}},
		{"zero hash", [32]byte{}, false, store.Document{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := s.FindBySHA256(ctx, tt.sum)
			if err != nil {
				t.Fatalf("FindBySHA256: %v", err)
			}
			if found != tt.wantFound {
				t.Fatalf("FindBySHA256 found = %v, want %v", found, tt.wantFound)
			}
			if found {
				sameDoc(t, got, tt.want)
			}

			has, err := s.HasSHA256(ctx, tt.sum)
			if err != nil {
				t.Fatalf("HasSHA256: %v", err)
			}
			if has != tt.wantFound {
				t.Errorf("HasSHA256 = %v, want %v", has, tt.wantFound)
			}
		})
	}
}

func TestStore_NextVersion(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()

	mustInsert(t, s, doc("edf", "one", 1, "one-v1"))
	mustInsert(t, s, doc("edf", "three", 1, "three-v1"))
	mustInsert(t, s, doc("edf", "three", 2, "three-v2"))
	mustInsert(t, s, doc("edf", "three", 3, "three-v3"))
	// A gap: latest is what counts, not the row count.
	mustInsert(t, s, doc("edf", "gap", 1, "gap-v1"))
	mustInsert(t, s, doc("edf", "gap", 5, "gap-v5"))
	mustInsert(t, s, doc("impots", "", 1, "no-id"))

	tests := []struct {
		name, provider, id string
		wantLatest         int
		wantFound          bool
		wantNext           int
	}{
		{"unknown id", "edf", "missing", 0, false, 1},
		{"unknown provider", "ileo", "one", 0, false, 1},
		{"single version", "edf", "one", 1, true, 2},
		{"three versions", "edf", "three", 3, true, 4},
		{"gap uses max", "edf", "gap", 5, true, 6},
		{"empty id is never versioned", "impots", "", 0, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			latest, found, err := s.LatestVersion(ctx, tt.provider, tt.id)
			if err != nil {
				t.Fatalf("LatestVersion: %v", err)
			}
			if latest != tt.wantLatest || found != tt.wantFound {
				t.Errorf("LatestVersion = (%d, %v), want (%d, %v)", latest, found, tt.wantLatest, tt.wantFound)
			}
			next, err := s.NextVersion(ctx, tt.provider, tt.id)
			if err != nil {
				t.Fatalf("NextVersion: %v", err)
			}
			if next != tt.wantNext {
				t.Errorf("NextVersion = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

// TestStore_DrivesDedupRules wires the real store into normalize.Decide: the
// spec's three dedup rules hold end to end.
func TestStore_DrivesDedupRules(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	ref := connector.DocumentRef{ProviderID: "10234567", Kind: connector.Invoice}

	d, err := normalize.BeforeFetch(ctx, s, "edf", ref)
	if err != nil || d.Action != normalize.New {
		t.Fatalf("BeforeFetch on empty store = (%v, %v), want new", d.Action, err)
	}
	mustInsert(t, s, doc("edf", "10234567", 1, "original"))

	d, err = normalize.BeforeFetch(ctx, s, "edf", ref)
	if err != nil || d.Action != normalize.SkipKnownID {
		t.Errorf("BeforeFetch after insert = (%v, %v), want skip-known-id", d.Action, err)
	}
	d, err = normalize.Decide(ctx, s, "ileo", connector.DocumentRef{ProviderID: "other"}, sum("original"))
	if err != nil || d.Action != normalize.SkipSameHash {
		t.Errorf("Decide same hash = (%v, %v), want skip-same-hash", d.Action, err)
	}
	d, err = normalize.Decide(ctx, s, "edf", ref, sum("corrected"))
	if err != nil || d.Action != normalize.NewVersion || d.Version != 2 {
		t.Errorf("Decide new hash = (%v v%d, %v), want new-version v2", d.Action, d.Version, err)
	}
}

func TestStore_UniqueViolation(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	original := mustInsert(t, s, doc("edf", "10234567", 1, "first"))

	dup := doc("edf", "10234567", 1, "second") // same key, other content
	dup.LocalPath = "elsewhere.pdf"
	if _, err := s.Insert(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("Insert duplicate key: err = %v, want ErrDuplicate", err)
	}

	got, err := s.FindByProviderID(ctx, "edf", "10234567")
	if err != nil {
		t.Fatalf("FindByProviderID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows after rejected duplicate, want 1", len(got))
	}
	sameDoc(t, got[0], original)
	if has, err := s.HasSHA256(ctx, sum("second")); err != nil || has {
		t.Errorf("HasSHA256(rejected content) = (%v, %v), want (false, nil)", has, err)
	}

	// Not duplicates: another version, another provider, another id, and
	// documents without a provider id (stored NULL, never colliding).
	for _, d := range []store.Document{
		doc("edf", "10234567", 2, "v2"),
		doc("ileo", "10234567", 1, "ileo"),
		doc("edf", "10234568", 1, "next id"),
		doc("impots", "", 1, "inbox-a"),
		doc("impots", "", 1, "inbox-b"),
	} {
		if _, err := s.Insert(ctx, d); err != nil {
			t.Errorf("Insert(%s/%q v%d): %v, want no error", d.Provider, d.ProviderID, d.Version, err)
		}
	}
}

func TestStore_InsertRejectsInvalidDocument(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*store.Document)
	}{
		{"empty provider", func(d *store.Document) { d.Provider = "" }},
		{"version zero", func(d *store.Document) { d.Version = 0 }},
		{"negative version", func(d *store.Document) { d.Version = -1 }},
		{"zero kind", func(d *store.Document) { d.Kind = 0 }},
		{"unknown kind", func(d *store.Document) { d.Kind = connector.DocKind(999) }},
		{"zero hash", func(d *store.Document) { d.SHA256 = [32]byte{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newStore(t)
			d := doc("edf", "10234567", 1, "content")
			tt.mutate(&d)
			if _, err := s.Insert(context.Background(), d); !errors.Is(err, store.ErrInvalidDocument) {
				t.Fatalf("Insert: err = %v, want ErrInvalidDocument", err)
			}
			if has, err := s.HasSHA256(context.Background(), d.SHA256); err != nil || has {
				t.Errorf("HasSHA256 after rejected insert = (%v, %v), want (false, nil)", has, err)
			}
			if _, found, err := s.LatestVersion(context.Background(), d.Provider, d.ProviderID); err != nil || found {
				t.Errorf("LatestVersion after rejected insert: found = %v, err = %v", found, err)
			}
		})
	}
}

func TestStore_MigrateIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := stateDir(t)
	clk := newClock()

	s1, err := store.Open(ctx, dir, clk)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	stored := mustInsert(t, s1, doc("edf", "10234567", 1, "persisted"))
	for i := range 2 {
		if err := s1.Migrate(ctx); err != nil {
			t.Fatalf("Migrate #%d on a migrated store: %v", i+1, err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening runs Migrate again on an up-to-date schema and keeps data.
	s2 := openStore(t, dir, clk)
	got, err := s2.FindByProviderID(ctx, "edf", "10234567")
	if err != nil {
		t.Fatalf("FindByProviderID after reopen: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d documents after reopen, want 1", len(got))
	}
	sameDoc(t, got[0], stored)

	// The unique constraint and the store still work after re-migration.
	if _, err := s2.Insert(ctx, doc("edf", "10234567", 1, "again")); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("Insert duplicate after reopen: err = %v, want ErrDuplicate", err)
	}
	mustInsert(t, s2, doc("edf", "10234567", 2, "v2"))
}

func TestStore_ContextCanceled(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	mustInsert(t, s, doc("edf", "known", 1, "known"))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Unix(1, 0)) // long past
	defer cancel2()

	ctxs := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"canceled", canceled, context.Canceled},
		{"deadline exceeded", expired, context.DeadlineExceeded},
	}
	ops := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"Insert", func(ctx context.Context) error {
			_, err := s.Insert(ctx, doc("edf", "new", 1, "never stored"))
			return err
		}},
		{"FindByProviderID", func(ctx context.Context) error {
			_, err := s.FindByProviderID(ctx, "edf", "known")
			return err
		}},
		{"FindBySHA256", func(ctx context.Context) error {
			_, _, err := s.FindBySHA256(ctx, sum("known"))
			return err
		}},
		{"HasSHA256", func(ctx context.Context) error {
			_, err := s.HasSHA256(ctx, sum("known"))
			return err
		}},
		{"LatestVersion", func(ctx context.Context) error {
			_, _, err := s.LatestVersion(ctx, "edf", "known")
			return err
		}},
		{"NextVersion", func(ctx context.Context) error {
			_, err := s.NextVersion(ctx, "edf", "known")
			return err
		}},
		{"Migrate", func(ctx context.Context) error { return s.Migrate(ctx) }},
		{"Open", func(ctx context.Context) error {
			s2, err := store.Open(ctx, stateDir(t), newClock())
			if err == nil {
				_ = s2.Close()
			}
			return err
		}},
	}
	for _, c := range ctxs {
		for _, op := range ops {
			t.Run(c.name+"/"+op.name, func(t *testing.T) {
				if err := op.call(c.ctx); !errors.Is(err, c.want) {
					t.Errorf("%s: err = %v, want errors.Is %v", op.name, err, c.want)
				}
			})
		}
	}

	// Nothing was stored by the canceled Insert.
	if has, err := s.HasSHA256(context.Background(), sum("never stored")); err != nil || has {
		t.Errorf("HasSHA256 after canceled Insert = (%v, %v), want (false, nil)", has, err)
	}
}

func TestStore_ConcurrentInserts(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			_, err := s.Insert(ctx, doc("edf", fmt.Sprintf("id-%02d", i), 1, fmt.Sprintf("c-%02d", i)))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Insert: %v", err)
		}
	}
	for i := range n {
		if has, err := s.HasSHA256(ctx, sum(fmt.Sprintf("c-%02d", i))); err != nil || !has {
			t.Errorf("HasSHA256(c-%02d) = (%v, %v), want (true, nil)", i, has, err)
		}
	}
}

func TestStore_ClosedReturnsErrors(t *testing.T) {
	t.Parallel()
	s, err := store.Open(context.Background(), stateDir(t), newClock())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()
	if _, err := s.Insert(ctx, doc("edf", "x", 1, "x")); err == nil {
		t.Error("Insert after Close: want error")
	}
	if _, err := s.HasSHA256(ctx, sum("x")); err == nil {
		t.Error("HasSHA256 after Close: want error")
	}
	if _, _, err := s.LatestVersion(ctx, "edf", "x"); err == nil {
		t.Error("LatestVersion after Close: want error")
	}
}

func TestOpen_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("missing parent", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "no-such-parent", "state")
		if _, err := store.Open(ctx, dir, newClock()); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open: err = %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("dir is a file", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		r, err := fsx.Open(parent)
		if err != nil {
			t.Fatalf("fsx.Open: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.WriteAtomic(ctx, "state", []byte("not a dir")); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if s, err := store.Open(ctx, filepath.Join(parent, "state"), newClock()); err == nil {
			_ = s.Close()
			t.Error("Open on a regular file: want error")
		}
	})

	t.Run("database is a directory", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		r, err := fsx.Open(parent)
		if err != nil {
			t.Fatalf("fsx.Open: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.MkdirPrivate("state/" + store.FileName); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if s, err := store.Open(ctx, filepath.Join(parent, "state"), newClock()); err == nil {
			_ = s.Close()
			t.Error("Open with a directory at the database path: want error")
		}
	})

	t.Run("not a database", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		r, err := fsx.Open(parent)
		if err != nil {
			t.Fatalf("fsx.Open: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.MkdirPrivate("state"); err != nil {
			t.Fatalf("setup: %v", err)
		}
		garbage := make([]byte, 4096)
		for i := range garbage {
			garbage[i] = byte(i*7 + 3)
		}
		if err := r.WriteAtomic(ctx, "state/"+store.FileName, garbage); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if s, err := store.Open(ctx, filepath.Join(parent, "state"), newClock()); err == nil {
			_ = s.Close()
			t.Error("Open on a corrupt database: want error")
		}
	})
}

// TestOpen_CreatesDatabaseFile pins the on-disk name used by backups and docs.
func TestOpen_CreatesDatabaseFile(t *testing.T) {
	t.Parallel()
	dir := stateDir(t)
	openStore(t, dir, newClock())
	fi, err := os.Stat(filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatalf("Stat database: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("%s mode = %v, want a regular file", store.FileName, fi.Mode())
	}
	if store.FileName != "index.db" {
		t.Errorf("FileName = %q, want %q", store.FileName, "index.db")
	}
}
