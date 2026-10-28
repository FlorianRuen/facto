package normalize_test

// Dedup decision (J0 T15), spec "Normalization and naming" → Dedup:
//  1. before download: (provider, ProviderID) already indexed → SkipKnownID
//     (BeforeFetch; otherwise New = "fetch it, then call Decide");
//  2. after download: SHA-256 already indexed, under ANY provider → SkipSameHash
//     (rule 2 wins over rule 3: same id + same bytes is a duplicate);
//  3. same (provider, ProviderID), different hash → NewVersion(latest+1).
//
// An empty ProviderID identifies nothing: rule 1 and rule 3 never apply to it
// (two inbox drops without an id must not become versions of each other), and
// the index is not asked about it. Decide/BeforeFetch are pure apart from idx:
// they pass ctx through and wrap index errors with %w, returning a zero
// Decision. API in naming_test.go.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/normalize"
)

type idKey struct{ provider, providerID string }

// fakeIndex is an in-memory normalize.Index that records its calls.
type fakeIndex struct {
	latest  map[idKey]int
	hashes  map[[32]byte]bool
	errID   error
	errHash error

	idCalls   []idKey
	hashCalls int
	ctxSeen   []context.Context
}

func (f *fakeIndex) LatestVersion(ctx context.Context, provider, providerID string) (int, bool, error) {
	f.ctxSeen = append(f.ctxSeen, ctx)
	f.idCalls = append(f.idCalls, idKey{provider, providerID})
	if f.errID != nil {
		return 0, false, f.errID
	}
	v, ok := f.latest[idKey{provider, providerID}]
	return v, ok, nil
}

func (f *fakeIndex) HasSHA256(ctx context.Context, sum [32]byte) (bool, error) {
	f.ctxSeen = append(f.ctxSeen, ctx)
	f.hashCalls++
	if f.errHash != nil {
		return false, f.errHash
	}
	return f.hashes[sum], nil
}

var _ normalize.Index = (*fakeIndex)(nil)

var (
	pdfA = sha256.Sum256([]byte("%PDF-1.7 synthetic invoice A"))
	pdfB = sha256.Sum256([]byte("%PDF-1.7 synthetic invoice B (corrected)"))
	pdfC = sha256.Sum256([]byte("%PDF-1.7 synthetic invoice C"))

	errIndexDown = errors.New("index: database is locked")
)

func docRef(id string) connector.DocumentRef {
	return connector.DocumentRef{
		ProviderID: id, Kind: connector.Invoice, IssuedAt: time.Date(2026, time.March, 14, 0, 0, 0, 0, time.UTC),
		Currency: "EUR", MimeType: "application/pdf",
	}
}

// seeded: edf/INV-001 v1 (pdfA); edf/INV-002 v1 and v2; ileo/W-1 v1 (pdfC).
func seeded() *fakeIndex {
	return &fakeIndex{
		latest: map[idKey]int{
			{"edf", "INV-001"}: 1,
			{"edf", "INV-002"}: 2,
			{"ileo", "W-1"}:    1,
		},
		hashes: map[[32]byte]bool{pdfA: true, pdfC: true},
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		idx      *fakeIndex
		provider string
		id       string
		sum      [32]byte
		want     normalize.Decision
	}{
		{"unknown id, unknown hash: new", seeded(), "edf", "INV-999", pdfB, normalize.Decision{Action: normalize.New, Version: 1}},
		{"rule 2: known hash under a new id", seeded(), "edf", "INV-999", pdfA, normalize.Decision{Action: normalize.SkipSameHash}},
		{"rule 2: same hash under another provider", seeded(), "edf", "INV-999", pdfC, normalize.Decision{Action: normalize.SkipSameHash}},
		{"rule 2 before rule 3: same id, same hash", seeded(), "edf", "INV-001", pdfA, normalize.Decision{Action: normalize.SkipSameHash}},
		{"rule 3: same id, new hash: v2", seeded(), "edf", "INV-001", pdfB, normalize.Decision{Action: normalize.NewVersion, Version: 2}},
		{"rule 3: v3 after v2", seeded(), "edf", "INV-002", pdfB, normalize.Decision{Action: normalize.NewVersion, Version: 3}},
		{"same id under another provider is a different document", seeded(), "edf", "W-1", pdfB, normalize.Decision{Action: normalize.New, Version: 1}},
		{"empty ProviderID: never a version", &fakeIndex{latest: map[idKey]int{{"edf", ""}: 4}, hashes: map[[32]byte]bool{}}, "edf", "", pdfB, normalize.Decision{Action: normalize.New, Version: 1}},
		{"empty ProviderID: hash still deduplicates", seeded(), "edf", "", pdfA, normalize.Decision{Action: normalize.SkipSameHash}},
		{"empty index", &fakeIndex{}, "edf", "INV-001", pdfA, normalize.Decision{Action: normalize.New, Version: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalize.Decide(t.Context(), tc.idx, tc.provider, docRef(tc.id), tc.sum)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Decide = %+v (%v), want %+v (%v)", got, got.Action, tc.want, tc.want.Action)
			}
			if tc.id == "" {
				for _, c := range tc.idx.idCalls {
					if c.providerID == "" {
						t.Fatalf("index asked about an empty ProviderID: %+v", c)
					}
				}
			}
		})
	}
}

func TestBeforeFetch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		idx      *fakeIndex
		provider string
		id       string
		want     normalize.Decision
	}{
		{"rule 1: known id skipped", seeded(), "edf", "INV-001", normalize.Decision{Action: normalize.SkipKnownID}},
		{"rule 1: known id with versions skipped", seeded(), "edf", "INV-002", normalize.Decision{Action: normalize.SkipKnownID}},
		{"unknown id: fetch", seeded(), "edf", "INV-999", normalize.Decision{Action: normalize.New, Version: 1}},
		{"known id under another provider: fetch", seeded(), "ileo", "INV-001", normalize.Decision{Action: normalize.New, Version: 1}},
		{"empty ProviderID: always fetch", &fakeIndex{latest: map[idKey]int{{"edf", ""}: 1}}, "edf", "", normalize.Decision{Action: normalize.New, Version: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalize.BeforeFetch(t.Context(), tc.idx, tc.provider, docRef(tc.id))
			if err != nil {
				t.Fatalf("BeforeFetch: %v", err)
			}
			if got != tc.want {
				t.Fatalf("BeforeFetch = %+v, want %+v", got, tc.want)
			}
			if tc.idx.hashCalls != 0 {
				t.Fatalf("BeforeFetch looked up a hash (%d calls): rule 1 needs none", tc.idx.hashCalls)
			}
			if tc.id == "" && len(tc.idx.idCalls) != 0 {
				t.Fatalf("index asked about an empty ProviderID: %+v", tc.idx.idCalls)
			}
		})
	}
}

// TestDecide_PropagatesIndexError: an index failure is never mistaken for
// "new" (which would file a duplicate) nor for "skip" (which would lose a
// document).
func TestDecide_PropagatesIndexError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		idx    *fakeIndex
		id     string
		before bool
	}{
		{"Decide: hash lookup fails", &fakeIndex{errHash: errIndexDown}, "INV-001", false},
		{"Decide: id lookup fails", &fakeIndex{errID: errIndexDown}, "INV-001", false},
		{"Decide: both fail", &fakeIndex{errHash: errIndexDown, errID: errIndexDown}, "INV-001", false},
		{"BeforeFetch: id lookup fails", &fakeIndex{errID: errIndexDown}, "INV-001", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				got normalize.Decision
				err error
			)
			if tc.before {
				got, err = normalize.BeforeFetch(t.Context(), tc.idx, "edf", docRef(tc.id))
			} else {
				got, err = normalize.Decide(t.Context(), tc.idx, "edf", docRef(tc.id), pdfB)
			}
			if !errors.Is(err, errIndexDown) {
				t.Fatalf("err = %v, want it to wrap %v", err, errIndexDown)
			}
			if got != (normalize.Decision{}) {
				t.Fatalf("returned %+v alongside an error", got)
			}
		})
	}
}

type ctxKey struct{}

// TestDecide_PassesContext: the caller's ctx (deadline, cancellation) reaches
// the index.
func TestDecide_PassesContext(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(t.Context(), ctxKey{}, "run-42")
	idx := seeded()
	if _, err := normalize.Decide(ctx, idx, "edf", docRef("INV-001"), pdfB); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if _, err := normalize.BeforeFetch(ctx, idx, "edf", docRef("INV-001")); err != nil {
		t.Fatalf("BeforeFetch: %v", err)
	}
	if len(idx.ctxSeen) == 0 {
		t.Fatal("index never called")
	}
	for i, c := range idx.ctxSeen {
		if c.Value(ctxKey{}) != "run-42" {
			t.Fatalf("index call %d got a different context", i)
		}
	}
}

func TestAction_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a    normalize.Action
		want string
	}{
		{normalize.New, "new"},
		{normalize.NewVersion, "new-version"},
		{normalize.SkipKnownID, "skip-known-id"},
		{normalize.SkipSameHash, "skip-same-hash"},
		{normalize.Action(0), "Action(0)"},
		{normalize.Action(42), "Action(42)"},
	}
	for _, tc := range tests {
		if got := tc.a.String(); got != tc.want {
			t.Errorf("Action(%d).String() = %q, want %q", int(tc.a), got, tc.want)
		}
		if got := fmt.Sprint(tc.a); got != tc.want {
			t.Errorf("fmt.Sprint(Action(%d)) = %q, want %q", int(tc.a), got, tc.want)
		}
	}
}

// TestDecide_VersionFeedsRender: the Decision version renders the spec's
// "_v2" suffix (rule 3 "new version suffixed _v2, the old one kept").
func TestDecide_VersionFeedsRender(t *testing.T) {
	t.Parallel()
	got, err := normalize.Decide(t.Context(), seeded(), "edf", docRef("INV-001"), pdfB)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	n := newNamer(t, normalize.Config{})
	p := render(t, n, normalize.Doc{Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14), Ref: "INV-001", Ext: "pdf", Version: got.Version})
	if want := "2026-03-14_edf_invoice_inv-001_v2.pdf"; p.File != want {
		t.Fatalf("File = %q, want %q", p.File, want)
	}
}
