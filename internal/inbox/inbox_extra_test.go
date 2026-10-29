// Extra tests for package inbox (J0 task T22), beyond the contract in
// inbox_test.go: item path shapes, forged sizes, and prompter answers that
// carry their own category.
package inbox_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// TestOpenDone_RejectUnscannablePaths: shapes Scan never produces are refused
// before touching the disk, even when a matching file exists.
func TestOpenDone_RejectUnscannablePaths(t *testing.T) {
	t.Parallel()
	content := plainPDF(t, "1")
	files := map[string][]byte{
		"edf/x/2026-03-14_edf_invoice.pdf": content,
		".hidden.pdf":                      content,
		"edf/.hidden.pdf":                  content,
	}
	dir := makeInbox(t, files)
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	for p := range files {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			before := snapshot(t, dir)
			it := inbox.Item{Path: p, Size: int64(len(content)), SHA256: sha256.Sum256(content)}
			if _, err := readAll(t, ib, it); !errors.Is(err, fsx.ErrInvalidName) {
				t.Fatalf("Open(%q) error = %v, want fsx.ErrInvalidName", p, err)
			}
			if err := ib.Done(t.Context(), it); !errors.Is(err, fsx.ErrInvalidName) {
				t.Fatalf("Done(%q) error = %v, want fsx.ErrInvalidName", p, err)
			}
			wantSnapshot(t, dir, before)
		})
	}
}

// TestOpenDone_ForgedSizes: an Item whose size cannot be a scanned one, or
// whose subfolder is a file or is missing, is refused without removing anything.
func TestOpenDone_ForgedSizes(t *testing.T) {
	t.Parallel()
	const p = "edf/2026-03-14_edf_invoice.pdf"
	content := plainPDF(t, "1")
	dir := makeInbox(t, map[string][]byte{p: content, "file.pdf": content})
	ib := newInbox(t, dir, inbox.Options{Providers: providers, MaxSize: 1 << 20})
	sum := sha256.Sum256(content)
	before := snapshot(t, dir)

	tests := []struct {
		name string
		it   inbox.Item
		want error
	}{
		{"negative size", inbox.Item{Path: p, Size: -1, SHA256: sum}, inbox.ErrChanged},
		{"over the cap", inbox.Item{Path: p, Size: 1<<20 + 1, SHA256: sum}, inbox.ErrChanged},
		{"other size", inbox.Item{Path: p, Size: int64(len(content)) - 1, SHA256: sum}, inbox.ErrChanged},
		{"subfolder is a file", inbox.Item{Path: "file.pdf/x.pdf", Size: int64(len(content)), SHA256: sum}, inbox.ErrChanged},
		{"missing subfolder", inbox.Item{Path: "wecasa/x.pdf", Size: int64(len(content)), SHA256: sum}, fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readAll(t, ib, tt.it); !errors.Is(err, tt.want) {
				t.Fatalf("Open error = %v, want %v", err, tt.want)
			}
			if err := ib.Done(t.Context(), tt.it); !errors.Is(err, tt.want) {
				t.Fatalf("Done error = %v, want %v", err, tt.want)
			}
		})
	}
	wantSnapshot(t, dir, before)
}

func TestOpen_ContextCanceled(t *testing.T) {
	t.Parallel()
	const p = "2026-03-14_edf_invoice.pdf"
	ib := newInbox(t, makeInbox(t, map[string][]byte{p: plainPDF(t, "1")}), inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ib.Open(ctx, it); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(canceled) error = %v, want context.Canceled", err)
	}
}

// TestScan_PrompterCategoryKept: a category given by the prompter wins over
// the provider defaults.
func TestScan_PrompterCategoryKept(t *testing.T) {
	t.Parallel()
	dir := makeInbox(t, map[string][]byte{"scan.pdf": plainPDF(t, "1")})
	fp := &fakePrompter{t: t, answers: map[string]answer{"scan.pdf": {ok: true, doc: normalize.Doc{
		Provider: "edf", Category: "energy", Kind: connector.Invoice, Date: day(3, 1),
	}}}}
	res := scan(t, newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp}))
	want := []itemView{{
		"scan.pdf", inbox.SourcePrompt,
		`provider="edf" category="energy" kind=invoice date=2026-03-01 amount=- currency="" ref="" ext="pdf" version=0`,
	}}
	if got := itemViews(res.Items); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("items = %+v, want %+v", got, want)
	}
}

func TestClose_Twice(t *testing.T) {
	t.Parallel()
	ib, err := inbox.New(makeInbox(t, nil), inbox.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ib.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	it := inbox.Item{Path: "x.pdf"}
	if _, err := ib.Open(t.Context(), it); err == nil {
		t.Fatal("Open after Close succeeded")
	}
	if err := ib.Done(t.Context(), it); err == nil {
		t.Fatal("Done after Close succeeded")
	}
}
