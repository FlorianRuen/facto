package orchestrator_test

// A file that changes while it is being read (inbox reader error wrapping
// inbox.ErrChanged) is reported as changed, not failed, and never filed or
// removed.

import (
	"context"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// readChangedInbox is a fakeInbox whose content for one path fails mid-read
// with an error wrapping inbox.ErrChanged.
type readChangedInbox struct {
	*fakeInbox
	changed string
}

func (f *readChangedInbox) Open(ctx context.Context, it inbox.Item) (io.ReadCloser, error) {
	rc, err := f.fakeInbox.Open(ctx, it)
	if err != nil || it.Path != f.changed {
		return rc, err
	}
	_ = rc.Close()
	return io.NopCloser(&errReader{
		data: []byte("%PDF-1.7 partial"),
		err:  fmt.Errorf("inbox read %q: %w", it.Path, inbox.ErrChanged),
	}), nil
}

func TestIngestInbox_ReadChangedIsChanged(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	a, b := pdf("a"), pdf("b")
	other := edfDoc()
	other.Ref = "10234568"
	src := &readChangedInbox{
		fakeInbox: newFakeInbox(r.ev,
			[]inbox.Item{item("a.pdf", edfDoc(), a), item("b.pdf", other, b)},
			map[string][]byte{"a.pdf": a, "b.pdf": b}),
		changed: "a.pdf",
	}

	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	if len(res.Documents) != 2 || res.Documents[0].Status != orchestrator.StatusChanged || res.Documents[1].Status != orchestrator.StatusFiled {
		t.Fatalf("documents = %+v, want [changed, filed]", res.Documents)
	}
	if res.Documents[0].Path != "" || res.Documents[0].Version != 0 {
		t.Fatalf("changed document = %+v, want no path and no version", res.Documents[0])
	}
	if got := src.doneList(); !slices.Equal(got, []string{"b.pdf"}) {
		t.Fatalf("Done = %q, want only b.pdf", got)
	}
	if got := r.ev.withPrefix("put"); len(got) != 1 {
		t.Fatalf("puts = %q, want only b.pdf filed", got)
	}
}
