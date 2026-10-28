// Integration test for the ingest pipeline: the real SQLite store, the real
// local destination and the real inbox, in temp dirs (J0 task T23; the same
// flow is exercised end to end by the T28 inbox e2e scenario). All files are
// synthetic.
package orchestrator_test

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
)

// realRig is an orchestrator wired to real dependencies under one temp dir:
// base/out (output folder, holding inbox/) and base/state.
type realRig struct {
	out, inboxDir, state string
	st                   *store.Store
	o                    *orchestrator.Orchestrator
}

func newRealRig(t *testing.T) *realRig {
	t.Helper()
	base := t.TempDir()
	r := &realRig{
		out:      filepath.Join(base, "out"),
		inboxDir: filepath.Join(base, "out", "inbox"),
		state:    filepath.Join(base, "state"),
	}
	root, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	for _, d := range []string{"out", "out/inbox"} {
		if err := root.MkdirPrivate(d); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	st, err := store.Open(t.Context(), r.state, clock.NewFake(time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r.st = st
	loc, err := local.New(t.Context(), r.out)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	t.Cleanup(func() { _ = loc.Close() })
	o, err := orchestrator.New(orchestrator.Deps{Index: st, Dest: loc, Namer: namer(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.o = o
	return r
}

// run scans the inbox with a fresh inbox.Inbox and ingests it.
func (r *realRig) run(t *testing.T) orchestrator.InboxResult {
	t.Helper()
	ib, err := inbox.New(r.inboxDir, inbox.Options{Providers: map[string]inbox.ProviderDefaults{"edf": {Category: "energy"}}})
	if err != nil {
		t.Fatalf("inbox.New: %v", err)
	}
	defer func() { _ = ib.Close() }()
	res, err := r.o.IngestInbox(t.Context(), ib)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	return res
}

// write creates (or replaces) rel under dir through fsx.
func write(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := mkdirAll(root, path.Dir(rel)); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := root.WriteAtomic(t.Context(), rel, data); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// files lists the regular files under dir (slash paths).
func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	slices.Sort(out)
	return out
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func statuses(docs []orchestrator.DocResult) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Origin+"="+string(d.Status)+"@"+d.Path)
	}
	return out
}

func TestIngestInbox_RealStoreLocalDestInbox(t *testing.T) {
	t.Parallel()
	r := newRealRig(t)
	const named = "2026-03-14_edf_invoice_84-12EUR_10234567.pdf"
	a, b := pdf("original"), pdf("corrected")
	unknown := pdf("unknown")

	// Run 1: a compliant name is filed; the same bytes under a subfolder
	// drop are a duplicate and removed; an unidentified file stays.
	write(t, r.inboxDir, named, a)
	write(t, r.inboxDir, "edf/2026-03-14-scan.pdf", a)
	write(t, r.inboxDir, "unknown.pdf", unknown)

	res := r.run(t)
	wantDocs := []string{named + "=filed@" + edfPath, "edf/2026-03-14-scan.pdf=skipped-duplicate@"}
	if got := statuses(res.Documents); !slices.Equal(got, wantDocs) {
		t.Fatalf("run 1 documents = %q, want %q", got, wantDocs)
	}
	wantWarn := []orchestrator.Warning{{Source: "inbox", Path: "unknown.pdf", Reason: "unidentified"}}
	if !slices.Equal(res.Warnings, wantWarn) {
		t.Fatalf("run 1 warnings = %+v, want %+v", res.Warnings, wantWarn)
	}
	if got := files(t, r.inboxDir); !slices.Equal(got, []string{"unknown.pdf"}) {
		t.Fatalf("inbox after run 1 = %q, want only unknown.pdf", got)
	}
	if got := mustRead(t, filepath.Join(r.out, filepath.FromSlash(edfPath))); !bytes.Equal(got, a) {
		t.Fatalf("filed content = %q, want %q", got, a)
	}
	docs, err := r.st.FindByProviderID(t.Context(), "edf", "10234567")
	if err != nil {
		t.Fatalf("FindByProviderID: %v", err)
	}
	if len(docs) != 1 || docs[0].Version != 1 || docs[0].LocalPath != edfPath || docs[0].SHA256 != sum(a) {
		t.Fatalf("index after run 1 = %+v, want v1 at %q", docs, edfPath)
	}

	// Run 2: a corrected invoice with the same number becomes _v2, v1 kept.
	write(t, r.inboxDir, named, b)
	res = r.run(t)
	if got, want := statuses(res.Documents), []string{named + "=filed@" + edfPathV2}; !slices.Equal(got, want) {
		t.Fatalf("run 2 documents = %q, want %q", got, want)
	}
	if res.Documents[0].Version != 2 {
		t.Fatalf("run 2 version = %d, want 2", res.Documents[0].Version)
	}
	if got := mustRead(t, filepath.Join(r.out, filepath.FromSlash(edfPathV2))); !bytes.Equal(got, b) {
		t.Fatalf("v2 content = %q, want %q", got, b)
	}
	if got := mustRead(t, filepath.Join(r.out, filepath.FromSlash(edfPath))); !bytes.Equal(got, a) {
		t.Fatal("v1 was modified by the new version")
	}
	docs, err = r.st.FindByProviderID(t.Context(), "edf", "10234567")
	if err != nil {
		t.Fatalf("FindByProviderID: %v", err)
	}
	if len(docs) != 2 || docs[1].Version != 2 || docs[1].LocalPath != edfPathV2 {
		t.Fatalf("index after run 2 = %+v, want v1 and v2", docs)
	}

	// Run 3: idempotent.
	before := files(t, r.out)
	res = r.run(t)
	if len(res.Documents) != 0 || !slices.Equal(res.Warnings, wantWarn) {
		t.Fatalf("run 3 = %+v, want no document and the same warning", res)
	}
	if got := files(t, r.out); !slices.Equal(got, before) {
		t.Fatalf("run 3 changed the output folder\nbefore %q\n after %q", before, got)
	}

	// Run 4: a file the index does not know is already at the target path
	// (put there by hand): exists, not indexed, the inbox file stays.
	const clashPath = "2026/energy/edf/2026-04-01_edf_invoice.pdf"
	foreign, drop := pdf("put there by hand"), pdf("dropped")
	write(t, r.out, clashPath, foreign)
	write(t, r.inboxDir, "2026-04-01_edf_invoice.pdf", drop)
	res = r.run(t)
	if got, want := statuses(res.Documents), []string{"2026-04-01_edf_invoice.pdf=exists@" + clashPath}; !slices.Equal(got, want) {
		t.Fatalf("run 4 documents = %q, want %q", got, want)
	}
	if got := mustRead(t, filepath.Join(r.out, filepath.FromSlash(clashPath))); !bytes.Equal(got, foreign) {
		t.Fatal("existing file was replaced")
	}
	if has, err := r.st.HasSHA256(t.Context(), sum(drop)); err != nil || has {
		t.Fatalf("HasSHA256(drop) = %v, %v; want not indexed", has, err)
	}
	if got := files(t, r.inboxDir); !slices.Contains(got, "2026-04-01_edf_invoice.pdf") {
		t.Fatalf("inbox after run 4 = %q, want the clashing drop kept", got)
	}
}
