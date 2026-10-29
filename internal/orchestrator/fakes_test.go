// Fakes and helpers shared by the orchestrator tests. Everything here is
// synthetic: provider ids, invoice numbers and contents are made up.
package orchestrator_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
)

// Compile-time pins of the consumer-side interfaces: the real
// implementations must satisfy them, so the CLI can wire them directly.
var (
	_ orchestrator.Index       = (*store.Store)(nil)
	_ orchestrator.Destination = dest.Destination(nil)
	_ orchestrator.InboxSource = (*inbox.Inbox)(nil)
	_ orchestrator.Namer       = (*normalize.Namer)(nil)
)

// events is an ordered, concurrency-safe log of side effects across fakes,
// used to pin ordering (Put, then Insert, then Done).
type events struct {
	mu  sync.Mutex
	evs []string
}

func (e *events) add(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evs = append(e.evs, fmt.Sprintf(format, args...))
}

func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.evs...)
}

// withPrefix returns the events starting with prefix.
func (e *events) withPrefix(prefix string) []string {
	var out []string
	for _, ev := range e.list() {
		if strings.HasPrefix(ev, prefix) {
			out = append(out, ev)
		}
	}
	return out
}

// --- fake index ---------------------------------------------------------------

// fakeIndex is an in-memory orchestrator.Index honoring ctx like the store.
type fakeIndex struct {
	ev *events

	mu   sync.Mutex
	docs []store.Document

	hasErr    error // returned by HasSHA256
	latestErr error // returned by LatestVersion
	insertErr error // returned by Insert (nothing stored)
}

func newFakeIndex(ev *events, docs ...store.Document) *fakeIndex {
	return &fakeIndex{ev: ev, docs: docs}
}

func (f *fakeIndex) LatestVersion(ctx context.Context, provider, providerID string) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if f.latestErr != nil {
		return 0, false, f.latestErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	latest, found := 0, false
	for _, d := range f.docs {
		if providerID != "" && d.Provider == provider && d.ProviderID == providerID {
			latest, found = max(latest, d.Version), true
		}
	}
	return latest, found, nil
}

func (f *fakeIndex) HasSHA256(ctx context.Context, sum [32]byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if f.hasErr != nil {
		return false, f.hasErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.docs {
		if d.SHA256 == sum {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeIndex) Insert(ctx context.Context, d store.Document) (store.Document, error) {
	if err := ctx.Err(); err != nil {
		f.ev.add("insert-fail:%s", d.LocalPath)
		return store.Document{}, err
	}
	if f.insertErr != nil {
		f.ev.add("insert-fail:%s", d.LocalPath)
		return store.Document{}, f.insertErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs = append(f.docs, d)
	f.ev.add("insert:%s/%s/v%d", d.Provider, d.ProviderID, d.Version)
	return d, nil
}

// all returns every indexed document, initial ones first.
func (f *fakeIndex) all() []store.Document {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.Document{}, f.docs...)
}

// --- fake destination ---------------------------------------------------------

// fakeDest is an in-memory orchestrator.Destination with the dest contract:
// Put never replaces (dest.ErrExists).
type fakeDest struct {
	ev   *events
	name string // "" = "local"

	mu    sync.Mutex
	files map[string][]byte               // Path.Rel() -> content
	puts  []dest.NormalizedDoc            // every successful Put
	err   error                           // forced Put error
	ref   *dest.RemoteRef                 // returned with err when non-nil (ErrNotDurable shape)
	id    func(dest.NormalizedDoc) string // RemoteRef.ID; nil = Path.Rel()
	after func()                          // called after a successful store
}

func newFakeDest(ev *events) *fakeDest {
	return &fakeDest{ev: ev, files: map[string][]byte{}}
}

func (f *fakeDest) Name() string {
	if f.name == "" {
		return "local"
	}
	return f.name
}

func (f *fakeDest) Put(ctx context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error) {
	if err := ctx.Err(); err != nil {
		f.ev.add("put-fail:%s", doc.Path.Rel())
		return dest.RemoteRef{}, err
	}
	rel := doc.Path.Rel()
	if f.err != nil {
		f.ev.add("put-fail:%s", rel)
		if f.ref != nil {
			f.mu.Lock()
			f.files[rel], _ = io.ReadAll(r)
			f.puts = append(f.puts, doc)
			f.mu.Unlock()
			return *f.ref, f.err
		}
		return dest.RemoteRef{}, f.err
	}
	f.mu.Lock()
	if _, ok := f.files[rel]; ok {
		f.mu.Unlock()
		f.ev.add("put-exists:%s", rel)
		return dest.RemoteRef{}, fmt.Errorf("fake put %q: %w", rel, dest.ErrExists)
	}
	f.mu.Unlock()
	data, err := io.ReadAll(r)
	if err != nil {
		f.ev.add("put-fail:%s", rel)
		return dest.RemoteRef{}, err
	}
	f.mu.Lock()
	f.files[rel] = data
	f.puts = append(f.puts, doc)
	f.mu.Unlock()
	f.ev.add("put:%s", rel)
	if f.after != nil {
		f.after()
	}
	id := rel
	if f.id != nil {
		id = f.id(doc)
	}
	return dest.RemoteRef{Destination: f.Name(), ID: id}, nil
}

func (f *fakeDest) Exists(_ context.Context, doc dest.NormalizedDoc) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[doc.Path.Rel()]
	return ok, nil
}

func (f *fakeDest) put() []dest.NormalizedDoc {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dest.NormalizedDoc{}, f.puts...)
}

func (f *fakeDest) file(rel string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[rel]
}

// --- fake inbox ---------------------------------------------------------------

// fakeInbox is an orchestrator.InboxSource serving a fixed Result.
type fakeInbox struct {
	ev *events

	mu      sync.Mutex
	res     inbox.Result
	content map[string][]byte // item path -> content
	openErr map[string]error
	scanErr error
	opened  []string
	done    []string
}

func newFakeInbox(ev *events, items []inbox.Item, content map[string][]byte, warnings ...inbox.Warning) *fakeInbox {
	return &fakeInbox{
		ev:      ev,
		res:     inbox.Result{Items: items, Warnings: warnings},
		content: content,
		openErr: map[string]error{},
	}
}

func (f *fakeInbox) Scan(ctx context.Context) (inbox.Result, error) {
	if err := ctx.Err(); err != nil {
		return inbox.Result{}, err
	}
	if f.scanErr != nil {
		return inbox.Result{}, f.scanErr
	}
	return f.res, nil
}

func (f *fakeInbox) Open(ctx context.Context, it inbox.Item) (io.ReadCloser, error) {
	f.mu.Lock()
	f.opened = append(f.opened, it.Path)
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.openErr[it.Path]; err != nil {
		return nil, err
	}
	data, ok := f.content[it.Path]
	if !ok {
		return nil, fmt.Errorf("fake inbox: no content for %q", it.Path)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeInbox) Done(ctx context.Context, it inbox.Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.done = append(f.done, it.Path)
	f.mu.Unlock()
	f.ev.add("done:%s", it.Path)
	return nil
}

func (f *fakeInbox) doneList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.done...)
}

func (f *fakeInbox) openedList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.opened...)
}

// --- builders -----------------------------------------------------------------

func day(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }

func cents(v int64) *int64 { return &v }

// edfDoc is a synthetic EDF invoice rendering to edfPath with the default
// templates.
func edfDoc() normalize.Doc {
	return normalize.Doc{
		Provider:    "edf",
		Category:    "energy",
		Kind:        connector.Invoice,
		Date:        day(time.March, 14),
		AmountCents: cents(8412),
		Currency:    "EUR",
		Ref:         "10234567",
		Ext:         "pdf",
	}
}

const (
	edfPath   = "2026/energy/edf/2026-03-14_edf_invoice_84-12EUR_10234567.pdf"
	edfPathV2 = "2026/energy/edf/2026-03-14_edf_invoice_84-12EUR_10234567_v2.pdf"
)

// pdf returns synthetic document bytes, unique per tag.
func pdf(tag string) []byte { return []byte("synthetic document " + tag + "\n") }

func sum(b []byte) [32]byte { return sha256.Sum256(b) }

// indexed is an already-indexed EDF invoice 10234567 with content c.
func indexed(version int, c []byte) store.Document {
	return store.Document{
		Provider:   "edf",
		ProviderID: "10234567",
		Kind:       connector.Invoice,
		IssuedAt:   day(time.March, 14),
		SHA256:     sum(c),
		LocalPath:  "2026/energy/edf/old.pdf",
		Version:    version,
	}
}

// item builds an inbox item for content c.
func item(p string, d normalize.Doc, c []byte) inbox.Item {
	return inbox.Item{Path: p, Size: int64(len(c)), SHA256: sum(c), Doc: d, Source: inbox.SourceName}
}

func namer(t *testing.T) *normalize.Namer {
	t.Helper()
	n, err := normalize.NewNamer(normalize.Config{})
	if err != nil {
		t.Fatalf("NewNamer: %v", err)
	}
	return n
}

// rig is one orchestrator wired to fakes.
type rig struct {
	ev  *events
	idx *fakeIndex
	dst *fakeDest
	o   *orchestrator.Orchestrator
	log *bytes.Buffer // plain (non-redacting) JSON handler output
}

type rigOpt func(*orchestrator.Deps)

func withMaxSize(n int64) rigOpt { return func(d *orchestrator.Deps) { d.MaxSize = n } }

func newRig(t *testing.T, docs []store.Document, opts ...rigOpt) *rig {
	t.Helper()
	ev := &events{}
	r := &rig{ev: ev, idx: newFakeIndex(ev, docs...), dst: newFakeDest(ev), log: &bytes.Buffer{}}
	deps := orchestrator.Deps{
		Index: r.idx,
		Dest:  r.dst,
		Namer: namer(t),
		// Deliberately NOT wrapped in logx: the orchestrator must wrap it.
		Log: slog.New(slog.NewJSONHandler(&lockedWriter{w: r.log}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, o := range opts {
		o(&deps)
	}
	o, err := orchestrator.New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.o = o
	return r
}

// lockedWriter serializes writes to a bytes.Buffer.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// errReader fails after returning some bytes.
type errReader struct {
	data []byte
	err  error
	done bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, r.err
}
