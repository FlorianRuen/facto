// Fakes for the connector loop tests (J0 task T24). Everything is synthetic:
// connector ids, domains, invoice numbers and contents are made up. The fake
// connectors live here, in test files only: the orchestrator never imports a
// concrete connector.
package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
)

// The registry is the connector source the CLI hands to Run.
var _ orchestrator.Connectors = (*connector.Registry)(nil)

// Stages where a fake connector can fail or panic.
const (
	stageLogin = "login"
	stageList  = "list"
	stageFetch = "fetch"
	stageRead  = "read" // while the orchestrator reads the fetched body
)

// fakeSession is the opaque session a fake connector returns from Login.
type fakeSession struct{ id string }

// fakeConn is a scripted connector.Connector. It records every call in the
// shared event log ("login:<id>", "list:<id>", "fetch:<id>/<ref>",
// "close:<id>/<ref>") and what it received.
type fakeConn struct {
	info connector.Info
	ev   *events

	loginErr error
	listErr  error
	refs     []connector.DocumentRef
	content  map[string][]byte // ProviderID -> body
	fetchErr map[string]error  // ProviderID -> Fetch error
	panicAt  string            // stage* constant; "" = never panic
	panicRef string            // for stageFetch/stageRead: the ref that panics ("" = any)
	panicVal any
	onLogin  func(ctx context.Context, env connector.Env)
	onList   func()

	mu        sync.Mutex
	envs      []connector.Env
	periods   []connector.Period
	listSess  []connector.Session
	fetchSess []connector.Session
	fetched   []string
	closed    []string
	session   *fakeSession
}

// newFakeConn returns a connector "<id>" in category "energy" allowed to
// reach billing.<id>.example only, listing refs with synthetic content.
func newFakeConn(ev *events, id string, refs ...connector.DocumentRef) *fakeConn {
	c := &fakeConn{
		info: connector.Info{
			ID:             id,
			Name:           "Synthetic " + id,
			Category:       "energy",
			Kinds:          []connector.DocKind{connector.Invoice},
			AllowedDomains: []string{"billing." + id + ".example"},
		},
		ev:       ev,
		refs:     refs,
		content:  map[string][]byte{},
		fetchErr: map[string]error{},
		session:  &fakeSession{id: id},
	}
	for _, r := range refs {
		c.content[r.ProviderID] = pdf(id + "/" + r.ProviderID)
	}
	return c
}

func (c *fakeConn) Info() connector.Info { return c.info }

func (c *fakeConn) Login(ctx context.Context, env connector.Env) (connector.Session, error) {
	c.ev.add("login:%s", c.info.ID)
	c.mu.Lock()
	c.envs = append(c.envs, env)
	c.mu.Unlock()
	if c.onLogin != nil {
		c.onLogin(ctx, env)
	}
	if c.panicAt == stageLogin {
		panic(c.panicVal)
	}
	if c.loginErr != nil {
		return nil, c.loginErr
	}
	return c.session, nil
}

func (c *fakeConn) List(_ context.Context, s connector.Session, p connector.Period) ([]connector.DocumentRef, error) {
	c.ev.add("list:%s", c.info.ID)
	c.mu.Lock()
	c.periods = append(c.periods, p)
	c.listSess = append(c.listSess, s)
	c.mu.Unlock()
	if c.onList != nil {
		c.onList()
	}
	if c.panicAt == stageList {
		panic(c.panicVal)
	}
	if c.listErr != nil {
		return nil, c.listErr
	}
	return slices.Clone(c.refs), nil
}

func (c *fakeConn) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	c.ev.add("fetch:%s/%s", c.info.ID, ref.ProviderID)
	c.mu.Lock()
	c.fetched = append(c.fetched, ref.ProviderID)
	c.fetchSess = append(c.fetchSess, s)
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hit := c.panicRef == "" || c.panicRef == ref.ProviderID
	if c.panicAt == stageFetch && hit {
		panic(c.panicVal)
	}
	if err := c.fetchErr[ref.ProviderID]; err != nil {
		return nil, err
	}
	b := &fakeBody{r: bytes.NewReader(c.content[ref.ProviderID])}
	if c.panicAt == stageRead && hit {
		b.panicVal, b.panics = c.panicVal, true
	}
	b.onClose = func() {
		c.ev.add("close:%s/%s", c.info.ID, ref.ProviderID)
		c.mu.Lock()
		c.closed = append(c.closed, ref.ProviderID)
		c.mu.Unlock()
	}
	return b, nil
}

func (c *fakeConn) envList() []connector.Env {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.envs)
}

func (c *fakeConn) fetchedList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.fetched)
}

func (c *fakeConn) closedList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.closed)
}

// fakeBody is a fetched document body that records Close and can panic on
// Read.
type fakeBody struct {
	r        io.Reader
	panics   bool
	panicVal any
	onClose  func()
}

func (b *fakeBody) Read(p []byte) (int, error) {
	if b.panics {
		panic(b.panicVal)
	}
	return b.r.Read(p)
}

func (b *fakeBody) Close() error {
	if b.onClose != nil {
		b.onClose()
	}
	return nil
}

// connList is a connector source returning a fixed order, to prove Run
// follows the source order rather than re-sorting.
type connList []connector.Connector

func (l connList) All() []connector.Connector { return slices.Clone(l) }

// registry registers conns in the given order.
func registry(t *testing.T, conns ...connector.Connector) *connector.Registry {
	t.Helper()
	reg := connector.NewRegistry()
	for _, c := range conns {
		if err := reg.Register(c); err != nil {
			t.Fatalf("Register(%s): %v", c.Info().ID, err)
		}
	}
	return reg
}

// errNoDial is returned by the test dialer: no test ever reaches a network.
var errNoDial = errors.New("synthetic dialer: network disabled in tests")

// httpRecorder is an injected orchestrator.HTTPFactory that records the
// allowlists it was asked for and the clients it returned. Its clients can
// never dial.
type httpRecorder struct {
	mu      sync.Mutex
	allowed [][]string
	clients []*httpx.Client
	dialed  []string
	err     map[string]error // first allowed domain -> forced factory error
}

func (h *httpRecorder) factory(allowed []string) (*httpx.Client, error) {
	h.mu.Lock()
	h.allowed = append(h.allowed, slices.Clone(allowed))
	var forced error
	if len(allowed) > 0 {
		forced = h.err[allowed[0]]
	}
	h.mu.Unlock()
	if forced != nil {
		return nil, forced
	}
	c, err := httpx.New(allowed, httpx.Options{
		Timeout: time.Second,
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			h.mu.Lock()
			h.dialed = append(h.dialed, addr)
			h.mu.Unlock()
			return nil, errNoDial
		},
	})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.clients = append(h.clients, c)
	h.mu.Unlock()
	return c, nil
}

func (h *httpRecorder) calls() ([][]string, []*httpx.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.allowed), slices.Clone(h.clients)
}

func (h *httpRecorder) dials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.dialed)
}

// runRig is a rig whose orchestrator gets the recording HTTP factory.
type runRig struct {
	*rig
	http *httpRecorder
}

func withHTTP(f orchestrator.HTTPFactory) rigOpt {
	return func(d *orchestrator.Deps) { d.NewHTTP = f }
}

func newRunRig(t *testing.T, docs []store.Document, opts ...rigOpt) *runRig {
	t.Helper()
	h := &httpRecorder{err: map[string]error{}}
	r := newRig(t, docs, append([]rigOpt{withHTTP(h.factory)}, opts...)...)
	return &runRig{rig: r, http: h}
}

// runRef is a synthetic invoice ref issued on 2026-03-<d>.
func runRef(id string, d int) connector.DocumentRef {
	return connector.DocumentRef{
		ProviderID:  id,
		Kind:        connector.Invoice,
		IssuedAt:    day(time.March, d),
		AmountCents: cents(1000 + int64(d)),
		Currency:    "EUR",
		MimeType:    "application/pdf",
	}
}

// period2026 is the period every Run test collects.
var period2026 = connector.Year(2026)

// byID returns the connector result for id.
func byID(t *testing.T, res orchestrator.RunResult, id string) orchestrator.ConnectorResult {
	t.Helper()
	for _, c := range res.Connectors {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no result for connector %q in %+v", id, res.Connectors)
	return orchestrator.ConnectorResult{}
}

func resultIDs(res orchestrator.RunResult) []string {
	ids := make([]string, 0, len(res.Connectors))
	for _, c := range res.Connectors {
		ids = append(ids, c.ID)
	}
	return ids
}

func docStatuses(docs []orchestrator.DocResult) map[string]orchestrator.Status {
	out := map[string]orchestrator.Status{}
	for _, d := range docs {
		out[d.ProviderID] = d.Status
	}
	return out
}
