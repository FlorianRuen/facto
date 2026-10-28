// Tests for the connector loop (J0 task T24). Spec: docs/spec.md "Connector
// model" (interface, Env, run lifecycle steps 1-5, connector states),
// "Graceful degradation"; go-conventions (recover at the orchestrator
// boundary per connector, mark it broken); CLAUDE.md (the orchestrator never
// imports a concrete connector, network only through httpx, logging only
// through logx).
//
// Expected API (implementer: follow exactly):
//
//	// State is a connector's outcome in a run.
//	type State string
//	const (
//		StateOK          State = "ok"
//		StateNeedsLogin  State = "needs_login"
//		StateBroken      State = "broken"
//		StateAuthFailed  State = "auth_failed"
//		StateRateLimited State = "rate_limited"
//	)
//
//	// Connectors is the connector source (*connector.Registry implements it).
//	type Connectors interface{ All() []connector.Connector }
//
//	// HTTPFactory builds the allowlisted client handed to one connector.
//	type HTTPFactory func(allowed []string) (*httpx.Client, error)
//
//	// Deps gains one optional field (existing callers unchanged):
//	//	NewHTTP HTTPFactory // nil = httpx.New(allowed, httpx.Options{})
//
//	// ConnectorResult is the outcome of one connector.
//	type ConnectorResult struct {
//		ID        string
//		State     State
//		Documents []DocResult // Source == ID, in listing order
//	}
//
//	// RunResult is the outcome of Run.
//	type RunResult struct {
//		Connectors []ConnectorResult // src.All() order, one per connector started
//	}
//
//	// Run collects p from every connector of src.All(), sequentially, in
//	// that order. Per connector: connector.ValidateInfo (failure: broken,
//	// never logged in); Env{HTTP: NewHTTP(Info.AllowedDomains) (error:
//	// broken, never logged in), Log: the orchestrator's redacting logger
//	// .With("connector", id)}; Login; List(session, p); for each ref:
//	// normalize.BeforeFetch with provider = Slug(id) — SkipKnownID gives a
//	// StatusSkippedKnownID DocResult without Fetch, a lookup error a
//	// StatusFailed one without Fetch; otherwise Fetch and Ingest(Input{
//	// Source: id, ProviderID: ref.ProviderID, Doc: {Provider: id,
//	// Category: Info.Category, Kind, Date: IssuedAt, AmountCents,
//	// Currency, Ref: ProviderID, Ext: "pdf" for application/pdf},
//	// PeriodStart, PeriodEnd, Content: body}), then close the body.
//	// Login and List errors end the connector: state = the sentinel found
//	// with errors.Is (ErrNeedsLogin, ErrBroken, ErrAuthFailed,
//	// ErrRateLimited), anything else broken. A Fetch error wrapping a
//	// sentinel ends the connector with that state; any other Fetch or
//	// Ingest error only fails that document (StatusFailed or the Ingest
//	// status) and the connector stays ok. A panic anywhere in a connector
//	// (its methods or the body it returned) is recovered: broken, the panic
//	// value is never logged or reported, the next connector runs. A
//	// canceled ctx stops the loop: no further Fetch/Put/Login, the error
//	// wraps ctx.Err(), the results so far are returned.
//	func (o *Orchestrator) Run(ctx context.Context, src Connectors, p connector.Period) (RunResult, error)
package orchestrator_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func TestRun_ZeroConnectors(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	res, err := r.o.Run(t.Context(), connector.NewRegistry(), period2026)
	if err != nil {
		t.Fatalf("Run(empty registry) error = %v, want nil (ADR 0007 D5)", err)
	}
	if len(res.Connectors) != 0 {
		t.Fatalf("Connectors = %+v, want none", res.Connectors)
	}
	if got := r.ev.list(); len(got) != 0 {
		t.Fatalf("side effects = %q, want none", got)
	}
}

func TestRun_NilSourceIsAnError(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	if _, err := r.o.Run(t.Context(), nil, period2026); err == nil {
		t.Fatal("Run(nil source) error = nil, want an error")
	}
}

func TestRun_SequentialInSourceOrder(t *testing.T) {
	t.Parallel()

	t.Run("registry order (sorted by id)", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		charlie := newFakeConn(r.ev, "charlie", runRef("c1", 3))
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
		bravo := newFakeConn(r.ev, "bravo")
		res, err := r.o.Run(t.Context(), registry(t, charlie, alpha, bravo), period2026)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if got, want := resultIDs(res), []string{"alpha", "bravo", "charlie"}; !slices.Equal(got, want) {
			t.Fatalf("result order = %q, want %q", got, want)
		}
		// Every step of a connector happens before the next one starts:
		// nothing interleaves.
		var got []string
		for _, ev := range r.ev.list() {
			if strings.HasPrefix(ev, "login:") || strings.HasPrefix(ev, "list:") || strings.HasPrefix(ev, "fetch:") || strings.HasPrefix(ev, "close:") {
				got = append(got, ev)
			}
		}
		want := []string{
			"login:alpha", "list:alpha", "fetch:alpha/a1", "close:alpha/a1", "fetch:alpha/a2", "close:alpha/a2",
			"login:bravo", "list:bravo",
			"login:charlie", "list:charlie", "fetch:charlie/c1", "close:charlie/c1",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("connector calls =\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("custom source order is kept", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		charlie := newFakeConn(r.ev, "charlie")
		alpha := newFakeConn(r.ev, "alpha")
		res, err := r.o.Run(t.Context(), connList{charlie, alpha}, period2026)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if got, want := resultIDs(res), []string{"charlie", "alpha"}; !slices.Equal(got, want) {
			t.Fatalf("result order = %q, want %q (Run must not re-sort the source)", got, want)
		}
		if got, want := r.ev.withPrefix("login:"), []string{"login:charlie", "login:alpha"}; !slices.Equal(got, want) {
			t.Fatalf("logins = %q, want %q", got, want)
		}
	})
}

func TestRun_FetchedDocumentGoesThroughIngest(t *testing.T) {
	t.Parallel()
	// dup's content is already indexed (under another provider): Ingest's
	// rule 2 must apply to connector documents too.
	dup := runRef("a2", 2)
	dupContent := pdf("already filed elsewhere")
	other := store.Document{Provider: "bravo", ProviderID: "b9", Kind: connector.Invoice, IssuedAt: day(time.March, 1), SHA256: sum(dupContent), Version: 1}
	r := newRunRig(t, []store.Document{other})

	ref := runRef("a1001", 14)
	ref.AmountCents = cents(8412)
	ref.PeriodStart = day(time.February, 1)
	ref.PeriodEnd = day(time.March, 1)
	ref.Contract = "synthetic-contract"
	alpha := newFakeConn(r.ev, "alpha", ref, dup)
	alpha.content[dup.ProviderID] = dupContent

	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := byID(t, res, "alpha")
	if got.State != orchestrator.StateOK {
		t.Fatalf("state = %q, want ok", got.State)
	}

	want, err := namer(t).Render(normalize.Doc{
		Provider: "alpha", Category: "energy", Kind: connector.Invoice, Date: day(time.March, 14),
		AmountCents: cents(8412), Currency: "EUR", Ref: "a1001", Ext: "pdf",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	wantDocs := []orchestrator.DocResult{
		{Source: "alpha", Provider: "alpha", ProviderID: "a1001", Status: orchestrator.StatusFiled, Version: 1, Path: want.Rel()},
		{Source: "alpha", Provider: "alpha", ProviderID: "a2", Status: orchestrator.StatusSkippedDuplicate},
	}
	if !slices.Equal(got.Documents, wantDocs) {
		t.Fatalf("documents =\n%+v\nwant\n%+v", got.Documents, wantDocs)
	}
	if c := r.dst.file(want.Rel()); string(c) != string(alpha.content["a1001"]) {
		t.Fatalf("destination content at %s = %q, want the fetched body", want.Rel(), c)
	}
	var row *store.Document
	for _, d := range r.idx.all() {
		if d.Provider == "alpha" {
			row = &d
		}
	}
	switch {
	case row == nil:
		t.Fatal("fetched document not indexed")
	case row.ProviderID != "a1001" || row.Version != 1 || row.SHA256 != sum(alpha.content["a1001"]):
		t.Fatalf("index row = %+v, want alpha/a1001 v1 with the body hash", *row)
	case !row.PeriodStart.Equal(ref.PeriodStart) || !row.PeriodEnd.Equal(ref.PeriodEnd):
		t.Fatalf("index period = %v..%v, want %v..%v", row.PeriodStart, row.PeriodEnd, ref.PeriodStart, ref.PeriodEnd)
	case row.LocalPath != want.Rel():
		t.Fatalf("index LocalPath = %q, want %q", row.LocalPath, want.Rel())
	}
	if got, want := alpha.closedList(), []string{"a1001", "a2"}; !slices.Equal(got, want) {
		t.Fatalf("closed bodies = %q, want %q (every fetched body is closed)", got, want)
	}
}

func TestRun_EnvPerConnector(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	r := newRunRig(t, nil)
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	alpha.info.AllowedDomains = []string{"billing.alpha.example", "*.cdn.alpha.example"}
	bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))
	for _, c := range []*fakeConn{alpha, bravo} {
		c.onLogin = func(ctx context.Context, env connector.Env) {
			if env.Log == nil {
				return
			}
			env.Log.InfoContext(ctx, "synthetic login step", "password", canary)
		}
	}

	if _, err := r.o.Run(t.Context(), registry(t, bravo, alpha), period2026); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	allowed, clients := r.http.calls()
	wantAllowed := [][]string{alpha.info.AllowedDomains, bravo.info.AllowedDomains}
	if !slices.EqualFunc(allowed, wantAllowed, slices.Equal[[]string]) {
		t.Fatalf("factory allowlists = %q, want %q (one client per connector, from Info.AllowedDomains)", allowed, wantAllowed)
	}
	for i, c := range []*fakeConn{alpha, bravo} {
		envs := c.envList()
		if len(envs) != 1 {
			t.Fatalf("%s: Login called %d times, want 1", c.info.ID, len(envs))
		}
		env := envs[0]
		if env.HTTP == nil || env.HTTP != clients[i] {
			t.Fatalf("%s: Env.HTTP = %p, want the factory's client %p", c.info.ID, env.HTTP, clients[i])
		}
		if env.Log == nil {
			t.Fatalf("%s: Env.Log is nil", c.info.ID)
		}
		c.mu.Lock()
		periods, listSess, fetchSess := slices.Clone(c.periods), slices.Clone(c.listSess), slices.Clone(c.fetchSess)
		c.mu.Unlock()
		if len(periods) != 1 || periods[0] != period2026 {
			t.Fatalf("%s: List periods = %v, want [%v]", c.info.ID, periods, period2026)
		}
		for _, s := range append(listSess, fetchSess...) {
			if s != connector.Session(c.session) {
				t.Fatalf("%s: List/Fetch got session %v, want the one Login returned", c.info.ID, s)
			}
		}
	}

	// The connector's logger is tagged with its id and redacts.
	out := r.log.String()
	if strings.Contains(out, canary) {
		t.Fatalf("Env.Log does not redact (canary in log):\n%s", out)
	}
	for _, id := range []string{"alpha", "bravo"} {
		found := false
		for _, line := range logLines(t, out) {
			if line["msg"] == "synthetic login step" && line["connector"] == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("no %q record tagged connector=%q; log:\n%s", "synthetic login step", id, out)
		}
	}
	if d := r.http.dials(); len(d) != 0 {
		t.Fatalf("dials = %q, want none", d)
	}
}

// The client handed to a connector enforces that connector's allowlist:
// another connector's domain is refused before any dial.
func TestRun_EnvHTTPEnforcesConnectorAllowlist(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	alpha := newFakeConn(r.ev, "alpha")
	var errs []error
	alpha.onLogin = func(ctx context.Context, env connector.Env) {
		for _, u := range []string{
			"https://billing.bravo.example/invoices", // another connector's domain
			"https://evil.example/collect",           // anywhere else
			"https://billing.alpha.example:8443/",    // allowed host, other port
			"http://billing.alpha.example/invoices",  // allowed host, plain http
			"https://billing.alpha.example/invoices", // allowed: reaches the (disabled) dialer
		} {
			resp, err := env.HTTP.Get(ctx, u)
			if resp != nil {
				_ = resp.Body.Close()
			}
			errs = append(errs, err)
		}
	}
	if _, err := r.o.Run(t.Context(), registry(t, alpha, newFakeConn(r.ev, "bravo")), period2026); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(errs) != 5 {
		t.Fatalf("Login not called with a usable Env.HTTP (%d requests made)", len(errs))
	}
	for i, want := range []error{httpx.ErrDomainNotAllowed, httpx.ErrDomainNotAllowed, httpx.ErrDomainNotAllowed, httpx.ErrInsecureScheme} {
		if !errors.Is(errs[i], want) {
			t.Errorf("request %d error = %v, want %v", i, errs[i], want)
		}
	}
	if errs[4] == nil || errors.Is(errs[4], httpx.ErrDomainNotAllowed) {
		t.Errorf("allowed request error = %v, want a dial failure (allowlisted)", errs[4])
	}
	if got := r.http.dials(); len(got) != 1 || !strings.HasPrefix(got[0], "billing.alpha.example:") {
		t.Fatalf("dials = %q, want only billing.alpha.example", got)
	}
}

// Without an injected factory the orchestrator builds an httpx client from
// the connector's allowlist itself (never a bare http.Client).
func TestRun_DefaultHTTPFactory(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil) // Deps.NewHTTP nil
	alpha := newFakeConn(r.ev, "alpha")
	var errs []error
	var gotClient bool
	alpha.onLogin = func(ctx context.Context, env connector.Env) {
		if env.HTTP == nil {
			return
		}
		gotClient = true
		// Both are refused before any dial.
		for _, u := range []string{"https://evil.example/", "http://billing.alpha.example/"} {
			resp, err := env.HTTP.Get(ctx, u)
			if resp != nil {
				_ = resp.Body.Close()
			}
			errs = append(errs, err)
		}
	}
	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !gotClient {
		t.Fatal("Env.HTTP is nil with the default factory")
	}
	if !errors.Is(errs[0], httpx.ErrDomainNotAllowed) || !errors.Is(errs[1], httpx.ErrInsecureScheme) {
		t.Fatalf("errors = %v, want [ErrDomainNotAllowed ErrInsecureScheme]", errs)
	}
	if s := byID(t, res, "alpha").State; s != orchestrator.StateOK {
		t.Fatalf("state = %q, want ok", s)
	}
}

func TestRun_HTTPFactoryErrorMarksBroken(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))
	r.http.err["billing.alpha.example"] = errors.New("synthetic factory failure")
	res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if s := byID(t, res, "alpha").State; s != orchestrator.StateBroken {
		t.Fatalf("alpha state = %q, want broken", s)
	}
	if n := len(alpha.envList()); n != 0 {
		t.Fatalf("alpha Login called %d times without an HTTP client, want 0", n)
	}
	if s := byID(t, res, "bravo").State; s != orchestrator.StateOK {
		t.Fatalf("bravo state = %q, want ok", s)
	}
}

// A connector with invalid metadata (a source other than the registry does
// not validate) is never logged in: its id would end up in paths.
func TestRun_InvalidInfoNeverLoggedIn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info func(*connector.Info)
	}{
		{"path traversal id", func(i *connector.Info) { i.ID = "../evil" }},
		{"slash in id", func(i *connector.Info) { i.ID = "a/b" }},
		{"empty id", func(i *connector.Info) { i.ID = "" }},
		{"no allowed domain", func(i *connector.Info) { i.AllowedDomains = nil }},
		{"public suffix allowlist", func(i *connector.Info) { i.AllowedDomains = []string{"*.co.uk"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			bad := newFakeConn(r.ev, "alpha", runRef("x1", 1))
			tt.info(&bad.info)
			good := newFakeConn(r.ev, "bravo", runRef("b1", 1))
			res, err := r.o.Run(t.Context(), connList{bad, good}, period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if n := len(bad.envList()); n != 0 || len(bad.fetchedList()) != 0 {
				t.Fatalf("invalid connector was run (logins %d, fetched %q)", n, bad.fetchedList())
			}
			if len(res.Connectors) != 2 || res.Connectors[0].State != orchestrator.StateBroken {
				t.Fatalf("results = %+v, want the invalid connector broken first", res.Connectors)
			}
			if s := byID(t, res, "bravo").State; s != orchestrator.StateOK {
				t.Fatalf("bravo state = %q, want ok", s)
			}
			for _, p := range r.dst.put() {
				if !strings.HasPrefix(p.Path.Rel(), "2026/energy/bravo/") {
					t.Fatalf("put %q, want only bravo documents", p.Path.Rel())
				}
			}
		})
	}
}

func TestRun_BrokenDoesNotStopOthers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(*fakeConn)
		want  orchestrator.State
	}{
		{"login broken", func(c *fakeConn) { c.loginErr = fmt.Errorf("login form: %w", connector.ErrBroken) }, orchestrator.StateBroken},
		{"list unknown error", func(c *fakeConn) { c.listErr = errors.New("synthetic selector not found") }, orchestrator.StateBroken},
		{"login needs login", func(c *fakeConn) { c.loginErr = connector.ErrNeedsLogin }, orchestrator.StateNeedsLogin},
		{"list rate limited", func(c *fakeConn) { c.listErr = connector.ErrRateLimited }, orchestrator.StateRateLimited},
		{"login panics", func(c *fakeConn) { c.panicAt, c.panicVal = stageLogin, "synthetic crash" }, orchestrator.StateBroken},
		{"fetch panics", func(c *fakeConn) { c.panicAt, c.panicVal = stageFetch, "synthetic crash" }, orchestrator.StateBroken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
			tt.setup(alpha)
			bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1), runRef("b2", 2))
			charlie := newFakeConn(r.ev, "charlie")
			charlie.loginErr = connector.ErrAuthFailed

			res, err := r.o.Run(t.Context(), registry(t, alpha, bravo, charlie), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v, want nil (connector failures are states)", err)
			}
			if got, want := resultIDs(res), []string{"alpha", "bravo", "charlie"}; !slices.Equal(got, want) {
				t.Fatalf("results = %q, want %q", got, want)
			}
			if s := byID(t, res, "alpha").State; s != tt.want {
				t.Fatalf("alpha state = %q, want %q", s, tt.want)
			}
			b := byID(t, res, "bravo")
			if b.State != orchestrator.StateOK {
				t.Fatalf("bravo state = %q, want ok", b.State)
			}
			if got := docStatuses(b.Documents); got["b1"] != orchestrator.StatusFiled || got["b2"] != orchestrator.StatusFiled || len(got) != 2 {
				t.Fatalf("bravo documents = %+v, want b1 and b2 filed", b.Documents)
			}
			if s := byID(t, res, "charlie").State; s != orchestrator.StateAuthFailed {
				t.Fatalf("charlie state = %q, want auth_failed", s)
			}
			// The non-ok state is logged with the connector id.
			if !hasLog(t, r.log.String(), "alpha", "WARN", "ERROR") {
				t.Fatalf("no warn/error record tagged connector=alpha; log:\n%s", r.log.String())
			}
		})
	}
}

func TestRun_StateFromSentinel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want orchestrator.State
		// wantFetch is the state when Fetch returns err: only sentinels
		// end a connector, any other error fails that document only.
		wantFetch orchestrator.State
	}{
		{"nil", nil, orchestrator.StateOK, orchestrator.StateOK},
		{"needs login", connector.ErrNeedsLogin, orchestrator.StateNeedsLogin, orchestrator.StateNeedsLogin},
		{"broken", connector.ErrBroken, orchestrator.StateBroken, orchestrator.StateBroken},
		{"auth failed", connector.ErrAuthFailed, orchestrator.StateAuthFailed, orchestrator.StateAuthFailed},
		{"rate limited", connector.ErrRateLimited, orchestrator.StateRateLimited, orchestrator.StateRateLimited},
		{"wrapped needs login", fmt.Errorf("restore session: %w", connector.ErrNeedsLogin), orchestrator.StateNeedsLogin, orchestrator.StateNeedsLogin},
		{"double wrapped auth failed", fmt.Errorf("login: %w", fmt.Errorf("submit form: %w", connector.ErrAuthFailed)), orchestrator.StateAuthFailed, orchestrator.StateAuthFailed},
		{"joined rate limited", errors.Join(io.ErrUnexpectedEOF, connector.ErrRateLimited), orchestrator.StateRateLimited, orchestrator.StateRateLimited},
		{"wrapped broken", fmt.Errorf("parse listing: %w", connector.ErrBroken), orchestrator.StateBroken, orchestrator.StateBroken},
		{"unknown error", errors.New("synthetic unexpected failure"), orchestrator.StateBroken, orchestrator.StateOK},
		{"allowlist violation", fmt.Errorf("get: %w", httpx.ErrDomainNotAllowed), orchestrator.StateBroken, orchestrator.StateOK},
		{"connector's own deadline", fmt.Errorf("wait: %w", context.DeadlineExceeded), orchestrator.StateBroken, orchestrator.StateOK},
		{"sentinel text without wrapping", errors.New(connector.ErrNeedsLogin.Error()), orchestrator.StateBroken, orchestrator.StateOK},
	}
	for _, stage := range []string{stageLogin, stageList, stageFetch} {
		for _, tt := range tests {
			t.Run(stage+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				r := newRunRig(t, nil)
				alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2), runRef("a3", 3))
				switch stage {
				case stageLogin:
					alpha.loginErr = tt.err
				case stageList:
					alpha.listErr = tt.err
				case stageFetch:
					if tt.err != nil {
						alpha.fetchErr["a2"] = tt.err
					}
				}
				res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
				if err != nil {
					t.Fatalf("Run() error = %v, want nil (connector errors are states)", err)
				}
				got := byID(t, res, "alpha")
				want := tt.want
				if stage == stageFetch {
					want = tt.wantFetch
				}
				if got.State != want {
					t.Fatalf("state = %q, want %q", got.State, want)
				}

				fetched := alpha.fetchedList()
				switch {
				case tt.err == nil:
					if !slices.Equal(fetched, []string{"a1", "a2", "a3"}) {
						t.Fatalf("fetched = %q, want all three", fetched)
					}
				case stage == stageLogin:
					if r.ev.withPrefix("list:") != nil || fetched != nil {
						t.Fatalf("List or Fetch called after a failed Login (fetched %q)", fetched)
					}
					if len(got.Documents) != 0 {
						t.Fatalf("documents = %+v, want none", got.Documents)
					}
				case stage == stageList:
					if fetched != nil {
						t.Fatalf("fetched = %q after a failed List, want none", fetched)
					}
				case want != orchestrator.StateOK: // fetch sentinel ends the connector
					if !slices.Equal(fetched, []string{"a1", "a2"}) {
						t.Fatalf("fetched = %q, want a1, a2 then stop", fetched)
					}
					if docStatuses(got.Documents)["a1"] != orchestrator.StatusFiled {
						t.Fatalf("documents = %+v, want a1 filed and kept", got.Documents)
					}
				default: // per-document failure
					if !slices.Equal(fetched, []string{"a1", "a2", "a3"}) {
						t.Fatalf("fetched = %q, want all three (a per-document error does not stop the connector)", fetched)
					}
					wantDocs := map[string]orchestrator.Status{"a1": orchestrator.StatusFiled, "a2": orchestrator.StatusFailed, "a3": orchestrator.StatusFiled}
					if gotDocs := docStatuses(got.Documents); !mapsEqual(gotDocs, wantDocs) {
						t.Fatalf("documents = %+v, want %v", got.Documents, wantDocs)
					}
				}
			})
		}
	}
}

// Ingest failures of one document never stop the connector.
func TestRun_IngestFailurePerDocument(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil, withMaxSize(64))
	big := runRef("a2", 2)
	broken := runRef("a3", 3)
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), big, broken, runRef("a4", 4))
	alpha.content["a2"] = []byte(strings.Repeat("x", 65))
	// a3's body fails mid-read.
	readFail := &errReader{data: []byte("partial"), err: errors.New("synthetic connection reset")}
	res, err := r.o.Run(t.Context(), registry(t, &bodyOverride{fakeConn: alpha, ref: "a3", body: io.NopCloser(readFail)}), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := byID(t, res, "alpha")
	if got.State != orchestrator.StateOK {
		t.Fatalf("state = %q, want ok", got.State)
	}
	want := map[string]orchestrator.Status{
		"a1": orchestrator.StatusFiled,
		"a2": orchestrator.StatusTooLarge,
		"a3": orchestrator.StatusFailed,
		"a4": orchestrator.StatusFiled,
	}
	if g := docStatuses(got.Documents); !mapsEqual(g, want) {
		t.Fatalf("documents = %+v, want %v", got.Documents, want)
	}
	if got := len(got.Documents); got != 4 {
		t.Fatalf("%d document results, want 4 (one per listed ref)", got)
	}
}

// bodyOverride serves body for ref instead of the fake's content.
type bodyOverride struct {
	*fakeConn
	ref  string
	body io.ReadCloser
}

func (b *bodyOverride) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	rc, err := b.fakeConn.Fetch(ctx, s, ref)
	if err != nil || ref.ProviderID != b.ref {
		return rc, err
	}
	_ = rc.Close()
	return b.body, nil
}

func TestRun_SkipsKnownIDBeforeFetch(t *testing.T) {
	t.Parallel()
	known := store.Document{Provider: "alpha", ProviderID: "a1", Kind: connector.Invoice, IssuedAt: day(time.March, 1), SHA256: sum(pdf("old alpha a1")), LocalPath: "2026/energy/alpha/old.pdf", Version: 1}
	// The same ProviderID under another provider identifies nothing for
	// alpha.
	otherProvider := store.Document{Provider: "bravo", ProviderID: "a2", Kind: connector.Invoice, IssuedAt: day(time.March, 2), SHA256: sum(pdf("bravo a2")), Version: 1}

	r := newRunRig(t, []store.Document{known, otherProvider})
	noID := runRef("", 5)
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2), noID)
	alpha.content[""] = pdf("alpha without id")

	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := alpha.fetchedList(), []string{"a2", ""}; !slices.Equal(got, want) {
		t.Fatalf("fetched = %q, want %q (a1 is known: never fetched)", got, want)
	}
	got := byID(t, res, "alpha")
	if got.State != orchestrator.StateOK {
		t.Fatalf("state = %q, want ok", got.State)
	}
	if len(got.Documents) != 3 {
		t.Fatalf("documents = %+v, want 3", got.Documents)
	}
	wantSkip := orchestrator.DocResult{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusSkippedKnownID}
	if got.Documents[0] != wantSkip {
		t.Fatalf("documents[0] = %+v, want %+v", got.Documents[0], wantSkip)
	}
	if got.Documents[1].Status != orchestrator.StatusFiled || got.Documents[2].Status != orchestrator.StatusFiled {
		t.Fatalf("documents = %+v, want a2 and the id-less ref filed", got.Documents)
	}
	if puts := r.ev.withPrefix("put:"); len(puts) != 2 {
		t.Fatalf("puts = %q, want 2", puts)
	}
}

// An index failure during the known-id lookup fails the document closed: it
// is neither fetched nor reported as skipped.
func TestRun_KnownIDLookupErrorFailsDocument(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	r.idx.latestErr = errors.New("synthetic index failure")
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if f := alpha.fetchedList(); len(f) != 0 {
		t.Fatalf("fetched = %q, want none", f)
	}
	docs := byID(t, res, "alpha").Documents
	want := orchestrator.DocResult{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusFailed}
	if len(docs) != 1 || docs[0] != want {
		t.Fatalf("documents = %+v, want [%+v]", docs, want)
	}
}

// Supplier-provided metadata never escapes the provider's directory.
func TestRun_UnsafeRefMetadataStaysConfined(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ref  func(*connector.DocumentRef)
	}{
		{"traversal provider id", func(r *connector.DocumentRef) { r.ProviderID = "../../../etc/passwd" }},
		{"absolute provider id", func(r *connector.DocumentRef) { r.ProviderID = "/tmp/x" }},
		{"traversal mime type", func(r *connector.DocumentRef) { r.MimeType = "application/../../x" }},
		{"control characters", func(r *connector.DocumentRef) { r.ProviderID = "a\x00b\nc\x1b[2J" }},
		{"backslashes", func(r *connector.DocumentRef) { r.ProviderID = `..\..\windows` }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			ref := runRef("a1", 1)
			tt.ref(&ref)
			alpha := newFakeConn(r.ev, "alpha", ref)
			if _, err := r.o.Run(t.Context(), registry(t, alpha), period2026); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			for _, p := range r.dst.put() {
				rel := p.Path.Rel()
				if !strings.HasPrefix(rel, "2026/energy/alpha/") || strings.Contains(rel, "..") || strings.ContainsAny(rel, "\\\x00\n\x1b") || strings.Count(rel, "/") != 3 {
					t.Fatalf("filed at %q, want a single safe name under 2026/energy/alpha/", rel)
				}
			}
		})
	}
}

func TestRun_PanicMarksBrokenWithoutLeakingCanary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		stage string
		val   func(canary string) any
	}{
		{"login string", stageLogin, func(c string) any { return "synthetic crash cookie " + c }},
		{"login error", stageLogin, func(c string) any { return fmt.Errorf("synthetic crash %s: %w", c, connector.ErrNeedsLogin) }},
		{"login stringer", stageLogin, func(c string) any { return stringerT("synthetic crash " + c) }},
		{"login bare canary", stageLogin, func(c string) any { return c }},
		{"login nil", stageLogin, func(string) any { return nil }},
		{"list string", stageList, func(c string) any { return "synthetic crash " + c }},
		{"fetch string", stageFetch, func(c string) any { return "synthetic crash " + c }},
		{"body read string", stageRead, func(c string) any { return "synthetic crash " + c }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Cookie)
			artDir := testsecrets.ArtifactDir(t)
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
			alpha.panicAt, alpha.panicRef, alpha.panicVal = tt.stage, "a2", tt.val(canary)
			bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))

			var res orchestrator.RunResult
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("Run let a connector panic escape: %v", "(value withheld)")
					}
				}()
				res, err = r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
			}()
			if err != nil {
				t.Fatalf("Run() error = %v, want nil (a panic is a broken connector)", err)
			}
			a := byID(t, res, "alpha")
			if a.State != orchestrator.StateBroken {
				t.Fatalf("alpha state = %q, want broken (a panic is always broken)", a.State)
			}
			if s := byID(t, res, "bravo"); s.State != orchestrator.StateOK || docStatuses(s.Documents)["b1"] != orchestrator.StatusFiled {
				t.Fatalf("bravo = %+v, want ok with b1 filed", s)
			}
			if tt.stage == stageFetch || tt.stage == stageRead {
				if got := docStatuses(a.Documents)["a1"]; got != orchestrator.StatusFiled {
					t.Fatalf("alpha documents = %+v, want a1 filed before the panic kept", a.Documents)
				}
			}
			if !hasLog(t, r.log.String(), "alpha", "ERROR") {
				t.Fatalf("panic not logged at error level with connector=alpha; log:\n%s", r.log.String())
			}

			rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
			rep.AddRun(res)
			js, jerr := rep.JSON()
			if jerr != nil {
				t.Fatalf("JSON: %v", jerr)
			}
			// Written to the artifact dir: make leakcheck scans it too.
			if _, werr := orchestrator.WriteReport(t.Context(), artDir, rep); werr != nil {
				t.Fatalf("WriteReport: %v", werr)
			}
			for name, out := range map[string]string{
				"log":         r.log.String(),
				"report json": string(js),
				"report text": rep.Text(),
				"result":      fmt.Sprintf("%+v", res),
			} {
				if strings.Contains(out, canary) {
					t.Fatalf("canary leaked into the %s:\n%s", name, out)
				}
			}
		})
	}
}

// stringerT is a panic value whose String method returns its content.
type stringerT string

func (s stringerT) String() string { return string(s) }

// Connector errors are logged through the redacting handler only; their text
// never reaches the result or the report.
func TestRun_ConnectorErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	tests := []struct {
		name  string
		setup func(*fakeConn)
	}{
		{"login error with a token in a url", func(c *fakeConn) {
			c.loginErr = fmt.Errorf("get https://billing.alpha.example/sso?access_token=%s: %w", canary, connector.ErrAuthFailed)
		}},
		{"list error with a bare token", func(c *fakeConn) {
			c.listErr = errors.New("synthetic failure, token " + canary)
		}},
		{"fetch error with a session", func(c *fakeConn) {
			c.fetchErr["a1"] = errors.New("synthetic fetch failure: session=" + canary)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
			tt.setup(alpha)
			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			rep := orchestrator.Report{}
			rep.AddRun(res)
			js, _ := rep.JSON()
			for name, out := range map[string]string{
				"log":         r.log.String(),
				"result":      fmt.Sprintf("%+v", res),
				"report json": string(js),
				"report text": rep.Text(),
			} {
				if strings.Contains(out, canary) {
					t.Fatalf("canary leaked into the %s:\n%s", name, out)
				}
			}
			if !hasLog(t, r.log.String(), "alpha", "WARN", "ERROR") {
				t.Fatalf("failure not logged with connector=alpha; log:\n%s", r.log.String())
			}
		})
	}
}

func TestRun_ContextCanceledStopsLoop(t *testing.T) {
	t.Parallel()

	t.Run("canceled during a connector", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
		alpha.onList = cancel
		bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))

		res, err := r.o.Run(ctx, registry(t, alpha, bravo), period2026)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
		if n := len(bravo.envList()); n != 0 {
			t.Fatalf("bravo Login called %d times after cancel, want 0", n)
		}
		if p := r.ev.withPrefix("put"); len(p) != 0 {
			t.Fatalf("puts after cancel = %q, want none", p)
		}
		if ins := r.ev.withPrefix("insert:"); len(ins) != 0 {
			t.Fatalf("inserts after cancel = %q, want none", ins)
		}
		if got := resultIDs(res); !slices.Equal(got, []string{"alpha"}) {
			t.Fatalf("results = %q, want [alpha] (bravo never started)", got)
		}
	})

	t.Run("canceled between connectors", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
		r.dst.after = cancel // cancel right after alpha's document is stored
		bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))

		res, err := r.o.Run(ctx, registry(t, alpha, bravo), period2026)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
		if n := len(bravo.envList()); n != 0 {
			t.Fatalf("bravo Login called %d times after cancel, want 0", n)
		}
		if slices.Contains(resultIDs(res), "bravo") {
			t.Fatalf("results = %q, want no bravo", resultIDs(res))
		}
	})

	t.Run("already canceled", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
		res, err := r.o.Run(ctx, registry(t, alpha), period2026)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
		if n := len(alpha.envList()); n != 0 || len(res.Connectors) != 0 {
			t.Fatalf("connector started on a canceled context (logins %d, results %+v)", n, res.Connectors)
		}
	})
}

// --- helpers ------------------------------------------------------------------

// logLines decodes the JSON log lines.
func logLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line is not JSON: %v: %q", err, sc.Text())
		}
		lines = append(lines, m)
	}
	return lines
}

// hasLog reports whether a record tagged connector=id has one of levels.
func hasLog(t *testing.T, out, id string, levels ...string) bool {
	t.Helper()
	for _, l := range logLines(t, out) {
		if l["connector"] == id && slices.Contains(levels, fmt.Sprint(l["level"])) {
			return true
		}
	}
	return false
}

func mapsEqual[K comparable, V comparable](a, b map[K]V) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
