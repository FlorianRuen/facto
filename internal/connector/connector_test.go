// Tests for package connector (J0 task T12): the contract between the
// orchestrator and supplier packages. Spec: docs/spec.md "Connector model".
//
// Expected API (implementer: follow exactly; types quoted from the spec are
// reproduced verbatim):
//
//	type Connector interface {
//	    Info() Info
//	    Login(ctx context.Context, env Env) (Session, error)
//	    List(ctx context.Context, s Session, p Period) ([]DocumentRef, error)
//	    Fetch(ctx context.Context, s Session, ref DocumentRef) (io.ReadCloser, error)
//	}
//
//	// Session is opaque connector state returned by Login. No methods in J0
//	// (any connector value satisfies it); persistence comes with internal/vault.
//	type Session any
//
//	// Info is a connector's static metadata.
//	type Info struct {
//	    ID             string    // ^[a-z0-9]+(-[a-z0-9]+)*$, at most 40 bytes; used in paths (sessions/<id>.age)
//	    Name           string    // human name, e.g. "Fournisseur Exemple"
//	    Category       string    // default output category: housing, internet, services…
//	    Kinds          []DocKind // document kinds the connector can list
//	    AllowedDomains []string  // httpx allowlist: exact host or "*.host"
//	}
//
//	type DocumentRef struct { // exactly the spec fields
//	    ProviderID  string
//	    Contract    string
//	    Kind        DocKind
//	    IssuedAt    time.Time
//	    PeriodStart time.Time
//	    PeriodEnd   time.Time
//	    AmountCents *int64
//	    Currency    string
//	    MimeType    string
//	    Extra       map[string]string
//	}
//
//	type Env struct { // exactly the spec fields
//	    Secrets SecretResolver
//	    Browser BrowserPool
//	    HTTP    *http.Client
//	    Prompt  Prompter
//	    Log     *slog.Logger
//	}
//	// Consumer-side interfaces. Method sets are not pinned by these tests:
//	// SecretResolver is meant to be Resolve(ctx, ref string) (secrets.Secret, error)
//	// once internal/secrets lands (T10); Prompter asks the user for an OTP code;
//	// BrowserPool is a placeholder until internal/browser exists.
//	type SecretResolver interface{ … }
//	type Prompter interface{ … }
//	type BrowserPool interface{ … }
//
//	// DocKind is an integer enum; the zero value is invalid ("unknown").
//	type DocKind int
//	const ( _ DocKind = iota; Invoice; Receipt; RentReceipt; TaxNotice; Statement )
//	// String: "invoice", "receipt", "rent-receipt", "tax-notice", "statement";
//	// any other value (zero, out of range) returns a non-empty string that
//	// ParseDocKind refuses.
//	func (k DocKind) String() string
//	// ParseDocKind is strict: exact lowercase String() forms only. Anything
//	// else wraps ErrUnknownDocKind.
//	func ParseDocKind(s string) (DocKind, error)
//	func (k DocKind) MarshalText() ([]byte, error)   // invalid kind: ErrUnknownDocKind
//	func (k *DocKind) UnmarshalText(b []byte) error  // same rules as ParseDocKind
//
//	// Period is the half-open UTC interval [Start, End).
//	type Period struct{ Start, End time.Time }
//	func Year(n int) Period                      // Jan 1 n 00:00 UTC → Jan 1 n+1 00:00 UTC
//	func PreviousYear(c clock.Clock) Period      // Year(c.Now().UTC().Year() - 1)
//	func (p Period) Contains(t time.Time) bool   // Start <= t < End
//
//	// Sentinels the orchestrator branches on (errors.Is), all distinct.
//	var ErrNeedsLogin, ErrBroken, ErrAuthFailed, ErrRateLimited error
//	// Registry and parsing errors.
//	var ErrDuplicateID, ErrInvalidInfo, ErrUnknownDocKind error
//
//	// Registry holds connectors by Info().ID. Safe for concurrent use. No
//	// package-level registry: cmd/facto builds one and injects it.
//	type Registry struct{ … }
//	func NewRegistry() *Registry
//	// Register validates c.Info() and adds c. nil connector or invalid Info:
//	// ErrInvalidInfo. Already registered ID: ErrDuplicateID. On error the
//	// registry is unchanged. Info validation: ID format above; at least one
//	// allowed domain; no empty, "*", scheme ("://") or path ("/") domain entry;
//	// every Kinds entry valid.
//	func (r *Registry) Register(c Connector) error
//	func (r *Registry) Get(id string) (Connector, bool)
//	// All returns the connectors sorted by ID, in a new slice.
//	func (r *Registry) All() []Connector
package connector_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/connector"
)

// fakeConnector is a minimal in-memory connector: it proves the interface
// shape matches the spec and gives the registry something to hold.
type fakeConnector struct {
	info connector.Info
}

var _ connector.Connector = (*fakeConnector)(nil)

type fakeSession struct{ user string }

func (f *fakeConnector) Info() connector.Info { return f.info }

func (f *fakeConnector) Login(_ context.Context, env connector.Env) (connector.Session, error) {
	if env.HTTP == nil {
		return nil, connector.ErrNeedsLogin
	}
	return fakeSession{user: "synthetic"}, nil
}

func (f *fakeConnector) List(_ context.Context, s connector.Session, p connector.Period) ([]connector.DocumentRef, error) {
	if _, ok := s.(fakeSession); !ok {
		return nil, fmt.Errorf("list: %w", connector.ErrNeedsLogin)
	}
	amount := int64(8412)
	return []connector.DocumentRef{{
		ProviderID:  "FA-2026-0001",
		Contract:    "CTR-EXEMPLE",
		Kind:        connector.Invoice,
		IssuedAt:    p.Start.AddDate(0, 2, 13),
		PeriodStart: p.Start,
		PeriodEnd:   p.Start.AddDate(0, 1, 0),
		AmountCents: &amount,
		Currency:    "EUR",
		MimeType:    "application/pdf",
		Extra:       map[string]string{"source": "synthetic"},
	}}, nil
}

func (f *fakeConnector) Fetch(_ context.Context, _ connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("%PDF-1.7 synthetic " + ref.ProviderID)), nil
}

func validInfo(id string) connector.Info {
	return connector.Info{
		ID:             id,
		Name:           "Fournisseur Exemple",
		Category:       "housing",
		Kinds:          []connector.DocKind{connector.Invoice},
		AllowedDomains: []string{"espace-client.fournisseur.example", "*.cdn.fournisseur.example"},
	}
}

func newFake(id string) *fakeConnector { return &fakeConnector{info: validInfo(id)} }

func TestConnector_ContractRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := connector.Env{
		Secrets: nil,
		Browser: nil,
		HTTP:    &http.Client{},
		Prompt:  nil,
		Log:     slog.New(slog.DiscardHandler),
	}
	// Pin the Env field types from the spec.
	pinEnv := func(connector.SecretResolver, connector.BrowserPool, *http.Client, connector.Prompter, *slog.Logger) {
	}
	pinEnv(env.Secrets, env.Browser, env.HTTP, env.Prompt, env.Log)

	var c connector.Connector = newFake("fakeprovider")
	s, err := c.Login(ctx, env)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	refs, err := c.List(ctx, s, connector.Year(2026))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 1 || refs[0].Kind != connector.Invoice || *refs[0].AmountCents != 8412 {
		t.Fatalf("List = %+v", refs)
	}
	rc, err := c.Fetch(ctx, s, refs[0])
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !strings.HasPrefix(string(b), "%PDF-") {
		t.Fatalf("Fetch body = %q", b)
	}

	if _, err := c.Login(ctx, connector.Env{}); !errors.Is(err, connector.ErrNeedsLogin) {
		t.Fatalf("Login without HTTP: err = %v, want ErrNeedsLogin", err)
	}
}

func TestSentinels_DistinctAndWrappable(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrNeedsLogin":     connector.ErrNeedsLogin,
		"ErrBroken":         connector.ErrBroken,
		"ErrAuthFailed":     connector.ErrAuthFailed,
		"ErrRateLimited":    connector.ErrRateLimited,
		"ErrDuplicateID":    connector.ErrDuplicateID,
		"ErrInvalidInfo":    connector.ErrInvalidInfo,
		"ErrUnknownDocKind": connector.ErrUnknownDocKind,
	}
	for name, err := range sentinels {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		wrapped := fmt.Errorf("edf: list invoices: %w", err)
		for other, oerr := range sentinels {
			if got, want := errors.Is(wrapped, oerr), name == other; got != want {
				t.Errorf("errors.Is(wrapped %s, %s) = %v, want %v", name, other, got, want)
			}
		}
	}
}

func TestRegistry_RegisterGetAll(t *testing.T) {
	t.Parallel()

	r := connector.NewRegistry()
	if got := r.All(); len(got) != 0 {
		t.Fatalf("empty registry All() = %v", got)
	}
	ids := []string{"wecasa", "bouyguestelecom", "edf", "ileo", "fake-provider2"}
	for _, id := range ids {
		if err := r.Register(newFake(id)); err != nil {
			t.Fatalf("Register(%q): %v", id, err)
		}
	}
	for _, id := range ids {
		c, ok := r.Get(id)
		if !ok || c.Info().ID != id {
			t.Fatalf("Get(%q) = %v, %v", id, c, ok)
		}
	}
	if c, ok := r.Get("unknown"); ok || c != nil {
		t.Fatalf("Get(unknown) = %v, %v, want nil, false", c, ok)
	}

	all := r.All()
	got := make([]string, 0, len(all))
	for _, c := range all {
		got = append(got, c.Info().ID)
	}
	want := slices.Clone(ids)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("All() IDs = %v, want sorted %v", got, want)
	}

	// The returned slice is a copy.
	all[0] = nil
	if again := r.All(); again[0] == nil {
		t.Fatal("All() exposes the registry's internal slice")
	}
}

func TestRegistry_RejectsDuplicateID(t *testing.T) {
	t.Parallel()

	r := connector.NewRegistry()
	first := newFake("edf")
	if err := r.Register(first); err != nil {
		t.Fatalf("Register first: %v", err)
	}
	second := newFake("edf")
	second.info.Name = "Imposteur Exemple"
	err := r.Register(second)
	if !errors.Is(err, connector.ErrDuplicateID) {
		t.Fatalf("Register duplicate: err = %v, want ErrDuplicateID", err)
	}
	got, ok := r.Get("edf")
	if !ok || got != connector.Connector(first) {
		t.Fatalf("duplicate Register replaced the first connector: got %v", got)
	}
	if n := len(r.All()); n != 1 {
		t.Fatalf("All() has %d connectors, want 1", n)
	}
}

func TestRegistry_RejectsInvalidInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*connector.Info)
	}{
		{name: "empty id", mutate: func(i *connector.Info) { i.ID = "" }},
		{name: "traversal id", mutate: func(i *connector.Info) { i.ID = "../evil" }},
		{name: "slash in id", mutate: func(i *connector.Info) { i.ID = "a/b" }},
		{name: "dot id", mutate: func(i *connector.Info) { i.ID = "." }},
		{name: "uppercase id", mutate: func(i *connector.Info) { i.ID = "EDF" }},
		{name: "space in id", mutate: func(i *connector.Info) { i.ID = "my provider" }},
		{name: "NUL in id", mutate: func(i *connector.Info) { i.ID = "edf\x00" }},
		{name: "leading hyphen", mutate: func(i *connector.Info) { i.ID = "-edf" }},
		{name: "trailing hyphen", mutate: func(i *connector.Info) { i.ID = "edf-" }},
		{name: "overlong id", mutate: func(i *connector.Info) { i.ID = strings.Repeat("a", 41) }},
		{name: "no allowed domain", mutate: func(i *connector.Info) { i.AllowedDomains = nil }},
		{name: "empty domain", mutate: func(i *connector.Info) { i.AllowedDomains = []string{""} }},
		{name: "bare wildcard domain", mutate: func(i *connector.Info) { i.AllowedDomains = []string{"*"} }},
		{name: "domain with scheme", mutate: func(i *connector.Info) { i.AllowedDomains = []string{"https://fournisseur.example"} }},
		{name: "domain with path", mutate: func(i *connector.Info) { i.AllowedDomains = []string{"fournisseur.example/login"} }},
		{name: "zero doc kind", mutate: func(i *connector.Info) { i.Kinds = []connector.DocKind{connector.Invoice, 0} }},
		{name: "out of range doc kind", mutate: func(i *connector.Info) { i.Kinds = []connector.DocKind{99} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newFake("fakeprovider")
			tt.mutate(&c.info)
			r := connector.NewRegistry()
			if err := r.Register(c); !errors.Is(err, connector.ErrInvalidInfo) {
				t.Fatalf("Register(%+v): err = %v, want ErrInvalidInfo", c.info, err)
			}
			if n := len(r.All()); n != 0 {
				t.Fatalf("invalid connector was registered (%d in registry)", n)
			}
		})
	}

	t.Run("nil connector", func(t *testing.T) {
		t.Parallel()
		if err := connector.NewRegistry().Register(nil); !errors.Is(err, connector.ErrInvalidInfo) {
			t.Fatalf("Register(nil): err = %v, want ErrInvalidInfo", err)
		}
	})
}

func TestRegistry_AcceptsValidIDs(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"edf", "bouyguestelecom", "fake-provider", "a1", strings.Repeat("a", 40)} {
		if err := connector.NewRegistry().Register(newFake(id)); err != nil {
			t.Errorf("Register(%q): %v", id, err)
		}
	}
}

func TestRegistry_ConcurrentUse(t *testing.T) {
	t.Parallel()

	r := connector.NewRegistry()
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			id := fmt.Sprintf("provider%d", i)
			if err := r.Register(newFake(id)); err != nil {
				t.Errorf("Register(%q): %v", id, err)
			}
			_, _ = r.Get(id)
			_ = r.All()
		})
	}
	wg.Wait()
	if n := len(r.All()); n != 32 {
		t.Fatalf("All() has %d connectors, want 32", n)
	}
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestPeriod_PreviousYear(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		now  time.Time
		want int
	}{
		{name: "mid january", now: time.Date(2027, 1, 15, 10, 30, 0, 0, time.UTC), want: 2026},
		{name: "first instant of the year", now: date(2027, 1, 1), want: 2026},
		{name: "last instant of the year", now: time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC), want: 2025},
		{name: "leap day", now: date(2028, 2, 29), want: 2027},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := connector.PreviousYear(clock.NewFake(tt.now))
			want := connector.Period{Start: date(tt.want, 1, 1), End: date(tt.want+1, 1, 1)}
			if !got.Start.Equal(want.Start) || !got.End.Equal(want.End) {
				t.Fatalf("PreviousYear(%s) = [%s, %s), want [%s, %s)", tt.now, got.Start, got.End, want.Start, want.End)
			}
			if got.Start.Location() != time.UTC || got.End.Location() != time.UTC {
				t.Fatalf("PreviousYear not in UTC: %s, %s", got.Start.Location(), got.End.Location())
			}
			if y := connector.Year(tt.want); !y.Start.Equal(got.Start) || !y.End.Equal(got.End) {
				t.Fatalf("Year(%d) = %+v, PreviousYear = %+v", tt.want, y, got)
			}
		})
	}
}

func TestPeriod_Year(t *testing.T) {
	t.Parallel()

	p := connector.Year(2026)
	if !p.Start.Equal(date(2026, 1, 1)) || !p.End.Equal(date(2027, 1, 1)) {
		t.Fatalf("Year(2026) = [%s, %s)", p.Start, p.End)
	}
	if p.Start.Location() != time.UTC || p.End.Location() != time.UTC {
		t.Fatalf("Year(2026) not in UTC")
	}
}

func TestPeriod_ContainsIsHalfOpen(t *testing.T) {
	t.Parallel()

	p := connector.Year(2026)
	paris := time.FixedZone("CET", 3600)
	tests := []struct {
		name string
		t    time.Time
		want bool
	}{
		{name: "start", t: p.Start, want: true},
		{name: "middle", t: date(2026, 3, 14), want: true},
		{name: "just before end", t: p.End.Add(-time.Nanosecond), want: true},
		{name: "end excluded", t: p.End, want: false},
		{name: "just before start", t: p.Start.Add(-time.Nanosecond), want: false},
		{name: "other location same instant as start", t: p.Start.In(paris), want: true},
		{name: "zero time", t: time.Time{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := p.Contains(tt.t); got != tt.want {
				t.Fatalf("Year(2026).Contains(%s) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}
}

func TestDocKind_ParseAndString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind connector.DocKind
		str  string
	}{
		{connector.Invoice, "invoice"},
		{connector.Receipt, "receipt"},
		{connector.RentReceipt, "rent-receipt"},
		{connector.TaxNotice, "tax-notice"},
		{connector.Statement, "statement"},
	}
	seen := map[connector.DocKind]bool{}
	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			if tt.kind == 0 {
				t.Fatalf("%s is the zero DocKind; zero must stay invalid", tt.str)
			}
			if seen[tt.kind] {
				t.Fatalf("%s shares its value with another kind", tt.str)
			}
			seen[tt.kind] = true

			if got := tt.kind.String(); got != tt.str {
				t.Fatalf("String() = %q, want %q", got, tt.str)
			}
			got, err := connector.ParseDocKind(tt.str)
			if err != nil || got != tt.kind {
				t.Fatalf("ParseDocKind(%q) = %v, %v; want %v", tt.str, got, err, tt.kind)
			}
			b, err := tt.kind.MarshalText()
			if err != nil || string(b) != tt.str {
				t.Fatalf("MarshalText() = %q, %v; want %q", b, err, tt.str)
			}
			var u connector.DocKind
			if err := u.UnmarshalText([]byte(tt.str)); err != nil || u != tt.kind {
				t.Fatalf("UnmarshalText(%q) = %v, %v; want %v", tt.str, u, err, tt.kind)
			}
		})
	}
}

func TestDocKind_RejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"", "unknown", "Invoice", "INVOICE", " invoice", "invoice ", "invoices",
		"rent_receipt", "rentreceipt", "tax notice", "0", "1", "DocKind(1)",
	} {
		got, err := connector.ParseDocKind(s)
		if !errors.Is(err, connector.ErrUnknownDocKind) {
			t.Errorf("ParseDocKind(%q) = %v, %v; want ErrUnknownDocKind", s, got, err)
		}
		var u connector.DocKind
		if err := u.UnmarshalText([]byte(s)); !errors.Is(err, connector.ErrUnknownDocKind) {
			t.Errorf("UnmarshalText(%q): err = %v, want ErrUnknownDocKind", s, err)
		}
	}

	for _, k := range []connector.DocKind{0, 99, -1} {
		s := k.String()
		if s == "" {
			t.Errorf("DocKind(%d).String() is empty", int(k))
		}
		if _, err := connector.ParseDocKind(s); err == nil {
			t.Errorf("ParseDocKind(DocKind(%d).String() = %q) succeeded, want error", int(k), s)
		}
		if b, err := k.MarshalText(); !errors.Is(err, connector.ErrUnknownDocKind) {
			t.Errorf("DocKind(%d).MarshalText() = %q, %v; want ErrUnknownDocKind", int(k), b, err)
		}
	}
}
