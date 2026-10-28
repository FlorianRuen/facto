// Extra tests for the connector loop (J0 task T24): the panic value never
// reaches the log at all (logx masking is only a second line of defence),
// Fetch is never called once the run is canceled, and edge cases of
// connector misbehaviour. Everything is synthetic.
package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// panicMarker looks like nothing logx would mask (no key, no token shape):
// only the orchestrator withholding the value keeps it out of the log.
const panicMarker = "plainmarkerword"

type panicStruct struct{ Note string }

func TestRun_PanicValueNeverLogged(t *testing.T) {
	t.Parallel()
	values := map[string]any{
		"string":   "crash " + panicMarker,
		"error":    fmt.Errorf("crash %s: %w", panicMarker, connector.ErrNeedsLogin),
		"stringer": stringerT("crash " + panicMarker),
		"struct":   panicStruct{Note: panicMarker},
	}
	stages := []string{stageLogin, stageList, stageFetch, stageRead}
	for _, stage := range stages {
		for vname, val := range values {
			t.Run(stage+"/"+vname, func(t *testing.T) {
				t.Parallel()
				r := newRunRig(t, nil)
				alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
				alpha.panicAt, alpha.panicRef, alpha.panicVal = stage, "a2", val
				res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
				if err != nil {
					t.Fatalf("Run() error = %v", err)
				}
				if s := byID(t, res, "alpha").State; s != orchestrator.StateBroken {
					t.Fatalf("state = %q, want broken", s)
				}
				out := r.log.String()
				if strings.Contains(out, panicMarker) {
					t.Fatalf("panic value reached the log (before any masking):\n%s", out)
				}
				if s := fmt.Sprintf("%+v", res); strings.Contains(s, panicMarker) {
					t.Fatalf("panic value reached the result: %s", s)
				}
				found := false
				for _, l := range logLines(t, out) {
					if l["connector"] == "alpha" && l["level"] == "ERROR" && l["phase"] == stage {
						found = true
						if msg, _ := l["msg"].(string); !strings.Contains(msg, "panicked") {
							t.Fatalf("panic record msg = %q, want the fixed panic message", msg)
						}
					}
				}
				if !found {
					t.Fatalf("no ERROR record with connector=alpha phase=%s; log:\n%s", stage, out)
				}
				if stage == stageFetch || stage == stageRead {
					want := map[string]orchestrator.Status{"a1": orchestrator.StatusFiled, "a2": orchestrator.StatusFailed}
					if got := docStatuses(byID(t, res, "alpha").Documents); !mapsEqual(got, want) {
						t.Fatalf("documents = %v, want %v (the panicking ref is reported failed)", got, want)
					}
				}
			})
		}
	}
}

func TestRun_NoFetchAfterCancel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setup       func(r *runRig, alpha *fakeConn, cancel context.CancelFunc)
		wantFetched []string
	}{
		{"canceled during login", func(_ *runRig, a *fakeConn, cancel context.CancelFunc) {
			a.onLogin = func(context.Context, connector.Env) { cancel() }
		}, nil},
		{"canceled during list", func(_ *runRig, a *fakeConn, cancel context.CancelFunc) {
			a.onList = cancel
		}, nil},
		{"canceled while filing the first document", func(r *runRig, _ *fakeConn, cancel context.CancelFunc) {
			r.dst.after = cancel
		}, []string{"a1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2), runRef("a3", 3))
			tt.setup(r, alpha, cancel)
			_, err := r.o.Run(ctx, registry(t, alpha), period2026)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
			if got := alpha.fetchedList(); !slices.Equal(got, tt.wantFetched) {
				t.Fatalf("fetched = %q, want %q (no Fetch after cancel)", got, tt.wantFetched)
			}
			if alpha.onLogin != nil && r.ev.withPrefix("list:") != nil {
				t.Fatalf("List called after a cancel during Login")
			}
			if p := r.ev.withPrefix("put:"); len(p) > len(tt.wantFetched) {
				t.Fatalf("puts = %q, want at most %d", p, len(tt.wantFetched))
			}
		})
	}
}

// infoPanics is a connector whose Info panics.
type infoPanics struct{ *fakeConn }

func (infoPanics) Info() connector.Info { panic("crash " + panicMarker) }

// closePanics returns bodies whose Close panics.
type closePanics struct{ *fakeConn }

func (c closePanics) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	rc, err := c.fakeConn.Fetch(ctx, s, ref)
	if err != nil {
		return nil, err
	}
	return panicCloser{rc}, nil
}

type panicCloser struct{ io.ReadCloser }

func (panicCloser) Close() error { panic("crash " + panicMarker) }

// nilBody returns no body and no error.
type nilBody struct{ *fakeConn }

func (n nilBody) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	_, _ = n.fakeConn.Fetch(ctx, s, ref)
	return nil, nil
}

func TestRun_MisbehavingConnectors(t *testing.T) {
	t.Parallel()

	t.Run("nil connector and panicking Info are broken", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))
		res, err := r.o.Run(t.Context(), connList{nil, infoPanics{newFakeConn(r.ev, "alpha")}, bravo}, period2026)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if len(res.Connectors) != 3 || res.Connectors[0].State != orchestrator.StateBroken || res.Connectors[1].State != orchestrator.StateBroken {
			t.Fatalf("results = %+v, want two broken then bravo", res.Connectors)
		}
		if s := byID(t, res, "bravo").State; s != orchestrator.StateOK {
			t.Fatalf("bravo state = %q, want ok", s)
		}
		if strings.Contains(r.log.String(), panicMarker) {
			t.Fatalf("panic value reached the log:\n%s", r.log.String())
		}
	})

	t.Run("panicking Close keeps the filed document", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
		res, err := r.o.Run(t.Context(), registry(t, closePanics{alpha}), period2026)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		got := byID(t, res, "alpha")
		want := []orchestrator.DocResult{{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusFiled, Version: 1, Path: got.Documents[0].Path}}
		if got.State != orchestrator.StateBroken || !slices.Equal(got.Documents, want) {
			t.Fatalf("alpha = %+v, want broken with only a1 filed (no duplicate failed entry)", got)
		}
		if strings.Contains(r.log.String(), panicMarker) {
			t.Fatalf("panic value reached the log:\n%s", r.log.String())
		}
	})

	t.Run("nil body fails the document only", func(t *testing.T) {
		t.Parallel()
		r := newRunRig(t, nil)
		alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
		res, err := r.o.Run(t.Context(), registry(t, nilBody{alpha}), period2026)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		got := byID(t, res, "alpha")
		want := map[string]orchestrator.Status{"a1": orchestrator.StatusFailed, "a2": orchestrator.StatusFailed}
		if got.State != orchestrator.StateOK || !mapsEqual(docStatuses(got.Documents), want) {
			t.Fatalf("alpha = %+v, want ok with both documents failed", got)
		}
	})
}

// The extension comes from the MIME type; parameters and case are ignored,
// and an unknown or malformed type files without an extension.
func TestRun_ExtensionFromMimeType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mime    string
		wantExt string
	}{
		{"application/pdf", ".pdf"},
		{"Application/PDF; charset=binary", ".pdf"},
		{"text/html", ""},
		{"", ""},
		{"not a mime type;;", ""},
	}
	for _, tt := range tests {
		t.Run(tt.mime, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			ref := runRef("a1", 1)
			ref.MimeType = tt.mime
			alpha := newFakeConn(r.ev, "alpha", ref)
			if _, err := r.o.Run(t.Context(), registry(t, alpha), period2026); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			puts := r.dst.put()
			if len(puts) != 1 {
				t.Fatalf("puts = %d, want 1", len(puts))
			}
			rel := puts[0].Path.Rel()
			if gotPDF := strings.HasSuffix(rel, ".pdf"); gotPDF != (tt.wantExt == ".pdf") {
				t.Fatalf("filed at %q, want extension %q", rel, tt.wantExt)
			}
			if tt.wantExt == "" && strings.HasSuffix(rel, ".pdf") {
				t.Fatalf("filed at %q, want no extension", rel)
			}
		})
	}
}
