// Review follow-ups for the connector loop (J0 task T24): a body whose Read
// panics is still closed, a connector stopped by the run's cancellation is
// interrupted (never ok), and a connector without a usable id is labelled by
// its position. Everything is synthetic.
package orchestrator_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestRun_ReadPanicClosesBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		wrap func(*fakeConn) connector.Connector
	}{
		{"plain body", func(c *fakeConn) connector.Connector { return c }},
		// Close panics too: the recovery must survive it and still log
		// nothing of either panic value.
		{"body whose Close also panics", func(c *fakeConn) connector.Connector { return closePanics{c} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
			// a1 panics: with closePanics, a later ref would never be reached.
			alpha.panicAt, alpha.panicRef, alpha.panicVal = stageRead, "a1", "crash "+panicMarker
			bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))
			res, err := r.o.Run(t.Context(), connList{tt.wrap(alpha), bravo}, period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			// closePanics never reaches fakeBody.Close, so only the plain
			// body records its close; the other row proves the recovery
			// survives Close panicking.
			if got := alpha.closedList(); tt.name == "plain body" && !slices.Equal(got, []string{"a1"}) {
				t.Fatalf("closed = %q, want [a1] (the panicking body is closed)", got)
			}
			if s := byID(t, res, "alpha").State; s != orchestrator.StateBroken {
				t.Fatalf("alpha state = %q, want broken", s)
			}
			if s := byID(t, res, "bravo").State; s != orchestrator.StateOK {
				t.Fatalf("bravo state = %q, want ok", s)
			}
			if strings.Contains(r.log.String(), panicMarker) {
				t.Fatalf("panic value reached the log:\n%s", r.log.String())
			}
			wantClosePanic := tt.name != "plain body"
			found := false
			for _, l := range logLines(t, r.log.String()) {
				if l["connector"] == "alpha" && l["phase"] == stageRead && l["close_panicked"] == wantClosePanic {
					found = true
				}
			}
			if !found {
				t.Fatalf("no read-phase panic record with close_panicked=%v; log:\n%s", wantClosePanic, r.log.String())
			}
		})
	}
}

func TestRun_CanceledConnectorIsInterrupted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(r *runRig, alpha *fakeConn, cancel context.CancelFunc)
	}{
		{"canceled during login", func(_ *runRig, a *fakeConn, cancel context.CancelFunc) {
			a.onLogin = func(context.Context, connector.Env) { cancel() }
		}},
		{"canceled during list", func(_ *runRig, a *fakeConn, cancel context.CancelFunc) {
			a.onList = cancel
		}},
		{"canceled while filing the first document", func(r *runRig, _ *fakeConn, cancel context.CancelFunc) {
			r.dst.after = cancel
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1), runRef("a2", 2))
			tt.setup(r, alpha, cancel)
			res, err := r.o.Run(ctx, registry(t, alpha), period2026)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
			if s := byID(t, res, "alpha").State; s != orchestrator.StateInterrupted {
				t.Fatalf("alpha state = %q, want %q", s, orchestrator.StateInterrupted)
			}
			var rep orchestrator.Report
			rep.AddRun(res)
			if code := orchestrator.ExitCode(rep, nil); code != orchestrator.ExitAttention {
				t.Fatalf("ExitCode(interrupted, nil) = %d, want %d", code, orchestrator.ExitAttention)
			}
		})
	}
}

func TestRun_UnidentifiedConnectorLabelledByPosition(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))
	res, err := r.o.Run(t.Context(), connList{nil, infoPanics{newFakeConn(r.ev, "alpha")}, bravo}, period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := resultIDs(res), []string{"connector[0]", "connector[1]", "bravo"}; !slices.Equal(got, want) {
		t.Fatalf("result ids = %q, want %q", got, want)
	}
	found := false
	for _, l := range logLines(t, r.log.String()) {
		if l["connector"] == "connector[1]" && l["level"] == "ERROR" && l["phase"] == "info" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no ERROR record with connector=connector[1] phase=info; log:\n%s", r.log.String())
	}
}
