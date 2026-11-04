// Tests added by the J1 T18 review: cancellation never drops a restored
// session, a Login panic still wipes Env.Saved and closes the browsers, a
// List rejection drops the restored session, and report notes are rendered
// (escaped in the text report). Every value is synthetic.
package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestRun_CanceledRunKeepsRestoredSession(t *testing.T) {
	t.Parallel()
	ev := &events{}
	sessions := newFakeSessions(ev, true)
	sessions.put("alpha", "synthetic-saved-blob-alpha")
	r := newRunRig(t, nil, withSessions(sessions))
	sessions.ev = r.ev
	alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
	alpha.loginErr = connector.ErrNeedsLogin
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	alpha.onLogin = func(context.Context, connector.Env) { cancel() }

	_, err := r.o.Run(ctx, registry(t, alpha), period2026)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if _, _, deletes := sessions.calls(); len(deletes) != 0 {
		t.Fatalf("Delete calls = %q, want none (a canceled run never drops a session)", deletes)
	}
	if _, ok := sessions.blob("alpha"); !ok {
		t.Fatal("saved session gone after a canceled run")
	}
}

func TestRun_LoginPanicWipesSavedAndClosesBrowsers(t *testing.T) {
	t.Parallel()
	ev := &events{}
	sessions := newFakeSessions(ev, true)
	sessions.put("alpha", "synthetic-saved-blob-alpha")
	pool := &fakePool{ev: ev}
	r := newRunRig(t, nil, withSessions(sessions), withBrowser(pool))
	sessions.ev, pool.ev = r.ev, r.ev
	alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
	alpha.panicAt, alpha.panicVal = stageLogin, "synthetic crash"
	alpha.onLogin = func(ctx context.Context, env connector.Env) {
		if env.Browser == nil {
			t.Errorf("Env.Browser is nil while Deps.Browser is set")
			return
		}
		if _, err := env.Browser.Launch(ctx, connector.LaunchOptions{}); err != nil {
			t.Errorf("Launch during Login: %v", err)
		}
	}

	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := byID(t, res, "alpha"); got.State != orchestrator.StateBroken {
		t.Fatalf("alpha = %+v, want broken after a Login panic", got)
	}
	if seen, _ := alpha.savedSeen(); len(seen) != 1 || seen[0] != "synthetic-saved-blob-alpha" {
		t.Fatal("alpha did not receive its saved session")
	}
	handed := sessions.handedOut()
	if len(handed) != 1 {
		t.Fatalf("Load handed out %d blobs, want 1", len(handed))
	}
	for i, s := range handed {
		if !s.IsZero() {
			t.Fatalf("restored blob %d not wiped after a Login panic", i)
		}
	}
	_, bs := pool.launched()
	if len(bs) != 1 {
		t.Fatalf("pool launched %d browsers, want 1", len(bs))
	}
	if n := bs[0].closeCount(); n != 1 {
		t.Fatalf("browser closed %d times after a Login panic, want exactly once", n)
	}
	if _, _, deletes := sessions.calls(); len(deletes) != 0 {
		t.Fatalf("Delete calls = %q, want none (a panic is not a rejected session)", deletes)
	}
}

func TestRun_ListRejectionDropsRestoredSession(t *testing.T) {
	t.Parallel()
	for _, listErr := range []error{connector.ErrNeedsLogin, connector.ErrAuthFailed} {
		t.Run(listErr.Error(), func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, true)
			sessions.put("alpha", "synthetic-saved-blob-alpha")
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
			alpha.listErr = listErr

			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if _, _, deletes := sessions.calls(); !slices.Equal(deletes, []string{"alpha"}) {
				t.Fatalf("Delete calls = %q, want exactly [alpha]", deletes)
			}
			if evs := r.ev.list(); slices.Index(evs, "delete:alpha") < slices.Index(evs, "list:alpha") {
				t.Fatalf("events = %q, want delete:alpha after list:alpha", evs)
			}
			got := byID(t, res, "alpha")
			if got.State != orchestrator.StateNeedsLogin || !hasNote(got, "facto login alpha") {
				t.Fatalf("alpha = %+v, want needs_login with a `facto login alpha` note", got)
			}
		})
	}
}

func TestReport_RendersNotes(t *testing.T) {
	t.Parallel()
	const raw = "synthetic note \x1b[31mred\x1b[0m\u202eend"
	rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
	rep.AddRun(orchestrator.RunResult{Connectors: []orchestrator.ConnectorResult{
		{ID: "alpha", State: orchestrator.StateNeedsLogin, Notes: []string{"first note", raw}},
		{ID: "bravo", State: orchestrator.StateOK},
	}})

	js, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var parsed struct {
		Connectors []map[string]json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(js, &parsed); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if len(parsed.Connectors) != 2 {
		t.Fatalf("connectors = %d, want 2:\n%s", len(parsed.Connectors), js)
	}
	var notes []string
	if err := json.Unmarshal(parsed.Connectors[0]["notes"], &notes); err != nil {
		t.Fatalf("alpha notes: %v\n%s", err, js)
	}
	if !slices.Equal(notes, []string{"first note", raw}) {
		t.Fatalf("alpha notes = %q, want both notes in order", notes)
	}
	if _, ok := parsed.Connectors[1]["notes"]; ok {
		t.Fatalf("bravo has a notes key, want it omitted when empty:\n%s", js)
	}

	text := rep.Text()
	if !strings.Contains(text, "first note") {
		t.Fatalf("text report misses the first note:\n%s", text)
	}
	if strings.ContainsRune(text, '\x1b') || strings.ContainsRune(text, '\u202e') {
		t.Fatalf("text report holds a raw control or format character:\n%q", text)
	}
	if !strings.Contains(text, `synthetic note \u001b[31mred`) {
		t.Fatalf("text report does not show the escaped note:\n%q", text)
	}
	lines := strings.Split(text, "\n")
	i := slices.IndexFunc(lines, func(l string) bool { return strings.HasSuffix(l, " alpha") })
	if i < 0 || i+2 >= len(lines) || !strings.Contains(lines[i+1], "first note") || !strings.Contains(lines[i+2], "synthetic note") {
		t.Fatalf("notes not rendered under the alpha line:\n%s", text)
	}
}
