package orchestrator_test

// Spec, state table: auth_failed means the supplier rejected the
// credentials, and the fix is `facto config <id>` (not `facto login`). Every
// auth_failed result carries one fixed note naming it; a restored session
// the supplier refused stays needs_login with the `facto login <id>` note.

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestRun_AuthFailedNoteNamesFactoConfig(t *testing.T) {
	t.Parallel()
	const wantNote = "credentials rejected: run `facto config alpha`"
	tests := []struct {
		name      string
		restored  bool
		loginErr  error
		listErr   error
		fetchErr  error
		wantState orchestrator.State
		wantNotes []string
	}{
		{name: "login auth failed", loginErr: fmt.Errorf("submit: %w", connector.ErrAuthFailed), wantState: orchestrator.StateAuthFailed, wantNotes: []string{wantNote}},
		{name: "list auth failed", listErr: fmt.Errorf("list: %w", connector.ErrAuthFailed), wantState: orchestrator.StateAuthFailed, wantNotes: []string{wantNote}},
		{name: "fetch auth failed", fetchErr: fmt.Errorf("fetch: %w", connector.ErrAuthFailed), wantState: orchestrator.StateAuthFailed, wantNotes: []string{wantNote}},
		{name: "restored session rejected stays needs login", restored: true, loginErr: fmt.Errorf("probe: %w", connector.ErrAuthFailed), wantState: orchestrator.StateNeedsLogin, wantNotes: []string{"login required: run `facto login alpha`"}},
		{name: "needs login unchanged", loginErr: connector.ErrNeedsLogin, wantState: orchestrator.StateNeedsLogin, wantNotes: []string{"login required: run `facto login alpha`"}},
		{name: "broken has no note", loginErr: connector.ErrBroken, wantState: orchestrator.StateBroken},
		{name: "rate limited has no note", loginErr: connector.ErrRateLimited, wantState: orchestrator.StateRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := newFakeSessions(&events{}, true)
			if tt.restored {
				sessions.put("alpha", "synthetic-saved-blob-alpha")
			}
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
			alpha.loginErr, alpha.listErr = tt.loginErr, tt.listErr
			if tt.fetchErr != nil {
				alpha.fetchErr["a1"] = tt.fetchErr
			}
			bravo := newSessConn(r.ev, "bravo", nil, runRef("b1", 1))

			res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := byID(t, res, "alpha")
			if got.State != tt.wantState {
				t.Fatalf("alpha state = %q, want %q", got.State, tt.wantState)
			}
			if !slices.Equal(got.Notes, tt.wantNotes) {
				t.Fatalf("alpha notes = %q, want %q", got.Notes, tt.wantNotes)
			}
			if b := byID(t, res, "bravo"); b.State != orchestrator.StateOK || len(b.Notes) != 0 {
				t.Fatalf("bravo = %+v, want ok without notes", b)
			}
			if tt.wantState != orchestrator.StateAuthFailed {
				if hasNote(got, "facto config") {
					t.Fatalf("alpha notes = %q: only auth_failed names `facto config`", got.Notes)
				}
				return
			}
			rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
			rep.AddRun(res)
			js, jerr := rep.JSON()
			if jerr != nil {
				t.Fatalf("JSON: %v", jerr)
			}
			for name, out := range map[string]string{"report json": string(js), "report text": rep.Text()} {
				if !strings.Contains(out, "facto config alpha") {
					t.Fatalf("%s does not name `facto config alpha`:\n%s", name, out)
				}
				if strings.Contains(out, "facto login alpha") {
					t.Fatalf("%s names `facto login alpha` for auth_failed:\n%s", name, out)
				}
			}
		})
	}
}
