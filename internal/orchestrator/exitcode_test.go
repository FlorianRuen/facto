// Tests for the run outcome in the report and the process exit code (J0 task
// T24, used by the CLI in T25). Spec: docs/spec.md "Configuration, commands
// and scheduling" (exit codes), "Connector states in the report"; ADR 0007
// D5 (collect with zero connectors exits 0).
//
// Expected API (implementer: follow exactly):
//
//	// ConnectorStatus is one connector line of the report.
//	type ConnectorStatus struct {
//		ID    string
//		State State
//	}
//
//	// Report gains one field (backward compatible):
//	//	Connectors []ConnectorStatus
//	// JSON adds "connectors": [{"id": ..., "state": ...}] only when
//	// non-empty (omitempty), so existing report goldens are unchanged.
//	// Text adds, only when non-empty, a block "\nconnectors:\n" with one
//	// "- <state> <id>\n" line per connector (escaped), before "documents:".
//
//	// AddRun appends one ConnectorStatus per res.Connectors entry, in
//	// order, and their Documents to r.Documents, after the existing ones.
//	func (r *Report) AddRun(res RunResult)
//
//	// ErrConfig marks a configuration error; the CLI wraps config loading
//	// and validation failures with it.
//	var ErrConfig = errors.New("orchestrator: configuration error")
//
//	const (
//		ExitOK        = 0 // no run error, every connector ok (or none)
//		ExitAttention = 1 // a connector is not ok, or the run failed
//		ExitConfig    = 2 // err wraps ErrConfig
//	)
//
//	// ExitCode: ExitConfig when errors.Is(err, ErrConfig); else
//	// ExitAttention when err != nil (canceled or failed run) or any
//	// connector state is not StateOK (needs_login, broken, auth_failed,
//	// rate_limited, or any unknown value: fail closed); else ExitOK.
//	// Document statuses and warnings never change the code: a connector is
//	// "ok" when it collected or found nothing new (spec), and per-document
//	// failures and inbox leftovers are reported, not exit-coded.
//	func ExitCode(r Report, err error) int
package orchestrator_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestExitCode_Values(t *testing.T) {
	t.Parallel()
	if orchestrator.ExitOK != 0 || orchestrator.ExitAttention != 1 || orchestrator.ExitConfig != 2 {
		t.Fatalf("exit codes = %d %d %d, want 0 1 2 (docs/spec.md)", orchestrator.ExitOK, orchestrator.ExitAttention, orchestrator.ExitConfig)
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()
	st := func(pairs ...string) []orchestrator.ConnectorStatus {
		var out []orchestrator.ConnectorStatus
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, orchestrator.ConnectorStatus{ID: pairs[i], State: orchestrator.State(pairs[i+1])})
		}
		return out
	}
	failedDoc := []orchestrator.DocResult{{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusFailed}}
	leftover := []orchestrator.Warning{{Source: "inbox", Path: "unknown.pdf", Reason: "unidentified"}}

	tests := []struct {
		name string
		rep  orchestrator.Report
		err  error
		want int
	}{
		{"zero connectors (ADR 0007 D5)", orchestrator.Report{}, nil, 0},
		{"zero connectors with inbox warnings", orchestrator.Report{Warnings: leftover}, nil, 0},
		{"all ok", orchestrator.Report{Connectors: st("alpha", "ok", "bravo", "ok")}, nil, 0},
		{"ok with a failed document", orchestrator.Report{Connectors: st("alpha", "ok"), Documents: failedDoc}, nil, 0},
		{"needs login", orchestrator.Report{Connectors: st("alpha", "ok", "bravo", "needs_login")}, nil, 1},
		{"broken", orchestrator.Report{Connectors: st("alpha", "broken")}, nil, 1},
		{"auth failed", orchestrator.Report{Connectors: st("alpha", "auth_failed", "bravo", "ok")}, nil, 1},
		{"rate limited", orchestrator.Report{Connectors: st("alpha", "rate_limited")}, nil, 1},
		{"unknown state fails closed", orchestrator.Report{Connectors: st("alpha", "weird")}, nil, 1},
		{"empty state fails closed", orchestrator.Report{Connectors: st("alpha", "")}, nil, 1},
		{"state differing in case fails closed", orchestrator.Report{Connectors: st("alpha", "OK")}, nil, 1},
		{"config error", orchestrator.Report{}, orchestrator.ErrConfig, 2},
		{"wrapped config error", orchestrator.Report{}, fmt.Errorf("load config: %w", orchestrator.ErrConfig), 2},
		{"config error wins over states", orchestrator.Report{Connectors: st("alpha", "needs_login")}, fmt.Errorf("validate: %w", orchestrator.ErrConfig), 2},
		{"canceled run", orchestrator.Report{Connectors: st("alpha", "ok")}, fmt.Errorf("run: %w", errors.New("context canceled")), 1},
		{"other run error", orchestrator.Report{}, errors.New("synthetic report write failure"), 1},
		{"config error text without wrapping", orchestrator.Report{}, errors.New(orchestrator.ErrConfig.Error()), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := orchestrator.ExitCode(tt.rep, tt.err); got != tt.want {
				t.Fatalf("ExitCode(%+v, %v) = %d, want %d", tt.rep.Connectors, tt.err, got, tt.want)
			}
		})
	}
}

// The run's states, through AddRun, drive the exit code end to end.
func TestExitCode_FromRun(t *testing.T) {
	t.Parallel()
	r := newRunRig(t, nil)
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	bravo := newFakeConn(r.ev, "bravo")
	res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var rep orchestrator.Report
	rep.AddRun(res)
	if got := orchestrator.ExitCode(rep, nil); got != 0 {
		t.Fatalf("ExitCode(all ok) = %d, want 0", got)
	}

	r2 := newRunRig(t, nil)
	alpha2 := newFakeConn(r2.ev, "alpha", runRef("a1", 1))
	bravo2 := newFakeConn(r2.ev, "bravo")
	bravo2.loginErr = fmt.Errorf("restore: %w", errors.Join(errors.New("synthetic"), connector.ErrNeedsLogin))
	res2, err := r2.o.Run(t.Context(), registry(t, alpha2, bravo2), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var rep2 orchestrator.Report
	rep2.AddRun(res2)
	if got := orchestrator.ExitCode(rep2, nil); got != 1 {
		t.Fatalf("ExitCode(bravo needs_login) = %d, want 1", got)
	}
}

func TestReport_AddRun(t *testing.T) {
	t.Parallel()
	inboxDoc := orchestrator.DocResult{Source: "inbox", Origin: "drop.pdf", Provider: "edf", Status: orchestrator.StatusFiled, Version: 1, Path: edfPath}
	a1 := orchestrator.DocResult{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusFiled, Version: 1, Path: "2026/energy/alpha/a1.pdf"}
	a2 := orchestrator.DocResult{Source: "alpha", Provider: "alpha", ProviderID: "a2", Status: orchestrator.StatusSkippedKnownID}
	c1 := orchestrator.DocResult{Source: "charlie", Provider: "charlie", ProviderID: "c1", Status: orchestrator.StatusFailed}

	rep := orchestrator.Report{Documents: []orchestrator.DocResult{inboxDoc}}
	rep.AddRun(orchestrator.RunResult{Connectors: []orchestrator.ConnectorResult{
		{ID: "alpha", State: orchestrator.StateOK, Documents: []orchestrator.DocResult{a1, a2}},
		{ID: "bravo", State: orchestrator.StateNeedsLogin},
	}})
	rep.AddRun(orchestrator.RunResult{Connectors: []orchestrator.ConnectorResult{
		{ID: "charlie", State: orchestrator.StateBroken, Documents: []orchestrator.DocResult{c1}},
	}})

	wantConn := []orchestrator.ConnectorStatus{
		{ID: "alpha", State: orchestrator.StateOK},
		{ID: "bravo", State: orchestrator.StateNeedsLogin},
		{ID: "charlie", State: orchestrator.StateBroken},
	}
	if !slices.Equal(rep.Connectors, wantConn) {
		t.Fatalf("Connectors = %+v, want %+v", rep.Connectors, wantConn)
	}
	if want := []orchestrator.DocResult{inboxDoc, a1, a2, c1}; !slices.Equal(rep.Documents, want) {
		t.Fatalf("Documents =\n%+v\nwant\n%+v", rep.Documents, want)
	}
}

func TestReport_RendersConnectors(t *testing.T) {
	t.Parallel()
	rep := orchestrator.Report{
		StartedAt:  time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, time.March, 20, 9, 1, 0, 0, time.UTC),
		Connectors: []orchestrator.ConnectorStatus{
			{ID: "alpha", State: orchestrator.StateOK},
			{ID: "bravo", State: orchestrator.StateNeedsLogin},
		},
		Documents: []orchestrator.DocResult{{Source: "alpha", Provider: "alpha", ProviderID: "a1", Status: orchestrator.StatusFiled, Version: 1, Path: "2026/energy/alpha/a1.pdf"}},
	}

	js, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got struct {
		ReportVersion int               `json:"report_version"`
		Connectors    []json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, js)
	}
	if got.ReportVersion != 1 {
		t.Fatalf("report_version = %d, want 1 (the change is additive)", got.ReportVersion)
	}
	wantJSON := []string{`{"id":"alpha","state":"ok"}`, `{"id":"bravo","state":"needs_login"}`}
	if len(got.Connectors) != len(wantJSON) {
		t.Fatalf("connectors = %s, want %q", js, wantJSON)
	}
	for i, raw := range got.Connectors {
		var compact strings.Builder
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("connector %d: %v", i, err)
		}
		b, _ := json.Marshal(v) // sorted keys: exactly id and state
		compact.Write(b)
		if compact.String() != wantJSON[i] {
			t.Fatalf("connectors[%d] = %s, want %s", i, compact.String(), wantJSON[i])
		}
	}

	text := rep.Text()
	block := "\nconnectors:\n- ok alpha\n- needs_login bravo\n"
	i := strings.Index(text, block)
	if i < 0 {
		t.Fatalf("text has no connectors block %q:\n%s", block, text)
	}
	if j := strings.Index(text, "\ndocuments:\n"); j >= 0 && j < i {
		t.Fatalf("connectors block after documents:\n%s", text)
	}
}

// Without connectors the rendering is exactly the pre-T24 one: the
// TestReport_Golden files stay valid.
func TestReport_NoConnectorsRendersAsBefore(t *testing.T) {
	t.Parallel()
	rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
	js, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := m["connectors"]; ok {
		t.Fatalf("empty report has a connectors key:\n%s", js)
	}
	if strings.Contains(rep.Text(), "connectors:") {
		t.Fatalf("empty report text has a connectors block:\n%s", rep.Text())
	}
}

func TestReport_ConnectorLineEscaped(t *testing.T) {
	t.Parallel()
	rep := orchestrator.Report{Connectors: []orchestrator.ConnectorStatus{
		{ID: "alpha\x1b[2J\nforged", State: orchestrator.State("ok\u202e")},
	}}
	text := rep.Text()
	if strings.ContainsAny(text, "\x1b\u202e") || strings.Contains(text, "\nforged") {
		t.Fatalf("unescaped control or format character in text:\n%q", text)
	}
}
