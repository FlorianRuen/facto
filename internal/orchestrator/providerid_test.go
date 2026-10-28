// ProviderID validation in the connector loop and logx.Clean on report
// string fields (red-team finding J0 T30). Everything is synthetic.
package orchestrator_test

import (
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestRun_RefusesUnsafeProviderID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
	}{
		{"url", "https://billing.alpha.example/dl"},
		{"scheme-relative url", "x://y"},
		{"query", "dl?id=1"},
		{"key value", "token=abc"},
		{"space", "FA 0001"},
		{"tab", "FA\t0001"},
		{"newline", "FA\n0001"},
		{"nul", "FA\x000001"},
		{"bidi override", "FA\u202e0001"},
		{"non-breaking space", "FA\u00a00001"},
		{"invalid utf-8", "FA\xff0001"},
		{"replacement char", "FA\ufffd0001"},
		{"too long", strings.Repeat("a", 129)},
		{"token-like run", "SyntheticTokenAbCdEfGh1234"},
		{"jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef(tt.id, 1), runRef("a2", 2))
			res, err := r.o.Run(t.Context(), connList{alpha}, period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := byID(t, res, "alpha")
			if got.State != orchestrator.StateOK {
				t.Fatalf("state = %q, want ok (one bad ref fails only itself)", got.State)
			}
			want := orchestrator.DocResult{Source: "alpha", Provider: "alpha", Status: orchestrator.StatusInvalid}
			if len(got.Documents) != 2 || got.Documents[0] != want {
				t.Fatalf("documents = %+v, want first %+v", got.Documents, want)
			}
			if got.Documents[1].Status != orchestrator.StatusFiled {
				t.Fatalf("documents[1] = %+v, want a2 filed", got.Documents[1])
			}
			if f := alpha.fetchedList(); len(f) != 1 || f[0] != "a2" {
				t.Fatalf("fetched = %q, want only a2", f)
			}
			if puts := r.ev.withPrefix("put:"); len(puts) != 1 {
				t.Fatalf("puts = %q, want only a2", puts)
			}
			if tt.id != "" && strings.Contains(r.log.String(), tt.id) {
				t.Fatalf("refused id reached the log:\n%s", r.log.String())
			}
		})
	}
}

func TestRun_AcceptsPlainProviderID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"a1", "10234567", "FA-2026-0001", "avis_2026.01", "facture-ÉDF-12", strings.Repeat("a", 128)} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef(id, 1))
			res, err := r.o.Run(t.Context(), connList{alpha}, period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := byID(t, res, "alpha")
			if len(got.Documents) != 1 || got.Documents[0].Status != orchestrator.StatusFiled || got.Documents[0].ProviderID != id {
				t.Fatalf("documents = %+v, want %q filed", got.Documents, id)
			}
		})
	}
}

func TestReport_CleansSupplierStrings(t *testing.T) {
	t.Parallel()
	const tok = "SyntheticTokenAbCdEfGh1234"
	at := time.Date(2026, time.March, 20, 10, 0, 0, 0, time.UTC)
	r := orchestrator.Report{
		StartedAt: at, FinishedAt: at,
		Documents: []orchestrator.DocResult{
			{Source: "inbox", Origin: "scan-" + tok + ".pdf", Provider: "edf", ProviderID: "https://x.example/dl?k=" + tok, Status: orchestrator.StatusFailed},
			{Source: "edf", Provider: "edf", ProviderID: "ok-1", Status: orchestrator.StatusFiled, Version: 1, Path: "2026/energy/edf/" + tok + ".pdf"},
		},
		Warnings: []orchestrator.Warning{{Source: "inbox", Path: "big-" + tok + ".pdf", Reason: "too-large"}},
	}
	js, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	for name, out := range map[string]string{"json": string(js), "text": r.Text()} {
		if strings.Contains(out, tok) {
			t.Errorf("%s report carries the token:\n%s", name, out)
		}
		if !strings.Contains(out, "ok-1") {
			t.Errorf("%s report lost a plain provider id:\n%s", name, out)
		}
	}
}
