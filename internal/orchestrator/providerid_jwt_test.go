// JWT-shaped ProviderIDs are refused; ids that only look a little like one
// are not. Everything is synthetic.
package orchestrator_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestRun_ProviderIDJWTShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		id     string
		refuse bool
	}{
		{"unsigned jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", true},
		{"signed jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlX3N5bnRo", true},
		{"jwt with dashes", "eyJhbGci-_9.eyJzd-_In0.ab-_cd", true},
		{"two segments", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0", false},
		{"four segments", "eyJh.eyJz.abc.def", false},
		{"no eyJ prefix", "abJhbGci.eyJzdWIi.c2ln", false},
		{"empty payload", "eyJhbGci..c2ln", false},
		{"non base64url byte", "eyJhbG+i.eyJzdWIi.c2ln", false},
		{"eyJ prefix, no dots", "eyJ2026000123", false},
		{"empty header", ".eyJzdWIi.c2ln", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRunRig(t, nil)
			alpha := newFakeConn(r.ev, "alpha", runRef(tt.id, 1))
			res, err := r.o.Run(t.Context(), connList{alpha}, period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := byID(t, res, "alpha")
			if len(got.Documents) != 1 {
				t.Fatalf("documents = %+v, want one", got.Documents)
			}
			want := orchestrator.StatusFiled
			if tt.refuse {
				want = orchestrator.StatusInvalid
			}
			if d := got.Documents[0]; d.Status != want {
				t.Fatalf("status = %q, want %q (%+v)", d.Status, want, d)
			}
		})
	}
}
