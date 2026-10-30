package logx_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/cputime"
	"github.com/FlorianRuen/facto/internal/logx"
)

// assertCleanLinear cleans a 1 MB line made of each unit and fails when one
// takes more than linearBudget of CPU time. CPU time (package cputime), not
// wall-clock time: a loaded machine cannot fail the budget, a quadratic
// scan still blows it by orders of magnitude.
func assertCleanLinear(t *testing.T, units map[string]string) {
	t.Helper()
	const size = 1 << 20
	for name, unit := range units {
		in := strings.Repeat(unit, size/len(unit))
		wall := cputime.Cap(t)
		d, err := cputime.Within(wall, func() { _ = logx.Clean(in) })
		if errors.Is(err, cputime.ErrWallTimeout) {
			t.Fatalf("%s: Clean of a 1 MB line still running after %v of wall-clock time: hung", name, wall)
		}
		if err != nil {
			t.Fatalf("%s: measure CPU time: %v", name, err)
		}
		t.Logf("%s: Clean of a 1 MB line took %v of CPU", name, d)
		if d > linearBudget() {
			t.Errorf("%s: Clean of a 1 MB line took %v of CPU, budget %v, want linear time", name, d, linearBudget())
		}
	}
}
