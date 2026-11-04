package logx_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/cputime"
	"github.com/FlorianRuen/facto/internal/logx"
)

// Linearity of Clean is measured against a baseline taken in the same
// process, on the same thread, right next to the measurement, instead of an
// absolute CPU budget. The race detector, atomic coverage counters
// (-coverprofile with -race) and a loaded machine (shared cores and caches)
// inflate every per-byte loop of Clean by the same factor, up to 25 times
// seen in make verify, which an absolute budget had to guess; a ratio of two
// adjacent measurements cancels that factor out.
//
// Two checks, so that neither "quadratic on hostile input only" nor
// "quadratic on every input" can pass:
//
//   - Hostile ratio: for each unit, CPU(Clean(1 MB hostile line)) divided by
//     CPU(Clean(1 MB benign line)) must stay at most hostileRatioMax. A
//     linear Clean does a bounded amount of extra work per hostile byte
//     (measured: at most about 10 times the benign line, with or without
//     -race and coverage). A quadratic rescan does work proportional to the
//     length still ahead for each unit of n = 2^20 bytes: about n^2/(2L)
//     byte steps for a unit of L bytes, against about n for a linear pass,
//     so 2^19/L times more: over 500 000 times for the 1-byte-ish units,
//     still over 250 for the longest unit here (depthUnits, about 2 KB),
//     never under hostileRatioMax. The quadratic scan the J0 tests were
//     written for took 87 s per MB without the race detector, about 1 000
//     times a linear pass.
//   - Baseline growth: CPU(Clean(benign line of 4n)) divided by
//     CPU(Clean(benign line of n)) must stay at most growthRatioMax. Linear
//     gives 4, quadratic 16; growthRatioMax is their geometric mean, 8. Both
//     lines are larger than CPU caches, so the ratio is not skewed by a
//     small line fitting in cache (an n/8 line did skew it to 22 once).
//     This is what catches a regression that makes every line quadratic,
//     benign ones included, which the hostile ratio alone would not see.
//
// The hostile-ratio arithmetic assumes the rescan costs about as much per
// byte as Clean's own scan. A rescan through a vectorised strings.Index can
// be up to about 200 times cheaper per byte than Clean's per-byte loops
// (about 10 ns per byte), which still leaves 2^19/(200 L) over
// hostileRatioMax for every unit up to about 50 bytes, that is every unit
// but depthUnits; the J0 regression and the injected rescan used to check
// this test both fail it by far (see the commit adding these checks).
//
// A failed check is measured again, up to linearAttempts times, and the
// test fails only when every attempt fails: a quadratic Clean fails every
// attempt by orders of magnitude, a scheduling spike does not repeat.
const (
	linearSize      = 1 << 20
	hostileRatioMax = 50.0
	growthRatioMax  = 8.0
	linearAttempts  = 3
)

// benignUnit builds the baseline line: plain words and punctuation with no
// key, separator, quote, scheme or token shape, so Clean scans every byte
// and masks nothing.
const benignUnit = "lorem ipsum dolor sit amet, consectetur adipiscing elit. "

// assertCleanLinear checks that Clean stays linear on a 1 MB line made of
// each unit (see the checks above). Units run one after the other, never in
// parallel: outside Linux cputime counts the whole process, and on every
// platform parallel goroutines would contend for the same coverage counters
// and caches as the measurement. Callers are top-level tests without
// t.Parallel for the same reason. A wall-clock watchdog (cputime.Cap)
// still catches a hang that burns no CPU.
func assertCleanLinear(t *testing.T, units map[string]string) {
	t.Helper()
	benign := strings.Repeat(benignUnit, linearSize/len(benignUnit))
	benignLarge := strings.Repeat(benign, 4)

	var growth float64
	for range linearAttempts {
		small := cleanCPU(t, "benign line of n", benign)
		large := cleanCPU(t, "benign line of 4n", benignLarge)
		growth = ratio(large, small)
		t.Logf("baseline growth: Clean of a benign line took %v at n, %v at 4n: ratio %.1f (linear 4, quadratic 16, max %.0f)",
			small, large, growth, growthRatioMax)
		if growth <= growthRatioMax {
			break
		}
	}
	if growth > growthRatioMax {
		t.Errorf("baseline growth: Clean of a benign line grew %.1f times from n to 4n in each of %d attempts, max %.0f: want linear time (4)",
			growth, linearAttempts, growthRatioMax)
	}

	for name, unit := range units {
		in := strings.Repeat(unit, linearSize/len(unit))
		var r float64
		for range linearAttempts {
			base := cleanCPU(t, name+" baseline", benign)
			d := cleanCPU(t, name, in)
			r = ratio(d, base)
			t.Logf("%s: Clean of a 1 MB line took %v of CPU, benign baseline %v: ratio %.1f (max %.0f)",
				name, d, base, r, hostileRatioMax)
			if r <= hostileRatioMax {
				break
			}
		}
		if r > hostileRatioMax {
			t.Errorf("%s: Clean of a 1 MB line took %.1f times the CPU of a 1 MB benign line in each of %d attempts, max %.0f: want linear time",
				name, r, linearAttempts, hostileRatioMax)
		}
	}
}

// cleanCPU returns the CPU time of Clean(in), failing the test at once on a
// hang (wall-clock watchdog) or a measurement error.
func cleanCPU(t *testing.T, name, in string) time.Duration {
	t.Helper()
	wall := cputime.Cap(t)
	d, err := cputime.Within(wall, func() { _ = logx.Clean(in) })
	if errors.Is(err, cputime.ErrWallTimeout) {
		t.Fatalf("%s: Clean of a %d-byte line still running after %v of wall-clock time: hung", name, len(in), wall)
	}
	if err != nil {
		t.Fatalf("%s: measure CPU time: %v", name, err)
	}
	return d
}

// ratio returns a/b, with b floored at one microsecond so a baseline under
// the clock resolution cannot divide by zero.
func ratio(a, b time.Duration) float64 {
	return float64(a) / float64(max(b, time.Microsecond))
}
