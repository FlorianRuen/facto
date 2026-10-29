// Tests for package clock (J0 task T1).
//
// Expected API (implementer: follow exactly):
//
//	// Clock is the only way business code reads the current time.
//	type Clock interface {
//		Now() time.Time
//	}
//
//	// Real reads the system clock and always returns UTC.
//	type Real struct{}
//	func (Real) Now() time.Time
//
//	// Fake is a manually driven clock for tests. Safe for concurrent use.
//	// Now always returns UTC, whatever the location of the time given to it.
//	type Fake struct{ /* unexported, mutex-protected */ }
//	func NewFake(t time.Time) *Fake
//	func (f *Fake) Now() time.Time
//	func (f *Fake) Set(t time.Time)
//	func (f *Fake) Advance(d time.Duration)
//
// internal/clock is exempt from the forbidigo time.Now rule, so these tests may
// call time.Now directly.
package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
)

// Compile-time proof that both implementations satisfy Clock.
var (
	_ clock.Clock = clock.Real{}
	_ clock.Clock = (*clock.Fake)(nil)
)

func TestFake_SetAndAdvance(t *testing.T) {
	t.Parallel()

	start := time.Date(2027, time.January, 15, 9, 30, 0, 0, time.UTC)
	paris := time.FixedZone("CET", 3600)

	tests := []struct {
		name string
		ops  func(f *clock.Fake)
		want time.Time
	}{
		{
			name: "initial value",
			ops:  func(*clock.Fake) {},
			want: start,
		},
		{
			name: "advance one hour",
			ops:  func(f *clock.Fake) { f.Advance(time.Hour) },
			want: start.Add(time.Hour),
		},
		{
			name: "advances accumulate",
			ops: func(f *clock.Fake) {
				f.Advance(24 * time.Hour)
				f.Advance(30 * time.Minute)
			},
			want: start.Add(24*time.Hour + 30*time.Minute),
		},
		{
			name: "advance crosses year boundary",
			ops:  func(f *clock.Fake) { f.Advance(-15 * 24 * time.Hour) },
			want: time.Date(2026, time.December, 31, 9, 30, 0, 0, time.UTC),
		},
		{
			name: "set replaces the time",
			ops: func(f *clock.Fake) {
				f.Advance(time.Hour)
				f.Set(time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC))
			},
			want: time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "advance after set starts from the set time",
			ops: func(f *clock.Fake) {
				f.Set(time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC))
				f.Advance(time.Minute)
			},
			want: time.Date(2030, time.June, 1, 0, 1, 0, 0, time.UTC),
		},
		{
			name: "set with a non-UTC location is normalized to UTC",
			ops: func(f *clock.Fake) {
				f.Set(time.Date(2030, time.June, 1, 1, 0, 0, 0, paris))
			},
			want: time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := clock.NewFake(start)
			tt.ops(f)
			got := f.Now()
			if !got.Equal(tt.want) {
				t.Fatalf("Now() = %v, want %v", got, tt.want)
			}
			if got.Location() != time.UTC {
				t.Fatalf("Now().Location() = %v, want UTC", got.Location())
			}
		})
	}
}

func TestFake_NewFakeNormalizesToUTC(t *testing.T) {
	t.Parallel()

	in := time.Date(2027, time.January, 15, 10, 30, 0, 0, time.FixedZone("CET", 3600))
	got := clock.NewFake(in).Now()
	if !got.Equal(in) {
		t.Fatalf("Now() = %v, want instant %v", got, in)
	}
	if got.Location() != time.UTC {
		t.Fatalf("Now().Location() = %v, want UTC", got.Location())
	}
}

func TestFake_NowIsStableWithoutAdvance(t *testing.T) {
	t.Parallel()

	start := time.Date(2027, time.January, 15, 9, 30, 0, 0, time.UTC)
	f := clock.NewFake(start)
	for range 3 {
		if got := f.Now(); !got.Equal(start) {
			t.Fatalf("Now() = %v, want %v (fake must not move on its own)", got, start)
		}
	}
}

// Run with -race: concurrent Now/Advance/Set must be data-race free.
func TestFake_ConcurrentUse(t *testing.T) {
	t.Parallel()

	start := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)

	const workers = 8
	const steps = 100
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range steps {
				f.Advance(time.Second)
				_ = f.Now()
			}
		})
	}
	wg.Wait()

	want := start.Add(workers * steps * time.Second)
	if got := f.Now(); !got.Equal(want) {
		t.Fatalf("Now() = %v, want %v (lost updates)", got, want)
	}
}

func TestReal_NowIsUTC(t *testing.T) {
	t.Parallel()

	var c clock.Clock = clock.Real{}

	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Location() != time.UTC {
		t.Fatalf("Real.Now().Location() = %v, want UTC", got.Location())
	}
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Fatalf("Real.Now() = %v, want between %v and %v", got, before, after)
	}
}
