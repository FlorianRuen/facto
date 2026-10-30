package cputime_test

import (
	"errors"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/cputime"
)

func TestWithin_HangHitsTheWatchdog(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	_, err := cputime.Within(10*time.Millisecond, func() { <-release })
	if !errors.Is(err, cputime.ErrWallTimeout) {
		t.Fatalf("Within(blocked until the end of the test) err = %v, want ErrWallTimeout", err)
	}
}

func TestWithin_ReturnsBeforeTheWatchdog(t *testing.T) {
	d, err := cputime.Within(time.Hour, func() { spin(1 << 10) })
	if err != nil || d < 0 {
		t.Fatalf("Within = %v, %v; want a CPU time and no error", d, err)
	}
}

// noDeadline is a test without a deadline (go test -timeout 0).
type noDeadline struct{}

func (noDeadline) Deadline() (time.Time, bool) { return time.Time{}, false }

func TestCap_NoDeadlineIsMax(t *testing.T) {
	if got := cputime.Cap(noDeadline{}); got != cputime.MaxWatchdog {
		t.Fatalf("Cap(no deadline) = %v, want %v", got, cputime.MaxWatchdog)
	}
}

func TestCap_RealDeadlineIsBounded(t *testing.T) {
	if got := cputime.Cap(t); got <= 0 || got > cputime.MaxWatchdog {
		t.Fatalf("Cap(t) = %v, want in (0, %v]", got, cputime.MaxWatchdog)
	}
}

func TestCapLeft(t *testing.T) {
	tests := []struct {
		name       string
		left, want time.Duration
	}{
		{"far deadline", time.Hour, cputime.MaxWatchdog},
		{"near deadline", 10 * time.Second, 9 * time.Second},
		{"past deadline", -time.Second, time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cputime.CapLeft(tc.left); got != tc.want {
				t.Fatalf("CapLeft(%v) = %v, want %v", tc.left, got, tc.want)
			}
		})
	}
}
