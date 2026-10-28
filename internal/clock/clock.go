// Package clock is the only way business code reads the current time. Inject a
// Clock (Real in production, Fake in tests) instead of calling time.Now.
package clock

import (
	"sync"
	"time"
)

// Clock is the only way business code reads the current time.
type Clock interface {
	Now() time.Time
}

// Real reads the system clock and always returns UTC.
type Real struct{}

// Now returns the current system time in UTC.
func (Real) Now() time.Time { return time.Now().UTC() }

// Fake is a manually driven clock for tests. Safe for concurrent use.
// Now always returns UTC, whatever the location of the time given to it.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake clock frozen at t (normalized to UTC).
func NewFake(t time.Time) *Fake {
	return &Fake{now: t.UTC()}
}

// Now returns the current fake time in UTC.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set replaces the current fake time with t (normalized to UTC).
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}

// Advance moves the fake time by d (which may be negative).
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
