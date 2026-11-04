package cputime_test

import (
	"crypto/sha256"
	"runtime"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/cputime"
)

// Not parallel: outside Linux Of measures the whole process.

// spin hashes a buffer n times: work that only a CPU can do.
func spin(n int) {
	sum := sha256.Sum256(nil)
	for range n {
		sum = sha256.Sum256(sum[:])
	}
	runtime.KeepAlive(sum)
}

func TestOf_CountsWorkDone(t *testing.T) {
	small, err := cputime.Of(func() { spin(1 << 12) })
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	big, err := cputime.Of(func() { spin(1 << 21) })
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if big <= 0 {
		t.Fatalf("Of(2M hashes) = %v, want > 0", big)
	}
	if big <= small {
		t.Fatalf("Of(2M hashes) = %v, not above Of(4K hashes) = %v", big, small)
	}
}

// TestOf_WaitingIsNotCounted blocks f while other goroutines burn CPU (on
// Linux, where Of is per thread) and while nothing runs (elsewhere): the
// wait costs no CPU time, which is what makes Of immune to machine load.
func TestOf_WaitingIsNotCounted(t *testing.T) {
	release := make(chan struct{})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	if cputime.ThreadLocal {
		for range runtime.GOMAXPROCS(0) {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						spin(64)
					}
				}
			})
		}
	}
	go func() {
		// Burn a lot of CPU elsewhere (beside the burners on Linux) while
		// the waiter is blocked, then release it.
		spin(1 << 20)
		close(release)
	}()
	d, err := cputime.Of(func() { <-release })
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if !cputime.ThreadLocal {
		// Process-wide: the releaser's work is counted by design.
		if d < 0 {
			t.Fatalf("Of(blocked) = %v, want >= 0", d)
		}
		return
	}
	// The releaser alone burnt as much as this measured spin: the waiter
	// must show a small fraction of it.
	work, err := cputime.Of(func() { spin(1 << 20) })
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if d >= work/4 {
		t.Fatalf("Of(blocked) = %v, want well under the %v of the work done meanwhile elsewhere", d, work)
	}
}
