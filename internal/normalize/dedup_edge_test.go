package normalize_test

import (
	"math"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize"
)

// TestDecide_VersionEdges: a stored version 0 still yields v2 (NewVersion is
// always >= 2), and an unincrementable version is an error, not a wrap-around.
func TestDecide_VersionEdges(t *testing.T) {
	t.Parallel()

	idx := &fakeIndex{latest: map[idKey]int{{"edf", "INV-0"}: 0, {"edf", "INV-MAX"}: math.MaxInt}}
	got, err := normalize.Decide(t.Context(), idx, "edf", docRef("INV-0"), pdfB)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if want := (normalize.Decision{Action: normalize.NewVersion, Version: 2}); got != want {
		t.Fatalf("Decide = %+v, want %+v", got, want)
	}

	got, err = normalize.Decide(t.Context(), idx, "edf", docRef("INV-MAX"), pdfB)
	if err == nil || got != (normalize.Decision{}) {
		t.Fatalf("Decide at MaxInt = %+v, %v; want zero Decision and an error", got, err)
	}
}
