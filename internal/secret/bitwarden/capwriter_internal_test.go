package bitwarden

import (
	"errors"
	"testing"
)

func TestCapWriterRefusesHugeWrite(t *testing.T) {
	t.Parallel()
	w := &capWriter{}
	if _, err := w.Write(make([]byte, MaxOutput+1)); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Write(MaxOutput+1) = %v, want ErrOutputTooLarge", err)
	}
	if len(w.buf) != 0 || cap(w.buf) > MaxOutput {
		t.Errorf("buffer len=%d cap=%d after refusal, want empty and <= MaxOutput", len(w.buf), cap(w.buf))
	}
	w = &capWriter{}
	if _, err := w.Write(make([]byte, MaxOutput-1)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 2)); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("overflowing second write = %v, want ErrOutputTooLarge", err)
	}
	if cap(w.buf) > MaxOutput {
		t.Errorf("cap %d > MaxOutput", cap(w.buf))
	}
}
