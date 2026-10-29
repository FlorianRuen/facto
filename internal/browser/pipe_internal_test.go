package browser

import (
	"bytes"
	"testing"
)

// TestAppendCapped_NeverOverCap: the frame buffer grows to the message, and
// never past MaxMessageBytes, whatever the chunk pattern (append alone
// could reserve ~25% more).
func TestAppendCapped_NeverOverCap(t *testing.T) {
	t.Parallel()
	chunk := bytes.Repeat([]byte{'a'}, readChunk)
	tests := []struct {
		name  string
		total int
	}{
		{name: "exactly the cap", total: MaxMessageBytes},
		{name: "cap minus one", total: MaxMessageBytes - 1},
		{name: "small", total: 3*readChunk + 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var acc []byte
			for len(acc) < tt.total {
				n := min(readChunk, tt.total-len(acc))
				acc = appendCapped(acc, chunk[:n])
				if cap(acc) > MaxMessageBytes {
					t.Fatalf("buffer capacity %d over the cap %d at length %d", cap(acc), MaxMessageBytes, len(acc))
				}
			}
			if len(acc) != tt.total {
				t.Errorf("length %d, want %d", len(acc), tt.total)
			}
		})
	}
}
