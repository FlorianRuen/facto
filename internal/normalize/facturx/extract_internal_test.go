package facturx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The time bound turns a slow parse into ErrInvalidPDF, still wrapping the
// deadline error; a canceled caller context is reported as such.
func TestExtract_TimeBound(t *testing.T) {
	t.Parallel()

	pdf, err := os.ReadFile(filepath.Join("testdata", "minimal.pdf"))
	if err != nil {
		t.Fatalf("read minimal.pdf: %v", err)
	}
	inv, err := extract(t.Context(), pdf, 0)
	if !errors.Is(err, ErrInvalidPDF) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("extract(timeout 0): err = %v, want ErrInvalidPDF and DeadlineExceeded", err)
	}
	if inv != (Invoice{}) {
		t.Fatalf("extract returned data alongside %v: %+v", err, inv)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := extract(ctx, pdf, extractTimeout); !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalidPDF) {
		t.Fatalf("extract(canceled): err = %v, want context.Canceled only", err)
	}
}
