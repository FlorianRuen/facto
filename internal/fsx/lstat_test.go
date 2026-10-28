// Tests for (*Root).Lstat, the read-only check the local destination uses
// for Exists (J0 task T21).
package fsx_test

import (
	"io/fs"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestLstat(t *testing.T) {
	t.Parallel()

	r, _ := openRoot(t)
	mustMkdir(t, r, "d")
	mustAtomic(t, r, "d/f.pdf")

	tests := []struct {
		name    string
		file    string
		regular bool
		want    error
	}{
		{name: "regular file", file: "d/f.pdf", regular: true},
		{name: "directory", file: "d"},
		{name: "missing", file: "d/missing.pdf", want: fs.ErrNotExist},
		{name: "escaping name", file: "../x", want: fsx.ErrInvalidName},
		{name: "empty name", file: "", want: fsx.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fi, err := r.Lstat(tt.file)
			checkErr(t, "Lstat", err, tt.want)
			if tt.want == nil && fi.Mode().IsRegular() != tt.regular {
				t.Fatalf("Lstat(%q) mode = %v, want regular=%v", tt.file, fi.Mode(), tt.regular)
			}
		})
	}
}
