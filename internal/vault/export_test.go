package vault

import (
	"context"
	"io"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// WithInstallIDWrite replaces the fsx WriteNew call that creates install-id
// (tests only: race, durability and hard-link failures).
func WithInstallIDWrite(o Options, fn func(ctx context.Context, state *fsx.Root, name string, src io.Reader) error) Options {
	o.writeNew = fn
	return o
}

// WithInstallIDOpen replaces the fsx OpenRegular call that reads install-id
// (tests only: I/O errors).
func WithInstallIDOpen(o Options, fn func(state *fsx.Root, name string) (io.ReadCloser, error)) Options {
	o.openInstallID = fn
	return o
}
