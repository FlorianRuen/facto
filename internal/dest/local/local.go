// Package local is the local-folder destination: documents are filed under
// one output folder through internal/fsx (os.Root confinement, 0600 files,
// 0700 directories, atomic create that never replaces). Publishing uses a
// hard link, so the output folder must be on a filesystem that supports them
// (checked once by New).
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/fsx"
)

// name is the Destination name, also RemoteRef.Destination.
const name = "local"

// probeLink and writeNew are the fsx calls New and Put go through: method
// expressions in production, replaced by internal tests only.
var (
	probeLink = (*fsx.Root).ProbeLink
	writeNew  = (*fsx.Root).WriteNew
)

// Local files documents under one output folder. Safe for concurrent use.
type Local struct {
	root *fsx.Root
}

var _ dest.Destination = (*Local)(nil)

// New opens the existing output folder dir. It does not create it: a missing
// dir wraps fs.ErrNotExist. dir itself may be a symlink (e.g. to a folder
// synced by Google Drive for desktop); symlinks inside it never lead out.
// New checks once that dir supports hard links (fsx.Root.ProbeLink), which
// Put needs, leaving it as it was: a folder on FAT, exFAT or some network or
// FUSE mounts is refused with an error wrapping fsx.ErrLinkUnsupported.
func New(dir string) (*Local, error) {
	r, err := fsx.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("local destination: %w", err)
	}
	if err := probeLink(r, context.Background()); err != nil {
		return nil, errors.Join(fmt.Errorf("local destination: %w", err), r.Close())
	}
	return &Local{root: r}, nil
}

// Close releases the output folder; later Put and Exists calls fail.
func (l *Local) Close() error {
	if err := l.root.Close(); err != nil {
		return fmt.Errorf("local destination: %w", err)
	}
	return nil
}

// Name returns "local".
func (l *Local) Name() string { return name }

// Put validates doc.Path (dest.ErrInvalidPath, nothing touched), creates
// the missing directories of doc.Path.Dir (0700), then streams r to a temp
// file and publishes it under doc.Path.File atomically and without
// replacement: if anything is already at that name, even a dangling symlink,
// Put fails with dest.ErrExists and leaves it untouched, also when two Puts
// race. A filesystem without hard links fails with an error wrapping
// fsx.ErrLinkUnsupported. Reader and context errors are wrapped.
//
// One error comes with a RemoteRef: when the error wraps fsx.ErrNotDurable,
// the document WAS published at doc.Path and only the fsync of its directory
// failed, so Put returns the non-zero RemoteRef together with that error and
// the caller can record the document and retry durability later. On any
// other error no file is left at the name nor any temp file and the
// RemoteRef is zero.
func (l *Local) Put(ctx context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error) {
	if err := dest.ValidatePath(doc.Path); err != nil {
		return dest.RemoteRef{}, fmt.Errorf("local put: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return dest.RemoteRef{}, fmt.Errorf("local put: %w", err)
	}
	if doc.Path.Dir != "" {
		if err := l.root.MkdirPrivate(doc.Path.Dir); err != nil {
			return dest.RemoteRef{}, fmt.Errorf("local put: %w", err)
		}
	}
	rel := doc.Path.Rel()
	ref := dest.RemoteRef{Destination: name, ID: rel}
	if err := writeNew(l.root, ctx, rel, r); err != nil {
		switch {
		case errors.Is(err, fsx.ErrNotDurable):
			return ref, fmt.Errorf("local put: %w", err)
		case errors.Is(err, fs.ErrExist):
			return dest.RemoteRef{}, fmt.Errorf("local put: %w: %w", dest.ErrExists, err)
		}
		return dest.RemoteRef{}, fmt.Errorf("local put: %w", err)
	}
	return ref, nil
}

// Exists reports whether a regular file is at doc.Path. It validates the
// path (dest.ErrInvalidPath) and never follows a symlink: a symlink at the
// name is not a document, and a directory symlink leading out of the output
// folder is an error. A missing document is false, nil.
func (l *Local) Exists(ctx context.Context, doc dest.NormalizedDoc) (bool, error) {
	if err := dest.ValidatePath(doc.Path); err != nil {
		return false, fmt.Errorf("local exists: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("local exists: %w", err)
	}
	fi, err := l.root.Lstat(doc.Path.Rel())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("local exists: %w", err)
	}
	return fi.Mode().IsRegular(), nil
}
