// Package dest defines where normalized documents are filed: the Destination
// contract shared by the local folder (internal/dest/local) and, later,
// Google Drive. Spec: docs/spec.md "Destinations: local folder and Google
// Drive".
package dest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// Destination stores normalized documents.
type Destination interface {
	// Name identifies the destination ("local", "gdrive"…).
	Name() string
	// Put stores r at doc.Path. It never replaces an existing document:
	// that is ErrExists.
	Put(ctx context.Context, doc NormalizedDoc, r io.Reader) (RemoteRef, error)
	// Exists reports whether a document is already stored at doc.Path.
	Exists(ctx context.Context, doc NormalizedDoc) (bool, error)
}

// NormalizedDoc is a document ready to be filed: its metadata and the
// relative path normalize.Namer rendered for it.
type NormalizedDoc struct {
	Doc  normalize.Doc
	Path normalize.Path
}

// RemoteRef identifies a stored copy. Destination is the Name() of the
// destination that stored it; ID is destination specific (local: the
// slash-separated path relative to the output folder, i.e. Path.Rel();
// Drive: the file id).
type RemoteRef struct {
	Destination string
	ID          string
}

var (
	// ErrInvalidPath reports a path ValidatePath refused.
	ErrInvalidPath = errors.New("dest: invalid path")
	// ErrExists reports that Put found something already at the path:
	// nothing was replaced.
	ErrExists = errors.New("dest: already exists")
)

// ValidatePath is the check every destination runs before touching storage
// (defense in depth: normalize.Namer already sanitizes). File must be
// non-empty and canonical (fsx.SafeName(File) == File, hence no separator,
// NUL, control or format character, leading/trailing dot or space, Windows
// reserved name, or more than fsx.MaxNameLen bytes). Dir is "" or
// slash-separated segments that are each non-empty and canonical. Any
// violation wraps ErrInvalidPath.
func ValidatePath(p normalize.Path) error {
	if err := validSegment(p.File); err != nil {
		return fmt.Errorf("%w: file: %w", ErrInvalidPath, err)
	}
	if p.Dir == "" {
		return nil
	}
	for seg := range strings.SplitSeq(p.Dir, "/") {
		if err := validSegment(seg); err != nil {
			return fmt.Errorf("%w: dir: %w", ErrInvalidPath, err)
		}
	}
	return nil
}

// errSegment is wrapped by validSegment; callers add ErrInvalidPath.
var errSegment = errors.New("not a canonical path component")

// validSegment accepts one non-empty path component equal to its SafeName.
// SafeName never returns "", "." or "..", and maps '/', '\\', NUL and
// controls to '_', so equality rules them all out.
func validSegment(s string) error {
	if s == "" || fsx.SafeName(s) != s {
		return fmt.Errorf("%w: %q", errSegment, s)
	}
	return nil
}
