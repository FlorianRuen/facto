// Tests for package dest (J0 task T21): the Destination contract shared by
// internal/dest/local (J0) and internal/dest/gdrive (later). Spec: docs/spec.md
// "Destinations: local folder and Google Drive" (interface reproduced
// verbatim) and "Threat model" (path traversal).
//
// Expected API (implementer: follow exactly):
//
//	type Destination interface {
//	    Name() string
//	    Put(ctx context.Context, doc NormalizedDoc, r io.Reader) (RemoteRef, error)
//	    Exists(ctx context.Context, doc NormalizedDoc) (bool, error)
//	}
//
//	// NormalizedDoc is a document ready to be filed: its metadata and the
//	// relative path normalize.Namer rendered for it.
//	type NormalizedDoc struct {
//	    Doc  normalize.Doc
//	    Path normalize.Path // Dir (slash-separated, may be "") + File
//	}
//
//	// RemoteRef identifies a stored copy. Destination is the Name() of the
//	// destination that stored it; ID is destination specific (local: the
//	// slash-separated path relative to the output folder, i.e. Path.Rel();
//	// Drive: the file id).
//	type RemoteRef struct {
//	    Destination string
//	    ID          string
//	}
//
//	var (
//	    ErrInvalidPath error // ValidatePath refused the path
//	    ErrExists      error // Put found something already at the path: nothing was replaced
//	)
//
//	// ValidatePath is the check every destination runs before touching
//	// storage (defense in depth: Namer already sanitizes). File must be
//	// non-empty and canonical (fsx.SafeName(File) == File), hence no '/',
//	// '\\', NUL, control characters, leading/trailing dots or spaces,
//	// Windows reserved names, or more than fsx.MaxNameLen bytes. Dir is ""
//	// or slash-separated segments that are each non-empty and canonical
//	// (no leading '/', no "", "." or ".." segment, no trailing '/'). Any
//	// violation wraps ErrInvalidPath.
//	func ValidatePath(p normalize.Path) error
package dest_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// memDest is a minimal in-memory destination: it proves the interface shape
// matches the spec.
type memDest struct{ files map[string][]byte }

var _ dest.Destination = (*memDest)(nil)

func (m *memDest) Name() string { return "mem" }

func (m *memDest) Put(_ context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error) {
	if err := dest.ValidatePath(doc.Path); err != nil {
		return dest.RemoteRef{}, err
	}
	if _, ok := m.files[doc.Path.Rel()]; ok {
		return dest.RemoteRef{}, dest.ErrExists
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return dest.RemoteRef{}, err
	}
	m.files[doc.Path.Rel()] = b
	return dest.RemoteRef{Destination: m.Name(), ID: doc.Path.Rel()}, nil
}

func (m *memDest) Exists(_ context.Context, doc dest.NormalizedDoc) (bool, error) {
	_, ok := m.files[doc.Path.Rel()]
	return ok, nil
}

func TestDestination_ContractShape(t *testing.T) {
	t.Parallel()

	var d dest.Destination = &memDest{files: map[string][]byte{}}
	doc := dest.NormalizedDoc{
		Doc:  normalize.Doc{Provider: "fournisseur-exemple", Category: "housing"},
		Path: normalize.Path{Dir: "2026/housing/fournisseur-exemple", File: "2026-03-14_fournisseur-exemple_invoice.pdf"},
	}
	ref, err := d.Put(t.Context(), doc, strings.NewReader("%PDF-1.7 synthetic"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ref != (dest.RemoteRef{Destination: "mem", ID: "2026/housing/fournisseur-exemple/2026-03-14_fournisseur-exemple_invoice.pdf"}) {
		t.Fatalf("Put ref = %+v", ref)
	}
	if ok, err := d.Exists(t.Context(), doc); err != nil || !ok {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	if _, err := d.Put(t.Context(), doc, strings.NewReader("other")); !errors.Is(err, dest.ErrExists) {
		t.Fatalf("second Put: err = %v, want ErrExists", err)
	}
}

func TestSentinels_Distinct(t *testing.T) {
	t.Parallel()

	if dest.ErrInvalidPath == nil || dest.ErrExists == nil {
		t.Fatal("nil sentinel")
	}
	if errors.Is(dest.ErrInvalidPath, dest.ErrExists) || errors.Is(dest.ErrExists, dest.ErrInvalidPath) {
		t.Fatal("ErrInvalidPath and ErrExists are not distinct")
	}
}

func TestValidatePath(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", fsx.MaxNameLen) + ".pdf"
	tests := []struct {
		name    string
		path    normalize.Path
		wantErr bool
	}{
		{name: "default layout", path: normalize.Path{Dir: "2026/housing/edf", File: "2026-03-14_edf_invoice_84.12EUR.pdf"}},
		{name: "versioned file", path: normalize.Path{Dir: "2026/housing/edf", File: "2026-03-14_edf_invoice_v2.pdf"}},
		{name: "empty dir", path: normalize.Path{File: "2026-03-14_edf_invoice.pdf"}},
		{name: "single dir", path: normalize.Path{Dir: "2026", File: "x.pdf"}},
		{name: "accents kept", path: normalize.Path{Dir: "2026/logement/électricité", File: "facture.pdf"}},

		{name: "empty file", path: normalize.Path{Dir: "2026"}, wantErr: true},
		{name: "dot file", path: normalize.Path{Dir: "2026", File: "."}, wantErr: true},
		{name: "dotdot file", path: normalize.Path{Dir: "2026", File: ".."}, wantErr: true},
		{name: "file with slash", path: normalize.Path{Dir: "2026", File: "edf/x.pdf"}, wantErr: true},
		{name: "file traversal", path: normalize.Path{Dir: "2026", File: "../../x.pdf"}, wantErr: true},
		{name: "file with backslash", path: normalize.Path{Dir: "2026", File: `..\x.pdf`}, wantErr: true},
		{name: "file with NUL", path: normalize.Path{Dir: "2026", File: "x\x00.pdf"}, wantErr: true},
		{name: "file with newline", path: normalize.Path{Dir: "2026", File: "x\n.pdf"}, wantErr: true},
		{name: "hidden file", path: normalize.Path{Dir: "2026", File: ".x.pdf"}, wantErr: true},
		{name: "trailing dot", path: normalize.Path{Dir: "2026", File: "x.pdf."}, wantErr: true},
		{name: "windows reserved", path: normalize.Path{Dir: "2026", File: "CON.pdf"}, wantErr: true},
		{name: "windows forbidden char", path: normalize.Path{Dir: "2026", File: "a:b.pdf"}, wantErr: true},
		{name: "bidi override", path: normalize.Path{Dir: "2026", File: "x\u202efdp.exe"}, wantErr: true},
		{name: "overlong file", path: normalize.Path{Dir: "2026", File: long}, wantErr: true},
		{name: "absolute dir", path: normalize.Path{Dir: "/etc", File: "x.pdf"}, wantErr: true},
		{name: "dir traversal", path: normalize.Path{Dir: "../outside", File: "x.pdf"}, wantErr: true},
		{name: "inner traversal", path: normalize.Path{Dir: "2026/../../outside", File: "x.pdf"}, wantErr: true},
		{name: "dot segment", path: normalize.Path{Dir: "./2026", File: "x.pdf"}, wantErr: true},
		{name: "empty segment", path: normalize.Path{Dir: "2026//edf", File: "x.pdf"}, wantErr: true},
		{name: "trailing slash", path: normalize.Path{Dir: "2026/", File: "x.pdf"}, wantErr: true},
		{name: "dir with backslash", path: normalize.Path{Dir: `2026\..\..`, File: "x.pdf"}, wantErr: true},
		{name: "windows drive", path: normalize.Path{Dir: "C:", File: "x.pdf"}, wantErr: true},
		{name: "dir with NUL", path: normalize.Path{Dir: "2026\x00", File: "x.pdf"}, wantErr: true},
		{name: "hidden dir", path: normalize.Path{Dir: "2026/.facto", File: "x.pdf"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := dest.ValidatePath(tt.path)
			if tt.wantErr {
				if !errors.Is(err, dest.ErrInvalidPath) {
					t.Fatalf("ValidatePath(%+v): err = %v, want ErrInvalidPath", tt.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidatePath(%+v): %v", tt.path, err)
			}
		})
	}
}
