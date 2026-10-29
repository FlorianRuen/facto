// Package orchestrator runs the collection pipeline: it files downloaded or
// dropped documents (hash, dedup, naming, destination, index) and writes the
// run report. It only sees consumer-side interfaces: concrete connectors and
// destinations are wired by cmd/.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/store"
)

// Index is the document index the pipeline reads and writes
// (*store.Store implements it).
type Index interface {
	normalize.Index
	Insert(ctx context.Context, d store.Document) (store.Document, error)
}

// Destination is the part of dest.Destination the pipeline uses.
type Destination interface {
	Name() string
	Put(ctx context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error)
}

// Namer renders the normalized path (*normalize.Namer implements it).
type Namer interface {
	Render(d normalize.Doc) (normalize.Path, error)
}

// InboxSource is the manual-import source (*inbox.Inbox implements it).
type InboxSource interface {
	Scan(ctx context.Context) (inbox.Result, error)
	Open(ctx context.Context, it inbox.Item) (io.ReadCloser, error)
	Done(ctx context.Context, it inbox.Item) error
}

// DefaultMaxSize caps a document read by Ingest (== inbox.MaxFileSize).
const DefaultMaxSize = inbox.MaxFileSize

var (
	// ErrTooLarge reports a document over Deps.MaxSize.
	ErrTooLarge = errors.New("orchestrator: document too large")
	// ErrInvalidDeps reports a missing required dependency.
	ErrInvalidDeps = errors.New("orchestrator: invalid dependencies")
	// ErrInvalidDoc reports document metadata that cannot be named or
	// indexed.
	ErrInvalidDoc = errors.New("orchestrator: invalid document")
)

// Deps are the Orchestrator's dependencies.
type Deps struct {
	Index   Index        // required
	Dest    Destination  // required
	Namer   Namer        // required
	Log     *slog.Logger // nil = discard; New always wraps its handler in logx.NewHandler
	MaxSize int64        // <= 0 = DefaultMaxSize
	NewHTTP HTTPFactory  // client per connector; nil = httpx.New(allowed, httpx.Options{})
}

// Orchestrator files documents. It is safe for sequential use; the pipeline
// processes one document at a time.
type Orchestrator struct {
	idx     Index
	dst     Destination
	namer   Namer
	log     *slog.Logger
	maxSize int64
	newHTTP HTTPFactory
}

// New validates d and returns an Orchestrator. A missing Index, Dest or
// Namer wraps ErrInvalidDeps. The logger's handler is always wrapped in the
// redacting logx handler, whatever the caller passed.
func New(d Deps) (*Orchestrator, error) {
	switch {
	case d.Index == nil:
		return nil, fmt.Errorf("%w: no index", ErrInvalidDeps)
	case d.Dest == nil:
		return nil, fmt.Errorf("%w: no destination", ErrInvalidDeps)
	case d.Namer == nil:
		return nil, fmt.Errorf("%w: no namer", ErrInvalidDeps)
	}
	inner := slog.DiscardHandler
	if d.Log != nil {
		inner = d.Log.Handler()
	}
	maxSize := d.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	newHTTP := d.NewHTTP
	if newHTTP == nil {
		newHTTP = defaultHTTP
	}
	return &Orchestrator{
		newHTTP: newHTTP,
		idx:     d.Index,
		dst:     d.Dest,
		namer:   d.Namer,
		log:     slog.New(logx.NewHandler(inner, logx.Options{})),
		maxSize: maxSize,
	}, nil
}
