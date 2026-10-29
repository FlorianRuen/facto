package normalize

import (
	"context"
	"fmt"
	"math"

	"github.com/FlorianRuen/facto/internal/connector"
)

// Index is the part of the document index the dedup rules read.
type Index interface {
	// LatestVersion returns the highest version stored for
	// (provider, providerID); found is false when there is none.
	LatestVersion(ctx context.Context, provider, providerID string) (version int, found bool, err error)
	// HasSHA256 reports whether any indexed document (any provider) has this
	// content hash.
	HasSHA256(ctx context.Context, sum [32]byte) (bool, error)
}

// Action is what to do with a listed or downloaded document. The zero value
// is invalid.
type Action int

// Dedup actions.
const (
	_            Action = iota
	New                 // file it as version 1
	NewVersion          // same ProviderID, new content: file it as Decision.Version
	SkipKnownID         // rule 1: (provider, ProviderID) already indexed
	SkipSameHash        // rule 2: identical content already indexed
)

var actionNames = [...]string{
	New:          "new",
	NewVersion:   "new-version",
	SkipKnownID:  "skip-known-id",
	SkipSameHash: "skip-same-hash",
}

// String returns "new", "new-version", "skip-known-id", "skip-same-hash", or
// "Action(<n>)" for an invalid value.
func (a Action) String() string {
	if a <= 0 || int(a) >= len(actionNames) {
		return fmt.Sprintf("Action(%d)", int(a))
	}
	return actionNames[a]
}

// Decision is the outcome of the dedup rules.
type Decision struct {
	Action Action
	// Version is 1 for New, latest+1 (>= 2) for NewVersion, 0 for skips.
	Version int
}

var (
	decisionNew          = Decision{Action: New, Version: 1}
	decisionSkipKnownID  = Decision{Action: SkipKnownID}
	decisionSkipSameHash = Decision{Action: SkipSameHash}
)

// BeforeFetch applies dedup rule 1 from the listing alone: a (provider,
// ProviderID) already indexed is SkipKnownID, anything else is New ("fetch it,
// then call Decide"). An empty ProviderID identifies nothing and is always
// fetched without asking the index. Index errors are wrapped and come with a
// zero Decision.
func BeforeFetch(ctx context.Context, idx Index, provider string, ref connector.DocumentRef) (Decision, error) {
	if ref.ProviderID == "" {
		return decisionNew, nil
	}
	_, found, err := idx.LatestVersion(ctx, provider, ref.ProviderID)
	if err != nil {
		return Decision{}, fmt.Errorf("dedup: look up %s id: %w", provider, err)
	}
	if found {
		return decisionSkipKnownID, nil
	}
	return decisionNew, nil
}

// Decide applies dedup rules 2 then 3 to downloaded content: a SHA-256 already
// indexed under any provider is SkipSameHash (even for the same ProviderID);
// otherwise a known (provider, ProviderID) is NewVersion(latest+1), and
// anything else is New. An empty ProviderID never makes a version. Index
// errors are wrapped and come with a zero Decision, so a failure is never
// mistaken for "new" (duplicate) or "skip" (lost document).
func Decide(ctx context.Context, idx Index, provider string, ref connector.DocumentRef, sum [32]byte) (Decision, error) {
	dup, err := idx.HasSHA256(ctx, sum)
	if err != nil {
		return Decision{}, fmt.Errorf("dedup: look up hash: %w", err)
	}
	if dup {
		return decisionSkipSameHash, nil
	}
	if ref.ProviderID == "" {
		return decisionNew, nil
	}
	latest, found, err := idx.LatestVersion(ctx, provider, ref.ProviderID)
	if err != nil {
		return Decision{}, fmt.Errorf("dedup: look up %s id: %w", provider, err)
	}
	if !found {
		return decisionNew, nil
	}
	if latest >= math.MaxInt {
		return Decision{}, fmt.Errorf("dedup: %s version %d cannot be incremented", provider, latest)
	}
	return Decision{Action: NewVersion, Version: max(latest, 1) + 1}, nil
}
