package connector

import (
	"fmt"
	"regexp"
	"slices"
	"sync"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// maxIDLen caps Info.ID: it ends up in file names.
const maxIDLen = 40

var idRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Registry holds connectors by Info().ID. Safe for concurrent use. There is no
// package-level registry: cmd/facto builds one and injects it.
type Registry struct {
	mu    sync.RWMutex
	byID  map[string]Connector
	ids   []string    // sorted; ids[i] is the ID of order[i]
	order []Connector // sorted by ID
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Connector{}}
}

// Register validates c.Info() and adds c. A nil connector or an invalid Info
// wraps ErrInvalidInfo; an already registered ID wraps ErrDuplicateID. On
// error the registry is unchanged.
func (r *Registry) Register(c Connector) error {
	if c == nil {
		return fmt.Errorf("%w: nil connector", ErrInvalidInfo)
	}
	info := c.Info()
	if err := ValidateInfo(info); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[info.ID]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicateID, info.ID)
	}
	r.byID[info.ID] = c
	// Search the cached IDs: calling a connector's Info() while holding the
	// lock would run third-party code inside the critical section.
	i, _ := slices.BinarySearch(r.ids, info.ID)
	r.ids = slices.Insert(r.ids, i, info.ID)
	r.order = slices.Insert(r.order, i, c)
	return nil
}

// Get returns the connector registered under id.
func (r *Registry) Get(id string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	return c, ok
}

// All returns the connectors sorted by ID, in a new slice.
func (r *Registry) All() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.order)
}

// ValidateInfo checks a connector's metadata; failures wrap ErrInvalidInfo.
// ID: ^[a-z0-9]+(-[a-z0-9]+)*$ and at most 40 bytes. AllowedDomains: the
// syntax of httpx.ParseAllowlist (single source of truth: what registers is
// exactly what httpx can enforce). Kinds: every entry valid.
func ValidateInfo(info Info) error {
	if len(info.ID) > maxIDLen || !idRe.MatchString(info.ID) {
		return fmt.Errorf("%w: id %q", ErrInvalidInfo, info.ID)
	}
	if _, err := httpx.ParseAllowlist(info.AllowedDomains); err != nil {
		return fmt.Errorf("%w: %s: allowed domains: %w", ErrInvalidInfo, info.ID, err)
	}
	for _, k := range info.Kinds {
		if !k.valid() {
			return fmt.Errorf("%w: %s: %s", ErrInvalidInfo, info.ID, k)
		}
	}
	return nil
}
