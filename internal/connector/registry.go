package connector

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// maxIDLen caps Info.ID: it ends up in file names.
const maxIDLen = 40

var idRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Registry holds connectors by Info().ID. Safe for concurrent use. There is no
// package-level registry: cmd/facto builds one and injects it.
type Registry struct {
	mu    sync.RWMutex
	byID  map[string]Connector
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
	i, _ := slices.BinarySearchFunc(r.order, info.ID, func(e Connector, id string) int {
		return cmp.Compare(e.Info().ID, id)
	})
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
// ID: ^[a-z0-9]+(-[a-z0-9]+)*$ and at most 40 bytes. AllowedDomains: at least
// one; each a bare host or "*." followed by a host, without scheme, path,
// port, whitespace or other wildcard. Kinds: every entry valid.
func ValidateInfo(info Info) error {
	if len(info.ID) > maxIDLen || !idRe.MatchString(info.ID) {
		return fmt.Errorf("%w: id %q", ErrInvalidInfo, info.ID)
	}
	if len(info.AllowedDomains) == 0 {
		return fmt.Errorf("%w: %s: no allowed domain", ErrInvalidInfo, info.ID)
	}
	for _, d := range info.AllowedDomains {
		if !validDomain(d) {
			return fmt.Errorf("%w: %s: allowed domain %q", ErrInvalidInfo, info.ID, d)
		}
	}
	for _, k := range info.Kinds {
		if !k.valid() {
			return fmt.Errorf("%w: %s: %s", ErrInvalidInfo, info.ID, k)
		}
	}
	return nil
}

func validDomain(d string) bool {
	host := strings.TrimPrefix(d, "*.")
	if host == "" || strings.ContainsAny(host, "*/:@?#\\ \t\r\n\x00") {
		return false
	}
	return !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}
