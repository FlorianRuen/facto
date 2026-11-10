// Package wecasa collects the invoices of Wecasa household services
// (docs/connectors/wecasa.md): one PDF per delivered order.
//
// Login goes through the hardened browser (Cloudflare checks and a Rails
// CSRF field rule out a direct POST). The browser cookies of www.wecasa.fr
// are then exported into the httpx jar, and the API bearer token is read
// over HTTPS from the inline window.wecasa block of the bookings page;
// every /api/v1/ call sends it. The token is a secret.Secret from the
// moment it is parsed and the page body is never kept nor logged.
//
// The package never imports net/http: every request goes through the
// *httpx.Client the Session carries (domain allowlist, TLS, sanitized
// errors).
package wecasa

import (
	"fmt"
	"regexp"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
)

// ID is the connector id.
const ID = "wecasa"

// Host is the only host the connector contacts.
const Host = "www.wecasa.fr"

// staticPrefix is where the customer-area React bundle lives (login
// browser only, GET only).
const staticPrefix = "https://storage.googleapis.com/wecasa-react-prod/"

// Caps from the connector sheet, applied when the matching Options field
// is zero (or negative).
const (
	DefaultMaxListBytes int64 = 2 << 20  // one JSON answer of List
	DefaultMaxItems           = 2000     // items of the delivered list
	DefaultMaxPDFBytes  int64 = 20 << 20 // one PDF body

	DefaultStepTimeout = 30 * time.Second // one automated browser step
	DefaultUserTimeout = 10 * time.Minute // the user completing a login by hand
)

// Fixed caps.
const (
	maxProbeBytes int64 = 64 << 10 // GET /api/v1/user
	maxPageBytes  int64 = 1 << 20  // the bookings page holding the token
	maxAbsCents         = 100_000_000
)

var (
	// idRe is the order public_id, the stable document id.
	idRe       = regexp.MustCompile(`^[A-Za-z0-9]{8,32}$`)
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
)

// Options tunes the caps and login timeouts; zero fields take the Default*
// values.
type Options struct {
	MaxListBytes int64
	MaxItems     int
	MaxPDFBytes  int64
	// StepTimeout bounds each automated browser step.
	StepTimeout time.Duration
	// UserTimeout bounds the wait for a user completing the login by hand
	// in a visible browser.
	UserTimeout time.Duration
}

// Connector is the Wecasa connector. Safe for concurrent use: it holds
// only immutable options.
type Connector struct {
	opts Options
}

// New returns a connector with opts, zero fields replaced by the defaults.
func New(opts Options) *Connector {
	if opts.MaxListBytes <= 0 {
		opts.MaxListBytes = DefaultMaxListBytes
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = DefaultMaxItems
	}
	if opts.MaxPDFBytes <= 0 {
		opts.MaxPDFBytes = DefaultMaxPDFBytes
	}
	if opts.StepTimeout <= 0 {
		opts.StepTimeout = DefaultStepTimeout
	}
	if opts.UserTimeout <= 0 {
		opts.UserTimeout = DefaultUserTimeout
	}
	return &Connector{opts: opts}
}

// Register adds the connector, with default options, to r. There is no
// package-level registry, hence a function and not init(): cmd/facto calls
// it when it builds the registry of shipped connectors.
func Register(r *connector.Registry) error {
	if err := r.Register(New(Options{})); err != nil {
		return fmt.Errorf("wecasa: register: %w", err)
	}
	return nil
}

// Info returns the connector metadata. Every call returns fresh slices, so
// a caller cannot widen the allowlist of later calls.
func (c *Connector) Info() connector.Info {
	return connector.Info{
		ID:             ID,
		Name:           "Wecasa",
		Category:       "services",
		Kinds:          []connector.DocKind{connector.Invoice},
		AllowedDomains: []string{Host},
		BrowserStatic:  []string{staticPrefix},
	}
}
