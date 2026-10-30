// Package fakeprovider is the synthetic supplier used by unit tests and
// make e2e (docs/connectors/fakeprovider.md). It has no real site: its two
// hosts are served by httptest servers and by the e2e fake site.
//
// The package never imports net/http: every request goes through the
// *httpx.Client a Session carries (domain allowlist, TLS, sanitized errors).
// It compiles in every build, but its only registration entry point,
// Register, lives behind //go:build e2e so the release binary never carries
// it (plan J1 T17).
package fakeprovider

import (
	"regexp"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
)

// ID is the connector id.
const ID = "fakeprovider"

// The two hosts of the fake site, in Info().AllowedDomains order.
const (
	HostWWW = "www.fakeprovider.test" // API and PDFs
	HostSSO = "sso.fakeprovider.test" // SSO login pages
)

// Caps, applied when the matching Options field is zero (or negative).
const (
	DefaultMaxListBytes int64 = 1 << 20  // one list page body
	DefaultMaxItems           = 2000     // items across all pages
	DefaultMaxPages           = 50       // pages per List call
	DefaultMaxPDFBytes  int64 = 20 << 20 // one PDF body

	DefaultStepTimeout = 30 * time.Second // one automated browser step
	DefaultUserTimeout = 10 * time.Minute // the user completing a login by hand
)

// maxProbeBytes caps the /api/me body.
const maxProbeBytes int64 = 64 << 10

// Wire formats shared with the fake site.
var (
	idRe       = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,63}$`)
	contractRe = regexp.MustCompile(`^[A-Z0-9-]{1,32}$`)
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
	dateRe     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// Options tunes the caps and login timeouts; zero fields take the Default*
// values.
type Options struct {
	MaxListBytes int64
	MaxItems     int
	MaxPages     int
	MaxPDFBytes  int64
	// StepTimeout bounds each automated browser step (navigate, wait, type,
	// click, read the URL or the cookies): the browser polls until its
	// context ends.
	StepTimeout time.Duration
	// UserTimeout bounds the wait for a user completing the login by hand
	// in a visible browser (captcha).
	UserTimeout time.Duration
}

// Connector is the fakeprovider connector. Safe for concurrent use: it
// holds only immutable options.
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
	if opts.MaxPages <= 0 {
		opts.MaxPages = DefaultMaxPages
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

// allowedHosts returns the allowlist in a fresh slice.
func allowedHosts() []string {
	return []string{HostWWW, HostSSO}
}

// Info returns the connector metadata. Every call returns fresh slices, so
// a caller cannot widen the allowlist of later calls.
func (c *Connector) Info() connector.Info {
	return connector.Info{
		ID:             ID,
		Name:           "Fake Provider (test only)",
		Category:       "services",
		Kinds:          []connector.DocKind{connector.Invoice},
		AllowedDomains: allowedHosts(),
	}
}
