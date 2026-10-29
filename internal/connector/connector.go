// Package connector defines the contract between the orchestrator and the
// supplier packages (connectors/<id>): the Connector interface, the documents
// it lists, the environment it receives, the sentinel errors the orchestrator
// branches on, and the Registry that holds connectors by ID. See docs/spec.md
// "Connector model".
package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Sentinels the orchestrator maps to a connector state (errors.Is).
var (
	// ErrNeedsLogin: the session expired and logging in needs the user
	// (2FA, captcha) while the run is non-interactive.
	ErrNeedsLogin = errors.New("connector: needs login")
	// ErrBroken: the site changed (selector or endpoint not found).
	ErrBroken = errors.New("connector: broken")
	// ErrAuthFailed: the supplier rejected the credentials.
	ErrAuthFailed = errors.New("connector: authentication failed")
	// ErrRateLimited: the supplier throttled the run.
	ErrRateLimited = errors.New("connector: rate limited")
)

// Registry and parsing errors.
var (
	// ErrDuplicateID: a connector with the same ID is already registered.
	ErrDuplicateID = errors.New("connector: duplicate id")
	// ErrInvalidInfo: nil connector or Info that fails validation.
	ErrInvalidInfo = errors.New("connector: invalid info")
	// ErrUnknownDocKind: a DocKind value or name outside the known set.
	ErrUnknownDocKind = errors.New("connector: unknown document kind")
)

// Connector is implemented by every supplier package. It only opens a
// session, lists documents and downloads them; naming, dedup, destinations
// and secrets belong to the core.
type Connector interface {
	// Info returns static metadata: id, name, document kinds, allowed domains.
	Info() Info
	// Login opens or restores a session. May require interaction (2FA, captcha).
	Login(ctx context.Context, env Env) (Session, error)
	// List lists the documents available for the period, without downloading them.
	List(ctx context.Context, s Session, p Period) ([]DocumentRef, error)
	// Fetch downloads one document. The core hashes it and decides whether it is new.
	Fetch(ctx context.Context, s Session, ref DocumentRef) (io.ReadCloser, error)
}

// Session is opaque connector state returned by Login. A session that also
// implements Persistable is saved encrypted by the orchestrator after a
// successful login; any other value is never saved.
type Session any

// Info is a connector's static metadata.
//
// TODO(T13): docs/spec.md lists "config fields" in a connector's static
// metadata; define them together with internal/config.
type Info struct {
	// ID matches ^[a-z0-9]+(-[a-z0-9]+)*$, at most 40 bytes. It is used in
	// paths (sessions/<id>.age).
	ID string
	// Name is the human name, e.g. "Fournisseur Exemple".
	Name string
	// Category is the default output category: housing, internet, services…
	Category string
	// Kinds lists the document kinds the connector can list.
	Kinds []DocKind
	// AllowedDomains is the httpx allowlist: exact host or "*.host".
	AllowedDomains []string
}

// DocumentRef describes one supplier document before it is downloaded.
type DocumentRef struct {
	ProviderID  string    // stable supplier-side id (invoice number when possible)
	Contract    string    // contract, line, dwelling
	Kind        DocKind   // Invoice, Receipt, RentReceipt, TaxNotice, Statement
	IssuedAt    time.Time // UTC
	PeriodStart time.Time // optional
	PeriodEnd   time.Time // optional
	AmountCents *int64    // optional, when the supplier provides it
	Currency    string    // ISO 4217
	MimeType    string
	Extra       map[string]string
}

// Env is what the core hands a connector for Login. HTTP is the hardened
// httpx client, never a bare *http.Client: net/http wraps errors in a
// *url.Error that carries the full URL, query included.
type Env struct {
	Secrets SecretResolver // resolves bw://, keyring://… references
	Browser BrowserPool    // headless or visible browser, login only
	HTTP    *httpx.Client  // allowlisted, errors never carry the URL query
	Prompt  Prompter       // asks the user for an OTP code
	Log     *slog.Logger   // redacting handler
	// Saved is the session blob a previous Persist returned, restored by the
	// orchestrator; zero (IsZero) when there is none.
	Saved secret.Secret
	// Credentials holds the configured secret references for this connector.
	Credentials Credentials
	// Interactive reports whether a user can answer prompts and see a
	// visible browser during this run. It is the single source of truth: the
	// core builds Prompt from the same value, so Prompt.Interactive() always
	// equals it. Connectors decide on Env.Interactive.
	Interactive bool
}

// Period is the half-open UTC interval [Start, End).
type Period struct {
	Start, End time.Time
}

// Year returns [Jan 1 n 00:00 UTC, Jan 1 n+1 00:00 UTC).
func Year(n int) Period {
	return Period{
		Start: time.Date(n, time.January, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(n+1, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
}

// PreviousYear returns the calendar year before c.Now(), in UTC.
func PreviousYear(c clock.Clock) Period {
	return Year(c.Now().UTC().Year() - 1)
}

// Contains reports whether Start <= t < End.
func (p Period) Contains(t time.Time) bool {
	return !t.Before(p.Start) && t.Before(p.End)
}

// DocKind is the kind of a supplier document. The zero value is invalid.
type DocKind int

// Document kinds.
const (
	_ DocKind = iota
	Invoice
	Receipt
	RentReceipt
	TaxNotice
	Statement
)

var docKindNames = [...]string{
	Invoice:     "invoice",
	Receipt:     "receipt",
	RentReceipt: "rent-receipt",
	TaxNotice:   "tax-notice",
	Statement:   "statement",
}

// valid reports whether k is one of the declared kinds.
func (k DocKind) valid() bool {
	return k > 0 && int(k) < len(docKindNames)
}

// String returns the lowercase name ("invoice", "rent-receipt"…). An invalid
// kind returns "DocKind(<n>)", which ParseDocKind refuses.
func (k DocKind) String() string {
	if !k.valid() {
		return fmt.Sprintf("DocKind(%d)", int(k))
	}
	return docKindNames[k]
}

// ParseDocKind is strict: exact lowercase String() forms only. Anything else
// wraps ErrUnknownDocKind.
func ParseDocKind(s string) (DocKind, error) {
	for k, name := range docKindNames {
		if k != 0 && name == s {
			return DocKind(k), nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownDocKind, s)
}

// MarshalText implements encoding.TextMarshaler. An invalid kind wraps
// ErrUnknownDocKind.
func (k DocKind) MarshalText() ([]byte, error) {
	if !k.valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownDocKind, int(k))
	}
	return []byte(docKindNames[k]), nil
}

// UnmarshalText implements encoding.TextUnmarshaler with ParseDocKind rules.
func (k *DocKind) UnmarshalText(b []byte) error {
	v, err := ParseDocKind(string(b))
	if err != nil {
		return err
	}
	*k = v
	return nil
}
