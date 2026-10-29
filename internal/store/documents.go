package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Document is one row of the documents table. Times are UTC.
type Document struct {
	Provider    string            // connector id or inbox provider slug, required
	ProviderID  string            // "" for documents without a supplier id (stored NULL)
	Kind        connector.DocKind // must be a valid kind
	IssuedAt    time.Time
	PeriodStart time.Time // zero = unknown, round-trips as zero
	PeriodEnd   time.Time // zero = unknown, round-trips as zero
	AmountCents *int64    // nil = unknown; nil and 0 are distinct
	Currency    string    // ISO 4217, "" allowed when AmountCents is nil
	SHA256      [32]byte  // content hash, must not be all zero
	LocalPath   string    // path under the output folder, "" if Drive only
	DriveID     string    // Drive file id, "" if local only
	CollectedAt time.Time // set by Insert from the clock; input ignored
	Version     int       // >= 1
}

// timeLayout stores instants as sortable UTC text with full precision.
const timeLayout = time.RFC3339Nano

const columns = `provider, provider_id, kind, issued_at, period_start, period_end,
	amount_cents, currency, sha256, local_path, drive_id, collected_at, version`

// Insert stores d with CollectedAt = clk.Now() and returns the stored
// document (times in UTC). Invalid input (empty Provider, Version < 1, invalid
// Kind, all-zero SHA256) wraps ErrInvalidDocument and stores nothing. An
// existing (Provider, ProviderID, Version) wraps ErrDuplicate and stores
// nothing. Documents with an empty ProviderID never collide.
func (s *Store) Insert(ctx context.Context, d Document) (Document, error) {
	if err := ctx.Err(); err != nil {
		return Document{}, fmt.Errorf("store insert: %w", err)
	}
	kind, err := validate(d)
	if err != nil {
		return Document{}, fmt.Errorf("store insert: %w", err)
	}
	d.IssuedAt = d.IssuedAt.UTC()
	d.PeriodStart = d.PeriodStart.UTC()
	d.PeriodEnd = d.PeriodEnd.UTC()
	d.CollectedAt = s.clk.Now().UTC()

	var amount any
	if d.AmountCents != nil {
		v := *d.AmountCents
		d.AmountCents = &v // do not alias the caller's value
		amount = v
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO documents (`+columns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Provider, nullString(d.ProviderID), kind,
		nullTime(d.IssuedAt), nullTime(d.PeriodStart), nullTime(d.PeriodEnd),
		amount, d.Currency, d.SHA256[:], d.LocalPath, d.DriveID,
		formatTime(d.CollectedAt), d.Version)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return Document{}, fmt.Errorf("store insert %s v%d: %w", d.Provider, d.Version, ErrDuplicate)
		}
		return Document{}, opErr(ctx, "insert", err)
	}
	return d, nil
}

// validate checks the invariants Insert enforces and returns the kind name.
func validate(d Document) (string, error) {
	kind, err := d.Kind.MarshalText()
	switch {
	case err != nil:
		return "", fmt.Errorf("%w: %w", ErrInvalidDocument, err)
	case d.Provider == "":
		return "", fmt.Errorf("%w: empty provider", ErrInvalidDocument)
	case d.Version < 1:
		return "", fmt.Errorf("%w: version %d < 1", ErrInvalidDocument, d.Version)
	case d.SHA256 == [32]byte{}:
		return "", fmt.Errorf("%w: zero sha256", ErrInvalidDocument)
	}
	return string(kind), nil
}

// FindByProviderID returns every version of (provider, providerID), ordered
// by Version ascending; an empty slice when none. An empty providerID matches
// nothing.
func (s *Store) FindByProviderID(ctx context.Context, provider, providerID string) ([]Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store find by provider id: %w", err)
	}
	docs := []Document{}
	if providerID == "" {
		return docs, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM documents
		WHERE provider = ? AND provider_id = ? ORDER BY version`, provider, providerID)
	if err != nil {
		return nil, opErr(ctx, "find by provider id", err)
	}
	defer func() { _ = rows.Close() }() // rows.Err below reports iteration errors
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, fmt.Errorf("store find by provider id: %w", err)
		}
		docs = append(docs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, opErr(ctx, "find by provider id", err)
	}
	return docs, nil
}

// FindBySHA256 returns the first stored document (insertion order) with this
// hash, whatever its provider; found is false when there is none.
func (s *Store) FindBySHA256(ctx context.Context, sum [32]byte) (doc Document, found bool, err error) {
	if err := ctx.Err(); err != nil {
		return Document{}, false, fmt.Errorf("store find by sha256: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM documents
		WHERE sha256 = ? ORDER BY id LIMIT 1`, sum[:])
	doc, err = scanDocument(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Document{}, false, nil
	case err != nil:
		return Document{}, false, opErr(ctx, "find by sha256", err)
	}
	return doc, true, nil
}

// LatestVersion returns the highest version stored for (provider,
// providerID); found is false when there is none or providerID is empty.
func (s *Store) LatestVersion(ctx context.Context, provider, providerID string) (version int, found bool, err error) {
	if err := ctx.Err(); err != nil {
		return 0, false, fmt.Errorf("store latest version: %w", err)
	}
	if providerID == "" {
		return 0, false, nil
	}
	var v sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM documents
		WHERE provider = ? AND provider_id = ?`, provider, providerID).Scan(&v)
	if err != nil {
		return 0, false, opErr(ctx, "latest version", err)
	}
	if !v.Valid {
		return 0, false, nil
	}
	return int(v.Int64), true, nil
}

// NextVersion returns 1 when (provider, providerID) is unknown or providerID
// is empty, latest+1 otherwise.
func (s *Store) NextVersion(ctx context.Context, provider, providerID string) (int, error) {
	v, _, err := s.LatestVersion(ctx, provider, providerID)
	if err != nil {
		return 0, err
	}
	return v + 1, nil
}

// HasSHA256 reports whether any stored document (any provider) has this
// content hash.
func (s *Store) HasSHA256(ctx context.Context, sum [32]byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("store has sha256: %w", err)
	}
	var has bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM documents WHERE sha256 = ?)`, sum[:]).Scan(&has)
	if err != nil {
		return false, opErr(ctx, "has sha256", err)
	}
	return has, nil
}

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanDocument decodes one row selected with columns.
func scanDocument(r rowScanner) (Document, error) {
	var (
		d                  Document
		providerID         sql.NullString
		kind               string
		issued, start, end sql.NullString
		amount             sql.NullInt64
		sum                []byte
		collected          string
	)
	if err := r.Scan(&d.Provider, &providerID, &kind, &issued, &start, &end,
		&amount, &d.Currency, &sum, &d.LocalPath, &d.DriveID, &collected, &d.Version); err != nil {
		return Document{}, fmt.Errorf("scan document: %w", err)
	}
	d.ProviderID = providerID.String
	k, err := connector.ParseDocKind(kind)
	if err != nil {
		return Document{}, fmt.Errorf("decode document: %w", err)
	}
	d.Kind = k
	if amount.Valid {
		v := amount.Int64
		d.AmountCents = &v
	}
	if len(sum) != len(d.SHA256) {
		return Document{}, fmt.Errorf("decode document: sha256 is %d bytes", len(sum))
	}
	copy(d.SHA256[:], sum)
	for _, t := range []struct {
		dst *time.Time
		src sql.NullString
	}{
		{&d.IssuedAt, issued},
		{&d.PeriodStart, start},
		{&d.PeriodEnd, end},
		{&d.CollectedAt, sql.NullString{String: collected, Valid: true}},
	} {
		if *t.dst, err = parseTime(t.src); err != nil {
			return Document{}, fmt.Errorf("decode document: %w", err)
		}
	}
	return d, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s sql.NullString) (time.Time, error) {
	if !s.Valid {
		return time.Time{}, nil
	}
	t, err := time.Parse(timeLayout, s.String)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time: %w", err)
	}
	return t.UTC(), nil
}
