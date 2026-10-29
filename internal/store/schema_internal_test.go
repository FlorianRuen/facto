// Tests for a blocking review finding on package store (J0 follow-up):
// refuse a downgrade.
//
// Expected behaviour (implementer: follow exactly):
//
//		// ErrSchemaTooNew reports a database whose recorded schema version is
//		// higher than the newest embedded migration: it was written by a newer
//		// facto, and this binary must not read or write it.
//		var ErrSchemaTooNew = errors.New("store: database schema is newer than this binary")
//
//	  - Migrate returns an error wrapping ErrSchemaTooNew when
//	    MAX(schema_migrations.version) is greater than the newest embedded
//	    migration version. It changes nothing (no migration applied, no
//	    schema_migrations row added or removed) and leaves the store usable
//	    for Close.
//	  - Open, which runs Migrate, fails the same way (errors.Is
//	    ErrSchemaTooNew) and returns a nil *Store.
//	  - An equal version is not an error (Migrate stays idempotent).
package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
)

// bumpSchema records a schema version newer than any embedded migration,
// as a newer facto binary would have.
func bumpSchema(t *testing.T, s *Store, version int) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(),
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		version, "9999_from_the_future.sql", formatTime(time.Unix(0, 0))); err != nil {
		t.Fatalf("bump schema: %v", err)
	}
}

func schemaRows(t *testing.T, s *Store) (count, maxVersion int) {
	t.Helper()
	if err := s.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*), COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&count, &maxVersion); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	return count, maxVersion
}

func TestMigrate_RefusesNewerSchema(t *testing.T) {
	t.Parallel()
	migs, err := loadMigrations(migrationFiles, "migrations")
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	newest := migs[len(migs)-1].version

	tests := []struct {
		name    string
		version int
	}{
		{name: "one ahead", version: newest + 1},
		{name: "far ahead", version: newest + 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s, err := Open(ctx, filepath.Join(t.TempDir(), "state"), clock.NewFake(time.Unix(0, 0)))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			bumpSchema(t, s, tt.version)
			wantCount, wantMax := schemaRows(t, s)

			err = s.Migrate(ctx)
			if !errors.Is(err, ErrSchemaTooNew) {
				t.Fatalf("Migrate on schema %d (newest embedded %d) = %v, want ErrSchemaTooNew", tt.version, newest, err)
			}
			if gotCount, gotMax := schemaRows(t, s); gotCount != wantCount || gotMax != wantMax {
				t.Errorf("schema_migrations = (%d rows, max %d), want unchanged (%d, %d)", gotCount, gotMax, wantCount, wantMax)
			}
		})
	}
}

func TestOpen_RefusesNewerSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	clk := clock.NewFake(time.Unix(0, 0))
	s, err := Open(ctx, dir, clk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	bumpSchema(t, s, 9999)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(ctx, dir, clk)
	if s2 != nil {
		t.Cleanup(func() { _ = s2.Close() })
	}
	if !errors.Is(err, ErrSchemaTooNew) || s2 != nil {
		t.Fatalf("Open on a newer schema = (%v, %v), want (nil, ErrSchemaTooNew)", s2, err)
	}
}

func TestMigrate_SameVersionStillIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state"), clock.NewFake(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := range 2 {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate #%d: %v", i+1, err)
		}
	}
}
