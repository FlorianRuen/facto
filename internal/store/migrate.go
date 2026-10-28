package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration is one embedded schema step, applied at most once.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads NNNN_<name>.sql files from dir in fsys, in order. The
// versions must be 1, 2, 3… with no gap.
func loadMigrations(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	migs := make([]migration, 0, len(entries))
	for _, e := range entries { // fs.ReadDir sorts by name
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v != len(migs)+1 {
			return nil, fmt.Errorf("migration %q: want version %d", e.Name(), len(migs)+1)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		migs = append(migs, migration{version: v, name: e.Name(), sql: string(b)})
	}
	return migs, nil
}

// Migrate applies the embedded migrations not yet applied, in one
// transaction. Idempotent.
func (s *Store) Migrate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store migrate: %w", err)
	}
	migs, err := loadMigrations(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("store migrate: %w", err)
	}
	if err := s.migrate(ctx, migs); err != nil {
		return opErr(ctx, "migrate", err)
	}
	return nil
}

func (s *Store) migrate(ctx context.Context, migs []migration) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // the step error is the one reported
		}
	}()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	var current sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, m := range migs {
		if int64(m.version) <= current.Int64 {
			continue
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("apply %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			m.version, m.name, formatTime(s.clk.Now())); err != nil {
			return fmt.Errorf("record %s: %w", m.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
