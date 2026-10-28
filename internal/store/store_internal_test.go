package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/connector"
)

func TestLoadMigrations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		files   fstest.MapFS
		want    []int
		wantErr string
	}{
		{"ordered", fstest.MapFS{
			"m/0002_b.sql": {Data: []byte("B")},
			"m/0001_a.sql": {Data: []byte("A")},
		}, []int{1, 2}, ""},
		{"gap", fstest.MapFS{
			"m/0001_a.sql": {Data: []byte("A")},
			"m/0003_c.sql": {Data: []byte("C")},
		}, nil, "want version 2"},
		{"no underscore", fstest.MapFS{"m/0001.sql": {Data: []byte("A")}}, nil, "want version 1"},
		{"not a number", fstest.MapFS{"m/one_a.sql": {Data: []byte("A")}}, nil, "want version 1"},
		{"missing dir", fstest.MapFS{}, nil, "read migrations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			migs, err := loadMigrations(tt.files, "m")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadMigrations: %v", err)
			}
			if len(migs) != len(tt.want) {
				t.Fatalf("got %d migrations, want %d", len(migs), len(tt.want))
			}
			for i, v := range tt.want {
				if migs[i].version != v {
					t.Errorf("migration %d version = %d, want %d", i, migs[i].version, v)
				}
			}
		})
	}
}

func TestEmbeddedMigrationsLoad(t *testing.T) {
	t.Parallel()
	migs, err := loadMigrations(migrationFiles, "migrations")
	if err != nil || len(migs) == 0 {
		t.Fatalf("embedded migrations = (%d, %v), want at least one", len(migs), err)
	}
}

func TestMigrate_FailingStepRollsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state"), clock.NewFake(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	bad := []migration{
		{version: 2, name: "0002_ok.sql", sql: "CREATE TABLE extra (x INTEGER) STRICT"},
		{version: 3, name: "0003_bad.sql", sql: "THIS IS NOT SQL"},
	}
	if err := s.migrate(ctx, bad); err == nil || !strings.Contains(err.Error(), "0003_bad.sql") {
		t.Fatalf("migrate = %v, want an error naming 0003_bad.sql", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_schema WHERE name = 'extra'`).Scan(&n); err != nil {
		t.Fatalf("query schema: %v", err)
	}
	if n != 0 {
		t.Error("table from the failed migration batch was kept, want rollback")
	}
}

// TestScanDocument_CorruptRows proves a row that does not decode is an error,
// never a silently wrong document.
func TestScanDocument_CorruptRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, stmt string
	}{
		{"unknown kind", `UPDATE documents SET kind = 'bogus'`},
		{"bad issued_at", `UPDATE documents SET issued_at = 'yesterday'`},
		{"bad collected_at", `UPDATE documents SET collected_at = '2026-13-45'`},
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
			sum := sha256.Sum256([]byte(tt.name))
			d := Document{Provider: "edf", ProviderID: "x", Kind: connector.Invoice, SHA256: sum, Version: 1}
			if _, err := s.Insert(ctx, d); err != nil {
				t.Fatalf("Insert: %v", err)
			}
			if _, err := s.db.ExecContext(ctx, tt.stmt); err != nil {
				t.Fatalf("corrupt row: %v", err)
			}
			if _, err := s.FindByProviderID(ctx, "edf", "x"); err == nil {
				t.Error("FindByProviderID on a corrupt row: want error")
			}
			if _, _, err := s.FindBySHA256(ctx, sum); err == nil {
				t.Error("FindBySHA256 on a corrupt row: want error")
			}
		})
	}
}

func TestClose_Twice(t *testing.T) {
	t.Parallel()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "state"), clock.NewFake(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); !errors.Is(err, errClosed) {
		t.Errorf("second Close = %v, want errClosed", err)
	}
	if err := s.Migrate(context.Background()); err == nil {
		t.Error("Migrate after Close: want error")
	}
	if _, err := s.FindByProviderID(context.Background(), "edf", "x"); err == nil {
		t.Error("FindByProviderID after Close: want error")
	}
	if _, _, err := s.FindBySHA256(context.Background(), [32]byte{1}); err == nil {
		t.Error("FindBySHA256 after Close: want error")
	}
	if _, err := s.NextVersion(context.Background(), "edf", "x"); err == nil {
		t.Error("NextVersion after Close: want error")
	}
}

// TestOpen_PathWithURIMetacharacters proves the file: URI points SQLite at the
// pre-created file, not at a name truncated at '?' or '#'.
func TestOpen_PathWithURIMetacharacters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "st ate?x=1#%41")
	s, err := Open(ctx, dir, clock.NewFake(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var file string
	if err := s.db.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&file); err != nil {
		t.Fatalf("database_list: %v", err)
	}
	if want := filepath.Join(dir, FileName); file != want {
		t.Errorf("SQLite opened %q, want %q", file, want)
	}
}

func TestDSN_EscapesPath(t *testing.T) {
	t.Parallel()
	got := dsn("/tmp/a dir?x#y/" + FileName)
	if strings.Count(got, "?") != 1 || strings.Contains(got, "#") {
		t.Errorf("dsn = %q: path metacharacters not escaped", got)
	}
	if !strings.HasPrefix(got, "file:///tmp/a%20dir%3Fx%23y/index.db?") {
		t.Errorf("dsn = %q, want an escaped file: URI", got)
	}
}
