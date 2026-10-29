package config_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestLoad_DefaultsGolden loads synthetic config files (copied to a 0600 file:
// a git checkout is 0644, which Load refuses) and pins the resulting config,
// defaults and "~" expansion included.
func TestLoad_DefaultsGolden(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"empty", "partial", "spec-example"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join("testdata", "TestLoad_DefaultsGolden")
			data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name+".yaml")))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			home := fakeHome(t)
			cfg, err := config.Load(t.Context(), writeConfig(t, data), opts(home))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			checkGolden(t, filepath.Join(dir, name+".golden"), []byte(flatten(cfg, home)))
		})
	}
}

// TestLoad_DefaultsMatchNormalize keeps the naming defaults in one place: the
// config defaults are normalize's.
func TestLoad_DefaultsMatchNormalize(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(t.Context(), writeConfig(t, nil), opts(fakeHome(t)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Naming.File != normalize.DefaultFileTemplate {
		t.Errorf("Naming.File = %q, want normalize.DefaultFileTemplate %q", cfg.Naming.File, normalize.DefaultFileTemplate)
	}
	if cfg.Naming.Dir != normalize.DefaultDirTemplate {
		t.Errorf("Naming.Dir = %q, want normalize.DefaultDirTemplate %q", cfg.Naming.Dir, normalize.DefaultDirTemplate)
	}
	if _, err := normalize.NewNamer(normalize.Config{File: cfg.Naming.File, Dir: cfg.Naming.Dir, Language: cfg.Naming.Language}); err != nil {
		t.Errorf("default naming does not compile: %v", err)
	}
}

// TestLoad_RejectsUnknownFields: a typo must be a configuration error (exit
// 2), never silently ignored (ADR 0003). The error names the bad key.
func TestLoad_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		yaml    string
		mention string // "" = only ErrInvalid is checked
	}{
		{"top level typo", "state_dri: ~/.facto\n", "state_dri"},
		{"unknown top level section", "telemetry:\n  enabled: true\n", "telemetry"},
		{"nested output typo", "output:\n  locl: ~/Invoices\n", "locl"},
		{"nested gdrive typo", "output:\n  gdrive:\n    enable: true\n", "enable"},
		{"connector field typo", "connectors:\n  edf:\n    pasword: keyring://facto/edf/password\n", "pasword"},
		{"connector unknown secret field", "connectors:\n  edf:\n    token: keyring://facto/edf/token\n", "token"},
		{"manual item typo", "manual:\n  - { id: impots, remind: \"10-01\" }\n", "remind"},
		{"duplicate key", "sessions: persistent\nsessions: ephemeral\n", "sessions"},
		{"second document is not ignored", "sessions: persistent\n---\nsessions: ephemeral\n", ""},
		{"top level is a list", "- sessions\n", ""},
		{"wrong type", "sessions: [persistent]\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(t.Context(), writeConfig(t, []byte(tt.yaml)), opts(fakeHome(t)))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			if cfg != nil {
				t.Errorf("Load() returned a config along with an error")
			}
			if tt.mention != "" {
				assertMentions(t, err, tt.mention)
			}
		})
	}
}

// TestLoad_ErrorsNeverEchoValues: a secret pasted in the wrong place must not
// be printed back, not even the few bytes yaml quotes in type errors.
func TestLoad_ErrorsNeverEchoValues(t *testing.T) {
	t.Parallel()
	c := testsecrets.Canary(t, testsecrets.Password)
	// Random bytes first, so that a truncated quote of the value would still
	// hit the random tail.
	v := c[strings.LastIndex(c, "-")+1:] + "x" + c
	tests := []struct {
		name string
		yaml string
	}{
		{"string into bool", "connectors:\n  edf:\n    enabled: " + v + "\n"},
		{"string into list", "manual: " + v + "\n"},
		{"string into mapping", "output: " + v + "\n"},
		{"unknown field holding a secret", "connectors:\n  edf:\n    pasword: " + v + "\n"},
		{"plaintext in secret field", "connectors:\n  edf:\n    password: " + v + "\n"},
		// A password starting with "*" or "!" parses as an alias or a tag;
		// yaml quotes the anchor name and prints the tag in its errors.
		{"alias to unknown anchor", "connectors:\n  edf:\n    password: *" + v + "\n"},
		{"custom tag on a non-string field", "connectors:\n  edf:\n    enabled: !" + v + " x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(t.Context(), writeConfig(t, []byte(tt.yaml)), opts(fakeHome(t)))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			assertNoEcho(t, err, v)
		})
	}
}

// TestLoad_SizeCap: config.yaml is small; a huge file (or a planted one) is
// refused before decoding.
func TestLoad_SizeCap(t *testing.T) {
	t.Parallel()
	comment := func(n int) []byte {
		b := []byte(strings.Repeat("#", n))
		b[n-1] = '\n'
		return b
	}
	t.Run("at cap", func(t *testing.T) {
		t.Parallel()
		if _, err := config.Load(t.Context(), writeConfig(t, comment(config.MaxFileSize)), opts(fakeHome(t))); err != nil {
			t.Fatalf("Load() at MaxFileSize error = %v, want nil", err)
		}
	})
	t.Run("over cap", func(t *testing.T) {
		t.Parallel()
		_, err := config.Load(t.Context(), writeConfig(t, comment(config.MaxFileSize+1)), opts(fakeHome(t)))
		if !errors.Is(err, config.ErrTooLarge) || !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("Load() error = %v, want ErrTooLarge and ErrInvalid", err)
		}
	})
}

func TestLoad_FileErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing file wraps fs.ErrNotExist", func(t *testing.T) {
		t.Parallel()
		_, err := config.Load(t.Context(), filepath.Join(t.TempDir(), "config.yaml"), opts(fakeHome(t)))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Load() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("directory is refused", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		r, err := fsx.Open(dir)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.MkdirPrivate("config.yaml"); err != nil {
			t.Fatalf("setup: %v", err)
		}
		_, err = config.Load(t.Context(), filepath.Join(dir, "config.yaml"), opts(fakeHome(t)))
		if !errors.Is(err, fsx.ErrNotRegular) {
			t.Fatalf("Load() error = %v, want fsx.ErrNotRegular", err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := config.Load(ctx, writeConfig(t, []byte("sessions: persistent\n")), opts(fakeHome(t)))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Load() error = %v, want context.Canceled", err)
		}
	})
}

// TestLoad_MatchesParse: Load is "read the file safely" + Parse.
func TestLoad_MatchesParse(t *testing.T) {
	t.Parallel()
	const yaml = "naming:\n  language: fr\nsessions: ephemeral\n"
	home := fakeHome(t)
	loaded, err := config.Load(t.Context(), writeConfig(t, []byte(yaml)), opts(home))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	parsed := mustParse(t, yaml, home)
	if got, want := flatten(loaded, home), flatten(parsed, home); got != want {
		t.Fatalf("Load and Parse disagree\n--- Load\n%s\n--- Parse\n%s", got, want)
	}
}
