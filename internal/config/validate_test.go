package config_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestValidate_RejectsPlaintextSecret: secret fields only hold references
// (docs/spec.md "Password managers"), checked with secret.ParseRef. The
// error names the field and never echoes the value.
func TestValidate_RejectsPlaintextSecret(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	tests := []struct {
		name  string
		field string // login, password or otp
		value string
		ok    bool
	}{
		{"bitwarden username ref", "login", "bw://" + testUUID + "/username", true},
		{"bitwarden password ref", "password", "bw://" + testUUID + "/password", true},
		{"bitwarden totp ref", "otp", "bw://" + testUUID + "/totp", true},
		{"keyring ref", "password", "keyring://facto/edf/password", true},
		{"empty means not used", "otp", "", true},
		{"plaintext password", "password", canary, false},
		{"plaintext login", "login", canary, false},
		{"plaintext otp seed", "otp", canary, false},
		{"bitwarden item name instead of uuid", "password", "bw://edf-account/username", false},
		{"bitwarden unknown field", "password", "bw://" + testUUID + "/notes", false},
		{"unknown scheme", "password", "vault://facto/edf/secret", false},
		{"url is not a ref", "password", "https://vault.example.invalid/edf", false},
		{"empty keyring ref", "password", "keyring://", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := "connectors:\n  edf:\n    enabled: true\n    category: housing\n    " + tt.field + ": '" + tt.value + "'\n"
			cfg, err := config.Parse([]byte(yaml), opts(fakeHome(t)))
			if tt.ok {
				if err != nil {
					t.Fatalf("Parse() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, config.ErrPlaintextSecret) || !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrPlaintextSecret and ErrInvalid", err)
			}
			if cfg != nil {
				t.Errorf("Parse() returned a config along with an error")
			}
			assertMentions(t, err, "connectors.edf."+tt.field)
			assertNoEcho(t, err, tt.value)
		})
	}
}

// TestValidate_RejectsPlaintextSecretInDisabledConnector: a disabled
// connector still must not keep a password in config.yaml.
func TestValidate_RejectsPlaintextSecretInDisabledConnector(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	err := parseErr(t, "connectors:\n  wecasa:\n    enabled: false\n    password: '"+canary+"'\n", fakeHome(t))
	if !errors.Is(err, config.ErrPlaintextSecret) {
		t.Fatalf("Parse() error = %v, want ErrPlaintextSecret", err)
	}
	assertNoEcho(t, err, canary)
}

// TestValidate_StateDirInsideOutputRefused: the state dir (index, sessions,
// logs) must never be inside the output folder (ADR 0007 D1).
func TestValidate_StateDirInsideOutputRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		output string
		state  string
		ok     bool
	}{
		{"defaults", "", "", true},
		{"sibling with common prefix", "~/Invoices", "~/Invoices-state", true},
		{"output inside home, state in home", "~/Documents/Invoices", "~/.facto", true},
		{"state equals output", "~/Invoices", "~/Invoices", false},
		{"state directly inside output", "~/Invoices", "~/Invoices/.facto", false},
		{"state deep inside output", "~/Invoices", "~/Invoices/2026/housing/.facto", false},
		{"state inside output after cleaning", "~/Invoices", "~/Other/../Invoices/.facto", false},
		{"trailing slashes", "~/Invoices/", "~/Invoices/.facto/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := ""
			if tt.output != "" {
				yaml += "output:\n  local: '" + tt.output + "'\n"
			}
			if tt.state != "" {
				yaml += "state_dir: '" + tt.state + "'\n"
			}
			cfg, err := config.Parse([]byte(yaml), opts(fakeHome(t)))
			if tt.ok {
				if err != nil {
					t.Fatalf("Parse() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, config.ErrStateDirInOutput) || !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrStateDirInOutput and ErrInvalid", err)
			}
			if cfg != nil {
				t.Errorf("Parse() returned a config along with an error")
			}
			assertMentions(t, err, "state_dir")
		})
	}

	// Validate is also usable on a config changed after Parse.
	t.Run("validate after mutation", func(t *testing.T) {
		t.Parallel()
		cfg := mustParse(t, "", fakeHome(t))
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() on parsed defaults error = %v", err)
		}
		cfg.StateDir = filepath.Join(cfg.Output.Local, ".facto")
		if err := cfg.Validate(); !errors.Is(err, config.ErrStateDirInOutput) {
			t.Fatalf("Validate() error = %v, want ErrStateDirInOutput", err)
		}
	})
}

// TestValidate_StateDirInSyncedFolderRefused: the state dir must not be in a
// folder a sync client uploads (Google Drive for desktop, Dropbox, OneDrive,
// iCloud Drive). Detection is lexical on path components, case-insensitive
// (macOS and Windows file systems are). The output folder itself may be
// synced: that is the point of it.
func TestValidate_StateDirInSyncedFolderRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		state  string
		output string
		ok     bool
	}{
		{"default state dir", "", "", true},
		{"output in google drive is fine", "~/.facto", "~/Google Drive/Invoices", true},
		{"marker only as substring", "~/drive-notes/.facto", "", true},
		{"google drive legacy folder", "~/Google Drive/.facto", "", false},
		{"google drive lower case", "~/google drive/.facto", "", false},
		{"google drive for desktop on macos", "~/Library/CloudStorage/GoogleDrive-synthetic/My Drive/.facto", "", false},
		{"google drive mount my drive", "~/GoogleDrive/My Drive/facto", "", false},
		{"dropbox", "~/Dropbox/.facto", "", false},
		{"dropbox team folder", "~/Dropbox (Synthetic Team)/.facto", "", false},
		{"onedrive", "~/OneDrive/.facto", "", false},
		{"onedrive business", "~/OneDrive - Synthetic Org/.facto", "", false},
		{"icloud drive", "~/Library/Mobile Documents/com~apple~CloudDocs/.facto", "", false},
		{"any cloudstorage provider on macos", "~/Library/CloudStorage/Box-Box/.facto", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := ""
			if tt.output != "" {
				yaml += "output:\n  local: '" + tt.output + "'\n"
			}
			if tt.state != "" {
				yaml += "state_dir: '" + tt.state + "'\n"
			}
			cfg, err := config.Parse([]byte(yaml), opts(fakeHome(t)))
			if tt.ok {
				if err != nil {
					t.Fatalf("Parse() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, config.ErrStateDirSynced) || !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrStateDirSynced and ErrInvalid", err)
			}
			if cfg != nil {
				t.Errorf("Parse() returned a config along with an error")
			}
			assertMentions(t, err, "state_dir")
		})
	}
}

// TestParse_ExpandsHome: "~" is expanded with the injected home (never the
// process environment); paths are cleaned; other users' homes and relative
// paths are refused. "@ABS@" stands for an OS-absolute directory outside home.
func TestParse_ExpandsHome(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		key     string // output.local or state_dir
		value   string
		want    string // "~" and "@ABS@" prefixes resolved as in value
		wantErr bool
	}{
		{"tilde alone", "state_dir", "~", "~", false},
		{"tilde slash", "output.local", "~/Documents/Invoices", "~/Documents/Invoices", false},
		{"tilde cleaned", "state_dir", "~/a/../.facto", "~/.facto", false},
		{"absolute untouched", "output.local", "@ABS@/invoices", "@ABS@/invoices", false},
		{"tilde not first is literal", "output.local", "@ABS@/~/invoices", "@ABS@/~/invoices", false},
		{"other user's home refused", "output.local", "~other/Invoices", "", true},
		{"relative output refused", "output.local", "Invoices", "", true},
		{"relative state dir refused", "state_dir", ".facto", "", true},
		{"dot relative refused", "state_dir", "./.facto", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := fakeHome(t)
			abs := filepath.Join(t.TempDir(), "srv")
			resolve := func(s string) string {
				switch {
				case s == "~":
					return home
				case strings.HasPrefix(s, "~/"):
					return filepath.Join(home, filepath.FromSlash(s[2:]))
				case strings.HasPrefix(s, "@ABS@/"):
					return filepath.Join(abs, filepath.FromSlash(s[len("@ABS@/"):]))
				}
				return s
			}
			value := tt.value
			if strings.HasPrefix(value, "@ABS@/") {
				value = resolve(value)
			}
			yaml := "state_dir: '" + value + "'\n"
			if tt.key == "output.local" {
				yaml = "output:\n  local: '" + value + "'\n"
			}
			if tt.wantErr {
				err := parseErr(t, yaml, home)
				if !errors.Is(err, config.ErrInvalid) {
					t.Fatalf("Parse() error = %v, want ErrInvalid", err)
				}
				assertMentions(t, err, tt.key)
				return
			}
			cfg := mustParse(t, yaml, home)
			got := cfg.StateDir
			if tt.key == "output.local" {
				got = cfg.Output.Local
			}
			if want := resolve(tt.want); got != want {
				t.Errorf("%s = %q, want %q", tt.key, got, want)
			}
		})
	}
}

// TestParse_RequiresAbsoluteHome: the home is injected; Parse never falls
// back to the environment.
func TestParse_RequiresAbsoluteHome(t *testing.T) {
	t.Parallel()
	for _, home := range []string{"", "relative/home"} {
		if _, err := config.Parse([]byte("sessions: persistent\n"), opts(home)); err == nil {
			t.Errorf("Parse() with home %q error = nil, want an error", home)
		}
	}
}

// TestValidate_NamingTemplate: templates must compile with normalize.NewNamer
// (same template language as rendering).
func TestValidate_NamingTemplate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  string // file or dir
		tmpl string
		ok   bool
	}{
		{"custom file template", "file", "{year}_{provider}_{kind}[_{ref}]", true},
		{"custom dir template", "dir", "{category}/{provider}", true},
		{"unknown placeholder", "file", "{date}_{supplier}", false},
		{"unclosed group", "file", "{date}_{provider}[_{amount}", false},
		{"slash in file template", "file", "{provider}/{date}", false},
		{"dot segment in dir template", "dir", "../{year}", false},
		{"absolute dir template", "dir", "/{year}/{provider}", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := "naming:\n  " + tt.key + ": '" + tt.tmpl + "'\n"
			if tt.ok {
				mustParse(t, yaml, fakeHome(t))
				return
			}
			err := parseErr(t, yaml, fakeHome(t))
			if !errors.Is(err, normalize.ErrBadTemplate) || !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want normalize.ErrBadTemplate and ErrInvalid", err)
			}
			assertMentions(t, err, "naming."+tt.key)
		})
	}
}

// TestValidate_Enums: closed value sets from docs/spec.md "Configuration".
// Values are case-sensitive; an empty value means the default.
func TestValidate_Enums(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
		key  string
		ok   bool
	}{
		{"language en", "naming:\n  language: en\n", "naming.language", true},
		{"language fr", "naming:\n  language: fr\n", "naming.language", true},
		{"language empty is default", "naming:\n  language: ''\n", "naming.language", true},
		{"language de", "naming:\n  language: de\n", "naming.language", false},
		{"language upper case", "naming:\n  language: FR\n", "naming.language", false},
		{"sessions persistent", "sessions: persistent\n", "sessions", true},
		{"sessions ephemeral", "sessions: ephemeral\n", "sessions", true},
		{"sessions unknown", "sessions: forever\n", "sessions", false},
		{"sessions upper case", "sessions: Ephemeral\n", "sessions", false},
		{"secrets keyring", "secrets:\n  default: keyring\n", "secrets.default", true},
		{"secrets bitwarden", "secrets:\n  default: bitwarden\n", "secrets.default", true},
		{"secrets plaintext provider", "secrets:\n  default: plain\n", "secrets.default", false},
		{"notify desktop", "notify: desktop\n", "notify", true},
		{"notify none", "notify: none\n", "notify", true},
		{"notify unknown", "notify: email\n", "notify", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.ok {
				mustParse(t, tt.yaml, fakeHome(t))
				return
			}
			err := parseErr(t, tt.yaml, fakeHome(t))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrInvalid", err)
			}
			assertMentions(t, err, tt.key)
		})
	}
}

// TestValidate_IDsAndCategories: connector ids, manual ids and categories end
// up in paths and file names; only slug-shaped values are accepted
// (connector ids follow the registry rule ^[a-z0-9]+(-[a-z0-9]+)*$).
func TestValidate_IDsAndCategories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
		ok   bool
	}{
		{"spec connector", "connectors:\n  bouyguestelecom: { enabled: true, category: internet }\n", true},
		{"hyphenated id and category", "connectors:\n  synthetic-co: { enabled: true, category: home-office }\n", true},
		{"manual entry", "manual:\n  - { id: impots, name: \"Impôts\", category: housing, reminder: \"10-01\" }\n", true},
		{"connector id traversal", "connectors:\n  \"../evil\": { enabled: true, category: housing }\n", false},
		{"connector id with slash", "connectors:\n  \"a/b\": { enabled: true, category: housing }\n", false},
		{"connector id upper case", "connectors:\n  EDF: { enabled: true, category: housing }\n", false},
		{"category traversal", "connectors:\n  edf: { enabled: true, category: \"../../etc\" }\n", false},
		{"category with separator", "connectors:\n  edf: { enabled: true, category: \"housing/edf\" }\n", false},
		{"category windows separator", "connectors:\n  edf: { enabled: true, category: 'housing\\edf' }\n", false},
		{"manual id traversal", "manual:\n  - { id: \"../impots\", category: housing }\n", false},
		{"manual empty id", "manual:\n  - { category: housing }\n", false},
		{"manual category traversal", "manual:\n  - { id: impots, category: \"..\" }\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.ok {
				mustParse(t, tt.yaml, fakeHome(t))
				return
			}
			err := parseErr(t, tt.yaml, fakeHome(t))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrInvalid", err)
			}
		})
	}
}
