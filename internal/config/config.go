// Package config loads and validates config.yaml (docs/spec.md
// "Configuration"; ADR 0003 for the YAML library, ADR 0007 D1 for the state
// directory).
//
// Decoding is strict: unknown keys, duplicate keys, a second YAML document
// and wrong types are configuration errors. Every validation error wraps
// ErrInvalid, names the offending key and never quotes the value, so that a
// password pasted in the wrong field cannot reach a terminal, a log or a
// report.
package config

import (
	"errors"

	"github.com/FlorianRuen/facto/internal/normalize"
)

// MaxFileSize is the largest config.yaml Load accepts, in bytes. A real
// config is a few kilobytes; anything larger is refused before decoding.
const MaxFileSize = 64 << 10

var (
	// ErrInvalid reports a configuration error (CLI exit code 2). Every
	// error below also wraps it.
	ErrInvalid = errors.New("config: configuration error")
	// ErrPlaintextSecret reports a secret field (login, password, otp) that
	// does not hold a valid secret reference: either a plaintext value or a
	// malformed reference.
	ErrPlaintextSecret = errors.New("config: secret field is not a secret reference")
	// ErrStateDirInOutput reports a state_dir equal to or inside output.local.
	ErrStateDirInOutput = errors.New("config: state_dir is inside the output folder")
	// ErrStateDirSynced reports a state_dir inside a folder a sync client
	// uploads (Google Drive, Dropbox, OneDrive, iCloud Drive…).
	ErrStateDirSynced = errors.New("config: state_dir is inside a synced folder")
	// ErrTooLarge reports a config file larger than MaxFileSize.
	ErrTooLarge = errors.New("config: file too large")
)

// Defaults applied by Parse to every absent or empty key. Paths starting with
// "~" are expanded with Options.Home.
const (
	DefaultOutputLocal    = "~/Documents/Invoices"
	DefaultGDriveRoot     = "Invoices"
	DefaultLanguage       = "en"
	DefaultSecretProvider = SecretsBitwarden
	DefaultSessions       = SessionsPersistent
	DefaultStateDir       = "~/.facto"
	DefaultNotify         = NotifyDesktop
)

// Closed value sets (case-sensitive).
const (
	SessionsPersistent = "persistent"
	SessionsEphemeral  = "ephemeral"

	SecretsBitwarden = "bitwarden"
	SecretsKeyring   = "keyring"

	NotifyDesktop = "desktop"
	NotifyNone    = "none"
)

// Options carries what Parse must not take from the process environment.
type Options struct {
	// Home is the absolute user home directory used to expand "~". It is
	// injected (never read from $HOME by this package).
	Home string
}

// Config is the decoded config.yaml, defaults applied and paths expanded.
type Config struct {
	Output   Output  `yaml:"output"`
	Naming   Naming  `yaml:"naming"`
	Secrets  Secrets `yaml:"secrets"`
	Sessions string  `yaml:"sessions"` // persistent or ephemeral
	// StateDir holds the index, reports, logs and sessions. Absolute; never
	// inside Output.Local nor inside a synced folder.
	StateDir   string               `yaml:"state_dir"`
	Connectors map[string]Connector `yaml:"connectors"` // by connector id
	Manual     []Manual             `yaml:"manual"`
	Notify     string               `yaml:"notify"` // desktop or none

	// home is Options.Home, kept so that Validate can ignore the home
	// directory's own components when looking for synced folders.
	home string
}

// Output selects the destinations.
type Output struct {
	Local  string `yaml:"local"` // absolute directory
	GDrive GDrive `yaml:"gdrive"`
}

// GDrive configures the Google Drive destination.
type GDrive struct {
	Enabled bool   `yaml:"enabled"`
	Root    string `yaml:"root"` // folder name in My Drive
}

// Naming holds the normalize templates (see normalize.NewNamer).
type Naming struct {
	File     string `yaml:"file"`
	Dir      string `yaml:"dir"`
	Language string `yaml:"language"` // en or fr
}

// Secrets configures secret providers.
type Secrets struct {
	// Default is the provider "facto add" uses when it creates references:
	// bitwarden or keyring. Existing references name their own scheme.
	Default string `yaml:"default"`
}

// Connector configures one supplier account. Login, Password and OTP hold
// secret references (bw://…, keyring://…) or are empty, never values.
type Connector struct {
	Enabled  bool   `yaml:"enabled"`
	Category string `yaml:"category"`
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	OTP      string `yaml:"otp"`
}

// Manual is a document the user fetches by hand, with a yearly reminder.
type Manual struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
	Reminder string `yaml:"reminder"` // MM-DD, or empty
}

// applyDefaults fills every empty field with its default.
func (c *Config) applyDefaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&c.Output.Local, DefaultOutputLocal)
	def(&c.Output.GDrive.Root, DefaultGDriveRoot)
	def(&c.Naming.File, normalize.DefaultFileTemplate)
	def(&c.Naming.Dir, normalize.DefaultDirTemplate)
	def(&c.Naming.Language, DefaultLanguage)
	def(&c.Secrets.Default, DefaultSecretProvider)
	def(&c.Sessions, DefaultSessions)
	def(&c.StateDir, DefaultStateDir)
	def(&c.Notify, DefaultNotify)
}
