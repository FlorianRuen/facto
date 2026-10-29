package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Length caps on values that end up in paths and file names.
const (
	maxIDLen       = 40 // same as connector.Info.ID
	maxCategoryLen = 40
	maxNameLen     = 200
)

// slugRe is the connector registry id rule, also used for manual ids and
// categories: they become path components.
var slugRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// invalid builds an ErrInvalid error for key. msg must never contain a value
// read from the config file.
func invalid(key, msg string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, key, msg)
}

// Validate checks c and returns every problem found, joined, each wrapping
// ErrInvalid (and a more specific sentinel where one exists). It is lexical:
// nothing touches the disk. Parse calls it; call it again after changing c.
func (c *Config) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(oneOf("naming.language", c.Naming.Language, "en", "fr"))
	add(oneOf("sessions", c.Sessions, SessionsPersistent, SessionsEphemeral))
	add(oneOf("secrets.default", c.Secrets.Default, SecretsBitwarden, SecretsKeyring))
	add(oneOf("notify", c.Notify, NotifyDesktop, NotifyNone))
	add(c.validateNaming())
	add(c.validatePaths())

	ids := make([]string, 0, len(c.Connectors))
	for id := range c.Connectors {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		add(validateConnector(id, c.Connectors[id]))
	}
	for i, m := range c.Manual {
		add(validateManual(fmt.Sprintf("manual[%d]", i), m))
	}
	return errors.Join(errs...)
}

// oneOf checks that v is one of the allowed values (case-sensitive).
func oneOf(key, v string, allowed ...string) error {
	if slices.Contains(allowed, v) {
		return nil
	}
	return invalid(key, fmt.Sprintf("unsupported value (want one of %q)", allowed))
}

// validateNaming compiles each template alone with the renderer's own parser,
// so that an error is attributed to the right key. The language is checked
// by Validate itself.
//
// The normalize error text is dropped: it quotes the template, and a
// template is a scalar value that may hold a secret pasted on the wrong
// line. The returned error names the key, wraps ErrInvalid and
// normalize.ErrBadTemplate, and gives a fixed reason.
func (c *Config) validateNaming() error {
	var errs []error
	if _, err := normalize.NewNamer(normalize.Config{File: c.Naming.File}); err != nil &&
		errors.Is(err, normalize.ErrBadTemplate) {
		errs = append(errs, badTemplate("naming.file", namingFileGrammar))
	}
	if _, err := normalize.NewNamer(normalize.Config{Dir: c.Naming.Dir}); err != nil &&
		errors.Is(err, normalize.ErrBadTemplate) {
		errs = append(errs, badTemplate("naming.dir", namingDirGrammar))
	}
	return errors.Join(errs...)
}

// Fixed, value-free descriptions of the template language (see
// internal/normalize/naming.go parseTemplate).
const (
	namingPlaceholders = "placeholders {date}, {date:<layout>}, {year}, {provider}, {category}, {kind}, {amount}, {ref}"
	namingFileGrammar  = "invalid naming template; allowed: lowercase letters, digits, - and _, " +
		namingPlaceholders + ", and one level of [optional] groups"
	namingDirGrammar = "invalid naming template; allowed: lowercase letters, digits, - and _, " +
		namingPlaceholders + ", one level of [optional] groups, and / between non-empty segments"
)

// badTemplate reports a naming template that does not compile, without its
// value.
func badTemplate(key, reason string) error {
	return fmt.Errorf("%w: %s: %w: %s", ErrInvalid, key, normalize.ErrBadTemplate, reason)
}

// validateSlug checks an id or a category used as a path component.
func validateSlug(key, v string, maxLen int) error {
	if len(v) > maxLen || !slugRe.MatchString(v) {
		return invalid(key, fmt.Sprintf("must be lowercase letters, digits and single hyphens, at most %d bytes", maxLen))
	}
	return nil
}

func validateConnector(id string, c Connector) error {
	// The id itself is user text: it is only printed once known to be a slug.
	if len(id) > maxIDLen || !slugRe.MatchString(id) {
		return invalid("connectors", fmt.Sprintf("invalid connector id: must match %s, at most %d bytes", slugRe, maxIDLen))
	}
	key := "connectors." + id
	var errs []error
	if c.Category != "" {
		errs = append(errs, validateSlug(key+".category", c.Category, maxCategoryLen))
	}
	for _, f := range []struct{ name, v string }{
		{"login", c.Login}, {"password", c.Password}, {"otp", c.OTP},
	} {
		errs = append(errs, validateRef(key+"."+f.name, f.v))
	}
	return errors.Join(errs...)
}

// validateRef checks that a secret field is empty or a secret reference.
// The message is fixed: neither the value nor the secret.ParseRef reason
// (which may quote fragments such as the scheme) is included.
func validateRef(key, v string) error {
	if v == "" {
		return nil
	}
	if _, err := secret.ParseRef(v); err != nil {
		return fmt.Errorf("%w: %s: %w: store the value in your password manager and put its reference here (docs/spec.md, Password managers)",
			ErrInvalid, key, ErrPlaintextSecret)
	}
	return nil
}

func validateManual(key string, m Manual) error {
	errs := []error{validateSlug(key+".id", m.ID, maxIDLen)}
	if m.Category != "" {
		errs = append(errs, validateSlug(key+".category", m.Category, maxCategoryLen))
	}
	if len(m.Name) > maxNameLen {
		errs = append(errs, invalid(key+".name", fmt.Sprintf("longer than %d bytes", maxNameLen)))
	}
	if m.Reminder != "" && !validMonthDay(m.Reminder) {
		errs = append(errs, invalid(key+".reminder", "must be a MM-DD date"))
	}
	return errors.Join(errs...)
}

// validMonthDay reports whether s is "MM-DD" naming a day that exists in a
// leap year (02-29 is accepted).
func validMonthDay(s string) bool {
	if len(s) != 5 || s[2] != '-' {
		return false
	}
	mm, err1 := strconv.Atoi(s[:2])
	dd, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || s[0] == '+' || s[3] == '+' || s[0] == '-' || s[3] == '-' {
		return false
	}
	days := [...]int{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	return mm >= 1 && mm <= 12 && dd >= 1 && dd <= days[mm-1]
}
