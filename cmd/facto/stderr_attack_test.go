// Red-team attack tests for the CLI error output (SEC-J0-19): an error
// printed on stderr may carry an untrusted inbox file name (terminal
// control sequences, bidi overrides, C1 controls) or a secret-shaped value.
// stderr must hold no raw control byte and no canary. Outputs are written
// under testsecrets.ArtifactDir so `make leakcheck` greps them. Everything
// is synthetic.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// hostileNames are inbox file names that try to drive the terminal.
var hostileNames = []string{
	"edf/\x1b]0;owned\x07.pdf",
	"\x1b[2J\x1b[Hfacture.pdf",
	"\x1b]52;c;ZWNobyBvd25lZA==\x07.pdf",
	"facture\u202egpj.pdf",
	"facture.pdf\rfacto: all good",
	"\x9b31mred.pdf",
	"\u009b31mred.pdf",
	"a\u2028b.pdf",
	"bad\xff.pdf",
}

// assertTerminalSafe fails when out holds, outside the final line feed of
// each line, a rune a terminal may interpret or render deceptively: C0 and
// C1 controls, DEL, invalid UTF-8 (decoded as U+FFFD), or any other
// non-printable rune such as a bidi override or a line separator.
func assertTerminalSafe(t *testing.T, label, out string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		for _, r := range line {
			if r == utf8.RuneError || !unicode.IsPrint(r) {
				t.Errorf("%s: stderr writes control or format character %U:\n%q", label, r, out)
				return
			}
		}
	}
}

// TestAttack_WriteErrCannotDriveTerminal wraps hostile names the way the
// inbox scan does (%q, then an *fs.PathError repeating the name unquoted)
// and prints them through writeErr.
func TestAttack_WriteErrCannotDriveTerminal(t *testing.T) {
	t.Parallel()
	for _, name := range hostileNames {
		var out bytes.Buffer
		err := fmt.Errorf("scan inbox: %q: %w", name,
			&fs.PathError{Op: "open", Path: "/home/u/Invoices/inbox/" + name, Err: fs.ErrPermission})
		writeErr(&out, err)
		assertTerminalSafe(t, fmt.Sprintf("%q", name), out.String())
		if !strings.HasPrefix(out.String(), "facto: ") {
			t.Errorf("stderr = %q, want the facto: prefix", out.String())
		}
	}
}

// TestAttack_WriteErrMasksSecrets prints errors holding a canary in shapes
// the redacting logger masks (sensitive key, URL userinfo and query, bearer
// scheme). Each line keeps the facto: prefix so a joined error cannot forge
// an unprefixed line.
func TestAttack_WriteErrMasksSecrets(t *testing.T) {
	t.Parallel()
	shapes := map[string]func(c string) error{
		"password key": func(c string) error { return fmt.Errorf("resolve: password=%s", c) },
		"token key":    func(c string) error { return fmt.Errorf("refresh failed: token: %s", c) },
		"url userinfo": func(c string) error {
			return fmt.Errorf("get https://user:%s@example.invalid/x: refused", c)
		},
		"url query": func(c string) error {
			return fmt.Errorf("get https://example.invalid/x?session=%s: refused", c)
		},
		"bearer":        func(c string) error { return fmt.Errorf("header Authorization: Bearer %s", c) },
		"joined errors": func(c string) error { return errors.Join(errors.New("first"), fmt.Errorf("cookie=%s", c)) },
	}
	for name, mk := range shapes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			var out bytes.Buffer
			writeErr(&out, mk(canary))
			writeFile(t, testsecrets.ArtifactDir(t), "stderr.txt", out.Bytes())
			if strings.Contains(out.String(), canary) || strings.Contains(out.String(), testsecrets.Prefix) {
				t.Errorf("stderr holds the canary:\n%s", out.String())
			}
			for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
				if !strings.HasPrefix(line, "facto: ") {
					t.Errorf("stderr line %q lacks the facto: prefix", line)
				}
			}
		})
	}
}

// TestAttack_CLIUsageErrorCannotDriveTerminal passes hostile strings as an
// unknown command: cobra echoes them in its error, which runEnv prints.
func TestAttack_CLIUsageErrorCannotDriveTerminal(t *testing.T) {
	t.Parallel()
	for _, name := range hostileNames {
		r := invoke(t.Context(), newSandbox(t).env(), "", name)
		if r.code != 2 {
			t.Errorf("unknown command %q: exit code = %d, want 2", name, r.code)
		}
		assertTerminalSafe(t, fmt.Sprintf("%q", name), r.stderr)
	}
}
