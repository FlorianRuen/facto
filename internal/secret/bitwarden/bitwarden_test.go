package bitwarden_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/bitwarden"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// The provider satisfies the core contract.
var _ secret.Provider = (*bitwarden.Provider)(nil)

func TestBitwarden_New(t *testing.T) {
	t.Parallel()
	if _, err := bitwarden.New(bitwarden.Options{}); err == nil {
		t.Fatal("New without a Runner: nil error, want an error")
	}
	p := newProvider(t, bitwarden.Options{Runner: vault(t)})
	if got := p.Scheme(); got != "bw" {
		t.Fatalf("Scheme() = %q, want bw", got)
	}
	if _, err := secret.NewResolver(p); err != nil {
		t.Fatalf("NewResolver(bitwarden provider): %v", err)
	}
}

func TestBitwarden_ReusesSessionEnv(t *testing.T) {
	t.Parallel()
	session := testsecrets.Canary(t, testsecrets.Session)
	f := vault(t)
	f.current = session // the user ran `bw unlock` in this terminal
	pr := &prompter{pw: secret.FromString("synthetic-master")}
	p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(session), Password: pr.get})

	for _, tc := range []struct{ field, want string }{
		{"username", "user-synthetic"},
		{"password", "pw-synthetic"},
		{"password", "pw-synthetic"}, // second resolve reuses the same session
	} {
		s, err := p.Resolve(t.Context(), bwRef(tc.field))
		if err != nil {
			t.Fatalf("Resolve(%s): %v", tc.field, err)
		}
		if s.Expose() != tc.want {
			t.Errorf("Resolve(%s) = %q, want %q", tc.field, s.Expose(), tc.want)
		}
	}

	if n := len(f.named("unlock")); n != 0 {
		t.Errorf("bw unlock ran %d times with a valid injected session, want 0", n)
	}
	if pr.count() != 0 {
		t.Errorf("master password prompted %d times with a valid injected session, want 0", pr.count())
	}
	if len(f.named("status")) == 0 {
		t.Error("bw status never ran: the provider must check the vault state first")
	}
	for _, c := range append(f.named("status"), f.named("get")...) {
		if got := c.envVals[sessionEnv]; got != session {
			t.Errorf("bw %q: %s in subprocess env = %q, want the injected session", c.args, sessionEnv, got)
		}
		for k := range c.env {
			if k != sessionEnv {
				t.Errorf("bw %q: unexpected subprocess env entry %q", c.args, k)
			}
		}
	}
	for _, c := range f.all() {
		if slices.ContainsFunc(c.args, func(a string) bool { return strings.Contains(a, session) }) {
			t.Errorf("session key on the command line: %q", c.args)
		}
		if slices.Contains(c.args, "--session") {
			t.Errorf("--session flag used (visible in ps): %q", c.args)
		}
	}
}

func TestBitwarden_StaleSessionFallsBackToUnlock(t *testing.T) {
	t.Parallel()
	f := vault(t) // f.current == "": the injected session is no longer valid
	pr := &prompter{pw: secret.FromString("synthetic-master")}
	p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString("synthetic-stale-session"), Password: pr.get})

	s, err := p.Resolve(t.Context(), bwRef("password"))
	if err != nil || s.Expose() != "pw-synthetic" {
		t.Fatalf("Resolve = %q, %v; want pw-synthetic, nil", s.Expose(), err)
	}
	if n := len(f.named("unlock")); n != 1 {
		t.Errorf("bw unlock ran %d times, want 1", n)
	}
	for _, c := range f.named("get") {
		if got := c.envVals[sessionEnv]; got != f.unlockKey {
			t.Errorf("bw %q used session %q, want the one from bw unlock", c.args, got)
		}
	}
}

func TestBitwarden_StatusHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setup       func(f *fakeBW)
		interactive bool
		wantErr     error // nil: success
		wantUnlock  int
	}{
		{name: "unlocked", setup: func(f *fakeBW) { f.current = "synthetic-session" }, wantUnlock: 0},
		{name: "locked interactive unlocks", setup: func(*fakeBW) {}, interactive: true, wantUnlock: 1},
		{name: "locked non-interactive", setup: func(*fakeBW) {}, wantErr: bitwarden.ErrLocked},
		{name: "unauthenticated", setup: func(f *fakeBW) { f.loggedOut = true }, interactive: true, wantErr: bitwarden.ErrNotLoggedIn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			tc.setup(f)
			opts := bitwarden.Options{Runner: f}
			if f.current != "" {
				opts.Session = secret.FromString(f.current)
			}
			pr := &prompter{pw: secret.FromString("synthetic-master")}
			if tc.interactive {
				opts.Password = pr.get
			}
			s, err := newProvider(t, opts).Resolve(t.Context(), bwRef("username"))
			if tc.wantErr == nil {
				if err != nil || s.Expose() != "user-synthetic" {
					t.Fatalf("Resolve = %q, %v; want user-synthetic, nil", s.Expose(), err)
				}
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Resolve error = %v, want %v", err, tc.wantErr)
				}
				if !s.IsZero() {
					t.Error("non-empty Secret returned with an error")
				}
				if n := len(f.named("get")); n != 0 {
					t.Errorf("bw get ran %d times, want 0", n)
				}
			}
			if n := len(f.named("unlock")); n != tc.wantUnlock {
				t.Errorf("bw unlock ran %d times, want %d", n, tc.wantUnlock)
			}
			if tc.wantErr != nil && pr.count() != 0 {
				t.Errorf("master password prompted %d times, want 0", pr.count())
			}
		})
	}
}

func TestBitwarden_StatusOutputRejected(t *testing.T) {
	t.Parallel()
	for _, out := range []string{
		"not json",
		`{"status":"weird"}`,
		`{"status":""}`,
		`{}`,
		`[{"status":"unlocked"}]`,
	} {
		t.Run(out, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			f.statusOut = out
			pr := &prompter{pw: secret.FromString("synthetic-master")}
			s, err := newProvider(t, bitwarden.Options{Runner: f, Password: pr.get}).Resolve(t.Context(), bwRef("password"))
			if err == nil {
				t.Fatalf("Resolve with bw status %q: nil error", out)
			}
			if errors.Is(err, secret.ErrSecretNotFound) {
				t.Errorf("unexpected status reported as not found: %v", err)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			if n := len(f.named("unlock")) + len(f.named("get")); n != 0 {
				t.Errorf("%d unlock/get commands after an unreadable status, want 0", n)
			}
			if pr.count() != 0 {
				t.Errorf("master password prompted after an unreadable status")
			}
		})
	}
}

var envNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func TestBitwarden_PasswordOnlyInUnlockSubprocessEnv(t *testing.T) {
	t.Parallel()
	master := testsecrets.Canary(t, testsecrets.Password)
	f := vault(t)
	f.password = master
	pw := secret.FromString(master)
	pr := &prompter{pw: pw}
	p := newProvider(t, bitwarden.Options{Runner: f, Password: pr.get})

	for _, field := range []string{"password", "username", "totp"} {
		if _, err := p.Resolve(t.Context(), bwRef(field)); err != nil {
			t.Fatalf("Resolve(%s): %v", field, err)
		}
	}

	if pr.count() != 1 {
		t.Errorf("master password prompted %d times, want 1 (unlock once per run)", pr.count())
	}
	unlocks := f.named("unlock")
	if len(unlocks) != 1 {
		t.Fatalf("bw unlock ran %d times, want 1", len(unlocks))
	}
	u := unlocks[0]
	if !slices.Equal(u.pos, []string{"unlock"}) {
		t.Errorf("unlock positional args = %q, want [unlock] (no password argument)", u.pos)
	}
	if !slices.Contains(u.args, "--raw") {
		t.Errorf("unlock args %q lack --raw (session key must be the only stdout)", u.args)
	}
	if slices.Contains(u.args, "--passwordfile") {
		t.Errorf("unlock args %q use --passwordfile (password written to disk)", u.args)
	}
	name := flagValue(u.args, "--passwordenv")
	if !envNameRe.MatchString(name) || name == sessionEnv {
		t.Fatalf("--passwordenv names %q, want a dedicated environment variable name", name)
	}
	if len(u.env) != 1 || u.envVals[name] != master {
		keys := slices.Sorted(func(yield func(string) bool) {
			for k := range u.env {
				if !yield(k) {
					return
				}
			}
		})
		t.Errorf("unlock subprocess env keys = %q, want exactly [%s] holding the master password", keys, name)
	}

	for _, c := range f.all() {
		for _, a := range c.args {
			if strings.Contains(a, master) {
				t.Errorf("master password on the command line of bw %q", c.pos)
			}
		}
		if c == u {
			continue
		}
		for k, v := range c.envVals {
			if strings.Contains(v, master) {
				t.Errorf("master password in env %s of bw %q (only the unlock subprocess may get it)", k, c.pos)
			}
		}
	}

	// The global process environment is never touched.
	if v, ok := os.LookupEnv(name); ok {
		t.Errorf("%s set in the process environment (%d bytes)", name, len(v))
	}
	for _, kv := range os.Environ() {
		if strings.Contains(kv, master) {
			t.Error("master password found in the process environment")
		}
	}

	// The password is wiped once bw unlock has run.
	if !pw.IsZero() {
		t.Error("master password Secret not wiped after unlock")
	}

	// Later commands use the session printed by bw unlock.
	for _, c := range f.named("get") {
		if got := c.envVals[sessionEnv]; got != f.unlockKey {
			t.Errorf("bw %q used session %q, want the key printed by bw unlock", c.pos, got)
		}
	}
}

func TestBitwarden_UnlockFailures(t *testing.T) {
	t.Parallel()
	errAborted := errors.New("prompt aborted")
	tests := []struct {
		name       string
		prompt     *prompter
		wantErr    error
		wantUnlock int
	}{
		{name: "wrong master password", prompt: &prompter{pw: secret.FromString("synthetic-wrong")}, wantUnlock: 1},
		{name: "prompt aborted", prompt: &prompter{err: errAborted}, wantErr: errAborted, wantUnlock: 0},
		{name: "empty master password", prompt: &prompter{pw: secret.FromString("")}, wantUnlock: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			s, err := newProvider(t, bitwarden.Options{Runner: f, Password: tc.prompt.get}).Resolve(t.Context(), bwRef("password"))
			if err == nil {
				t.Fatal("Resolve: nil error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not wrap %v", err, tc.wantErr)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			if n := len(f.named("unlock")); n != tc.wantUnlock {
				t.Errorf("bw unlock ran %d times, want %d", n, tc.wantUnlock)
			}
			if n := len(f.named("get")); n != 0 {
				t.Errorf("bw get ran %d times without a session, want 0", n)
			}
			if !tc.prompt.pw.IsZero() {
				t.Error("master password Secret not wiped after a failed unlock")
			}
		})
	}
}

func TestBitwarden_ResolvesByUUIDOnly(t *testing.T) {
	t.Parallel()
	bad := []struct {
		name string
		ref  secret.Ref
	}{
		{name: "item name", ref: secret.Ref{Scheme: "bw", Item: "EDF Login", Field: "password"}},
		{name: "item slug", ref: secret.Ref{Scheme: "bw", Item: "edf-login", Field: "password"}},
		{name: "uuid without dashes", ref: secret.Ref{Scheme: "bw", Item: strings.ReplaceAll(itemID, "-", ""), Field: "password"}},
		{name: "uuid with search wildcard", ref: secret.Ref{Scheme: "bw", Item: itemID[:35] + "*", Field: "password"}},
		{name: "flag injection", ref: secret.Ref{Scheme: "bw", Item: "--session", Field: "password"}},
		{name: "empty item", ref: secret.Ref{Scheme: "bw", Item: "", Field: "password"}},
		{name: "unknown field", ref: secret.Ref{Scheme: "bw", Item: itemID, Field: "notes"}},
		{name: "empty field", ref: secret.Ref{Scheme: "bw", Item: itemID, Field: ""}},
		{name: "other scheme", ref: secret.Ref{Scheme: "keyring", Item: itemID, Field: "password"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			f.current = "synthetic-session"
			p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
			s, err := p.Resolve(t.Context(), tc.ref)
			if !errors.Is(err, secret.ErrInvalidRef) {
				t.Fatalf("Resolve(%+v) error = %v, want ErrInvalidRef", tc.ref, err)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			if calls := f.all(); len(calls) != 0 {
				t.Errorf("bw invoked for an invalid reference: %q", calls[0].args)
			}
		})
	}

	// Valid references hit bw with the exact UUID, never a search.
	f := vault(t)
	f.current = "synthetic-session"
	p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
	for _, field := range []string{"username", "password", "totp"} {
		if _, err := p.Resolve(t.Context(), bwRef(field)); err != nil {
			t.Fatalf("Resolve(%s): %v", field, err)
		}
	}
	for _, c := range f.named("get") {
		if len(c.pos) != 3 || c.pos[2] != itemID {
			t.Errorf("bw get positional args = %q, want [get <kind> %s]", c.pos, itemID)
		}
		if slices.ContainsFunc(c.args, func(a string) bool { return strings.HasPrefix(a, "--search") }) {
			t.Errorf("bw %q searches by name", c.args)
		}
	}
	for _, c := range f.all() {
		if len(c.pos) > 0 && c.pos[0] == "list" {
			t.Errorf("bw list used: %q", c.args)
		}
	}
}

func TestBitwarden_RejectsSubstitutedItem(t *testing.T) {
	t.Parallel()
	f := vault(t)
	f.current = "synthetic-session"
	it := f.items[itemID]
	it.id = otherID // bw answered with another item than the one asked for
	f.items[itemID] = it
	p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
	s, err := p.Resolve(t.Context(), bwRef("password"))
	if err == nil {
		t.Fatalf("Resolve returned %d bytes from item %s for a ref to %s", len(s.Expose()), otherID, itemID)
	}
	if !s.IsZero() {
		t.Error("non-empty Secret returned with an error")
	}
	if errors.Is(err, secret.ErrSecretNotFound) {
		t.Errorf("substituted item reported as not found (must be a hard error): %v", err)
	}
}

func TestBitwarden_ResolvesFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		item         *item // nil: item absent from the vault
		field        string
		want         string
		wantNotFound bool
		wantGet      []string // positional args of the bw get producing the value
	}{
		{name: "username", item: &item{username: strp("user-synthetic"), password: strp("pw-synthetic")}, field: "username", want: "user-synthetic", wantGet: []string{"get", "item", itemID}},
		{name: "password", item: &item{username: strp("user-synthetic"), password: strp("pw-synthetic")}, field: "password", want: "pw-synthetic", wantGet: []string{"get", "item", itemID}},
		{name: "totp code, not the seed", item: &item{totpSeed: "otpauth://totp/Synthetic?secret=SYNTHETICSEEDAAA", totpCode: "492039"}, field: "totp", want: "492039", wantGet: []string{"get", "totp", itemID}},
		{name: "missing item", item: nil, field: "password", wantNotFound: true},
		{name: "null password", item: &item{username: strp("user-synthetic")}, field: "password", wantNotFound: true},
		{name: "empty username", item: &item{username: strp(""), password: strp("pw-synthetic")}, field: "username", wantNotFound: true},
		{name: "no totp configured", item: &item{username: strp("user-synthetic")}, field: "totp", wantNotFound: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			f.current = "synthetic-session"
			delete(f.items, itemID)
			if tc.item != nil {
				f.items[itemID] = *tc.item
			}
			p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
			s, err := p.Resolve(t.Context(), bwRef(tc.field))
			if tc.wantNotFound {
				if !errors.Is(err, secret.ErrSecretNotFound) {
					t.Fatalf("Resolve(%s) error = %v, want ErrSecretNotFound", tc.field, err)
				}
				if !s.IsZero() {
					t.Error("non-empty Secret returned with an error")
				}
				// A missing entry is a user configuration problem, not a
				// reason to lock the vault for the rest of the run.
				if n := len(f.named("lock")); n != 0 {
					t.Errorf("bw lock ran %d times after a not-found, want 0", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%s): %v", tc.field, err)
			}
			if s.Expose() != tc.want {
				t.Errorf("Resolve(%s) = %q, want %q", tc.field, s.Expose(), tc.want)
			}
			gets := f.named("get")
			if len(gets) == 0 || !slices.Equal(gets[len(gets)-1].pos, tc.wantGet) {
				var got [][]string
				for _, g := range gets {
					got = append(got, g.pos)
				}
				t.Errorf("bw get calls = %q, want the last one to be %q", got, tc.wantGet)
			}
		})
	}
}

func TestBitwarden_TOTPOutputValidated(t *testing.T) {
	t.Parallel()
	for _, out := range []string{
		"otpauth://totp/Synthetic?secret=SYNTHETICSEEDAAA", // a seed, not a code
		"SYNTHETICSEEDAAA",
		"12 34 56",
		"",
		"1234567890123",
	} {
		t.Run(out, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			f.current = "synthetic-session"
			f.setHook(func(_ context.Context, c *call, stdout, _ io.Writer) (bool, error) {
				if slices.Equal(c.pos, []string{"get", "totp", itemID}) {
					return true, write(stdout, out+"\n")
				}
				return false, nil
			})
			p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
			s, err := p.Resolve(t.Context(), bwRef("totp"))
			if err == nil {
				t.Fatalf("Resolve(totp) with output %q = %q, want an error", out, s.Expose())
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
		})
	}
}

func TestBitwarden_LocksOnCloseAndError(t *testing.T) {
	t.Parallel()

	t.Run("close after unlock", func(t *testing.T) {
		t.Parallel()
		f := vault(t)
		p := newProvider(t, bitwarden.Options{Runner: f, Password: (&prompter{pw: secret.FromString("synthetic-master")}).get})
		if _, err := p.Resolve(t.Context(), bwRef("password")); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		gets := f.named("get")
		if len(gets) == 0 {
			t.Fatal("no bw get recorded")
		}
		sess := gets[0].env[sessionEnv]
		if err := p.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if n := len(f.named("lock")); n != 1 {
			t.Fatalf("bw lock ran %d times on Close, want 1", n)
		}
		if !sess.IsZero() {
			t.Error("session key Secret not wiped on Close")
		}
		// Idempotent, and closed for good.
		if err := p.Close(); err != nil {
			t.Errorf("second Close = %v, want nil", err)
		}
		if n := len(f.named("lock")); n != 1 {
			t.Errorf("bw lock ran %d times after a second Close, want 1", n)
		}
		before := len(f.all())
		if _, err := p.Resolve(t.Context(), bwRef("password")); !errors.Is(err, secret.ErrClosed) {
			t.Errorf("Resolve after Close error = %v, want ErrClosed", err)
		}
		if after := len(f.all()); after != before {
			t.Errorf("bw invoked %d times after Close, want 0", after-before)
		}
	})

	t.Run("close after reusing the injected session", func(t *testing.T) {
		t.Parallel()
		f := vault(t)
		f.current = "synthetic-session"
		injected := secret.FromString(f.current)
		p := newProvider(t, bitwarden.Options{Runner: f, Session: injected})
		if _, err := p.Resolve(t.Context(), bwRef("username")); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if n := len(f.named("lock")); n != 1 {
			t.Errorf("bw lock ran %d times on Close, want 1 (spec: lock at the end of the run)", n)
		}
		if !injected.IsZero() {
			t.Error("injected session Secret not wiped on Close")
		}
	})

	t.Run("close reports a failing lock and still wipes", func(t *testing.T) {
		t.Parallel()
		f := vault(t)
		f.current = "synthetic-session"
		injected := secret.FromString(f.current)
		f.setHook(func(_ context.Context, c *call, _, stderr io.Writer) (bool, error) {
			if len(c.pos) > 0 && c.pos[0] == "lock" {
				_ = write(stderr, "lock failed")
				return true, errExit
			}
			return false, nil
		})
		p := newProvider(t, bitwarden.Options{Runner: f, Session: injected})
		if _, err := p.Resolve(t.Context(), bwRef("username")); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if err := p.Close(); err == nil {
			t.Error("Close with a failing bw lock = nil, want an error")
		}
		if !injected.IsZero() {
			t.Error("session Secret not wiped when bw lock failed")
		}
	})

	errorCases := []struct {
		name string
		hook func(cancel context.CancelFunc) hookFunc
	}{
		{name: "bw get crashes", hook: func(context.CancelFunc) hookFunc {
			return onGet(func(_ io.Writer, stderr io.Writer) error {
				_ = write(stderr, "Segmentation fault")
				return errors.New("signal: killed")
			})
		}},
		{name: "malformed item json", hook: func(context.CancelFunc) hookFunc {
			return onGet(func(stdout, _ io.Writer) error { return write(stdout, `{"object":"item","id":`) })
		}},
		{name: "item json of another type", hook: func(context.CancelFunc) hookFunc {
			return onGet(func(stdout, _ io.Writer) error { return write(stdout, `["`+itemID+`"]`) })
		}},
		{name: "substituted item id", hook: func(context.CancelFunc) hookFunc {
			return onGet(func(stdout, _ io.Writer) error {
				return write(stdout, itemJSON(item{id: otherID, password: strp("pw-synthetic")}))
			})
		}},
		{name: "output too large", hook: func(context.CancelFunc) hookFunc {
			return onGet(func(stdout, _ io.Writer) error { return flood(stdout, bitwarden.MaxOutput+1) })
		}},
		{name: "context canceled during get", hook: func(cancel context.CancelFunc) hookFunc {
			return onGet(func(io.Writer, io.Writer) error {
				cancel()
				return context.Canceled
			})
		}},
	}
	for _, tc := range errorCases {
		t.Run("error: "+tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := vault(t)
			pr := &prompter{pw: secret.FromString("synthetic-master")}
			p := newProvider(t, bitwarden.Options{Runner: f, Password: pr.get})
			f.setHook(tc.hook(cancel))

			s, err := p.Resolve(ctx, bwRef("password"))
			if err == nil {
				t.Fatal("Resolve: nil error")
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			locks := f.named("lock")
			if len(locks) != 1 {
				t.Fatalf("bw lock ran %d times after the error, want 1", len(locks))
			}
			if locks[0].ctxErr != nil {
				t.Errorf("bw lock started with a done context (%v): it must run even when the caller's context is canceled", locks[0].ctxErr)
			}
			gets := f.named("get")
			if len(gets) == 0 {
				t.Fatal("no bw get recorded")
			}
			if sess := gets[0].env[sessionEnv]; !sess.IsZero() {
				t.Error("session key Secret not wiped after the error")
			}
			// The vault stays locked: no further get, no new prompt.
			nGet := len(gets)
			if _, err := p.Resolve(t.Context(), bwRef("username")); err == nil {
				t.Error("Resolve after a fatal error succeeded, want an error")
			}
			if n := len(f.named("get")); n != nGet {
				t.Errorf("bw get ran %d more times after the error, want 0", n-nGet)
			}
			if pr.count() != 1 {
				t.Errorf("master password prompted %d times, want 1", pr.count())
			}
		})
	}
}

// onGet builds a hook that replaces every `bw get` with fn.
func onGet(fn func(stdout, stderr io.Writer) error) hookFunc {
	return func(_ context.Context, c *call, stdout, stderr io.Writer) (bool, error) {
		if len(c.pos) > 0 && c.pos[0] == "get" {
			return true, fn(stdout, stderr)
		}
		return false, nil
	}
}

// allowedSubcommands are the only bw commands the provider may run.
var allowedSubcommands = []string{"status", "unlock", "get", "lock"}

func TestBitwarden_NeverServe(t *testing.T) {
	t.Parallel()
	scenarios := map[string]func(t *testing.T) *fakeBW{
		"reuse session": func(t *testing.T) *fakeBW {
			f := vault(t)
			f.current = "synthetic-session"
			p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
			for _, field := range []string{"username", "password", "totp"} {
				_, _ = p.Resolve(t.Context(), bwRef(field))
			}
			_ = p.Close()
			return f
		},
		"unlock": func(t *testing.T) *fakeBW {
			f := vault(t)
			p := newProvider(t, bitwarden.Options{Runner: f, Password: (&prompter{pw: secret.FromString("synthetic-master")}).get})
			for _, field := range []string{"username", "password", "totp"} {
				_, _ = p.Resolve(t.Context(), bwRef(field))
			}
			_ = p.Close()
			return f
		},
		"error path": func(t *testing.T) *fakeBW {
			f := vault(t)
			f.current = "synthetic-session"
			f.setHook(onGet(func(io.Writer, io.Writer) error { return errExit }))
			p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
			_, _ = p.Resolve(t.Context(), bwRef("password"))
			_ = p.Close()
			return f
		},
		"locked non-interactive": func(t *testing.T) *fakeBW {
			f := vault(t)
			p := newProvider(t, bitwarden.Options{Runner: f})
			_, _ = p.Resolve(t.Context(), bwRef("password"))
			_ = p.Close()
			return f
		},
	}
	for name, run := range scenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := run(t)
			if len(f.all()) == 0 {
				t.Fatal("no bw command recorded")
			}
			for _, c := range f.all() {
				if slices.Contains(c.args, "serve") {
					t.Errorf("bw serve invoked (exposes the vault on localhost): %q", c.args)
				}
				if len(c.pos) == 0 || !slices.Contains(allowedSubcommands, c.pos[0]) {
					t.Errorf("bw %q: subcommand outside %q", c.args, allowedSubcommands)
				}
				for _, forbidden := range []string{"--session", "--passwordfile", "--port", "--hostname"} {
					if slices.Contains(c.args, forbidden) {
						t.Errorf("bw %q uses %s", c.args, forbidden)
					}
				}
			}
		})
	}
}

func TestBitwarden_OutputCapped(t *testing.T) {
	t.Parallel()
	if bitwarden.MaxOutput <= 0 || bitwarden.MaxOutput > 1<<20 {
		t.Fatalf("MaxOutput = %d, want a positive cap of at most 1 MiB", bitwarden.MaxOutput)
	}
	tests := []struct {
		name   string
		locked bool // go through bw unlock
		field  string
		match  func(c *call) bool
		stderr bool // flood stderr instead of stdout
	}{
		{name: "status stdout", field: "password", match: func(c *call) bool { return c.pos[0] == "status" }},
		{name: "unlock stdout", locked: true, field: "password", match: func(c *call) bool { return c.pos[0] == "unlock" }},
		{name: "get item stdout", field: "password", match: func(c *call) bool { return c.pos[0] == "get" }},
		{name: "get totp stdout", field: "totp", match: func(c *call) bool { return c.pos[0] == "get" }},
		{name: "get item stderr", field: "password", stderr: true, match: func(c *call) bool { return c.pos[0] == "get" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := vault(t)
			opts := bitwarden.Options{Runner: f, Password: (&prompter{pw: secret.FromString("synthetic-master")}).get}
			if !tc.locked {
				f.current = "synthetic-session"
				opts.Session = secret.FromString(f.current)
			}
			f.setHook(func(_ context.Context, c *call, stdout, stderr io.Writer) (bool, error) {
				if len(c.pos) == 0 || !tc.match(c) {
					return false, nil
				}
				if tc.stderr {
					if err := flood(stderr, bitwarden.MaxOutput+1); err != nil {
						return true, err
					}
					return true, errExit
				}
				return true, flood(stdout, bitwarden.MaxOutput+1)
			})
			s, err := newProvider(t, opts).Resolve(t.Context(), bwRef(tc.field))
			if err == nil {
				t.Fatal("Resolve with oversized bw output: nil error")
			}
			if !tc.stderr && !errors.Is(err, bitwarden.ErrOutputTooLarge) {
				t.Errorf("error = %v, want ErrOutputTooLarge", err)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			if l := len(err.Error()); l > 1024 {
				t.Errorf("error message is %d bytes: bw output leaked into it", l)
			}
		})
	}

	t.Run("output at the cap is accepted", func(t *testing.T) {
		t.Parallel()
		f := vault(t)
		f.current = "synthetic-session"
		doc := itemJSON(item{id: itemID, username: strp("user-synthetic"), password: strp("pw-synthetic")})
		f.setHook(onGet(func(stdout, _ io.Writer) error {
			// Trailing JSON whitespace pads the document to exactly MaxOutput.
			return write(stdout, doc+strings.Repeat(" ", bitwarden.MaxOutput-len(doc)))
		}))
		p := newProvider(t, bitwarden.Options{Runner: f, Session: secret.FromString(f.current)})
		s, err := p.Resolve(t.Context(), bwRef("password"))
		if err != nil || s.Expose() != "pw-synthetic" {
			t.Fatalf("Resolve with %d-byte output = %q, %v; want pw-synthetic, nil", bitwarden.MaxOutput, s.Expose(), err)
		}
	})
}

func TestBitwarden_CanaryNotInErrors(t *testing.T) {
	t.Parallel()
	master := testsecrets.Canary(t, testsecrets.Password)
	session := testsecrets.Canary(t, testsecrets.Session)
	itemPW := testsecrets.Canary(t, testsecrets.Password)
	seed := testsecrets.Canary(t, testsecrets.Token)
	canaries := []string{master, session, itemPW, seed}

	echo := func(stderr io.Writer, msg string) error {
		_ = write(stderr, msg)
		return fmt.Errorf("exit status 1: %s", msg) // a runner that copies stderr into its error
	}
	tests := []struct {
		name   string
		locked bool
		field  string
		hook   hookFunc
	}{
		{
			name: "unlock rejects and echoes the master password", locked: true, field: "password",
			hook: func(_ context.Context, c *call, _, stderr io.Writer) (bool, error) {
				if c.pos[0] != "unlock" {
					return false, nil
				}
				return true, echo(stderr, "Invalid master password: "+master)
			},
		},
		{
			name: "get echoes the session key", field: "password",
			hook: onGet(func(_ io.Writer, stderr io.Writer) error { return echo(stderr, "bad session "+session) }),
		},
		{
			name: "get echoes the item password", field: "password",
			hook: onGet(func(_ io.Writer, stderr io.Writer) error { return echo(stderr, "decrypt failed for "+itemPW) }),
		},
		{
			name: "malformed item json holding the password", field: "password",
			hook: onGet(func(stdout, _ io.Writer) error {
				return write(stdout, `{"object":"item","id":"`+itemID+`","login":{"password":"`+itemPW+`",`)
			}),
		},
		{
			name: "item json with a wrongly typed password", field: "password",
			hook: onGet(func(stdout, _ io.Writer) error {
				return write(stdout, `{"object":"item","id":"`+itemID+`","login":{"password":["`+itemPW+`"]}}`)
			}),
		},
		{
			name: "substituted item holding the password", field: "password",
			hook: onGet(func(stdout, _ io.Writer) error {
				return write(stdout, itemJSON(item{id: otherID, password: strp(itemPW)}))
			}),
		},
		{
			name: "totp output is the seed", field: "totp",
			hook: onGet(func(stdout, _ io.Writer) error { return write(stdout, "otpauth://totp/x?secret="+seed+"\n") }),
		},
		{
			name: "status garbage holding the session", field: "password",
			hook: func(_ context.Context, c *call, stdout, _ io.Writer) (bool, error) {
				if c.pos[0] != "status" {
					return false, nil
				}
				return true, write(stdout, `{"status":"`+session+`"}`)
			},
		},
	}
	var rendered strings.Builder
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := vault(t)
			f.password = master
			f.unlockKey = session
			opts := bitwarden.Options{Runner: f, Password: (&prompter{pw: secret.FromString(master)}).get}
			if !tc.locked {
				f.current = session
				opts.Session = secret.FromString(session)
			}
			f.setHook(func(ctx context.Context, c *call, stdout, stderr io.Writer) (bool, error) {
				if len(c.pos) == 0 {
					return false, nil
				}
				return tc.hook(ctx, c, stdout, stderr)
			})
			p := newProvider(t, opts)
			s, err := p.Resolve(t.Context(), bwRef(tc.field))
			if err == nil {
				t.Fatalf("Resolve: nil error (got %d bytes)", len(s.Expose()))
			}
			closeErr := p.Close()
			for _, e := range []error{err, closeErr} {
				if e == nil {
					continue
				}
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
					out := fmt.Sprintf(verb, e)
					fmt.Fprintf(&rendered, "%s %s: %s\n", tc.name, verb, out)
					for _, c := range canaries {
						if strings.Contains(out, c) {
							t.Errorf("error formatted with %s contains a canary: %s", verb, out)
						}
					}
				}
			}
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				out := fmt.Sprintf(verb, p)
				fmt.Fprintf(&rendered, "%s provider %s: %s\n", tc.name, verb, out)
				for _, c := range canaries {
					if strings.Contains(out, c) {
						t.Errorf("provider formatted with %s contains a canary", verb)
					}
				}
			}
		})
	}
	writeArtifact(t, "bitwarden-errors.txt", rendered.String())
}
