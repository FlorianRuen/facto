package bitwarden_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/bitwarden"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Synthetic vault item ids (the spec example and a made-up one).
const (
	itemID  = "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"
	otherID = "0b8e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b"

	// sessionEnv is the variable the bw CLI reads its session key from.
	sessionEnv = "BW_SESSION"
)

// errExit mimics *exec.ExitError for a bw command exiting 1.
var errExit = errors.New("exit status 1")

// item is a synthetic vault login item.
type item struct {
	id       string // id reported by bw; defaults to the map key
	username *string
	password *string
	totpSeed string // otpauth seed stored in the item (must never be returned)
	totpCode string // what `bw get totp` prints
}

func strp(s string) *string { return &s }

// call records one invocation of the fake bw binary.
type call struct {
	args    []string
	pos     []string                 // positional arguments (flags removed)
	env     map[string]secret.Secret // handles as passed by the provider
	envVals map[string]string        // values exposed at call time
	ctxErr  error                    // ctx.Err() when the command started
}

// hookFunc intercepts a command before the default bw simulation. handled
// false falls through to the simulation.
type hookFunc func(ctx context.Context, c *call, stdout, stderr io.Writer) (handled bool, err error)

// fakeBW simulates the bw CLI. It never runs a process.
type fakeBW struct {
	t testing.TB

	mu        sync.Mutex
	current   string // session key bw considers unlocked; "" means locked
	loggedOut bool   // `bw status` says unauthenticated
	password  string // master password accepted by unlock
	unlockKey string // session key printed by `bw unlock --raw`
	statusOut string // raw `bw status` stdout override
	items     map[string]item
	hook      hookFunc
	calls     []*call
}

var _ bitwarden.Runner = (*fakeBW)(nil)

func (f *fakeBW) Run(ctx context.Context, cmd bitwarden.Command) error {
	c := &call{
		args:    slices.Clone(cmd.Args),
		pos:     positional(cmd.Args),
		env:     maps.Clone(cmd.Env),
		envVals: map[string]string{},
		ctxErr:  ctx.Err(),
	}
	for k, v := range cmd.Env {
		c.envVals[k] = v.Expose()
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	hook := f.hook
	f.mu.Unlock()

	if cmd.Stdout == nil || cmd.Stderr == nil {
		f.t.Errorf("bw %q run without stdout/stderr writers (output must be captured and capped by the provider)", c.args)
		return errExit
	}
	if hook != nil {
		if handled, err := hook(ctx, c, cmd.Stdout, cmd.Stderr); handled {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.simulate(c, cmd.Stdout, cmd.Stderr)
}

func (f *fakeBW) simulate(c *call, stdout, stderr io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(c.pos) == 0 {
		return f.unexpected(c)
	}
	switch c.pos[0] {
	case "status":
		if f.statusOut != "" {
			return write(stdout, f.statusOut)
		}
		st := "locked"
		switch s := c.envVals[sessionEnv]; {
		case f.loggedOut:
			st = "unauthenticated"
		case s != "" && s == f.current:
			st = "unlocked"
		}
		return write(stdout, fmt.Sprintf(`{"serverUrl":"https://vault.example.test","lastSync":"2026-10-01T00:00:00.000Z",`+
			`"userEmail":"user@example.test","userId":"00000000-0000-4000-8000-0000000000aa","status":%q}`, st))
	case "unlock":
		name := flagValue(c.args, "--passwordenv")
		if name == "" || f.password == "" || c.envVals[name] != f.password {
			_ = write(stderr, "Invalid master password.")
			return errExit
		}
		f.current = f.unlockKey
		if slices.Contains(c.args, "--raw") {
			return write(stdout, f.unlockKey)
		}
		return write(stdout, "Your vault is now unlocked!\n\n$ export "+sessionEnv+"=\""+f.unlockKey+"\"\n")
	case "get":
		if s := c.envVals[sessionEnv]; s == "" || s != f.current {
			_ = write(stderr, "Vault is locked.")
			return errExit
		}
		if len(c.pos) != 3 {
			return f.unexpected(c)
		}
		it, ok := f.items[c.pos[2]]
		if !ok {
			_ = write(stderr, "Not found.")
			return errExit
		}
		switch c.pos[1] {
		case "item":
			if it.id == "" {
				it.id = c.pos[2]
			}
			return write(stdout, itemJSON(it))
		case "totp":
			if it.totpSeed == "" {
				_ = write(stderr, "No TOTP available for this login.")
				return errExit
			}
			return write(stdout, it.totpCode+"\n")
		}
		return f.unexpected(c)
	case "lock":
		f.current = ""
		return write(stdout, "Your vault is locked.")
	}
	return f.unexpected(c)
}

func (f *fakeBW) unexpected(c *call) error {
	f.t.Errorf("unexpected bw invocation %q", c.args)
	return errExit
}

func (f *fakeBW) all() []*call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// named returns the calls whose first positional argument is sub.
func (f *fakeBW) named(sub string) []*call {
	var out []*call
	for _, c := range f.all() {
		if len(c.pos) > 0 && c.pos[0] == sub {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeBW) setHook(h hookFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

type loginJSON struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	Totp     *string `json:"totp"`
}

type itemDoc struct {
	Object string    `json:"object"`
	ID     string    `json:"id"`
	Type   int       `json:"type"`
	Name   string    `json:"name"`
	Login  loginJSON `json:"login"`
}

func itemJSON(it item) string {
	doc := itemDoc{Object: "item", ID: it.id, Type: 1, Name: "Synthetic supplier", Login: loginJSON{
		Username: it.username,
		Password: it.password,
	}}
	if it.totpSeed != "" {
		doc.Login.Totp = strp(it.totpSeed)
	}
	b, _ := json.Marshal(doc) // cannot fail: strings, ints and string pointers only
	return string(b)
}

func write(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}

// flood writes n bytes in 4 KiB chunks and returns the first write error, the
// way exec.Cmd surfaces a failing stdout writer.
func flood(w io.Writer, n int) error {
	chunk := []byte(strings.Repeat("A", 4096))
	for n > 0 {
		k := min(n, len(chunk))
		if _, err := w.Write(chunk[:k]); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

// valueFlags take the next argument as their value.
var valueFlags = map[string]bool{"--passwordenv": true, "--passwordfile": true, "--session": true}

func positional(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if valueFlags[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v
		}
	}
	return ""
}

// prompter is the interactive master-password source.
type prompter struct {
	mu  sync.Mutex
	n   int
	pw  secret.Secret
	err error
}

func (p *prompter) get(context.Context) (secret.Secret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	if p.err != nil {
		return secret.Secret{}, p.err
	}
	return p.pw, nil
}

func (p *prompter) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// vault returns a fake bw with one synthetic login item.
func vault(t testing.TB) *fakeBW {
	return &fakeBW{
		t:         t,
		password:  "synthetic-master",
		unlockKey: "synthetic-session-from-unlock",
		items: map[string]item{
			itemID: {
				username: strp("user-synthetic"),
				password: strp("pw-synthetic"),
				totpSeed: "otpauth://totp/Synthetic?secret=SYNTHETICSEEDAAA",
				totpCode: "492039",
			},
		},
	}
}

func bwRef(field string) secret.Ref {
	return secret.Ref{Scheme: "bw", Item: itemID, Field: field}
}

func newProvider(t *testing.T, opts bitwarden.Options) *bitwarden.Provider {
	t.Helper()
	p, err := bitwarden.New(opts)
	if err != nil {
		t.Fatalf("bitwarden.New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// writeArtifact stores rendered errors under ArtifactDir so make leakcheck
// greps them for canaries.
func writeArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}
