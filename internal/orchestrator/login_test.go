// Tests for Deps.Prompt, Deps.Credentials and Login (J1 task T19: `facto
// login <id>`). Everything is synthetic.
package orchestrator_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret"
)

// stubPrompter is a connector.Prompter that never reads anything.
type stubPrompter struct{ interactive bool }

func (p stubPrompter) Prompt(context.Context, connector.PromptRequest) (secret.Secret, error) {
	return secret.Secret{}, connector.ErrNeedsLogin
}

func (p stubPrompter) Interactive() bool { return p.interactive }

// TestRun_EnvCarriesPromptAndCredentials: every Env gets Deps.Prompt,
// Interactive = Prompt.Interactive() and the connector's own references.
func TestRun_EnvCarriesPromptAndCredentials(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		prompt      connector.Prompter
		interactive bool
	}{
		{name: "no prompter"},
		{name: "non-interactive", prompt: stubPrompter{}},
		{name: "interactive", prompt: stubPrompter{interactive: true}, interactive: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loginRef, otherRef := "keyring://synthetic/alpha-login", "keyring://synthetic/alpha-other"
			creds := map[string]connector.Credentials{"alpha": {Login: loginRef, Password: otherRef}}
			r := newRunRig(t, nil, func(d *orchestrator.Deps) {
				d.Prompt = tt.prompt
				d.Credentials = creds
			})
			// The orchestrator keeps its own copy.
			creds["alpha"] = connector.Credentials{}
			alpha := newFakeConn(r.ev, "alpha")
			beta := newFakeConn(r.ev, "beta")
			if _, err := r.o.Run(t.Context(), registry(t, alpha, beta), period2026); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			a, b := alpha.envList(), beta.envList()
			if len(a) != 1 || len(b) != 1 {
				t.Fatalf("Login calls = %d, %d; want 1 each", len(a), len(b))
			}
			if a[0].Credentials.Password != otherRef || a[0].Credentials.Login != loginRef {
				t.Errorf("alpha credentials = %+v, want its configured references", a[0].Credentials)
			}
			if b[0].Credentials != (connector.Credentials{}) {
				t.Errorf("beta credentials = %+v, want none", b[0].Credentials)
			}
			for _, env := range []connector.Env{a[0], b[0]} {
				if env.Prompt != tt.prompt || env.Interactive != tt.interactive {
					t.Errorf("Env.Prompt = %v, Interactive = %v; want %v, %v", env.Prompt, env.Interactive, tt.prompt, tt.interactive)
				}
			}
		})
	}
}

// TestLogin_FreshLoginSavedNoListing: Login ignores a saved session, saves
// a Persistable one and never lists or fetches; it needs no index,
// destination or namer.
func TestLogin_FreshLoginSavedNoListing(t *testing.T) {
	t.Parallel()
	ev := &events{}
	sessions := newFakeSessions(ev, true)
	sessions.blobs["alpha"] = "synthetic-old-blob"
	pool := &fakePool{ev: ev}
	sess := &persistSession{blob: "synthetic-new-blob"}
	alpha := newSessConn(ev, "alpha", sess, runRef("a1", 1))
	ref := "keyring://synthetic/alpha"
	alpha.onLogin = func(ctx context.Context, env connector.Env) {
		b, err := env.Browser.Launch(ctx, connector.LaunchOptions{AllowedDomains: []string{"evil.example"}, Visible: true})
		if err == nil {
			_ = b.Close()
		}
	}

	res := orchestrator.Login(t.Context(), orchestrator.Deps{
		Sessions:    sessions,
		Browser:     pool,
		Prompt:      stubPrompter{interactive: true},
		Credentials: map[string]connector.Credentials{"alpha": {Password: ref}},
	}, alpha)
	if res.ID != "alpha" || res.State != orchestrator.StateOK || len(res.Documents) != 0 {
		t.Fatalf("Login result = %+v, want alpha ok without documents", res)
	}
	loads, saves, _ := sessions.calls()
	if len(loads) != 0 {
		t.Errorf("Load = %q, want none (a fresh login)", loads)
	}
	if !slices.Equal(saves, []string{"alpha"}) {
		t.Errorf("Save = %q, want alpha", saves)
	}
	if b, _ := sessions.blob("alpha"); b != "synthetic-new-blob" {
		t.Errorf("saved blob differs from the Persisted one")
	}
	if _, zero := alpha.savedSeen(); !slices.Equal(zero, []bool{true}) {
		t.Errorf("Env.Saved zero = %v, want [true]", zero)
	}
	if got := ev.withPrefix("list:"); len(got) != 0 {
		t.Errorf("List called: %q", got)
	}
	if fetched := alpha.fetchedList(); len(fetched) != 0 {
		t.Errorf("Fetch called: %q", fetched)
	}
	opts, _ := pool.launched()
	if len(opts) != 1 || !slices.Equal(opts[0].AllowedDomains, []string{"billing.alpha.example"}) {
		t.Errorf("launches = %+v, want one on the connector's allowlist", opts)
	}
	env := alpha.envList()[0]
	if !env.Interactive || env.Credentials.Password != ref {
		t.Errorf("Env.Interactive = %v, Credentials = %+v", env.Interactive, env.Credentials)
	}
}

// TestLogin_FailureStates: a Login error ends in its sentinel state (else
// broken), a panic is recovered as broken, a canceled run is interrupted;
// nothing is saved.
func TestLogin_FailureStates(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		loginErr error
		panics   bool
		cancel   bool
		want     orchestrator.State
	}{
		{name: "auth failed", loginErr: connector.ErrAuthFailed, want: orchestrator.StateAuthFailed},
		{name: "needs login", loginErr: connector.ErrNeedsLogin, want: orchestrator.StateNeedsLogin},
		{name: "other error", loginErr: errors.New("synthetic"), want: orchestrator.StateBroken},
		{name: "panic", panics: true, want: orchestrator.StateBroken},
		{name: "canceled", cancel: true, want: orchestrator.StateInterrupted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, true)
			alpha := newSessConn(ev, "alpha", &persistSession{blob: "synthetic-blob"})
			alpha.loginErr = tt.loginErr
			if tt.panics {
				alpha.panicAt, alpha.panicVal = stageLogin, "synthetic panic"
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				alpha.onLogin = func(context.Context, connector.Env) { cancel() }
			}
			res := orchestrator.Login(ctx, orchestrator.Deps{Sessions: sessions}, alpha)
			if res.State != tt.want {
				t.Fatalf("state = %q, want %q", res.State, tt.want)
			}
			if _, saves, _ := sessions.calls(); len(saves) != 0 {
				t.Errorf("Save = %q, want none", saves)
			}
		})
	}
}
