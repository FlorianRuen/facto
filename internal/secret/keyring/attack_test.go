// Red-team attack tests for the keyring provider (J0 task T30): hand-built
// references aimed at other keyring entries, and backend errors carrying the
// value pushed through the whole production chain (Resolver, then the
// redacting logx handler into a log file under testsecrets.ArtifactDir).
// Uses fakeBackend and writeArtifact from keyring_test.go. A test passes
// when the attack is defeated. The real keyring is never touched.
package keyring_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestAttack_KeyringHandBuiltRefsNeverReachBackend calls Resolve directly
// (no Resolver, no ParseRef) with Refs that would read another entry of the
// user's keyring: another service, a key with traversal or separators, a
// NUL, Unicode look-alikes, or the wrong scheme. The backend must never be
// asked.
func TestAttack_KeyringHandBuiltRefsNeverReachBackend(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	b := &fakeBackend{values: map[[2]string]string{
		{"facto", "ileo/password"}: "value-synthetic",
		{"login.example", "token"}: canary, // another program's entry
	}}
	p := keyring.New(b)
	refs := map[string]secret.Ref{
		"service with slash":     {Scheme: "keyring", Item: "facto/../login.example", Field: "token"},
		"key traversal":          {Scheme: "keyring", Item: "facto", Field: "../login.example/token"},
		"absolute key":           {Scheme: "keyring", Item: "facto", Field: "/token"},
		"NUL in service":         {Scheme: "keyring", Item: "login.example\x00facto", Field: "token"},
		"NUL in key":             {Scheme: "keyring", Item: "facto", Field: "ileo/password\x00"},
		"space in service":       {Scheme: "keyring", Item: "login.example ", Field: "token"},
		"unicode dot in service": {Scheme: "keyring", Item: "login․example", Field: "token"},
		"empty service":          {Scheme: "keyring", Item: "", Field: "token"},
		"dot service":            {Scheme: "keyring", Item: ".", Field: "token"},
		"wrong scheme":           {Scheme: "bw", Item: "login.example", Field: "token"},
		"empty scheme":           {Scheme: "", Item: "login.example", Field: "token"},
		"trailing slash in key":  {Scheme: "keyring", Item: "login.example", Field: "token/"},
	}
	for name, ref := range refs {
		s, err := p.Resolve(t.Context(), ref)
		if !errors.Is(err, secret.ErrInvalidRef) {
			t.Errorf("%s: Resolve = %d bytes, %v; want ErrInvalidRef", name, len(s.Expose()), err)
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), canary) {
			t.Errorf("%s: error carries the other entry's value", name)
		}
	}
	if calls := b.callLog(); len(calls) != 0 {
		t.Errorf("backend reached by hostile refs: %q", calls)
	}
}

// TestAttack_KeyringBackendErrorsNeverReachLogs makes the backend fail with
// messages that quote the value (as some OS keyring errors quote the item
// data), resolves through a Resolver and logs the error the way the
// orchestrator would. Neither the error text nor the log may hold the value.
func TestAttack_KeyringBackendErrorsNeverReachLogs(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	backends := map[string]*fakeBackend{
		"plain error":               {err: errors.New("dbus: secret " + canary + " locked")},
		"joined errors":             {err: errors.Join(errors.New("first"), errors.New("item data: "+canary))},
		"not-found quoting value":   {err: fmt.Errorf("no match for %s: %w", canary, keyring.ErrNotFound)},
		"value returned with error": {err: errors.New("partial read"), valueWithErr: canary},
		"secret-not-found wrapped":  {err: fmt.Errorf("%s: %w", canary, secret.ErrSecretNotFound)},
	}
	var logBuf bytes.Buffer
	log := slog.New(logx.NewHandler(slog.NewJSONHandler(&logBuf, nil), logx.Options{}))
	var rendered strings.Builder
	for name, b := range backends {
		r, err := secret.NewResolver(keyring.New(b))
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
		s, rerr := r.Resolve(t.Context(), "keyring://facto/ileo/password")
		if rerr == nil {
			t.Errorf("%s: Resolve = nil error", name)
			continue
		}
		if !s.IsZero() {
			t.Errorf("%s: non-empty Secret returned with an error", name)
		}
		log.Error("resolve credentials", "connector", "ileo", "err", rerr, slog.Any("cause", rerr))
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(verb, rerr)
			fmt.Fprintf(&rendered, "%s %s: %s\n", name, verb, out)
			if strings.Contains(out, canary) {
				t.Errorf("%s: error formatted with %s holds the value", name, verb)
			}
		}
	}
	writeArtifact(t, "keyring-attack-errors.txt", rendered.String())
	writeArtifact(t, "keyring-attack.log", logBuf.String())
	if strings.Contains(logBuf.String(), canary) {
		t.Error("log holds the keyring value")
	}
}
