// Tests for the secret resolver handed to connectors (J1 task T17,
// SEC-J0-22). All values are synthetic.
//
// Expected API (implementer: follow exactly):
//
//	// Deps gains:
//	//	Secrets connector.SecretResolver // copied into every connector.Env; nil = none
//
// Run sets connector.Env.Secrets to Deps.Secrets for every connector. The
// orchestrator never closes the resolver: its owner (the CLI) does.
package orchestrator_test

import (
	"context"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret"
)

// recordingResolver is a synthetic connector.SecretResolver.
type recordingResolver struct{ closed bool }

func (*recordingResolver) Resolve(context.Context, string) (secret.Secret, error) {
	return secret.Secret{}, secret.ErrSecretNotFound
}

// CloseAll exists so the test can prove the orchestrator never calls it
// through a type assertion.
func (r *recordingResolver) CloseAll() error { r.closed = true; return nil }

func withSecrets(s connector.SecretResolver) rigOpt {
	return func(d *orchestrator.Deps) { d.Secrets = s }
}

func TestRun_EnvCarriesSecretResolver(t *testing.T) {
	t.Parallel()
	res := &recordingResolver{}
	r := newRunRig(t, nil, withSecrets(res))
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	bravo := newFakeConn(r.ev, "bravo", runRef("b1", 1))

	if _, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, c := range []*fakeConn{alpha, bravo} {
		envs := c.envList()
		if len(envs) != 1 {
			t.Fatalf("%s: Login called %d times, want 1", c.info.ID, len(envs))
		}
		got, ok := envs[0].Secrets.(*recordingResolver)
		if !ok || got != res {
			t.Fatalf("%s: Env.Secrets = %T, want Deps.Secrets", c.info.ID, envs[0].Secrets)
		}
	}
	if res.closed {
		t.Fatal("the orchestrator closed the resolver: only its owner may")
	}
}
