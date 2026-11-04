package orchestrator

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestErrAttr_NeverRendersSecretsOrReferences pins the log form of a connector
// error (CodeQL #14): logged as a cleaned string, never as the raw error value,
// so a canary secret or a credential reference wrapped anywhere in the chain
// never reaches a log line, while the classification stays readable.
func TestErrAttr_NeverRendersSecretsOrReferences(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	ref := "bw://00000000-0000-0000-0000-000000000000/password"

	tests := []struct {
		name string
		err  error
		want string // a fragment the cleaned text must keep
	}{
		{
			name: "token in a wrapped connector error",
			err:  fmt.Errorf("login: %w: server said token=%s", connector.ErrAuthFailed, tok),
			want: "authentication failed",
		},
		{
			name: "bearer header in the chain",
			err:  fmt.Errorf("list: %w", fmt.Errorf("%w: Authorization: Bearer %s", connector.ErrBroken, tok)),
			want: "broken",
		},
		{
			name: "credential reference in a resolver error",
			err:  fmt.Errorf("login: %w: resolve password %s: %w", connector.ErrNeedsLogin, ref, errors.New("not found")),
			want: "needs login",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := errAttr(tc.err)
			if a.Key != "error" {
				t.Errorf("errAttr key = %q, want \"error\"", a.Key)
			}
			if a.Value.Kind().String() != "String" {
				t.Fatalf("errAttr value kind = %v, want a String (never the raw error value)", a.Value.Kind())
			}
			got := a.Value.String()
			if strings.Contains(got, tok) {
				t.Errorf("errAttr = %q holds the canary token", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("errAttr = %q, want it to keep %q", got, tc.want)
			}
		})
	}

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()
		if got := errAttr(nil).Value.String(); got != "" {
			t.Errorf("errAttr(nil) = %q, want empty", got)
		}
	})
}
