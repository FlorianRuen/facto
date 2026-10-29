package keyring

import (
	"errors"
	"testing"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/FlorianRuen/facto/internal/secret"
)

// TestSystemBackend checks the go-keyring adapter with an injected getter:
// the real keyring is never touched.
func TestSystemBackend(t *testing.T) {
	t.Parallel()
	if _, ok := System().(goBackend); !ok {
		t.Fatal("System() is not the go-keyring adapter")
	}
	errDBus := errors.New("dbus: no secret service")
	tests := []struct {
		name    string
		get     func(service, user string) (string, error)
		want    string
		wantErr error
	}{
		{name: "value", get: func(s, u string) (string, error) {
			if s != "facto" || u != "ileo/login" {
				return "", errors.New("wrong lookup")
			}
			return "synthetic", nil
		}, want: "synthetic"},
		{name: "not found", get: func(string, string) (string, error) { return "", gokeyring.ErrNotFound }, wantErr: secret.ErrSecretNotFound},
		{name: "other error", get: func(string, string) (string, error) { return "leak", errDBus }, wantErr: errDBus},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := goBackend{get: tc.get}.Get("facto", "ileo/login")
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Get error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Get = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBackendErrorGoString(t *testing.T) {
	t.Parallel()
	e := &backendError{err: errors.New("synthetic-inner")}
	if e.GoString() != "keyring: backend error" {
		t.Fatalf("GoString = %q", e.GoString())
	}
}
