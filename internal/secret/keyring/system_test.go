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

// TestSystemBackend_SetAndDelete checks the go-keyring adapter for Set and
// Delete (T15) with injected functions: go-keyring's ErrNotFound on Delete
// maps to ErrNotFound, other errors are wrapped as is (Provider hides their
// text). The real keyring is never touched.
func TestSystemBackend_SetAndDelete(t *testing.T) {
	t.Parallel()
	errDBus := errors.New("dbus: no secret service")
	var gotSet [3]string
	b := goBackend{
		get: func(string, string) (string, error) { return "", errors.New("get must not be called") },
		set: func(s, u, v string) error {
			gotSet = [3]string{s, u, v}
			return nil
		},
		del: func(s, u string) error {
			switch {
			case s == "facto" && u == "missing":
				return gokeyring.ErrNotFound
			case s == "facto" && u == "broken":
				return errDBus
			case s == "facto" && u == "ileo":
				return nil
			}
			return errors.New("wrong delete")
		},
	}
	if err := b.Set("facto", "ileo", "synthetic"); err != nil || gotSet != [3]string{"facto", "ileo", "synthetic"} {
		t.Errorf("Set = %v, backend got %q", err, gotSet)
	}
	if err := b.Delete("facto", "ileo"); err != nil {
		t.Errorf("Delete existing = %v, want nil", err)
	}
	if err := b.Delete("facto", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing = %v, want ErrNotFound", err)
	}
	if err := b.Delete("facto", "broken"); !errors.Is(err, errDBus) || errors.Is(err, ErrNotFound) {
		t.Errorf("Delete broken = %v, want the backend error, not ErrNotFound", err)
	}
	setErr := goBackend{set: func(string, string, string) error { return errDBus }}
	if err := setErr.Set("facto", "ileo", "synthetic"); !errors.Is(err, errDBus) {
		t.Errorf("Set error = %v, want the backend error", err)
	}
}
