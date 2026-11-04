package browser_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

type execCase struct {
	name    string
	path    string // built in a fresh private directory by the case setup
	wantErr bool
}

func TestExecutable_RefusesRelativeWorldWritableOrSymlinkOut(t *testing.T) {
	t.Parallel()
	cases := []execCase{
		{name: "bare name", path: "chrome", wantErr: true},
		{name: "dot relative", path: "./chrome", wantErr: true},
		{name: "parent relative", path: filepath.Join("..", "chrome"), wantErr: true},
		{name: "empty", path: "", wantErr: true},
		{name: "missing absolute", path: filepath.Join(t.TempDir(), "missing-chrome"), wantErr: true},
		{name: "directory", path: t.TempDir(), wantErr: true},
	}
	cases = append(cases, platformExecutableCases(t)...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := browser.CheckExecutable(tc.path)
			if tc.wantErr && !errors.Is(err, browser.ErrUnsafeExecutable) {
				t.Errorf("CheckExecutable(%q) = %v, want ErrUnsafeExecutable", tc.path, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CheckExecutable(%q) = %v, want nil", tc.path, err)
			}
		})
	}
}
