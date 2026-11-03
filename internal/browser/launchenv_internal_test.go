package browser

// Internal checks of the private launch dirs (J1 T23): the Pool-only
// Options.privateDir and Options.tempDir are vetted like ProfileDir, and a
// private TMPDIR over the SingletonSocket limit is refused before Chrome
// starts.

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPrepareWith_PrivateDirs(t *testing.T) {
	t.Parallel()
	base := "/facto-test/"
	limit := maxSocketPath - len(singletonSocketSuffix)
	long := func(n int) string { return base + strings.Repeat("d", n-len(base)) }
	tests := []struct {
		name          string
		private, tmp  string
		wantErr       error
		wantTMP       string
		wantConfigDir string
	}{
		{name: "private TMPDIR at the limit", private: long(limit), tmp: long(limit), wantTMP: long(limit), wantConfigDir: long(limit) + "/config"},
		{name: "private TMPDIR one byte over", private: long(limit + 1), tmp: long(limit + 1), wantErr: ErrSocketPathTooLong},
		{name: "relative private dir", private: "rel/area", wantErr: ErrNoProfileDir},
		{name: "relative TMPDIR", tmp: "rel/tmp", wantErr: ErrNoProfileDir},
		{name: "unclean private dir", private: "/facto-test/a/../b", wantErr: ErrNoProfileDir},
		{name: "control character", tmp: "/facto-test/t\n", wantErr: ErrNoProfileDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{GOOS: goosLinux, ProfileDir: "/facto-test/profile", AllowedDomains: []string{"login.supplier.example"}, privateDir: tt.private, tempDir: tt.tmp}
			env, err := launchEnv(func(string) (string, bool) { return "", false }, opts)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("launchEnv = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("launchEnv: %v", err)
			}
			if !slices.Contains(env, "TMPDIR="+tt.wantTMP) || !slices.Contains(env, "XDG_CONFIG_HOME="+tt.wantConfigDir) {
				t.Errorf("env = %q, want TMPDIR=%s and XDG_CONFIG_HOME=%s", env, tt.wantTMP, tt.wantConfigDir)
			}
		})
	}
}

// TestLaunchEnv_PrivateDirsInTargetSyntax: the private XDG paths are joined
// in the path syntax of Options.GOOS, the one the private dir was vetted
// in, whatever the host: a launch never mixes '/' and '\'.
func TestLaunchEnv_PrivateDirsInTargetSyntax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		goos, profile, private string
		want                   map[string]string
	}{
		{
			goos: goosLinux, profile: "/facto-test/profile", private: "/facto-test/area",
			want: map[string]string{
				"TMPDIR":          "/facto-test/area",
				"XDG_CONFIG_HOME": "/facto-test/area/config",
				"XDG_CACHE_HOME":  "/facto-test/area/cache",
				"XDG_DATA_HOME":   "/facto-test/area/data",
				"XDG_STATE_HOME":  "/facto-test/area/state",
			},
		},
		{
			goos: goosDarwin, profile: "/facto-test/profile", private: "/facto-test/area",
			want: map[string]string{
				"TMPDIR":          "/facto-test/area",
				"XDG_CONFIG_HOME": "/facto-test/area/config",
				"XDG_CACHE_HOME":  "/facto-test/area/cache",
				"XDG_DATA_HOME":   "/facto-test/area/data",
				"XDG_STATE_HOME":  "/facto-test/area/state",
			},
		},
		{
			goos: goosWindows, profile: `C:\facto-test\profile`, private: `C:\facto-test\area`,
			want: map[string]string{
				"TMPDIR":          `C:\facto-test\area`,
				"XDG_CONFIG_HOME": `C:\facto-test\area\config`,
				"XDG_CACHE_HOME":  `C:\facto-test\area\cache`,
				"XDG_DATA_HOME":   `C:\facto-test\area\data`,
				"XDG_STATE_HOME":  `C:\facto-test\area\state`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			t.Parallel()
			opts := Options{GOOS: tt.goos, ProfileDir: tt.profile, AllowedDomains: []string{"login.supplier.example"}, privateDir: tt.private, tempDir: tt.private}
			env, err := launchEnv(func(string) (string, bool) { return "", false }, opts)
			if err != nil {
				t.Fatalf("launchEnv: %v", err)
			}
			for k, v := range tt.want {
				if !slices.Contains(env, k+"="+v) {
					t.Errorf("env = %q, want %s=%s", env, k, v)
				}
			}
		})
	}
}
