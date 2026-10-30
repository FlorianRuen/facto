package browser

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// allowProxyEnv is the only switch that lets Chrome use the system proxy
// settings (spec, Security; security checklist "Network").
const allowProxyEnv = "FACTO_ALLOW_PROXY"

// ProxyAllowed reports whether FACTO_ALLOW_PROXY is exactly "1". A nil
// lookup reports false.
func ProxyAllowed(lookup func(string) (string, bool)) bool {
	if lookup == nil {
		return false
	}
	v, ok := lookup(allowProxyEnv)
	return ok && v == "1"
}

// chromeEnv lists the variables passed from facto's environment to Chrome,
// built like inherited() in internal/secret/bitwarden/exec.go. None of them
// holds a secret. Never passed: proxy variables (whatever FACTO_ALLOW_PROXY
// says: --no-proxy-server is the switch), loader variables (LD_*, DYLD_*),
// SSLKEYLOGFILE, SSL_CERT_*, GOOGLE_* API keys, CHROME_LOG_FILE and
// anything unknown.
func chromeEnv() []string {
	return []string{
		"PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "LC_ALL", "TZ", "TMPDIR",
		"XDG_RUNTIME_DIR",
		// Visible window on Linux.
		"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
		// Windows.
		"SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
	}
}

// BuildEnv returns Chrome's environment ("K=V") from the fixed allowlist
// above, in its order. A nil lookup gives an empty environment.
func BuildEnv(lookup func(string) (string, bool)) []string {
	env := []string{}
	if lookup == nil {
		return env
	}
	for _, k := range chromeEnv() {
		if v, ok := lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Chrome's private XDG directories inside Options.PrivateDir.
const (
	privateConfigSubdir = "config"
	privateCacheSubdir  = "cache"
	privateDataSubdir   = "data"
	privateStateSubdir  = "state"
)

// privateXDG maps each XDG base directory variable Chrome (and the
// libraries it loads: fontconfig, dconf, GTK) writes under to its subdir of
// the private area.
var privateXDG = []struct{ env, sub string }{
	{"XDG_CONFIG_HOME", privateConfigSubdir},
	{"XDG_CACHE_HOME", privateCacheSubdir},
	{"XDG_DATA_HOME", privateDataSubdir},
	{"XDG_STATE_HOME", privateStateSubdir},
}

// BuildLaunchEnv is BuildEnv with TMPDIR set to tmp when tmp is not "",
// and XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME and XDG_STATE_HOME set
// to <private>/config, cache, data and state when private is not "". HOME, DISPLAY and the other
// allowlisted variables are kept: fonts and the display keep working.
func BuildLaunchEnv(lookup func(string) (string, bool), private, tmp string) []string {
	env := BuildEnv(lookup)
	if tmp != "" {
		env = slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "TMPDIR=") })
		env = append(env, "TMPDIR="+tmp)
	}
	if private != "" {
		for _, x := range privateXDG {
			env = append(env, x.env+"="+filepath.Join(private, x.sub))
		}
	}
	return env
}

// singletonSocketSuffix is what Chrome appends to its TMPDIR for the
// ProcessSingleton socket (base::CreateNewTempDirectory, then
// SingletonSocket); the six X are random characters.
const singletonSocketSuffix = "/org.chromium.Chromium.XXXXXX/SingletonSocket"

// maxSocketPath is the longest unix socket path on Linux: sun_path is 108
// bytes, NUL included.
const maxSocketPath = 107

// socketPathFits reports whether a TMPDIR of tmp leaves Chrome's
// SingletonSocket path within maxSocketPath.
func socketPathFits(tmp string) bool {
	return len(tmp)+len(singletonSocketSuffix) <= maxSocketPath
}

// checkSocketPath fails with ErrSocketPathTooLong when Chrome, launched on
// goos with env, would get a SingletonSocket path over the limit. Linux
// only: Chrome on macOS takes its temp dir from NSTemporaryDirectory and
// Windows has no unix socket there.
func checkSocketPath(goos string, env []string) error {
	if goos != goosLinux {
		return nil
	}
	tmp := "/tmp" // base::GetTempDir without TMPDIR
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "TMPDIR="); ok {
			tmp = v
		}
	}
	if socketPathFits(tmp) {
		return nil
	}
	return fmt.Errorf("%w: Chrome's TMPDIR is %d bytes, so its SingletonSocket "+
		"(<TMPDIR>%s) would be %d bytes, over the %d-byte unix socket limit; "+
		"set XDG_RUNTIME_DIR, or use a shorter TMPDIR or state_dir",
		ErrSocketPathTooLong, len(tmp), singletonSocketSuffix,
		len(tmp)+len(singletonSocketSuffix), maxSocketPath)
}
