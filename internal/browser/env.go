package browser

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
