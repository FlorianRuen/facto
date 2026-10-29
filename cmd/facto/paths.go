package main

import (
	"errors"
	"path/filepath"
	"runtime"
)

// runtimeGOOS is the OS the default config path is resolved for.
const runtimeGOOS = runtime.GOOS

// configFile is the config file name inside the config directory.
const configFile = "config.yaml"

// errNoConfigDir reports that no config directory can be derived from the
// injected environment.
var errNoConfigDir = errors.New("no config directory: pass --config")

// configPathFor returns the default config.yaml path for goos from the
// injected home and environment only (docs/spec.md "Configuration"):
// %APPDATA%\facto on Windows, <home>/Library/Application Support/facto on
// macOS, and $XDG_CONFIG_HOME/facto (default <home>/.config/facto)
// elsewhere. Relative environment values are ignored, as the XDG spec asks.
func configPathFor(goos string, e env) (string, error) {
	lookup := func(k string) string {
		if e.LookupEnv == nil {
			return ""
		}
		v, ok := e.LookupEnv(k)
		if !ok || !filepath.IsAbs(v) {
			return ""
		}
		return v
	}
	var base string
	switch goos {
	case "windows":
		base = lookup("APPDATA")
		if base == "" && e.Home != "" {
			base = filepath.Join(e.Home, "AppData", "Roaming")
		}
	case "darwin":
		if e.Home != "" {
			base = filepath.Join(e.Home, "Library", "Application Support")
		}
	default:
		base = lookup("XDG_CONFIG_HOME")
		if base == "" && e.Home != "" {
			base = filepath.Join(e.Home, ".config")
		}
	}
	if base == "" || !filepath.IsAbs(base) {
		return "", errNoConfigDir
	}
	return filepath.Join(base, "facto", configFile), nil
}
