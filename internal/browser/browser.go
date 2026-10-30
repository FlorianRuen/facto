// Package browser launches and drives the disposable Chrome used for
// supplier logins (ADR 0008). This file holds the sentinel errors; the
// launch flags, the release flag check, the executable checks and the
// launcher live next to it.
package browser

import "errors"

// Sentinel errors, errors.Is targets.
var (
	// ErrForbiddenFlag: argv holds a deny-listed, unknown, test-only,
	// duplicate or positional argument.
	ErrForbiddenFlag = errors.New("browser: forbidden chrome flag")
	// ErrNoProfileDir: Options.ProfileDir is empty, relative, not clean or
	// holds a control character.
	ErrNoProfileDir = errors.New("browser: invalid or missing profile directory")
	// ErrInvalidDomain: an AllowedDomains entry is refused (httpx rules, IP
	// literals, loopback names, characters that could alter a flag value).
	ErrInvalidDomain = errors.New("browser: invalid allowed domain")
	// ErrUnsupportedOS: Options.GOOS is not linux, darwin or windows.
	ErrUnsupportedOS = errors.New("browser: unsupported operating system")
	// ErrUnsafeExecutable: the browser executable is relative, missing, not a
	// regular executable file, writable by others, or in (or linked to) a
	// directory others can write.
	ErrUnsafeExecutable = errors.New("browser: unsafe browser executable")
	// ErrRunAsRoot: facto refuses to start Chrome as euid 0, or when the
	// effective uid cannot be read (fail closed).
	ErrRunAsRoot = errors.New("browser: refusing to launch chrome as root")
	// ErrNoUsableSandbox: Chrome reported "No usable sandbox". The fix is
	// outside facto; the launch is never retried with weaker flags.
	ErrNoUsableSandbox = errors.New("browser: chrome has no usable sandbox")
	// ErrLaunchFailed: any other start failure.
	ErrLaunchFailed = errors.New("browser: chrome launch failed")
	// ErrSocketPathTooLong: the TMPDIR Chrome would get leaves its
	// SingletonSocket path (<TMPDIR>/org.chromium.Chromium.XXXXXX/
	// SingletonSocket) over the unix socket path limit (107 bytes on
	// Linux): Chrome would exit at once. Checked before Chrome starts.
	ErrSocketPathTooLong = errors.New("browser: chrome singleton socket path too long")
)
