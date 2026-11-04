//go:build !unix

package browser

// checkRuntimeDir has no meaning outside unix: XDG_RUNTIME_DIR is a unix
// convention and ownership/ACL checks are deferred with SEC-J0-18.
func checkRuntimeDir(Host, string) error { return nil }

// checkBaseOwner does not apply outside unix (SEC-J0-18).
func checkBaseOwner(Host, string) error { return nil }
