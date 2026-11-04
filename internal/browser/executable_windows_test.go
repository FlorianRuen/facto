//go:build windows

package browser_test

import "testing"

// On Windows only the platform-independent cases apply (relative, missing,
// directory); ACL checks are deferred with SEC-J0-18.
func platformExecutableCases(t *testing.T) []execCase {
	t.Helper()
	return []execCase{
		{name: "drive relative", path: `C:chrome.exe`, wantErr: true},
		{name: "rooted without drive", path: `\chrome.exe`, wantErr: true},
	}
}
