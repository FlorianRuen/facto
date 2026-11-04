//go:build unix && !(e2e && chrome && linux)

package browser_test

// runE2EMode has no helper mode outside the e2e Linux build
// (chrome_e2e_linux_test.go, tags e2e,chrome): every mode is unknown.
func runE2EMode(string) int { return 2 }
