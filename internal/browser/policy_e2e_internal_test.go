//go:build e2e

package browser

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testSPKI = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// e2ePolicy returns the argv policy WithE2E installs for a pool mapping the
// exact allowed hosts to 127.0.0.1:8443.
func e2ePolicy(t *testing.T) *argvPolicy {
	t.Helper()
	cfg, err := WithE2E(PoolConfig{}, PoolE2E{LoopbackPort: 8443, TestCASPKI: []string{testSPKI}})
	if err != nil {
		t.Fatalf("WithE2E: %v", err)
	}
	if cfg.flags == nil {
		t.Fatal("WithE2E set no argv policy")
	}
	return cfg.flags
}

func e2eOpts(goos, profile string) Options {
	return Options{GOOS: goos, ProfileDir: profile, AllowedDomains: []string{"www.supplier.example", "*.cdn.supplier.example"}}
}

// TestWithE2E_PolicyBuildsAndVetsE2EArgv (J1 T22): the pool policy maps
// only the exact allowed hosts, trusts the test CA, and its check accepts
// what its build produced, on every OS, while the release CheckFlags still
// refuses that argv.
func TestWithE2E_PolicyBuildsAndVetsE2EArgv(t *testing.T) {
	t.Parallel()
	pol := e2ePolicy(t)
	for _, tc := range []struct{ goos, profile string }{{"linux", "/facto-test/profile"}, {"darwin", "/facto-test/profile"}, {"windows", `C:\facto-test\profile`}} {
		o := e2eOpts(tc.goos, tc.profile)
		args, err := pol.build(o)
		if err != nil {
			t.Fatalf("%s: build: %v", tc.goos, err)
		}
		joined := strings.Join(args, "\n")
		if !strings.Contains(joined, "MAP www.supplier.example 127.0.0.1:8443") || strings.Contains(joined, "cdn.supplier.example 127.0.0.1") {
			t.Errorf("%s: loopback mapping = %q, want the exact host only", tc.goos, args)
		}
		if !slices.Contains(args, "--ignore-certificate-errors-spki-list="+testSPKI) {
			t.Errorf("%s: SPKI flag missing in %q", tc.goos, args)
		}
		if err := pol.check(o, args); err != nil {
			t.Errorf("%s: policy check refused its own argv: %v", tc.goos, err)
		}
		if err := CheckFlags(tc.goos, args); !errors.Is(err, ErrForbiddenFlag) {
			t.Errorf("%s: release CheckFlags accepted the e2e argv: %v", tc.goos, err)
		}
	}
}

// TestCheckFlagsE2E_RefusesTampering: anything beyond the declared
// overrides is refused.
func TestCheckFlagsE2E_RefusesTampering(t *testing.T) {
	t.Parallel()
	pol := e2ePolicy(t)
	o := e2eOpts("linux", "/facto-test/profile")
	args, err := pol.build(o)
	if err != nil {
		t.Fatal(err)
	}
	replace := func(prefix, v string) []string {
		out := slices.Clone(args)
		for i, a := range out {
			if strings.HasPrefix(a, prefix) {
				out[i] = v
			}
		}
		return out
	}
	without := func(prefix string) []string {
		return slices.DeleteFunc(slices.Clone(args), func(a string) bool { return strings.HasPrefix(a, prefix) })
	}
	tests := []struct {
		name string
		args []string
	}{
		{"other SPKI", replace("--ignore-certificate-errors-spki-list=", "--ignore-certificate-errors-spki-list=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")},
		{"SPKI missing", without("--ignore-certificate-errors-spki-list=")},
		{"SPKI twice", append(slices.Clone(args), "--ignore-certificate-errors-spki-list="+testSPKI)},
		{"other port", replace("--host-resolver-rules=", "--host-resolver-rules=MAP www.supplier.example 127.0.0.1:9443, MAP * ~NOTFOUND")},
		{"other target", replace("--host-resolver-rules=", "--host-resolver-rules=MAP www.supplier.example 10.0.0.1:8443, MAP * ~NOTFOUND")},
		{"unlisted host mapped", replace("--host-resolver-rules=", "--host-resolver-rules=MAP www.supplier.example 127.0.0.1:8443, MAP evil.test 127.0.0.1:8443, MAP * ~NOTFOUND")},
		{"host mapped twice", replace("--host-resolver-rules=", "--host-resolver-rules=MAP www.supplier.example 127.0.0.1:8443, MAP www.supplier.example 127.0.0.1:8443, MAP * ~NOTFOUND")},
		{"host not mapped", replace("--host-resolver-rules=", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE www.supplier.example")},
		{"sandbox off", append(slices.Clone(args), "--no-sandbox")},
		{"unknown switch", append(slices.Clone(args), "--remote-allow-origins=*")},
	}
	for _, tt := range tests {
		if err := pol.check(o, tt.args); !errors.Is(err, ErrForbiddenFlag) && !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("%s: check = %v, want ErrForbiddenFlag", tt.name, err)
		}
	}
}

// TestWithE2E_RefusesBadConfig: port out of range, no or malformed SPKI.
func TestWithE2E_RefusesBadConfig(t *testing.T) {
	t.Parallel()
	for _, e := range []PoolE2E{
		{LoopbackPort: 0, TestCASPKI: []string{testSPKI}},
		{LoopbackPort: 65536, TestCASPKI: []string{testSPKI}},
		{LoopbackPort: 8443},
		{LoopbackPort: 8443, TestCASPKI: []string{"not-base64"}},
	} {
		if _, err := WithE2E(PoolConfig{}, e); !errors.Is(err, ErrForbiddenFlag) {
			t.Errorf("WithE2E(%+v) = %v, want ErrForbiddenFlag", e, err)
		}
	}
}

// TestPortArgvProfile_E2EPolicy (J1 T22): the windows port Starter re-vets
// the argv with the Command's check. A Command from an e2e argvPolicy
// carries the e2e check, so its argv is accepted; without one (every
// release Command) the release CheckFlags still refuses the same argv.
func TestPortArgvProfile_E2EPolicy(t *testing.T) {
	t.Parallel()
	pol := e2ePolicy(t)
	o := e2eOpts("windows", `C:\facto-test\profile`)
	args, err := pol.build(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := portArgvProfile(args, nil); !errors.Is(err, ErrForbiddenFlag) {
		t.Errorf("release port check accepted the e2e argv: %v", err)
	}
	got, err := portArgvProfile(args, func(a []string) error { return pol.check(o, a) })
	if err != nil {
		t.Fatalf("e2e port check: %v", err)
	}
	if got != o.ProfileDir {
		t.Errorf("profile = %q, want %q", got, o.ProfileDir)
	}
}

// TestPrepareWith_CommandCarriesPolicyCheck: prepareWith hands the
// policy's check to the Starter through Command.checkArgs; Prepare (the
// release path) never sets one.
func TestPrepareWith_CommandCarriesPolicyCheck(t *testing.T) {
	t.Parallel()
	exe := fakeExecutable(t)
	h := Host{Executable: exe, Geteuid: func() int { return 1000 }, Owner: func(string) (int, error) { return 1000, nil }}
	o := e2eOpts("linux", "/facto-test/profile")
	rel, err := Prepare(h, Options{GOOS: "linux", ProfileDir: o.ProfileDir, AllowedDomains: o.AllowedDomains})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if rel.checkArgs != nil {
		t.Error("release Command carries an argv check")
	}
	cmd, err := prepareWith(h, o, e2ePolicy(t))
	if err != nil {
		t.Fatalf("prepareWith: %v", err)
	}
	if cmd.checkArgs == nil {
		t.Fatal("e2e Command carries no argv check")
	}
	if err := cmd.checkArgs(cmd.Args); err != nil {
		t.Errorf("e2e Command check refused its argv: %v", err)
	}
	if err := cmd.checkArgs(append(slices.Clone(cmd.Args), "--no-sandbox")); !errors.Is(err, ErrForbiddenFlag) {
		t.Errorf("e2e Command check accepted --no-sandbox: %v", err)
	}
}

// fakeExecutable returns the resolved path of the running test binary: a
// regular executable file the checks accept (owner stubbed by the caller).
func fakeExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
