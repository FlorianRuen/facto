// Red-team attack tests for package secret (J0 task T30): renderings the
// T10 tests do not cover (templates, YAML, gob, reflect, deep nesting), an
// unrecovered panic carrying a Secret in a real child process (panic value
// and goroutine traceback), hostile reference strings, and hand-built Refs
// pushed straight into a Resolver. Uses writeArtifact from secret_test.go;
// every output is written under testsecrets.ArtifactDir so `make leakcheck`
// greps it. A test passes when the attack is defeated. Everything is
// synthetic.
package secret_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	texttemplate "text/template"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/FlorianRuen/facto/internal/cputime"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkUUID is the synthetic vault item id of the spec examples.
const atkUUID = "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"

// atkLogin is a connector-side struct that carries a Secret the ways real
// code would: exported, unexported, behind pointers, in containers.
type atkLogin struct {
	User     string
	Password secret.Secret
	Ptr      *secret.Secret
	List     []secret.Secret
	ByName   map[string]secret.Secret
	hidden   secret.Secret
	deep     struct{ s *secret.Secret }
}

// TestAttack_SecretRenderingsBeyondFmtNeverExposeValue renders a canary
// Secret through the encoders and printers a connector could reach for:
// text/template and html/template, YAML (the config library), gob, reflect
// values handed to fmt, and %v/%+v/%#v of a struct holding it in exported,
// unexported, pointer, slice and map fields.
func TestAttack_SecretRenderingsBeyondFmtNeverExposeValue(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	s := secret.FromString(canary)
	login := atkLogin{
		User: "user-synthetic", Password: s, Ptr: &s,
		List: []secret.Secret{s}, ByName: map[string]secret.Secret{"pw": s}, hidden: s,
	}
	login.deep.s = &s

	out := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T", "%p"} {
		out["struct "+verb] = fmt.Sprintf(verb, login)
		out["*struct "+verb] = fmt.Sprintf(verb, &login)
		out["reflect "+verb] = fmt.Sprintf(verb, reflect.ValueOf(login))
		out["reflect field "+verb] = fmt.Sprintf(verb, reflect.ValueOf(login).FieldByName("hidden"))
	}

	tt := texttemplate.Must(texttemplate.New("t").Parse(
		"{{.}} {{.Password}} {{.Ptr}} {{index .List 0}} {{.ByName.pw}} {{printf \"%#v\" .Password}} {{js .Password}} {{urlquery .Password}}"))
	var tb bytes.Buffer
	if err := tt.Execute(&tb, login); err != nil {
		t.Fatalf("text/template: %v", err)
	}
	out["text/template"] = tb.String()

	ht := htmltemplate.Must(htmltemplate.New("h").Parse(
		`<p title="{{.Password}}">{{.Password}}</p><a href="/x?p={{.Password}}">x</a><script>var p = {{.Password}};</script>`))
	var hb bytes.Buffer
	if err := ht.Execute(&hb, login); err != nil {
		t.Fatalf("html/template: %v", err)
	}
	out["html/template"] = hb.String()

	y, err := yaml.Marshal(struct {
		Password secret.Secret            `yaml:"password"`
		List     []secret.Secret          `yaml:"list"`
		Map      map[string]secret.Secret `yaml:"map"`
	}{s, []secret.Secret{s}, map[string]secret.Secret{"k": s}})
	out["yaml"] = string(y) + fmt.Sprint(err)

	// gob must refuse the type (no exported fields) rather than encode it.
	var gb bytes.Buffer
	gerr := gob.NewEncoder(&gb).Encode(struct{ P secret.Secret }{s})
	out["gob"] = gb.String() + fmt.Sprint(gerr)

	var report strings.Builder
	for label, got := range out {
		fmt.Fprintf(&report, "%s\t%s\n", label, got)
	}
	writeArtifact(t, "secret-renderings-attack.txt", report.String())
	for label, got := range out {
		if strings.Contains(got, canary) {
			t.Errorf("canary leaked through %s", label)
		}
	}
	if s.Expose() != canary {
		t.Error("rendering changed the secret value")
	}
}

const (
	// atkPanicChildEnv switches the test binary into "panicking child"
	// mode; atkPanicCanaryEnv carries the canary into the child.
	atkPanicChildEnv  = "FACTO_ATK_SECRET_PANIC_CHILD"
	atkPanicCanaryEnv = "FACTO_ATK_SECRET_PANIC_VALUE"
)

// atkHold keeps a Secret and its exposed string live in a frame that the
// traceback prints, then panics with v.
//
//go:noinline
func atkHold(s secret.Secret, exposed string, v any) {
	if len(exposed) == 0 || s.IsZero() {
		return
	}
	panic(v)
}

// atkSink defeats dead-code elimination of the nil dereference.
var atkSink string

// atkNilDeref dereferences a nil pointer (a runtime error, not a panic
// call) while the Secret and its exposed string are live arguments.
//
//go:noinline
func atkNilDeref(s secret.Secret, exposed string) {
	var p *atkLogin
	if len(exposed) > 0 && !s.IsZero() {
		atkSink = p.User
	}
}

// atkPanicChild is the body of the child process: it panics, unrecovered,
// with the secret in the panic value of the selected mode.
func atkPanicChild(mode string) {
	v := os.Getenv(atkPanicCanaryEnv)
	s := secret.FromString(v)
	_ = os.Unsetenv(atkPanicCanaryEnv) // not in the child's environment any more
	var val any
	switch mode {
	case "value":
		val = s
	case "pointer":
		val = &s
	case "struct":
		val = struct{ Password secret.Secret }{s}
	case "error":
		val = fmt.Errorf("login failed with %v: %w", s, errors.New("supplier refused"))
	case "goroutine":
		done := make(chan struct{})
		go func() {
			defer close(done)
			atkHold(s, s.Expose(), "connector goroutine crashed")
		}()
		<-done
		return
	case "nil deref":
		atkNilDeref(s, s.Expose())
		return
	}
	atkHold(s, s.Expose(), val)
}

// TestAttack_SecretUnrecoveredPanicNeverPrintsValue crashes a real child
// process (GOTRACEBACK=all) while a Secret is the panic value or is live in
// the panicking frames. The runtime's panic message and every goroutine
// trace go to the child's stderr, which must not contain the canary.
func TestAttack_SecretUnrecoveredPanicNeverPrintsValue(t *testing.T) {
	if mode := os.Getenv(atkPanicChildEnv); mode != "" {
		atkPanicChild(mode)
		return
	}
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	var report strings.Builder
	for _, mode := range []string{"value", "pointer", "struct", "error", "goroutine", "nil deref"} {
		t.Run(mode, func(t *testing.T) {
			canary := testsecrets.Canary(t, testsecrets.Password)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAttack_SecretUnrecoveredPanicNeverPrintsValue$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				atkPanicChildEnv+"="+mode, atkPanicCanaryEnv+"="+canary,
				"GOTRACEBACK=all", "FACTO_CANARY=0")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			fmt.Fprintf(&report, "== %s (err %v)\n%s\n%s\n", mode, runErr, stdout.String(), stderr.String())

			var exit *exec.ExitError
			if !errors.As(runErr, &exit) || !strings.Contains(stderr.String(), "panic") {
				t.Fatalf("child did not crash with a panic (err %v): the attack did not run", runErr)
			}
			for name, b := range map[string][]byte{"stderr": stderr.Bytes(), "stdout": stdout.Bytes()} {
				if bytes.Contains(b, []byte(canary)) {
					t.Errorf("child %s carries the canary after a %s panic", name, mode)
				}
			}
		})
	}
	writeArtifact(t, "secret-panic-children.txt", report.String())
}

// TestAttack_ParseRefHostileInputs feeds reference strings built to slip a
// name, a path or a second value past ParseRef: Unicode look-alikes, NUL and
// line breaks, encodings, traversal segments, and a 1 MiB input. Each must
// be refused quickly with ErrInvalidRef and an error that echoes nothing.
// "Quickly" is at most 2 s of CPU time (package cputime), which a loaded
// machine cannot exhaust the way it did a 2 s wall-clock deadline. Not
// parallel: outside Linux cputime measures the whole process.
func TestAttack_ParseRefHostileInputs(t *testing.T) {
	canary := testsecrets.Canary(t, testsecrets.Password)
	big := "keyring://facto/" + strings.Repeat("a/", 512<<10) + canary + "/"
	inputs := map[string]string{
		"NUL after field":            "bw://" + atkUUID + "/password\x00" + canary,
		"newline after field":        "bw://" + atkUUID + "/password\n" + canary,
		"CRLF in keyring key":        "keyring://facto/key\r\n" + canary,
		"unicode hyphen in UUID":     "bw://3f2a9c1e‐5b7d-4e8a-9c21-7d4e5f6a8b90/password",
		"fullwidth digit in UUID":    "bw://３f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b9/password",
		"kelvin sign in field":       "bw://" + atkUUID + "/passworK",
		"uppercase scheme":           "BW://" + atkUUID + "/password",
		"scheme with spaces":         " bw://" + atkUUID + "/password",
		"traversal in keyring key":   "keyring://facto/../../" + canary,
		"dot segment in keyring key": "keyring://facto/a/./" + canary,
		"encoded traversal":          "keyring://facto/%2e%2e/" + canary,
		"backslash traversal":        "keyring://facto/..\\..\\" + canary,
		"empty service":              "keyring:///" + canary,
		"userinfo":                   "keyring://" + canary + "@facto/key",
		"two references":             "bw://" + atkUUID + "/password bw://" + atkUUID + "/totp",
		"name instead of UUID":       "bw://EDF " + canary + "/password",
		"field with suffix":          "bw://" + atkUUID + "/password/" + canary,
		"1 MiB keyring reference":    big,
	}
	var report strings.Builder
	for name, in := range inputs {
		var ref secret.Ref
		var err error
		wall := cputime.Cap(t)
		cpu, cpuErr := cputime.Within(wall, func() { ref, err = secret.ParseRef(in) })
		if errors.Is(cpuErr, cputime.ErrWallTimeout) {
			t.Fatalf("%s: ParseRef still running after %v of wall-clock time: hung", name, wall)
		}
		if cpuErr != nil {
			t.Fatalf("%s: measure CPU time: %v", name, cpuErr)
		}
		if cpu > 2*time.Second {
			t.Fatalf("%s: ParseRef took %v of CPU, want at most 2s", name, cpu)
		}
		if !errors.Is(err, secret.ErrInvalidRef) {
			t.Errorf("%s: ParseRef = %+v, %v; want ErrInvalidRef", name, ref, err)
			continue
		}
		msg := err.Error()
		fmt.Fprintf(&report, "%s\t%s\n", name, msg)
		if strings.Contains(msg, canary) || len(msg) > 200 {
			t.Errorf("%s: error echoes the input (%d bytes)", name, len(msg))
		}
	}
	writeArtifact(t, "parseref-hostile.txt", report.String())
}

// atkProvider records whether it was reached.
type atkProvider struct {
	scheme string
	calls  int
}

func (p *atkProvider) Scheme() string { return p.scheme }
func (p *atkProvider) Close() error   { return nil }
func (p *atkProvider) Resolve(context.Context, secret.Ref) (secret.Secret, error) {
	p.calls++
	return secret.FromString("value-synthetic"), nil
}

// TestAttack_ResolverHandBuiltRefsNeverReachProvider builds Refs by hand
// (a connector bypassing ParseRef) carrying names, traversal, separators and
// canaries. The Resolver must refuse them before the bw or keyring provider
// runs, and never echo them.
func TestAttack_ResolverHandBuiltRefsNeverReachProvider(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	bw, kr := &atkProvider{scheme: "bw"}, &atkProvider{scheme: "keyring"}
	r, err := secret.NewResolver(bw, kr)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	refs := map[string]secret.Ref{
		"bw item name":           {Scheme: "bw", Item: "EDF " + canary, Field: "password"},
		"bw field outside set":   {Scheme: "bw", Item: atkUUID, Field: canary},
		"bw field with slash":    {Scheme: "bw", Item: atkUUID, Field: "password/" + canary},
		"bw item with slash":     {Scheme: "bw", Item: atkUUID + "/password", Field: "totp"},
		"keyring traversal":      {Scheme: "keyring", Item: "..", Field: canary},
		"keyring item slash":     {Scheme: "keyring", Item: "facto/" + canary, Field: "k"},
		"keyring key traversal":  {Scheme: "keyring", Item: "facto", Field: "../" + canary},
		"keyring NUL":            {Scheme: "keyring", Item: "facto", Field: "k\x00" + canary},
		"keyring empty key":      {Scheme: "keyring", Item: "facto", Field: ""},
		"unknown scheme":         {Scheme: canary, Item: "x", Field: "y"},
		"scheme with separators": {Scheme: "bw://" + atkUUID + "/password#", Item: atkUUID, Field: "password"},
	}
	var report strings.Builder
	for name, ref := range refs {
		s, err := r.ResolveRef(t.Context(), ref)
		if err == nil {
			t.Errorf("%s: ResolveRef = nil error (%d bytes)", name, len(s.Expose()))
			continue
		}
		if !errors.Is(err, secret.ErrInvalidRef) && !errors.Is(err, secret.ErrNoProvider) {
			t.Errorf("%s: error %v, want ErrInvalidRef or ErrNoProvider", name, err)
		}
		fmt.Fprintf(&report, "%s\t%v\t%+v\t%#v\n", name, err, err, err)
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(verb, err), canary) {
				t.Errorf("%s: error rendered with %s echoes the ref", name, verb)
			}
		}
	}
	writeArtifact(t, "resolver-handbuilt.txt", report.String())
	if bw.calls != 0 || kr.calls != 0 {
		t.Errorf("providers reached by hostile refs: bw %d, keyring %d calls", bw.calls, kr.calls)
	}
}
