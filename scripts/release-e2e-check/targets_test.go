package main

import (
	"runtime"
	"slices"
	"testing"
)

// TestLoadRelease_Targets: the release targets are goos x goarch of the
// facto build, read from the goreleaser file. Windows is not released until
// the Job object gate of ADR 0008 (issue #3, SEC-J1-11) lands.
func TestLoadRelease_Targets(t *testing.T) {
	t.Parallel()
	got := realRelease(t).Targets
	want := []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("Targets = %q, want %q", got, want)
	}

	path := writeTemp(t, "g.yaml", "version: 2\nbuilds:\n  - id: facto\n    main: ./cmd/facto\n    goos: linux\n    goarch: [amd64, arm64]\n")
	b, err := loadRelease(path)
	if err != nil {
		t.Fatalf("loadRelease: %v", err)
	}
	if want := []string{"linux/amd64", "linux/arm64"}; !slices.Equal(b.Targets, want) {
		t.Fatalf("Targets = %q, want %q", b.Targets, want)
	}
}

// TestGoList_EveryTarget: go list covers every release target, not only the
// host: internal/fsx pulls golang.org/x/sys/windows on Windows targets only
// and golang.org/x/sys/unix on the others, and both appear in one listing.
// The real release has no Windows target while the ADR 0008 gate is open,
// so the windows targets are added here to keep the target loop exercised.
func TestGoList_EveryTarget(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root := repoRoot(t)
	b := realRelease(t)
	b.Targets = append(slices.Clone(b.Targets), "windows/amd64", "windows/arm64")
	pkgs, err := goList(ctx, root, b, b.listPkgsArgs(nil, "./internal/fsx"))
	if err != nil {
		t.Fatalf("goList: %v", err)
	}
	paths := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		paths = append(paths, p.importPath)
	}
	for _, want := range []string{"golang.org/x/sys/windows", "golang.org/x/sys/unix"} {
		if !slices.Contains(paths, want) {
			t.Errorf("deps over every target lack %s: %q", want, paths)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	// Control: the host-only listing of a non-Windows host lacks the
	// Windows package, so the hit above comes from the target loop.
	host := b
	host.Targets = nil
	pkgs, err = goList(ctx, root, host, host.listPkgsArgs(nil, "./internal/fsx"))
	if err != nil {
		t.Fatalf("goList(host): %v", err)
	}
	for _, p := range pkgs {
		if p.importPath == "golang.org/x/sys/windows" {
			t.Fatal("host-only listing has golang.org/x/sys/windows: the control is vacuous")
		}
	}
}
