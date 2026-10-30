# Single entry points for humans, agents and CI. Keep targets stable: GOALS.md depends on them.
GO        ?= go
PKGS      := ./...
COVER_GATES := internal/normalize:85 internal/store:85 internal/secret:85 internal/vault:85 internal/fsx:85 internal/httpx:85 internal/browser/cft:85 internal/browser:85
export FACTO_CANARY := 1
# go test runs in each package directory: export absolute paths.
export CANARY_FILE := $(CURDIR)/.cache/canaries.txt
export ART_DIR := $(CURDIR)/.cache/test-artifacts

# lint-selftest creates in-tree fixtures that race/lint must not see: never run targets in parallel.
.NOTPARALLEL:

.PHONY: verify fmt-check lint lint-selftest test race cover e2e e2e-unit leakcheck audit score-check tools lint-actions release-check release-e2e-check

# goreleaser runs from its pinned image (ADR 0001) so its dependencies stay out
# of tools/go.mod and the osv-scanner scope.
GORELEASER_IMAGE := goreleaser/goreleaser:v2.12.7@sha256:a2a47c0dda85f8d40eaaa5b9765bf76c69addb6060666f8a51441410d9b008e9
# The image ships an older Go: the host module cache (which already holds the
# go.mod toolchain and every module) is served read-only as a file GOPROXY, so
# nothing is fetched from the network. GOSUMDB is off for that local proxy only;
# modules are still checked against go.sum.
GORELEASER_RUN := -e HOME=/tmp -e GOFLAGS=-mod=readonly -e GOTOOLCHAIN=go$(shell sed -n 's/^go //p' go.mod) \
	-e GOPROXY=file:///hostmod/cache/download -e GOSUMDB=off -e GOMODCACHE=/tmp/gomod \
	-v $(shell $(GO) env GOMODCACHE):/hostmod:ro -v $(CURDIR):/src:ro

verify: fmt-check lint lint-selftest race cover e2e-unit release-e2e-check leakcheck ## everything required before a commit
	@echo "verify: ok"

fmt-check:
	@out="$$(gofumpt -l $$(git ls-files '*.go'))"; if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run

# Proves two depguard rules are live, in production and test files:
# - the ban on golang.org/x/crypto/openpgp (ADR 0009), by linting a throwaway
#   module built under .cache/lint-selftest/ from the module cache only
#   (GOPROXY=off);
# - rule cdploopback (ADR 0008, J1 T7.1), by linting temporary in-tree fixtures
#   (gitignored, removed on exit): internal/browser lints clean, imports from
#   internal/httpx and other packages are rejected.
lint-selftest:
	GOLANGCI_LINT=golangci-lint GO=$(GO) ./scripts/lint-selftest.sh

lint-actions:
	actionlint

# Validates .goreleaser.yaml and builds an unsigned snapshot of every target
# of HEAD (no publishing, no signing), like a release does. The repository is
# mounted read-only and cloned inside the container, so the host tree is never
# written (a remapped Docker user namespace could not write it anyway).
release-check:
	docker run --rm $(GORELEASER_RUN) --entrypoint sh $(GORELEASER_IMAGE) -c \
		'git config --global --add safe.directory "*" && git clone -q /src /tmp/w && cd /tmp/w && \
		git remote set-url origin https://github.com/FlorianRuen/facto.git && \
		goreleaser check && goreleaser release --snapshot --clean --skip=sign,sbom,publish'

# Proves the release build has no e2e-only code (ADR 0009 A3, J1 T17): with
# the exact .goreleaser.yaml flags, go list -deps finds no e2e-only package
# or e2e-tagged file and go tool nm no e2e symbol; the same check on a
# -tags e2e build must hit. Separate from release-check (goreleaser snapshot).
release-e2e-check:
	@$(GO) run ./scripts/release-e2e-check

test:
	$(GO) test -short -count=1 $(PKGS)

# The canary file is created 0600: testsecrets appends through fsx, which
# refuses group/world-readable files.
race:
	rm -rf "$(ART_DIR)"
	mkdir -p "$(ART_DIR)"
	install -m 600 /dev/null "$(CANARY_FILE)"
	$(GO) test -race -count=1 -coverprofile=.cache/coverage.out $(PKGS)

# Unit tests of the e2e build, in every package holding a Go file whose
# //go:build line mentions the e2e tag (test files included), computed from
# the tree. test/e2e is excluded: it needs the Vaultwarden container and
# runs in make e2e.
E2E_UNIT_PKGS = $(shell git ls-files --cached --others --exclude-standard '*.go' | \
	xargs grep -lE '^//go:build .*\<e2e\>' | xargs -n1 dirname | sort -u | \
	grep -vx 'test/e2e' | sed 's|^|./|')

e2e-unit:
	$(GO) test -race -count=1 -tags e2e $(E2E_UNIT_PKGS)

cover: race
	./scripts/check-coverage.sh .cache/coverage.out "$(COVER_GATES)" 70

e2e:
	docker compose -f test/compose.yaml up -d --wait vaultwarden
	$(GO) test -tags e2e -count=1 -v ./test/e2e/... ; status=$$?; \
	docker compose -f test/compose.yaml down -v; exit $$status

leakcheck:
	./scripts/leakcheck.sh

# Every scanner runs even when an earlier one fails: each line records its exit
# status in .cache/audit/<name>.status (the line itself always succeeds), then
# scripts/scanners-json writes security/scanners.json through fsx and exits
# non-zero if any scanner failed or left no status, which fails the target.
audit:
	rm -rf .cache/audit
	mkdir -p -m 700 .cache/audit
	umask 077; govulncheck ./...; echo $$? > .cache/audit/govulncheck.status
	umask 077; gosec -quiet -severity high ./...; echo $$? > .cache/audit/gosec.status
	umask 077; gitleaks detect --no-banner --redact; echo $$? > .cache/audit/gitleaks.status
	umask 077; osv-scanner --config=osv-scanner.toml --no-call-analysis=go --recursive .; echo $$? > .cache/audit/osv-scanner.status
	$(GO) run ./scripts/scanners-json

score-check:
	./scripts/check-score.sh

# Pinned tool versions live in tools/go.mod and tools/actionlint/go.mod (ADR 0001):
# actionlint has its own module because of a yaml/v4 rc clash with osv-scanner.
# gosec and gitleaks only report a version injected by -ldflags; it is read
# back from tools/go.mod so the pin stays in one place.
TOOLS_VERSION = $(shell $(GO) list -modfile=tools/go.mod -m -f '{{.Version}}' $(1))
TOOLS_LDFLAGS = -X main.Version=$(call TOOLS_VERSION,github.com/securego/gosec/v2) \
	-X github.com/zricethezav/gitleaks/v8/version.Version=$(call TOOLS_VERSION,github.com/zricethezav/gitleaks/v8)

tools: ## install pinned dev and security tools into GOBIN
	$(GO) install -modfile=tools/go.mod -ldflags "$(TOOLS_LDFLAGS)" tool
	$(GO) install -modfile=tools/actionlint/go.mod tool
