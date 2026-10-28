# Single entry points for humans, agents and CI. Keep targets stable: GOALS.md depends on them.
GO        ?= go
PKGS      := ./...
COVER_GATES := internal/normalize:85 internal/store:85 internal/secrets:85 internal/vault:85 internal/fsx:85 internal/httpx:85
export FACTO_CANARY := 1
# go test runs in each package directory: export absolute paths.
export CANARY_FILE := $(CURDIR)/.cache/canaries.txt
export ART_DIR := $(CURDIR)/.cache/test-artifacts

.PHONY: verify fmt-check lint test race cover e2e leakcheck audit score-check tools lint-actions

verify: fmt-check lint race cover leakcheck ## everything required before a commit
	@echo "verify: ok"

fmt-check:
	@out="$$(gofumpt -l $$(git ls-files '*.go'))"; if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run

lint-actions:
	actionlint

test:
	$(GO) test -short -count=1 $(PKGS)

# The canary file is created 0600: testsecrets appends through fsx, which
# refuses group/world-readable files.
race:
	rm -rf "$(ART_DIR)"
	mkdir -p "$(ART_DIR)"
	install -m 600 /dev/null "$(CANARY_FILE)"
	$(GO) test -race -count=1 -coverprofile=.cache/coverage.out $(PKGS)

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
	umask 077; osv-scanner --recursive .; echo $$? > .cache/audit/osv-scanner.status
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
