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

race:
	mkdir -p "$(ART_DIR)"
	: > "$(CANARY_FILE)"
	$(GO) test -race -count=1 -coverprofile=.cache/coverage.out $(PKGS)

cover: race
	./scripts/check-coverage.sh .cache/coverage.out "$(COVER_GATES)" 70

e2e:
	docker compose -f test/compose.yaml up -d --wait vaultwarden
	$(GO) test -tags e2e -count=1 -v ./test/e2e/... ; status=$$?; \
	docker compose -f test/compose.yaml down -v; exit $$status

leakcheck:
	./scripts/leakcheck.sh

audit:
	govulncheck ./...
	gosec -quiet -severity high ./...
	gitleaks detect --no-banner --redact
	osv-scanner --recursive .
	$(GO) run ./scripts/scanners-json > security/scanners.json

score-check:
	./scripts/check-score.sh

tools: ## pinned tool versions are set in tools/go.mod
	$(GO) install -modfile=tools/go.mod tool
