# Goal conditions per milestone

Copy one line into Claude Code (`/goal …`) at the start of a milestone session, or run
it headless: `claude -p "/goal <condition>"`. Each condition is provable from printed
command output, because the goal evaluator only reads the transcript.

## J0 — Foundations (needs H1)
/goal `make verify` exits 0 on a clean checkout, `make cover` prints >= 85% for internal/normalize, internal/store, internal/secret, internal/fsx and internal/httpx, `make e2e` passes the `inbox` scenario, `make leakcheck` prints "0 canary hits", `actionlint` reports no error on .github/workflows, and docs/agentic/PROGRESS.md marks J0 done, or stop after 100 turns

## J1 — Browser layer and fake provider
/goal `make e2e` passes every fakeprovider scenario (password, totp, email-otp, sso-redirect, expired-session, rate-limit, site-changed, captcha), the browser security scenarios print "no listening CDP port" and "profile removed", `make leakcheck` prints "0 canary hits", `make score-check` prints "AUDIT: PASS" with total >= 85 and no category below 6, red-team attack tests all pass, `golangci-lint run` passes with a depguard rule banning golang.org/x/crypto/openpgp, `osv-scanner --recursive .` reports no unignored vulnerability, the ADRs for the browser library and the vault are committed, the latest ci and security runs on milestone/j1 are green as shown by `gh run list --branch milestone/j1 --limit 5`, and PROGRESS.md marks J1 done, or stop after 150 turns

## J2 — Real connectors (offline part; H3 then H4 for live)
/goal for each of ileo, edf, bouyguestelecom with fixtures present in testdata/<id>/: `go test ./connectors/<id>/... -race` passes the 8 scenarios of the add-connector skill, docs/connectors/<id>.md is complete, `make verify` exits 0, `make score-check` prints "AUDIT: PASS", and PROGRESS.md lists `NEEDS(H4): facto doctor <id>` for each; connectors without fixtures are listed as BLOCKED(H3), or stop after 150 turns

## J3 — Drive and receipts (needs H2 for live)
/goal `go test ./internal/dest/gdrive/... -race` passes against the fake Drive API (create folder, upload, dedup by appProperties, token refresh, 401 re-auth), `npx playwright test web/capture` passes with mocked Google APIs (capture, offline queue, upload, CSP check), `facto export --year 2026 --csv` golden test passes including a receipt row, `make score-check` prints "AUDIT: PASS", `osv-scanner --recursive .` reports no unignored vulnerability (now including the PWA's npm dependencies), `grep -n languages .github/workflows/security.yml` shows javascript enabled for CodeQL (Florian's change: mark BLOCKED(H1) in PROGRESS.md until it is there), the latest ci and security runs on milestone/j3 are green as shown by `gh run list --branch milestone/j3 --limit 5`, and PROGRESS.md marks J3 done, or stop after 120 turns

## J4 — Opening
/goal the declarative engine passes contract tests against the mock server generated from test/openapi/invoices.yaml, the local web UI E2E passes including foreign Origin/Host rejection, wecasa and cooloc are implemented from fixtures or marked BLOCKED(H3), README connector table matches the sheets, `make verify` exits 0, `make score-check` prints "AUDIT: PASS", and `goreleaser release --snapshot --clean` succeeds, or stop after 150 turns
