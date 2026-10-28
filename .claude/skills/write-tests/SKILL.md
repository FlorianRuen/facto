---
name: write-tests
description: How to write facto tests that actually protect behaviour (table tests, golden files, fakeprovider E2E, canary leak tests, negative security tests). Use whenever writing or changing tests, fixtures, or E2E scenarios.
---

# Writing tests for facto

- **Name the behaviour**: `TestNormalize_SanitizesSupplierProvidedNames`.
- **Fail first**: run the test before the implementation exists and keep the failure output in your turn summary.
- **Table tests** with `name`, input, want, wantErr (`errors.Is` target).
- **Golden files**: `testdata/<test>/<case>.golden`, `-update` flag, review diffs.
- **Fake clock** (`clock.NewFake`), never sleep. **No network**: `httptest` or `fakeprovider`.
- **E2E** (`make e2e`): scenarios live in `test/e2e/*.yaml` and drive the real binary
  against `fakeprovider` modes: `password`, `totp`, `email-otp`, `sso-redirect`,
  `expired-session`, `rate-limit`, `site-changed`, `captcha`.
- **Canary tests**: use `testsecrets.Canary(t)` values; `make leakcheck` greps every
  artifact written by tests for them. Any hit fails CI.
- **Security negatives**: every guard (allowlist, permissions, SafeName, size caps,
  XML entities) has a test proving it rejects bad input.
- Coverage gates (`make cover`): 85% for `internal/normalize`, `internal/store`,
  `internal/secrets`, `internal/vault`, `internal/fsx`, `internal/httpx`; 70% elsewhere.
