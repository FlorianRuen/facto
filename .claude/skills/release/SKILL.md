---
name: release
description: Release procedure for facto (versioning, changelog, goreleaser, signatures, SBOM, verification). Use when preparing a tag, a release candidate, or when asked about publishing binaries.
disable-model-invocation: true
---

# Release

1. All milestones in scope closed, `security/score.json` PASS on the release commit.
2. Version: SemVer; `0.x` until the J4 gate and an external audit.
3. Changelog from Conventional Commits; Florian reviews the release notes.
4. Florian pushes the signed tag (agents never push tags). `release.yml` runs
   goreleaser: binaries for linux/darwin/windows (amd64, arm64), checksums, SBOM,
   keyless cosign signatures, provenance.
5. Verify a downloaded artifact with `cosign verify-blob` and the checksum file;
   paste the verification output in the release discussion.
