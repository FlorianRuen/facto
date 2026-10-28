# Progress log (append-only)

Format: `YYYY-MM-DD <milestone> <task> <done|BLOCKED(Hn)|NEEDS(Hn)>: <one line> (commit <sha>)`

2026-10-28 J0 T1 done: make plumbing (abs canary paths, .cache, lint-actions) + internal/clock 100% (commit 5be18a5)
2026-10-28 J0 T2 done: internal/fsx private atomic ops confined by os.Root, 87.0% (commit 6c828e5)
2026-10-28 J0 T4-T6 done: ADRs 0001-0007; actionlint in its own tools module (commit 41b9498)
2026-10-28 J0 T2 follow-up: Windows perm checks are no-ops (spec Data at rest gap); needs owner-only DACL check via x/sys/windows + ADR, planned J1
2026-10-28 J0 T3 done: testsecrets canaries + leakcheck.sh fixed (binary scan, exit codes); first green make verify (commit 46f4725)
2026-10-28 J0 T8 done: fsx SafeName/JoinWithin, ErrNotDurable; Windows reserved-name gaps queued as review fix (commit 1bfed0d)
2026-10-28 J0 T12 done: connector contracts, registry, periods, 100% (commit 315d6ba)
2026-10-28 J0 T16 done: hardened Factur-X CII parsing 96.5%; coverage gates now apply to subpackages (commit 781ce11)
2026-10-28 J0 T7 done: tools/go.mod + tools/actionlint/go.mod pinned, make tools installs both with real versions (commit b3e0f59)
2026-10-28 J0 T10 BLOCKED(H1): writes under internal/secrets/ are denied by a permission rule not found in repo or user settings (managed policy?); tests ready in scratchpad j0sec/internal/secrets/*_test.go; Florian to allow the path or copy the files. Also blocks T13, T18, T19
2026-10-28 J0 T7 reviewed: PASS
2026-10-28 J0 T11 done: httpx allowlisted HTTPS client 95.9%, review PASS; hardening follow-ups (wildcard TLDs, ports, body close) in progress (commit 54b19df)
2026-10-28 J0 T9 review BLOCKING: logx leaks values nested in maps/structs (http.Header, []byte); fix in progress (commit ae1c014)
2026-10-28 J0 T14 done: normalize naming/slug/ParseName 98.9%, review PASS; follow-up: escape refs shaped like v<N> (commit 79e3a71)
2026-10-28 J0 T15 done: dedup split into BeforeFetch (rule 1) + Decide (rules 2-3), takes provider; rule 3 reachable via inbox/refetch only (commit bd1a390)
2026-10-28 J0 T8 follow-up done: Windows reserved names complete, longest-prefix coverage gates (commits 0a9f2fc, f71a1e0); follow-up: check-coverage.sh must reject malformed gates and not skip packages silently
2026-10-28 J0 T20 done: store SQLite index (modernc, 0600 db+wal/shm, NULL provider_id) 92.0%, review PASS; follow-up: refuse schema downgrade (commit 2358990)
2026-10-28 J0 T29 done: per-scanner status + scanners.json writer, make audit fails on any scanner, review PASS (commit dbeeb60)
2026-10-28 J0 T23b done: connector Env.HTTP is *httpx.Client, spec Env block updated (commit 60de3e5)
2026-10-28 J0 T9 review BLOCKING (2nd pass): logx still leaks map[any]any keys, url.URL userinfo/query, request bodies; fix round in progress (commit c48b330)
2026-10-28 J0 audit NEEDS(H1): govulncheck flags 10 Go 1.27.1 stdlib vulns fixed in 1.27.2/1.27.3; bump toolchain locally and in CI
2026-10-28 J0 T17 done: Factur-X extraction from PDF, own capped inflate (flate bomb closed), stateless pdfcpu, 10s bound; review PASS (commit 8e84422)
2026-10-28 J0 T21 done: dest + dest/local via fsx.WriteNew (never replaces) 96.7%; review: hard-link requirement needs ErrLinkUnsupported + startup probe (commit 3f60350)
2026-10-28 J0 store follow-up done: ErrSchemaTooNew refuses downgrades (commit ce60fb3)
2026-10-28 J0 T9 review BLOCKING (3rd pass): cookies with hex values, promoted String() of embedded url types, non-https URLs; switching to fail-closed rendering for net/http, net/url, crypto types
2026-10-28 J0 T21 BLOCKED(H1): output folders without hard links (exFAT, likely Google Drive for desktop) fail WriteNew; decide on a no-replace fallback (renameat2/renamex_np/MoveFileEx via x/sys + ADR, or non-atomic O_EXCL)
2026-10-28 J0 T9 round 3: fail-closed net/url/crypto types, promoted methods walked, any-scheme URLs (commit ac229b9); 4th-pass leak (url.Parse error quoting userinfo with space/quote) fixed test-first (commit d3397ea); pending reviewer confirmation
2026-10-28 J0 T21 follow-up done: fsx.ErrLinkUnsupported + startup ProbeLink, Put returns ref on ErrNotDurable, spec row updated (commit 7e68aae)
2026-10-28 J0 T22 done: inbox scan/infer/Open/Done + fsx confined read API (ReadDir, OpenDir, OpenRegular) 88.5%; review: no blocking (commits ff067f9, fab5402)
2026-10-28 J0 hardening queue (before T30): narrow ErrLinkUnsupported to EPERM/ENOTSUP/EXDEV; test hooks so fsx/inbox SameFile identity checks are exercised; logx keys code/pin/key; refuse wildcards over any *.amazonaws.com; defined types convertible to url/http structs
2026-10-28 J0 T9 done: logx userinfo-with-space/quote leak closed, review confirmed (commit d3397ea); follow-up: mask raw URL quoted in url.Parse errors (in progress)
2026-10-28 J0 T23 review BLOCKING: cancel between Put and Insert leaves an unindexed file stuck as "exists"; fix: Insert with context.WithoutCancel (in progress) (commit a63cf6a)
2026-10-28 J0 T23 follow-ups: self-heal ErrExists when destination file has the same SHA-256 (needs a Destination read/hash method); replace Name()=="local" check with a RemoteRef kind
2026-10-28 J0 T23 fix: Insert after a successful Put ignores cancellation, read-changed maps to "changed"; one subtest tightened (commit 564ffbf); logx masks raw URL in url.Parse errors (commit 39657f9); pending reviewer confirmation with T24
2026-10-28 J0 T23 done: cancellation gap closed, review confirmed (commits a63cf6a, 564ffbf)
2026-10-28 J0 T24 review BLOCKING: body left open after a read panic; fix in progress with interrupted state and goroutine-panic docs (commit 374295d)
2026-10-28 J0 T10 BLOCKED(H1): rechecked, writes under internal/secrets/ still denied (mkdir refused); blocks T13, T18, T19 -> T25 -> T26, T27 -> T28 (inbox e2e) -> T30
2026-10-28 J0 hardening 2 done: test hooks (openDirHook, openRegularHook, doneRecheckHook) prove fsx OpenDir/OpenRegular and inbox Done identity checks fire (mutations now caught); Done doc names the remaining recheck-to-Remove window
2026-10-28 J0 hardening 3 done: logx default whole-word keys code, pin, key (keyboard/pincode/zipcode/barcode kept; country_code/status_code masked, documented)
2026-10-28 J0 hardening 4 done: httpx refuses wildcards below amazonaws.com except one tenant directly under a known S3 suffix (existing storage_suffix_test keeps *.mybucket.s3.<region> valid); exact tenant hosts stay valid
