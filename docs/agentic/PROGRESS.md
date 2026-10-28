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
