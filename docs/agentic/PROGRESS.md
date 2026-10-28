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
