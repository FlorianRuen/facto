# Progress log (append-only)

Format: `YYYY-MM-DD <milestone> <task> <done|BLOCKED(Hn)|NEEDS(Hn)>: <one line> (commit <sha>)`

2026-10-28 J0 T1 done: make plumbing (abs canary paths, .cache, lint-actions) + internal/clock 100% (commit 5be18a5)
2026-10-28 J0 T2 done: internal/fsx private atomic ops confined by os.Root, 87.0% (commit 6c828e5)
2026-10-28 J0 T4-T6 done: ADRs 0001-0007; actionlint in its own tools module (commit 41b9498)
2026-10-28 J0 T2 follow-up: Windows perm checks are no-ops (spec Data at rest gap); needs owner-only DACL check via x/sys/windows + ADR, planned J1
