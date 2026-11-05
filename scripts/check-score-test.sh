#!/usr/bin/env bash
# Tests for scripts/check-score.sh, run by `make score-check-test` (part of verify).
# Each case builds a throwaway git repository under .cache/score-check-test/ with a
# copy of check-score.sh and code-tree.sh, commits a passing score.json for the
# audited commit, then reshapes history and checks the gate's verdict.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work="$root/.cache/score-check-test"
rm -rf "$work"
mkdir -p -m 700 "$work"
trap 'rm -rf "$work"' EXIT
failures=0

g() {
  git -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false \
    -c init.defaultBranch=main "$@"
}

# write_score <dir> [code_tree|-]: passing score.json for HEAD, committed.
# Without a second argument code_tree is computed; "-" leaves it out.
write_score() {
  local d=$1 tree=${2-}
  (
    cd "$d"
    [[ -n $tree ]] || tree=$(scripts/code-tree.sh)
    python3 - "$(git rev-parse HEAD)" "$tree" <<'PY'
import json, sys
s = {"date": "2026-11-04", "milestone": "J1", "commit": sys.argv[1], "total": 90,
     "categories": [{"id": i, "name": f"c{i}", "max": 10, "score": 9} for i in range(1, 11)],
     "findings": [], "scanners": {"gosec": "pass"}, "verdict": "PASS"}
if sys.argv[2] != "-":
    s["code_tree"] = sys.argv[2]
json.dump(s, open("security/score.json", "w"), indent=2)
PY
    g add -A && g commit -qm "chore(security): score"
  )
}

# new_repo <dir>: repo with code and docs, audited on main.
new_repo() {
  local d=$1
  mkdir -p "$d/scripts" "$d/security" "$d/internal/a" "$d/cmd/facto" "$d/connectors/x" "$d/docs"
  cp "$root/scripts/check-score.sh" "$root/scripts/code-tree.sh" "$d/scripts/"
  echo 'package a' >"$d/internal/a/a.go"
  echo 'package main' >"$d/cmd/facto/main.go"
  echo 'package x' >"$d/connectors/x/x.go"
  echo 'doc' >"$d/docs/readme.md"
  (cd "$d" && g init -q && g add -A && g commit -qm audited)
  write_score "$d"
}

# expect <name> <ok|ko> <dir> [pattern]: ok = gate exits 0, ko = gate exits non-zero.
expect() {
  local name=$1 want=$2 d=$3 pat=${4-} out status=0 got=ok
  out=$(cd "$d" && ./scripts/check-score.sh 2>&1) || status=$?
  [[ $status -eq 0 ]] || got=ko
  if [[ $got != "$want" ]] || { [[ -n $pat ]] && ! grep -qF -- "$pat" <<<"$out"; }; then
    echo "FAIL $name: want $want${pat:+ matching '$pat'}, got $got (exit $status): $out"
    failures=$((failures + 1))
  else
    echo "ok   $name"
  fi
}

# 1. The audited commit itself.
d="$work/head"
new_repo "$d"
expect "audited commit accepted" ok "$d" "AUDIT: PASS"

# 2. Same code reaching main through a merge commit (docs-only branch merged with
#    --no-ff, plus an unrelated docs commit on main): ancestry differs, code does
#    not. This is the case the old merge-base check broke.
d="$work/merge"
new_repo "$d"
(cd "$d" && g checkout -qb feature && echo more >>docs/readme.md && g commit -qam "docs: more" &&
  g checkout -q main && echo other >docs/other.md && g add -A && g commit -qm "docs: other" &&
  g merge -q --no-ff -m "Merge feature" feature)
expect "same code via merge commit accepted" ok "$d" "AUDIT: PASS"

# 3. Same code reaching main through a squash commit on a fresh root history: the
#    audited commit is not an ancestor of HEAD at all.
d="$work/squash"
new_repo "$d"
(cd "$d" && g checkout -q --orphan squashed && g commit -qm "Milestone (#1)")
expect "same code via squash commit accepted" ok "$d" "AUDIT: PASS"

# 3b. Code changed and audited on a feature branch, then rebase-merged onto a main
#     that moved on (commits re-created): score.json names the pre-rebase commit.
d="$work/rebase"
new_repo "$d"
(cd "$d" && g checkout -qb feature && echo '// feat' >>internal/a/a.go && g commit -qam "feat: a")
write_score "$d"
(cd "$d" && g checkout -q main && echo other >docs/other.md && g add -A && g commit -qm "docs: other" &&
  g cherry-pick main..feature >/dev/null)
expect "same code via rebase merge accepted" ok "$d" "AUDIT: PASS"

# 4-6. Any change under cmd/, internal/ or connectors/ after the audit is rejected,
#      also when it arrives through a merge commit.
for dir in internal/a cmd/facto connectors/x; do
  d="$work/changed-${dir%%/*}"
  new_repo "$d"
  (cd "$d" && g checkout -qb feature && echo '// change' >>"$dir"/*.go && g commit -qam "feat: change" &&
    g checkout -q main && g merge -q --no-ff -m "Merge feature" feature)
  expect "changed code in ${dir%%/*} via merge rejected" ko "$d" "changed since the audit"
done

# 7. A new file under a code directory.
d="$work/added"
new_repo "$d"
(cd "$d" && echo 'package b' >internal/a/b.go && g add -A && g commit -qm "feat: add")
expect "added code file rejected" ko "$d" "changed since the audit"

# 8. A deleted code file.
d="$work/deleted"
new_repo "$d"
(cd "$d" && g rm -q connectors/x/x.go && g commit -qm "feat: drop")
expect "deleted code file rejected" ko "$d" "changed since the audit"

# 9. A file mode change: ls-tree records the mode.
d="$work/mode"
new_repo "$d"
(cd "$d" && chmod +x internal/a/a.go && g commit -qam "chore: mode")
expect "code file mode change rejected" ko "$d" "changed since the audit"

# 10. score.json without code_tree.
d="$work/missing"
new_repo "$d"
write_score "$d" -
expect "score.json without code_tree rejected" ko "$d" "no code_tree"

# 11. Matching code_tree but a failing score: the other checks are kept.
d="$work/lowscore"
new_repo "$d"
(cd "$d" && python3 - <<'PY' && g commit -qam "chore: low score"
import json
s = json.load(open("security/score.json"))
s["total"] = 80
s["categories"][0]["score"] = 5
s["findings"] = [{"id": "SEC-J1-1", "category": 1, "severity": "high", "location": "a.go:1", "status": "open"}]
s["scanners"]["gosec"] = "fail"
json.dump(s, open("security/score.json", "w"))
PY
)
expect "low total, low category, open high and failed scanner rejected" ko "$d" \
  "total 80 < 85; category 1 c1 5/10 < 60%; open high SEC-J1-1 at a.go:1; scanner gosec failed"

# 12. No score.json.
d="$work/none"
new_repo "$d"
(cd "$d" && g rm -q security/score.json && g commit -qm "rm")
expect "no score.json rejected" ko "$d" "no security/score.json"

if [[ $failures -ne 0 ]]; then
  echo "score-check-test: $failures failure(s)"
  exit 1
fi
echo "score-check-test: ok"
