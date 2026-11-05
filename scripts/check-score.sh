#!/usr/bin/env bash
# Fails unless security/score.json exists, was produced for the code currently checked
# out, and passes the gate. Prints AUDIT: PASS|FAIL.
#
# "Code currently checked out" is the tree hash code_tree: the sha256 of
# `git ls-tree -r HEAD -- cmd internal connectors` (see scripts/code-tree.sh). It only
# depends on the content of those directories, so a merge or squash commit carrying
# exactly the audited code still passes, while any change under them fails until a new
# audit writes a new code_tree. Uncommitted changes are not part of HEAD and are ignored.
set -euo pipefail
f=security/score.json
[[ -f $f ]] || { echo "AUDIT: FAIL (no $f)"; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
want=$(python3 -c 'import json;print(json.load(open("security/score.json")).get("code_tree", ""))')
[[ -n "$want" ]] || { echo "AUDIT: FAIL (score.json has no code_tree)"; exit 1; }
got=$("$here/code-tree.sh")
if [[ "$got" != "$want" ]]; then
  echo "AUDIT: FAIL (code under cmd/ internal/ connectors/ changed since the audit: code_tree $got != score.json $want)"
  exit 1
fi
python3 - <<'PY'
import json, sys
s = json.load(open("security/score.json"))
reasons = []
if s["total"] < 85: reasons.append(f"total {s['total']} < 85")
for c in s["categories"]:
    if c["score"] < 0.6 * c["max"]:
        reasons.append(f"category {c['id']} {c['name']} {c['score']}/{c['max']} < 60%")
for f in s["findings"]:
    if f["status"] == "open" and f["severity"] in ("critical", "high"):
        reasons.append(f"open {f['severity']} {f['id']} at {f['location']}")
for k, v in s["scanners"].items():
    if v != "pass": reasons.append(f"scanner {k} failed")
if reasons:
    print("AUDIT: FAIL (" + "; ".join(reasons) + ")"); sys.exit(1)
mins = min(c["score"] / c["max"] * 10 for c in s["categories"])
print(f"AUDIT: PASS total {s['total']} min category {mins:.1f}/10")
PY
