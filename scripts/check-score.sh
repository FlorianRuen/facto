#!/usr/bin/env bash
# Fails unless security/score.json exists, matches HEAD (or is newer than the last
# change under internal/ and connectors/), and passes the gate. Prints AUDIT: PASS|FAIL.
set -euo pipefail
f=security/score.json
[[ -f $f ]] || { echo "AUDIT: FAIL (no $f)"; exit 1; }
commit=$(python3 -c 'import json;print(json.load(open("security/score.json"))["commit"])')
last_code=$(git log -1 --format=%H -- internal connectors cmd || true)
if [[ -n "$last_code" ]] && ! git merge-base --is-ancestor "$last_code" "$commit" 2>/dev/null; then
  echo "AUDIT: FAIL (score.json is older than the last code change $last_code)"; exit 1
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
