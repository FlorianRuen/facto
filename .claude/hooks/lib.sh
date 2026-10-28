#!/usr/bin/env bash
# Shared helper: read a field from the hook JSON on stdin (jq, else python3).
json_field() {
  local expr="$1" input
  input="$(cat)"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$input" | jq -r "$expr // \"\""
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$input" | python3 -c '
import json,sys
d=json.load(sys.stdin); path=sys.argv[1].lstrip(".").split(".")
for p in path:
    d = d.get(p, "") if isinstance(d, dict) else ""
print(d if isinstance(d, str) else "")' "$expr"
  else
    echo "__NO_PARSER__"
  fi
}
