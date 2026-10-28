#!/usr/bin/env bash
# Usage: check-coverage.sh coverage.out "pkg:min pkg:min ..." default_min
set -euo pipefail
out=$1; gates=$2; def=${3:-70}
go tool cover -func="$out" >/dev/null
fail=0
for pkg in $(go list ./... | grep -v /test/); do
  short=${pkg#*/facto/}
  min=$def
  for g in $gates; do [[ "$short" == "${g%%:*}" ]] && min=${g##*:}; done
  pct=$(go test -cover "$pkg" 2>/dev/null | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p')
  [[ -z "$pct" ]] && continue
  printf '%-40s %6s%% (min %s%%)\n' "$short" "$pct" "$min"
  awk -v p="$pct" -v m="$min" 'BEGIN{exit !(p+0 < m+0)}' && fail=1
done
exit $fail
