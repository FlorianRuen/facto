#!/usr/bin/env bash
# Usage: check-coverage.sh coverage.out "pkg:min pkg:min ..." default_min
#
# A gate covers its package and every subpackage (internal/normalize gates
# internal/normalize/facturx). When several gates match a package, the longest
# (most specific) prefix wins, whatever their order in the list.
set -euo pipefail
out=$1; gates=$2; def=${3:-70}
go tool cover -func="$out" >/dev/null
fail=0
for pkg in $(go list ./... | grep -v /test/); do
  short=${pkg#*/facto/}
  min=$def
  best=-1
  for g in $gates; do
    prefix=${g%%:*}
    if [[ "$short" == "$prefix" || "$short" == "$prefix"/* ]] && (( ${#prefix} > best )); then
      best=${#prefix}
      min=${g##*:}
    fi
  done
  pct=$(go test -cover "$pkg" 2>/dev/null | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p')
  [[ -z "$pct" ]] && continue
  printf '%-40s %6s%% (min %s%%)\n' "$short" "$pct" "$min"
  awk -v p="$pct" -v m="$min" 'BEGIN{exit !(p+0 < m+0)}' && fail=1
done
exit $fail
