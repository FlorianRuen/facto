#!/usr/bin/env bash
# PostToolUse: format Go files right after an edit, warn on shrinking tests. Never fails the turn.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
file="$(json_field .tool_input.file_path)"
case "$file" in
  *.go)
    command -v gofumpt  >/dev/null 2>&1 && gofumpt -w "$file"
    command -v goimports >/dev/null 2>&1 && goimports -w "$file"
    ;;
esac
if [[ "$file" == *_test.go ]] && git rev-parse --git-dir >/dev/null 2>&1; then
  read -r added removed _ < <(git diff --numstat -- "$file" 2>/dev/null || echo "0 0 x")
  if [[ "${removed:-0}" =~ ^[0-9]+$ && "${added:-0}" =~ ^[0-9]+$ ]] && (( removed > added + 20 )); then
    echo "format.sh: warning: $file lost $((removed - added)) lines. Removing assertions breaks CLAUDE.md rule 1." >&2
  fi
fi
exit 0
