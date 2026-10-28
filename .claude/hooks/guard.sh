#!/usr/bin/env bash
# PreToolUse guard for Bash. Reads the hook JSON on stdin; exit 2 blocks the call
# and the message on stderr is shown to the agent.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
cmd="$(json_field .tool_input.command)"
[[ "$cmd" == "__NO_PARSER__" ]] && { echo "guard.sh: install jq or python3 (fail closed)" >&2; exit 2; }

block() { echo "guard.sh: blocked: $1" >&2; exit 2; }

# Secrets and real accounts are off limits to agents.
[[ "$cmd" =~ (^|[[:space:]\;\|\&])(bw|op|pass|secret-tool|keepassxc-cli)([[:space:]]|$) ]] \
  && block "password manager CLIs are only used by facto itself and by Florian (H4)"
[[ "$cmd" =~ BW_SESSION|BW_PASSWORD|ANTHROPIC_API_KEY|GOOGLE_CLIENT_SECRET ]] \
  && block "do not touch secret environment variables"
[[ "$cmd" =~ \.facto/|\.config/facto|\.ssh/|\.har\.raw ]] \
  && block "user state, keys and raw HAR files are not readable by agents"

# No ad-hoc network: go through Go tests and the module proxy only.
[[ "$cmd" =~ (^|[[:space:]\;\|\&])(curl|wget|nc|ncat|ssh|scp)([[:space:]]|$) ]] \
  && block "no ad-hoc network tools; write a test using internal/httpx instead"

# Protect history and the safety net.
[[ "$cmd" =~ git[[:space:]]+push.*(-f|--force) ]] && block "force push is forbidden"
[[ "$cmd" =~ git[[:space:]]+(reset[[:space:]]+--hard|clean[[:space:]]+-fdx) ]] && block "destructive git command"
[[ "$cmd" =~ (-test\.skip|[[:space:]]-skip[[:space:]]|t\.Skip) ]] && block "skipping tests is forbidden (CLAUDE.md rule 1)"
[[ "$cmd" =~ (chmod|rm|mv)[[:space:]].*\.claude/hooks ]] && block "hooks are not editable by agents"

exit 0
