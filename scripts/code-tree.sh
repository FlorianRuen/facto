#!/usr/bin/env bash
# Prints code_tree for security/score.json: the sha256 of
# `git ls-tree -r HEAD -- cmd internal connectors`. Single definition, used by
# check-score.sh and by the security auditor when writing score.json.
set -euo pipefail
git ls-tree -r HEAD -- cmd internal connectors | sha256sum | cut -d' ' -f1
