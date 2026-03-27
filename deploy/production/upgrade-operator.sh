#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

cat >&2 <<'EOF'
error: upgrade-operator.sh is disabled

Use the release-driven rollout path instead:
  1. publish the operator release artifacts
  2. update the operator handoff/runtime refs
  3. run deploy/production/deploy-operator.sh
EOF

exit 1
