#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

cat >&2 <<'EOF'
error: rotate-operator-key.sh is disabled

Use the release-driven operator handoff flow instead:
  1. prepare a new operator handoff with deploy/production/prepare-operator-handoff.sh
  2. apply the updated handoff refs
  3. redeploy through deploy/production/deploy-operator.sh
EOF

exit 1
