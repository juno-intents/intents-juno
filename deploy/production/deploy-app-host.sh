#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

cat <<'EOF' >&2
deploy-app-host.sh is deprecated.
Use the role-backed app deployment flow driven by app-role outputs and instance refresh.
EOF

exit 1
