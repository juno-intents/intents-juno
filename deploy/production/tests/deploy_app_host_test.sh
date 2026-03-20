#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

test_deploy_app_host_is_fail_closed() {
  local tmpdir stdout stderr
  tmpdir="$(mktemp -d)"
  stdout="$tmpdir/stdout"
  stderr="$tmpdir/stderr"

  if bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" >"$stdout" 2>"$stderr"; then
    printf 'expected deploy-app-host.sh to fail closed\n' >&2
    rm -rf "$tmpdir"
    exit 1
  fi

  grep -Fq 'deploy-app-host.sh is deprecated.' "$stderr"
  grep -Fq 'Use the role-backed app deployment flow driven by app-role outputs and instance refresh.' "$stderr"
  [[ ! -s "$stdout" ]]
  rm -rf "$tmpdir"
}

main() {
  test_deploy_app_host_is_fail_closed
  echo "deploy app host cleanup test: PASS"
}

main "$@"
