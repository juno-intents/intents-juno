#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

test_rotate_operator_key_is_disabled_for_release_driven_handoffs() {
  local stdout stderr
  stdout="$(mktemp)"
  stderr="$(mktemp)"

  if bash "$REPO_ROOT/deploy/production/rotate-operator-key.sh" >"$stdout" 2>"$stderr"; then
    printf 'expected rotate-operator-key.sh to fail closed\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "rotate-operator-key.sh is disabled" "rotation helper fails closed"
  assert_contains "$(cat "$stderr")" "prepare a new operator handoff with deploy/production/prepare-operator-handoff.sh" "rotation helper points to the release-driven handoff flow"
  assert_contains "$(cat "$stderr")" "redeploy through deploy/production/deploy-operator.sh" "rotation helper points to operator redeploy"
  assert_eq "$(cat "$stdout")" "" "disabled rotation helper does not write stdout"

  rm -f "$stdout" "$stderr"
}

main() {
  test_rotate_operator_key_is_disabled_for_release_driven_handoffs
}

main "$@"
