#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" "dkg_roster_canonical=" "run-operator-rollout stores the canonical roster before hashing"
  assert_contains "$script_text" "jq -c '.roster' \"\$dkg_roster_tmp\"" "run-operator-rollout canonicalizes the nested roster before hashing"
  assert_contains "$script_text" 'printf '\''%s'\'' "$dkg_roster_canonical" | sha256sum' "run-operator-rollout hashes the canonical roster without a trailing newline"
  assert_not_contains "$script_text" 'jq -r '\''.roster | @json'\'' "$dkg_roster_tmp" | sha256sum' "run-operator-rollout no longer hashes roster json with an implicit trailing newline"
}

main() {
  test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline
}

main "$@"
