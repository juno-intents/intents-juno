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
  assert_contains "$script_text" "roster_version: .roster_version" "run-operator-rollout hashes the roster through the coordinator canonicalizer"
  assert_contains "$script_text" "sort_by(.operator_id)" "run-operator-rollout sorts operators before hashing"
  assert_contains "$script_text" "with_entries(select(.value != null))" "run-operator-rollout drops null roster fields before hashing"
  assert_contains "$script_text" 'compute_dkg_roster_hash_hex "$dkg_roster_canonical"' "run-operator-rollout hashes the canonical roster through the helper"
  assert_not_contains "$script_text" 'printf '\''%s'\'' "$dkg_roster_canonical" | sha256sum' "run-operator-rollout no longer hashes the raw roster object directly"
  assert_contains "$script_text" "intents-juno-multikey-extend-signer.sh" "run-operator-rollout reinstalls the extend signer wrapper on live rollouts"
}

main() {
  test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline
}

main "$@"
