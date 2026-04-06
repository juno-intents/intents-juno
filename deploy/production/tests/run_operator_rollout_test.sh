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
  assert_contains "$script_text" "intents-juno-operator-signer-api.sh" "run-operator-rollout reinstalls the operator signer api wrapper on live rollouts"
  assert_contains "$script_text" "operator-signer-api.service" "run-operator-rollout restarts the operator signer api service on live rollouts"
}

test_run_operator_rollout_repairs_missing_dkg_admin_from_published_release() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" 'dkg_common_stage="$stage_dir/common.sh"' "run-operator-rollout stages the dkg common helper"
  assert_contains "$script_text" 'ensure_runtime_dkg_admin_binary() {' "run-operator-rollout defines a runtime dkg-admin repair helper"
  assert_contains "$script_text" 'if sudo test -x "$runtime_dir/bin/dkg-admin"; then' "run-operator-rollout only repairs dkg-admin when runtime restore missed it"
  assert_contains "$script_text" 'export JUNO_DKG_DISABLE_SOURCE_BUILD="true"' "run-operator-rollout disables dkg source-build fallback during live repair"
  assert_contains "$script_text" 'ensure_dkg_binary "dkg-admin" "${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}" "$dkg_stage_dir"' "run-operator-rollout repairs dkg-admin from the published release path only"
  assert_contains "$script_text" 'sudo install -d -m 0755 "$runtime_dir/bin"' "run-operator-rollout creates the runtime bin dir before repairing dkg-admin"
  assert_contains "$script_text" 'sudo install -m 0755 "$dkg_admin_downloaded" "$runtime_dir/bin/dkg-admin"' "run-operator-rollout installs the repaired dkg-admin into the runtime dir"
}

main() {
  test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline
  test_run_operator_rollout_repairs_missing_dkg_admin_from_published_release
}

main "$@"
