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

test_run_operator_rollout_repairs_juno_txsign_from_published_release() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" 'for cmd in curl jq sha256sum sudo systemctl tar; do' "run-operator-rollout requires the release download toolchain"
  assert_contains "$script_text" 'download_github_release_asset_with_checksum() {' "run-operator-rollout defines a shared GitHub release downloader"
  assert_contains "$script_text" 'ensure_runtime_juno_txsign_binary() {' "run-operator-rollout defines a juno-txsign repair helper"
  assert_contains "$script_text" "requested_tag=\"\$(jq -r '.juno_txsign_release_tag // empty' \"\$operator_deploy\")\"" "run-operator-rollout reads an optional pinned juno-txsign release tag from the operator manifest"
  assert_contains "$script_text" "sudo /usr/local/bin/juno-txsign sign-digest --help 2>&1 | grep -q -- '--operator-endpoint'" "run-operator-rollout verifies operator-endpoint support before skipping repair"
  assert_contains "$script_text" 'sudo /usr/local/bin/juno-txsign serve --help >/dev/null 2>&1' "run-operator-rollout verifies the signer API server mode before skipping repair"
  assert_contains "$script_text" 'download_github_release_asset_with_checksum "junocash-tools/juno-txsign" "$requested_tag" "$asset_name" "$archive"' "run-operator-rollout repairs juno-txsign from the published upstream release"
  assert_contains "$script_text" 'sudo install -m 0755 "$extract_dir/juno-txsign" /usr/local/bin/juno-txsign' "run-operator-rollout installs the repaired juno-txsign binary into /usr/local/bin"
  assert_contains "$script_text" 'printf '\''%s\n'\'' "$requested_tag" | sudo tee "$release_tag_marker" >/dev/null' "run-operator-rollout records the installed juno-txsign release tag on the host"
}

main() {
  test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline
  test_run_operator_rollout_repairs_missing_dkg_admin_from_published_release
  test_run_operator_rollout_repairs_juno_txsign_from_published_release
}

main "$@"
