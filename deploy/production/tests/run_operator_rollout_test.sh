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
  assert_contains "$script_text" "intents-juno-juno-scan.sh" "run-operator-rollout reinstalls the juno-scan wrapper on live rollouts"
  assert_contains "$script_text" "intents-juno-juno-scan-backfill.sh" "run-operator-rollout reinstalls the juno-scan backfill wrapper on live rollouts"
  assert_contains "$script_text" "operator-signer-api.service" "run-operator-rollout restarts the operator signer api service on live rollouts"
  assert_contains "$script_text" "juno-scan.service" "run-operator-rollout reinstalls the juno-scan systemd unit on live rollouts"
  assert_contains "$script_text" "juno-scan-backfill.service" "run-operator-rollout reinstalls the juno-scan backfill systemd unit on live rollouts"
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

  assert_contains "$script_text" 'for cmd in curl jq sha256sum sudo systemctl tar openssl; do' "run-operator-rollout requires the release download toolchain"
  assert_contains "$script_text" 'download_github_release_asset_with_checksum() {' "run-operator-rollout defines a shared GitHub release downloader"
  assert_contains "$script_text" 'ensure_runtime_juno_txsign_binary() {' "run-operator-rollout defines a juno-txsign repair helper"
  assert_contains "$script_text" "requested_tag=\"\$(jq -r '.juno_txsign_release_tag // empty' \"\$operator_deploy\")\"" "run-operator-rollout reads an optional pinned juno-txsign release tag from the operator manifest"
  assert_contains "$script_text" "sudo /usr/local/bin/juno-txsign sign-digest --help 2>&1 | grep -q -- '--operator-endpoint'" "run-operator-rollout verifies operator-endpoint support before skipping repair"
  assert_contains "$script_text" 'sudo /usr/local/bin/juno-txsign serve --help >/dev/null 2>&1' "run-operator-rollout verifies the signer API server mode before skipping repair"
  assert_contains "$script_text" 'download_github_release_asset_with_checksum "junocash-tools/juno-txsign" "$requested_tag" "$asset_name" "$archive"' "run-operator-rollout repairs juno-txsign from the published upstream release"
  assert_contains "$script_text" 'sudo install -m 0755 "$extract_dir/juno-txsign" /usr/local/bin/juno-txsign' "run-operator-rollout installs the repaired juno-txsign binary into /usr/local/bin"
  assert_contains "$script_text" 'printf '\''%s\n'\'' "$requested_tag" | sudo tee "$release_tag_marker" >/dev/null' "run-operator-rollout records the installed juno-txsign release tag on the host"
}

test_run_operator_rollout_repairs_deposit_relayer_from_published_release() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" 'ensure_runtime_deposit_relayer_binary() {' "run-operator-rollout defines a deposit-relayer repair helper"
  assert_contains "$script_text" "requested_tag=\"\$(jq -r '.deposit_relayer_release_tag // empty' \"\$operator_deploy\")\"" "run-operator-rollout reads an optional pinned deposit-relayer release tag from the operator manifest"
  assert_contains "$script_text" 'download_github_release_asset_with_checksum "juno-intents/intents-juno" "$requested_tag" "$asset_name" "$binary_path"' "run-operator-rollout repairs deposit-relayer from the published app binary release"
  assert_contains "$script_text" 'sudo install -m 0755 "$binary_path" /usr/local/bin/deposit-relayer' "run-operator-rollout installs the repaired deposit-relayer into /usr/local/bin"
  assert_contains "$script_text" 'release_tag_marker="/var/lib/intents-juno/.deposit-relayer-release-tag"' "run-operator-rollout records the installed deposit-relayer release tag on the host"
}

test_run_operator_rollout_repairs_withdraw_binaries_from_published_release() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" 'ensure_runtime_withdraw_coordinator_binary() {' "run-operator-rollout defines a withdraw-coordinator repair helper"
  assert_contains "$script_text" 'asset_name="withdraw-coordinator_linux_amd64"' "run-operator-rollout downloads withdraw-coordinator from the published app binary release"
  assert_contains "$script_text" 'sudo install -m 0755 "$binary_path" /usr/local/bin/withdraw-coordinator' "run-operator-rollout installs withdraw-coordinator into /usr/local/bin"
  assert_contains "$script_text" 'release_tag_marker="/var/lib/intents-juno/.withdraw-coordinator-release-tag"' "run-operator-rollout records the installed withdraw-coordinator release tag on the host"
  assert_contains "$script_text" 'ensure_runtime_withdraw_finalizer_binary() {' "run-operator-rollout defines a withdraw-finalizer repair helper"
  assert_contains "$script_text" 'asset_name="withdraw-finalizer_linux_amd64"' "run-operator-rollout downloads withdraw-finalizer from the published app binary release"
  assert_contains "$script_text" 'sudo install -m 0755 "$binary_path" /usr/local/bin/withdraw-finalizer' "run-operator-rollout installs withdraw-finalizer into /usr/local/bin"
  assert_contains "$script_text" 'release_tag_marker="/var/lib/intents-juno/.withdraw-finalizer-release-tag"' "run-operator-rollout records the installed withdraw-finalizer release tag on the host"
  assert_contains "$script_text" 'ensure_runtime_base_event_scanner_binary() {' "run-operator-rollout defines a base-event-scanner repair helper"
  assert_contains "$script_text" 'asset_name="base-event-scanner_linux_amd64"' "run-operator-rollout downloads base-event-scanner from the published app binary release"
  assert_contains "$script_text" 'sudo install -m 0755 "$binary_path" /usr/local/bin/base-event-scanner' "run-operator-rollout installs base-event-scanner into /usr/local/bin"
  assert_contains "$script_text" 'release_tag_marker="/var/lib/intents-juno/.base-event-scanner-release-tag"' "run-operator-rollout records the installed base-event-scanner release tag on the host"
}

test_run_operator_rollout_refreshes_dkg_client_tls_identity_after_staging() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/run-operator-rollout.sh")"

  assert_contains "$script_text" 'for cmd in curl jq sha256sum sudo systemctl tar openssl; do' "run-operator-rollout requires openssl for dkg client cert hashing"
  assert_contains "$script_text" 'certificate_sha256_hex() {' "run-operator-rollout defines a cert fingerprint helper"
  assert_contains "$script_text" 'openssl x509 -in "$cert_path" -outform DER' "run-operator-rollout hashes the coordinator client cert from DER bytes"
  assert_contains "$script_text" 'refresh_dkg_client_tls_identity() {' "run-operator-rollout defines a dkg client tls refresh helper"
  assert_contains "$script_text" 'coordinator_client_cert_sha256: $fingerprint' "run-operator-rollout rewrites the dkg client cert fingerprint after staging tls"
  assert_contains "$script_text" 'tls_client_cert_pem_path: "./tls/coordinator-client.pem"' "run-operator-rollout rewrites the dkg client cert path after staging tls"
  assert_contains "$script_text" 'tls_client_key_pem_path: "./tls/coordinator-client.key"' "run-operator-rollout rewrites the dkg client key path after staging tls"
  assert_contains "$script_text" 'operator runtime admin config missing coordinator client tls paths' "run-operator-rollout verifies the refreshed dkg client tls paths"
  assert_contains "$script_text" 'operator runtime admin config missing coordinator client fingerprint' "run-operator-rollout verifies the refreshed dkg client fingerprint"
  assert_contains "$script_text" 'stage_optional_tls_files' "run-operator-rollout stages replacement tls files before refreshing admin config"
  assert_contains "$script_text" 'refresh_dkg_client_tls_identity' "run-operator-rollout refreshes the dkg client tls identity during rollout"
}

main() {
  test_run_operator_rollout_recomputes_roster_hash_from_canonical_roster_without_newline
  test_run_operator_rollout_repairs_missing_dkg_admin_from_published_release
  test_run_operator_rollout_repairs_juno_txsign_from_published_release
  test_run_operator_rollout_repairs_deposit_relayer_from_published_release
  test_run_operator_rollout_repairs_withdraw_binaries_from_published_release
  test_run_operator_rollout_refreshes_dkg_client_tls_identity_after_staging
}

main "$@"
