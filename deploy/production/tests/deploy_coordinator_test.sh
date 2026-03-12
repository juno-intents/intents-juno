#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh "$workdir/known_hosts" \
    --arg app_kh "$workdir/app-known_hosts" \
    --arg backup "$workdir/dkg-backup.zip" \
    --arg secrets "$workdir/operator-secrets.env" \
    --arg app_secrets "$workdir/app-secrets.env" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_deploy_coordinator_generates_handoffs() {
  local workdir output_dir manifest operator_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  manifest="$output_dir/alpha/shared-manifest.json"
  operator_dir="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111"
  assert_file_exists "$manifest" "shared manifest"
  assert_file_exists "$output_dir/alpha/rollout-state.json" "rollout state"
  assert_file_exists "$operator_dir/operator-deploy.json" "operator manifest"
  assert_file_exists "$output_dir/alpha/app/app-deploy.json" "app manifest"
  assert_eq "$(jq -r '.environment' "$manifest")" "alpha" "manifest environment"
  assert_eq "$(jq -r '.contracts.juno_network' "$manifest")" "testnet" "manifest juno network"
  assert_eq "$(jq -r '.governance.timelock.address' "$manifest")" "0x8888888888888888888888888888888888888888" "timelock address"
  assert_eq "$(jq -r '.dns.record_name' "$operator_dir/operator-deploy.json")" "op1.alpha.intents-testing.thejunowallet.com" "operator dns record"
  assert_eq "$(jq -r '.operator_address' "$operator_dir/operator-deploy.json")" "0x9999999999999999999999999999999999999999" "operator signer address"
  assert_eq "$(jq -r '.checkpoint_signer_driver' "$operator_dir/operator-deploy.json")" "aws-kms" "operator signer driver"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$operator_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "operator signer kms key id"
  assert_eq "$(jq -r '.services.bridge_api.public_url' "$output_dir/alpha/app/app-deploy.json")" "https://bridge.alpha.intents-testing.thejunowallet.com" "app manifest bridge url"
  rm -rf "$workdir"
}

test_deploy_coordinator_supports_run_label() {
  local workdir output_dir run_dir operator_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" \
    --run-label "run-fixed" >/dev/null

  run_dir="$output_dir/alpha/run-fixed"
  operator_dir="$run_dir/operators/0x1111111111111111111111111111111111111111"
  assert_file_exists "$run_dir/shared-manifest.json" "run label shared manifest"
  assert_file_exists "$run_dir/rollout-state.json" "run label rollout state"
  assert_file_exists "$operator_dir/operator-deploy.json" "run label operator manifest"
  assert_file_exists "$run_dir/app/app-deploy.json" "run label app manifest"
  assert_eq "$(jq -r '.shared_manifest_path' "$operator_dir/operator-deploy.json")" "$run_dir/shared-manifest.json" "run label shared manifest path"
  assert_eq "$(jq -r '.rollout_state_file' "$operator_dir/operator-deploy.json")" "$run_dir/rollout-state.json" "run label rollout state path"
  assert_eq "$(jq -r '.shared_manifest_path' "$run_dir/app/app-deploy.json")" "$run_dir/shared-manifest.json" "run label app shared manifest path"
  rm -rf "$workdir"
}

test_deploy_coordinator_normalizes_relative_output_paths() {
  local workdir inventory_path operator_dir
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  inventory_path="$workdir/inventory.json"

  (
    cd "$workdir"
    bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$inventory_path" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir output >/dev/null
  )

  operator_dir="$workdir/output/alpha/operators/0x1111111111111111111111111111111111111111"
  assert_eq "$(jq -r '.shared_manifest_path' "$operator_dir/operator-deploy.json")" "$workdir/output/alpha/shared-manifest.json" "relative output path shared manifest path"
  assert_eq "$(jq -r '.rollout_state_file' "$operator_dir/operator-deploy.json")" "$workdir/output/alpha/rollout-state.json" "relative output path rollout state path"
  assert_eq "$(jq -r '.shared_manifest_path' "$workdir/output/alpha/app/app-deploy.json")" "$workdir/output/alpha/shared-manifest.json" "relative output path app shared manifest path"
  rm -rf "$workdir"
}

test_deploy_coordinator_uses_dkg_completion_for_signer_ufvk() {
  local workdir output_dir dkg_summary_no_ufvk dkg_completion bridge_summary_no_ua manifest
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.contracts.owallet_ua)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary_no_ufvk="$workdir/dkg-summary.no-ufvk.json"
  jq 'del(.ufvk)' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary_no_ufvk"
  bridge_summary_no_ua="$workdir/bridge-summary.no-ua.json"
  jq 'del(.owallet_ua) | del(.juno_shielded_address)' "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" >"$bridge_summary_no_ua"
  dkg_completion="$workdir/dkg-completion.json"
  cat >"$dkg_completion" <<'EOF'
{
  "network": "testnet",
  "ufvk": "uview1coordinatorfallback",
  "juno_shielded_address": "u1coordinatorfallback"
}
EOF

  bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$dkg_summary_no_ufvk" \
    --dkg-completion "$dkg_completion" \
    --existing-bridge-summary "$bridge_summary_no_ua" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  manifest="$output_dir/alpha/shared-manifest.json"
  assert_eq "$(jq -r '.checkpoint.signer_ufvk' "$manifest")" "uview1coordinatorfallback" "coordinator signer ufvk fallback"
  assert_eq "$(jq -r '.contracts.owallet_ua' "$manifest")" "u1coordinatorfallback" "coordinator juno shielded address fallback"
  rm -rf "$workdir"
}

main() {
  test_deploy_coordinator_generates_handoffs
  test_deploy_coordinator_supports_run_label
  test_deploy_coordinator_normalizes_relative_output_paths
  test_deploy_coordinator_uses_dkg_completion_for_signer_ufvk
}

main "$@"
