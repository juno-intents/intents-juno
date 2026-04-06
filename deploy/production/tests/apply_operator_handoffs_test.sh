#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_operator_deploy_fixture() {
  local target="$1"
  local operator_id="$2"
  local operator_index="$3"
  local operator_host="$4"
  cat >"$target" <<JSON
{
  "version": "3",
  "environment": "mainnet",
  "shared_manifest_path": "../../shared-manifest.json",
  "rollout_state_file": "../../rollout-state.json",
  "operator_id": "$operator_id",
  "operator_address": "$operator_id",
  "operator_index": $operator_index,
  "operator_host": "$operator_host",
  "public_endpoint": "$operator_host",
  "operator_user": "ubuntu",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "checkpoint_signer_driver": "aws-kms",
  "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/original-$operator_index",
  "runtime_material_ref": {
    "mode": "s3-kms-zip",
    "bucket": "original-runtime-materials",
    "key": "operators/$operator_index/runtime-material.zip",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/original-runtime-$operator_index"
  },
  "runtime_config_secret_id": "original/op$operator_index/runtime-config",
  "runtime_config_secret_region": "us-east-1"
}
JSON
}

write_operator_handoff_fixture() {
  local target="$1"
  local operator_id="$2"
  local operator_address="$3"
  local operator_index="$4"
  cat >"$target" <<JSON
{
  "operator_id": "$operator_id",
  "operator_address": "$operator_address",
  "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/final-$operator_index",
  "base_relayer_address": "0x777777777777777777777777777777777777777$operator_index",
  "withdraw_coordinator_juno_wallet_id": "wallet-mainnet-$operator_index-coordinator",
  "withdraw_finalizer_juno_scan_wallet_id": "wallet-mainnet-$operator_index-finalizer",
  "runtime_material_ref": {
    "mode": "s3-kms-zip",
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op$operator_index/runtime-material.zip",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/final-runtime-$operator_index"
  },
  "runtime_config_secret_id": "mainnet/op$operator_index/runtime-config",
  "runtime_config_secret_region": "us-east-1",
  "access": {
    "user_name": "mainnet-op$operator_index-runtime-access",
    "access_key_id": "AKIAEXAMPLE$operator_index",
    "secret_access_key": "secret-example-$operator_index"
  }
}
JSON
}

test_apply_operator_handoffs_updates_live_manifests_and_rosters() {
  local tmp handoff_dir op1 op2
  tmp="$(mktemp -d)"
  handoff_dir="$tmp/mainnet"
  op1="0x1111111111111111111111111111111111111111"
  op2="0x2222222222222222222222222222222222222222"

  mkdir -p "$handoff_dir/operators/$op1" "$handoff_dir/operators/$op2" "$handoff_dir/app"
  cat >"$handoff_dir/shared-manifest.json" <<JSON
{
  "environment": "mainnet",
  "checkpoint": {
    "operators": ["$op1", "$op2"],
    "threshold": 2
  },
  "operator_roster": [
    {"operator_id": "$op1", "dkg_endpoint": "https://203.0.113.11:18443"},
    {"operator_id": "$op2", "dkg_endpoint": "https://203.0.113.12:18444"}
  ]
}
JSON
  cat >"$handoff_dir/app/app-deploy.json" <<JSON
{
  "operator_addresses": ["$op1", "$op2"],
  "operator_endpoints": ["$op1=203.0.113.11:18443", "$op2=203.0.113.12:18444"]
}
JSON
  cat >"$handoff_dir/rollout-state.json" <<JSON
{"operators":[{"operator_id":"$op1","status":"pending"},{"operator_id":"$op2","status":"pending"}]}
JSON

  write_operator_deploy_fixture "$handoff_dir/operators/$op1/operator-deploy.json" "$op1" 1 "203.0.113.11"
  write_operator_deploy_fixture "$handoff_dir/operators/$op2/operator-deploy.json" "$op2" 2 "203.0.113.12"
  write_operator_handoff_fixture "$handoff_dir/operators/$op1/operator-handoff.json" "$op1" "0x9999999999999999999999999999999999999999" 1
  write_operator_handoff_fixture "$handoff_dir/operators/$op2/operator-handoff.json" "$op2" "0x8888888888888888888888888888888888888888" 2

  bash "$REPO_ROOT/deploy/production/apply-operator-handoffs.sh" \
    --handoff-dir "$handoff_dir"

  assert_eq "$(jq -r '.operator_address' "$handoff_dir/operators/$op1/operator-deploy.json")" "0x9999999999999999999999999999999999999999" "apply updates the first operator address"
  assert_eq "$(jq -r '.operator_address' "$handoff_dir/operators/$op2/operator-deploy.json")" "0x8888888888888888888888888888888888888888" "apply updates the second operator address"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$handoff_dir/operators/$op1/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/final-1" "apply updates the first operator checkpoint signer kms key"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$handoff_dir/operators/$op2/operator-deploy.json")" "mainnet/op2/runtime-config" "apply updates the second runtime config secret id"
  assert_eq "$(jq -r '.withdraw_coordinator_juno_wallet_id' "$handoff_dir/operators/$op1/operator-deploy.json")" "wallet-mainnet-1-coordinator" "apply updates the first coordinator wallet id"
  assert_eq "$(jq -r '.withdraw_finalizer_juno_scan_wallet_id' "$handoff_dir/operators/$op2/operator-deploy.json")" "wallet-mainnet-2-finalizer" "apply updates the second finalizer wallet id"
  assert_eq "$(jq -r '.deposit_scan_juno_scan_wallet_id' "$handoff_dir/operators/$op1/operator-deploy.json")" "wallet-mainnet-1-finalizer" "apply derives the deposit scan wallet id from the returned handoff"
  assert_eq "$(jq -r '.withdraw_operator_endpoints[0]' "$handoff_dir/operators/$op1/operator-deploy.json")" "0x9999999999999999999999999999999999999999=203.0.113.11:18443" "apply writes the first operator endpoint roster entry"
  assert_eq "$(jq -r '.withdraw_operator_endpoints[1]' "$handoff_dir/operators/$op1/operator-deploy.json")" "0x8888888888888888888888888888888888888888=203.0.113.12:18444" "apply writes the second operator endpoint roster entry"
  assert_eq "$(jq -r '.checkpoint.operators[0]' "$handoff_dir/shared-manifest.json")" "0x9999999999999999999999999999999999999999" "apply rewrites the shared checkpoint operator roster"
  assert_eq "$(jq -r '.checkpoint.operators[1]' "$handoff_dir/shared-manifest.json")" "0x8888888888888888888888888888888888888888" "apply rewrites the shared checkpoint operator roster for the second operator"
  assert_eq "$(jq -r '.operator_addresses[0]' "$handoff_dir/app/app-deploy.json")" "0x9999999999999999999999999999999999999999" "apply rewrites app operator addresses"
  assert_eq "$(jq -r '.operator_endpoints[1]' "$handoff_dir/app/app-deploy.json")" "0x8888888888888888888888888888888888888888=203.0.113.12:18444" "apply rewrites app operator endpoints"

  rm -rf "$tmp"
}

main() {
  test_apply_operator_handoffs_updates_live_manifests_and_rosters
}

main "$@"
