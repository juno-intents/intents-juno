#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

assert_file_missing() {
  local path="$1"
  local msg="$2"
  if [[ -e "$path" ]]; then
    printf 'assert_file_missing failed: %s: %s\n' "$msg" "$path" >&2
    exit 1
  fi
}

test_package_mainnet_release_keeps_live_runtime_refs_and_omits_local_materials() {
  local workdir handoff_dir release_dir operator_id bundle_zip extract_dir bundle_root manifest_path
  workdir="$(mktemp -d)"
  handoff_dir="$workdir/handoff/mainnet"
  release_dir="$workdir/release"
  operator_id="0x1111111111111111111111111111111111111111"

  mkdir -p "$handoff_dir/operators/$operator_id"
  cat >"$handoff_dir/shared-manifest.json" <<'JSON'
{"contracts":{"base_rpc_url":"https://base.example.invalid"}}
JSON
  cat >"$handoff_dir/rollout-state.json" <<JSON
{"operators":[{"operator_id":"$operator_id","status":"pending"}]}
JSON
  cat >"$handoff_dir/operators/$operator_id/operator-deploy.json" <<JSON
{
  "version": "3",
  "environment": "mainnet",
  "shared_manifest_path": "../../shared-manifest.json",
  "rollout_state_file": "../../rollout-state.json",
  "operator_id": "$operator_id",
  "operator_address": "0x9999999999999999999999999999999999999999",
  "checkpoint_signer_driver": "aws-kms",
  "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555",
  "checkpoint_blob_bucket": "mainnet-op1-checkpoints",
  "checkpoint_blob_prefix": "operators/op1/checkpoint-packages",
  "checkpoint_blob_sse_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "operator_index": 1,
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "account_id": "021490342184",
  "operator_host": "203.0.113.11",
  "asg": "juno-op1",
  "launch_template": {
    "id": "lt-0123456789abcdef0",
    "version": "1"
  },
  "operator_user": "ubuntu",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "runtime_material_ref": {
    "mode": "s3-kms-zip",
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op1/runtime-material.zip",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
  },
  "runtime_config_secret_id": "mainnet/op1/runtime-config",
  "runtime_config_secret_region": "us-east-1",
  "public_endpoint": "203.0.113.11",
  "dns": {
    "mode": "public-zone",
    "zone_id": "Z01169511CVMQJAD7T3TJ",
    "record_name": "op1.mainnet.intents.thejunowallet.com",
    "ttl_seconds": 60
  }
}
JSON

  bash "$REPO_ROOT/deploy/production/package-mainnet-release.sh" \
    --handoff-dir "$handoff_dir" \
    --release-tag "v1.2.3-mainnet" \
    --output-dir "$release_dir"

  bundle_zip="$(find "$release_dir" -name 'operator-bundle-*.zip' -print | head -n 1)"
  assert_file_exists "$bundle_zip" "live release bundle zip"
  extract_dir="$workdir/extract"
  unzip -q "$bundle_zip" -d "$extract_dir"
  bundle_root="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d -print | head -n 1)"
  manifest_path="$bundle_root/bundle/operator/operators/$operator_id/operator-deploy.json"

  assert_file_exists "$bundle_root/deploy/production/run-operator-rollout.sh" "live bundle includes the host rollout entrypoint"
  assert_file_exists "$bundle_root/deploy/production/run-operator-local-canary.sh" "live bundle includes the host canary entrypoint"
  assert_file_exists "$bundle_root/deploy/production/prepare-runtime-materials.sh" "live bundle includes the runtime material setup helper"
  assert_eq "$(jq -r '.runtime_material_ref.mode' "$manifest_path")" "s3-kms-zip" "live bundle preserves the runtime material mode"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$manifest_path")" "mainnet/op1/runtime-config" "live bundle preserves the runtime config secret id"
  assert_eq "$(jq -r '.dkg_backup_zip // ""' "$manifest_path")" "" "live bundle omits local runtime packages from the manifest"
  assert_eq "$(jq -r '.secret_contract_file // ""' "$manifest_path")" "" "live bundle omits local secret contracts from the manifest"
  assert_file_missing "$bundle_root/bundle/operator/operators/$operator_id/dkg-backup.zip" "live bundle does not include a local runtime package"
  assert_file_missing "$bundle_root/bundle/operator/operators/$operator_id/operator-secrets.env" "live bundle does not include a local secret contract"
  assert_file_missing "$bundle_root/bundle/operator/operators/$operator_id/known_hosts" "live bundle does not include a known_hosts file"

  rm -rf "$workdir"
}

main() {
  test_package_mainnet_release_keeps_live_runtime_refs_and_omits_local_materials
}

main "$@"
