#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_operator_manifest_with_runtime_refs() {
  local target="$1"
  local mode="${2:-s3-kms-zip}"
  cat >"$target" <<JSON
{
  "environment": "mainnet",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "operator_host": "203.0.113.11",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "runtime_config_secret_id": "mainnet/op1/runtime-config",
  "runtime_material_ref": {
    "mode": "$mode",
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op1/runtime-material.zip",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
  }
}
JSON
}

test_operator_boot_canary_dry_run_validates_runtime_material_refs() {
  local tmp manifest output_json
  tmp="$(mktemp -d)"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  write_operator_manifest_with_runtime_refs "$manifest"

  bash "$REPO_ROOT/deploy/production/canary-operator-boot.sh" \
    --operator-deploy "$manifest" \
    --dry-run >"$output_json"

  assert_eq "$(jq -r '.operator_id' "$output_json")" "0x1111111111111111111111111111111111111111" "dry-run output operator id"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "dry-run output is not deploy-ready"
  assert_eq "$(jq -r '.checks.inputs.status' "$output_json")" "skipped" "dry-run skips input checks"
  assert_eq "$(jq -r '.checks.systemd.detail' "$output_json")" "dry run" "dry-run annotates skipped systemd check"

  rm -rf "$tmp"
}

test_operator_boot_canary_rejects_missing_runtime_material_ref() {
  local tmp manifest stderr
  tmp="$(mktemp -d)"
  manifest="$tmp/operator-deploy.json"
  stderr="$tmp/stderr"
  write_operator_manifest_with_runtime_refs "$manifest" ""
  jq 'del(.runtime_material_ref.mode)' "$manifest" >"$manifest.tmp"
  mv "$manifest.tmp" "$manifest"

  if bash "$REPO_ROOT/deploy/production/canary-operator-boot.sh" \
    --operator-deploy "$manifest" \
    --dry-run >"$tmp/stdout" 2>"$stderr"; then
    printf 'expected canary-operator-boot.sh to reject missing runtime material mode\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "operator deploy manifest must set runtime_material_ref.mode=s3-kms-zip" "missing runtime material mode is rejected"

  rm -rf "$tmp"
}

main() {
  test_operator_boot_canary_dry_run_validates_runtime_material_refs
  test_operator_boot_canary_rejects_missing_runtime_material_ref
}

main "$@"
