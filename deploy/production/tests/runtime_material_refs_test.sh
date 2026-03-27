#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_live_inventory_fixture() {
  local target="$1"
  jq '
    .environment = "mainnet"
    | .dkg_tls_dir = ""
    | .operators[0].known_hosts_file = null
    | .operators[0].dkg_backup_zip = null
    | .operators[0].secret_contract_file = null
    | .operators[0].runtime_material_ref = {
        mode: "s3-kms-zip",
        bucket: "mainnet-runtime-materials",
        key: "operators/op1/runtime-material.zip",
        region: "us-east-1",
        kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
      }
    | .operators[0].runtime_config_secret_id = "mainnet/op1/runtime-config"
    | .operators[0].runtime_config_secret_region = "us-east-1"
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

render_live_handoffs() {
  local workdir="$1"
  local shared_manifest="$workdir/shared-manifest.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs \
    "$workdir/inventory.json" \
    "$shared_manifest" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$workdir/output" \
    "$workdir"
}

test_live_handoffs_emit_runtime_material_refs() {
  local workdir handoff_dir manifest
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  render_live_handoffs "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"

  assert_eq "$(jq -r '.version' "$manifest")" "3" "live operator manifest uses the runtime-ref schema version"
  assert_eq "$(jq -r '.runtime_material_ref.mode' "$manifest")" "s3-kms-zip" "live operator manifest carries the runtime material mode"
  assert_eq "$(jq -r '.runtime_material_ref.bucket' "$manifest")" "mainnet-runtime-materials" "live operator manifest carries the runtime material bucket"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$manifest")" "mainnet/op1/runtime-config" "live operator manifest carries the runtime config secret id"
  assert_eq "$(jq -r '.runtime_config_secret_region' "$manifest")" "us-east-1" "live operator manifest carries the runtime config secret region"
  assert_eq "$(jq -r '.dkg_backup_zip // ""' "$manifest")" "" "live operator manifest omits local runtime packages"
  assert_eq "$(jq -r '.secret_contract_file // ""' "$manifest")" "" "live operator manifest omits local secret contracts"
  if [[ -e "$handoff_dir/dkg-backup.zip" ]]; then
    printf 'expected no local runtime package in the live handoff dir\n' >&2
    exit 1
  fi
  if [[ -e "$handoff_dir/operator-secrets.env" ]]; then
    printf 'expected no local secret contract in the live handoff dir\n' >&2
    exit 1
  fi

  rm -rf "$workdir"
}

test_live_handoffs_reject_local_runtime_inputs() {
  local workdir output
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"
  jq '
    .operators[0].secret_contract_file = "operators/op1/operator-secrets.env"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  mkdir -p "$workdir/operators/op1"
  printf 'CHECKPOINT_POSTGRES_DSN=aws-sm://runtime\n' >"$workdir/operators/op1/operator-secrets.env"

  set +e
  output="$(
    (
      production_render_shared_manifest \
        "$workdir/inventory.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
        "$workdir/shared-manifest.json" \
        "$workdir"
      production_render_operator_handoffs \
        "$workdir/inventory.json" \
        "$workdir/shared-manifest.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        "$workdir/output" \
        "$workdir"
    ) 2>&1
  )"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    printf 'expected live handoff rendering to reject local runtime inputs\n' >&2
    exit 1
  fi
  assert_contains "$output" "must not set secret_contract_file" "live handoff rendering rejects local secret contracts"

  rm -rf "$workdir"
}

test_live_handoffs_reject_local_runtime_packages() {
  local workdir output
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"
  jq '
    .operators[0].dkg_backup_zip = "operators/op1/dkg-backup.zip"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  mkdir -p "$workdir/operators/op1"
  printf 'placeholder' >"$workdir/operators/op1/dkg-backup.zip"

  set +e
  output="$(
    (
      production_render_shared_manifest \
        "$workdir/inventory.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
        "$workdir/shared-manifest.json" \
        "$workdir"
      production_render_operator_handoffs \
        "$workdir/inventory.json" \
        "$workdir/shared-manifest.json" \
        "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        "$workdir/output" \
        "$workdir"
    ) 2>&1
  )"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    printf 'expected live handoff rendering to reject local runtime packages\n' >&2
    exit 1
  fi
  assert_contains "$output" "must not set dkg_backup_zip" "live handoff rendering rejects local runtime packages"

  rm -rf "$workdir"
}

test_runtime_config_render_skips_local_secret_requirements() {
  local workdir handoff_dir manifest rendered_env
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  render_live_handoffs "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"
  rendered_env="$workdir/operator-stack.env"
  : >"$workdir/resolved.env"

  production_render_operator_stack_env \
    "$workdir/shared-manifest.json" \
    "$manifest" \
    "$workdir/resolved.env" \
    "$rendered_env"

  assert_contains "$(cat "$rendered_env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "runtime-config render keeps the kms signer mode"
  assert_contains "$(cat "$rendered_env")" "JUNO_RPC_BIND=127.0.0.1" "runtime-config render restores the local rpc bind default"
  assert_contains "$(cat "$rendered_env")" "WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS=0x9999999999999999999999999999999999999999=203.0.113.11:18443" "runtime-config render stages operator endpoints for live withdraw signing"
  assert_not_contains "$(cat "$rendered_env")" "CHECKPOINT_POSTGRES_DSN=" "runtime-config render omits host-resolved postgres secrets"
  assert_not_contains "$(cat "$rendered_env")" "JUNO_RPC_USER=" "runtime-config render omits host-resolved rpc credentials"
  assert_not_contains "$(cat "$rendered_env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=" "runtime-config render omits the legacy withdraw extend signer roster for live rollouts"

  rm -rf "$workdir"
}

main() {
  test_live_handoffs_emit_runtime_material_refs
  test_live_handoffs_reject_local_runtime_inputs
  test_live_handoffs_reject_local_runtime_packages
  test_runtime_config_render_skips_local_secret_requirements
}

main "$@"
