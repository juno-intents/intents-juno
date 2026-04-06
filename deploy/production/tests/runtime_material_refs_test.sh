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

write_fake_ufvk_derive_cargo() {
  local target="$1"
  local deposit_ivk="$2"
  local withdraw_ovk="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'SP1_DEPOSIT_OWALLET_IVK_HEX=%s\n' '$deposit_ivk'
printf 'SP1_WITHDRAW_OWALLET_OVK_HEX=%s\n' '$withdraw_ovk'
EOF
  chmod 0755 "$target"
}

write_fake_aws_secret_reader() {
  local target="$1"
  local expected_secret_arn="$2"
  local secret_value="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=( "\$@" )
for ((i=0; i<\${#args[@]}; i++)); do
  if [[ "\${args[\$i]}" == "secretsmanager" && \$((i + 1)) -lt \${#args[@]} && "\${args[\$((i + 1))]}" == "get-secret-value" ]]; then
    secret_arn=""
    for ((j=0; j<\${#args[@]}; j++)); do
      if [[ "\${args[\$j]}" == "--secret-id" && \$((j + 1)) -lt \${#args[@]} ]]; then
        secret_arn="\${args[\$((j + 1))]}"
        break
      fi
    done
    [[ "\$secret_arn" == "$expected_secret_arn" ]] || {
      printf 'unexpected secret id: %s\n' "\$secret_arn" >&2
      exit 1
    }
    printf '%s\n' "$secret_value"
    exit 0
  fi
done
exit 0
EOF
  chmod 0755 "$target"
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
  jq '
    .operators[0].deposit_relayer_release_tag = "app-binaries-v2026.04.06-r2-mainnet"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  render_live_handoffs "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"

  assert_eq "$(jq -r '.version' "$manifest")" "3" "live operator manifest uses the runtime-ref schema version"
  assert_eq "$(jq -r '.runtime_material_ref.mode' "$manifest")" "s3-kms-zip" "live operator manifest carries the runtime material mode"
  assert_eq "$(jq -r '.runtime_material_ref.bucket' "$manifest")" "mainnet-runtime-materials" "live operator manifest carries the runtime material bucket"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$manifest")" "mainnet/op1/runtime-config" "live operator manifest carries the runtime config secret id"
  assert_eq "$(jq -r '.runtime_config_secret_region' "$manifest")" "us-east-1" "live operator manifest carries the runtime config secret region"
  assert_eq "$(jq -r '.deposit_relayer_release_tag' "$manifest")" "app-binaries-v2026.04.06-r2-mainnet" "live operator manifest carries the pinned deposit-relayer release tag"
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
  local workdir handoff_dir manifest rendered_env fake_bin old_path derived_ivk derived_ovk
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  render_live_handoffs "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"
  rendered_env="$workdir/operator-stack.env"
  : >"$workdir/resolved.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  derived_ivk="0x$(printf 'a%.0s' $(seq 1 128))"
  derived_ovk="0x$(printf 'b%.0s' $(seq 1 64))"
  write_fake_ufvk_derive_cargo "$fake_bin/cargo" "$derived_ivk" "$derived_ovk"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env \
    "$workdir/shared-manifest.json" \
    "$manifest" \
    "$workdir/resolved.env" \
    "$rendered_env"
  PATH="$old_path"

  assert_contains "$(cat "$rendered_env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "runtime-config render keeps the kms signer mode"
  assert_contains "$(cat "$rendered_env")" "JUNO_RPC_BIND=127.0.0.1" "runtime-config render restores the local rpc bind default"
  assert_contains "$(cat "$rendered_env")" "TSS_SIGNER_RUNTIME_MODE=host-process" "runtime-config render forces the host-process signer runtime"
  assert_contains "$(cat "$rendered_env")" "WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS=0x9999999999999999999999999999999999999999=203.0.113.11:18443" "runtime-config render stages operator endpoints for live withdraw signing"
  assert_not_contains "$(cat "$rendered_env")" "CHECKPOINT_POSTGRES_DSN=" "runtime-config render omits host-resolved postgres secrets"
  assert_not_contains "$(cat "$rendered_env")" "JUNO_RPC_USER=" "runtime-config render omits host-resolved rpc credentials"
  assert_not_contains "$(cat "$rendered_env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=" "runtime-config render omits the legacy withdraw extend signer roster for live rollouts"

  rm -rf "$workdir"
}

test_runtime_config_render_includes_live_withdraw_and_deposit_derivations() {
  local workdir handoff_dir manifest rendered_env resolved_env fake_bin old_path expected_blob_bucket derived_ivk derived_ovk
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  render_live_handoffs "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"
  rendered_env="$workdir/operator-stack.env"
  resolved_env="$workdir/resolved.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

  cat >"$resolved_env" <<'EOF'
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=wallet-live-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=wallet-live-op1
EOF

  derived_ivk="0x$(printf 'a%.0s' $(seq 1 128))"
  derived_ovk="0x$(printf 'b%.0s' $(seq 1 64))"
  write_fake_ufvk_derive_cargo "$fake_bin/cargo" "$derived_ivk" "$derived_ovk"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env \
    "$workdir/shared-manifest.json" \
    "$manifest" \
    "$resolved_env" \
    "$rendered_env"
  PATH="$old_path"

  expected_blob_bucket="$(jq -r '.checkpoint_blob_bucket // empty' "$manifest")"
  if [[ -z "$expected_blob_bucket" ]]; then
    expected_blob_bucket="$(jq -r '.shared_services.artifacts.checkpoint_blob_bucket // empty' "$workdir/shared-manifest.json")"
  fi
  assert_contains "$(cat "$rendered_env")" "WITHDRAW_BLOB_BUCKET=$expected_blob_bucket" "runtime-config render derives withdraw blob bucket from the shared manifest"
  assert_contains "$(cat "$rendered_env")" "DEPOSIT_SCAN_ENABLED=true" "runtime-config render enables deposit scan"
  assert_contains "$(cat "$rendered_env")" "DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=wallet-live-op1" "runtime-config render derives the deposit scan wallet id from runtime wallet ids"
  assert_contains "$(cat "$rendered_env")" "DEPOSIT_OWALLET_IVK=$derived_ivk" "runtime-config render derives and stages the deposit oWallet ivk"

  rm -rf "$workdir"
}

test_runtime_config_render_injects_queueauth_hmac_from_shared_manifest() {
  local workdir handoff_dir manifest rendered_env resolved_env fake_bin old_path queueauth_secret_arn derived_ivk derived_ovk tf_json
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  tf_json="$workdir/terraform-output.json"
  jq \
    --arg arn "arn:aws:secretsmanager:us-east-1:021490342184:secret:live-kafka-critical-hmac" \
    '.shared_kafka_critical_hmac_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs \
    "$workdir/inventory.json" \
    "$workdir/shared-manifest.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$workdir/output" \
    "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"
  rendered_env="$workdir/operator-stack.env"
  resolved_env="$workdir/resolved.env"
  : >"$resolved_env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

  queueauth_secret_arn="$(jq -r '.shared_services.kafka.critical_hmac_secret_arn' "$workdir/shared-manifest.json")"
  derived_ivk="0x$(printf 'a%.0s' $(seq 1 128))"
  derived_ovk="0x$(printf 'b%.0s' $(seq 1 64))"
  write_fake_ufvk_derive_cargo "$fake_bin/cargo" "$derived_ivk" "$derived_ovk"
  write_fake_aws_secret_reader "$fake_bin/aws" "$queueauth_secret_arn" "queueauth-live-hmac"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env \
    "$workdir/shared-manifest.json" \
    "$manifest" \
    "$resolved_env" \
    "$rendered_env"
  PATH="$old_path"

  assert_contains "$(cat "$rendered_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=queueauth-live-hmac" "runtime-config render injects the shared queueauth hmac secret"

  rm -rf "$workdir"
}

test_runtime_config_render_prefers_inline_queueauth_hmac_key() {
  local workdir handoff_dir manifest rendered_env resolved_env fake_bin old_path queueauth_secret_arn derived_ivk derived_ovk tf_json
  workdir="$(mktemp -d)"
  write_live_inventory_fixture "$workdir/inventory.json"

  tf_json="$workdir/terraform-output.json"
  jq \
    --arg arn "arn:aws:secretsmanager:us-east-1:021490342184:secret:live-kafka-critical-hmac" \
    '.shared_kafka_critical_hmac_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs \
    "$workdir/inventory.json" \
    "$workdir/shared-manifest.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$workdir/output" \
    "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  manifest="$handoff_dir/operator-deploy.json"
  rendered_env="$workdir/operator-stack.env"
  resolved_env="$workdir/resolved.env"
  cat >"$resolved_env" <<'EOF'
JUNO_QUEUE_CRITICAL_HMAC_KEY=inline-queueauth-hmac
EOF
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

  queueauth_secret_arn="$(jq -r '.shared_services.kafka.critical_hmac_secret_arn' "$workdir/shared-manifest.json")"
  derived_ivk="0x$(printf 'a%.0s' $(seq 1 128))"
  derived_ovk="0x$(printf 'b%.0s' $(seq 1 64))"
  write_fake_ufvk_derive_cargo "$fake_bin/cargo" "$derived_ivk" "$derived_ovk"
  write_fake_aws_secret_reader "$fake_bin/aws" "$queueauth_secret_arn" "aws-queueauth-hmac"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env \
    "$workdir/shared-manifest.json" \
    "$manifest" \
    "$resolved_env" \
    "$rendered_env"
  PATH="$old_path"

  assert_contains "$(cat "$rendered_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=inline-queueauth-hmac" "runtime-config render prefers the inline queueauth hmac key"
  assert_not_contains "$(cat "$rendered_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=aws-queueauth-hmac" "runtime-config render ignores the shared secret when an inline queueauth hmac key is already set"

  rm -rf "$workdir"
}

main() {
  test_live_handoffs_emit_runtime_material_refs
  test_live_handoffs_reject_local_runtime_inputs
  test_live_handoffs_reject_local_runtime_packages
  test_runtime_config_render_skips_local_secret_requirements
  test_runtime_config_render_includes_live_withdraw_and_deposit_derivations
  test_runtime_config_render_injects_queueauth_hmac_from_shared_manifest
  test_runtime_config_render_prefers_inline_queueauth_hmac_key
}

main "$@"
