#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  local balance_wei="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  printf '0x1111111111111111111111111111111111111111\n'
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  printf '%s\n' "$balance_wei"
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_bridge_deploy_binary() {
  local target="$1"
  local log_file="$2"
  local bridge_summary_fixture="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'bridge-e2e %s\n' "\$*" >>"$log_file"
if [[ "\${1:-}" == "deploy" ]]; then
  printf 'unexpected subcommand invocation: %s\n' "\$*" >&2
  exit 1
fi
deploy_only="false"
output_path=""
has_dkg_summary="false"
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --deploy-only) deploy_only="true"; shift ;;
    --output) output_path="\$2"; shift 2 ;;
    --dkg-summary) has_dkg_summary="true"; shift 2 ;;
    *) shift ;;
  esac
done
[[ "\$deploy_only" == "true" ]] || {
  printf 'expected --deploy-only flag\n' >&2
  exit 1
}
[[ -n "\$output_path" ]] || {
  printf 'missing --output path\n' >&2
  exit 1
}
[[ "\$has_dkg_summary" == "false" ]] || {
  printf 'unexpected --dkg-summary path\n' >&2
  exit 1
}
cp "$bridge_summary_fixture" "\$output_path"
EOF
  chmod +x "$target"
}

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
  local workdir output_dir manifest operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
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
  local workdir output_dir run_dir operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
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

test_deploy_coordinator_uses_bridge_e2e_deploy_contract() {
  local workdir output_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  cat >"$workdir/deployer.key" <<'EOF'
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"
  write_fake_bridge_deploy_binary "$fake_bin/bridge-e2e" "$log_dir/bridge.log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --bridge-deploy-binary "$fake_bin/bridge-e2e" \
    --deployer-key-file "$workdir/deployer.key" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_contains "$(cat "$log_dir/bridge.log")" '--contracts-out /Users/ardud/intents-juno/monorepo/contracts/out' "bridge deploy uses repo contracts output"
  assert_contains "$(cat "$log_dir/bridge.log")" '--threshold 2' "bridge deploy forwards dkg threshold"
  assert_contains "$(cat "$log_dir/bridge.log")" '--verifier-address 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B' "bridge deploy forwards verifier address"
  assert_contains "$(cat "$log_dir/bridge.log")" '--deposit-image-id 0x000000000000000000000000000000000000000000000000000000000000aa01' "bridge deploy forwards deposit image id"
  assert_contains "$(cat "$log_dir/bridge.log")" '--withdraw-image-id 0x000000000000000000000000000000000000000000000000000000000000aa02' "bridge deploy forwards withdraw image id"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x1111111111111111111111111111111111111111' "bridge deploy forwards first operator"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x6666666666666666666666666666666666666666' "bridge deploy forwards second operator"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x7777777777777777777777777777777777777777' "bridge deploy forwards third operator"
  assert_not_contains "$(cat "$log_dir/bridge.log")" '--dkg-summary' "bridge deploy does not pass dkg summary"
  assert_file_exists "$output_dir/alpha/bridge-summary.json" "bridge deploy summary"
  rm -rf "$workdir"
}

test_deploy_coordinator_normalizes_relative_output_paths() {
  local workdir inventory_path operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  inventory_path="$workdir/inventory.json"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"

  (
    cd "$workdir"
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
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
  local workdir output_dir dkg_summary_no_ufvk dkg_completion bridge_summary_no_ua manifest fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
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
  assert_eq "$(jq -r '.owallet_ua' "$output_dir/alpha/bridge-summary.json")" "u1coordinatorfallback" "coordinator bridge summary owallet ua refreshed"
  assert_eq "$(jq -r '.juno_shielded_address' "$output_dir/alpha/bridge-summary.json")" "u1coordinatorfallback" "coordinator bridge summary juno shielded address refreshed"
  rm -rf "$workdir"
}

test_deploy_coordinator_rejects_underfunded_operator_before_render() {
  local workdir output_dir fake_bin log_dir output
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1000"

  if output="$(
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$workdir/inventory.json" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir "$output_dir" 2>&1
  )"; then
    printf 'expected deploy-coordinator.sh to reject underfunded operator relayer\n' >&2
    exit 1
  fi

  assert_contains "$output" "base relayer 0x1111111111111111111111111111111111111111 balance 1000 wei is below minimum 250000000000000 wei" "underfunded relayer error"
  [[ ! -e "$output_dir/alpha/shared-manifest.json" ]] || {
    printf 'expected no shared manifest when relayer funding preflight fails\n' >&2
    exit 1
  }
  rm -rf "$workdir"
}

test_deploy_coordinator_invokes_bridge_binary_with_direct_flags() {
  local workdir output_dir fake_bin log_dir bridge_log
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  bridge_log="$log_dir/bridge.log"
  mkdir -p "$fake_bin" "$log_dir"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "300000000000000"
  write_fake_bridge_deploy_binary "$fake_bin/bridge-e2e" "$bridge_log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --bridge-deploy-binary "$fake_bin/bridge-e2e" \
    --deployer-key-file "$workdir/dkg-backup.zip" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_contains "$(cat "$bridge_log")" "--deploy-only" "bridge deploy binary receives deploy-only flag"
  if grep -Fq "bridge-e2e deploy " "$bridge_log"; then
    printf 'expected bridge deploy binary invocation without legacy subcommand\n' >&2
    exit 1
  fi
  assert_file_exists "$output_dir/alpha/bridge-summary.json" "bridge summary created from direct bridge deploy invocation"
  rm -rf "$workdir"
}

main() {
  test_deploy_coordinator_generates_handoffs
  test_deploy_coordinator_supports_run_label
  test_deploy_coordinator_normalizes_relative_output_paths
  test_deploy_coordinator_uses_dkg_completion_for_signer_ufvk
  test_deploy_coordinator_rejects_underfunded_operator_before_render
  test_deploy_coordinator_invokes_bridge_binary_with_direct_flags
}

main "$@"
