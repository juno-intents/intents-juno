#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh "$workdir/known_hosts" \
    --arg app_kh "$workdir/app-known_hosts" \
    --arg backup "$workdir/dkg-backup.zip" \
    --arg secrets "$workdir/operator-secrets.env" \
    --arg app_secrets "$workdir/app-secrets.env" \
    --arg app_host "203.0.113.21" \
    --arg app_public_endpoint "203.0.113.21" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
      | .app_host.host = $app_host
      | .app_host.public_endpoint = $app_public_endpoint
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
printf 'cast %s\n' "$*" >>"$TEST_LOG_DIR/cast.log"
if [[ "$1" == "wallet" && "$2" == "address" ]]; then
  printf '0x0000000000000000000000000000000000000abc\n'
  exit 0
fi
if [[ "$1" == "call" ]]; then
  printf '0x0000000000000000000000000000000000000abc\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_aws() {
  local target="$1"
  local desired_count="${2:-1}"
  local running_count="${3:-1}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"\$TEST_LOG_DIR/aws.log"
if [[ "\$1" == "--profile" ]]; then
  shift 2
fi
if [[ "\$1" == "--region" ]]; then
  shift 2
fi
if [[ "\$1" == "ecs" && "\$2" == "describe-services" ]]; then
  printf '{"services":[{"desiredCount":%s,"runningCount":%s},{"desiredCount":%s,"runningCount":%s}]}\n' "$desired_count" "$running_count" "$desired_count" "$running_count"
  exit 0
fi
printf 'unexpected aws invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

test_canary_app_host_checks_remote_services_and_http_endpoints() {
  local workdir fake_bin log_dir shared_manifest app_manifest output_json tf_json
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  mkdir -p "$fake_bin" "$log_dir"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  tf_json="$workdir/terraform-output.json"
  jq '
    .shared_ecs_cluster_arn = {
      value: "arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared"
    }
    | .shared_proof_requestor_service_name = {
      value: "alpha-proof-requestor"
    }
    | .shared_proof_funder_service_name = {
      value: "alpha-proof-funder"
    }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  output_json="$workdir/canary.json"

  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|https://ops.alpha.intents-testing.thejunowallet.com/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","bridgeAddress":"0x2222222222222222222222222222222222222222","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  https://ops.alpha.intents-testing.thejunowallet.com/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  https://ops.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>JUNO BACKOFFICE</body></html>\n'
    ;;
  *)
    exit 1
    ;;
esac
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  write_fake_aws "$fake_bin/aws" 1 1
  chmod +x "$fake_bin/ssh" "$fake_bin/curl"

  TEST_LOG_DIR="$log_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$workdir/output/app/known_hosts" "canary uses known_hosts file"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active bridge-api" "bridge systemd checked"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active backoffice" "backoffice systemd checked"
  assert_contains "$(cat "$log_dir/curl.log")" "https://bridge.alpha.intents-testing.thejunowallet.com/v1/config" "bridge config checked"
  assert_contains "$(cat "$log_dir/curl.log")" "https://ops.alpha.intents-testing.thejunowallet.com/api/settings/runtime" "backoffice settings checked"
  assert_contains "$(cat "$log_dir/curl.log")" "https://ops.alpha.intents-testing.thejunowallet.com/" "backoffice ui checked"
  assert_contains "$(cat "$log_dir/cast.log")" "wallet address --private-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "canary derives configured min deposit admin signer"
  assert_contains "$(cat "$log_dir/cast.log")" "call --rpc-url https://base-sepolia.example.invalid 0x2222222222222222222222222222222222222222 minDepositAdmin()(address)" "canary checks on-chain minDepositAdmin"
  assert_contains "$(cat "$log_dir/aws.log")" "ecs describe-services --cluster arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared --services alpha-proof-requestor alpha-proof-funder" "canary checks shared proof services"
  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "true" "app canary ready for test"
  assert_eq "$(jq -r '.checks.bridge_config.status' "$output_json")" "passed" "bridge config passed"
  assert_eq "$(jq -r '.checks.backoffice_ui.status' "$output_json")" "passed" "backoffice ui passed"
  assert_eq "$(jq -r '.checks.backoffice_settings.status' "$output_json")" "passed" "backoffice settings passed"
  assert_eq "$(jq -r '.checks.min_deposit_admin.status' "$output_json")" "passed" "min deposit admin passed"
  assert_eq "$(jq -r '.checks.shared_proof_services.status' "$output_json")" "passed" "shared proof services passed"
  rm -rf "$workdir"
}

test_canary_app_host_rejects_missing_shared_proof_capacity() {
  local workdir fake_bin log_dir shared_manifest app_manifest output_json tf_json
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  mkdir -p "$fake_bin" "$log_dir"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  tf_json="$workdir/terraform-output.json"
  jq '
    .shared_ecs_cluster_arn = {
      value: "arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared"
    }
    | .shared_proof_requestor_service_name = {
      value: "alpha-proof-requestor"
    }
    | .shared_proof_funder_service_name = {
      value: "alpha-proof-funder"
    }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  output_json="$workdir/canary.json"

  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|https://ops.alpha.intents-testing.thejunowallet.com/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","bridgeAddress":"0x2222222222222222222222222222222222222222","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  https://ops.alpha.intents-testing.thejunowallet.com/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  https://ops.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>JUNO BACKOFFICE</body></html>\n'
    ;;
  *)
    exit 1
    ;;
esac
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  write_fake_aws "$fake_bin/aws" 0 0
  chmod +x "$fake_bin/ssh" "$fake_bin/curl"

  TEST_LOG_DIR="$log_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "false" "app canary blocks missing proof services"
  assert_eq "$(jq -r '.checks.shared_proof_services.status' "$output_json")" "failed" "shared proof services failed"
  assert_contains "$(jq -r '.checks.shared_proof_services.detail' "$output_json")" "desiredCount/runningCount" "shared proof services failure detail"
  rm -rf "$workdir"
}

test_canary_app_host_rejects_non_https_manifest() {
  local workdir shared_manifest app_manifest
  workdir="$(mktemp -d)"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  jq '
    .public_scheme = "http"
    | .services.bridge_api.public_url = "http://bridge.alpha.intents-testing.thejunowallet.com:8082"
    | .services.backoffice.public_url = "http://ops.alpha.intents-testing.thejunowallet.com:8090"
  ' "$app_manifest" >"$workdir/app-deploy.http.json"

  if (
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$workdir/app-deploy.http.json" \
      --dry-run >/dev/null 2>&1
  ); then
    printf 'expected canary-app-host.sh to reject non-https manifests\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

main() {
  test_canary_app_host_checks_remote_services_and_http_endpoints
  test_canary_app_host_rejects_missing_shared_proof_capacity
  test_canary_app_host_rejects_non_https_manifest
}

main "$@"
