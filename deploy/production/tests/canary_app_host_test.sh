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
      | .operators[0].asg = "juno-op1"
      | .operators[0].launch_template = {"id":"lt-0123456789abcdef0","version":"1"}
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
      | .app_host.host = $app_host
      | .app_host.public_endpoint = $app_public_endpoint
      | .app_host.operator_endpoints = ["0x9999999999999999999999999999999999999999=203.0.113.11:18443"]
      | .app_host.publish_public_dns = false
      | .app_role = {
          host: $app_host,
          user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/app-runtime",
          public_endpoint: $app_public_endpoint,
          private_endpoint: "10.0.10.21",
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          security_group_id: "sg-0123456789abcdef0",
          known_hosts_file: $app_kh,
          secret_contract_file: $app_secrets,
          bridge_public_dns_label: "bridge",
          backoffice_dns_label: "ops",
          public_scheme: "https",
          bridge_api_listen: "127.0.0.1:8082",
          backoffice_listen: "127.0.0.1:8090",
          juno_rpc_url: "http://127.0.0.1:18232",
          service_urls: ["bridge-api=http://127.0.0.1:8082/readyz"],
          operator_endpoints: ["0x9999999999999999999999999999999999999999=203.0.113.11:18443"],
          publish_public_dns: false
        }
      | .shared_roles.proof = {
          requestor_address: "0x1234567890abcdef1234567890abcdef12345678",
          rpc_url: "https://rpc.mainnet.succinct.xyz"
        }
      | .shared_roles.wireguard = {
          public_subnet_id: "subnet-0abc1234def567890",
          public_subnet_ids: ["subnet-0abc1234def567890"],
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          backoffice_hostname: "ops.alpha.intents-testing.thejunowallet.com",
          backoffice_private_endpoint: "10.0.10.21",
          client_config_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config",
          endpoint_host: "198.51.100.25",
          publish_public_dns: false
        }
      | .wireguard_role = .shared_roles.wireguard
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_fake_cast() {
  local target="$1"
  local log_file="$2"
cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  printf '0x0000000000000000000000000000000000000abc\n'
  exit 0
fi
if [[ "\$1" == "call" ]]; then
  printf '0x0000000000000000000000000000000000000abc\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_aws() {
  local target="$1"
  local log_file="${target%/*}/../logs/aws.log"
  local desired_count="${2:-1}"
  local running_count="${3:-1}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_file"
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
    | .shared_sp1_requestor_address = {
      value: "0x4444444444444444444444444444444444444444"
    }
    | .shared_sp1_rpc_url = {
      value: "https://rpc.mainnet.succinct.xyz"
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
  assert_eq "$(jq -r '.version' "$app_manifest")" "2" "app canary renders v2 app manifest"
  assert_eq "$(jq -r '.services.backoffice.access.publish_public_dns' "$app_manifest")" "false" "app canary suppresses public backoffice dns"
  assert_eq "$(jq -r '.services.backoffice.public_url // empty' "$app_manifest")" "" "app canary omits public backoffice url"
  output_json="$workdir/canary.json"

cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/dig" <<'EOF'
#!/usr/bin/env bash
printf 'dig %s\n' "$*" >>"$TEST_LOG_DIR/dig.log"
if [[ "$*" == *"bridge.alpha.intents-testing.thejunowallet.com"* ]]; then
  printf '203.0.113.21\n'
  exit 0
fi
exit 1
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
resolve_value=""
next_is_resolve="false"
for arg in "$@"; do
  if [[ "$next_is_resolve" == "true" ]]; then
    resolve_value="$arg"
    next_is_resolve="false"
    continue
  fi
  if [[ "$arg" == "--resolve" ]]; then
    next_is_resolve="true"
  fi
done
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz)
    [[ "$resolve_value" == "bridge.alpha.intents-testing.thejunowallet.com:443:203.0.113.21" ]] || exit 6
    printf '{"status":"ok"}\n'
    ;;
  http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    [[ "$resolve_value" == "bridge.alpha.intents-testing.thejunowallet.com:443:203.0.113.21" ]] || exit 6
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    [[ "$resolve_value" == "bridge.alpha.intents-testing.thejunowallet.com:443:203.0.113.21" ]] || exit 6
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    [[ "$resolve_value" == "bridge.alpha.intents-testing.thejunowallet.com:443:203.0.113.21" ]] || exit 6
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","creditsRaw":"123","creditsFormatted":"0.000000000000000123","network":"succinct","detail":"shared proof requestor"},"mpcWallet":{"address":"jtest1exampleaddress","total":"1.25","detail":"app-host rpc"}}\n'
    ;;
  http://127.0.0.1:8090/)
    printf '<!doctype html><html><body>JUNO BACKOFFICE</body></html>\n'
    ;;
  *)
    exit 1
    ;;
esac
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  write_fake_aws "$fake_bin/aws" 1 1
  chmod +x "$fake_bin/ssh" "$fake_bin/dig" "$fake_bin/curl"

  PRODUCTION_CANARY_REQUIRE_FUNDS_CHECK=true TEST_LOG_DIR="$log_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$workdir/output/app/known_hosts" "canary uses known_hosts file"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active bridge-api" "bridge systemd checked"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active backoffice" "backoffice systemd checked"
  assert_contains "$(cat "$log_dir/dig.log")" "@1.1.1.1 +short bridge.alpha.intents-testing.thejunowallet.com" "canary resolves bridge via public DNS fallback"
  assert_contains "$(cat "$log_dir/curl.log")" "--resolve bridge.alpha.intents-testing.thejunowallet.com:443:203.0.113.21" "canary pins bridge probes to the authoritative edge IP"
  assert_contains "$(cat "$log_dir/curl.log")" "https://bridge.alpha.intents-testing.thejunowallet.com/v1/config" "bridge config checked"
  assert_contains "$(cat "$log_dir/curl.log")" "https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111" "bridge deposit memo checked"
  assert_contains "$(cat "$log_dir/curl.log")" "http://127.0.0.1:8090/api/settings/runtime" "backoffice settings checked"
  assert_contains "$(cat "$log_dir/curl.log")" "http://127.0.0.1:8090/api/funds" "backoffice funds checked"
  assert_contains "$(cat "$log_dir/curl.log")" "http://127.0.0.1:8090/" "backoffice ui checked"
  assert_contains "$(cat "$log_dir/cast.log")" "wallet address --private-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "canary derives configured min deposit admin signer"
  assert_contains "$(cat "$log_dir/cast.log")" "call --rpc-url https://base-sepolia.example.invalid 0x2222222222222222222222222222222222222222 minDepositAdmin()(address)" "canary checks on-chain minDepositAdmin"
  assert_contains "$(cat "$log_dir/aws.log")" "ecs describe-services --cluster arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared --services alpha-proof-requestor alpha-proof-funder" "canary checks shared proof services"
  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "true" "app canary ready for test"
  assert_eq "$(jq -r '.checks.bridge_config.status' "$output_json")" "passed" "bridge config passed"
  assert_eq "$(jq -r '.checks.deposit_memo.status' "$output_json")" "passed" "deposit memo passed"
  assert_eq "$(jq -r '.checks.backoffice_ui.status' "$output_json")" "passed" "backoffice ui passed"
  assert_eq "$(jq -r '.checks.backoffice_settings.status' "$output_json")" "passed" "backoffice settings passed"
  assert_eq "$(jq -r '.checks.shared_proof_runtime.status' "$output_json")" "passed" "shared proof runtime passed"
  assert_eq "$(jq -r '.checks.backoffice_funds.status' "$output_json")" "passed" "backoffice funds passed"
  assert_eq "$(jq -r '.checks.min_deposit_admin.status' "$output_json")" "passed" "min deposit admin passed"
  assert_eq "$(jq -r '.checks.shared_proof_services.status' "$output_json")" "passed" "shared proof services passed"
  rm -rf "$workdir"
}

test_canary_app_host_blocks_backoffice_funds_missing_prover_and_mpc() {
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
    | .shared_sp1_requestor_address = {
      value: "0x4444444444444444444444444444444444444444"
    }
    | .shared_sp1_rpc_url = {
      value: "https://rpc.mainnet.succinct.xyz"
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
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}]}\n'
    ;;
  http://127.0.0.1:8090/)
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

  PRODUCTION_CANARY_REQUIRE_FUNDS_CHECK=true PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "false" "app canary blocks missing funds payload"
  assert_eq "$(jq -r '.checks.backoffice_funds.status' "$output_json")" "failed" "backoffice funds failed"
  assert_contains "$(jq -r '.checks.backoffice_funds.detail' "$output_json")" "missing prover or MPC" "backoffice funds detail explains failure"
  rm -rf "$workdir"
}

test_canary_app_host_blocks_backoffice_funds_runtime_errors() {
  local workdir fake_bin shared_manifest app_manifest output_json tf_json
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

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
    | .shared_sp1_requestor_address = {
      value: "0x4444444444444444444444444444444444444444"
    }
    | .shared_sp1_rpc_url = {
      value: "https://rpc.mainnet.succinct.xyz"
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
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","network":"succinct","error":"grpc http status 500"},"mpcWallet":{"address":"jtest1exampleaddress","error":"juno rpc call: context deadline exceeded"}}\n'
    ;;
  http://127.0.0.1:8090/)
    printf '<!doctype html><html><body>JUNO BACKOFFICE</body></html>\n'
    ;;
  *)
    exit 1
    ;;
esac
EOF
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  write_fake_aws "$fake_bin/aws" 1 1
  chmod +x "$fake_bin/ssh" "$fake_bin/curl"

  PRODUCTION_CANARY_REQUIRE_FUNDS_CHECK=true PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "false" "app canary blocks funds runtime errors"
  assert_eq "$(jq -r '.checks.backoffice_funds.status' "$output_json")" "failed" "backoffice funds runtime errors failed"
  assert_contains "$(jq -r '.checks.backoffice_funds.detail' "$output_json")" "runtime error" "backoffice funds detail explains runtime error"
  rm -rf "$workdir"
}

test_canary_app_host_blocks_bridge_config_contract_mismatch() {
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
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","creditsRaw":"123","creditsFormatted":"0.000000000000000123","network":"succinct","detail":"shared proof requestor"},"mpcWallet":{"address":"jtest1exampleaddress","total":"1.25","detail":"app-host rpc"}}\n'
    ;;
  http://127.0.0.1:8090/)
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

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "false" "app canary blocks stale bridge config"
  assert_eq "$(jq -r '.checks.bridge_config.status' "$output_json")" "failed" "bridge config mismatch failed"
  assert_contains "$(jq -r '.checks.bridge_config.detail' "$output_json")" "mismatched" "bridge config mismatch detail"
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
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","creditsRaw":"123","creditsFormatted":"0.000000000000000123","network":"succinct","detail":"shared proof requestor"},"mpcWallet":{"address":"jtest1exampleaddress","total":"1.25","detail":"app-host rpc"}}\n'
    ;;
  http://127.0.0.1:8090/)
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

test_canary_app_host_blocks_deposit_memo_probe_failure() {
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
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf 'curl: (22) The requested URL returned error: 500\n' >&2
    exit 22
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","creditsRaw":"123","creditsFormatted":"0.000000000000000123","network":"succinct","detail":"shared proof requestor"},"mpcWallet":{"address":"jtest1exampleaddress","total":"1.25","detail":"app-host rpc"}}\n'
    ;;
  http://127.0.0.1:8090/)
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

  TEST_LOG_DIR="$log_dir" \
  PRODUCTION_CANARY_HTTP_MAX_ATTEMPTS=1 \
  PRODUCTION_CANARY_HTTP_RETRY_SLEEP_SECONDS=0 \
  PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "false" "app canary blocks failing deposit memo probe"
  assert_eq "$(jq -r '.checks.deposit_memo.status' "$output_json")" "failed" "deposit memo probe failed"
  assert_contains "$(jq -r '.checks.deposit_memo.detail' "$output_json")" "/v1/deposit-memo" "deposit memo failure detail"
  rm -rf "$workdir"
}

test_canary_app_host_retries_transient_public_tls_failures() {
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
  exit 0
fi
if [[ "$*" == *"curl -fsS "* ]]; then
  eval "${@: -1}"
  exit $?
fi
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$TEST_LOG_DIR/curl.log"
url="${@: -1}"
count_file="$TEST_LOG_DIR/$(printf '%s' "$url" | tr -c '[:alnum:]' '_').count"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"
if (( count <= 2 )); then
  printf 'curl: (35) LibreSSL/3.3.6: error:1404B438:SSL routines:ST_CONNECT:tlsv1 alert internal error\n' >&2
  exit 35
fi
case "$url" in
  https://bridge.alpha.intents-testing.thejunowallet.com/readyz|http://127.0.0.1:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/config)
    printf '{"version":"v1","baseChainId":84532,"bridgeAddress":"0x2222222222222222222222222222222222222222","wjunoAddress":"0x3333333333333333333333333333333333333333","oWalletUA":"u1alphaexample","minDepositAmount":"201005025","depositMinConfirmations":2}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111)
    printf '{"version":"v1","baseRecipient":"0x1111111111111111111111111111111111111111","nonce":"7","memoHex":"'
    printf 'aa%.0s' $(seq 1 512)
    printf '"}\n'
    ;;
  https://bridge.alpha.intents-testing.thejunowallet.com/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://127.0.0.1:8090/api/settings/runtime)
    printf '{"version":"v1","data":{"minDepositAmount":"201005025","minDepositAdmin":"0x0000000000000000000000000000000000000abc","depositMinConfirmations":2,"withdrawPlannerMinConfirmations":3,"withdrawBatchConfirmations":4}}\n'
    ;;
  http://127.0.0.1:8090/api/funds)
    printf '{"version":"v1","bridge":{"wjunoBalanceRaw":"0","wjunoBalanceFormatted":"0.0"},"operators":[{"address":"0x660B5284fF10C873050a286A124127e3E310ad05","balanceWei":"2000000000000000","balanceEth":"0.002","belowThreshold":false}],"prover":{"address":"0x4444444444444444444444444444444444444444","creditsRaw":"123","creditsFormatted":"0.000000000000000123","network":"succinct","detail":"shared proof requestor"},"mpcWallet":{"address":"jtest1exampleaddress","total":"1.25","detail":"app-host rpc"}}\n'
    ;;
  http://127.0.0.1:8090/)
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

  TEST_LOG_DIR="$log_dir" \
  PRODUCTION_CANARY_HTTP_MAX_ATTEMPTS=3 \
  PRODUCTION_CANARY_HTTP_RETRY_SLEEP_SECONDS=0 \
  PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "true" "app canary tolerates transient tls warmup failures"
  assert_eq "$(jq -r '.checks.bridge_ready.status' "$output_json")" "passed" "bridge ready passed after retry"
  assert_eq "$(jq -r '.checks.bridge_config.status' "$output_json")" "passed" "bridge config passed after retry"
  assert_eq "$(jq -r '.checks.deposit_memo.status' "$output_json")" "passed" "deposit memo passed after retry"
  assert_eq "$(jq -r '.checks.backoffice_ready.status' "$output_json")" "passed" "backoffice ready passed after retry"
  assert_eq "$(cat "$log_dir/https___bridge_alpha_intents_testing_thejunowallet_com_readyz.count")" "3" "bridge ready retried twice before success"
  assert_contains "$(cat "$log_dir/curl.log")" "https://bridge.alpha.intents-testing.thejunowallet.com/v1/deposit-memo?baseRecipient=0x1111111111111111111111111111111111111111" "deposit memo probed during retry test"
  assert_eq "$(cat "$log_dir/http___127_0_0_1_8090_readyz.count")" "3" "backoffice ready retried twice before success"
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
  test_canary_app_host_blocks_backoffice_funds_missing_prover_and_mpc
  test_canary_app_host_blocks_backoffice_funds_runtime_errors
  test_canary_app_host_blocks_bridge_config_contract_mismatch
  test_canary_app_host_rejects_missing_shared_proof_capacity
  test_canary_app_host_blocks_deposit_memo_probe_failure
  test_canary_app_host_retries_transient_public_tls_failures
  test_canary_app_host_rejects_non_https_manifest
}

main "$@"
