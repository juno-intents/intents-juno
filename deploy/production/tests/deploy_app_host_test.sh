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
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  case "\$4" in
    0x1111111111111111111111111111111111111111111111111111111111111111)
      printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
      ;;
    *)
      printf 'unexpected private key: %s\n' "\$4" >&2
      exit 1
      ;;
  esac
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

test_deploy_app_host_uses_release_assets_and_updates_remote_runtime() {
  local workdir fake_bin log_dir assets_dir shared_manifest app_manifest release_tag
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  assets_dir="$workdir/assets"
  mkdir -p "$fake_bin" "$log_dir" "$assets_dir"
  release_tag="app-binaries-v0.1.0-testnet"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
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
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  jq '.edge.enabled = false' "$app_manifest" >"$workdir/output/app/app-deploy.direct.json"
  app_manifest="$workdir/output/app/app-deploy.direct.json"

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  printf 'shared-infra-e2e-binary\n' >"$assets_dir/shared-infra-e2e_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
    sha256sum shared-infra-e2e_linux_amd64 >shared-infra-e2e_linux_amd64.sha256
  )

  cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$TEST_LOG_DIR/gh.log"
pattern=""
dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pattern)
      pattern="$2"
      shift 2
      ;;
    --dir)
      dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "$TEST_ASSETS_DIR/$pattern" "$dir/$pattern"
EOF
  cat >"$fake_bin/scp" <<'EOF'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >>"$TEST_LOG_DIR/scp.log"
for arg in "$@"; do
  if [[ -f "$arg" ]]; then
    cp "$arg" "$TEST_LOG_DIR/$(basename "$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >>"$TEST_LOG_DIR/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
printf 'aws %s\n' "$*" >>"$TEST_LOG_DIR/aws.log"
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_contains "$(cat "$log_dir/gh.log")" "release download $release_tag" "gh release download"
  assert_contains "$(cat "$log_dir/gh.log")" "bridge-api_linux_amd64" "bridge asset download"
  assert_contains "$(cat "$log_dir/gh.log")" "backoffice_linux_amd64" "backoffice asset download"
  assert_contains "$(cat "$log_dir/gh.log")" "shared-infra-e2e_linux_amd64" "shared infra asset download"
  assert_contains "$(cat "$log_dir/scp.log")" "StrictHostKeyChecking=yes" "scp strict host key checking"
  assert_contains "$(cat "$log_dir/scp.log")" "bridge-api.env" "bridge env copied"
  assert_contains "$(cat "$log_dir/scp.log")" "backoffice.env" "backoffice env copied"
  assert_contains "$(cat "$log_dir/scp.log")" "shared-infra-e2e_linux_amd64" "shared infra binary copied"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'bridge_api_wrapper="/usr/local/bin/intents-juno-bridge-api.sh"' "remote bridge wrapper path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'backoffice_wrapper="/usr/local/bin/intents-juno-backoffice.sh"' "remote backoffice wrapper path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'shared_infra_e2e_bin="$runtime_dir/bin/shared-infra-e2e"' "remote shared infra binary path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if ! id -u intents-juno >/dev/null 2>&1; then' "remote ensures intents-juno user"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -d -m 0755 -o intents-juno -g intents-juno "$runtime_dir"' "remote ensures runtime root is writable for shared infra report"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$remote_stage_dir/shared-infra-e2e_linux_amd64" "$shared_infra_e2e_bin"' "remote installs shared infra binary"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'JUNO_QUEUE_KAFKA_TLS="$kafka_tls_enabled"' "shared infra validation carries kafka tls setting"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'shared_infra_check_max_attempts="' "shared infra validation configures retry attempts"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'shared_infra_check_timeout="420s"' "shared infra validation uses the extended default timeout budget"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'shared_ipfs_api_bearer_token="' "shared infra validation carries the resolved IPFS bearer token"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'run_shared_infra_e2e() {' "shared infra validation uses retry helper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'for ((shared_infra_attempt = 1; shared_infra_attempt <= shared_infra_check_max_attempts; shared_infra_attempt++)); do' "shared infra validation retries transient failures"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'CHECKPOINT_IPFS_API_BEARER_TOKEN="$shared_ipfs_api_bearer_token"' "shared infra validation exports the IPFS bearer token env var"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--timeout "$shared_infra_check_timeout"' "shared infra validation passes explicit timeout"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--required-kafka-topics "$shared_required_kafka_topics"' "shared infra validation ensures required kafka topics"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'proof.requests.v1' "shared infra validation includes proof request topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'proof.fulfillments.v1' "shared infra validation includes proof fulfillment topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'proof.failures.v1' "shared infra validation includes proof failure topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'deposits.event.v2' "shared infra validation includes deposit event topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdrawals.requested.v2' "shared infra validation includes withdrawal topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'ops.alerts.v1' "shared infra validation includes ops alert topic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'EnvironmentFile=/etc/intents-juno/bridge-api.env' "bridge unit uses env file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'EnvironmentFile=/etc/intents-juno/backoffice.env' "backoffice unit uses env file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--base-rpc-url "$BRIDGE_API_BASE_RPC_URL"' "bridge wrapper passes base rpc url"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--deposit-min-confirmations "${BRIDGE_API_DEPOSIT_MIN_CONFIRMATIONS:-1}"' "bridge wrapper passes deposit confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--withdraw-planner-min-confirmations "${BRIDGE_API_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"' "bridge wrapper passes withdraw planner confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--withdraw-batch-confirmations "${BRIDGE_API_WITHDRAW_BATCH_CONFIRMATIONS:-1}"' "bridge wrapper passes withdraw batch confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES:-}" ]]; then' "backoffice wrapper guards relayer signer flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI:-}" ]]; then' "backoffice wrapper guards relayer gas floor flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--base-relayer-signer-addresses "$BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES"' "backoffice wrapper passes relayer signer addresses"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--base-relayer-gas-min-wei "$BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI"' "backoffice wrapper passes relayer gas floor"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--deposit-min-confirmations "${BACKOFFICE_DEPOSIT_MIN_CONFIRMATIONS:-1}"' "backoffice wrapper passes deposit confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--withdraw-planner-min-confirmations "${BACKOFFICE_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"' "backoffice wrapper passes withdraw planner confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--withdraw-batch-confirmations "${BACKOFFICE_WITHDRAW_BATCH_CONFIRMATIONS:-1}"' "backoffice wrapper passes withdraw batch confirmation seed"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--owallet-ua "$BACKOFFICE_OWALLET_UA"' "backoffice wrapper passes mpc wallet address"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--sp1-requestor-address "$BACKOFFICE_SP1_REQUESTOR_ADDRESS"' "backoffice wrapper passes prover requestor address"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--sp1-rpc-url "$BACKOFFICE_SP1_RPC_URL"' "backoffice wrapper passes sp1 rpc url"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_IPFS_API_BEARER_TOKEN:-}" ]]; then' "backoffice wrapper guards the optional IPFS bearer token flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--ipfs-api-bearer-token "$BACKOFFICE_IPFS_API_BEARER_TOKEN"' "backoffice wrapper passes the optional IPFS bearer token"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo apt-get install -y caddy' "remote installs caddy when https is enabled"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '/etc/caddy/Caddyfile' "remote writes caddyfile"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'acme_account_email="ops@thejunowallet.com"' "remote configures acme account email"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'email $acme_account_email' "caddyfile uses configured acme account email"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'reverse_proxy 127.0.0.1:8082' "bridge caddy reverse proxy"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'reverse_proxy 127.0.0.1:8090' "backoffice caddy reverse proxy"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart bridge-api' "remote bridge restart"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart backoffice' "remote backoffice restart"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart caddy' "remote caddy restart"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active bridge-api" "bridge service verified"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active backoffice" "backoffice service verified"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active caddy" "caddy service verified"
  assert_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "dns publish"
  assert_contains "$(cat "$log_dir/aws.log")" '"FromPort":80' "security group ingress http"
  assert_contains "$(cat "$log_dir/aws.log")" '"FromPort":443' "security group ingress https"
  assert_not_contains "$(cat "$log_dir/aws.log")" '"FromPort":8082' "https deploy must not expose bridge app port"
  assert_not_contains "$(cat "$log_dir/aws.log")" '"FromPort":8090' "https deploy must not expose backoffice app port"
  assert_contains "$(cat "$log_dir/bridge-api.env")" "BRIDGE_API_OWALLET_UA=u1alphaexample" "bridge env owallet ua"
  assert_contains "$(cat "$log_dir/bridge-api.env")" "BRIDGE_API_BASE_RPC_URL=https://base-sepolia.example.invalid" "bridge env base rpc url"
  assert_contains "$(cat "$log_dir/bridge-api.env")" "BRIDGE_API_DEPOSIT_MIN_CONFIRMATIONS=1" "bridge env deposit confirmation default"
  assert_contains "$(cat "$log_dir/bridge-api.env")" "BRIDGE_API_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=1" "bridge env withdraw planner confirmation default"
  assert_contains "$(cat "$log_dir/bridge-api.env")" "BRIDGE_API_WITHDRAW_BATCH_CONFIRMATIONS=1" "bridge env withdraw batch confirmation default"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_AUTH_SECRET=backoffice-token" "backoffice env auth secret"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_OWALLET_UA=u1alphaexample" "backoffice env mpc address"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_SP1_REQUESTOR_ADDRESS=0x1234567890abcdef1234567890abcdef12345678" "backoffice env prover requestor address"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_SP1_RPC_URL=https://rpc.mainnet.succinct.xyz" "backoffice env sp1 rpc url"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_OPERATOR_ADDRESSES=0x9999999999999999999999999999999999999999" "backoffice env operator addresses"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES=0xd68c28F414B210a6C519D05159014378A5b8Bc0F" "backoffice env relayer signer addresses"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI=1000000000000000" "backoffice env relayer gas floor"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_DEPOSIT_MIN_CONFIRMATIONS=1" "backoffice env deposit confirmation default"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=1" "backoffice env withdraw planner confirmation default"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_WITHDRAW_BATCH_CONFIRMATIONS=1" "backoffice env withdraw batch confirmation default"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_OPERATOR_ENDPOINTS=0x9999999999999999999999999999999999999999=203.0.113.11:18443" "backoffice env operator endpoints"
  assert_not_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_URL=http://127.0.0.1:18232" "backoffice env omits unusable loopback juno rpc url"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_URLS=http://203.0.113.11:18232" "backoffice env renders juno rpc fallback urls from operator endpoints"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for fallback urls"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for fallback urls"
  assert_contains "$(cat "$log_dir/backoffice.env")" "MIN_DEPOSIT_ADMIN_PRIVATE_KEY=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "backoffice env min deposit admin key"
  rm -rf "$workdir"
}

test_deploy_app_host_allows_missing_backoffice_juno_rpc_url() {
  local workdir fake_bin log_dir assets_dir shared_manifest app_manifest release_tag
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  assets_dir="$workdir/assets"
  mkdir -p "$fake_bin" "$log_dir" "$assets_dir"
  release_tag="app-binaries-v0.1.0-testnet"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.app_host.juno_rpc_url)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  jq '.edge.enabled = false' "$app_manifest" >"$workdir/output/app/app-deploy.direct.json"
  app_manifest="$workdir/output/app/app-deploy.direct.json"

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  printf 'shared-infra-e2e-binary\n' >"$assets_dir/shared-infra-e2e_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
    sha256sum shared-infra-e2e_linux_amd64 >shared-infra-e2e_linux_amd64.sha256
  )

  cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$TEST_LOG_DIR/gh.log"
pattern=""
dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pattern)
      pattern="$2"
      shift 2
      ;;
    --dir)
      dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "$TEST_ASSETS_DIR/$pattern" "$dir/$pattern"
EOF
  cat >"$fake_bin/scp" <<'EOF'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >>"$TEST_LOG_DIR/scp.log"
for arg in "$@"; do
  if [[ -f "$arg" ]]; then
    cp "$arg" "$TEST_LOG_DIR/$(basename "$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >>"$TEST_LOG_DIR/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
printf 'aws %s\n' "$*" >>"$TEST_LOG_DIR/aws.log"
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_URLS=http://203.0.113.11:18232" "backoffice env derives juno rpc fallback urls when explicit juno rpc is missing"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for fallback urls"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for fallback urls"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES=0xd68c28F414B210a6C519D05159014378A5b8Bc0F" "backoffice env still carries relayer signer addresses"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_URLS:-}" ]]; then' "backoffice wrapper guards juno rpc urls flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '"$backoffice_bin" -h 2>&1 | grep -q -- '\''--juno-rpc-urls'\''' "backoffice wrapper detects multi-url support"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-rpc-urls "$BACKOFFICE_JUNO_RPC_URLS"' "backoffice wrapper uses multi-url flag when supported"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'IFS=, read -r backoffice_juno_rpc_url _ <<< "$BACKOFFICE_JUNO_RPC_URLS"' "backoffice wrapper extracts the first fallback url for legacy binaries"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-rpc-url "$backoffice_juno_rpc_url"' "backoffice wrapper falls back to the singular juno rpc flag for legacy binaries"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_USER:-}" ]]; then' "backoffice wrapper guards juno rpc user flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_PASS:-}" ]]; then' "backoffice wrapper guards juno rpc pass flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--base-relayer-signer-addresses "$BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES"' "backoffice wrapper still passes relayer signer addresses without juno rpc"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--required-kafka-topics "$shared_required_kafka_topics"' "shared infra validation still runs when backoffice juno rpc falls back to operator endpoints"
  rm -rf "$workdir"
}

test_deploy_app_host_preserves_preview_iam_kafka_auth() {
  local workdir fake_bin log_dir assets_dir shared_manifest app_manifest release_tag
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  assets_dir="$workdir/assets"
  mkdir -p "$fake_bin" "$log_dir" "$assets_dir"
  release_tag="app-binaries-v0.1.0-testnet"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"
  jq '.edge.enabled = false' "$app_manifest" >"$workdir/output/app/app-deploy.direct.json"
  app_manifest="$workdir/output/app/app-deploy.direct.json"

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  printf 'shared-infra-e2e-binary\n' >"$assets_dir/shared-infra-e2e_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
    sha256sum shared-infra-e2e_linux_amd64 >shared-infra-e2e_linux_amd64.sha256
  )

  cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
pattern=""
dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pattern)
      pattern="$2"
      shift 2
      ;;
    --dir)
      dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "$TEST_ASSETS_DIR/$pattern" "$dir/$pattern"
EOF
  cat >"$fake_bin/scp" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
cat >>"$TEST_LOG_DIR/ssh.stdin" || true
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
exit 0
EOF
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_contains "$(cat "$log_dir/ssh.stdin")" 'shared_kafka_auth_mode="aws-msk-iam"' "preview app deploy passes kafka auth iam to shared infra validation"
  rm -rf "$workdir"
}

test_deploy_app_host_provisions_edge_and_uses_origin_proxy() {
  local workdir fake_bin log_dir assets_dir shared_manifest app_manifest release_tag
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  assets_dir="$workdir/assets"
  mkdir -p "$fake_bin" "$log_dir" "$assets_dir"
  release_tag="app-binaries-v0.1.0-testnet"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
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
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  printf 'shared-infra-e2e-binary\n' >"$assets_dir/shared-infra-e2e_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
    sha256sum shared-infra-e2e_linux_amd64 >shared-infra-e2e_linux_amd64.sha256
  )

  cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
pattern=""
dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pattern)
      pattern="$2"
      shift 2
      ;;
    --dir)
      dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "$TEST_ASSETS_DIR/$pattern" "$dir/$pattern"
EOF
  cat >"$fake_bin/scp" <<'EOF'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >>"$TEST_LOG_DIR/scp.log"
for arg in "$@"; do
  if [[ -f "$arg" ]]; then
    cp "$arg" "$TEST_LOG_DIR/$(basename "$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >>"$TEST_LOG_DIR/ssh.log"
if [[ "$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >>"$TEST_LOG_DIR/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
printf 'aws %s\n' "$*" >>"$TEST_LOG_DIR/aws.log"
exit 0
EOF
  cat >"$fake_bin/terraform" <<'EOF'
#!/usr/bin/env bash
printf 'terraform %s\n' "$*" >>"$TEST_LOG_DIR/terraform.log"
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log"
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws" "$fake_bin/terraform"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_contains "$(cat "$log_dir/terraform.log")" "init" "edge terraform init"
  assert_contains "$(cat "$log_dir/terraform.log")" "apply" "edge terraform apply"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'origin.alpha.intents-testing.thejunowallet.com' "edge caddy serves the dedicated origin hostname"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'email $acme_account_email' "edge caddy uses acme for origin tls"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'handle_path /bridge*' "edge caddy bridge origin route"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '$backoffice_record_name {' "edge caddy serves backoffice on a direct hostname"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '@backoffice_wireguard {' "edge caddy defines a wireguard matcher for backoffice"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'remote_ip 10.66.0.0/24' "edge caddy restricts backoffice to the wireguard client cidr"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'handle @backoffice_wireguard {' "edge caddy only proxies allowed wireguard backoffice traffic"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'respond "forbidden" 403' "edge caddy returns forbidden for non-wireguard backoffice traffic"
  assert_not_contains "$(cat "$log_dir/ssh.stdin")" 'handle_path /ops* {' "edge origin no longer publishes /ops"
  assert_not_contains "$(cat "$log_dir/ssh.stdin")" 'auto_https off' "edge caddy no longer disables direct tls"
  assert_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "edge path publishes direct backoffice dns"
  assert_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress" "edge path opens public 443 for origin tls"
  assert_contains "$(cat "$log_dir/aws.log")" '"FromPort":443' "edge path authorizes https ingress"
  assert_contains "$(cat "$log_dir/aws.log")" "revoke-security-group-ingress" "edge path revokes legacy direct http ingress"
  rm -rf "$workdir"
}

test_deploy_app_host_rejects_non_https_manifest() {
  local workdir shared_manifest app_manifest fake_bin
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
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
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
  jq '.public_scheme = "http"' "$app_manifest" >"$workdir/app-deploy.http.json"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"

  if (
    PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$workdir/app-deploy.http.json" \
      --release-tag app-binaries-v0.1.0-testnet \
      --dry-run >/dev/null 2>&1
  ); then
    printf 'expected deploy-app-host.sh to reject non-https manifests\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_deploy_app_host_rejects_non_loopback_listeners() {
  local workdir shared_manifest app_manifest fake_bin
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
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
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
  jq '.services.bridge_api.listen_addr = "0.0.0.0:8082"' "$app_manifest" >"$workdir/app-deploy.nonloopback.json"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"

  if (
    PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$workdir/app-deploy.nonloopback.json" \
      --release-tag app-binaries-v0.1.0-testnet \
      --dry-run >/dev/null 2>&1
  ); then
    printf 'expected deploy-app-host.sh to reject non-loopback listeners\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

main() {
  test_deploy_app_host_uses_release_assets_and_updates_remote_runtime
  test_deploy_app_host_allows_missing_backoffice_juno_rpc_url
  test_deploy_app_host_preserves_preview_iam_kafka_auth
  test_deploy_app_host_provisions_edge_and_uses_origin_proxy
  test_deploy_app_host_rejects_non_https_manifest
  test_deploy_app_host_rejects_non_loopback_listeners
}

main "$@"
