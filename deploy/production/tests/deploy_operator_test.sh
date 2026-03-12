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

assert_line_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"
  local first_line second_line
  first_line="$(awk -v needle="$first" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  second_line="$(awk -v needle="$second" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'assert_line_order failed: %s: first=%q second=%q first_line=%q second_line=%q\n' "$msg" "$first" "$second" "$first_line" "$second_line" >&2
    exit 1
  fi
}

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh "$workdir/known_hosts" \
    --arg backup "$workdir/dkg-backup.zip" \
    --arg secrets "$workdir/operator-secrets.env" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_deploy_operator_enforces_known_hosts_and_updates_rollout() {
  local workdir output_dir manifest shared_manifest log_dir fake_bin state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  shared_manifest="$workdir/shared-manifest.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/scp.log"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/ssh.stdin"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "StrictHostKeyChecking=yes" "scp strict host key checking"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.pem" "tls cert copied"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.key" "tls key copied"
  assert_contains "$(cat "$log_dir/scp.log")" "ufvk.txt" "ufvk file copied"
  assert_contains "$(cat "$log_dir/scp.log")" "junocashd.conf" "junocashd config copied"
  assert_contains "$(cat "$log_dir/scp.log")" "dkg-peer-hosts.json" "distributed dkg peer host map copied"
  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/known_hosts" "ssh uses known_hosts file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"' "remote deploy updates checkpoint signer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'checkpoint_signer_help="$(/usr/local/bin/checkpoint-signer --help 2>&1 || true)"' "remote deploy checks checkpoint signer flag support before writing wrapper args"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'checkpoint_signer_lease_name="${CHECKPOINT_SIGNER_LEASE_NAME:-checkpoint-signer-${OPERATOR_ADDRESS}}"' "remote deploy restores per-operator checkpoint signer lease names"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--lease-name "${checkpoint_signer_lease_name}"' "remote deploy wires the per-operator checkpoint signer lease into the wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"' "remote deploy updates checkpoint aggregator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'source "$remote_stage_dir/common.sh"' "remote deploy loads dkg helper functions on the host"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_stage_dir="$(mktemp -d)"' "remote deploy stages dkg-admin in a writable temp dir"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'ensure_dkg_binary "dkg-admin" "$dkg_release_tag" "$dkg_stage_dir"' "remote deploy fetches the Linux dkg-admin release artifact"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$dkg_admin_downloaded" "$runtime_dir/bin/dkg-admin"' "remote deploy installs the downloaded dkg-admin binary into the protected runtime"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_admin_runtime_bin="$runtime_dir/bin/dkg-admin"' "remote deploy records the installed dkg-admin runtime path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo chown -R intents-juno:intents-juno "$runtime_dir"' "remote deploy reassigns restored runtime to the service user"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl stop juno-scan || true' "remote deploy stops juno-scan before repairing its state directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "sudo bash -lc 'chown -R intents-juno:intents-juno /var/lib/intents-juno/juno-scan.db'" "remote deploy repairs juno-scan state ownership through a root shell"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo test -x "$dkg_admin_runtime_bin"' "remote deploy verifies the restored runtime binary through sudo"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_admin_serve_script="/usr/local/bin/intents-juno-dkg-admin-serve.sh"' "remote deploy can patch legacy dkg-admin wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_admin_tmp="$(mktemp)"' "remote deploy rewrites the dkg-admin wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'admin_config_dir="$(dirname "$admin_config")"' "remote deploy writes a dkg-admin wrapper that derives the bundle directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'cd "$admin_config_dir"' "remote deploy writes a dkg-admin wrapper that runs from the bundle directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'exec /var/lib/intents-juno/operator-runtime/bin/dkg-admin --config "$admin_config" serve' "remote deploy writes the corrected dkg-admin wrapper command"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$dkg_admin_tmp" "$dkg_admin_serve_script"' "remote deploy installs the corrected dkg-admin wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'spendauth_signer_script="/usr/local/bin/intents-juno-spendauth-signer.sh"' "remote deploy can patch the spendauth signer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'spendauth_tmp="$(mktemp)"' "remote deploy rewrites the spendauth signer wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'exec "${TSS_SPENDAUTH_SIGNER_BIN}" --config "$admin_config" "$@"' "remote deploy writes the corrected spendauth signer wrapper command"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$spendauth_tmp" "$spendauth_signer_script"' "remote deploy installs the corrected spendauth signer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"' "remote deploy can patch the withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'base_event_scanner_script="/usr/local/bin/intents-juno-base-event-scanner.sh"' "remote deploy can patch the base-event-scanner wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'base-event-scanner requires BASE_EVENT_SCANNER_START_BLOCK in /etc/intents-juno/operator-stack.env' "remote deploy restores base-event-scanner start block guard"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "remote deploy backfills exported Postgres DSN into the withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'coord_client_cert="$(env_get_value_remote "WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE")"' "remote deploy derives withdraw coordinator client cert path from staged env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'openssl x509 -in "$coord_client_cert" -noout -purpose' "remote deploy validates the restored coordinator client cert purpose"
  assert_not_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -D -m 0640 -o root -g intents-juno "$server_cert" "$coord_client_cert"' "remote deploy no longer fabricates coordinator client certs from the server cert"
  assert_not_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -D -m 0640 -o root -g intents-juno "$server_key" "$coord_client_key"' "remote deploy no longer fabricates coordinator client keys from the server key"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_peer_hosts_file="$remote_stage_dir/dkg-peer-hosts.json"' "remote deploy stages a distributed dkg peer host map"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo cat "$admin_config_path" | jq --slurpfile peer_hosts' "remote deploy reads the protected admin-config through sudo before rewriting the distributed roster"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '.roster.operators |= map(' "remote deploy rewrites admin-config roster endpoints from the staged peer map"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'capture("^(?<scheme>https?)://(?<host>[^:/]+)(?::(?<port>[0-9]+))?$")' "remote deploy preserves grpc endpoint scheme and port while replacing the host"
  assert_contains "$(cat "$log_dir/ssh.stdin")" ".roster |" "remote deploy canonicalizes the nested roster object when recomputing roster_hash_hex"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "printf '%s' \"\$dkg_roster_canonical\"" "remote deploy hashes the canonical roster without a trailing newline"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"' "remote deploy can patch legacy config hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'grep -Fq '\''install -m 0600 "$tmp" "$file"'\''' "remote deploy detects legacy hydrator env rewrites"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$hydrator_tmp" "$config_hydrator_script"' "remote deploy replaces the legacy hydrator script before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo sed -i '\''/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d'\'' /etc/intents-juno/operator-stack.env' "remote deploy scrubs stale private key env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo rm -f /etc/intents-juno/checkpoint-signer.key' "remote deploy removes deprecated signer key file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/operator-stack.env" /etc/intents-juno/operator-stack.env' "remote deploy stages the rendered operator env atomically"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/junocashd.conf" /etc/intents-juno/junocashd.conf' "remote deploy stages junocashd rpc config"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"' "remote deploy stages signer ufvk file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl daemon-reload' "remote deploy reloads systemd units before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart intents-juno-config-hydrator.service' "remote deploy restarts config hydrator before dependent services"
  assert_line_order "$(cat "$log_dir/ssh.stdin")" 'restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force' 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"' "remote deploy stages signer ufvk after restoring the runtime"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do' "remote deploy restarts junocashd before scanner-dependent services"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active junocashd" "deploy verifies junocashd after restarting it"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force' "remote deploy forces backup restore for retry-safe rollout"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active juno-scan" "deploy verifies juno-scan after restarting it"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "kms signer driver staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "kms signer key id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "operator address staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_USER=juno" "juno rpc user staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_PASS=rpcpass" "juno rpc pass staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "DEPOSIT_SCAN_ENABLED=true" "deposit scan enabled"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "DEPOSIT_SCAN_JUNO_SCAN_URL=http://127.0.0.1:8080" "deposit scan url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=wallet-op1" "deposit scan wallet id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "DEPOSIT_SCAN_JUNO_RPC_URL=http://127.0.0.1:18232" "deposit scan rpc url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "withdraw coordinator rpc url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "withdraw finalizer scan url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_EVENT_SCANNER_START_BLOCK=12345" "base event scanner start block staged"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'curl -fsS -X POST "${curl_headers[@]}" -H "Content-Type: application/json" --data "$payload" "${scan_url%/}${path}"' "deploy posts scan wallet mutations through curl"
  assert_contains "$(cat "$log_dir/ssh.log")" "bash -s -- http://127.0.0.1:8080 /v1/wallets" "deploy runs wallet registration over ssh"
  assert_contains "$(cat "$log_dir/ssh.log")" "/v1/wallets/wallet-op1/backfill" "deploy runs wallet backfill over ssh"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "tss ufvk path staged"
  assert_contains "$(cat "$log_dir/ufvk.txt")" "uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" "ufvk value staged"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcuser=juno" "junocashd config rpc user staged"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcpassword=rpcpass" "junocashd config rpc pass staged"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "kms operator env omits private key"
  assert_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "dns publish"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_ALLOWED_CONTRACTS=0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333,0x4444444444444444444444444444444444444444,0x5555555555555555555555555555555555555555" "allowlist injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_PER_SECOND=20" "rate limit refill default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_BURST=40" "rate limit burst default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_MAX_TRACKED_CLIENTS=10000" "rate limit capacity default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_TLS_CERT_FILE=/etc/intents-juno/base-relayer/server.pem" "tls cert path injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_TLS_KEY_FILE=/etc/intents-juno/base-relayer/server.key" "tls key path injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_URL=https://127.0.0.1:18081" "https base relayer url"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_stages_distributed_dkg_server_tls() {
  local workdir output_dir manifest shared_manifest log_dir fake_bin state_file cert_b64 key_b64 san_text
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin" "$workdir/dkg-tls"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$workdir/dkg-tls/ca.key" \
    -out "$workdir/dkg-tls/ca.pem" \
    -subj "/CN=Test DKG CA" \
    -days 1 >/dev/null 2>&1

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  shared_manifest="$workdir/shared-manifest.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/scp.log"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/ssh.stdin"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
printf '10.0.0.11\n'
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "dkg-server.pem" "deploy copies generated dkg server cert"
  assert_contains "$(cat "$log_dir/scp.log")" "dkg-server.key" "deploy copies generated dkg server key"
  assert_contains "$(cat "$log_dir/aws.log")" "describe-instances" "deploy resolves peer hosts through aws"
  assert_contains "$(cat "$log_dir/dkg-peer-hosts.json")" "10.0.0.11" "deploy writes resolved peer hosts"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/dkg-server.pem" "$runtime_dir/bundle/tls/server.pem"' "remote deploy installs generated dkg server cert"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/dkg-server.key" "$runtime_dir/bundle/tls/server.key"' "remote deploy installs generated dkg server key"
  san_text="$(openssl x509 -in "$log_dir/dkg-server.pem" -noout -ext subjectAltName 2>/dev/null)"
  assert_contains "$san_text" "DNS:localhost" "generated cert preserves localhost san"
  assert_contains "$san_text" "IP Address:10.0.0.11" "generated cert includes resolved peer host"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_force_reruns_done_operator() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  jq '(.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111")).status = "done"' "$state_file" >"$state_file.tmp"
  mv "$state_file.tmp" "$state_file"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/scp.log"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >>"$log_dir/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --force >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "operator-deploy.json" "force rerun still stages manifest files"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active checkpoint-signer" "force rerun still verifies restarted services"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "force rerun preserves done rollout status after redeploy"
  rm -rf "$workdir"
}

test_deploy_operator_retries_transient_service_checks() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
if [[ "\$*" == *"systemctl is-active juno-scan"* ]]; then
  counter_file="$log_dir/juno-scan.counter"
  count=0
  if [[ -f "\$counter_file" ]]; then
    count="\$(cat "\$counter_file")"
  fi
  count=\$((count + 1))
  printf '%s' "\$count" >"\$counter_file"
  if (( count < 3 )); then
    printf 'inactive\n'
    exit 0
  fi
  printf 'active\n'
  exit 0
fi
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
cat >>"$log_dir/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES=5 \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS=0.01 \
  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  if [[ "$(grep -c 'systemctl is-active juno-scan' "$log_dir/ssh.log")" -lt 3 ]]; then
    printf 'expected deploy-operator.sh to retry juno-scan readiness\n' >&2
    exit 1
  fi
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "transient service retries still complete rollout"
  rm -rf "$workdir"
}

main() {
  test_deploy_operator_enforces_known_hosts_and_updates_rollout
  test_deploy_operator_stages_distributed_dkg_server_tls
  test_deploy_operator_force_reruns_done_operator
  test_deploy_operator_retries_transient_service_checks
}

main "$@"
