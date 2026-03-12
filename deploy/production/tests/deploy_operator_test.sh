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
EOF
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
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$output_dir/alpha" "$workdir"

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
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "StrictHostKeyChecking=yes" "scp strict host key checking"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.pem" "tls cert copied"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.key" "tls key copied"
  assert_contains "$(cat "$log_dir/scp.log")" "junocashd.conf" "junocashd config copied"
  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/known_hosts" "ssh uses known_hosts file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"' "remote deploy updates checkpoint signer wrapper"
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
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"' "remote deploy can patch the withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "remote deploy backfills exported Postgres DSN into the withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'coord_client_cert="$(env_get_value_remote "WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE")"' "remote deploy derives withdraw coordinator client cert path from staged env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -D -m 0640 -o root -g intents-juno "$server_cert" "$coord_client_cert"' "remote deploy materializes dev-mode coordinator client cert from the server cert"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -D -m 0640 -o root -g intents-juno "$server_key" "$coord_client_key"' "remote deploy materializes dev-mode coordinator client key from the server key"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"' "remote deploy can patch legacy config hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'grep -Fq '\''install -m 0600 "$tmp" "$file"'\''' "remote deploy detects legacy hydrator env rewrites"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$hydrator_tmp" "$config_hydrator_script"' "remote deploy replaces the legacy hydrator script before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo sed -i '\''/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d'\'' /etc/intents-juno/operator-stack.env' "remote deploy scrubs stale private key env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo rm -f /etc/intents-juno/checkpoint-signer.key' "remote deploy removes deprecated signer key file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/operator-stack.env" /etc/intents-juno/operator-stack.env' "remote deploy stages the rendered operator env atomically"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/junocashd.conf" /etc/intents-juno/junocashd.conf' "remote deploy stages junocashd rpc config"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart intents-juno-config-hydrator.service' "remote deploy restarts config hydrator before dependent services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do' "remote deploy restarts junocashd before scanner-dependent services"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active junocashd" "deploy verifies junocashd after restarting it"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force' "remote deploy forces backup restore for retry-safe rollout"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active juno-scan" "deploy verifies juno-scan after restarting it"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "kms signer driver staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "kms signer key id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "operator address staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_USER=juno" "juno rpc user staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_PASS=rpcpass" "juno rpc pass staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "withdraw coordinator rpc url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "withdraw finalizer scan url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "tss ufvk path staged"
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
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$output_dir/alpha" "$workdir"

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

main() {
  test_deploy_operator_enforces_known_hosts_and_updates_rollout
  test_deploy_operator_force_reruns_done_operator
}

main "$@"
