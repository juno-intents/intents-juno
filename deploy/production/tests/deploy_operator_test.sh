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
if [[ "\$1" == "call" && "\$5" == "isOperator(address)(bool)" ]]; then
  printf 'true\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
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

write_dkg_summary_with_operator_key() {
  local target="$1"
  local operator_key_file="$2"
  jq \
    --arg operator_key_file "$operator_key_file" \
    '
      .operators[0].operator_key_file = $operator_key_file
    ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$target"
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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "StrictHostKeyChecking=yes" "scp strict host key checking"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.pem" "tls cert copied"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.key" "tls key copied"
  assert_contains "$(cat "$log_dir/scp.log")" "ufvk.txt" "ufvk file copied"
  assert_contains "$(cat "$log_dir/scp.log")" "junocashd.conf" "junocashd config copied"
  assert_contains "$(cat "$log_dir/scp.log")" "dkg-peer-hosts.json" "distributed dkg peer host map copied"
  assert_contains "$(cat "$log_dir/scp.log")" "operator-export-kms.sh" "kms export helper copied"
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
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'juno_txsign_downloaded="$(ensure_juno_txsign_binary "$JUNO_TXSIGN_VERSION_DEFAULT" "$dkg_stage_dir")"' "remote deploy fetches the Linux juno-txsign release artifact"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$juno_txsign_downloaded" "$runtime_dir/bin/juno-txsign"' "remote deploy installs the downloaded juno-txsign binary into the protected runtime"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'juno_txsign_runtime_bin="$runtime_dir/bin/juno-txsign"' "remote deploy records the installed juno-txsign runtime path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo chown -R intents-juno:intents-juno "$runtime_dir"' "remote deploy reassigns restored runtime to the service user"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl stop juno-scan || true' "remote deploy stops juno-scan before repairing its state directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "sudo bash -lc 'chown -R intents-juno:intents-juno /var/lib/intents-juno/juno-scan.db'" "remote deploy repairs juno-scan state ownership through a root shell"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo test -x "$dkg_admin_runtime_bin"' "remote deploy verifies the restored runtime binary through sudo"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo test -x "$juno_txsign_runtime_bin"' "remote deploy verifies the restored juno-txsign binary through sudo"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'juno_txsign_help="$(sudo "$juno_txsign_runtime_bin" --help 2>&1 || true)"' "remote deploy probes the runtime juno-txsign command set"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'grep -qE '\''(^|[[:space:]])sign-digest([[:space:]]|$)'\'' <<<"$juno_txsign_help"' "remote deploy requires juno-txsign sign-digest support"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_admin_serve_script="/usr/local/bin/intents-juno-dkg-admin-serve.sh"' "remote deploy can patch legacy dkg-admin wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'dkg_admin_tmp="$(mktemp)"' "remote deploy rewrites the dkg-admin wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'admin_config_dir="$(dirname "$admin_config")"' "remote deploy writes a dkg-admin wrapper that derives the bundle directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'cd "$admin_config_dir"' "remote deploy writes a dkg-admin wrapper that runs from the bundle directory"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'exec /var/lib/intents-juno/operator-runtime/bin/dkg-admin --config "$admin_config" serve' "remote deploy writes the corrected dkg-admin wrapper command"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$dkg_admin_tmp" "$dkg_admin_serve_script"' "remote deploy installs the corrected dkg-admin wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'spendauth_signer_script="/usr/local/bin/intents-juno-spendauth-signer.sh"' "remote deploy can patch the spendauth signer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'spendauth_tmp="$(mktemp)"' "remote deploy rewrites the spendauth signer wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'exec sudo -u intents-juno "$0" "$@"' "remote deploy writes the spendauth wrapper to drop root before host-process signing"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'exec "${TSS_SPENDAUTH_SIGNER_BIN}" --config "$admin_config" "$@"' "remote deploy writes the corrected spendauth signer wrapper command"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$spendauth_tmp" "$spendauth_signer_script"' "remote deploy installs the corrected spendauth signer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"' "remote deploy can patch the withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_tmp="$(mktemp)"' "remote deploy rewrites the withdraw-coordinator wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--postgres-dsn-env "${WITHDRAW_COORDINATOR_POSTGRES_DSN_ENV:-CHECKPOINT_POSTGRES_DSN}"' "remote deploy writes the withdraw wrapper to pass the Postgres DSN by env indirection"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--claim-ttl "${WITHDRAW_COORDINATOR_CLAIM_TTL:-5m}"' "remote deploy writes the withdraw wrapper with a durable claim ttl default"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'deposit_base_rpc_url="${BASE_RPC_URL:-${BASE_RELAYER_RPC_URL:-${BASE_EVENT_SCANNER_BASE_RPC_URL:-}}}"' "remote deploy derives the deposit relayer base rpc url from staged env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'deposit_juno_rpc_url="${DEPOSIT_SCAN_JUNO_RPC_URL:-${WITHDRAW_COORDINATOR_JUNO_RPC_URL:-}}"' "remote deploy derives the deposit relayer juno rpc url from staged env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--base-rpc-url "${deposit_base_rpc_url}"' "remote deploy writes the deposit wrapper with the required base rpc url"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-rpc-url "${deposit_juno_rpc_url}"' "remote deploy writes the deposit wrapper with the required juno rpc url"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS' "remote deploy exports kafka iam and AWS sdk env into service wrappers"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-scan-url "${WITHDRAW_COORDINATOR_JUNO_SCAN_URL}"' "remote deploy writes the withdraw wrapper to pin juno txbuild to juno-scan"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-scan-bearer-env JUNO_SCAN_BEARER_TOKEN' "remote deploy writes the withdraw wrapper to pass the scanner bearer env name"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--juno-fee-add-zat "${WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT:-1000000}"' "remote deploy writes the withdraw wrapper with a durable juno fee floor"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--expiry-safety-margin "${WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN:-6h}"' "remote deploy writes the withdraw wrapper with a bounded expiry safety margin"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--max-expiry-extension "${WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION:-12h}"' "remote deploy writes the withdraw wrapper with the on-chain max expiry extension"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--tss-server-name "${WITHDRAW_COORDINATOR_TSS_SERVER_NAME}"' "remote deploy writes the withdraw wrapper to forward the optional tss server-name override"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$withdraw_tmp" "$withdraw_coordinator_script"' "remote deploy installs the corrected withdraw-coordinator wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_finalizer_script="/usr/local/bin/intents-juno-withdraw-finalizer.sh"' "remote deploy can patch the withdraw-finalizer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'withdraw_finalizer_tmp="$(mktemp)"' "remote deploy rewrites the withdraw-finalizer wrapper from a temp file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$withdraw_finalizer_tmp" "$withdraw_finalizer_script"' "remote deploy installs the corrected withdraw-finalizer wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'base_event_scanner_script="/usr/local/bin/intents-juno-base-event-scanner.sh"' "remote deploy can patch the base-event-scanner wrapper"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'base-event-scanner requires BASE_EVENT_SCANNER_START_BLOCK in /etc/intents-juno/operator-stack.env' "remote deploy restores base-event-scanner start block guard"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN JUNO_TXSIGN_SIGNER_KEYS' "remote deploy backfills exported signer env into the withdraw-coordinator wrapper"
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
  assert_contains "$(cat "$log_dir/ssh.stdin")" '! grep -Fq '\''txunpaidactionlimit=10000'\'' "$config_hydrator_script"' "remote deploy backfills the junocashd unpaid action limit into legacy hydrators"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'print "txunpaidactionlimit=10000"' "remote deploy injects the junocashd unpaid action limit into the legacy hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$hydrator_tmp" "$config_hydrator_script"' "remote deploy replaces the legacy hydrator script before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo sed -i '\''/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d'\'' /etc/intents-juno/operator-stack.env' "remote deploy scrubs stale private key env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo rm -f /etc/intents-juno/checkpoint-signer.key' "remote deploy removes deprecated signer key file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/operator-stack.env" /etc/intents-juno/operator-stack.env' "remote deploy stages the rendered operator env atomically"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/junocashd.conf" /etc/intents-juno/junocashd.conf' "remote deploy stages junocashd rpc config"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir/exports"' "remote deploy creates runtime export receipt dir"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo -u intents-juno bash "$remote_stage_dir/operator-export-kms.sh" export' "remote deploy exports restored dkg package to kms"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--kms-key-id "${CHECKPOINT_SIGNER_KMS_KEY_ID}"' "remote deploy exports with the staged kms key"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--s3-bucket "${CHECKPOINT_BLOB_BUCKET}"' "remote deploy exports with the staged checkpoint bucket"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--s3-key-prefix "${CHECKPOINT_BLOB_PREFIX:-dkg/keypackages}"' "remote deploy exports with the staged checkpoint prefix"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '--s3-sse-kms-key-id "${CHECKPOINT_SIGNER_KMS_KEY_ID}"' "remote deploy stores exported checkpoint packages under kms-backed s3 encryption"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'latest_kms_receipt="$(sudo bash -lc '\''ls -1t "$1"/exports/kms-export-receipt-*.json 2>/dev/null | head -n1'\'' _ "$runtime_dir")"' "remote deploy captures the latest kms export receipt"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo ln -sfn "$latest_kms_receipt" "$runtime_dir/exports/kms-export-receipt.json"' "remote deploy publishes a stable latest kms export receipt path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"' "remote deploy stages signer ufvk file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl daemon-reload' "remote deploy reloads systemd units before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart intents-juno-config-hydrator.service' "remote deploy restarts config hydrator before dependent services"
  assert_line_order "$(cat "$log_dir/ssh.stdin")" 'restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force' 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"' "remote deploy stages signer ufvk after restoring the runtime"
  assert_line_order "$(cat "$log_dir/ssh.stdin")" 'restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force' 'sudo -u intents-juno bash "$remote_stage_dir/operator-export-kms.sh" export' "remote deploy exports the restored dkg package after restore"
  assert_line_order "$(cat "$log_dir/ssh.stdin")" 'sudo -u intents-juno bash "$remote_stage_dir/operator-export-kms.sh" export' 'for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do' "remote deploy completes kms export before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo pkill -f '\''/usr/local/bin/intents-juno-dkg-admin-serve.sh'\'' || true' "remote deploy clears stale dkg-admin wrapper processes before restart"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo pkill -f '\''dkg-admin .* serve'\'' || true' "remote deploy clears stale dkg-admin runtime processes before restart"
  assert_line_order "$(cat "$log_dir/ssh.stdin")" 'sudo pkill -f '\''/usr/local/bin/intents-juno-dkg-admin-serve.sh'\'' || true' 'sudo systemctl reset-failed "$svc" || true' "remote deploy clears stale dkg-admin processes before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do' "remote deploy restarts junocashd before scanner-dependent services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl reset-failed "$svc" || true' "remote deploy clears systemd start limits before restarting operator services"
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
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000" "withdraw coordinator juno fee floor staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h" "withdraw coordinator expiry safety margin staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h" "withdraw coordinator max expiry extension staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/juno-txsign" "withdraw coordinator extend signer staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "withdraw coordinator signer key staged"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "staged env omits non-local withdraw signer keys"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "withdraw finalizer scan url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_EVENT_SCANNER_START_BLOCK=12345" "base event scanner start block staged"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'curl -fsS -X POST "${curl_headers[@]}" -H "Content-Type: application/json" --data "$payload" "${scan_url%/}${path}"' "deploy posts scan wallet mutations through curl"
  assert_contains "$(cat "$log_dir/ssh.log")" "bash -s -- http://127.0.0.1:8080 /v1/wallets" "deploy runs wallet registration over ssh"
  assert_contains "$(cat "$log_dir/ssh.log")" "/v1/wallets/wallet-op1/backfill" "deploy runs wallet backfill over ssh"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "tss ufvk path staged"
  assert_contains "$(cat "$log_dir/ufvk.txt")" "uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" "ufvk value staged"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcuser=juno" "junocashd config rpc user staged"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcpassword=rpcpass" "junocashd config rpc pass staged"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "txunpaidactionlimit=10000" "junocashd config raises unpaid action limit"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "kms operator env omits private key"
  assert_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "dns publish"
  assert_contains "$(cat "$log_dir/cast.log")" "call --rpc-url https://base-sepolia.example.invalid 0x4444444444444444444444444444444444444444 isOperator(address)(bool) 0x9999999999999999999999999999999999999999" "deploy validates operator registry membership before rollout"
  assert_contains "$(cat "$log_dir/cast.log")" "wallet address --private-key" "deploy derives the base relayer address from the configured key"
  assert_contains "$(cat "$log_dir/cast.log")" "balance --rpc-url" "deploy verifies base relayer funding before rollout"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_ALLOWED_CONTRACTS=0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333,0x4444444444444444444444444444444444444444,0x5555555555555555555555555555555555555555" "allowlist injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_PER_SECOND=20" "rate limit refill default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_BURST=40" "rate limit burst default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_MAX_TRACKED_CLIENTS=10000" "rate limit capacity default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_TLS_CERT_FILE=/etc/intents-juno/base-relayer/server.pem" "tls cert path injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_TLS_KEY_FILE=/etc/intents-juno/base-relayer/server.key" "tls key path injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_URL=https://127.0.0.1:18081" "https base relayer url"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "operator env uses operator-owned checkpoint bucket"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_PREFIX=operators/op1/checkpoint-packages" "operator env uses operator-owned checkpoint prefix"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-dkg-keypackages" "operator env omits shared checkpoint bucket when operator bucket is configured"
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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$workdir/dkg-tls/coordinator-client.key" \
    -out "$workdir/dkg-tls/coordinator-client.csr" \
    -subj "/CN=coordinator-client" >/dev/null 2>&1
  openssl x509 -req \
    -in "$workdir/dkg-tls/coordinator-client.csr" \
    -CA "$workdir/dkg-tls/ca.pem" \
    -CAkey "$workdir/dkg-tls/ca.key" \
    -CAcreateserial \
    -out "$workdir/dkg-tls/coordinator-client.pem" \
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/scp.log")" "dkg-server.pem" "deploy copies generated dkg server cert"
  assert_contains "$(cat "$log_dir/scp.log")" "dkg-server.key" "deploy copies generated dkg server key"
  assert_contains "$(cat "$log_dir/scp.log")" "coordinator-client.pem" "deploy copies dkg coordinator client cert"
  assert_contains "$(cat "$log_dir/scp.log")" "coordinator-client.key" "deploy copies dkg coordinator client key"
  assert_contains "$(cat "$log_dir/scp.log")" "ca.pem" "deploy copies dkg ca"
  assert_contains "$(cat "$log_dir/aws.log")" "describe-instances" "deploy resolves peer hosts through aws"
  assert_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress" "deploy ensures operator grpc mesh ingress"
  assert_contains "$(cat "$log_dir/cast.log")" "balance --rpc-url" "deploy verifies base relayer funding before distributed dkg rollout"
  assert_contains "$(cat "$log_dir/dkg-peer-hosts.json")" "10.0.0.11" "deploy writes resolved peer hosts"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_TSS_SERVER_NAME=10.0.0.11" "deploy stages tss server name override from resolved private host"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/ca.pem" "$runtime_dir/bundle/tls/ca.pem"' "remote deploy installs shared dkg ca"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/coordinator-client.pem" "$runtime_dir/bundle/tls/coordinator-client.pem"' "remote deploy installs shared dkg coordinator client cert"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/coordinator-client.key" "$runtime_dir/bundle/tls/coordinator-client.key"' "remote deploy installs shared dkg coordinator client key"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "coordinator_client_cert_sha256" "remote deploy refreshes dkg coordinator client fingerprint"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "tls_client_cert_pem_path" "remote deploy patches dkg admin config with tls client cert path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "tls_client_key_pem_path" "remote deploy patches dkg admin config with tls client key path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "operator runtime admin config missing coordinator client tls paths" "remote deploy verifies final dkg admin client tls paths"
  assert_contains "$(cat "$log_dir/ssh.stdin")" "operator runtime admin config missing coordinator client fingerprint" "remote deploy verifies final dkg admin client fingerprint"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/dkg-server.pem" "$runtime_dir/bundle/tls/server.pem"' "remote deploy installs generated dkg server cert"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/dkg-server.key" "$runtime_dir/bundle/tls/server.key"' "remote deploy installs generated dkg server key"
  san_text="$(openssl x509 -in "$log_dir/dkg-server.pem" -noout -ext subjectAltName 2>/dev/null)"
  assert_contains "$san_text" "DNS:localhost" "generated cert preserves localhost san"
  assert_contains "$san_text" "IP Address:10.0.0.11" "generated cert includes resolved peer host"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_dry_run_does_not_mutate_rollout_or_remote_state() {
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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/scp.log"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
cat >>"$log_dir/ssh.stdin" || true
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
if [[ "\$*" == *"describe-instances"* ]]; then
  printf '10.0.0.11\n'
fi
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --dry-run >/dev/null

  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "dry-run leaves rollout state pending"
  if [[ -e "$log_dir/scp.log" ]]; then
    printf 'expected dry-run to avoid scp but saw:\n%s\n' "$(cat "$log_dir/scp.log")" >&2
    exit 1
  fi
  if [[ -e "$log_dir/ssh.log" ]]; then
    printf 'expected dry-run to avoid ssh but saw:\n%s\n' "$(cat "$log_dir/ssh.log")" >&2
    exit 1
  fi
  if [[ -e "$log_dir/aws.log" ]]; then
    assert_not_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress" "dry-run avoids mutating security groups"
  fi

  rm -rf "$workdir"
}

test_deploy_operator_rejects_underfunded_base_relayer_before_rollout() {
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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
printf 'scp %s\n' "\$*" >>"$log_dir/scp.log"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null 2>&1; then
    printf 'expected deploy-operator.sh to reject underfunded base relayer\n' >&2
    exit 1
  fi

  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "underfunded relayer leaves rollout state pending"
  assert_contains "$(cat "$log_dir/cast.log")" "balance --rpc-url" "underfunded relayer check reads balance"
  if [[ -e "$log_dir/scp.log" ]]; then
    printf 'expected underfunded relayer to block before scp but saw:\n%s\n' "$(cat "$log_dir/scp.log")" >&2
    exit 1
  fi
  if [[ -e "$log_dir/ssh.log" ]]; then
    printf 'expected underfunded relayer to block before ssh but saw:\n%s\n' "$(cat "$log_dir/ssh.log")" >&2
    exit 1
  fi

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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
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
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
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

test_deploy_operator_preserves_secure_preview_signer_configuration() {
  local workdir output_dir manifest log_dir fake_bin state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'preview-backup' >"$workdir/dkg-backup.zip"
  export TEST_PREVIEW_CHECKPOINT_POSTGRES_DSN="postgres://preview?sslmode=require"
  export TEST_PREVIEW_BASE_RELAYER_KEYS="0x1111111111111111111111111111111111111111111111111111111111111111"
  export TEST_PREVIEW_BASE_RELAYER_AUTH_TOKEN="preview-token"
  export TEST_PREVIEW_JUNO_RPC_USER="juno"
  export TEST_PREVIEW_JUNO_RPC_PASS="rpcpass"
  export TEST_PREVIEW_WALLET_ID="wallet-op1"
  export TEST_PREVIEW_JUNO_TXSIGN_SIGNER_KEYS="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=env:TEST_PREVIEW_CHECKPOINT_POSTGRES_DSN
BASE_RELAYER_PRIVATE_KEYS=env:TEST_PREVIEW_BASE_RELAYER_KEYS
BASE_RELAYER_AUTH_TOKEN=env:TEST_PREVIEW_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=env:TEST_PREVIEW_JUNO_RPC_USER
JUNO_RPC_PASS=env:TEST_PREVIEW_JUNO_RPC_PASS
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=env:TEST_PREVIEW_WALLET_ID
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=env:TEST_PREVIEW_WALLET_ID
JUNO_TXSIGN_SIGNER_KEYS=env:TEST_PREVIEW_JUNO_TXSIGN_SIGNER_KEYS
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/preview" "$workdir"

  manifest="$output_dir/preview/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/preview/rollout-state.json"

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
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "preview operator env stages kms checkpoint signer mode"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "preview operator env stages the checkpoint signer kms key"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "preview operator env omits local checkpoint signer key material"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "preview operator env stages the checkpoint package bucket required by config hydration"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" "preview operator env stages kafka auth iam"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'export JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam' "preview deploy writes wrappers for kafka auth iam"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "preview secure signer rollout succeeds"
  rm -rf "$workdir"
}

main() {
  test_deploy_operator_enforces_known_hosts_and_updates_rollout
  test_deploy_operator_stages_distributed_dkg_server_tls
  test_deploy_operator_dry_run_does_not_mutate_rollout_or_remote_state
  test_deploy_operator_rejects_underfunded_base_relayer_before_rollout
  test_deploy_operator_force_reruns_done_operator
  test_deploy_operator_retries_transient_service_checks
  test_deploy_operator_preserves_secure_preview_signer_configuration
}

main "$@"
