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

test_rotate_operator_key_captures_evidence_and_restarts_services() {
  local workdir output_dir log_dir fake_bin manifest evidence_dir cert_b64 key_b64
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
  exit 0
fi
if [[ "\$*" == *'awk -F='*'/etc/intents-juno/operator-stack.env'* ]]; then
  case "\$*" in
    *'CHECKPOINT_SIGNER_DRIVER'*) printf 'aws-kms\n' ;;
    *'CHECKPOINT_SIGNER_KMS_KEY_ID'*) printf 'arn:aws:kms:us-east-1:021490342184:key/original\n' ;;
    *'OPERATOR_ADDRESS'*) printf '0x1111111111111111111111111111111111111111\n' ;;
  esac
  exit 0
fi
cat >>"$log_dir/ssh.stdin" || true
exit 0
EOF
  chmod +x "$fake_bin/scp" "$fake_bin/ssh"

  evidence_dir="$workdir/evidence"
  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/rotate-operator-key.sh" \
    --operator-deploy "$manifest" \
    --output-dir "$evidence_dir" >/dev/null

  assert_file_exists "$evidence_dir/pre.json" "pre-rotation evidence"
  assert_file_exists "$evidence_dir/post.json" "post-rotation evidence"
  assert_contains "$(cat "$log_dir/scp.log")" "operator-stack.env" "rotation uploads rendered env"
  assert_contains "$(cat "$log_dir/scp.log")" "junocashd.conf" "rotation uploads junocashd config"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.pem" "rotation uploads tls cert when materialized"
  assert_contains "$(cat "$log_dir/scp.log")" "base-relayer-server.key" "rotation uploads tls key when materialized"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo sed -i '\''/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d'\'' /etc/intents-juno/operator-stack.env' "rotation scrubs stale private key env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo rm -f /etc/intents-juno/checkpoint-signer.key' "rotation removes deprecated signer key file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/operator-stack.env" /etc/intents-juno/operator-stack.env' "rotation installs rendered env"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/junocashd.conf" /etc/intents-juno/junocashd.conf' "rotation installs junocashd rpc config"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"' "rotation can patch legacy config hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '! grep -Fq '\''txunpaidactionlimit=10000'\'' "$config_hydrator_script"' "rotation backfills the junocashd unpaid action limit into legacy hydrators"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'print "txunpaidactionlimit=10000"' "rotation injects the junocashd unpaid action limit into the legacy hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo install -m 0755 "$hydrator_tmp" "$config_hydrator_script"' "rotation replaces the legacy hydrator script before restarting services"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo systemctl restart intents-juno-config-hydrator.service' "rotation restarts config hydrator"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'for svc in checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do' "rotation restarts checkpoint signer and dependent services as a batch"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active checkpoint-signer" "rotation verifies checkpoint signer"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "rotation env signer driver"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "rotation env kms key id"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "rotation env operator address"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_USER=juno" "rotation env juno rpc user"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_RPC_PASS=rpcpass" "rotation env juno rpc pass"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "rotation env withdraw coordinator rpc url"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "rotation env withdraw finalizer scan url"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "rotation env tss ufvk path"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcuser=juno" "rotation junocashd config rpc user"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "rpcpassword=rpcpass" "rotation junocashd config rpc pass"
  assert_contains "$(cat "$log_dir/junocashd.conf")" "txunpaidactionlimit=10000" "rotation junocashd config raises unpaid action limit"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "rotation env omits private key"
  assert_eq "$(jq -r '.signer.driver' "$evidence_dir/pre.json")" "aws-kms" "pre evidence signer driver"
  assert_eq "$(jq -r '.services["checkpoint-signer"]' "$evidence_dir/post.json")" "active" "post evidence checkpoint signer active"
  rm -rf "$workdir"
}

main() {
  test_rotate_operator_key_captures_evidence_and_restarts_services
}

main "$@"
