#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  local first_balance_wei="$3"
  local second_balance_wei="${4:-$3}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  case "\$4" in
    0x1111111111111111111111111111111111111111111111111111111111111111)
      printf '0x1111111111111111111111111111111111111111\n'
      ;;
    0x2222222222222222222222222222222222222222222222222222222222222222)
      printf '0x2222222222222222222222222222222222222222\n'
      ;;
    *)
      printf 'unexpected private key: %s\n' "\$4" >&2
      exit 1
      ;;
  esac
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  case "\${@: -1}" in
    0x1111111111111111111111111111111111111111)
      printf '%s\n' "$first_balance_wei"
      ;;
    0x2222222222222222222222222222222222222222)
      printf '%s\n' "$second_balance_wei"
      ;;
    *)
      printf 'unexpected balance address: %s\n' "\${@: -1}" >&2
      exit 1
      ;;
  esac
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod 0755 "$target"
}

test_operator_boot_canary_checks_services_over_strict_ssh() {
  local tmp fake_bin log_file manifest output_json shared_manifest
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  log_file="$tmp/ssh.log"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  shared_manifest="$tmp/shared-manifest.json"
  mkdir -p "$fake_bin"

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/known_hosts"
  cat >"$tmp/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222222222222222222222222222
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  printf 'backup' >"$tmp/dkg-backup.zip"
  cat >"$shared_manifest" <<JSON
{
  "shared_services": {
    "artifacts": {}
  },
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid"
  }
}
JSON

  cat >"$manifest" <<JSON
{
  "environment": "alpha",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "operator_host": "203.0.113.11",
  "operator_user": "intents-juno",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "shared_manifest_path": "$shared_manifest",
  "checkpoint_blob_bucket": "alpha-op1-dkg-keypackages",
  "checkpoint_blob_prefix": "operators/op1/checkpoint-packages",
  "dkg_backup_zip": "$tmp/dkg-backup.zip",
  "known_hosts_file": "$tmp/known_hosts",
  "secret_contract_file": "$tmp/operator-secrets.env",
  "dns": {
    "mode": "public-zone",
    "record_name": "op1.alpha.intents-testing.thejunowallet.com",
    "ttl_seconds": 60
  }
}
JSON

  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_file"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^CHECKPOINT_SIGNER_DRIVER=aws-kms$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY='"* ]]; then
  exit 1
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/juno-txsign$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -qE '^JUNO_TXSIGN_SIGNER_KEYS=0x[0-9a-fA-F]{64}\$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"/var/lib/intents-juno/operator-runtime/bin/juno-txsign --help"* ]]; then
  printf 'Usage: juno-txsign sign-digest [flags]\n'
  exit 0
fi
if [[ "\$*" == *"test -e /var/lib/intents-juno/operator-runtime/exports/kms-export-receipt.json"* ]]; then
  exit 0
fi
if [[ "\$*" == *"curl -fsS http://127.0.0.1:\${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz"* ]]; then
  exit 0
fi
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$tmp/cast.log" "1300000000000000" "1400000000000000"
  chmod 0755 "$fake_bin/ssh"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-operator-boot.sh \
      --operator-deploy "$manifest" >"$output_json"
  )

  assert_contains "$(cat "$log_file")" "StrictHostKeyChecking=yes" "operator canary enforces strict host key checking"
  assert_contains "$(cat "$log_file")" "UserKnownHostsFile=$tmp/known_hosts" "operator canary uses supplied known_hosts file"
  assert_contains "$(cat "$log_file")" "systemctl is-active checkpoint-signer" "operator canary checks checkpoint signer"
  assert_contains "$(cat "$log_file")" "systemctl is-active withdraw-finalizer" "operator canary checks withdraw finalizer"
  assert_contains "$(cat "$log_file")" "WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000" "operator canary verifies remote juno fee floor"
  assert_contains "$(cat "$log_file")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "operator canary verifies the production kms signer mode"
  assert_contains "$(cat "$log_file")" "WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h" "operator canary verifies remote expiry safety margin"
  assert_contains "$(cat "$log_file")" "WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h" "operator canary verifies remote max expiry extension"
  assert_contains "$(cat "$log_file")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/juno-txsign" "operator canary verifies remote juno-txsign path"
  assert_contains "$(cat "$log_file")" "/var/lib/intents-juno/operator-runtime/bin/juno-txsign --help" "operator canary verifies juno-txsign runtime"
  assert_contains "$(cat "$log_file")" "test -e /var/lib/intents-juno/operator-runtime/exports/kms-export-receipt.json" "operator canary verifies kms export receipt"
  assert_contains "$(cat "$log_file")" 'curl -fsS http://127.0.0.1:${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz' "operator canary verifies deposit-relayer readiness"
  assert_contains "$(cat "$tmp/cast.log")" "wallet address --private-key" "operator canary derives the base relayer address from the configured key"
  assert_contains "$(cat "$tmp/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0x1111111111111111111111111111111111111111" "operator canary checks first base relayer signer funding"
  assert_contains "$(cat "$tmp/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0x2222222222222222222222222222222222222222" "operator canary checks second base relayer signer funding"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "operator canary ready flag"
  assert_eq "$(jq -r '.checks.relayer_funding.status' "$output_json")" "passed" "operator canary relayer funding status"
  assert_contains "$(jq -r '.checks.relayer_funding.detail' "$output_json")" "0x1111111111111111111111111111111111111111=1300000000000000" "operator canary reports first relayer balance"
  assert_contains "$(jq -r '.checks.relayer_funding.detail' "$output_json")" "0x2222222222222222222222222222222222222222=1400000000000000" "operator canary reports second relayer balance"
  assert_eq "$(jq -r '.checks.withdraw_config.status' "$output_json")" "passed" "operator canary withdraw config status"
  assert_eq "$(jq -r '.checks.txsign_runtime.status' "$output_json")" "passed" "operator canary txsign runtime status"
  assert_eq "$(jq -r '.checks.kms_export.status' "$output_json")" "passed" "operator canary kms export status"
  assert_eq "$(jq -r '.checks.systemd.status' "$output_json")" "passed" "operator canary systemd status"
  assert_eq "$(jq -r '.checks.deposit_relayer_ready.status' "$output_json")" "passed" "operator canary deposit-relayer readiness status"

  rm -rf "$tmp"
}

test_operator_boot_canary_rejects_underfunded_relayer() {
  local tmp fake_bin manifest output_json shared_manifest
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  shared_manifest="$tmp/shared-manifest.json"
  mkdir -p "$fake_bin"

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/known_hosts"
  cat >"$tmp/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222222222222222222222222222
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  printf 'backup' >"$tmp/dkg-backup.zip"
  cat >"$shared_manifest" <<JSON
{
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid"
  }
}
JSON

  cat >"$manifest" <<JSON
{
  "environment": "alpha",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "operator_host": "203.0.113.11",
  "operator_user": "intents-juno",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "shared_manifest_path": "$shared_manifest",
  "dkg_backup_zip": "$tmp/dkg-backup.zip",
  "known_hosts_file": "$tmp/known_hosts",
  "secret_contract_file": "$tmp/operator-secrets.env"
}
JSON

  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf 'ssh should not be called when relayer funding is insufficient\n' >&2
exit 1
EOF
  write_fake_cast "$fake_bin/cast" "$tmp/cast.log" "1300000000000000" "1000"
  chmod 0755 "$fake_bin/ssh"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-operator-boot.sh \
      --operator-deploy "$manifest" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "underfunded relayer blocks ready flag"
  assert_eq "$(jq -r '.checks.relayer_funding.status' "$output_json")" "failed" "underfunded relayer fails funding check"
  assert_contains "$(jq -r '.checks.relayer_funding.detail' "$output_json")" "below minimum" "underfunded relayer detail"
  assert_contains "$(jq -r '.checks.relayer_funding.detail' "$output_json")" "0x2222222222222222222222222222222222222222" "underfunded relayer detail identifies the failing signer"
  assert_contains "$(cat "$tmp/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0x1111111111111111111111111111111111111111" "underfunded relayer still checks the first signer"
  assert_contains "$(cat "$tmp/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0x2222222222222222222222222222222222222222" "underfunded relayer still checks the failing signer"

  rm -rf "$tmp"
}

test_operator_boot_canary_preserves_secure_preview_signer_configuration() {
  local tmp fake_bin log_file manifest output_json shared_manifest
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  log_file="$tmp/ssh.log"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  shared_manifest="$tmp/shared-manifest.json"
  mkdir -p "$fake_bin"

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/known_hosts"
  cat >"$tmp/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://preview
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  printf 'backup' >"$tmp/dkg-backup.zip"
  cat >"$shared_manifest" <<JSON
{
  "shared_services": {
    "artifacts": {
      "checkpoint_blob_bucket": "preview-op1-dkg-keypackages"
    }
  },
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid"
  }
}
JSON

  cat >"$manifest" <<JSON
{
  "environment": "preview",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "operator_host": "203.0.113.11",
  "operator_user": "intents-juno",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "shared_manifest_path": "$shared_manifest",
  "checkpoint_signer_driver": "aws-kms",
  "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555",
  "dkg_backup_zip": "$tmp/dkg-backup.zip",
  "known_hosts_file": "$tmp/known_hosts",
  "secret_contract_file": "$tmp/operator-secrets.env"
}
JSON

  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_file"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^CHECKPOINT_SIGNER_DRIVER=aws-kms$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY='"* ]]; then
  exit 1
fi
if [[ "\$*" == *"test -e /var/lib/intents-juno/operator-runtime/exports/kms-export-receipt.json"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -q '^WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/juno-txsign$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"grep -qE '^JUNO_TXSIGN_SIGNER_KEYS=0x[0-9a-fA-F]{64}\$'"* ]]; then
  exit 0
fi
if [[ "\$*" == *"/var/lib/intents-juno/operator-runtime/bin/juno-txsign --help"* ]]; then
  printf 'Usage: juno-txsign sign-digest [flags]\n'
  exit 0
fi
if [[ "\$*" == *"curl -fsS http://127.0.0.1:\${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz"* ]]; then
  exit 0
fi
exit 0
EOF
  write_fake_cast "$fake_bin/cast" "$tmp/cast.log" "1300000000000000"
  chmod 0755 "$fake_bin/ssh"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-operator-boot.sh \
      --operator-deploy "$manifest" >"$output_json"
  )

  assert_contains "$(cat "$log_file")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "preview canary verifies kms checkpoint signer mode"
  assert_contains "$(cat "$log_file")" "test -e /var/lib/intents-juno/operator-runtime/exports/kms-export-receipt.json" "preview canary verifies kms export receipt"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "preview canary ready flag"
  assert_eq "$(jq -r '.checks.kms_export.status' "$output_json")" "passed" "preview canary requires kms export checks"

  rm -rf "$tmp"
}

main() {
  test_operator_boot_canary_checks_services_over_strict_ssh
  test_operator_boot_canary_rejects_underfunded_relayer
  test_operator_boot_canary_preserves_secure_preview_signer_configuration
}

main "$@"
