#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

test_operator_boot_canary_checks_services_over_strict_ssh() {
  local tmp fake_bin log_file manifest output_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  log_file="$tmp/ssh.log"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin"

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/known_hosts"
  printf 'CHECKPOINT_POSTGRES_DSN=env:CHECKPOINT_POSTGRES_DSN\n' >"$tmp/operator-secrets.env"
  printf 'backup' >"$tmp/dkg-backup.zip"

  cat >"$manifest" <<JSON
{
  "environment": "alpha",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "operator_host": "203.0.113.11",
  "operator_user": "intents-juno",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
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
fi
exit 0
EOF
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
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "operator canary ready flag"
  assert_eq "$(jq -r '.checks.systemd.status' "$output_json")" "passed" "operator canary systemd status"

  rm -rf "$tmp"
}

main() {
  test_operator_boot_canary_checks_services_over_strict_ssh
}

main "$@"
