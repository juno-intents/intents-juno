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
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
EOF
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
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssh.log"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >/dev/null || true
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
  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/known_hosts" "ssh uses known_hosts file"
  assert_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "dns publish"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

main() {
  test_deploy_operator_enforces_known_hosts_and_updates_rollout
}

main "$@"
