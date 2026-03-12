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

test_canary_app_host_checks_remote_services_and_http_endpoints() {
  local workdir fake_bin log_dir shared_manifest app_manifest output_json
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
  http://203.0.113.21:8082/readyz|http://203.0.113.21:8090/readyz)
    printf '{"status":"ok"}\n'
    ;;
  http://203.0.113.21:8082/v1/config)
    printf '{"version":"v1","bridgeAddress":"0x2222222222222222222222222222222222222222","oWalletUA":"u1alphaexample"}\n'
    ;;
  http://203.0.113.21:8082/)
    printf '<!doctype html><html><body>Bridge UI</body></html>\n'
    ;;
  http://203.0.113.21:8090/)
    printf '<!doctype html><html><body>JUNO BACKOFFICE</body></html>\n'
    ;;
  *)
    exit 1
    ;;
esac
EOF
  chmod +x "$fake_bin/ssh" "$fake_bin/curl"

  TEST_LOG_DIR="$log_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/canary-app-host.sh" \
      --app-deploy "$app_manifest" >"$output_json"

  assert_contains "$(cat "$log_dir/ssh.log")" "UserKnownHostsFile=$workdir/output/app/known_hosts" "canary uses known_hosts file"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active bridge-api" "bridge systemd checked"
  assert_contains "$(cat "$log_dir/ssh.log")" "systemctl is-active backoffice" "backoffice systemd checked"
  assert_contains "$(cat "$log_dir/curl.log")" "http://203.0.113.21:8082/v1/config" "bridge config checked"
  assert_contains "$(cat "$log_dir/curl.log")" "http://203.0.113.21:8090/" "backoffice ui checked"
  assert_eq "$(jq -r '.ready_for_test' "$output_json")" "true" "app canary ready for test"
  assert_eq "$(jq -r '.checks.bridge_config.status' "$output_json")" "passed" "bridge config passed"
  assert_eq "$(jq -r '.checks.backoffice_ui.status' "$output_json")" "passed" "backoffice ui passed"
  rm -rf "$workdir"
}

main() {
  test_canary_app_host_checks_remote_services_and_http_endpoints
}

main "$@"
