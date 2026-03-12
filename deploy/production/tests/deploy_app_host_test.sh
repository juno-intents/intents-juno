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

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
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
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_contains "$(cat "$log_dir/gh.log")" "release download $release_tag" "gh release download"
  assert_contains "$(cat "$log_dir/gh.log")" "bridge-api_linux_amd64" "bridge asset download"
  assert_contains "$(cat "$log_dir/gh.log")" "backoffice_linux_amd64" "backoffice asset download"
  assert_contains "$(cat "$log_dir/scp.log")" "StrictHostKeyChecking=yes" "scp strict host key checking"
  assert_contains "$(cat "$log_dir/scp.log")" "bridge-api.env" "bridge env copied"
  assert_contains "$(cat "$log_dir/scp.log")" "backoffice.env" "backoffice env copied"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'bridge_api_wrapper="/usr/local/bin/intents-juno-bridge-api.sh"' "remote bridge wrapper path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'backoffice_wrapper="/usr/local/bin/intents-juno-backoffice.sh"' "remote backoffice wrapper path"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'EnvironmentFile=/etc/intents-juno/bridge-api.env' "bridge unit uses env file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'EnvironmentFile=/etc/intents-juno/backoffice.env' "backoffice unit uses env file"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'sudo apt-get install -y caddy' "remote installs caddy when https is enabled"
  assert_contains "$(cat "$log_dir/ssh.stdin")" '/etc/caddy/Caddyfile' "remote writes caddyfile"
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
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_AUTH_SECRET=backoffice-token" "backoffice env auth secret"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_OPERATOR_ADDRESSES=0x9999999999999999999999999999999999999999" "backoffice env operator addresses"
  assert_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_URL=http://127.0.0.1:18232" "backoffice env juno rpc url"
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
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  printf 'bridge-api-binary\n' >"$assets_dir/bridge-api_linux_amd64"
  printf 'backoffice-binary\n' >"$assets_dir/backoffice_linux_amd64"
  (
    cd "$assets_dir"
    sha256sum bridge-api_linux_amd64 >bridge-api_linux_amd64.sha256
    sha256sum backoffice_linux_amd64 >backoffice_linux_amd64.sha256
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
  chmod +x "$fake_bin/gh" "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  TEST_LOG_DIR="$log_dir" TEST_ASSETS_DIR="$assets_dir" PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-app-host.sh" \
      --app-deploy "$app_manifest" \
      --release-tag "$release_tag" >/dev/null

  assert_not_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_URL=" "backoffice env omits juno rpc url"
  assert_not_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_USER=" "backoffice env omits juno rpc user"
  assert_not_contains "$(cat "$log_dir/backoffice.env")" "BACKOFFICE_JUNO_RPC_PASS=" "backoffice env omits juno rpc pass"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_URL:-}" ]]; then' "backoffice wrapper guards juno rpc flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_USER:-}" ]]; then' "backoffice wrapper guards juno rpc user flag"
  assert_contains "$(cat "$log_dir/ssh.stdin")" 'if [[ -n "${BACKOFFICE_JUNO_RPC_PASS:-}" ]]; then' "backoffice wrapper guards juno rpc pass flag"
  rm -rf "$workdir"
}

test_deploy_app_host_rejects_non_https_manifest() {
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

  if (
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

  if (
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
  test_deploy_app_host_rejects_non_https_manifest
  test_deploy_app_host_rejects_non_loopback_listeners
}

main "$@"
