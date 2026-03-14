#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

write_local_sha256_file() {
  local input="$1"
  local output="$2"
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$input" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$input" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$(basename "$input")" >"$output"
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
    --arg operator_address "0x9999999999999999999999999999999999999999" \
    --arg app_host "203.0.113.21" \
    --arg app_public_endpoint "203.0.113.21" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
      | .operators[0].operator_address = $operator_address
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
      | .app_host.host = $app_host
      | .app_host.public_endpoint = $app_public_endpoint
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_package_mainnet_release_renders_self_contained_operator_bundle() {
  local workdir handoff_dir release_dir shared_manifest bundle_zip extract_dir
  local operator_id operator_slug bundle_root deploy_log cast_log fake_bin local_manifest

  workdir="$(mktemp -d)"
  handoff_dir="$workdir/output/alpha"
  release_dir="$workdir/release"
  operator_id="0x1111111111111111111111111111111111111111"
  operator_slug="$(production_safe_slug "$operator_id")"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  mkdir -p "$handoff_dir"
  shared_manifest="$handoff_dir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$handoff_dir" "$workdir"

  bash "$REPO_ROOT/deploy/production/package-mainnet-release.sh" \
    --handoff-dir "$handoff_dir" \
    --release-tag "v1.2.3-mainnet" \
    --output-dir "$release_dir"

  assert_file_exists "$release_dir/mainnet-release-manifest.json" "release manifest"
  assert_file_exists "$release_dir/mainnet-release-manifest.sha256" "release manifest checksum"
  assert_eq "$(jq -r '.release_tag' "$release_dir/mainnet-release-manifest.json")" "v1.2.3-mainnet" "release tag recorded"
  assert_eq "$(jq -r '.operators[0].bundle_name' "$release_dir/mainnet-release-manifest.json")" "operator-bundle-${operator_slug}.zip" "bundle name recorded"

  bundle_zip="$release_dir/operator-bundle-${operator_slug}.zip"
  assert_file_exists "$bundle_zip" "operator bundle zip"
  assert_file_exists "$release_dir/operator-bundle-${operator_slug}.zip.sha256" "operator bundle checksum"

  extract_dir="$workdir/extract"
  unzip -q "$bundle_zip" -d "$extract_dir"
  bundle_root="$extract_dir/$operator_slug"
  assert_file_exists "$bundle_root/mainnet-release-manifest.json" "bundled release manifest"
  assert_file_exists "$bundle_root/deploy/production/deploy-operator.sh" "bundled deploy script"
  assert_file_exists "$bundle_root/deploy/production/canary-operator-boot.sh" "bundled canary script"
  assert_file_exists "$bundle_root/deploy/operators/dkg/backup-package.sh" "bundled dkg restore script"
  assert_file_exists "$bundle_root/deploy/operators/dkg/operator-export-kms.sh" "bundled dkg kms export script"
  assert_file_exists "$bundle_root/bundle/operator/shared-manifest.json" "bundled shared manifest"
  assert_file_exists "$bundle_root/bundle/operator/rollout-state.json" "bundled rollout state"
  assert_file_exists "$bundle_root/bundle/operator/operators/$operator_id/operator-deploy.json" "bundled local operator manifest"
  assert_file_exists "$bundle_root/bundle/operator/operators/$operator_id/known_hosts" "bundled known_hosts"
  assert_file_exists "$bundle_root/bundle/operator/operators/$operator_id/operator-secrets.env" "bundled operator secrets"
  assert_file_exists "$bundle_root/bundle/operator/operators/$operator_id/dkg-backup.zip" "bundled dkg backup"
  assert_file_exists "$bundle_root/bundle/operator/deploy-mainnet-operator.sh" "bundled one-click deploy wrapper"
  assert_file_exists "$bundle_root/bundle/operator/deployment-report.json" "bundled deployment report"
  assert_file_exists "$bundle_root/bundle/operator/canary-result.json" "bundled canary report"

  local_manifest="$bundle_root/bundle/operator/operators/$operator_id/operator-deploy.json"
  assert_eq "$(jq -r '.shared_manifest_path' "$local_manifest")" "../../shared-manifest.json" "local manifest rewrites shared manifest path"
  assert_eq "$(jq -r '.rollout_state_file' "$local_manifest")" "../../rollout-state.json" "local manifest rewrites rollout state path"
  assert_eq "$(jq -r '.secret_contract_file' "$local_manifest")" "./operator-secrets.env" "local manifest rewrites secret contract path"
  assert_eq "$(jq -r '.dkg_backup_zip' "$local_manifest")" "./dkg-backup.zip" "local manifest rewrites backup path"

  deploy_log="$workdir/deploy.log"
  cat >"$bundle_root/deploy/production/deploy-operator.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$deploy_log"
exit 0
EOF
  cat >"$bundle_root/deploy/production/canary-operator-boot.sh" <<'EOF'
#!/usr/bin/env bash
cat <<'JSON'
{"ready_for_deploy":true,"checks":{"systemd":{"status":"passed"}}}
JSON
EOF
  chmod 0755 "$bundle_root/deploy/production/deploy-operator.sh" "$bundle_root/deploy/production/canary-operator-boot.sh"

  fake_bin="$workdir/bin"
  cast_log="$workdir/cast.log"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '021490342184\n'
  exit 0
fi
if [[ "$*" == *"kms describe-key"* ]]; then
  printf 'arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555\n'
  exit 0
fi
printf 'unexpected aws invocation: %s\n' "$*" >&2
exit 1
EOF
  cat >"$fake_bin/cast" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'cast %s\n' "\$*" >>"$cast_log"
if [[ "\$1" == "call" && "\$5" == "isOperator(address)(bool)" ]]; then
  printf 'true\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod 0755 "$fake_bin/aws"
  chmod 0755 "$fake_bin/cast"

  PATH="$fake_bin:$PATH" "$bundle_root/bundle/operator/deploy-mainnet-operator.sh" --dry-run

  assert_contains "$(cat "$cast_log")" "call --rpc-url https://base-sepolia.example.invalid 0x4444444444444444444444444444444444444444 isOperator(address)(bool) 0x9999999999999999999999999999999999999999" "bundle wrapper validates operator registry membership"
  assert_contains "$(cat "$deploy_log")" "--operator-deploy" "deploy wrapper forwards operator manifest"
  assert_eq "$(jq -r '.status' "$bundle_root/bundle/operator/deployment-report.json")" "ready" "deployment report records success"
  assert_eq "$(jq -r '.ready_for_deploy' "$bundle_root/bundle/operator/canary-result.json")" "true" "canary result persisted"

  rm -rf "$workdir"
}

test_bundle_wrapper_rejects_release_manifest_identity_mismatch() {
  local workdir handoff_dir release_dir shared_manifest bundle_zip extract_dir
  local operator_id operator_slug bundle_root cast_log fake_bin

  workdir="$(mktemp -d)"
  handoff_dir="$workdir/output/alpha"
  release_dir="$workdir/release"
  operator_id="0x1111111111111111111111111111111111111111"
  operator_slug="$(production_safe_slug "$operator_id")"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  mkdir -p "$handoff_dir"
  shared_manifest="$handoff_dir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$handoff_dir" "$workdir"

  bash "$REPO_ROOT/deploy/production/package-mainnet-release.sh" \
    --handoff-dir "$handoff_dir" \
    --release-tag "v1.2.3-mainnet" \
    --output-dir "$release_dir"

  bundle_zip="$release_dir/operator-bundle-${operator_slug}.zip"
  extract_dir="$workdir/extract"
  unzip -q "$bundle_zip" -d "$extract_dir"
  bundle_root="$extract_dir/$operator_slug"

  cat >"$bundle_root/deploy/production/deploy-operator.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$bundle_root/deploy/production/canary-operator-boot.sh" <<'EOF'
#!/usr/bin/env bash
cat <<'JSON'
{"ready_for_deploy":true}
JSON
EOF
  chmod 0755 "$bundle_root/deploy/production/deploy-operator.sh" "$bundle_root/deploy/production/canary-operator-boot.sh"

  fake_bin="$workdir/bin"
  cast_log="$workdir/cast.log"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '021490342184\n'
  exit 0
fi
if [[ "$*" == *"kms describe-key"* ]]; then
  printf 'arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555\n'
  exit 0
fi
printf 'unexpected aws invocation: %s\n' "$*" >&2
exit 1
EOF
  cat >"$fake_bin/cast" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'cast %s\n' "\$*" >>"$cast_log"
if [[ "\$1" == "call" && "\$5" == "isOperator(address)(bool)" ]]; then
  printf 'true\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod 0755 "$fake_bin/aws" "$fake_bin/cast"

  jq '(.operators[] | select(.operator_id == "0x1111111111111111111111111111111111111111")).account_id = "999999999999"' \
    "$bundle_root/mainnet-release-manifest.json" >"$bundle_root/mainnet-release-manifest.json.tmp"
  mv "$bundle_root/mainnet-release-manifest.json.tmp" "$bundle_root/mainnet-release-manifest.json"
  write_local_sha256_file "$bundle_root/mainnet-release-manifest.json" "$bundle_root/mainnet-release-manifest.sha256"

  if PATH="$fake_bin:$PATH" "$bundle_root/bundle/operator/deploy-mainnet-operator.sh" --dry-run; then
    fail "expected wrapper to reject release manifest account mismatch"
  fi

  assert_eq "$(jq -r '.status' "$bundle_root/bundle/operator/deployment-report.json")" "release_manifest_account_mismatch" "report records release manifest account mismatch"
  if [[ -f "$cast_log" ]]; then
    assert_eq "$(wc -c <"$cast_log" | tr -d ' ')" "0" "wrapper stops before operator registry call on release manifest mismatch"
  fi

  rm -rf "$workdir"
}

main() {
  test_package_mainnet_release_renders_self_contained_operator_bundle
  test_bundle_wrapper_rejects_release_manifest_identity_mismatch
}

main "$@"
