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

test_resolve_secret_contract_allows_alpha_literals() {
  local workdir inventory resolved file_secret
  workdir="$(mktemp -d)"
  file_secret="$workdir/secret.txt"
  printf 'from-file' >"$file_secret"
  export TEST_ENV_SECRET="from-env"
  cat >"$workdir/operator-secrets.env" <<EOF
JUNO_RPC_USER=literal:testuser
JUNO_RPC_PASS=file:$file_secret
JUNO_SCAN_BEARER_TOKEN=env:TEST_ENV_SECRET
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  resolved="$workdir/resolved.env"
  production_resolve_secret_contract "$workdir/operator-secrets.env" "true" "" "" "$resolved"
  assert_contains "$(cat "$resolved")" "JUNO_RPC_USER=testuser" "literal resolver"
  assert_contains "$(cat "$resolved")" "JUNO_RPC_PASS=from-file" "file resolver"
  assert_contains "$(cat "$resolved")" "JUNO_SCAN_BEARER_TOKEN=from-env" "env resolver"
  rm -rf "$workdir"
}

test_resolve_secret_contract_rejects_literals_outside_alpha() {
  local workdir
  workdir="$(mktemp -d)"
  cat >"$workdir/operator-secrets.env" <<'EOF'
JUNO_RPC_USER=literal:testuser
EOF
  if (production_resolve_secret_contract "$workdir/operator-secrets.env" "false" "" "" "$workdir/resolved.env") >/dev/null 2>&1; then
    printf 'expected production_resolve_secret_contract to reject literal resolver outside alpha\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_and_handoffs() {
  local workdir inventory shared_manifest handoff_dir
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  printf 'secret' >"$workdir/secret.txt"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  assert_eq "$(jq -r '.contracts.bridge' "$shared_manifest")" "0x2222222222222222222222222222222222222222" "bridge address"
  assert_eq "$(jq -r '.checkpoint.threshold' "$shared_manifest")" "3" "checkpoint threshold"
  assert_contains "$(jq -cr '.secret_reference_names' "$shared_manifest")" "CHECKPOINT_POSTGRES_DSN" "secret keys"
  assert_eq "$(jq -r '.governance.timelock.address' "$shared_manifest")" "0x8888888888888888888888888888888888888888" "timelock address"
  assert_eq "$(jq -r '.governance.timelock.min_delay_seconds' "$shared_manifest")" "0" "timelock delay"

  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_file_exists "$handoff_dir/operator-deploy.json" "operator manifest"
  assert_file_exists "$handoff_dir/operator-secrets.env" "secret contract copy"
  assert_file_exists "$handoff_dir/known_hosts" "known_hosts copy"
  assert_eq "$(jq -r '.operator_address' "$handoff_dir/operator-deploy.json")" "0x9999999999999999999999999999999999999999" "handoff operator address"
  assert_eq "$(jq -r '.checkpoint_signer_driver' "$handoff_dir/operator-deploy.json")" "aws-kms" "handoff signer driver"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$handoff_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "handoff signer kms key id"
  assert_eq "$(jq -r '.current_operator_id // ""' "$workdir/output/rollout-state.json")" "" "initial rollout state"
  rm -rf "$workdir"
}

test_render_shared_manifest_prefers_inventory_owallet_ua() {
  local workdir shared_manifest bridge_summary_no_ua
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  bridge_summary_no_ua="$workdir/bridge-summary-no-ua.json"
  jq 'del(.owallet_ua)' "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" >"$bridge_summary_no_ua"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$bridge_summary_no_ua" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"

  assert_eq "$(jq -r '.contracts.owallet_ua' "$shared_manifest")" "u1alphaexample" "inventory owallet ua fallback"
  rm -rf "$workdir"
}

test_render_operator_stack_env_uses_kms_contract() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "rendered env signer driver"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "rendered env signer kms key id"
  assert_contains "$(cat "$output_env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "rendered env operator address"
  assert_contains "$(cat "$output_env")" "AWS_REGION=us-east-1" "rendered env aws region"
  assert_contains "$(cat "$output_env")" "AWS_DEFAULT_REGION=us-east-1" "rendered env aws default region"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_USER=juno" "rendered env juno rpc user"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_PASS=rpcpass" "rendered env juno rpc pass"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "rendered env withdraw coordinator juno rpc url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443" "rendered env withdraw coordinator tss url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem" "rendered env withdraw coordinator tss ca"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.pem" "rendered env withdraw coordinator client cert"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.key" "rendered env withdraw coordinator client key"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin" "rendered env withdraw coordinator extend signer"
  assert_contains "$(cat "$output_env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "rendered env withdraw finalizer scan url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_FINALIZER_JUNO_RPC_URL=http://127.0.0.1:18232" "rendered env withdraw finalizer juno rpc url"
  assert_contains "$(cat "$output_env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "rendered env tss ufvk path"
  assert_contains "$(cat "$output_env")" "TSS_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin" "rendered env tss spendauth signer path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-attested-signer" "rendered env tss nitro signer path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ENCLAVE_EIF_FILE=/var/lib/intents-juno/operator-runtime/enclave/spendauth-signer.eif" "rendered env tss enclave path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ENCLAVE_CID=16" "rendered env tss enclave cid"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ATTESTATION_FILE=/var/lib/intents-juno/operator-runtime/attestation/spendauth-attestation.json" "rendered env tss attestation path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ATTESTATION_MAX_AGE_SECONDS=300" "rendered env tss attestation max age"
  assert_contains "$(cat "$output_env")" "TSS_SIGNER_WORK_DIR=/var/lib/intents-juno/tss-signer" "rendered env tss work dir"
  assert_contains "$(cat "$output_env")" "TSS_LISTEN_ADDR=127.0.0.1:9443" "rendered env tss listen addr"
  assert_contains "$(cat "$output_env")" "TSS_TLS_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.pem" "rendered env tss cert path"
  assert_contains "$(cat "$output_env")" "TSS_TLS_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.key" "rendered env tss key path"
  assert_contains "$(cat "$output_env")" "TSS_CLIENT_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem" "rendered env tss client ca"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "rendered env omits private key for kms signer"
  rm -rf "$workdir"
}

test_render_operator_stack_env_requires_juno_rpc_credentials() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to require JUNO_RPC_USER/JUNO_RPC_PASS\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_stack_env_rejects_private_key_with_kms_contract() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
CHECKPOINT_SIGNER_PRIVATE_KEY=literal:0xdeadbeef
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to reject CHECKPOINT_SIGNER_PRIVATE_KEY for aws-kms\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_junocashd_conf_uses_juno_rpc_credentials() {
  local workdir env_file output_conf
  workdir="$(mktemp -d)"
  env_file="$workdir/operator-stack.env"
  output_conf="$workdir/junocashd.conf"

  cat >"$env_file" <<'EOF'
JUNO_RPC_USER=juno
JUNO_RPC_PASS=rpcpass
EOF

  production_render_junocashd_conf "$env_file" "$output_conf"

  assert_contains "$(cat "$output_conf")" "rpcbind=127.0.0.1" "junocashd conf rpc bind"
  assert_contains "$(cat "$output_conf")" "rpcport=18232" "junocashd conf rpc port"
  assert_contains "$(cat "$output_conf")" "rpcuser=juno" "junocashd conf rpc user"
  assert_contains "$(cat "$output_conf")" "rpcpassword=rpcpass" "junocashd conf rpc password"
  rm -rf "$workdir"
}

test_rollout_state_enforces_one_operator_at_a_time() {
  local workdir inventory
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.operators += [{"index":2,"operator_id":"0x6666666666666666666666666666666666666666","aws_profile":"juno","aws_region":"us-east-1","account_id":"021490342184","operator_host":"203.0.113.12","operator_user":"ubuntu","runtime_dir":"/var/lib/intents-juno/operator-runtime","public_dns_label":"op2","public_endpoint":"203.0.113.12","known_hosts_file":"known_hosts","dkg_backup_zip":"dkg-backup.zip","secret_contract_file":"operator-secrets.env"}]' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_write_rollout_state "$workdir/inventory.json" "$workdir/rollout-state.json"
  production_rollout_reserve "$workdir/rollout-state.json" "0x1111111111111111111111111111111111111111"
  if (production_rollout_reserve "$workdir/rollout-state.json" "0x6666666666666666666666666666666666666666") >/dev/null 2>&1; then
    printf 'expected rollout reserve to fail while another operator is in progress\n' >&2
    exit 1
  fi
  production_rollout_complete "$workdir/rollout-state.json" "0x1111111111111111111111111111111111111111" "done" "healthy"
  production_rollout_reserve "$workdir/rollout-state.json" "0x6666666666666666666666666666666666666666"
  assert_eq "$(jq -r '.current_operator_id' "$workdir/rollout-state.json")" "0x6666666666666666666666666666666666666666" "second operator reserved"
  rm -rf "$workdir"
}

test_render_app_handoff_and_envs() {
  local workdir shared_manifest app_manifest resolved_env bridge_env backoffice_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
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

  assert_file_exists "$app_manifest" "app deploy manifest"
  assert_eq "$(jq -r '.public_scheme' "$app_manifest")" "https" "public scheme"
  assert_eq "$(jq -r '.services.bridge_api.public_url' "$app_manifest")" "https://bridge.alpha.intents-testing.thejunowallet.com" "bridge public url"
  assert_eq "$(jq -r '.services.bridge_api.probe_url' "$app_manifest")" "https://bridge.alpha.intents-testing.thejunowallet.com" "bridge probe url"
  assert_eq "$(jq -r '.services.bridge_api.internal_url' "$app_manifest")" "http://127.0.0.1:8082" "bridge internal url"
  assert_eq "$(jq -r '.services.backoffice.public_url' "$app_manifest")" "https://ops.alpha.intents-testing.thejunowallet.com" "backoffice public url"
  assert_eq "$(jq -r '.security_group_id' "$app_manifest")" "sg-0123456789abcdef0" "security group id"
  assert_contains "$(jq -cr '.operator_addresses' "$app_manifest")" "0x9999999999999999999999999999999999999999" "operator addresses"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$workdir/app-secrets.env" "true" "" "" "$resolved_env"
  bridge_env="$workdir/bridge-api.env"
  backoffice_env="$workdir/backoffice.env"
  production_render_bridge_api_env "$shared_manifest" "$app_manifest" "$resolved_env" "$bridge_env"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"

  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_POSTGRES_DSN=postgres://alpha" "bridge env postgres dsn"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_OWALLET_UA=u1alphaexample" "bridge env owallet ua"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_WJUNO_ADDRESS=0x3333333333333333333333333333333333333333" "bridge env wjuno"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_AUTH_SECRET=backoffice-token" "backoffice env auth secret"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_OPERATOR_ADDRESSES=0x9999999999999999999999999999999999999999" "backoffice env operator addresses"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env juno rpc user"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_SERVICE_URLS=bridge-api=http://127.0.0.1:8082/readyz" "backoffice env service urls"
  rm -rf "$workdir"
}

main() {
  test_resolve_secret_contract_allows_alpha_literals
  test_resolve_secret_contract_rejects_literals_outside_alpha
  test_render_shared_manifest_and_handoffs
  test_render_shared_manifest_prefers_inventory_owallet_ua
  test_render_operator_stack_env_uses_kms_contract
  test_render_operator_stack_env_requires_juno_rpc_credentials
  test_render_operator_stack_env_rejects_private_key_with_kms_contract
  test_render_junocashd_conf_uses_juno_rpc_credentials
  test_rollout_state_enforces_one_operator_at_a_time
  test_render_app_handoff_and_envs
}

main "$@"
