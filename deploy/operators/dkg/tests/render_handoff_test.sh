#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_file_exists() {
  local path="$1"
  local msg="$2"
  if [[ ! -f "$path" ]]; then
    printf 'assert_file_exists failed: %s: missing=%s\n' "$msg" "$path" >&2
    exit 1
  fi
}

build_fixture_backup_zip() {
  local tmp="$1"
  local runtime="$tmp/runtime"
  local output="$tmp/operator-backup.zip"

  mkdir -p "$runtime/bundle/tls" "$tmp/backup" "$tmp/exports"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {"roster_version":1, "operators":[]},
  "state_dir": "./state",
  "grpc": {
    "listen_addr": "0.0.0.0:18443",
    "tls_ca_cert_pem_path": "./tls/ca.pem",
    "tls_server_cert_pem_path": "./tls/server.pem",
    "tls_server_key_pem_path": "./tls/server.key"
  }
}
JSON

  printf 'FAKE-CA\n' >"$runtime/bundle/tls/ca.pem"
  printf 'FAKE-SERVER\n' >"$runtime/bundle/tls/server.pem"
  printf 'FAKE-KEY\n' >"$runtime/bundle/tls/server.key"
  chmod 0600 "$runtime/bundle/tls/server.key"

  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$tmp/backup/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$tmp/exports/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$tmp/exports/keypackage-backup.json.KeyImportReceipt.json"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --output "$output"
  )

  printf '%s\n' "$output"
}

write_fake_age() {
  local bin_dir="$1"
  mkdir -p "$bin_dir"
  cat >"$bin_dir/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--decrypt" ]]; then
  cat <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "key_package_bytes_b64": "a3BieXRlcw==",
  "public_key_package_bytes_b64": "cGtwYnl0ZXM="
}
JSON
  exit 0
fi

recipient=""
output=""
input=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r)
      recipient="$2"
      shift 2
      ;;
    -o)
      output="$2"
      shift 2
      ;;
    *)
      input="$1"
      shift
      ;;
  esac
done
[[ -n "$recipient" ]] || exit 1
[[ -n "$output" ]] || exit 1
printf 'age recipient=%s input=%s\n' "$recipient" "$input" >"$output"
EOF
  chmod 0755 "$bin_dir/age"
}

test_render_handoff_bundle_renders_operator_deploy_and_placeholder_inputs() {
  local tmp backup_zip inventory shared_manifest dkg_summary output_dir rollout_state_file
  tmp="$(mktemp -d)"
  backup_zip="$(build_fixture_backup_zip "$tmp")"
  inventory="$tmp/deployment-inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  dkg_summary="$tmp/dkg-summary.json"
  output_dir="$tmp/handoff"
  rollout_state_file="$tmp/rollout-state.json"

  cat >"$inventory" <<'JSON'
{
  "environment": "alpha",
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "aws_profile": "juno",
      "aws_region": "us-east-1",
      "account_id": "021490342184",
      "operator_host": "203.0.113.11",
      "operator_user": "ubuntu",
      "runtime_dir": "/var/lib/intents-juno/operator-runtime",
      "public_dns_label": "op1",
      "public_endpoint": "203.0.113.11"
    }
  ],
  "dns": {
    "mode": "public-zone",
    "ttl_seconds": 60
  }
}
JSON

  cat >"$shared_manifest" <<'JSON'
{
  "version": "1",
  "environment": "alpha"
}
JSON

  cat >"$dkg_summary" <<JSON
{
  "summary_version": 1,
  "network": "testnet",
  "threshold": 3,
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "backup_package": "$backup_zip",
      "restore_report": "$tmp/restore-report.json",
      "status": {
        "running": true
      }
    }
  ]
}
JSON

  cat >"$tmp/restore-report.json" <<'JSON'
{
  "report_version": 1,
  "operator_id": "0x1111111111111111111111111111111111111111",
  "restore_status": "passed"
}
JSON

  (
    cd "$REPO_ROOT"
    bash deploy/operators/dkg/render-handoff.sh \
      --inventory "$inventory" \
      --dkg-summary "$dkg_summary" \
      --shared-manifest-path "$shared_manifest" \
      --rollout-state-file "$rollout_state_file" \
      --output-dir "$output_dir"
  )

  local bundle_dir deploy_json manifest_json validation_json
  bundle_dir="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111"
  deploy_json="$bundle_dir/operator-deploy.json"
  manifest_json="$output_dir/alpha/handoff-manifest.json"
  validation_json="$bundle_dir/handoff-validation.json"

  assert_file_exists "$bundle_dir/dkg-backup.zip" "handoff backup zip"
  assert_file_exists "$deploy_json" "operator deploy manifest"
  assert_file_exists "$manifest_json" "handoff manifest"
  assert_file_exists "$validation_json" "handoff validation report"
  assert_file_exists "$bundle_dir/known_hosts" "placeholder known_hosts"
  assert_file_exists "$bundle_dir/operator-secrets.env" "placeholder secret contract"

  assert_eq "$(jq -r '.operator_id' "$deploy_json")" \
    "0x1111111111111111111111111111111111111111" \
    "operator-deploy operator id"
  assert_eq "$(jq -r '.dkg_backup_zip' "$deploy_json")" \
    "operators/0x1111111111111111111111111111111111111111/dkg-backup.zip" \
    "operator-deploy backup path"
  assert_eq "$(jq -r '.known_hosts_file' "$deploy_json")" \
    "operators/0x1111111111111111111111111111111111111111/known_hosts" \
    "operator-deploy known_hosts path"
  assert_eq "$(jq -r '.secret_contract_file' "$deploy_json")" \
    "operators/0x1111111111111111111111111111111111111111/operator-secrets.env" \
    "operator-deploy secret contract path"
  assert_eq "$(jq -r '.rollout_state_file' "$deploy_json")" \
    "$rollout_state_file" \
    "operator-deploy rollout state path"
  assert_eq "$(jq -r '.dns.record_name' "$deploy_json")" \
    "op1.alpha" \
    "operator-deploy dns record name"
  assert_eq "$(jq -r '.ready_for_deploy' "$validation_json")" \
    "false" \
    "placeholder inputs keep handoff not-ready"
  assert_eq "$(jq -r '.operators[0].ready_for_deploy' "$manifest_json")" \
    "false" \
    "manifest records not-ready handoff"
  assert_eq "$(jq -r '.operators[0].restore_validation.status' "$manifest_json")" \
    "skipped" \
    "render without validation records skipped restore validation"

  rm -rf "$tmp"
}

test_render_handoff_validate_restores_backup_and_marks_bundle_ready() {
  local tmp backup_zip inventory shared_manifest dkg_summary output_dir fake_bin
  tmp="$(mktemp -d)"
  backup_zip="$(build_fixture_backup_zip "$tmp")"
  inventory="$tmp/deployment-inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  dkg_summary="$tmp/dkg-summary.json"
  output_dir="$tmp/handoff"
  fake_bin="$tmp/fake-bin"

  write_fake_age "$fake_bin"

  cat >"$inventory" <<JSON
{
  "environment": "alpha",
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "aws_profile": "juno",
      "aws_region": "us-east-1",
      "account_id": "021490342184",
      "operator_host": "203.0.113.11",
      "operator_user": "ubuntu",
      "runtime_dir": "/var/lib/intents-juno/operator-runtime",
      "public_dns_label": "op1",
      "public_endpoint": "203.0.113.11",
      "known_hosts_file": "$tmp/source-known_hosts",
      "secret_contract_file": "$tmp/source-operator-secrets.env"
    }
  ],
  "dns": {
    "mode": "public-zone",
    "ttl_seconds": 60
  }
}
JSON

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/source-known_hosts"
  cat >"$tmp/source-operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=aws-sm://arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha/checkpoint-postgres
BASE_RELAYER_AUTH_TOKEN=env:BASE_RELAYER_AUTH_TOKEN
EOF

  cat >"$shared_manifest" <<'JSON'
{
  "version": "1",
  "environment": "alpha"
}
JSON

  cat >"$dkg_summary" <<JSON
{
  "summary_version": 1,
  "network": "testnet",
  "threshold": 3,
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "backup_package": "$backup_zip",
      "restore_report": "$tmp/restore-report.json",
      "status": {
        "running": true
      }
    }
  ]
}
JSON

  cat >"$tmp/restore-report.json" <<'JSON'
{
  "report_version": 1,
  "operator_id": "0x1111111111111111111111111111111111111111",
  "restore_status": "passed"
}
JSON

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/operators/dkg/render-handoff.sh \
      --inventory "$inventory" \
      --dkg-summary "$dkg_summary" \
      --shared-manifest-path "$shared_manifest" \
      --output-dir "$output_dir" \
      --validate
  )

  local manifest_json validation_json validation_output
  manifest_json="$output_dir/alpha/handoff-manifest.json"
  validation_json="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/handoff-validation.json"

  assert_file_exists "$validation_json" "validation report"
  assert_eq "$(jq -r '.restore_validation.status' "$validation_json")" \
    "passed" \
    "restore validation status"
  assert_eq "$(jq -r '.ready_for_deploy' "$validation_json")" \
    "true" \
    "bundle ready flag"
  assert_eq "$(jq -r '.operators[0].ready_for_deploy' "$manifest_json")" \
    "true" \
    "manifest ready flag"

  validation_output="$(
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/operators/dkg/render-handoff.sh validate \
      --handoff-manifest "$manifest_json"
  )"
  assert_contains "$validation_output" '"ready_for_deploy": true' "validate command prints ready bundle summary"

  rm -rf "$tmp"
}

test_render_handoff_age_secret_mode_writes_encrypted_contract() {
  local tmp backup_zip inventory shared_manifest dkg_summary output_dir fake_bin
  tmp="$(mktemp -d)"
  backup_zip="$(build_fixture_backup_zip "$tmp")"
  inventory="$tmp/deployment-inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  dkg_summary="$tmp/dkg-summary.json"
  output_dir="$tmp/handoff"
  fake_bin="$tmp/fake-bin"

  write_fake_age "$fake_bin"

  printf '203.0.113.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBundleHostKey\n' >"$tmp/source-known_hosts"
  cat >"$tmp/source-operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
EOF

  cat >"$inventory" <<JSON
{
  "environment": "alpha",
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "aws_profile": "juno",
      "aws_region": "us-east-1",
      "account_id": "021490342184",
      "operator_host": "203.0.113.11",
      "operator_user": "ubuntu",
      "runtime_dir": "/var/lib/intents-juno/operator-runtime",
      "public_dns_label": "op1",
      "public_endpoint": "203.0.113.11",
      "known_hosts_file": "$tmp/source-known_hosts",
      "secret_contract_file": "$tmp/source-operator-secrets.env"
    }
  ]
}
JSON

  cat >"$shared_manifest" <<'JSON'
{
  "version": "1",
  "environment": "alpha"
}
JSON

  cat >"$dkg_summary" <<JSON
{
  "summary_version": 1,
  "network": "testnet",
  "threshold": 3,
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "backup_package": "$backup_zip"
    }
  ]
}
JSON

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/operators/dkg/render-handoff.sh \
      --inventory "$inventory" \
      --dkg-summary "$dkg_summary" \
      --shared-manifest-path "$shared_manifest" \
      --output-dir "$output_dir" \
      --secret-mode age \
      --age-recipient "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj0n8l2"
  )

  assert_file_exists "$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-secrets.env.age" \
    "encrypted secret contract"
  assert_eq "$(jq -r '.bundle.secret_contract_file' "$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/dkg-handoff.json")" \
    "operator-secrets.env.age" \
    "handoff points at encrypted secret contract"
  assert_eq "$(jq -r '.bundle.secret_contract_mode' "$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/dkg-handoff.json")" \
    "age" \
    "handoff records age secret mode"
  assert_contains "$(cat "$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-secrets.env.age")" \
    "age recipient=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj0n8l2" \
    "age recipient recorded in encrypted handoff"

  rm -rf "$tmp"
}

main() {
  test_render_handoff_bundle_renders_operator_deploy_and_placeholder_inputs
  test_render_handoff_validate_restores_backup_and_marks_bundle_ready
  test_render_handoff_age_secret_mode_writes_encrypted_contract
}

main "$@"
