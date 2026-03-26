#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  package-mainnet-release.sh --handoff-dir PATH --release-tag TAG --output-dir PATH [--force]

Options:
  --handoff-dir PATH   Production handoff directory with shared-manifest.json and operators/ (required)
  --release-tag TAG    Published release tag for the packaged artifacts (required)
  --output-dir PATH    Output directory for the release manifest and operator bundles (required)
  --force              Overwrite existing output files
EOF
}

have_cmd_local() {
  command -v "$1" >/dev/null 2>&1
}

sha256_hex_file() {
  local path="$1"
  if have_cmd_local sha256sum; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  shasum -a 256 "$path" | awk '{print $1}'
}

write_sha256_file() {
  local path="$1"
  local output_file="$2"
  local filename digest

  filename="$(basename "$path")"
  digest="$(sha256_hex_file "$path")"
  printf '%s  %s\n' "$digest" "$filename" >"$output_file"
}

release_manifest_entry() {
  local operator_manifest="$1"
  local bundle_name="$2"
  local shared_manifest="$3"

  jq -n \
    --arg operator_id "$(jq -r '.operator_id' "$operator_manifest")" \
    --arg operator_address "$(jq -r '.operator_address // empty' "$operator_manifest")" \
    --arg aws_profile "$(jq -r '.aws_profile // empty' "$operator_manifest")" \
    --arg aws_region "$(jq -r '.aws_region // empty' "$operator_manifest")" \
    --arg account_id "$(jq -r '.account_id // empty' "$operator_manifest")" \
    --arg kms_key_id "$(jq -r '.checkpoint_signer_kms_key_id // empty' "$operator_manifest")" \
    --arg bundle_name "$bundle_name" \
    --arg shared_manifest_sha256 "$(sha256_hex_file "$shared_manifest")" \
    '{
      operator_id: $operator_id,
      operator_address: (if $operator_address == "" then null else $operator_address end),
      aws_profile: (if $aws_profile == "" then null else $aws_profile end),
      aws_region: (if $aws_region == "" then null else $aws_region end),
      account_id: (if $account_id == "" then null else $account_id end),
      checkpoint_signer_kms_key_id: (if $kms_key_id == "" then null else $kms_key_id end),
      bundle_name: $bundle_name,
      shared_manifest_sha256: $shared_manifest_sha256
    }'
}

rewrite_operator_manifest_for_bundle() {
  local source_manifest="$1"
  local output_manifest="$2"
  local local_operator_id="$3"

  jq \
    --arg local_operator_id "$local_operator_id" \
    '
      .shared_manifest_path = "../../shared-manifest.json"
      | .rollout_state_file = "../../rollout-state.json"
      | .dkg_tls_dir = (
          if (.dkg_tls_dir // "" | tostring | length) > 0 then
            "../../dkg-tls"
          else
            null
          end
        )
      | if (.runtime_material_ref.mode // "") == "s3-kms-zip" then
          .known_hosts_file = null
          | .secret_contract_file = null
          | .dkg_backup_zip = null
        elif .operator_id == $local_operator_id then
          .known_hosts_file = "./known_hosts"
          | .secret_contract_file = "./operator-secrets.env"
          | .dkg_backup_zip = "./dkg-backup.zip"
        else
          .known_hosts_file = null
          | .secret_contract_file = null
          | .dkg_backup_zip = null
        end
    ' "$source_manifest" >"$output_manifest"
}

render_deploy_wrapper() {
  local output_file="$1"
  local operator_id="$2"
  local template_file

  template_file="$(mktemp)"
  cat >"$template_file" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPERATOR_ID="__OPERATOR_ID__"
OPERATOR_DEPLOY="$SCRIPT_DIR/operators/$OPERATOR_ID/operator-deploy.json"
SHARED_MANIFEST="$SCRIPT_DIR/shared-manifest.json"
DEPLOY_BIN="$BUNDLE_ROOT/deploy/production/deploy-operator.sh"
CANARY_BIN="$BUNDLE_ROOT/deploy/production/canary-operator-boot.sh"
RELEASE_MANIFEST="$BUNDLE_ROOT/mainnet-release-manifest.json"
RELEASE_MANIFEST_SHA="$BUNDLE_ROOT/mainnet-release-manifest.sha256"
REPORT_FILE="$SCRIPT_DIR/deployment-report.json"
CANARY_FILE="$SCRIPT_DIR/canary-result.json"

have_cmd_local() {
  command -v "$1" >/dev/null 2>&1
}

sha256_hex_file() {
  local path="$1"
  if have_cmd_local sha256sum; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  shasum -a 256 "$path" | awk '{print $1}'
}

write_failure_report() {
  local status="$1"
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n --arg operator_id "$OPERATOR_ID" --arg started_at "$started_at" --arg finished_at "$finished_at" --arg status "$status" \
    '{operator_id: $operator_id, started_at: $started_at, finished_at: $finished_at, status: $status}' >"$REPORT_FILE"
  exit 1
}

[[ -f "$OPERATOR_DEPLOY" ]] || {
  echo "operator deploy manifest not found: $OPERATOR_DEPLOY" >&2
  exit 1
}
[[ -f "$SHARED_MANIFEST" ]] || {
  echo "shared manifest not found: $SHARED_MANIFEST" >&2
  exit 1
}
[[ -f "$RELEASE_MANIFEST" ]] || {
  echo "release manifest not found: $RELEASE_MANIFEST" >&2
  exit 1
}
[[ -f "$RELEASE_MANIFEST_SHA" ]] || {
  echo "release manifest checksum not found: $RELEASE_MANIFEST_SHA" >&2
  exit 1
}
[[ -x "$DEPLOY_BIN" ]] || {
  echo "deploy binary not found: $DEPLOY_BIN" >&2
  exit 1
}
[[ -x "$CANARY_BIN" ]] || {
  echo "canary binary not found: $CANARY_BIN" >&2
  exit 1
}

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status="deploy_failed"
have_cmd_local jq || {
  echo "required command not found: jq" >&2
  write_failure_report "missing_jq"
}
have_cmd_local cast || {
  echo "required command not found: cast" >&2
  write_failure_report "missing_cast"
}

expected_manifest_sha="$(awk 'NF { print $1; exit }' "$RELEASE_MANIFEST_SHA")"
actual_manifest_sha="$(sha256_hex_file "$RELEASE_MANIFEST")"
[[ -n "$expected_manifest_sha" && "$actual_manifest_sha" == "$expected_manifest_sha" ]] || {
  echo "release manifest checksum mismatch" >&2
  write_failure_report "release_manifest_checksum_mismatch"
}

release_entry="$(jq -c --arg operator_id "$OPERATOR_ID" '.operators[] | select(.operator_id == $operator_id)' "$RELEASE_MANIFEST")"
[[ -n "$release_entry" ]] || {
  echo "release manifest entry missing for operator $OPERATOR_ID" >&2
  write_failure_report "release_manifest_entry_missing"
}

shared_manifest_sha="$(sha256_hex_file "$SHARED_MANIFEST")"
entry_shared_manifest_sha="$(jq -r '.shared_manifest_sha256 // empty' <<<"$release_entry")"
[[ -n "$entry_shared_manifest_sha" && "$shared_manifest_sha" == "$entry_shared_manifest_sha" ]] || {
  echo "shared manifest checksum mismatch for operator $OPERATOR_ID" >&2
  write_failure_report "shared_manifest_mismatch"
}

operator_address="$(jq -r '.operator_address // empty' "$OPERATOR_DEPLOY")"
expected_operator_address="$(jq -r '.operator_address // empty' <<<"$release_entry")"
[[ -z "$expected_operator_address" || "$operator_address" == "$expected_operator_address" ]] || {
  echo "operator address mismatch: expected $expected_operator_address, got $operator_address" >&2
  write_failure_report "operator_address_mismatch"
}

aws_region="$(jq -r '.aws_region // empty' "$OPERATOR_DEPLOY")"
expected_aws_region="$(jq -r '.aws_region // empty' <<<"$release_entry")"
[[ "$aws_region" == "$expected_aws_region" ]] || {
  echo "aws region mismatch: expected $expected_aws_region, got $aws_region" >&2
  write_failure_report "release_manifest_region_mismatch"
}

account_id="$(jq -r '.account_id // empty' "$OPERATOR_DEPLOY")"
expected_account_id="$(jq -r '.account_id // empty' <<<"$release_entry")"
[[ "$account_id" == "$expected_account_id" ]] || {
  echo "aws account mismatch: expected $expected_account_id, got $account_id" >&2
  write_failure_report "release_manifest_account_mismatch"
}

kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' "$OPERATOR_DEPLOY")"
expected_kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$release_entry")"
[[ "$kms_key_id" == "$expected_kms_key_id" ]] || {
  echo "kms key mismatch: expected $expected_kms_key_id, got $kms_key_id" >&2
  write_failure_report "release_manifest_kms_mismatch"
}

if command -v aws >/dev/null 2>&1; then
  aws_profile="$(jq -r '.aws_profile // empty' "$OPERATOR_DEPLOY")"
  if [[ -n "$aws_profile" && -n "$aws_region" && -n "$account_id" ]]; then
    actual_account="$(aws --profile "$aws_profile" --region "$aws_region" sts get-caller-identity --query Account --output text)"
    [[ "$actual_account" == "$account_id" ]] || {
      echo "aws account mismatch: expected $account_id, got $actual_account" >&2
      status="account_mismatch"
      finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      jq -n --arg operator_id "$OPERATOR_ID" --arg started_at "$started_at" --arg finished_at "$finished_at" --arg status "$status" \
        '{operator_id: $operator_id, started_at: $started_at, finished_at: $finished_at, status: $status}' >"$REPORT_FILE"
      exit 1
    }
  fi
  if [[ -n "$aws_profile" && -n "$aws_region" && -n "$kms_key_id" ]]; then
    actual_kms="$(aws --profile "$aws_profile" --region "$aws_region" kms describe-key --key-id "$kms_key_id" --query 'KeyMetadata.Arn' --output text)"
    [[ "$actual_kms" == "$kms_key_id" ]] || {
      echo "kms key mismatch: expected $kms_key_id, got $actual_kms" >&2
      status="kms_mismatch"
      finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      jq -n --arg operator_id "$OPERATOR_ID" --arg started_at "$started_at" --arg finished_at "$finished_at" --arg status "$status" \
        '{operator_id: $operator_id, started_at: $started_at, finished_at: $finished_at, status: $status}' >"$REPORT_FILE"
      exit 1
    }
  fi
fi

base_rpc_url="$(jq -r '.contracts.base_rpc_url // empty' "$SHARED_MANIFEST")"
operator_registry="$(jq -r '.contracts.operator_registry // empty' "$SHARED_MANIFEST")"
effective_operator_address="${operator_address:-$OPERATOR_ID}"
[[ "$base_rpc_url" =~ ^https?:// ]] || {
  echo "shared manifest is missing contracts.base_rpc_url" >&2
  write_failure_report "shared_manifest_missing_base_rpc"
}
[[ "$operator_registry" =~ ^0x[0-9a-fA-F]{40}$ ]] || {
  echo "shared manifest is missing contracts.operator_registry" >&2
  write_failure_report "shared_manifest_missing_operator_registry"
}
[[ "$effective_operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || {
  echo "operator deploy manifest is missing a valid operator address" >&2
  write_failure_report "operator_address_missing"
}

operator_registered="$(cast call --rpc-url "$base_rpc_url" "$operator_registry" "isOperator(address)(bool)" "$effective_operator_address" 2>/dev/null | tr -d '[:space:]')"
case "$operator_registered" in
  true|1|0x1)
    ;;
  *)
    echo "operator $effective_operator_address is not active in operator registry $operator_registry" >&2
    write_failure_report "operator_not_registered"
    ;;
esac

if "$DEPLOY_BIN" --operator-deploy "$OPERATOR_DEPLOY" "$@"; then
  if "$CANARY_BIN" --operator-deploy "$OPERATOR_DEPLOY" >"$CANARY_FILE"; then
    status="ready"
  else
    status="canary_failed"
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg operator_id "$OPERATOR_ID" \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg status "$status" \
  --arg canary_file "$CANARY_FILE" \
  '{
    operator_id: $operator_id,
    started_at: $started_at,
    finished_at: $finished_at,
    status: $status,
    canary_file: $canary_file
  }' >"$REPORT_FILE"

[[ "$status" == "ready" ]]
EOF
  sed "s/__OPERATOR_ID__/$operator_id/g" "$template_file" >"$output_file"
  rm -f "$template_file"
  chmod 0755 "$output_file"
}

handoff_dir=""
release_tag=""
output_dir=""
force="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --handoff-dir) handoff_dir="$2"; shift 2 ;;
    --release-tag) release_tag="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --force) force="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$handoff_dir" ]] || die "--handoff-dir is required"
[[ -n "$release_tag" ]] || die "--release-tag is required"
[[ -n "$output_dir" ]] || die "--output-dir is required"

have_cmd_local jq || die "required command not found: jq"
have_cmd_local zip || die "required command not found: zip"

handoff_dir="$(production_abs_path "$(pwd)" "$handoff_dir")"
output_dir="$(production_abs_path "$(pwd)" "$output_dir")"

shared_manifest="$handoff_dir/shared-manifest.json"
rollout_state="$handoff_dir/rollout-state.json"
operators_dir="$handoff_dir/operators"
dkg_tls_dir=""
dkg_tls_present="false"

[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -f "$rollout_state" ]] || die "rollout state not found: $rollout_state"
[[ -d "$operators_dir" ]] || die "operator handoff directory not found: $operators_dir"

mkdir -p "$output_dir"

operator_entries_tmp="$(mktemp)"
: >"$operator_entries_tmp"

mapfile -t operator_manifests < <(find "$operators_dir" -mindepth 2 -maxdepth 2 -name operator-deploy.json -print | sort)
(( ${#operator_manifests[@]} > 0 )) || die "no operator deploy manifests found under $operators_dir"

if [[ -d "$handoff_dir/dkg-tls" ]]; then
  dkg_tls_dir="$handoff_dir/dkg-tls"
else
  mapfile -t dkg_tls_candidates < <(
    for operator_manifest in "${operator_manifests[@]}"; do
      manifest_dir="$(cd "$(dirname "$operator_manifest")" && pwd)"
      manifest_dkg_tls_dir="$(jq -r '.dkg_tls_dir // empty' "$operator_manifest")"
      [[ -n "$manifest_dkg_tls_dir" ]] || continue
      production_abs_path "$manifest_dir" "$manifest_dkg_tls_dir"
    done | LC_ALL=C sort -u
  )
  if (( ${#dkg_tls_candidates[@]} > 1 )); then
    die "operator manifests disagree on dkg_tls_dir: ${dkg_tls_candidates[*]}"
  elif (( ${#dkg_tls_candidates[@]} == 1 )); then
    dkg_tls_dir="${dkg_tls_candidates[0]}"
  fi
fi

if [[ -n "$dkg_tls_dir" ]]; then
  [[ -d "$dkg_tls_dir" ]] || die "dkg tls dir not found: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/ca.pem" ]] || die "dkg tls dir missing ca.pem: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/ca.key" ]] || die "dkg tls dir missing ca.key: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/coordinator-client.pem" ]] || die "dkg tls dir missing coordinator-client.pem: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/coordinator-client.key" ]] || die "dkg tls dir missing coordinator-client.key: $dkg_tls_dir"
  dkg_tls_present="true"
fi

for operator_manifest in "${operator_manifests[@]}"; do
  operator_id="$(jq -r '.operator_id' "$operator_manifest")"
  bundle_name="operator-bundle-$(production_safe_slug "$operator_id").zip"
  release_manifest_entry "$operator_manifest" "$bundle_name" "$shared_manifest" >>"$operator_entries_tmp"
done

mainnet_release_manifest="$output_dir/mainnet-release-manifest.json"
operators_json="$(jq -s 'sort_by(.operator_id)' "$operator_entries_tmp")"
jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg environment "$(jq -r '.environment' "$shared_manifest")" \
  --arg release_tag "$release_tag" \
  --arg shared_manifest_sha256 "$(sha256_hex_file "$shared_manifest")" \
  --arg rollout_state_sha256 "$(sha256_hex_file "$rollout_state")" \
  --argjson operators "$operators_json" \
  '{
    version: $version,
    generated_at: $generated_at,
    environment: $environment,
    release_tag: $release_tag,
    shared_manifest_sha256: $shared_manifest_sha256,
    rollout_state_sha256: $rollout_state_sha256,
    operators: $operators
  }' >"$mainnet_release_manifest"
write_sha256_file "$mainnet_release_manifest" "$output_dir/mainnet-release-manifest.sha256"

for operator_manifest in "${operator_manifests[@]}"; do
  operator_id="$(jq -r '.operator_id' "$operator_manifest")"
  operator_slug="$(production_safe_slug "$operator_id")"
  bundle_name="operator-bundle-${operator_slug}.zip"
  bundle_path="$output_dir/$bundle_name"
  bundle_sha_path="$output_dir/$bundle_name.sha256"
  [[ "$force" == "true" || ! -e "$bundle_path" ]] || die "bundle already exists (use --force to overwrite): $bundle_path"

  stage_dir="$(mktemp -d)"
  bundle_root="$stage_dir/$operator_slug"
  bundle_operator_root="$bundle_root/bundle/operator"
  bundle_operator_dir="$bundle_operator_root/operators/$operator_id"
  mkdir -p "$bundle_root/deploy/production" "$bundle_root/deploy/operators/dkg" "$bundle_operator_dir"

  cp "$mainnet_release_manifest" "$bundle_root/mainnet-release-manifest.json"
  cp "$output_dir/mainnet-release-manifest.sha256" "$bundle_root/mainnet-release-manifest.sha256"
  cp "$shared_manifest" "$bundle_operator_root/shared-manifest.json"
  write_sha256_file "$bundle_operator_root/shared-manifest.json" "$bundle_operator_root/shared-manifest.sha256"
  cp "$rollout_state" "$bundle_operator_root/rollout-state.json"
  if [[ "$dkg_tls_present" == "true" ]]; then
    mkdir -p "$bundle_operator_root/dkg-tls"
    cp "$dkg_tls_dir/ca.pem" "$bundle_operator_root/dkg-tls/ca.pem"
    cp "$dkg_tls_dir/ca.key" "$bundle_operator_root/dkg-tls/ca.key"
    cp "$dkg_tls_dir/coordinator-client.pem" "$bundle_operator_root/dkg-tls/coordinator-client.pem"
    cp "$dkg_tls_dir/coordinator-client.key" "$bundle_operator_root/dkg-tls/coordinator-client.key"
  fi
  cp "$SCRIPT_DIR/deploy-operator.sh" "$bundle_root/deploy/production/deploy-operator.sh"
  cp "$SCRIPT_DIR/canary-operator-boot.sh" "$bundle_root/deploy/production/canary-operator-boot.sh"
  cp "$SCRIPT_DIR/run-operator-rollout.sh" "$bundle_root/deploy/production/run-operator-rollout.sh"
  cp "$SCRIPT_DIR/run-operator-local-canary.sh" "$bundle_root/deploy/production/run-operator-local-canary.sh"
  cp "$SCRIPT_DIR/prepare-runtime-materials.sh" "$bundle_root/deploy/production/prepare-runtime-materials.sh"
  cp "$SCRIPT_DIR/lib.sh" "$bundle_root/deploy/production/lib.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/backup-package.sh" "$bundle_root/deploy/operators/dkg/backup-package.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/common.sh" "$bundle_root/deploy/operators/dkg/common.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/operator-export-kms.sh" "$bundle_root/deploy/operators/dkg/operator-export-kms.sh"
  chmod 0755 \
    "$bundle_root/deploy/production/deploy-operator.sh" \
    "$bundle_root/deploy/production/canary-operator-boot.sh" \
    "$bundle_root/deploy/production/run-operator-rollout.sh" \
    "$bundle_root/deploy/production/run-operator-local-canary.sh" \
    "$bundle_root/deploy/production/prepare-runtime-materials.sh" \
    "$bundle_root/deploy/operators/dkg/backup-package.sh" \
    "$bundle_root/deploy/operators/dkg/operator-export-kms.sh"

  for peer_manifest in "${operator_manifests[@]}"; do
    peer_id="$(jq -r '.operator_id' "$peer_manifest")"
    peer_dir="$bundle_operator_root/operators/$peer_id"
    mkdir -p "$peer_dir"
    rewrite_operator_manifest_for_bundle "$peer_manifest" "$peer_dir/operator-deploy.json" "$operator_id"
  done

  local_handoff_dir="$(cd "$(dirname "$operator_manifest")" && pwd)"
  dkg_backup_zip_src="$(jq -r '.dkg_backup_zip // empty' "$operator_manifest")"
  if [[ -n "$dkg_backup_zip_src" ]]; then
    dkg_backup_zip_src="$(production_abs_path "$local_handoff_dir" "$dkg_backup_zip_src")"
    cp "$local_handoff_dir/known_hosts" "$bundle_operator_dir/known_hosts"
    cp "$local_handoff_dir/operator-secrets.env" "$bundle_operator_dir/operator-secrets.env"
    cp "$dkg_backup_zip_src" "$bundle_operator_dir/dkg-backup.zip"
  fi
  jq -n '{status: "pending"}' >"$bundle_operator_root/canary-result.json"
  jq -n '{status: "pending"}' >"$bundle_operator_root/deployment-report.json"
  render_deploy_wrapper "$bundle_operator_root/deploy-mainnet-operator.sh" "$operator_id"

  (
    cd "$stage_dir"
    zip -qr "$bundle_path" "$operator_slug"
  )
  write_sha256_file "$bundle_path" "$bundle_sha_path"
  rm -rf "$stage_dir"
done

rm -f "$operator_entries_tmp"
log "packaged mainnet release: $output_dir"
