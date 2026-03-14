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
      | if .operator_id == $local_operator_id then
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
DEPLOY_BIN="$BUNDLE_ROOT/deploy/production/deploy-operator.sh"
CANARY_BIN="$BUNDLE_ROOT/deploy/production/canary-operator-boot.sh"
RELEASE_MANIFEST="$BUNDLE_ROOT/mainnet-release-manifest.json"
REPORT_FILE="$SCRIPT_DIR/deployment-report.json"
CANARY_FILE="$SCRIPT_DIR/canary-result.json"

[[ -f "$OPERATOR_DEPLOY" ]] || {
  echo "operator deploy manifest not found: $OPERATOR_DEPLOY" >&2
  exit 1
}
[[ -f "$RELEASE_MANIFEST" ]] || {
  echo "release manifest not found: $RELEASE_MANIFEST" >&2
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
if command -v aws >/dev/null 2>&1; then
  aws_profile="$(jq -r '.aws_profile // empty' "$OPERATOR_DEPLOY")"
  aws_region="$(jq -r '.aws_region // empty' "$OPERATOR_DEPLOY")"
  account_id="$(jq -r '.account_id // empty' "$OPERATOR_DEPLOY")"
  kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' "$OPERATOR_DEPLOY")"
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

[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -f "$rollout_state" ]] || die "rollout state not found: $rollout_state"
[[ -d "$operators_dir" ]] || die "operator handoff directory not found: $operators_dir"

mkdir -p "$output_dir"

operator_entries_tmp="$(mktemp)"
: >"$operator_entries_tmp"

mapfile -t operator_manifests < <(find "$operators_dir" -mindepth 2 -maxdepth 2 -name operator-deploy.json -print | sort)
(( ${#operator_manifests[@]} > 0 )) || die "no operator deploy manifests found under $operators_dir"

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
  cp "$SCRIPT_DIR/deploy-operator.sh" "$bundle_root/deploy/production/deploy-operator.sh"
  cp "$SCRIPT_DIR/canary-operator-boot.sh" "$bundle_root/deploy/production/canary-operator-boot.sh"
  cp "$SCRIPT_DIR/lib.sh" "$bundle_root/deploy/production/lib.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/backup-package.sh" "$bundle_root/deploy/operators/dkg/backup-package.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/common.sh" "$bundle_root/deploy/operators/dkg/common.sh"
  cp "$REPO_ROOT/deploy/operators/dkg/operator-export-kms.sh" "$bundle_root/deploy/operators/dkg/operator-export-kms.sh"
  chmod 0755 \
    "$bundle_root/deploy/production/deploy-operator.sh" \
    "$bundle_root/deploy/production/canary-operator-boot.sh" \
    "$bundle_root/deploy/operators/dkg/backup-package.sh" \
    "$bundle_root/deploy/operators/dkg/operator-export-kms.sh"

  for peer_manifest in "${operator_manifests[@]}"; do
    peer_id="$(jq -r '.operator_id' "$peer_manifest")"
    peer_dir="$bundle_operator_root/operators/$peer_id"
    mkdir -p "$peer_dir"
    rewrite_operator_manifest_for_bundle "$peer_manifest" "$peer_dir/operator-deploy.json" "$operator_id"
  done

  local_handoff_dir="$(cd "$(dirname "$operator_manifest")" && pwd)"
  dkg_backup_zip_src="$(production_abs_path "$local_handoff_dir" "$(jq -r '.dkg_backup_zip' "$operator_manifest")")"
  cp "$local_handoff_dir/known_hosts" "$bundle_operator_dir/known_hosts"
  cp "$local_handoff_dir/operator-secrets.env" "$bundle_operator_dir/operator-secrets.env"
  cp "$dkg_backup_zip_src" "$bundle_operator_dir/dkg-backup.zip"
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
