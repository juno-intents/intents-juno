#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  resolve-role-runtime-release-inputs.sh --inventory <path> --output <path> [options]

Options:
  --inventory PATH    Deployment inventory JSON (required)
  --output PATH       Resolved inventory JSON output path (required)
  --operator-stack-ami-release-tag TAG
                     Optional pinned operator stack AMI release tag used to seed
                     shared_services.live_e2e.operator_ami_id when absent
  --github-repo REPO  GitHub repo in owner/name form (default: juno-intents/intents-juno)
  --aws-profile NAME  Optional AWS profile for ECR repository ARN fallback
  --aws-region NAME   Optional AWS region override (defaults from inventory)
EOF
}

inventory=""
output=""
operator_stack_ami_release_tag=""
github_repo="juno-intents/intents-juno"
aws_profile=""
aws_region=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory)
      inventory="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    --operator-stack-ami-release-tag)
      operator_stack_ami_release_tag="$2"
      shift 2
      ;;
    --github-repo)
      github_repo="$2"
      shift 2
      ;;
    --aws-profile)
      aws_profile="$2"
      shift 2
      ;;
    --aws-region)
      aws_region="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$output" ]] || die "--output is required"
have_cmd jq || die "required command not found: jq"
have_cmd gh || die "required command not found: gh"

release_tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$release_tmp_dir"
}
trap cleanup EXIT

resolved_network="$(production_json_required "$inventory" '.contracts.juno_network | select(type == "string" and length > 0)')"
if [[ -z "$aws_profile" ]]; then
  aws_profile="$(production_json_optional "$inventory" '.shared_services.aws_profile')"
fi
if [[ -z "$aws_profile" ]]; then
  aws_profile="$(production_json_optional "$inventory" '.app_role.aws_profile')"
fi
if [[ -z "$aws_region" ]]; then
  aws_region="$(production_json_optional "$inventory" '.shared_services.aws_region')"
fi
if [[ -z "$aws_region" ]]; then
  aws_region="$(production_json_optional "$inventory" '.app_role.aws_region')"
fi
[[ -n "$aws_region" ]] || die "inventory is missing shared_services.aws_region and app_role.aws_region"

validate_release_tag() {
  local tag="$1"
  local field="$2"

  [[ -n "$tag" ]] || return 0
  [[ "$tag" != *latest* ]] || die "$field must not use latest tags: $tag"
  case "$resolved_network" in
    testnet)
      [[ "$tag" == *-testnet ]] || die "$field must end with -testnet for ${resolved_network}: $tag"
      ;;
    mainnet)
      [[ "$tag" == *-mainnet ]] || die "$field must end with -mainnet for ${resolved_network}: $tag"
      ;;
    *)
      die "unsupported contracts.juno_network: $resolved_network"
      ;;
  esac
}

sha256_hex_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return 0
  fi
  die "missing sha256 tool"
}

download_release_asset_with_checksum() {
  local tag="$1"
  local asset_name="$2"
  local output_path="$3"
  local asset_dir checksum_path expected actual

  asset_dir="$release_tmp_dir/$tag"
  mkdir -p "$asset_dir"
  gh release download "$tag" \
    --repo "$github_repo" \
    --pattern "$asset_name" \
    --pattern "${asset_name}.sha256" \
    --dir "$asset_dir" \
    --clobber >/dev/null

  checksum_path="$asset_dir/${asset_name}.sha256"
  [[ -f "$asset_dir/$asset_name" ]] || die "release asset download failed: $tag $asset_name"
  [[ -f "$checksum_path" ]] || die "release checksum download failed: $tag ${asset_name}.sha256"

  expected="$(awk '{print $1}' "$checksum_path" | head -n 1)"
  actual="$(sha256_hex_file "$asset_dir/$asset_name")"
  [[ -n "$expected" ]] || die "release checksum file is empty: $checksum_path"
  [[ "$expected" == "$actual" ]] || die "release checksum mismatch: $tag $asset_name"

  cp "$asset_dir/$asset_name" "$output_path"
}

resolve_proof_repository_arn() {
  local manifest_json="$1"
  local repository_arn repository_uri repository_name repository_host account_id derived_region aws_args=()

  repository_arn="$(jq -r --arg region "$aws_region" '.regions[$region].repository_arn // empty' "$manifest_json")"
  if [[ -n "$repository_arn" ]]; then
    printf '%s\n' "$repository_arn"
    return 0
  fi

  repository_uri="$(jq -r --arg region "$aws_region" '.regions[$region].repository_uri // empty' "$manifest_json")"
  [[ -n "$repository_uri" ]] || die "shared proof release manifest is missing repository_uri for region=$aws_region"
  repository_host="${repository_uri%%/*}"
  repository_name="${repository_uri#*/}"
  [[ -n "$repository_name" && "$repository_name" != "$repository_uri" ]] || die "failed to derive ECR repository name from repository_uri=$repository_uri"
  if [[ "$repository_host" =~ ^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$ ]]; then
    account_id="${BASH_REMATCH[1]}"
    derived_region="${BASH_REMATCH[2]}"
    printf 'arn:aws:ecr:%s:%s:repository/%s\n' "$derived_region" "$account_id" "$repository_name"
    return 0
  fi
  have_cmd aws || die "required command not found: aws for ECR repository ARN fallback"
  [[ -n "$aws_profile" ]] && aws_args+=(--profile "$aws_profile")
  aws_args+=(--region "$aws_region")
  repository_arn="$(AWS_PAGER="" aws "${aws_args[@]}" ecr describe-repositories \
    --repository-names "$repository_name" \
    --query 'repositories[0].repositoryArn' \
    --output text 2>/dev/null || true)"
  [[ -n "$repository_arn" && "$repository_arn" != "None" ]] || die "failed to resolve ECR repository ARN for $repository_name in $aws_region"
  printf '%s\n' "$repository_arn"
}

app_runtime_release_tag="$(production_json_optional "$inventory" '.app_role.ami_release_tag')"
shared_proof_release_tag="$(production_json_optional "$inventory" '.shared_roles.proof.image_release_tag')"
wireguard_release_tag="$(production_json_optional "$inventory" '.wireguard_role.ami_release_tag')"
if [[ -z "$wireguard_release_tag" ]]; then
  wireguard_release_tag="$(production_json_optional "$inventory" '.shared_roles.wireguard.ami_release_tag')"
fi
wireguard_release_required="$(
  jq -r '
    if (.shared_services.terraform_dir // "") == "deploy/shared/terraform/live-e2e" then
      "true"
    elif (.wireguard_role? | type == "object" and length > 0) or (.shared_roles.wireguard? | type == "object" and length > 0) then
      "true"
    else
      "false"
    end
  ' "$inventory"
)"

validate_release_tag "$app_runtime_release_tag" "app_role.ami_release_tag"
validate_release_tag "$shared_proof_release_tag" "shared_roles.proof.image_release_tag"
if [[ "$wireguard_release_required" == "true" ]]; then
  validate_release_tag "$wireguard_release_tag" "wireguard_role.ami_release_tag"
fi
validate_release_tag "$operator_stack_ami_release_tag" "operator_stack_ami_release_tag"

app_runtime_manifest="$release_tmp_dir/app-runtime-ami-manifest.json"
shared_proof_manifest="$release_tmp_dir/shared-proof-services-image-manifest.json"
wireguard_manifest="$release_tmp_dir/wireguard-role-ami-manifest.json"
operator_stack_manifest="$release_tmp_dir/operator-ami-manifest.json"

[[ -n "$app_runtime_release_tag" ]] || die "inventory is missing app_role.ami_release_tag"
[[ -n "$shared_proof_release_tag" ]] || die "inventory is missing shared_roles.proof.image_release_tag"
if [[ "$wireguard_release_required" == "true" ]]; then
  [[ -n "$wireguard_release_tag" ]] || die "inventory is missing wireguard_role.ami_release_tag or shared_roles.wireguard.ami_release_tag"
fi

download_release_asset_with_checksum "$app_runtime_release_tag" "app-runtime-ami-manifest.json" "$app_runtime_manifest"
download_release_asset_with_checksum "$shared_proof_release_tag" "shared-proof-services-image-manifest.json" "$shared_proof_manifest"
if [[ "$wireguard_release_required" == "true" ]]; then
  download_release_asset_with_checksum "$wireguard_release_tag" "wireguard-role-ami-manifest.json" "$wireguard_manifest"
fi
if [[ -n "$operator_stack_ami_release_tag" ]]; then
  download_release_asset_with_checksum "$operator_stack_ami_release_tag" "operator-ami-manifest.json" "$operator_stack_manifest"
fi

app_ami_id="$(jq -r --arg region "$aws_region" '.regions[$region].ami_id // empty' "$app_runtime_manifest")"
[[ -n "$app_ami_id" ]] || die "app runtime release manifest is missing regions[$aws_region].ami_id"
shared_proof_image_uri="$(jq -r --arg region "$aws_region" '.regions[$region].image_uri // .image_uri // empty' "$shared_proof_manifest")"
[[ -n "$shared_proof_image_uri" ]] || die "shared proof release manifest is missing regions[$aws_region].image_uri"
shared_proof_repository_arn="$(resolve_proof_repository_arn "$shared_proof_manifest")"
wireguard_ami_id=""
if [[ "$wireguard_release_required" == "true" ]]; then
  wireguard_ami_id="$(jq -r --arg region "$aws_region" '.regions[$region].ami_id // empty' "$wireguard_manifest")"
  [[ -n "$wireguard_ami_id" ]] || die "wireguard release manifest is missing regions[$aws_region].ami_id"
fi
operator_stack_ami_id=""
if [[ -n "$operator_stack_ami_release_tag" ]]; then
  operator_stack_ami_id="$(jq -r --arg region "$aws_region" '.regions[$region].ami_id // empty' "$operator_stack_manifest")"
  [[ -n "$operator_stack_ami_id" ]] || die "operator stack release manifest is missing regions[$aws_region].ami_id"
fi

jq \
  --arg app_ami_id "$app_ami_id" \
  --arg app_release_tag "$app_runtime_release_tag" \
  --arg proof_image_uri "$shared_proof_image_uri" \
  --arg proof_image_release_tag "$shared_proof_release_tag" \
  --arg proof_image_ecr_repository_arn "$shared_proof_repository_arn" \
  --arg wireguard_ami_id "$wireguard_ami_id" \
  --arg wireguard_release_tag "$wireguard_release_tag" \
  --arg operator_stack_ami_id "$operator_stack_ami_id" \
  '
    .app_role.app_ami_id = $app_ami_id
    | .app_role.ami_release_tag = $app_release_tag
    | .shared_roles.proof.image_uri = $proof_image_uri
    | .shared_roles.proof.image_release_tag = $proof_image_release_tag
    | .shared_roles.proof.image_ecr_repository_arn = $proof_image_ecr_repository_arn
    | if $wireguard_ami_id != "" then
        .shared_roles.wireguard.ami_id = $wireguard_ami_id
        | .shared_roles.wireguard.ami_release_tag = $wireguard_release_tag
        | .wireguard_role.ami_id = $wireguard_ami_id
        | .wireguard_role.ami_release_tag = $wireguard_release_tag
      else .
      end
    | if $operator_stack_ami_id != ""
         and (.shared_services.terraform_dir // "") == "deploy/shared/terraform/live-e2e"
         and (.shared_services.live_e2e.operator_ami_id // "") == "" then
        .shared_services.live_e2e = (.shared_services.live_e2e // {})
        | .shared_services.live_e2e.operator_ami_id = $operator_stack_ami_id
      else .
      end
  ' "$inventory" >"$output"
