#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  copy-operator-ami.sh replicate \
    --manifest-in <path> \
    --manifest-out <path> \
    --source-region <region> \
    --target-regions <comma-or-space-separated-regions>
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

copy_manifest_across_regions() {
  local manifest_in=""
  local manifest_out=""
  local source_region=""
  local target_regions_raw=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --manifest-in)
        manifest_in="$2"
        shift 2
        ;;
      --manifest-out)
        manifest_out="$2"
        shift 2
        ;;
      --source-region)
        source_region="$2"
        shift 2
        ;;
      --target-regions)
        target_regions_raw="$2"
        shift 2
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  [[ -n "$manifest_in" ]] || die "--manifest-in is required"
  [[ -n "$manifest_out" ]] || die "--manifest-out is required"
  [[ -n "$source_region" ]] || die "--source-region is required"
  [[ -f "$manifest_in" ]] || die "manifest not found: $manifest_in"

  local source_ami_id image_name image_description
  source_ami_id="$(jq -r --arg region "$source_region" '.regions[$region].ami_id // empty' "$manifest_in")"
  [[ -n "$source_ami_id" ]] || die "source manifest does not contain region: $source_region"
  image_name="$(jq -r '.image.name // empty' "$manifest_in")"
  image_description="$(jq -r '.image.description // empty' "$manifest_in")"
  [[ -n "$image_name" ]] || die "manifest image.name is required"
  [[ -n "$image_description" ]] || die "manifest image.description is required"

  local -A seen_regions=()
  local -a target_regions=()
  local region
  while read -r region; do
    [[ -n "$region" ]] || continue
    [[ "$region" == "$source_region" ]] && continue
    if [[ -n "${seen_regions[$region]:-}" ]]; then
      continue
    fi
    seen_regions[$region]=1
    target_regions+=("$region")
  done < <(printf '%s' "$target_regions_raw" | tr ',\n\t' '   ' | awk '{ for (i = 1; i <= NF; ++i) print $i }')

  cp "$manifest_in" "$manifest_out"
  [[ ${#target_regions[@]} -gt 0 ]] || return 0

  local copied_ami_id tmp_manifest
  tmp_manifest="$(mktemp)"
  for region in "${target_regions[@]}"; do
    copied_ami_id="$(
      aws ec2 copy-image \
        --region "$region" \
        --source-region "$source_region" \
        --source-image-id "$source_ami_id" \
        --name "$image_name" \
        --description "$image_description" \
        --query 'ImageId' \
        --output text
    )"
    [[ -n "$copied_ami_id" && "$copied_ami_id" != "None" ]] || die "failed to copy AMI into $region"

    aws ec2 wait image-available \
      --region "$region" \
      --image-ids "$copied_ami_id"

    aws ec2 create-tags \
      --region "$region" \
      --resources "$copied_ami_id" \
      --tags \
        "Key=Name,Value=$image_name" \
        "Key=Project,Value=intents-juno" \
        "Key=Stack,Value=operator-ami" >/dev/null

    jq \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg region "$region" \
      --arg ami_id "$copied_ami_id" \
      '.generated_at = $generated_at | .regions[$region] = { ami_id: $ami_id }' \
      "$manifest_out" >"$tmp_manifest"
    mv "$tmp_manifest" "$manifest_out"
  done
}

main() {
  local command="${1:-}"
  case "$command" in
    replicate)
      shift
      copy_manifest_across_regions "$@"
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      die "unknown command: $command"
      ;;
  esac
}

main "$@"
