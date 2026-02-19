#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  create-synced-junocashd-ami.sh create [options]

Options:
  --instance-id <id>      source EC2 instance id with fully synced junocashd (required)
  --name <name>           AMI name (default: junocashd-synced-<UTC timestamp>)
  --description <text>    AMI description
  --no-reboot             create image without reboot (default: reboot before snapshot)
  --wait                  wait for AMI to become available (default: true)
  --aws-profile <name>    optional AWS profile
  --aws-region <region>   required AWS region

Example:
  ./deploy/shared/runbooks/create-synced-junocashd-ami.sh create \
    --instance-id i-0123456789abcdef0 \
    --aws-profile juno \
    --aws-region us-east-1
EOF
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

aws_args() {
  local profile="$1"
  local region="$2"
  AWS_ARGS=()
  if [[ -n "$profile" ]]; then
    AWS_ARGS+=(--profile "$profile")
  fi
  if [[ -n "$region" ]]; then
    AWS_ARGS+=(--region "$region")
  fi
}

command_create() {
  shift || true

  local instance_id=""
  local name="junocashd-synced-$(date -u +%Y%m%dT%H%M%SZ)"
  local description="Synced junocashd image for intents-juno operator hosts"
  local no_reboot="false"
  local wait_for_available="true"
  local aws_profile=""
  local aws_region=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --instance-id)
        [[ $# -ge 2 ]] || die "missing value for --instance-id"
        instance_id="$2"
        shift 2
        ;;
      --name)
        [[ $# -ge 2 ]] || die "missing value for --name"
        name="$2"
        shift 2
        ;;
      --description)
        [[ $# -ge 2 ]] || die "missing value for --description"
        description="$2"
        shift 2
        ;;
      --no-reboot)
        no_reboot="true"
        shift
        ;;
      --wait)
        wait_for_available="true"
        shift
        ;;
      --aws-profile)
        [[ $# -ge 2 ]] || die "missing value for --aws-profile"
        aws_profile="$2"
        shift 2
        ;;
      --aws-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-region"
        aws_region="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for create: $1"
        ;;
    esac
  done

  have_cmd aws || die "missing required command: aws"
  [[ -n "$instance_id" ]] || die "--instance-id is required"
  [[ -n "$aws_region" ]] || die "--aws-region is required"
  [[ "$instance_id" =~ ^i-[a-zA-Z0-9]+$ ]] || die "--instance-id must look like an EC2 instance id"

  aws_args "$aws_profile" "$aws_region"

  local no_reboot_arg
  if [[ "$no_reboot" == "true" ]]; then
    no_reboot_arg="--no-reboot"
  else
    no_reboot_arg="--reboot"
  fi

  log "creating AMI from instance=$instance_id name=$name region=$aws_region"
  local image_id
  image_id="$(
    AWS_PAGER="" aws "${AWS_ARGS[@]}" ec2 create-image \
      --instance-id "$instance_id" \
      --name "$name" \
      --description "$description" \
      "$no_reboot_arg" \
      --query 'ImageId' \
      --output text
  )"
  [[ -n "$image_id" && "$image_id" != "None" ]] || die "failed to create AMI"

  if [[ "$wait_for_available" == "true" ]]; then
    log "waiting for AMI to become available: $image_id"
    AWS_PAGER="" aws "${AWS_ARGS[@]}" ec2 wait image-available --image-ids "$image_id"
  fi

  log "ami_id=$image_id"
  printf '%s\n' "$image_id"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    create) command_create "$@" ;;
    -h|--help|"")
      usage
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

main "$@"
