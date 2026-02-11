#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'EOF'
Usage:
  operator-export-kms.sh export [options]
  operator-export-kms.sh age-recipient [options]

Commands:
  export:
    --workdir <path>                operator runtime dir (default: ~/.juno-dkg/operator-runtime)
    --release-tag <tag>             dkg-admin release tag (default: v0.1.0)
    --kms-key-id <arn>              required
    --s3-bucket <name>              required
    --s3-sse-kms-key-id <arn>       required
    --s3-key-prefix <prefix>        default dkg/keypackages
    --s3-key <key>                  optional explicit object key override
    --aws-profile <name>            optional AWS profile used for preflight + export
    --aws-region <name>             optional AWS region used for preflight + export
    --skip-aws-preflight            skip aws sts/kms/s3 validation checks
    --backup-age-recipient <age1..> optional, repeatable local backup recipient
    --backup-out <path>             local backup output path for age export
    --force                         allow overwriting --backup-out when it exists

  age-recipient:
    --identity-file <path>          default ~/.juno-dkg/backup/age-identity.txt
    --output <path>                 default stdout ("-")

Notes:
  - `export` reads operator metadata from <workdir>/bundle/admin-config.json.
  - Exported key package plaintext never leaves this machine.
EOF
}

run_dkg_admin_export() {
  local dkg_admin_bin="$1"
  local config_path="$2"
  local aws_profile="$3"
  local aws_region="$4"
  shift 4

  local -a env_args=()
  if [[ -n "$aws_profile" ]]; then
    env_args+=("AWS_PROFILE=$aws_profile")
  fi
  if [[ -n "$aws_region" ]]; then
    env_args+=("AWS_REGION=$aws_region")
  fi

  if (( ${#env_args[@]} > 0 )); then
    env "${env_args[@]}" "$dkg_admin_bin" --config "$config_path" export-key-package "$@"
    return
  fi
  "$dkg_admin_bin" --config "$config_path" export-key-package "$@"
}

aws_preflight() {
  local kms_key_id="$1"
  local s3_bucket="$2"
  local aws_profile="$3"
  local aws_region="$4"

  ensure_command aws

  local -a aws_args=()
  if [[ -n "$aws_profile" ]]; then
    aws_args+=(--profile "$aws_profile")
  fi
  if [[ -n "$aws_region" ]]; then
    aws_args+=(--region "$aws_region")
  fi

  AWS_PAGER="" aws "${aws_args[@]}" sts get-caller-identity >/dev/null \
    || die "aws credentials are unavailable for this environment/profile"
  AWS_PAGER="" aws "${aws_args[@]}" kms describe-key --key-id "$kms_key_id" >/dev/null \
    || die "kms key is not accessible: $kms_key_id"
  AWS_PAGER="" aws "${aws_args[@]}" s3api head-bucket --bucket "$s3_bucket" >/dev/null \
    || die "s3 bucket is not accessible: $s3_bucket"
}

command_export() {
  shift || true

  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local kms_key_id=""
  local s3_bucket=""
  local s3_key_prefix="dkg/keypackages"
  local s3_key=""
  local s3_sse_kms_key_id=""
  local aws_profile=""
  local aws_region=""
  local skip_aws_preflight="false"
  local backup_out=""
  local force="false"
  local backup_age_recipients=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --kms-key-id)
        [[ $# -ge 2 ]] || die "missing value for --kms-key-id"
        kms_key_id="$2"
        shift 2
        ;;
      --s3-bucket)
        [[ $# -ge 2 ]] || die "missing value for --s3-bucket"
        s3_bucket="$2"
        shift 2
        ;;
      --s3-key-prefix)
        [[ $# -ge 2 ]] || die "missing value for --s3-key-prefix"
        s3_key_prefix="$2"
        shift 2
        ;;
      --s3-key)
        [[ $# -ge 2 ]] || die "missing value for --s3-key"
        s3_key="$2"
        shift 2
        ;;
      --s3-sse-kms-key-id)
        [[ $# -ge 2 ]] || die "missing value for --s3-sse-kms-key-id"
        s3_sse_kms_key_id="$2"
        shift 2
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
      --skip-aws-preflight)
        skip_aws_preflight="true"
        shift
        ;;
      --backup-age-recipient)
        [[ $# -ge 2 ]] || die "missing value for --backup-age-recipient"
        backup_age_recipients+=("$2")
        shift 2
        ;;
      --backup-out)
        [[ $# -ge 2 ]] || die "missing value for --backup-out"
        backup_out="$2"
        shift 2
        ;;
      --force)
        force="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for export: $1"
        ;;
    esac
  done

  [[ -n "$kms_key_id" ]] || die "--kms-key-id is required"
  [[ -n "$s3_bucket" ]] || die "--s3-bucket is required"
  [[ -n "$s3_sse_kms_key_id" ]] || die "--s3-sse-kms-key-id is required"

  ensure_base_dependencies
  ensure_dir "$workdir/bin"
  ensure_dir "$workdir/exports"

  local config_path="$workdir/bundle/admin-config.json"
  [[ -f "$config_path" ]] || die "missing operator config: $config_path"

  local operator_id ceremony_id identifier
  operator_id="$(jq -r '.operator_id // ""' "$config_path")"
  ceremony_id="$(jq -r '.ceremony_id // ""' "$config_path")"
  identifier="$(jq -r '.identifier // ""' "$config_path")"
  [[ -n "$operator_id" ]] || die "operator_id missing in $config_path"
  [[ -n "$ceremony_id" ]] || die "ceremony_id missing in $config_path"
  [[ -n "$identifier" ]] || die "identifier missing in $config_path"

  if [[ -z "$s3_key" ]]; then
    s3_key="$(build_export_s3_key "$s3_key_prefix" "$ceremony_id" "$operator_id" "$identifier")"
  fi

  if [[ "$skip_aws_preflight" != "true" ]]; then
    aws_preflight "$kms_key_id" "$s3_bucket" "$aws_profile" "$aws_region"
  fi

  local dkg_admin_bin
  dkg_admin_bin="$(ensure_dkg_binary "dkg-admin" "$release_tag" "$workdir/bin")"

  local stamp kms_receipt
  stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
  kms_receipt="$workdir/exports/kms-export-receipt-${stamp}.json"

  run_dkg_admin_export \
    "$dkg_admin_bin" \
    "$config_path" \
    "$aws_profile" \
    "$aws_region" \
    --kms-key-id "$kms_key_id" \
    --s3-bucket "$s3_bucket" \
    --s3-key "$s3_key" \
    --s3-sse-kms-key-id "$s3_sse_kms_key_id" | tee "$kms_receipt"

  log "kms export complete"
  log "operator_id=$operator_id"
  log "ceremony_id=$ceremony_id"
  log "s3://${s3_bucket}/${s3_key}"
  log "kms_receipt=$kms_receipt"

  if (( ${#backup_age_recipients[@]} > 0 )); then
    if [[ -z "$backup_out" ]]; then
      backup_out="$workdir/exports/keypackage-backup-${identifier}.json"
    fi
    ensure_dir "$(dirname "$backup_out")"
    if [[ -f "$backup_out" && "$force" != "true" ]]; then
      die "backup file exists (use --force to overwrite): $backup_out"
    fi

    local -a backup_args=()
    local recipient
    for recipient in "${backup_age_recipients[@]}"; do
      backup_args+=(--age-recipient "$recipient")
    done

    local age_receipt
    age_receipt="$workdir/exports/age-export-receipt-${stamp}.json"
    run_dkg_admin_export \
      "$dkg_admin_bin" \
      "$config_path" \
      "$aws_profile" \
      "$aws_region" \
      "${backup_args[@]}" \
      --out "$backup_out" | tee "$age_receipt"

    log "age backup export complete"
    log "backup_out=$backup_out"
    log "age_receipt=$age_receipt"
  fi
}

command_age_recipient() {
  shift || true

  local identity_file="$JUNO_DKG_HOME_DEFAULT/backup/age-identity.txt"
  local output_path="-"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --identity-file)
        [[ $# -ge 2 ]] || die "missing value for --identity-file"
        identity_file="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output_path="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for age-recipient: $1"
        ;;
    esac
  done

  ensure_base_dependencies
  ensure_command age-keygen
  have_cmd age-keygen || die "age-keygen command not found after install"

  local created="false"
  if [[ ! -f "$identity_file" ]]; then
    ensure_dir "$(dirname "$identity_file")"
    age-keygen -o "$identity_file" >/dev/null
    chmod 0600 "$identity_file" || true
    created="true"
  fi

  local recipient
  recipient="$(age-keygen -y "$identity_file" | tr -d '\r\n')"
  [[ "$recipient" =~ ^age1[0-9a-z]+$ ]] || die "invalid recipient derived from $identity_file"

  local payload
  payload="$(jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg identity_file "$identity_file" \
    --arg recipient "$recipient" \
    --arg created "$created" \
    '{
      generated_at: $generated_at,
      identity_file: $identity_file,
      age_recipient: $recipient,
      identity_created: ($created == "true")
    }')"

  if [[ "$output_path" == "-" ]]; then
    printf '%s\n' "$payload"
  else
    ensure_dir "$(dirname "$output_path")"
    printf '%s\n' "$payload" >"$output_path"
    chmod 0644 "$output_path"
    log "wrote age recipient payload: $output_path"
  fi
}

main() {
  local cmd="${1:-export}"
  case "$cmd" in
    export) command_export "$@" ;;
    age-recipient) command_age_recipient "$@" ;;
    -h|--help)
      usage
      ;;
    --*)
      set -- "export" "$@"
      command_export "$@"
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

main "$@"
