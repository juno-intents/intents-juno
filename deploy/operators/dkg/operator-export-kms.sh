#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  operator-export-kms.sh export [options]
  operator-export-kms.sh backup-age [options]
  operator-export-kms.sh rewrap-age-to-kms [options]
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

  backup-age:
    --workdir <path>                operator runtime dir (default: ~/.juno-dkg/operator-runtime)
    --release-tag <tag>             dkg-admin release tag (default: v0.1.0)
    --age-recipient <age1..>        required, repeatable
    --out <path>                    required output path for encrypted age backup
    --force                         allow overwriting --out when it exists

  rewrap-age-to-kms:
    --release-tag <tag>             dkg-admin release tag (default: v0.1.0)
    --age-backup-file <path>        required age backup file created by backup-age/export
    --age-identity-file <path>      required age private identity file used to decrypt backup
    --admin-config <path>           required admin-config.json backup from operator bundle
    --kms-key-id <arn>              required
    --s3-bucket <name>              required
    --s3-sse-kms-key-id <arn>       required
    --s3-key-prefix <prefix>        default dkg/keypackages
    --s3-key <key>                  optional explicit object key override
    --aws-profile <name>            optional AWS profile used for preflight + export
    --aws-region <name>             optional AWS region used for preflight + export
    --skip-aws-preflight            skip aws sts/kms/s3 validation checks

Notes:
  - `export` reads operator metadata from <workdir>/bundle/admin-config.json.
  - `rewrap-age-to-kms` works from backup artifacts (age backup + age identity + admin-config backup), not runtime state.
  - Exported key package plaintext never leaves this machine.
EOF
}

run_dkg_admin_export() {
  local dkg_admin_bin="$1"
  local config_path="$2"
  local aws_profile="$3"
  local aws_region="$4"
  shift 4

  local config_dir config_file
  config_dir="$(cd "$(dirname "$config_path")" && pwd)"
  config_file="$(basename "$config_path")"

  local -a env_args=()
  if [[ -n "$aws_profile" ]]; then
    env_args+=("AWS_PROFILE=$aws_profile")
  fi
  if [[ -n "$aws_region" ]]; then
    env_args+=("AWS_REGION=$aws_region")
  fi

  if (( ${#env_args[@]} > 0 )); then
    (
      cd "$config_dir"
      env "${env_args[@]}" "$dkg_admin_bin" --config "./$config_file" export-key-package "$@"
    )
    return
  fi
  (
    cd "$config_dir"
    "$dkg_admin_bin" --config "./$config_file" export-key-package "$@"
  )
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

decode_base64_to_file() {
  local input="$1"
  local out_path="$2"

  if printf '%s' "$input" | base64 --decode >"$out_path" 2>/dev/null; then
    return
  fi
  if printf '%s' "$input" | base64 -D >"$out_path" 2>/dev/null; then
    return
  fi
  if have_cmd openssl; then
    if printf '%s' "$input" | openssl base64 -d -A >"$out_path" 2>/dev/null; then
      return
    fi
  fi
  die "base64 decode failed"
}

command_rewrap_age_to_kms() {
  shift || true

  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local age_backup_file=""
  local age_identity_file=""
  local admin_config_path=""
  local kms_key_id=""
  local s3_bucket=""
  local s3_key_prefix="dkg/keypackages"
  local s3_key=""
  local s3_sse_kms_key_id=""
  local aws_profile=""
  local aws_region=""
  local skip_aws_preflight="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --age-backup-file)
        [[ $# -ge 2 ]] || die "missing value for --age-backup-file"
        age_backup_file="$2"
        shift 2
        ;;
      --age-identity-file)
        [[ $# -ge 2 ]] || die "missing value for --age-identity-file"
        age_identity_file="$2"
        shift 2
        ;;
      --admin-config)
        [[ $# -ge 2 ]] || die "missing value for --admin-config"
        admin_config_path="$2"
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
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for rewrap-age-to-kms: $1"
        ;;
    esac
  done

  [[ -f "$age_backup_file" ]] || die "--age-backup-file not found: $age_backup_file"
  [[ -f "$age_identity_file" ]] || die "--age-identity-file not found: $age_identity_file"
  [[ -f "$admin_config_path" ]] || die "--admin-config not found: $admin_config_path"
  [[ -n "$kms_key_id" ]] || die "--kms-key-id is required"
  [[ -n "$s3_bucket" ]] || die "--s3-bucket is required"
  [[ -n "$s3_sse_kms_key_id" ]] || die "--s3-sse-kms-key-id is required"

  ensure_base_dependencies
  ensure_command age
  ensure_dir "$JUNO_DKG_HOME_DEFAULT/bin"
  ensure_dir "$JUNO_DKG_HOME_DEFAULT/exports"

  local backend ciphertext_b64
  backend="$(jq -r '.encryption_backend // ""' "$age_backup_file")"
  [[ "$backend" == "age" ]] || die "age backup file is not age-encrypted"
  ciphertext_b64="$(jq -r '.ciphertext_b64 // ""' "$age_backup_file")"
  [[ -n "$ciphertext_b64" ]] || die "age backup missing ciphertext_b64"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'if [[ -n "${tmp_dir:-}" ]]; then rm -rf "$tmp_dir"; fi' RETURN

  decode_base64_to_file "$ciphertext_b64" "$tmp_dir/ciphertext.age"
  age --decrypt -i "$age_identity_file" "$tmp_dir/ciphertext.age" >"$tmp_dir/plaintext.json" \
    || die "failed to decrypt age backup with provided identity"

  local p_operator_id p_identifier p_threshold p_max_signers p_network p_roster_hash
  local p_key_package_b64 p_public_key_package_b64
  p_operator_id="$(jq -r '.operator_id // ""' "$tmp_dir/plaintext.json")"
  p_identifier="$(jq -r '.identifier // ""' "$tmp_dir/plaintext.json")"
  p_threshold="$(jq -r '.threshold // ""' "$tmp_dir/plaintext.json")"
  p_max_signers="$(jq -r '.max_signers // ""' "$tmp_dir/plaintext.json")"
  p_network="$(jq -r '.network // ""' "$tmp_dir/plaintext.json")"
  p_roster_hash="$(jq -r '.roster_hash_hex // ""' "$tmp_dir/plaintext.json")"
  p_key_package_b64="$(jq -r '.key_package_bytes_b64 // ""' "$tmp_dir/plaintext.json")"
  p_public_key_package_b64="$(jq -r '.public_key_package_bytes_b64 // ""' "$tmp_dir/plaintext.json")"
  [[ -n "$p_operator_id" ]] || die "decrypted backup missing operator_id"
  [[ -n "$p_identifier" ]] || die "decrypted backup missing identifier"
  [[ -n "$p_threshold" ]] || die "decrypted backup missing threshold"
  [[ -n "$p_max_signers" ]] || die "decrypted backup missing max_signers"
  [[ -n "$p_network" ]] || die "decrypted backup missing network"
  [[ -n "$p_roster_hash" ]] || die "decrypted backup missing roster_hash_hex"
  [[ -n "$p_key_package_b64" ]] || die "decrypted backup missing key_package_bytes_b64"
  [[ -n "$p_public_key_package_b64" ]] || die "decrypted backup missing public_key_package_bytes_b64"

  local c_operator_id c_identifier c_threshold c_max_signers c_network c_roster_hash c_ceremony_id
  c_operator_id="$(jq -r '.operator_id // ""' "$admin_config_path")"
  c_identifier="$(jq -r '.identifier // ""' "$admin_config_path")"
  c_threshold="$(jq -r '.threshold // ""' "$admin_config_path")"
  c_max_signers="$(jq -r '.max_signers // ""' "$admin_config_path")"
  c_network="$(jq -r '.network // ""' "$admin_config_path")"
  c_roster_hash="$(jq -r '.roster_hash_hex // ""' "$admin_config_path")"
  c_ceremony_id="$(jq -r '.ceremony_id // ""' "$admin_config_path")"

  [[ "$p_operator_id" == "$c_operator_id" ]] || die "operator_id mismatch between age backup and admin config"
  [[ "$p_identifier" == "$c_identifier" ]] || die "identifier mismatch between age backup and admin config"
  [[ "$p_threshold" == "$c_threshold" ]] || die "threshold mismatch between age backup and admin config"
  [[ "$p_max_signers" == "$c_max_signers" ]] || die "max_signers mismatch between age backup and admin config"
  [[ "$p_network" == "$c_network" ]] || die "network mismatch between age backup and admin config"
  [[ "$p_roster_hash" == "$c_roster_hash" ]] || die "roster_hash mismatch between age backup and admin config"
  [[ -n "$c_ceremony_id" ]] || die "admin config missing ceremony_id"

  ensure_dir "$tmp_dir/state"
  decode_base64_to_file "$p_key_package_b64" "$tmp_dir/state/key_package.bin"
  decode_base64_to_file "$p_public_key_package_b64" "$tmp_dir/state/public_key_package.bin"

  jq -n \
    --slurpfile cfg "$admin_config_path" \
    --arg state_dir "$tmp_dir/state" \
    '{
      config_version: ($cfg[0].config_version // 1),
      ceremony_id: $cfg[0].ceremony_id,
      operator_id: $cfg[0].operator_id,
      identifier: $cfg[0].identifier,
      threshold: $cfg[0].threshold,
      max_signers: $cfg[0].max_signers,
      network: $cfg[0].network,
      roster: $cfg[0].roster,
      roster_hash_hex: $cfg[0].roster_hash_hex,
      state_dir: $state_dir,
      age_identity_file: null,
      grpc: null
    }' >"$tmp_dir/config.json"

  if [[ -z "$s3_key" ]]; then
    s3_key="$(build_export_s3_key "$s3_key_prefix" "$c_ceremony_id" "$c_operator_id" "$c_identifier")"
  fi

  if [[ "$skip_aws_preflight" != "true" ]]; then
    aws_preflight "$kms_key_id" "$s3_bucket" "$aws_profile" "$aws_region"
  fi

  local dkg_admin_bin
  dkg_admin_bin="$(ensure_dkg_binary "dkg-admin" "$release_tag" "$JUNO_DKG_HOME_DEFAULT/bin")"

  local stamp kms_receipt
  stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
  kms_receipt="$JUNO_DKG_HOME_DEFAULT/exports/kms-rewrap-receipt-${stamp}.json"
  run_dkg_admin_export \
    "$dkg_admin_bin" \
    "$tmp_dir/config.json" \
    "$aws_profile" \
    "$aws_region" \
    --kms-key-id "$kms_key_id" \
    --s3-bucket "$s3_bucket" \
    --s3-key "$s3_key" \
    --s3-sse-kms-key-id "$s3_sse_kms_key_id" | tee "$kms_receipt"

  log "kms rewrap export complete"
  log "operator_id=$c_operator_id"
  log "ceremony_id=$c_ceremony_id"
  log "s3://${s3_bucket}/${s3_key}"
  log "kms_receipt=$kms_receipt"
}

command_backup_age() {
  shift || true

  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local out_path=""
  local force="false"
  local age_recipients=()

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
      --age-recipient)
        [[ $# -ge 2 ]] || die "missing value for --age-recipient"
        age_recipients+=("$2")
        shift 2
        ;;
      --out)
        [[ $# -ge 2 ]] || die "missing value for --out"
        out_path="$2"
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
        die "unknown argument for backup-age: $1"
        ;;
    esac
  done

  (( ${#age_recipients[@]} > 0 )) || die "at least one --age-recipient is required"
  [[ -n "$out_path" ]] || die "--out is required"

  local config_path="$workdir/bundle/admin-config.json"
  [[ -f "$config_path" ]] || die "missing operator config: $config_path"

  ensure_base_dependencies
  ensure_dir "$workdir/bin"
  ensure_dir "$(dirname "$out_path")"
  if [[ -f "$out_path" && "$force" != "true" ]]; then
    die "output exists (use --force to overwrite): $out_path"
  fi

  local dkg_admin_bin
  dkg_admin_bin="$(ensure_dkg_binary "dkg-admin" "$release_tag" "$workdir/bin")"

  local -a age_args=()
  local recipient
  for recipient in "${age_recipients[@]}"; do
    age_args+=(--age-recipient "$recipient")
  done

  local stamp age_receipt_log
  stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
  ensure_dir "$workdir/exports"
  age_receipt_log="$workdir/exports/age-export-receipt-${stamp}.json"
  run_dkg_admin_export \
    "$dkg_admin_bin" \
    "$config_path" \
    "" \
    "" \
    "${age_args[@]}" \
    --out "$out_path" | tee "$age_receipt_log"

  log "age backup export complete"
  log "backup_out=$out_path"
  log "age_receipt=$age_receipt_log"
  log "backup_receipt=${out_path}.KeyImportReceipt.json"
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
    backup-age) command_backup_age "$@" ;;
    rewrap-age-to-kms) command_rewrap_age_to_kms "$@" ;;
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
