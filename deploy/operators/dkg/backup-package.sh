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
  backup-package.sh create [options]

Options:
  --workdir <path>                  operator runtime dir (default: ~/.juno-dkg/operator-runtime)
  --age-identity-file <path>        default ~/.juno-dkg/backup/age-identity.txt
  --age-backup-file <path>          default ~/.juno-dkg/exports/keypackage-backup.json
  --age-backup-receipt <path>       default <age-backup-file>.KeyImportReceipt.json
  --admin-config <path>             default <workdir>/bundle/admin-config.json
  --completion-report <path>        optional test-completiton.json path
  --output <path>                   default ~/.juno-dkg/backup-packages/dkg-backup-<operator>-<ts>.zip
  --force                           overwrite --output when it already exists
EOF
}

ensure_zip_command() {
  if have_cmd zip; then
    return
  fi

  local os
  os="$(detect_os)"
  log "installing missing dependency: zip"
  if [[ "$os" == "darwin" ]]; then
    brew_install_formula zip || die "failed to install zip"
  else
    apt_install zip || die "failed to install zip"
  fi
  have_cmd zip || die "zip command still missing after install attempt"
}

command_create() {
  shift || true

  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local age_identity_file="$JUNO_DKG_HOME_DEFAULT/backup/age-identity.txt"
  local age_backup_file="$JUNO_DKG_HOME_DEFAULT/exports/keypackage-backup.json"
  local age_backup_receipt=""
  local admin_config_path=""
  local completion_report=""
  local output=""
  local force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --age-identity-file)
        [[ $# -ge 2 ]] || die "missing value for --age-identity-file"
        age_identity_file="$2"
        shift 2
        ;;
      --age-backup-file)
        [[ $# -ge 2 ]] || die "missing value for --age-backup-file"
        age_backup_file="$2"
        shift 2
        ;;
      --age-backup-receipt)
        [[ $# -ge 2 ]] || die "missing value for --age-backup-receipt"
        age_backup_receipt="$2"
        shift 2
        ;;
      --admin-config)
        [[ $# -ge 2 ]] || die "missing value for --admin-config"
        admin_config_path="$2"
        shift 2
        ;;
      --completion-report)
        [[ $# -ge 2 ]] || die "missing value for --completion-report"
        completion_report="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output="$2"
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
        die "unknown argument for create: $1"
        ;;
    esac
  done

  if [[ -z "$age_backup_receipt" ]]; then
    age_backup_receipt="${age_backup_file}.KeyImportReceipt.json"
  fi
  if [[ -z "$admin_config_path" ]]; then
    admin_config_path="$workdir/bundle/admin-config.json"
  fi

  [[ -f "$age_identity_file" ]] || die "age identity file not found: $age_identity_file"
  [[ -f "$age_backup_file" ]] || die "age backup file not found: $age_backup_file"
  [[ -f "$age_backup_receipt" ]] || die "age backup receipt not found: $age_backup_receipt"
  [[ -f "$admin_config_path" ]] || die "admin config not found: $admin_config_path"
  if [[ -n "$completion_report" ]]; then
    [[ -f "$completion_report" ]] || die "completion report not found: $completion_report"
  fi

  ensure_base_dependencies
  ensure_zip_command

  local operator_id identifier ceremony_id stamp operator_slug
  operator_id="$(jq -r '.operator_id // ""' "$admin_config_path")"
  identifier="$(jq -r '.identifier // ""' "$admin_config_path")"
  ceremony_id="$(jq -r '.ceremony_id // ""' "$admin_config_path")"
  [[ -n "$operator_id" ]] || die "admin config missing operator_id"
  [[ -n "$identifier" ]] || die "admin config missing identifier"
  [[ -n "$ceremony_id" ]] || die "admin config missing ceremony_id"

  stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
  operator_slug="$(safe_slug "$operator_id")"
  if [[ -z "$output" ]]; then
    output="$JUNO_DKG_HOME_DEFAULT/backup-packages/dkg-backup-${operator_slug}-${stamp}.zip"
  fi
  ensure_dir "$(dirname "$output")"
  if [[ -f "$output" && "$force" != "true" ]]; then
    die "output already exists (use --force to overwrite): $output"
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'if [[ -n "${tmp_dir:-}" ]]; then rm -rf "$tmp_dir"; fi' RETURN
  ensure_dir "$tmp_dir/payload"

  cp "$age_identity_file" "$tmp_dir/payload/age-identity.txt"
  cp "$age_backup_file" "$tmp_dir/payload/keypackage-backup.json"
  cp "$age_backup_receipt" "$tmp_dir/payload/keypackage-backup.json.KeyImportReceipt.json"
  cp "$admin_config_path" "$tmp_dir/payload/admin-config.json"
  if [[ -n "$completion_report" ]]; then
    cp "$completion_report" "$tmp_dir/payload/test-completiton.json"
  fi

  local completion_included="false"
  if [[ -n "$completion_report" ]]; then
    completion_included="true"
  fi

  jq -n \
    --arg report_created_at "$(timestamp_utc)" \
    --arg operator_id "$operator_id" \
    --argjson identifier "$identifier" \
    --arg ceremony_id "$ceremony_id" \
    --arg age_identity_file "$age_identity_file" \
    --arg age_backup_file "$age_backup_file" \
    --arg age_backup_receipt "$age_backup_receipt" \
    --arg admin_config "$admin_config_path" \
    --arg completion_report "$completion_report" \
    --arg completion_included "$completion_included" \
    '{
      package_version: 1,
      created_at: $report_created_at,
      operator_id: $operator_id,
      identifier: $identifier,
      ceremony_id: $ceremony_id,
      includes: {
        age_identity_file: "payload/age-identity.txt",
        age_backup_file: "payload/keypackage-backup.json",
        age_backup_receipt: "payload/keypackage-backup.json.KeyImportReceipt.json",
        admin_config: "payload/admin-config.json",
        completion_report: (
          if $completion_included == "true" then "payload/test-completiton.json" else null end
        )
      },
      source_paths: {
        age_identity_file: $age_identity_file,
        age_backup_file: $age_backup_file,
        age_backup_receipt: $age_backup_receipt,
        admin_config: $admin_config,
        completion_report: (
          if $completion_included == "true" then $completion_report else null end
        )
      }
    }' >"$tmp_dir/manifest.json"

  (
    cd "$tmp_dir"
    zip -r "$output" manifest.json payload >/dev/null
  )

  log "backup package created: $output"
}

main() {
  local cmd="${1:-create}"
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
