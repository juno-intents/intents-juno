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
  backup-package.sh restore [options]

Options:
  create:
  --workdir <path>                  operator runtime dir (default: ~/.juno-dkg/operator-runtime)
  --age-identity-file <path>        default ~/.juno-dkg/backup/age-identity.txt
  --age-backup-file <path>          default ~/.juno-dkg/exports/keypackage-backup.json
  --age-backup-receipt <path>       default <age-backup-file>.KeyImportReceipt.json
  --admin-config <path>             default <workdir>/bundle/admin-config.json
  --completion-report <path>        optional test-completiton.json path
  --output <path>                   default ~/.juno-dkg/backup-packages/dkg-backup-<operator>-<ts>.zip
  --force                           overwrite --output when it already exists

  restore:
  --package <path>                  required backup zip path created by `backup-package.sh create`
  --workdir <path>                  target operator runtime dir (default: ~/.juno-dkg/operator-runtime)
  --report <path>                   restore report json path (default: <workdir>/restore-report.json)
  --force                           overwrite --workdir when it already exists

Notes:
  - restore reconstructs:
      <workdir>/bundle/admin-config.json
      <workdir>/bundle/state/key_package.bin
      <workdir>/bundle/state/public_key_package.bin
      <workdir>/bundle/tls/{ca.pem,server.pem,server.key}
  - if TLS files are absent in the backup zip, restore generates fresh self-signed TLS certs.
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

ensure_unzip_command() {
  if have_cmd unzip; then
    return
  fi

  local os
  os="$(detect_os)"
  log "installing missing dependency: unzip"
  if [[ "$os" == "darwin" ]]; then
    brew_install_formula unzip || die "failed to install unzip"
  else
    apt_install unzip || die "failed to install unzip"
  fi
  have_cmd unzip || die "unzip command still missing after install attempt"
}

ensure_openssl_command() {
  if have_cmd openssl; then
    return
  fi

  local os
  os="$(detect_os)"
  log "installing missing dependency: openssl"
  if [[ "$os" == "darwin" ]]; then
    brew_install_formula openssl || die "failed to install openssl"
  else
    apt_install openssl || die "failed to install openssl"
  fi
  have_cmd openssl || die "openssl command still missing after install attempt"
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

command_create() {
  shift || true

  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local age_identity_file="$JUNO_DKG_HOME_DEFAULT/backup/age-identity.txt"
  local age_backup_file="$JUNO_DKG_HOME_DEFAULT/exports/keypackage-backup.json"
  local age_backup_receipt=""
  local admin_config_path=""
  local completion_report=""
  local tls_ca_path=""
  local tls_server_cert_path=""
  local tls_server_key_path=""
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
  tls_ca_path="$workdir/bundle/tls/ca.pem"
  tls_server_cert_path="$workdir/bundle/tls/server.pem"
  tls_server_key_path="$workdir/bundle/tls/server.key"

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
  local tls_included="false"
  if [[ -n "$completion_report" ]]; then
    completion_included="true"
  fi
  if [[ -f "$tls_ca_path" && -f "$tls_server_cert_path" && -f "$tls_server_key_path" ]]; then
    tls_included="true"
    ensure_dir "$tmp_dir/payload/tls"
    cp "$tls_ca_path" "$tmp_dir/payload/tls/ca.pem"
    cp "$tls_server_cert_path" "$tmp_dir/payload/tls/server.pem"
    cp "$tls_server_key_path" "$tmp_dir/payload/tls/server.key"
    chmod 0600 "$tmp_dir/payload/tls/server.key" || true
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
    --arg tls_ca_path "$tls_ca_path" \
    --arg tls_server_cert_path "$tls_server_cert_path" \
    --arg tls_server_key_path "$tls_server_key_path" \
    --arg tls_included "$tls_included" \
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
        ),
        tls_ca_cert: (
          if $tls_included == "true" then "payload/tls/ca.pem" else null end
        ),
        tls_server_cert: (
          if $tls_included == "true" then "payload/tls/server.pem" else null end
        ),
        tls_server_key: (
          if $tls_included == "true" then "payload/tls/server.key" else null end
        )
      },
      source_paths: {
        age_identity_file: $age_identity_file,
        age_backup_file: $age_backup_file,
        age_backup_receipt: $age_backup_receipt,
        admin_config: $admin_config,
        completion_report: (
          if $completion_included == "true" then $completion_report else null end
        ),
        tls_ca_cert: (
          if $tls_included == "true" then $tls_ca_path else null end
        ),
        tls_server_cert: (
          if $tls_included == "true" then $tls_server_cert_path else null end
        ),
        tls_server_key: (
          if $tls_included == "true" then $tls_server_key_path else null end
        )
      }
    }' >"$tmp_dir/manifest.json"

  (
    cd "$tmp_dir"
    zip -r "$output" manifest.json payload >/dev/null
  )

  log "backup package created: $output"
}

write_self_signed_tls_material() {
  local tls_dir="$1"

  ensure_openssl_command
  ensure_dir "$tls_dir"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'if [[ -n "${tmp_dir:-}" ]]; then rm -rf "$tmp_dir"; fi' RETURN

  cat >"$tmp_dir/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$tmp_dir/ca.key" \
    -out "$tls_dir/ca.pem" \
    -days 3650 \
    -subj "/CN=Juno DKG Restore CA" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/server.key" \
    -out "$tmp_dir/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1

  openssl x509 -req \
    -in "$tmp_dir/server.csr" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tmp_dir/ca.key" \
    -CAcreateserial \
    -out "$tls_dir/server.pem" \
    -days 3650 \
    -sha256 \
    -extfile "$tmp_dir/server.ext" >/dev/null 2>&1

  chmod 0600 "$tls_dir/server.key" || true
}

normalize_restored_admin_config() {
  local config_path="$1"
  local tmp_path
  tmp_path="$(mktemp)"
  jq '
    .state_dir = (
      if (.state_dir // "" | tostring | length) == 0
      then "./state"
      else .state_dir
      end
    )
    | .grpc = (
      if .grpc == null then
        {
          listen_addr: "0.0.0.0:8443",
          tls_ca_cert_pem_path: "./tls/ca.pem",
          tls_server_cert_pem_path: "./tls/server.pem",
          tls_server_key_pem_path: "./tls/server.key",
          coordinator_client_cert_sha256: null
        }
      else
        (.grpc + {
          tls_ca_cert_pem_path: "./tls/ca.pem",
          tls_server_cert_pem_path: "./tls/server.pem",
          tls_server_key_pem_path: "./tls/server.key"
        })
      end
    )
  ' "$config_path" >"$tmp_path"
  mv "$tmp_path" "$config_path"
}

command_restore() {
  shift || true

  local package_path=""
  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local report_path=""
  local force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --package)
        [[ $# -ge 2 ]] || die "missing value for --package"
        package_path="$2"
        shift 2
        ;;
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --report)
        [[ $# -ge 2 ]] || die "missing value for --report"
        report_path="$2"
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
        die "unknown argument for restore: $1"
        ;;
    esac
  done

  [[ -n "$package_path" ]] || die "--package is required"
  [[ -f "$package_path" ]] || die "backup package not found: $package_path"

  ensure_base_dependencies
  ensure_unzip_command
  ensure_command age

  if [[ -e "$workdir" ]]; then
    if [[ "$force" != "true" ]]; then
      die "workdir already exists (use --force to overwrite): $workdir"
    fi
    rm -rf "$workdir"
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'if [[ -n "${tmp_dir:-}" ]]; then rm -rf "$tmp_dir"; fi' RETURN

  local extract_dir payload_dir
  extract_dir="$tmp_dir/extracted"
  payload_dir="$extract_dir/payload"
  ensure_dir "$extract_dir"
  unzip -q "$package_path" -d "$extract_dir"

  local age_identity_file age_backup_file admin_config_backup
  age_identity_file="$payload_dir/age-identity.txt"
  age_backup_file="$payload_dir/keypackage-backup.json"
  admin_config_backup="$payload_dir/admin-config.json"
  [[ -f "$age_identity_file" ]] || die "restore package missing payload/age-identity.txt"
  [[ -f "$age_backup_file" ]] || die "restore package missing payload/keypackage-backup.json"
  [[ -f "$admin_config_backup" ]] || die "restore package missing payload/admin-config.json"

  local bundle_dir config_path state_dir tls_dir
  bundle_dir="$workdir/bundle"
  config_path="$bundle_dir/admin-config.json"
  state_dir="$bundle_dir/state"
  tls_dir="$bundle_dir/tls"
  ensure_dir "$state_dir"
  ensure_dir "$tls_dir"

  cp "$admin_config_backup" "$config_path"
  normalize_restored_admin_config "$config_path"

  local backend ciphertext_b64
  backend="$(jq -r '.encryption_backend // ""' "$age_backup_file")"
  [[ "$backend" == "age" ]] || die "age backup file is not age-encrypted"
  ciphertext_b64="$(jq -r '.ciphertext_b64 // ""' "$age_backup_file")"
  [[ -n "$ciphertext_b64" ]] || die "age backup missing ciphertext_b64"

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
  c_operator_id="$(jq -r '.operator_id // ""' "$config_path")"
  c_identifier="$(jq -r '.identifier // ""' "$config_path")"
  c_threshold="$(jq -r '.threshold // ""' "$config_path")"
  c_max_signers="$(jq -r '.max_signers // ""' "$config_path")"
  c_network="$(jq -r '.network // ""' "$config_path")"
  c_roster_hash="$(jq -r '.roster_hash_hex // ""' "$config_path")"
  c_ceremony_id="$(jq -r '.ceremony_id // ""' "$config_path")"
  [[ "$p_operator_id" == "$c_operator_id" ]] || die "operator_id mismatch between age backup and admin config"
  [[ "$p_identifier" == "$c_identifier" ]] || die "identifier mismatch between age backup and admin config"
  [[ "$p_threshold" == "$c_threshold" ]] || die "threshold mismatch between age backup and admin config"
  [[ "$p_max_signers" == "$c_max_signers" ]] || die "max_signers mismatch between age backup and admin config"
  [[ "$p_network" == "$c_network" ]] || die "network mismatch between age backup and admin config"
  [[ "$p_roster_hash" == "$c_roster_hash" ]] || die "roster_hash mismatch between age backup and admin config"
  [[ -n "$c_ceremony_id" ]] || die "admin config missing ceremony_id"

  decode_base64_to_file "$p_key_package_b64" "$state_dir/key_package.bin"
  decode_base64_to_file "$p_public_key_package_b64" "$state_dir/public_key_package.bin"

  local tls_source="generated"
  if [[ -f "$payload_dir/tls/ca.pem" && -f "$payload_dir/tls/server.pem" && -f "$payload_dir/tls/server.key" ]]; then
    cp "$payload_dir/tls/ca.pem" "$tls_dir/ca.pem"
    cp "$payload_dir/tls/server.pem" "$tls_dir/server.pem"
    cp "$payload_dir/tls/server.key" "$tls_dir/server.key"
    chmod 0600 "$tls_dir/server.key" || true
    tls_source="package"
  else
    write_self_signed_tls_material "$tls_dir"
  fi

  if [[ -z "$report_path" ]]; then
    report_path="$workdir/restore-report.json"
  fi
  ensure_dir "$(dirname "$report_path")"
  jq -n \
    --arg restored_at "$(timestamp_utc)" \
    --arg workdir "$workdir" \
    --arg package_path "$package_path" \
    --arg operator_id "$c_operator_id" \
    --arg ceremony_id "$c_ceremony_id" \
    --arg tls_source "$tls_source" \
    --arg admin_config_path "$config_path" \
    --arg state_dir "$state_dir" \
    '{
      restore_version: 1,
      restored_at: $restored_at,
      package_path: $package_path,
      workdir: $workdir,
      operator_id: $operator_id,
      ceremony_id: $ceremony_id,
      tls_source: $tls_source,
      admin_config_path: $admin_config_path,
      state_dir: $state_dir
    }' >"$report_path"

  log "backup package restored"
  log "workdir=$workdir"
  log "operator_id=$c_operator_id"
  log "report=$report_path"
}

main() {
  local cmd="${1:-create}"
  case "$cmd" in
    create) command_create "$@" ;;
    restore) command_restore "$@" ;;
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
