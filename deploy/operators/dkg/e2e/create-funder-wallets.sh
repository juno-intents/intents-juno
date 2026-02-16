#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  create-funder-wallets.sh create [options]

Options:
  --out-dir <path>            output directory (default: <repo>/tmp/funders)
  --base-key-file <path>      base funder private key file (default: <out-dir>/base-funder.key)
  --juno-key-file <path>      juno funder private key file (default: <out-dir>/juno-funder.key)
  --report <path>             output json report (default: <out-dir>/funder-wallets.json)
  --force                     overwrite existing report

Notes:
  - Keys are secp256k1 private keys in hex (0x...).
  - The Base funder key is used directly by the e2e workflow.
  - The Juno funder key is saved for future Juno-chain funding steps.
  - A Juno testnet transparent address and WIF are derived into the report/out-dir.
EOF
}

command_create() {
  shift || true

  local out_dir="$REPO_ROOT/tmp/funders"
  local base_key_file=""
  local juno_key_file=""
  local report_path=""
  local force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir)
        [[ $# -ge 2 ]] || die "missing value for --out-dir"
        out_dir="$2"
        shift 2
        ;;
      --base-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-key-file"
        base_key_file="$2"
        shift 2
        ;;
      --juno-key-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-key-file"
        juno_key_file="$2"
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
        die "unknown argument for create: $1"
        ;;
    esac
  done

  if [[ -z "$base_key_file" ]]; then
    base_key_file="$out_dir/base-funder.key"
  fi
  if [[ -z "$juno_key_file" ]]; then
    juno_key_file="$out_dir/juno-funder.key"
  fi
  if [[ -z "$report_path" ]]; then
    report_path="$out_dir/funder-wallets.json"
  fi

  ensure_base_dependencies
  ensure_command go
  ensure_dir "$out_dir"

  if [[ -f "$report_path" && "$force" != "true" ]]; then
    die "report already exists (use --force to overwrite): $report_path"
  fi

  local base_meta juno_meta juno_testnet_meta juno_wif_file
  base_meta="$out_dir/base-funder.meta.json"
  juno_meta="$out_dir/juno-funder.meta.json"
  juno_testnet_meta="$out_dir/juno-funder.testnet.meta.json"
  juno_wif_file="$out_dir/juno-funder.wif"

  (
    cd "$REPO_ROOT"
    go run ./cmd/operator-keygen -private-key-path "$base_key_file" >"$base_meta"
    go run ./cmd/operator-keygen -private-key-path "$juno_key_file" >"$juno_meta"
    go run ./cmd/juno-keyinfo \
      --private-key-file "$juno_key_file" \
      --network testnet \
      --wif-output "$juno_wif_file" >"$juno_testnet_meta"
  )

  chmod 0600 "$base_key_file" "$juno_key_file" "$juno_wif_file" || true

  local base_address juno_address juno_taddr
  base_address="$(jq -r '.operator_id' "$base_meta")"
  juno_address="$(jq -r '.operator_id' "$juno_meta")"
  juno_taddr="$(jq -r '.transparent_address' "$juno_testnet_meta")"

  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg base_key_file "$base_key_file" \
    --arg juno_key_file "$juno_key_file" \
    --arg base_address "$base_address" \
    --arg juno_address "$juno_address" \
    --arg juno_taddr "$juno_taddr" \
    --arg juno_wif_file "$juno_wif_file" \
    --arg base_secret_name "BASE_FUNDER_PRIVATE_KEY_HEX" \
    --arg juno_secret_name "JUNO_FUNDER_PRIVATE_KEY_HEX" \
    '{
      generated_at: $generated_at,
      wallets: {
        base: {
          private_key_file: $base_key_file,
          address: $base_address
        },
        juno: {
          private_key_file: $juno_key_file,
          secp256k1_address_hint: $juno_address,
          testnet_transparent_address: $juno_taddr,
          testnet_wif_file: $juno_wif_file
        }
      },
      github_secrets: {
        base_private_key_hex: $base_secret_name,
        juno_private_key_hex: $juno_secret_name
      }
    }' >"$report_path"

  chmod 0644 "$report_path" || true

  log "created funder wallet files"
  log "base_address=$base_address"
  log "juno_address_hint=$juno_address"
  log "report=$report_path"
  printf '%s\n' "$report_path"
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
