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
  run-testnet-e2e.sh run [options]

Options:
  --workdir <path>                 working directory (default: <repo>/tmp/testnet-e2e)
  --base-rpc-url <url>             required Base testnet RPC URL
  --base-chain-id <id>             Base chain ID (default: 84532)
  --base-funder-key-file <path>    required file with Base private key hex (0x...)
  --contracts-out <path>           foundry out directory (default: <repo>/contracts/out)
  --operator-count <n>             DKG operator count (default: 5)
  --threshold <n>                  DKG threshold (default: 3)
  --base-port <port>               first operator grpc port (default: 18443)
  --base-operator-fund-wei <wei>   optional pre-fund per operator (default: 1000000000000000)
  --output <path>                  summary json output (default: <workdir>/reports/testnet-e2e-summary.json)
  --force                          remove existing workdir before starting

Environment:
  JUNO_FUNDER_PRIVATE_KEY_HEX      optional juno funder key hint included in summary metadata.

This script orchestrates:
  1) DKG ceremony -> backup packages -> restore from backup-only
  2) Base operator pre-funding (optional)
  3) Base testnet deploy + bridge smoke transactions via cmd/bridge-e2e
EOF
}

trimmed_file_value() {
  local path="$1"
  tr -d '\r\n' <"$path"
}

command_run() {
  shift || true

  local workdir="$REPO_ROOT/tmp/testnet-e2e"
  local base_rpc_url=""
  local base_chain_id=84532
  local base_funder_key_file=""
  local contracts_out="$REPO_ROOT/contracts/out"
  local operator_count=5
  local threshold=3
  local base_port=18443
  local base_operator_fund_wei="1000000000000000"
  local output_path=""
  local force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --base-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --base-rpc-url"
        base_rpc_url="$2"
        shift 2
        ;;
      --base-chain-id)
        [[ $# -ge 2 ]] || die "missing value for --base-chain-id"
        base_chain_id="$2"
        shift 2
        ;;
      --base-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-funder-key-file"
        base_funder_key_file="$2"
        shift 2
        ;;
      --contracts-out)
        [[ $# -ge 2 ]] || die "missing value for --contracts-out"
        contracts_out="$2"
        shift 2
        ;;
      --operator-count)
        [[ $# -ge 2 ]] || die "missing value for --operator-count"
        operator_count="$2"
        shift 2
        ;;
      --threshold)
        [[ $# -ge 2 ]] || die "missing value for --threshold"
        threshold="$2"
        shift 2
        ;;
      --base-port)
        [[ $# -ge 2 ]] || die "missing value for --base-port"
        base_port="$2"
        shift 2
        ;;
      --base-operator-fund-wei)
        [[ $# -ge 2 ]] || die "missing value for --base-operator-fund-wei"
        base_operator_fund_wei="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output_path="$2"
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
        die "unknown argument for run: $1"
        ;;
    esac
  done

  [[ -n "$base_rpc_url" ]] || die "--base-rpc-url is required"
  [[ -n "$base_funder_key_file" ]] || die "--base-funder-key-file is required"
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  [[ "$base_chain_id" =~ ^[0-9]+$ ]] || die "--base-chain-id must be numeric"
  [[ "$operator_count" =~ ^[0-9]+$ ]] || die "--operator-count must be numeric"
  [[ "$threshold" =~ ^[0-9]+$ ]] || die "--threshold must be numeric"
  [[ "$base_port" =~ ^[0-9]+$ ]] || die "--base-port must be numeric"
  [[ "$base_operator_fund_wei" =~ ^[0-9]+$ ]] || die "--base-operator-fund-wei must be numeric"

  if [[ -z "$output_path" ]]; then
    output_path="$workdir/reports/testnet-e2e-summary.json"
  fi

  ensure_base_dependencies
  ensure_command go
  ensure_dir "$(dirname "$output_path")"

  if [[ -d "$workdir" ]]; then
    if [[ "$force" != "true" ]]; then
      die "workdir already exists (use --force to overwrite): $workdir"
    fi
    rm -rf "$workdir"
  fi
  ensure_dir "$workdir/reports"

  local dkg_summary="$workdir/reports/dkg-summary.json"
  local bridge_summary="$workdir/reports/base-bridge-summary.json"

  (
    cd "$REPO_ROOT/contracts"
    forge build
  )

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/e2e/run-dkg-backup-restore.sh run \
      --workdir "$workdir/dkg" \
      --operator-count "$operator_count" \
      --threshold "$threshold" \
      --base-port "$base_port" \
      --output "$dkg_summary" \
      --force
  )

  local base_key
  base_key="$(trimmed_file_value "$base_funder_key_file")"

  if (( base_operator_fund_wei > 0 )); then
    ensure_command cast
    local operator
    while IFS= read -r operator; do
      [[ -n "$operator" ]] || continue
      cast send \
        --rpc-url "$base_rpc_url" \
        --private-key "$base_key" \
        --value "$base_operator_fund_wei" \
        "$operator" >/dev/null
    done < <(jq -r '.operators[].operator_id' "$dkg_summary")
  fi

  local -a bridge_args=()
  bridge_args+=(
    "--rpc-url" "$base_rpc_url"
    "--chain-id" "$base_chain_id"
    "--deployer-key-file" "$base_funder_key_file"
    "--threshold" "$threshold"
    "--contracts-out" "$contracts_out"
    "--output" "$bridge_summary"
  )

  local key_path
  while IFS= read -r key_path; do
    [[ -n "$key_path" ]] || continue
    bridge_args+=("--operator-key-file" "$key_path")
  done < <(jq -r '.operators[].operator_key_file' "$dkg_summary")

  (
    cd "$REPO_ROOT"
    go run ./cmd/bridge-e2e "${bridge_args[@]}"
  )

  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg workdir "$workdir" \
    --arg dkg_summary "$dkg_summary" \
    --arg bridge_summary "$bridge_summary" \
    --arg base_rpc_url "$base_rpc_url" \
    --argjson base_chain_id "$base_chain_id" \
    --argjson operator_count "$operator_count" \
    --argjson threshold "$threshold" \
    --arg base_operator_fund_wei "$base_operator_fund_wei" \
    --arg juno_funder_present "${JUNO_FUNDER_PRIVATE_KEY_HEX:+true}" \
    --argjson dkg "$(cat "$dkg_summary")" \
    --argjson bridge "$(cat "$bridge_summary")" \
    '{
      summary_version: 1,
      generated_at: $generated_at,
      workdir: $workdir,
      base: {
        rpc_url: $base_rpc_url,
        chain_id: $base_chain_id,
        operator_prefund_wei: $base_operator_fund_wei
      },
      dkg: {
        operator_count: $operator_count,
        threshold: $threshold,
        summary_path: $dkg_summary,
        report: $dkg
      },
      bridge: {
        summary_path: $bridge_summary,
        report: $bridge
      },
      juno: {
        funder_env_present: ($juno_funder_present == "true")
      }
    }' >"$output_path"

  log "testnet e2e flow complete"
  log "summary=$output_path"
  printf '%s\n' "$output_path"
}

main() {
  local cmd="${1:-run}"
  case "$cmd" in
    run) command_run "$@" ;;
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
