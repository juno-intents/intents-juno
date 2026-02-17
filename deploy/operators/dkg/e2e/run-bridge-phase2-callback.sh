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
  run-bridge-phase2-callback.sh run [options]

Options:
  --base-rpc-url <url>            required Base RPC URL
  --base-funder-key-file <path>   required sender key file used for callback transactions
  --proof-inputs-file <path>      required bridge-proof-inputs.json from prepare-only run
  --deposit-seal-file <path>      required deposit seal hex file
  --withdraw-seal-file <path>     required withdraw seal hex file
  --base-chain-id <id>            optional chain ID override (must match proof inputs + rpc)
  --withdraw-amount <zat>         optional withdraw amount override (required for older proof bundles)
  --run-timeout <duration>        callback runtime timeout (default: 15m)
  --output <path>                 callback report output (default: <proof-dir>/phase2-callback-report.json)

This script executes phase-2 callback transactions against already deployed contracts:
  1) mintBatch
  2) approve (WJUNO -> Bridge)
  3) requestWithdraw
  4) finalizeWithdrawBatch
EOF
}

command_run() {
  shift || true

  local base_rpc_url=""
  local base_funder_key_file=""
  local proof_inputs_file=""
  local deposit_seal_file=""
  local withdraw_seal_file=""
  local base_chain_id=""
  local withdraw_amount=""
  local run_timeout="15m"
  local output_path=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --base-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --base-rpc-url"
        base_rpc_url="$2"
        shift 2
        ;;
      --base-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-funder-key-file"
        base_funder_key_file="$2"
        shift 2
        ;;
      --proof-inputs-file)
        [[ $# -ge 2 ]] || die "missing value for --proof-inputs-file"
        proof_inputs_file="$2"
        shift 2
        ;;
      --deposit-seal-file)
        [[ $# -ge 2 ]] || die "missing value for --deposit-seal-file"
        deposit_seal_file="$2"
        shift 2
        ;;
      --withdraw-seal-file)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-seal-file"
        withdraw_seal_file="$2"
        shift 2
        ;;
      --base-chain-id)
        [[ $# -ge 2 ]] || die "missing value for --base-chain-id"
        base_chain_id="$2"
        shift 2
        ;;
      --withdraw-amount)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-amount"
        withdraw_amount="$2"
        shift 2
        ;;
      --run-timeout)
        [[ $# -ge 2 ]] || die "missing value for --run-timeout"
        run_timeout="$2"
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
        die "unknown argument for run: $1"
        ;;
    esac
  done

  [[ -n "$base_rpc_url" ]] || die "--base-rpc-url is required"
  [[ -n "$base_funder_key_file" ]] || die "--base-funder-key-file is required"
  [[ -n "$proof_inputs_file" ]] || die "--proof-inputs-file is required"
  [[ -n "$deposit_seal_file" ]] || die "--deposit-seal-file is required"
  [[ -n "$withdraw_seal_file" ]] || die "--withdraw-seal-file is required"
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  [[ -f "$proof_inputs_file" ]] || die "proof inputs file not found: $proof_inputs_file"
  [[ -f "$deposit_seal_file" ]] || die "deposit seal file not found: $deposit_seal_file"
  [[ -f "$withdraw_seal_file" ]] || die "withdraw seal file not found: $withdraw_seal_file"
  if [[ -n "$base_chain_id" && ! "$base_chain_id" =~ ^[0-9]+$ ]]; then
    die "--base-chain-id must be numeric"
  fi
  if [[ -n "$withdraw_amount" && ! "$withdraw_amount" =~ ^[0-9]+$ ]]; then
    die "--withdraw-amount must be numeric"
  fi

  if [[ -z "$output_path" ]]; then
    output_path="$(dirname "$proof_inputs_file")/phase2-callback-report.json"
  fi

  ensure_base_dependencies
  ensure_command go
  ensure_dir "$(dirname "$output_path")"

  local -a args=(
    "--rpc-url" "$base_rpc_url"
    "--sender-key-file" "$base_funder_key_file"
    "--proof-inputs-file" "$proof_inputs_file"
    "--deposit-seal-file" "$deposit_seal_file"
    "--withdraw-seal-file" "$withdraw_seal_file"
    "--run-timeout" "$run_timeout"
    "--output" "$output_path"
  )

  if [[ -n "$base_chain_id" ]]; then
    args+=("--chain-id" "$base_chain_id")
  fi
  if [[ -n "$withdraw_amount" ]]; then
    args+=("--withdraw-amount" "$withdraw_amount")
  fi

  (
    cd "$REPO_ROOT"
    go run ./cmd/bridge-callback "${args[@]}"
  )

  log "phase2 callback complete"
  log "report=$output_path"
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
