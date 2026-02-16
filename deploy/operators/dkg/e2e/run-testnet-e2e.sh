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
  --bridge-verifier-address <addr> optional verifier router address for real proof verification
  --bridge-deposit-image-id <hex>  optional deposit image ID (bytes32 hex)
  --bridge-withdraw-image-id <hex> optional withdraw image ID (bytes32 hex)
  --bridge-deposit-seal-file <path> optional file with deposit proof seal hex
  --bridge-withdraw-seal-file <path> optional file with withdraw proof seal hex
  --bridge-prepare-only            prepare proof inputs only (skip mint/finalize)
  --bridge-proof-inputs-output <path> optional proof inputs bundle output path
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

is_transient_rpc_error() {
  local msg lowered
  msg="${1:-}"
  lowered="$(lower "$msg")"
  [[ "$lowered" == *"null response"* ]] ||
    [[ "$lowered" == *"429"* ]] ||
    [[ "$lowered" == *"timeout"* ]] ||
    [[ "$lowered" == *"503"* ]] ||
    [[ "$lowered" == *"connection reset"* ]] ||
    [[ "$lowered" == *"eof"* ]]
}

run_with_rpc_retry() {
  local attempts="$1"
  local delay_seconds="$2"
  local label="$3"
  shift 3

  local attempt=1 output status
  while true; do
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e

    if (( status == 0 )); then
      if [[ -n "$output" ]]; then
        printf '%s\n' "$output"
      fi
      return 0
    fi

    if (( attempt >= attempts )) || ! is_transient_rpc_error "$output"; then
      printf '%s\n' "$output" >&2
      return "$status"
    fi

    log "$label transient rpc error (attempt ${attempt}/${attempts}); retrying in ${delay_seconds}s"
    sleep "$delay_seconds"
    attempt=$((attempt + 1))
  done
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
  local bridge_verifier_address=""
  local bridge_deposit_image_id=""
  local bridge_withdraw_image_id=""
  local bridge_deposit_seal_file=""
  local bridge_withdraw_seal_file=""
  local bridge_prepare_only="false"
  local bridge_proof_inputs_output=""
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
      --bridge-verifier-address)
        [[ $# -ge 2 ]] || die "missing value for --bridge-verifier-address"
        bridge_verifier_address="$2"
        shift 2
        ;;
      --bridge-deposit-image-id)
        [[ $# -ge 2 ]] || die "missing value for --bridge-deposit-image-id"
        bridge_deposit_image_id="$2"
        shift 2
        ;;
      --bridge-withdraw-image-id)
        [[ $# -ge 2 ]] || die "missing value for --bridge-withdraw-image-id"
        bridge_withdraw_image_id="$2"
        shift 2
        ;;
      --bridge-deposit-seal-file)
        [[ $# -ge 2 ]] || die "missing value for --bridge-deposit-seal-file"
        bridge_deposit_seal_file="$2"
        shift 2
        ;;
      --bridge-withdraw-seal-file)
        [[ $# -ge 2 ]] || die "missing value for --bridge-withdraw-seal-file"
        bridge_withdraw_seal_file="$2"
        shift 2
        ;;
      --bridge-prepare-only)
        bridge_prepare_only="true"
        shift
        ;;
      --bridge-proof-inputs-output)
        [[ $# -ge 2 ]] || die "missing value for --bridge-proof-inputs-output"
        bridge_proof_inputs_output="$2"
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
  if [[ -n "$bridge_deposit_seal_file" ]]; then
    [[ -f "$bridge_deposit_seal_file" ]] || die "bridge deposit seal file not found: $bridge_deposit_seal_file"
  fi
  if [[ -n "$bridge_withdraw_seal_file" ]]; then
    [[ -f "$bridge_withdraw_seal_file" ]] || die "bridge withdraw seal file not found: $bridge_withdraw_seal_file"
  fi

  if [[ -z "$output_path" ]]; then
    output_path="$workdir/reports/testnet-e2e-summary.json"
  fi
  if [[ -z "$bridge_proof_inputs_output" ]]; then
    bridge_proof_inputs_output="$workdir/reports/bridge-proof-inputs.json"
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
    local funder_address next_nonce
    funder_address="$(cast wallet address --private-key "$base_key")"
    next_nonce="$(run_with_rpc_retry 5 2 "cast nonce" cast nonce "$funder_address" --rpc-url "$base_rpc_url" --block pending)"

    local operator
    while IFS= read -r operator; do
      [[ -n "$operator" ]] || continue
      run_with_rpc_retry 5 2 "cast send" cast send \
        --rpc-url "$base_rpc_url" \
        --private-key "$base_key" \
        --nonce "$next_nonce" \
        --value "$base_operator_fund_wei" \
        "$operator" >/dev/null
      next_nonce=$((next_nonce + 1))
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
  if [[ -n "$bridge_verifier_address" ]]; then
    bridge_args+=("--verifier-address" "$bridge_verifier_address")
  fi
  if [[ -n "$bridge_deposit_image_id" ]]; then
    bridge_args+=("--deposit-image-id" "$bridge_deposit_image_id")
  fi
  if [[ -n "$bridge_withdraw_image_id" ]]; then
    bridge_args+=("--withdraw-image-id" "$bridge_withdraw_image_id")
  fi
  if [[ -n "$bridge_deposit_seal_file" ]]; then
    bridge_args+=("--deposit-seal-hex" "$(trimmed_file_value "$bridge_deposit_seal_file")")
  fi
  if [[ -n "$bridge_withdraw_seal_file" ]]; then
    bridge_args+=("--withdraw-seal-hex" "$(trimmed_file_value "$bridge_withdraw_seal_file")")
  fi
  if [[ "$bridge_prepare_only" == "true" ]]; then
    bridge_args+=("--prepare-only")
  fi
  if [[ -n "$bridge_proof_inputs_output" ]]; then
    bridge_args+=("--proof-inputs-output" "$bridge_proof_inputs_output")
  fi

  local key_path
  while IFS= read -r key_path; do
    [[ -n "$key_path" ]] || continue
    bridge_args+=("--operator-key-file" "$key_path")
  done < <(jq -r '.operators[].operator_key_file' "$dkg_summary")

  (
    cd "$REPO_ROOT"
    run_with_rpc_retry 4 3 "bridge-e2e" go run ./cmd/bridge-e2e "${bridge_args[@]}"
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
    --arg bridge_verifier_address "$bridge_verifier_address" \
    --arg bridge_deposit_image_id "$bridge_deposit_image_id" \
    --arg bridge_withdraw_image_id "$bridge_withdraw_image_id" \
    --arg bridge_prepare_only "$bridge_prepare_only" \
    --arg bridge_proof_inputs_output "$bridge_proof_inputs_output" \
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
        verifier_address: (if $bridge_verifier_address == "" then null else $bridge_verifier_address end),
        deposit_image_id: (if $bridge_deposit_image_id == "" then null else $bridge_deposit_image_id end),
        withdraw_image_id: (if $bridge_withdraw_image_id == "" then null else $bridge_withdraw_image_id end),
        prepare_only: ($bridge_prepare_only == "true"),
        proof_inputs_output: $bridge_proof_inputs_output,
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
