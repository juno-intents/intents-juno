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
  --bridge-run-timeout <duration>  bridge-e2e runtime timeout (default: 8m; 90m with --boundless-auto)
  --boundless-auto                 auto-submit/wait Boundless proofs and callback with returned seals
  --boundless-bin <path>           boundless binary (default: boundless)
  --boundless-rpc-url <url>        boundless market RPC URL (default: https://mainnet.base.org)
  --boundless-market-address <addr> boundless market contract address
                                   (default: 0xFd152dADc5183870710FE54f939Eae3aB9F0fE82)
  --boundless-verifier-router-address <addr> boundless verifier router address
                                   (default: 0x0b144e07a0826182b6b59788c34b32bfa86fb711)
  --boundless-set-verifier-address <addr> boundless set verifier address
                                   (default: 0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104)
  --boundless-input-mode <mode>    boundless private input mode: private-input | journal-bytes-v1 (default: private-input)
  --boundless-requestor-key-file <path> requestor key file for boundless (required with --boundless-auto)
  --boundless-deposit-program-url <url> deposit guest program URL for boundless (required with --boundless-auto)
  --boundless-withdraw-program-url <url> withdraw guest program URL for boundless (required with --boundless-auto)
  --boundless-min-price-wei <wei>  auction min price (default: 100000000000000)
  --boundless-max-price-wei <wei>  auction max price (default: 250000000000000)
  --boundless-lock-stake-wei <wei> auction lock stake (default: 20000000000000000000)
  --boundless-bidding-delay-seconds <s> auction bidding delay (default: 85)
  --boundless-ramp-up-period-seconds <s> auction ramp period (default: 170)
  --boundless-lock-timeout-seconds <s> auction lock timeout (default: 625)
  --boundless-timeout-seconds <s> auction timeout (default: 1500)
  --shared-postgres-dsn <dsn>       optional shared Postgres DSN for infra validation
  --shared-kafka-brokers <list>     optional shared Kafka brokers CSV for infra validation
  --shared-topic-prefix <prefix>    shared infra Kafka topic prefix (default: shared.infra.e2e)
  --shared-timeout <duration>       shared infra validation timeout (default: 90s)
  --shared-output <path>            shared infra report output (default: <workdir>/reports/shared-infra-summary.json)
  --output <path>                  summary json output (default: <workdir>/reports/testnet-e2e-summary.json)
  --force                          remove existing workdir before starting

Environment:
  JUNO_FUNDER_PRIVATE_KEY_HEX      juno funder key hint included in summary metadata (required by CI workflow).

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

is_nonce_race_error() {
  local msg lowered
  msg="${1:-}"
  lowered="$(lower "$msg")"
  [[ "$lowered" == *"nonce too low"* ]] ||
    [[ "$lowered" == *"replacement transaction underpriced"* ]] ||
    [[ "$lowered" == *"already known"* ]]
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

    if [[ "$label" == "cast send" ]] && is_nonce_race_error "$output"; then
      log "$label nonce race detected; assuming previous submission accepted"
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

nonce_has_advanced() {
  local rpc_url="$1"
  local sender="$2"
  local nonce="$3"

  local latest_nonce pending_nonce
  latest_nonce="$(cast nonce --rpc-url "$rpc_url" --block latest "$sender" 2>/dev/null || true)"
  pending_nonce="$(cast nonce --rpc-url "$rpc_url" --block pending "$sender" 2>/dev/null || true)"

  [[ "$latest_nonce" =~ ^[0-9]+$ ]] || latest_nonce="$nonce"
  [[ "$pending_nonce" =~ ^[0-9]+$ ]] || pending_nonce="$latest_nonce"

  (( latest_nonce > nonce || pending_nonce > nonce ))
}

cast_send_with_nonce_retry() {
  local attempts="$1"
  local delay_seconds="$2"
  local rpc_url="$3"
  local private_key="$4"
  local sender="$5"
  local nonce="$6"
  local value_wei="$7"
  local recipient="$8"

  local attempt=1 output status
  while true; do
    set +e
    output="$(cast send \
      --rpc-url "$rpc_url" \
      --private-key "$private_key" \
      --async \
      --nonce "$nonce" \
      --value "$value_wei" \
      "$recipient" 2>&1)"
    status=$?
    set -e

    if (( status == 0 )); then
      if [[ -n "$output" ]]; then
        printf '%s\n' "$output"
      fi
      return 0
    fi

    if is_nonce_race_error "$output"; then
      if nonce_has_advanced "$rpc_url" "$sender" "$nonce"; then
        log "cast send nonce race detected and sender nonce advanced; assuming previous submission accepted"
        return 0
      fi
      log "cast send nonce race detected but sender nonce not advanced; nonce=$nonce attempt=${attempt}/${attempts}"
    elif (( attempt >= attempts )) || ! is_transient_rpc_error "$output"; then
      printf '%s\n' "$output" >&2
      return "$status"
    else
      log "cast send transient rpc error (attempt ${attempt}/${attempts}); retrying in ${delay_seconds}s"
    fi

    if (( attempt >= attempts )); then
      printf '%s\n' "$output" >&2
      return "$status"
    fi

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
  local bridge_run_timeout=""
  local boundless_auto="false"
  local boundless_bin="boundless"
  local boundless_rpc_url="https://mainnet.base.org"
  local boundless_market_address="0xFd152dADc5183870710FE54f939Eae3aB9F0fE82"
  local boundless_verifier_router_address="0x0b144e07a0826182b6b59788c34b32bfa86fb711"
  local boundless_set_verifier_address="0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104"
  local boundless_input_mode="private-input"
  local boundless_requestor_key_file=""
  local boundless_deposit_program_url=""
  local boundless_withdraw_program_url=""
  local boundless_min_price_wei="100000000000000"
  local boundless_max_price_wei="250000000000000"
  local boundless_lock_stake_wei="20000000000000000000"
  local boundless_bidding_delay_seconds="85"
  local boundless_ramp_up_period_seconds="170"
  local boundless_lock_timeout_seconds="625"
  local boundless_timeout_seconds="1500"
  local shared_postgres_dsn=""
  local shared_kafka_brokers=""
  local shared_topic_prefix="shared.infra.e2e"
  local shared_timeout="90s"
  local shared_output=""
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
      --bridge-run-timeout)
        [[ $# -ge 2 ]] || die "missing value for --bridge-run-timeout"
        bridge_run_timeout="$2"
        shift 2
        ;;
      --boundless-auto)
        boundless_auto="true"
        shift
        ;;
      --boundless-bin)
        [[ $# -ge 2 ]] || die "missing value for --boundless-bin"
        boundless_bin="$2"
        shift 2
        ;;
      --boundless-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --boundless-rpc-url"
        boundless_rpc_url="$2"
        shift 2
        ;;
      --boundless-market-address)
        [[ $# -ge 2 ]] || die "missing value for --boundless-market-address"
        boundless_market_address="$2"
        shift 2
        ;;
      --boundless-verifier-router-address)
        [[ $# -ge 2 ]] || die "missing value for --boundless-verifier-router-address"
        boundless_verifier_router_address="$2"
        shift 2
        ;;
      --boundless-set-verifier-address)
        [[ $# -ge 2 ]] || die "missing value for --boundless-set-verifier-address"
        boundless_set_verifier_address="$2"
        shift 2
        ;;
      --boundless-input-mode)
        [[ $# -ge 2 ]] || die "missing value for --boundless-input-mode"
        boundless_input_mode="$(lower "$2")"
        shift 2
        ;;
      --boundless-requestor-key-file)
        [[ $# -ge 2 ]] || die "missing value for --boundless-requestor-key-file"
        boundless_requestor_key_file="$2"
        shift 2
        ;;
      --boundless-deposit-program-url)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-program-url"
        boundless_deposit_program_url="$2"
        shift 2
        ;;
      --boundless-withdraw-program-url)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-program-url"
        boundless_withdraw_program_url="$2"
        shift 2
        ;;
      --boundless-min-price-wei)
        [[ $# -ge 2 ]] || die "missing value for --boundless-min-price-wei"
        boundless_min_price_wei="$2"
        shift 2
        ;;
      --boundless-max-price-wei)
        [[ $# -ge 2 ]] || die "missing value for --boundless-max-price-wei"
        boundless_max_price_wei="$2"
        shift 2
        ;;
      --boundless-lock-stake-wei)
        [[ $# -ge 2 ]] || die "missing value for --boundless-lock-stake-wei"
        boundless_lock_stake_wei="$2"
        shift 2
        ;;
      --boundless-bidding-delay-seconds)
        [[ $# -ge 2 ]] || die "missing value for --boundless-bidding-delay-seconds"
        boundless_bidding_delay_seconds="$2"
        shift 2
        ;;
      --boundless-ramp-up-period-seconds)
        [[ $# -ge 2 ]] || die "missing value for --boundless-ramp-up-period-seconds"
        boundless_ramp_up_period_seconds="$2"
        shift 2
        ;;
      --boundless-lock-timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --boundless-lock-timeout-seconds"
        boundless_lock_timeout_seconds="$2"
        shift 2
        ;;
      --boundless-timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --boundless-timeout-seconds"
        boundless_timeout_seconds="$2"
        shift 2
        ;;
      --shared-postgres-dsn)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-dsn"
        shared_postgres_dsn="$2"
        shift 2
        ;;
      --shared-kafka-brokers)
        [[ $# -ge 2 ]] || die "missing value for --shared-kafka-brokers"
        shared_kafka_brokers="$2"
        shift 2
        ;;
      --shared-topic-prefix)
        [[ $# -ge 2 ]] || die "missing value for --shared-topic-prefix"
        shared_topic_prefix="$2"
        shift 2
        ;;
      --shared-timeout)
        [[ $# -ge 2 ]] || die "missing value for --shared-timeout"
        shared_timeout="$2"
        shift 2
        ;;
      --shared-output)
        [[ $# -ge 2 ]] || die "missing value for --shared-output"
        shared_output="$2"
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
  [[ "$boundless_min_price_wei" =~ ^[0-9]+$ ]] || die "--boundless-min-price-wei must be numeric"
  [[ "$boundless_max_price_wei" =~ ^[0-9]+$ ]] || die "--boundless-max-price-wei must be numeric"
  [[ "$boundless_lock_stake_wei" =~ ^[0-9]+$ ]] || die "--boundless-lock-stake-wei must be numeric"
  [[ "$boundless_bidding_delay_seconds" =~ ^[0-9]+$ ]] || die "--boundless-bidding-delay-seconds must be numeric"
  [[ "$boundless_ramp_up_period_seconds" =~ ^[0-9]+$ ]] || die "--boundless-ramp-up-period-seconds must be numeric"
  [[ "$boundless_lock_timeout_seconds" =~ ^[0-9]+$ ]] || die "--boundless-lock-timeout-seconds must be numeric"
  [[ "$boundless_timeout_seconds" =~ ^[0-9]+$ ]] || die "--boundless-timeout-seconds must be numeric"
  case "$boundless_input_mode" in
    private-input|journal-bytes-v1)
      ;;
    *)
      die "--boundless-input-mode must be one of: private-input, journal-bytes-v1"
      ;;
  esac

  if [[ -z "$bridge_run_timeout" ]]; then
    if [[ "$boundless_auto" == "true" ]]; then
      bridge_run_timeout="90m"
    else
      bridge_run_timeout="8m"
    fi
  fi

  if [[ "$boundless_auto" == "true" ]]; then
    [[ -n "$boundless_requestor_key_file" ]] || die "--boundless-requestor-key-file is required with --boundless-auto"
    [[ -f "$boundless_requestor_key_file" ]] || die "boundless requestor key file not found: $boundless_requestor_key_file"
    [[ -n "$boundless_deposit_program_url" ]] || die "--boundless-deposit-program-url is required with --boundless-auto"
    [[ -n "$boundless_withdraw_program_url" ]] || die "--boundless-withdraw-program-url is required with --boundless-auto"
    [[ -n "$bridge_verifier_address" ]] || die "--bridge-verifier-address is required with --boundless-auto"
    [[ "$bridge_prepare_only" != "true" ]] || die "--boundless-auto cannot be used with --bridge-prepare-only"
  fi

  if [[ -n "$bridge_deposit_seal_file" ]]; then
    [[ -f "$bridge_deposit_seal_file" ]] || die "bridge deposit seal file not found: $bridge_deposit_seal_file"
  fi
  if [[ -n "$bridge_withdraw_seal_file" ]]; then
    [[ -f "$bridge_withdraw_seal_file" ]] || die "bridge withdraw seal file not found: $bridge_withdraw_seal_file"
  fi
  if [[ "$boundless_auto" == "true" && ( -n "$bridge_deposit_seal_file" || -n "$bridge_withdraw_seal_file" ) ]]; then
    die "--boundless-auto cannot be combined with --bridge-deposit-seal-file/--bridge-withdraw-seal-file"
  fi

  if [[ -z "$output_path" ]]; then
    output_path="$workdir/reports/testnet-e2e-summary.json"
  fi
  if [[ -z "$bridge_proof_inputs_output" ]]; then
    bridge_proof_inputs_output="$workdir/reports/bridge-proof-inputs.json"
  fi
  if [[ -z "$shared_output" ]]; then
    shared_output="$workdir/reports/shared-infra-summary.json"
  fi

  local shared_enabled="false"
  if [[ -n "$shared_postgres_dsn" || -n "$shared_kafka_brokers" ]]; then
    [[ -n "$shared_postgres_dsn" ]] || die "--shared-kafka-brokers requires --shared-postgres-dsn"
    [[ -n "$shared_kafka_brokers" ]] || die "--shared-postgres-dsn requires --shared-kafka-brokers"
    shared_enabled="true"
  fi

  ensure_base_dependencies
  ensure_command go
  if [[ "$boundless_auto" == "true" ]]; then
    ensure_command "$boundless_bin"
    local boundless_version
    boundless_version="$("$boundless_bin" --version 2>/dev/null || true)"
    if [[ "$boundless_version" == boundless-cli\ 0.* ]]; then
      die "boundless-auto requires boundless-cli v1.x+; installed version is '$boundless_version'"
    fi
  fi
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
  local shared_summary="$shared_output"

  if [[ "$shared_enabled" == "true" ]]; then
    (
      cd "$REPO_ROOT"
      go run ./cmd/shared-infra-e2e \
        --postgres-dsn "$shared_postgres_dsn" \
        --kafka-brokers "$shared_kafka_brokers" \
        --topic-prefix "$shared_topic_prefix" \
        --timeout "$shared_timeout" \
        --output "$shared_summary"
    )
  fi

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

  local bridge_deployer_address
  bridge_deployer_address="$(jq -r '.operators[0].operator_id // empty' "$dkg_summary")"
  [[ -n "$bridge_deployer_address" ]] || die "dkg summary missing operators[0].operator_id"

  if (( base_operator_fund_wei > 0 )); then
    ensure_command cast
    local funding_sender_address
    funding_sender_address="$(cast wallet address --private-key "$base_key")"
    [[ -n "$funding_sender_address" ]] || die "failed to derive funding sender address"

    local funding_nonce
    funding_nonce="$(cast nonce --rpc-url "$base_rpc_url" --block pending "$funding_sender_address")"
    [[ "$funding_nonce" =~ ^[0-9]+$ ]] || die "unexpected funding nonce from cast: $funding_nonce"

    local operator
    while IFS= read -r operator; do
      [[ -n "$operator" ]] || continue
      cast_send_with_nonce_retry 5 2 "$base_rpc_url" "$base_key" "$funding_sender_address" "$funding_nonce" "$base_operator_fund_wei" "$operator" >/dev/null
      funding_nonce=$((funding_nonce + 1))
    done < <(jq -r '.operators[].operator_id' "$dkg_summary")

    local bridge_deployer_required_wei
    bridge_deployer_required_wei=$((base_operator_fund_wei * 10))
    local funded_bridge_deployer="false"
    local attempt bridge_deployer_balance bridge_deployer_topup_wei
    for attempt in $(seq 1 12); do
      bridge_deployer_balance="$(cast balance --rpc-url "$base_rpc_url" "$bridge_deployer_address")"
      [[ "$bridge_deployer_balance" =~ ^[0-9]+$ ]] || die "unexpected bridge deployer balance from cast: $bridge_deployer_balance"
      if (( bridge_deployer_balance >= bridge_deployer_required_wei )); then
        funded_bridge_deployer="true"
        break
      fi

      bridge_deployer_topup_wei=$((bridge_deployer_required_wei - bridge_deployer_balance))
      log "bridge deployer balance below required target; topping up address=$bridge_deployer_address balance=$bridge_deployer_balance required=$bridge_deployer_required_wei topup=$bridge_deployer_topup_wei attempt=$attempt/12"
      cast_send_with_nonce_retry 5 2 "$base_rpc_url" "$base_key" "$funding_sender_address" "$funding_nonce" "$bridge_deployer_topup_wei" "$bridge_deployer_address" >/dev/null
      funding_nonce=$((funding_nonce + 1))
      sleep 2
    done
    [[ "$funded_bridge_deployer" == "true" ]] || die "failed to fund bridge deployer: address=$bridge_deployer_address required_wei=$bridge_deployer_required_wei"
  fi

  local bridge_deployer_key_file
  bridge_deployer_key_file="$(jq -r '.operators[0].operator_key_file // empty' "$dkg_summary")"
  [[ -n "$bridge_deployer_key_file" ]] || die "dkg summary missing operators[0].operator_key_file"
  [[ -f "$bridge_deployer_key_file" ]] || die "bridge deployer key file not found: $bridge_deployer_key_file"

  local -a bridge_args=()
  bridge_args+=(
    "--rpc-url" "$base_rpc_url"
    "--chain-id" "$base_chain_id"
    "--deployer-key-file" "$bridge_deployer_key_file"
    "--threshold" "$threshold"
    "--contracts-out" "$contracts_out"
    "--run-timeout" "$bridge_run_timeout"
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
  if [[ "$boundless_auto" == "true" ]]; then
    bridge_args+=(
      "--boundless-auto"
      "--boundless-bin" "$boundless_bin"
      "--boundless-rpc-url" "$boundless_rpc_url"
      "--boundless-market-address" "$boundless_market_address"
      "--boundless-verifier-router-address" "$boundless_verifier_router_address"
      "--boundless-set-verifier-address" "$boundless_set_verifier_address"
      "--boundless-input-mode" "$boundless_input_mode"
      "--boundless-requestor-key-file" "$boundless_requestor_key_file"
      "--boundless-deposit-program-url" "$boundless_deposit_program_url"
      "--boundless-withdraw-program-url" "$boundless_withdraw_program_url"
      "--boundless-min-price-wei" "$boundless_min_price_wei"
      "--boundless-max-price-wei" "$boundless_max_price_wei"
      "--boundless-lock-stake-wei" "$boundless_lock_stake_wei"
      "--boundless-bidding-delay-seconds" "$boundless_bidding_delay_seconds"
      "--boundless-ramp-up-period-seconds" "$boundless_ramp_up_period_seconds"
      "--boundless-lock-timeout-seconds" "$boundless_lock_timeout_seconds"
      "--boundless-timeout-seconds" "$boundless_timeout_seconds"
    )
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
    --arg bridge_run_timeout "$bridge_run_timeout" \
    --arg boundless_auto "$boundless_auto" \
    --arg boundless_bin "$boundless_bin" \
    --arg boundless_rpc_url "$boundless_rpc_url" \
    --arg boundless_input_mode "$boundless_input_mode" \
    --arg boundless_deposit_program_url "$boundless_deposit_program_url" \
    --arg boundless_withdraw_program_url "$boundless_withdraw_program_url" \
    --arg boundless_min_price_wei "$boundless_min_price_wei" \
    --arg boundless_max_price_wei "$boundless_max_price_wei" \
    --arg boundless_lock_stake_wei "$boundless_lock_stake_wei" \
    --arg boundless_bidding_delay_seconds "$boundless_bidding_delay_seconds" \
    --arg boundless_ramp_up_period_seconds "$boundless_ramp_up_period_seconds" \
    --arg boundless_lock_timeout_seconds "$boundless_lock_timeout_seconds" \
    --arg boundless_timeout_seconds "$boundless_timeout_seconds" \
    --arg shared_enabled "$shared_enabled" \
    --arg shared_kafka_brokers "$shared_kafka_brokers" \
    --arg shared_topic_prefix "$shared_topic_prefix" \
    --arg shared_timeout "$shared_timeout" \
    --arg shared_summary "$shared_summary" \
    --arg juno_funder_present "${JUNO_FUNDER_PRIVATE_KEY_HEX:+true}" \
    --argjson shared "$(if [[ -f "$shared_summary" ]]; then cat "$shared_summary"; else printf 'null'; fi)" \
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
        run_timeout: $bridge_run_timeout,
        proof_inputs_output: $bridge_proof_inputs_output,
        boundless: {
          auto: ($boundless_auto == "true"),
          bin: $boundless_bin,
          rpc_url: $boundless_rpc_url,
          input_mode: $boundless_input_mode,
          deposit_program_url: (if $boundless_deposit_program_url == "" then null else $boundless_deposit_program_url end),
          withdraw_program_url: (if $boundless_withdraw_program_url == "" then null else $boundless_withdraw_program_url end),
          min_price_wei: $boundless_min_price_wei,
          max_price_wei: $boundless_max_price_wei,
          lock_stake_wei: $boundless_lock_stake_wei,
          bidding_delay_seconds: $boundless_bidding_delay_seconds,
          ramp_up_period_seconds: $boundless_ramp_up_period_seconds,
          lock_timeout_seconds: $boundless_lock_timeout_seconds,
          timeout_seconds: $boundless_timeout_seconds
        },
        report: $bridge
      },
      shared_infra: {
        enabled: ($shared_enabled == "true"),
        postgres_configured: ($shared_enabled == "true"),
        kafka_brokers: (if $shared_kafka_brokers == "" then null else $shared_kafka_brokers end),
        topic_prefix: (if $shared_topic_prefix == "" then null else $shared_topic_prefix end),
        timeout: (if $shared_timeout == "" then null else $shared_timeout end),
        summary_path: (if $shared_summary == "" then null else $shared_summary end),
        report: $shared
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
