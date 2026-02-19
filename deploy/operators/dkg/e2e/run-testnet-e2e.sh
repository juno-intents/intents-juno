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
  --dkg-summary-path <path>        optional precomputed DKG summary (skip local DKG flow)
  --base-operator-fund-wei <wei>   optional pre-fund per operator (default: 1000000000000000)
  --bridge-verifier-address <addr> required verifier router address for proof verification
  --bridge-deposit-image-id <hex>  required deposit image ID (bytes32 hex)
  --bridge-withdraw-image-id <hex> required withdraw image ID (bytes32 hex)
  --bridge-deposit-final-orchard-root <hex> required in manual witness mode; checkpoint root for deposit proof
  --bridge-withdraw-final-orchard-root <hex> optional in manual witness mode; defaults to deposit root
  --bridge-deposit-checkpoint-height <n> required in manual witness mode; Juno height for deposit checkpoint
  --bridge-deposit-checkpoint-block-hash <hex> required in manual witness mode; Juno block hash for deposit checkpoint
  --bridge-withdraw-checkpoint-height <n> optional in manual witness mode; defaults to deposit checkpoint height
  --bridge-withdraw-checkpoint-block-hash <hex> optional in manual witness mode; defaults to deposit checkpoint block hash
  --bridge-proof-inputs-output <path> optional proof inputs bundle output path
  --bridge-juno-execution-tx-hash <hash> optional canonical Juno execution tx hash reported by bridge-e2e
  --bridge-run-timeout <duration>  bridge-e2e runtime timeout (default: 90m)
  --bridge-operator-signer-bin <path> external operator signer binary for bridge-e2e
                                   (default: <dkg coordinator_workdir>/bin/dkg-admin when available, else dkg-admin)
  --boundless-bin <path>           boundless binary (default: boundless)
  --boundless-rpc-url <url>        boundless market RPC URL (default: https://mainnet.base.org)
  --boundless-market-address <addr> boundless market contract address
                                   (default: 0xFd152dADc5183870710FE54f939Eae3aB9F0fE82)
  --boundless-verifier-router-address <addr> boundless verifier router address
                                   (default: 0x0b144e07a0826182b6b59788c34b32bfa86fb711)
  --boundless-set-verifier-address <addr> boundless set verifier address
                                   (default: 0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104)
  --boundless-input-mode <mode>     boundless input mode (guest-witness-v1 only, default: guest-witness-v1)
  --boundless-deposit-owallet-ivk-hex <hex>  64-byte oWallet IVK hex (required for guest-witness-v1)
  --boundless-withdraw-owallet-ovk-hex <hex> 32-byte oWallet OVK hex (required for guest-witness-v1)
  --boundless-deposit-witness-item-file <path> deposit witness item file (repeat for guest-witness-v1)
  --boundless-withdraw-witness-item-file <path> withdraw witness item file (repeat for guest-witness-v1)
  --boundless-witness-juno-scan-url <url> juno-scan URL for witness extraction (optional, guest-witness-v1)
  --boundless-witness-juno-rpc-url <url> junocashd RPC URL for witness extraction (optional, guest-witness-v1)
  --boundless-witness-juno-scan-bearer-token-env <name> env var for optional juno-scan bearer token
                                   (default: JUNO_SCAN_BEARER_TOKEN)
  --boundless-witness-juno-rpc-user-env <name> env var for junocashd RPC username (default: JUNO_RPC_USER)
  --boundless-witness-juno-rpc-pass-env <name> env var for junocashd RPC password (default: JUNO_RPC_PASS)
  --boundless-deposit-witness-wallet-id <id> juno-scan wallet id for deposit witness extraction
  --boundless-deposit-witness-txid <txid> txid for deposit witness extraction
  --boundless-deposit-witness-action-index <n> orchard action index for deposit witness extraction
  --boundless-withdraw-witness-wallet-id <id> juno-scan wallet id for withdraw witness extraction
  --boundless-withdraw-witness-txid <txid> txid for withdraw witness extraction
  --boundless-withdraw-witness-action-index <n> orchard action index for withdraw witness extraction
  --boundless-withdraw-witness-withdrawal-id-hex <hex> withdrawal id (32-byte hex) for withdraw witness extraction
  --boundless-withdraw-witness-recipient-raw-address-hex <hex> recipient raw Orchard address (43-byte hex)
                                   for withdraw witness extraction
  --boundless-requestor-key-file <path> requestor key file for boundless (required)
  --boundless-deposit-program-url <url> deposit guest program URL for boundless (required)
  --boundless-withdraw-program-url <url> withdraw guest program URL for boundless (required)
  --boundless-input-s3-bucket <name> S3 bucket used for oversized boundless inputs
                                   (required for guest-witness-v1 / >2048-byte inputs)
  --boundless-input-s3-prefix <prefix> S3 key prefix for oversized boundless inputs
                                   (default: bridge-e2e/boundless-input)
  --boundless-input-s3-region <region> optional AWS region override for oversized input uploads
  --boundless-input-s3-presign-ttl <duration> presigned URL TTL for oversized input uploads
                                   (default: 2h)
  --boundless-min-price-wei <wei>  auction min price (default: 0)
  --boundless-max-price-wei <wei>  auction max price (default: 50000000000000)
  --boundless-max-price-cap-wei <wei> max auction price cap used by retry bumps (default: 250000000000000)
  --boundless-max-price-bump-multiplier <n> max price bump multiplier on lock failures (default: 2)
  --boundless-max-price-bump-retries <n> max price bump retries on lock failures (default: 3)
  --boundless-lock-stake-wei <wei> auction lock stake (default: 20000000000000000000)
  --boundless-bidding-delay-seconds <s> auction bidding delay (default: 85)
  --boundless-ramp-up-period-seconds <s> auction ramp period (default: 170)
  --boundless-lock-timeout-seconds <s> auction lock timeout (default: 625)
  --boundless-timeout-seconds <s> auction timeout (default: 1500)
  --shared-postgres-dsn <dsn>       shared Postgres DSN (required; proof-requestor/proof-funder store + lease backend)
  --shared-kafka-brokers <list>     shared Kafka brokers CSV (required; centralized proof request/fulfillment topics)
  --shared-ipfs-api-url <url>       shared IPFS API URL (required; checkpoint package publish/pin verification)
  --shared-ecs-cluster-arn <arn>    shared ECS cluster ARN for centralized proof services (optional; enables ECS-managed proof services)
  --shared-proof-requestor-service-name <name> ECS service name for shared proof-requestor
  --shared-proof-funder-service-name <name> ECS service name for shared proof-funder
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
  3) Shared infra validation (Postgres + Kafka + checkpoint package publish/pin to IPFS)
  4) Centralized proof-requestor/proof-funder startup on shared topics
  5) Base testnet deploy + bridge flow via cmd/bridge-e2e with centralized Kafka proof jobs
EOF
}

trimmed_file_value() {
  local path="$1"
  tr -d '\r\n' <"$path"
}

json_array_from_args() {
  jq -n --args "$@" '$ARGS.positional'
}

resolve_aws_region() {
  local aws_region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  [[ -n "$aws_region" ]] || die "AWS_REGION or AWS_DEFAULT_REGION is required for shared ECS proof services"
  printf '%s' "$aws_region"
}

ecs_register_service_task_definition() {
  local aws_region="$1"
  local cluster_arn="$2"
  local service_name="$3"
  local container_name="$4"
  local command_json="$5"

  local service_json task_definition_arn task_definition_json register_input
  service_json="$(
    aws ecs describe-services \
      --region "$aws_region" \
      --cluster "$cluster_arn" \
      --services "$service_name"
  )"
  task_definition_arn="$(jq -r '.services[0].taskDefinition // empty' <<<"$service_json")"
  [[ -n "$task_definition_arn" ]] || die "failed to resolve task definition for ecs service: $service_name"

  task_definition_json="$(
    aws ecs describe-task-definition \
      --region "$aws_region" \
      --task-definition "$task_definition_arn"
  )"

  register_input="$(
    jq \
      --arg container_name "$container_name" \
      --argjson command "$command_json" \
      '
        .taskDefinition
        | .containerDefinitions = (
            .containerDefinitions
            | map(
                if .name == $container_name then
                  .command = $command
                else
                  .
                end
              )
          )
        | del(
            .taskDefinitionArn,
            .revision,
            .status,
            .requiresAttributes,
            .compatibilities,
            .registeredAt,
            .registeredBy,
            .deregisteredAt
          )
      ' <<<"$task_definition_json"
  )"

  aws ecs register-task-definition \
    --region "$aws_region" \
    --cli-input-json "$register_input" \
    | jq -r '.taskDefinition.taskDefinitionArn // empty'
}

ecs_service_log_group() {
  local aws_region="$1"
  local cluster_arn="$2"
  local service_name="$3"
  local container_name="$4"

  local service_json task_definition_arn task_definition_json
  service_json="$(
    aws ecs describe-services \
      --region "$aws_region" \
      --cluster "$cluster_arn" \
      --services "$service_name"
  )"
  task_definition_arn="$(jq -r '.services[0].taskDefinition // empty' <<<"$service_json")"
  [[ -n "$task_definition_arn" ]] || return 0

  task_definition_json="$(
    aws ecs describe-task-definition \
      --region "$aws_region" \
      --task-definition "$task_definition_arn"
  )"

  jq -r \
    --arg container_name "$container_name" \
    '.taskDefinition.containerDefinitions[] | select(.name == $container_name) | .logConfiguration.options["awslogs-group"] // empty' \
    <<<"$task_definition_json"
}

rollout_shared_proof_services_ecs() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"
  local proof_requestor_command_json="$5"
  local proof_funder_command_json="$6"

  local requestor_task_definition_arn funder_task_definition_arn
  requestor_task_definition_arn="$(
    ecs_register_service_task_definition \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_requestor_service_name" \
      "proof-requestor" \
      "$proof_requestor_command_json"
  )"
  [[ -n "$requestor_task_definition_arn" ]] || die "failed to register proof-requestor task definition revision"

  funder_task_definition_arn="$(
    ecs_register_service_task_definition \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_funder_service_name" \
      "proof-funder" \
      "$proof_funder_command_json"
  )"
  [[ -n "$funder_task_definition_arn" ]] || die "failed to register proof-funder task definition revision"

  aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_requestor_service_name" \
    --task-definition "$requestor_task_definition_arn" \
    --desired-count 1 \
    --force-new-deployment >/dev/null

  aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_funder_service_name" \
    --task-definition "$funder_task_definition_arn" \
    --desired-count 1 \
    --force-new-deployment >/dev/null

  aws ecs wait services-stable \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --services "$proof_requestor_service_name" "$proof_funder_service_name"
}

scale_shared_proof_services_ecs() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"
  local desired_count="$5"

  aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_requestor_service_name" \
    --desired-count "$desired_count" >/dev/null

  aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_funder_service_name" \
    --desired-count "$desired_count" >/dev/null

  aws ecs wait services-stable \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --services "$proof_requestor_service_name" "$proof_funder_service_name"
}

dump_shared_proof_services_ecs_logs() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"

  local requestor_log_group funder_log_group
  requestor_log_group="$(
    ecs_service_log_group \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_requestor_service_name" \
      "proof-requestor"
  )"
  funder_log_group="$(
    ecs_service_log_group \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_funder_service_name" \
      "proof-funder"
  )"

  if [[ -n "$requestor_log_group" ]]; then
    log "tailing shared proof-requestor ecs logs from $requestor_log_group"
    aws logs tail "$requestor_log_group" --region "$aws_region" --since 30m --format short | tail -n 200 >&2 || true
  fi
  if [[ -n "$funder_log_group" ]]; then
    log "tailing shared proof-funder ecs logs from $funder_log_group"
    aws logs tail "$funder_log_group" --region "$aws_region" --since 30m --format short | tail -n 200 >&2 || true
  fi

  aws ecs describe-services \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --services "$proof_requestor_service_name" "$proof_funder_service_name" \
    | jq -r '
      .services[]
      | .serviceName as $name
      | (.events // [])[:5][]
      | "[\($name)] \(.createdAt) \(.message)"
    ' >&2 || true
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
  local value_wei="$6"
  local recipient="$7"

  local attempt=1 output status nonce gas_price_wei
  while true; do
    nonce="$(cast nonce --rpc-url "$rpc_url" --block pending "$sender" 2>/dev/null || true)"
    [[ "$nonce" =~ ^[0-9]+$ ]] || nonce="$(cast nonce --rpc-url "$rpc_url" --block latest "$sender" 2>/dev/null || true)"
    [[ "$nonce" =~ ^[0-9]+$ ]] || nonce="0"
    gas_price_wei=$((5000000000 * attempt))

    set +e
    output="$(cast send \
      --rpc-url "$rpc_url" \
      --private-key "$private_key" \
      --async \
      --gas-limit 21000 \
      --gas-price "$gas_price_wei" \
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
      if (( attempt >= attempts )); then
        if force_replace_stuck_nonce "$rpc_url" "$private_key" "$sender" "$nonce"; then
          log "stuck nonce replacement succeeded; original transfer will retry on next balance probe"
          return 0
        fi
      fi
      log "cast send nonce race detected but sender nonce not advanced; nonce=$nonce gas_price_wei=$gas_price_wei attempt=${attempt}/${attempts}"
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

force_replace_stuck_nonce() {
  local rpc_url="$1"
  local private_key="$2"
  local sender="$3"
  local nonce="$4"

  local -a replacement_prices_wei=(
    50000000000
    100000000000
    200000000000
    400000000000
  )

  local gas_price_wei output status
  for gas_price_wei in "${replacement_prices_wei[@]}"; do
    set +e
    output="$(cast send \
      --rpc-url "$rpc_url" \
      --private-key "$private_key" \
      --async \
      --gas-limit 21000 \
      --gas-price "$gas_price_wei" \
      --nonce "$nonce" \
      --value 0 \
      "$sender" 2>&1)"
    status=$?
    set -e

    if (( status == 0 )); then
      log "submitted stuck nonce replacement tx nonce=$nonce gas_price_wei=$gas_price_wei"
    elif is_nonce_race_error "$output"; then
      log "stuck nonce replacement race nonce=$nonce gas_price_wei=$gas_price_wei"
    else
      log "stuck nonce replacement failed nonce=$nonce gas_price_wei=$gas_price_wei"
      continue
    fi

    sleep 2
    if nonce_has_advanced "$rpc_url" "$sender" "$nonce"; then
      return 0
    fi
  done

  return 1
}

ensure_recipient_min_balance() {
  local rpc_url="$1"
  local private_key="$2"
  local sender="$3"
  local recipient="$4"
  local min_balance_wei="$5"
  local label="$6"

  local attempt balance topup_wei
  for attempt in $(seq 1 12); do
    balance="$(cast balance --rpc-url "$rpc_url" "$recipient")"
    [[ "$balance" =~ ^[0-9]+$ ]] || die "unexpected $label balance from cast: $balance"
    if (( balance >= min_balance_wei )); then
      return 0
    fi

    topup_wei=$((min_balance_wei - balance))
    log "$label balance below target; topping up address=$recipient balance=$balance required=$min_balance_wei topup=$topup_wei attempt=$attempt/12"
    cast_send_with_nonce_retry 5 2 "$rpc_url" "$private_key" "$sender" "$topup_wei" "$recipient" >/dev/null
    sleep 2
  done

  return 1
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
  local dkg_summary_path=""
  local base_operator_fund_wei="1000000000000000"
  local bridge_verifier_address=""
  local bridge_deposit_image_id=""
  local bridge_withdraw_image_id=""
  local bridge_deposit_final_orchard_root=""
  local bridge_withdraw_final_orchard_root=""
  local bridge_deposit_checkpoint_height=""
  local bridge_deposit_checkpoint_block_hash=""
  local bridge_withdraw_checkpoint_height=""
  local bridge_withdraw_checkpoint_block_hash=""
  local bridge_proof_inputs_output=""
  local bridge_juno_execution_tx_hash=""
  local bridge_run_timeout=""
  local bridge_operator_signer_bin=""
  local boundless_auto="true"
  local boundless_proof_submission_mode="queue"
  local boundless_bin="boundless"
  local boundless_rpc_url="https://mainnet.base.org"
  local boundless_market_address="0xFd152dADc5183870710FE54f939Eae3aB9F0fE82"
  local boundless_verifier_router_address="0x0b144e07a0826182b6b59788c34b32bfa86fb711"
  local boundless_set_verifier_address="0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104"
  local boundless_input_mode="guest-witness-v1"
  local boundless_deposit_owallet_ivk_hex=""
  local boundless_withdraw_owallet_ovk_hex=""
  local -a boundless_deposit_witness_item_files=()
  local -a boundless_withdraw_witness_item_files=()
  local boundless_witness_juno_scan_url=""
  local boundless_witness_juno_rpc_url=""
  local boundless_witness_juno_scan_bearer_token_env="JUNO_SCAN_BEARER_TOKEN"
  local boundless_witness_juno_rpc_user_env="JUNO_RPC_USER"
  local boundless_witness_juno_rpc_pass_env="JUNO_RPC_PASS"
  local boundless_deposit_witness_wallet_id=""
  local boundless_deposit_witness_txid=""
  local boundless_deposit_witness_action_index=""
  local boundless_withdraw_witness_wallet_id=""
  local boundless_withdraw_witness_txid=""
  local boundless_withdraw_witness_action_index=""
  local boundless_withdraw_witness_withdrawal_id_hex=""
  local boundless_withdraw_witness_recipient_raw_address_hex=""
  local boundless_requestor_key_file=""
  local boundless_deposit_program_url=""
  local boundless_withdraw_program_url=""
  local boundless_input_s3_bucket=""
  local boundless_input_s3_prefix="bridge-e2e/boundless-input"
  local boundless_input_s3_region=""
  local boundless_input_s3_presign_ttl="2h"
  local boundless_min_price_wei="0"
  local boundless_max_price_wei="50000000000000"
  local boundless_max_price_cap_wei="250000000000000"
  local boundless_max_price_bump_multiplier="2"
  local boundless_max_price_bump_retries="3"
  local boundless_lock_stake_wei="20000000000000000000"
  local boundless_bidding_delay_seconds="85"
  local boundless_ramp_up_period_seconds="170"
  local boundless_lock_timeout_seconds="625"
  local boundless_timeout_seconds="1500"
  local shared_postgres_dsn=""
  local shared_kafka_brokers=""
  local shared_ipfs_api_url=""
  local shared_ecs_cluster_arn=""
  local shared_proof_requestor_service_name=""
  local shared_proof_funder_service_name=""
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
      --dkg-summary-path)
        [[ $# -ge 2 ]] || die "missing value for --dkg-summary-path"
        dkg_summary_path="$2"
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
      --bridge-deposit-final-orchard-root)
        [[ $# -ge 2 ]] || die "missing value for --bridge-deposit-final-orchard-root"
        bridge_deposit_final_orchard_root="$2"
        shift 2
        ;;
      --bridge-withdraw-final-orchard-root)
        [[ $# -ge 2 ]] || die "missing value for --bridge-withdraw-final-orchard-root"
        bridge_withdraw_final_orchard_root="$2"
        shift 2
        ;;
      --bridge-deposit-checkpoint-height)
        [[ $# -ge 2 ]] || die "missing value for --bridge-deposit-checkpoint-height"
        bridge_deposit_checkpoint_height="$2"
        shift 2
        ;;
      --bridge-deposit-checkpoint-block-hash)
        [[ $# -ge 2 ]] || die "missing value for --bridge-deposit-checkpoint-block-hash"
        bridge_deposit_checkpoint_block_hash="$2"
        shift 2
        ;;
      --bridge-withdraw-checkpoint-height)
        [[ $# -ge 2 ]] || die "missing value for --bridge-withdraw-checkpoint-height"
        bridge_withdraw_checkpoint_height="$2"
        shift 2
        ;;
      --bridge-withdraw-checkpoint-block-hash)
        [[ $# -ge 2 ]] || die "missing value for --bridge-withdraw-checkpoint-block-hash"
        bridge_withdraw_checkpoint_block_hash="$2"
        shift 2
        ;;
      --bridge-proof-inputs-output)
        [[ $# -ge 2 ]] || die "missing value for --bridge-proof-inputs-output"
        bridge_proof_inputs_output="$2"
        shift 2
        ;;
      --bridge-juno-execution-tx-hash)
        [[ $# -ge 2 ]] || die "missing value for --bridge-juno-execution-tx-hash"
        bridge_juno_execution_tx_hash="$2"
        shift 2
        ;;
      --bridge-run-timeout)
        [[ $# -ge 2 ]] || die "missing value for --bridge-run-timeout"
        bridge_run_timeout="$2"
        shift 2
        ;;
      --bridge-operator-signer-bin)
        [[ $# -ge 2 ]] || die "missing value for --bridge-operator-signer-bin"
        bridge_operator_signer_bin="$2"
        shift 2
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
        boundless_input_mode="$2"
        shift 2
        ;;
      --boundless-deposit-owallet-ivk-hex)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-owallet-ivk-hex"
        boundless_deposit_owallet_ivk_hex="$2"
        shift 2
        ;;
      --boundless-withdraw-owallet-ovk-hex)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-owallet-ovk-hex"
        boundless_withdraw_owallet_ovk_hex="$2"
        shift 2
        ;;
      --boundless-deposit-witness-item-file)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-witness-item-file"
        boundless_deposit_witness_item_files+=("$2")
        shift 2
        ;;
      --boundless-withdraw-witness-item-file)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-item-file"
        boundless_withdraw_witness_item_files+=("$2")
        shift 2
        ;;
      --boundless-witness-juno-scan-url)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-scan-url"
        boundless_witness_juno_scan_url="$2"
        shift 2
        ;;
      --boundless-witness-juno-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-rpc-url"
        boundless_witness_juno_rpc_url="$2"
        shift 2
        ;;
      --boundless-witness-juno-scan-bearer-token-env)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-scan-bearer-token-env"
        boundless_witness_juno_scan_bearer_token_env="$2"
        shift 2
        ;;
      --boundless-witness-juno-rpc-user-env)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-rpc-user-env"
        boundless_witness_juno_rpc_user_env="$2"
        shift 2
        ;;
      --boundless-witness-juno-rpc-pass-env)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-rpc-pass-env"
        boundless_witness_juno_rpc_pass_env="$2"
        shift 2
        ;;
      --boundless-deposit-witness-wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-witness-wallet-id"
        boundless_deposit_witness_wallet_id="$2"
        shift 2
        ;;
      --boundless-deposit-witness-txid)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-witness-txid"
        boundless_deposit_witness_txid="$2"
        shift 2
        ;;
      --boundless-deposit-witness-action-index)
        [[ $# -ge 2 ]] || die "missing value for --boundless-deposit-witness-action-index"
        boundless_deposit_witness_action_index="$2"
        shift 2
        ;;
      --boundless-withdraw-witness-wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-wallet-id"
        boundless_withdraw_witness_wallet_id="$2"
        shift 2
        ;;
      --boundless-withdraw-witness-txid)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-txid"
        boundless_withdraw_witness_txid="$2"
        shift 2
        ;;
      --boundless-withdraw-witness-action-index)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-action-index"
        boundless_withdraw_witness_action_index="$2"
        shift 2
        ;;
      --boundless-withdraw-witness-withdrawal-id-hex)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-withdrawal-id-hex"
        boundless_withdraw_witness_withdrawal_id_hex="$2"
        shift 2
        ;;
      --boundless-withdraw-witness-recipient-raw-address-hex)
        [[ $# -ge 2 ]] || die "missing value for --boundless-withdraw-witness-recipient-raw-address-hex"
        boundless_withdraw_witness_recipient_raw_address_hex="$2"
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
      --boundless-input-s3-bucket)
        [[ $# -ge 2 ]] || die "missing value for --boundless-input-s3-bucket"
        boundless_input_s3_bucket="$2"
        shift 2
        ;;
      --boundless-input-s3-prefix)
        [[ $# -ge 2 ]] || die "missing value for --boundless-input-s3-prefix"
        boundless_input_s3_prefix="$2"
        shift 2
        ;;
      --boundless-input-s3-region)
        [[ $# -ge 2 ]] || die "missing value for --boundless-input-s3-region"
        boundless_input_s3_region="$2"
        shift 2
        ;;
      --boundless-input-s3-presign-ttl)
        [[ $# -ge 2 ]] || die "missing value for --boundless-input-s3-presign-ttl"
        boundless_input_s3_presign_ttl="$2"
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
      --boundless-max-price-cap-wei)
        [[ $# -ge 2 ]] || die "missing value for --boundless-max-price-cap-wei"
        boundless_max_price_cap_wei="$2"
        shift 2
        ;;
      --boundless-max-price-bump-multiplier)
        [[ $# -ge 2 ]] || die "missing value for --boundless-max-price-bump-multiplier"
        boundless_max_price_bump_multiplier="$2"
        shift 2
        ;;
      --boundless-max-price-bump-retries)
        [[ $# -ge 2 ]] || die "missing value for --boundless-max-price-bump-retries"
        boundless_max_price_bump_retries="$2"
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
      --shared-ipfs-api-url)
        [[ $# -ge 2 ]] || die "missing value for --shared-ipfs-api-url"
        shared_ipfs_api_url="$2"
        shift 2
        ;;
      --shared-ecs-cluster-arn)
        [[ $# -ge 2 ]] || die "missing value for --shared-ecs-cluster-arn"
        shared_ecs_cluster_arn="$2"
        shift 2
        ;;
      --shared-proof-requestor-service-name)
        [[ $# -ge 2 ]] || die "missing value for --shared-proof-requestor-service-name"
        shared_proof_requestor_service_name="$2"
        shift 2
        ;;
      --shared-proof-funder-service-name)
        [[ $# -ge 2 ]] || die "missing value for --shared-proof-funder-service-name"
        shared_proof_funder_service_name="$2"
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
  [[ "$boundless_max_price_cap_wei" =~ ^[0-9]+$ ]] || die "--boundless-max-price-cap-wei must be numeric"
  [[ "$boundless_max_price_bump_multiplier" =~ ^[0-9]+$ ]] || die "--boundless-max-price-bump-multiplier must be numeric"
  [[ "$boundless_max_price_bump_retries" =~ ^[0-9]+$ ]] || die "--boundless-max-price-bump-retries must be numeric"
  [[ "$boundless_lock_stake_wei" =~ ^[0-9]+$ ]] || die "--boundless-lock-stake-wei must be numeric"
  [[ "$boundless_bidding_delay_seconds" =~ ^[0-9]+$ ]] || die "--boundless-bidding-delay-seconds must be numeric"
  [[ "$boundless_ramp_up_period_seconds" =~ ^[0-9]+$ ]] || die "--boundless-ramp-up-period-seconds must be numeric"
  [[ "$boundless_lock_timeout_seconds" =~ ^[0-9]+$ ]] || die "--boundless-lock-timeout-seconds must be numeric"
  [[ "$boundless_timeout_seconds" =~ ^[0-9]+$ ]] || die "--boundless-timeout-seconds must be numeric"
  [[ -z "$bridge_deposit_checkpoint_height" || "$bridge_deposit_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-deposit-checkpoint-height must be numeric"
  [[ -z "$bridge_withdraw_checkpoint_height" || "$bridge_withdraw_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-withdraw-checkpoint-height must be numeric"
  (( boundless_max_price_cap_wei >= boundless_max_price_wei )) || die "--boundless-max-price-cap-wei must be >= --boundless-max-price-wei"
  if [[ "$boundless_input_mode" != "guest-witness-v1" ]]; then
    die "--boundless-input-mode must be guest-witness-v1"
  fi
  if (( boundless_max_price_bump_retries > 0 && boundless_max_price_bump_multiplier < 2 )); then
    die "--boundless-max-price-bump-multiplier must be >= 2 when --boundless-max-price-bump-retries > 0"
  fi
  if [[ -z "$bridge_run_timeout" ]]; then
    bridge_run_timeout="90m"
  fi

  [[ -n "$boundless_requestor_key_file" ]] || die "--boundless-requestor-key-file is required"
  [[ -f "$boundless_requestor_key_file" ]] || die "boundless requestor key file not found: $boundless_requestor_key_file"
  [[ -n "$boundless_deposit_program_url" ]] || die "--boundless-deposit-program-url is required"
  [[ -n "$boundless_withdraw_program_url" ]] || die "--boundless-withdraw-program-url is required"
  [[ -n "$boundless_input_s3_prefix" ]] || die "--boundless-input-s3-prefix must not be empty"
  [[ -n "$boundless_input_s3_presign_ttl" ]] || die "--boundless-input-s3-presign-ttl must not be empty"
  [[ -n "$bridge_verifier_address" ]] || die "--bridge-verifier-address is required"
  [[ -n "$bridge_deposit_image_id" ]] || die "--bridge-deposit-image-id is required"
  [[ -n "$bridge_withdraw_image_id" ]] || die "--bridge-withdraw-image-id is required"
  local guest_witness_manual_mode="true"
  local guest_witness_extract_mode="false"
  [[ -n "$boundless_input_s3_bucket" ]] || die "--boundless-input-s3-bucket is required when --boundless-input-mode guest-witness-v1"
  [[ -n "$boundless_deposit_owallet_ivk_hex" ]] || die "--boundless-deposit-owallet-ivk-hex is required when --boundless-input-mode guest-witness-v1"
  [[ -n "$boundless_withdraw_owallet_ovk_hex" ]] || die "--boundless-withdraw-owallet-ovk-hex is required when --boundless-input-mode guest-witness-v1"

  local guest_witness_extract_any="false"
  if [[ -n "$boundless_witness_juno_scan_url" || -n "$boundless_witness_juno_rpc_url" || \
    -n "$boundless_deposit_witness_wallet_id" || -n "$boundless_deposit_witness_txid" || -n "$boundless_deposit_witness_action_index" || \
    -n "$boundless_withdraw_witness_wallet_id" || -n "$boundless_withdraw_witness_txid" || -n "$boundless_withdraw_witness_action_index" || \
    -n "$boundless_withdraw_witness_withdrawal_id_hex" || -n "$boundless_withdraw_witness_recipient_raw_address_hex" ]]; then
    guest_witness_extract_any="true"
  fi

  if (( ${#boundless_deposit_witness_item_files[@]} > 0 || ${#boundless_withdraw_witness_item_files[@]} > 0 )); then
    (( ${#boundless_deposit_witness_item_files[@]} > 0 )) || die "--boundless-deposit-witness-item-file is required when --boundless-withdraw-witness-item-file is set"
    (( ${#boundless_withdraw_witness_item_files[@]} > 0 )) || die "--boundless-withdraw-witness-item-file is required when --boundless-deposit-witness-item-file is set"
    if [[ "$guest_witness_extract_any" == "true" ]]; then
      die "guest witness extraction flags cannot be combined with explicit --boundless-*-witness-item-file inputs"
    fi
  else
    guest_witness_manual_mode="false"
    guest_witness_extract_mode="true"
    [[ "$boundless_deposit_witness_action_index" =~ ^[0-9]+$ ]] || die "--boundless-deposit-witness-action-index must be numeric when guest witness extraction is enabled"
    [[ "$boundless_withdraw_witness_action_index" =~ ^[0-9]+$ ]] || die "--boundless-withdraw-witness-action-index must be numeric when guest witness extraction is enabled"
    [[ -n "$boundless_witness_juno_scan_url" ]] || die "--boundless-witness-juno-scan-url is required when witness files are not provided"
    [[ -n "$boundless_witness_juno_rpc_url" ]] || die "--boundless-witness-juno-rpc-url is required when witness files are not provided"
    [[ -n "$boundless_deposit_witness_wallet_id" ]] || die "--boundless-deposit-witness-wallet-id is required when witness files are not provided"
    [[ -n "$boundless_deposit_witness_txid" ]] || die "--boundless-deposit-witness-txid is required when witness files are not provided"
    [[ -n "$boundless_deposit_witness_action_index" ]] || die "--boundless-deposit-witness-action-index is required when witness files are not provided"
    [[ -n "$boundless_withdraw_witness_wallet_id" ]] || die "--boundless-withdraw-witness-wallet-id is required when witness files are not provided"
    [[ -n "$boundless_withdraw_witness_txid" ]] || die "--boundless-withdraw-witness-txid is required when witness files are not provided"
    [[ -n "$boundless_withdraw_witness_action_index" ]] || die "--boundless-withdraw-witness-action-index is required when witness files are not provided"
    [[ -n "$boundless_withdraw_witness_withdrawal_id_hex" ]] || die "--boundless-withdraw-witness-withdrawal-id-hex is required when witness files are not provided"
    [[ -n "$boundless_withdraw_witness_recipient_raw_address_hex" ]] || die "--boundless-withdraw-witness-recipient-raw-address-hex is required when witness files are not provided"
  fi
  local witness_file
  if [[ "$guest_witness_extract_mode" != "true" ]]; then
    for witness_file in "${boundless_deposit_witness_item_files[@]}"; do
      [[ -f "$witness_file" ]] || die "boundless deposit witness item file not found: $witness_file"
    done
    for witness_file in "${boundless_withdraw_witness_item_files[@]}"; do
      [[ -f "$witness_file" ]] || die "boundless withdraw witness item file not found: $witness_file"
    done
    [[ -n "$bridge_deposit_final_orchard_root" ]] || \
      die "--bridge-deposit-final-orchard-root is required when witness files are provided"
    [[ -n "$bridge_deposit_checkpoint_height" ]] || \
      die "--bridge-deposit-checkpoint-height is required when witness files are provided"
    [[ -n "$bridge_deposit_checkpoint_block_hash" ]] || \
      die "--bridge-deposit-checkpoint-block-hash is required when witness files are provided"
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

  [[ -n "$shared_postgres_dsn" ]] || die "--shared-postgres-dsn is required (centralized proof-requestor/proof-funder topology)"
  [[ -n "$shared_kafka_brokers" ]] || die "--shared-kafka-brokers is required (centralized proof-requestor/proof-funder topology)"
  [[ -n "$shared_ipfs_api_url" ]] || die "--shared-ipfs-api-url is required (checkpoint package publish/pin verification)"
  [[ -n "$shared_topic_prefix" ]] || die "--shared-topic-prefix must not be empty"
  local shared_ecs_enabled="false"
  if [[ -n "$shared_ecs_cluster_arn" || -n "$shared_proof_requestor_service_name" || -n "$shared_proof_funder_service_name" ]]; then
    [[ -n "$shared_ecs_cluster_arn" ]] || die "--shared-ecs-cluster-arn is required when shared ECS proof services are enabled"
    [[ -n "$shared_proof_requestor_service_name" ]] || die "--shared-proof-requestor-service-name is required when shared ECS proof services are enabled"
    [[ -n "$shared_proof_funder_service_name" ]] || die "--shared-proof-funder-service-name is required when shared ECS proof services are enabled"
    shared_ecs_enabled="true"
  fi
  local shared_enabled="true"

  ensure_base_dependencies
  ensure_command go
  ensure_command "$boundless_bin"
  local boundless_version
  boundless_version="$("$boundless_bin" --version 2>/dev/null || true)"
  if [[ "$boundless_version" == boundless-cli\ 0.* ]]; then
    die "boundless-auto requires boundless-cli v1.x+; installed version is '$boundless_version'"
  fi
  ensure_command openssl
  ensure_command cast
  if [[ "$shared_ecs_enabled" == "true" ]]; then
    ensure_command aws
  fi

  local bridge_recipient_key_file="$workdir/reports/bridge-recipient.key"
  local bridge_recipient_key_hex="0x$(openssl rand -hex 32)"
  printf '%s\n' "$bridge_recipient_key_hex" >"$bridge_recipient_key_file"
  chmod 0600 "$bridge_recipient_key_file"
  local bridge_recipient_address
  bridge_recipient_address="$(cast wallet address --private-key "$bridge_recipient_key_hex")"
  if [[ -z "$bridge_recipient_address" ]]; then
    die "failed to derive bridge recipient address"
  fi
  local boundless_requestor_key_hex
  boundless_requestor_key_hex="$(trimmed_file_value "$boundless_requestor_key_file")"
  [[ -n "$boundless_requestor_key_hex" ]] || die "boundless requestor key file is empty: $boundless_requestor_key_file"
  local boundless_requestor_address
  boundless_requestor_address="$(cast wallet address --private-key "$boundless_requestor_key_hex" 2>/dev/null || true)"
  [[ -n "$boundless_requestor_address" ]] || die "failed to derive boundless requestor address from key file: $boundless_requestor_key_file"
  ensure_dir "$(dirname "$output_path")"

  if [[ -d "$workdir" ]]; then
    if [[ "$force" != "true" && -z "$dkg_summary_path" ]]; then
      die "workdir already exists (use --force to overwrite): $workdir"
    fi
    if [[ "$force" == "true" && -z "$dkg_summary_path" ]]; then
      rm -rf "$workdir"
    fi
  fi
  ensure_dir "$workdir/reports"

  local proof_topic_seed
  proof_topic_seed="$(date +%s)-$RANDOM"
  local proof_request_topic="${shared_topic_prefix}.proof.requests.${proof_topic_seed}"
  local proof_result_topic="${shared_topic_prefix}.proof.fulfillments.${proof_topic_seed}"
  local proof_failure_topic="${shared_topic_prefix}.proof.failures.${proof_topic_seed}"
  local proof_requestor_group="${shared_topic_prefix}.proof-requestor.${proof_topic_seed}"
  local proof_bridge_consumer_group="${shared_topic_prefix}.bridge-e2e.${proof_topic_seed}"

  local dkg_summary="$workdir/reports/dkg-summary.json"
  local bridge_summary="$workdir/reports/base-bridge-summary.json"
  local shared_summary="$shared_output"

  if [[ "$boundless_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    ensure_dir "$workdir/reports/witness"
    local deposit_witness_auto_file="$workdir/reports/witness/deposit.witness.bin"
    local withdraw_witness_auto_file="$workdir/reports/witness/withdraw.witness.bin"
    local deposit_witness_auto_json="$workdir/reports/witness/deposit-witness.json"
    local withdraw_witness_auto_json="$workdir/reports/witness/withdraw-witness.json"

    (
      cd "$REPO_ROOT"
      go run ./cmd/juno-witness-extract deposit \
        --juno-scan-url "$boundless_witness_juno_scan_url" \
        --wallet-id "$boundless_deposit_witness_wallet_id" \
        --juno-scan-bearer-token-env "$boundless_witness_juno_scan_bearer_token_env" \
        --juno-rpc-url "$boundless_witness_juno_rpc_url" \
        --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
        --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
        --txid "$boundless_deposit_witness_txid" \
        --action-index "$boundless_deposit_witness_action_index" \
        --output-witness-item-file "$deposit_witness_auto_file" >"$deposit_witness_auto_json"

      go run ./cmd/juno-witness-extract withdraw \
        --juno-scan-url "$boundless_witness_juno_scan_url" \
        --wallet-id "$boundless_withdraw_witness_wallet_id" \
        --juno-scan-bearer-token-env "$boundless_witness_juno_scan_bearer_token_env" \
        --juno-rpc-url "$boundless_witness_juno_rpc_url" \
        --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
        --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
        --txid "$boundless_withdraw_witness_txid" \
        --action-index "$boundless_withdraw_witness_action_index" \
        --withdrawal-id-hex "$boundless_withdraw_witness_withdrawal_id_hex" \
        --recipient-raw-address-hex "$boundless_withdraw_witness_recipient_raw_address_hex" \
        --output-witness-item-file "$withdraw_witness_auto_file" >"$withdraw_witness_auto_json"
    )

    boundless_deposit_witness_item_files=("$deposit_witness_auto_file")
    boundless_withdraw_witness_item_files=("$withdraw_witness_auto_file")

    if [[ -z "$bridge_deposit_final_orchard_root" ]]; then
      bridge_deposit_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$deposit_witness_auto_json")"
    fi
    if [[ -z "$bridge_withdraw_final_orchard_root" ]]; then
      bridge_withdraw_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$withdraw_witness_auto_json")"
    fi
    if [[ -z "$bridge_deposit_checkpoint_height" ]]; then
      bridge_deposit_checkpoint_height="$(jq -r '.anchor_height // empty' "$deposit_witness_auto_json")"
    fi
    if [[ -z "$bridge_deposit_checkpoint_block_hash" ]]; then
      bridge_deposit_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_witness_auto_json")"
    fi
    if [[ -z "$bridge_withdraw_checkpoint_height" ]]; then
      bridge_withdraw_checkpoint_height="$(jq -r '.anchor_height // empty' "$withdraw_witness_auto_json")"
    fi
    if [[ -z "$bridge_withdraw_checkpoint_block_hash" ]]; then
      bridge_withdraw_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$withdraw_witness_auto_json")"
    fi
  fi

  if [[ -z "$bridge_withdraw_final_orchard_root" ]]; then
    bridge_withdraw_final_orchard_root="$bridge_deposit_final_orchard_root"
  fi
  if [[ -z "$bridge_withdraw_checkpoint_height" ]]; then
    bridge_withdraw_checkpoint_height="$bridge_deposit_checkpoint_height"
  fi
  if [[ -z "$bridge_withdraw_checkpoint_block_hash" ]]; then
    bridge_withdraw_checkpoint_block_hash="$bridge_deposit_checkpoint_block_hash"
  fi
  [[ -n "$bridge_deposit_final_orchard_root" ]] || \
    die "--bridge-deposit-final-orchard-root is required"
  [[ -n "$bridge_withdraw_final_orchard_root" ]] || \
    die "--bridge-withdraw-final-orchard-root is required"
  [[ -n "$bridge_deposit_checkpoint_height" ]] || \
    die "--bridge-deposit-checkpoint-height is required"
  [[ -n "$bridge_deposit_checkpoint_block_hash" ]] || \
    die "--bridge-deposit-checkpoint-block-hash is required"
  [[ -n "$bridge_withdraw_checkpoint_height" ]] || \
    die "--bridge-withdraw-checkpoint-height is required"
  [[ -n "$bridge_withdraw_checkpoint_block_hash" ]] || \
    die "--bridge-withdraw-checkpoint-block-hash is required"
  [[ "$bridge_deposit_checkpoint_height" =~ ^[0-9]+$ ]] || \
    die "--bridge-deposit-checkpoint-height must be numeric"
  [[ "$bridge_withdraw_checkpoint_height" =~ ^[0-9]+$ ]] || \
    die "--bridge-withdraw-checkpoint-height must be numeric"
  (( bridge_deposit_checkpoint_height > 0 )) || die "--bridge-deposit-checkpoint-height must be > 0"
  (( bridge_withdraw_checkpoint_height > 0 )) || die "--bridge-withdraw-checkpoint-height must be > 0"

  if [[ "$shared_enabled" == "true" ]]; then
    (
      cd "$REPO_ROOT"
      go run ./cmd/shared-infra-e2e \
        --postgres-dsn "$shared_postgres_dsn" \
        --kafka-brokers "$shared_kafka_brokers" \
        --checkpoint-ipfs-api-url "$shared_ipfs_api_url" \
        --topic-prefix "$shared_topic_prefix" \
        --timeout "$shared_timeout" \
        --output "$shared_summary"
    )
  fi

  (
    cd "$REPO_ROOT/contracts"
    forge build
  )

  if [[ -n "$dkg_summary_path" ]]; then
    dkg_summary="$dkg_summary_path"
    [[ -f "$dkg_summary" ]] || die "dkg summary file not found: $dkg_summary"
    local summary_operator_count summary_threshold
    summary_operator_count="$(jq -r '.operator_count // (.operators | length) // 0' "$dkg_summary")"
    summary_threshold="$(jq -r '.threshold // 0' "$dkg_summary")"
    [[ "$summary_operator_count" =~ ^[0-9]+$ ]] || die "dkg summary operator_count is invalid: $summary_operator_count"
    (( summary_operator_count >= 1 )) || die "dkg summary operator_count must be >= 1"
    operator_count="$summary_operator_count"
    if [[ "$summary_threshold" =~ ^[0-9]+$ ]] && (( summary_threshold >= 1 )); then
      threshold="$summary_threshold"
    fi
  else
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
  fi

  if [[ -z "$bridge_operator_signer_bin" ]]; then
    local coordinator_workdir_from_summary
    coordinator_workdir_from_summary="$(jq -r '.coordinator_workdir // empty' "$dkg_summary")"
    if [[ -n "$coordinator_workdir_from_summary" && -x "$coordinator_workdir_from_summary/bin/dkg-admin" ]]; then
      bridge_operator_signer_bin="$coordinator_workdir_from_summary/bin/dkg-admin"
    else
      bridge_operator_signer_bin="dkg-admin"
    fi
  fi
  if [[ "$bridge_operator_signer_bin" == */* ]]; then
    [[ -x "$bridge_operator_signer_bin" ]] || die "bridge operator signer binary is not executable: $bridge_operator_signer_bin"
  else
    command -v "$bridge_operator_signer_bin" >/dev/null 2>&1 || die "bridge operator signer binary not found in PATH: $bridge_operator_signer_bin"
  fi

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

    local operator
    while IFS= read -r operator; do
      [[ -n "$operator" ]] || continue
      ensure_recipient_min_balance "$base_rpc_url" "$base_key" "$funding_sender_address" "$operator" "$base_operator_fund_wei" "operator pre-fund" || \
        die "failed to pre-fund operator: address=$operator required_wei=$base_operator_fund_wei"
    done < <(jq -r '.operators[].operator_id' "$dkg_summary")

    local bridge_deployer_required_wei
    bridge_deployer_required_wei=$((base_operator_fund_wei * 10))
    # Bridge deployment retries can require a high fee cap on Base testnet; keep
    # a hard floor so replacement transactions do not fail with insufficient funds.
    local bridge_deployer_min_wei="70000000000000000"
    if (( bridge_deployer_required_wei < bridge_deployer_min_wei )); then
      bridge_deployer_required_wei="$bridge_deployer_min_wei"
    fi
    ensure_recipient_min_balance "$base_rpc_url" "$base_key" "$funding_sender_address" "$bridge_deployer_address" "$bridge_deployer_required_wei" "bridge deployer" || \
      die "failed to fund bridge deployer: address=$bridge_deployer_address required_wei=$bridge_deployer_required_wei"
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
    "--operator-signer-bin" "$bridge_operator_signer_bin"
    "--threshold" "$threshold"
    "--contracts-out" "$contracts_out"
    "--recipient" "$bridge_recipient_address"
    "--boundless-auto"
    "--run-timeout" "$bridge_run_timeout"
    "--output" "$bridge_summary"
  )
  bridge_args+=("--verifier-address" "$bridge_verifier_address")
  bridge_args+=("--deposit-image-id" "$bridge_deposit_image_id")
  bridge_args+=("--withdraw-image-id" "$bridge_withdraw_image_id")
  bridge_args+=("--deposit-final-orchard-root" "$bridge_deposit_final_orchard_root")
  bridge_args+=("--withdraw-final-orchard-root" "$bridge_withdraw_final_orchard_root")
  bridge_args+=("--deposit-checkpoint-height" "$bridge_deposit_checkpoint_height")
  bridge_args+=("--deposit-checkpoint-block-hash" "$bridge_deposit_checkpoint_block_hash")
  bridge_args+=("--withdraw-checkpoint-height" "$bridge_withdraw_checkpoint_height")
  bridge_args+=("--withdraw-checkpoint-block-hash" "$bridge_withdraw_checkpoint_block_hash")
  if [[ -n "$bridge_proof_inputs_output" ]]; then
    bridge_args+=("--proof-inputs-output" "$bridge_proof_inputs_output")
  fi
  if [[ -n "$bridge_juno_execution_tx_hash" ]]; then
    bridge_args+=("--juno-execution-tx-hash" "$bridge_juno_execution_tx_hash")
  fi
  bridge_args+=(
    "--boundless-bin" "$boundless_bin"
    "--boundless-rpc-url" "$boundless_rpc_url"
    "--boundless-proof-submission-mode" "$boundless_proof_submission_mode"
    "--boundless-proof-queue-brokers" "$shared_kafka_brokers"
    "--boundless-proof-request-topic" "$proof_request_topic"
    "--boundless-proof-result-topic" "$proof_result_topic"
    "--boundless-proof-failure-topic" "$proof_failure_topic"
    "--boundless-proof-consumer-group" "$proof_bridge_consumer_group"
    "--boundless-market-address" "$boundless_market_address"
    "--boundless-verifier-router-address" "$boundless_verifier_router_address"
    "--boundless-set-verifier-address" "$boundless_set_verifier_address"
    "--boundless-input-mode" "$boundless_input_mode"
    "--boundless-deposit-program-url" "$boundless_deposit_program_url"
    "--boundless-withdraw-program-url" "$boundless_withdraw_program_url"
    "--boundless-input-s3-bucket" "$boundless_input_s3_bucket"
    "--boundless-input-s3-prefix" "$boundless_input_s3_prefix"
    "--boundless-input-s3-region" "$boundless_input_s3_region"
    "--boundless-input-s3-presign-ttl" "$boundless_input_s3_presign_ttl"
    "--boundless-min-price-wei" "$boundless_min_price_wei"
    "--boundless-max-price-wei" "$boundless_max_price_wei"
    "--boundless-max-price-cap-wei" "$boundless_max_price_cap_wei"
    "--boundless-max-price-bump-multiplier" "$boundless_max_price_bump_multiplier"
    "--boundless-max-price-bump-retries" "$boundless_max_price_bump_retries"
    "--boundless-lock-stake-wei" "$boundless_lock_stake_wei"
    "--boundless-bidding-delay-seconds" "$boundless_bidding_delay_seconds"
    "--boundless-ramp-up-period-seconds" "$boundless_ramp_up_period_seconds"
    "--boundless-lock-timeout-seconds" "$boundless_lock_timeout_seconds"
    "--boundless-timeout-seconds" "$boundless_timeout_seconds"
  )
  bridge_args+=(
    "--boundless-deposit-owallet-ivk-hex" "$boundless_deposit_owallet_ivk_hex"
    "--boundless-withdraw-owallet-ovk-hex" "$boundless_withdraw_owallet_ovk_hex"
  )
  for witness_file in "${boundless_deposit_witness_item_files[@]}"; do
    bridge_args+=("--boundless-deposit-witness-item-file" "$witness_file")
  done
  for witness_file in "${boundless_withdraw_witness_item_files[@]}"; do
    bridge_args+=("--boundless-withdraw-witness-item-file" "$witness_file")
  done

  local operator_id operator_endpoint
  while IFS=$'\t' read -r operator_id operator_endpoint; do
    [[ -n "$operator_id" ]] || continue
    bridge_args+=("--operator-address" "$operator_id")
    [[ -n "$operator_endpoint" ]] || die "dkg summary missing operator endpoint for operator_id=$operator_id"
    bridge_args+=("--operator-signer-endpoint" "$operator_endpoint")
  done < <(jq -r '.operators[] | [.operator_id, (.endpoint // .grpc_endpoint // "")] | @tsv' "$dkg_summary")

  local proof_requestor_log="$workdir/reports/proof-requestor.log"
  local proof_funder_log="$workdir/reports/proof-funder.log"
  local proof_services_mode="local-process"
  local proof_requestor_owner="testnet-e2e-proof-requestor-${proof_topic_seed}"
  local proof_funder_owner="testnet-e2e-proof-funder-${proof_topic_seed}"
  local proof_requestor_pid=""
  local proof_funder_pid=""
  local shared_ecs_region=""
  local shared_ecs_started="false"

  if [[ "$shared_ecs_enabled" == "true" ]]; then
    proof_services_mode="shared-ecs"
    proof_requestor_log=""
    proof_funder_log=""
    shared_ecs_region="$(resolve_aws_region)"

    local -a proof_requestor_ecs_command=(
      "/usr/local/bin/proof-requestor"
      "--postgres-dsn" "$shared_postgres_dsn"
      "--store-driver" "postgres"
      "--owner" "$proof_requestor_owner"
      "--requestor-address" "$boundless_requestor_address"
      "--requestor-key-secret-arn" "unused"
      "--requestor-key-env" "PROOF_REQUESTOR_KEY"
      "--secrets-driver" "env"
      "--chain-id" "$base_chain_id"
      "--submission-mode" "offchain_primary_onchain_fallback"
      "--order-stream-url" "$boundless_rpc_url"
      "--boundless-market-address" "$boundless_market_address"
      "--input-topic" "$proof_request_topic"
      "--result-topic" "$proof_result_topic"
      "--failure-topic" "$proof_failure_topic"
      "--max-inflight-requests" "32"
      "--request-timeout" "${boundless_timeout_seconds}s"
      "--queue-driver" "kafka"
      "--queue-brokers" "$shared_kafka_brokers"
      "--queue-group" "$proof_requestor_group"
      "--boundless-bin" "/usr/local/bin/boundless"
      "--onchain-max-price-per-proof-wei" "$boundless_max_price_cap_wei"
      "--onchain-max-stake-per-proof-wei" "$boundless_lock_stake_wei"
    )
    local -a proof_funder_ecs_command=(
      "/usr/local/bin/proof-funder"
      "--postgres-dsn" "$shared_postgres_dsn"
      "--lease-driver" "postgres"
      "--owner-id" "$proof_funder_owner"
      "--owner-address" "$boundless_requestor_address"
      "--owner-key-secret-arn" "unused"
      "--owner-key-env" "PROOF_FUNDER_KEY"
      "--secrets-driver" "env"
      "--requestor-address" "$boundless_requestor_address"
      "--queue-driver" "kafka"
      "--queue-brokers" "$shared_kafka_brokers"
      "--boundless-bin" "/usr/local/bin/boundless"
    )
    local proof_requestor_ecs_command_json
    local proof_funder_ecs_command_json
    proof_requestor_ecs_command_json="$(json_array_from_args "${proof_requestor_ecs_command[@]}")"
    proof_funder_ecs_command_json="$(json_array_from_args "${proof_funder_ecs_command[@]}")"

    log "rolling out shared ECS proof-requestor/proof-funder services"
    rollout_shared_proof_services_ecs \
      "$shared_ecs_region" \
      "$shared_ecs_cluster_arn" \
      "$shared_proof_requestor_service_name" \
      "$shared_proof_funder_service_name" \
      "$proof_requestor_ecs_command_json" \
      "$proof_funder_ecs_command_json"
    shared_ecs_started="true"
  else
    local proof_requestor_bin="$workdir/bin/proof-requestor"
    local proof_funder_bin="$workdir/bin/proof-funder"
    ensure_dir "$workdir/bin"
    (
      cd "$REPO_ROOT"
      go build -o "$proof_requestor_bin" ./cmd/proof-requestor
      go build -o "$proof_funder_bin" ./cmd/proof-funder
    )

    (
      cd "$REPO_ROOT"
      PROOF_REQUESTOR_KEY="$boundless_requestor_key_hex" "$proof_requestor_bin" \
        --postgres-dsn "$shared_postgres_dsn" \
        --store-driver postgres \
        --owner "$proof_requestor_owner" \
        --requestor-address "$boundless_requestor_address" \
        --requestor-key-secret-arn "unused" \
        --requestor-key-env "PROOF_REQUESTOR_KEY" \
        --secrets-driver env \
        --chain-id "$base_chain_id" \
        --submission-mode offchain_primary_onchain_fallback \
        --order-stream-url "$boundless_rpc_url" \
        --boundless-market-address "$boundless_market_address" \
        --input-topic "$proof_request_topic" \
        --result-topic "$proof_result_topic" \
        --failure-topic "$proof_failure_topic" \
        --max-inflight-requests 32 \
        --request-timeout "${boundless_timeout_seconds}s" \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --queue-group "$proof_requestor_group" \
        --boundless-bin "$boundless_bin" \
        --onchain-max-price-per-proof-wei "$boundless_max_price_cap_wei" \
        --onchain-max-stake-per-proof-wei "$boundless_lock_stake_wei" \
        >"$proof_requestor_log" 2>&1
    ) &
    proof_requestor_pid="$!"

    (
      cd "$REPO_ROOT"
      PROOF_FUNDER_KEY="$boundless_requestor_key_hex" "$proof_funder_bin" \
        --postgres-dsn "$shared_postgres_dsn" \
        --lease-driver postgres \
        --owner-id "$proof_funder_owner" \
        --owner-address "$boundless_requestor_address" \
        --owner-key-secret-arn "unused" \
        --owner-key-env "PROOF_FUNDER_KEY" \
        --secrets-driver env \
        --requestor-address "$boundless_requestor_address" \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --boundless-bin "$boundless_bin" \
        >"$proof_funder_log" 2>&1
    ) &
    proof_funder_pid="$!"

    sleep 5
    if ! kill -0 "$proof_requestor_pid" >/dev/null 2>&1; then
      log "proof-requestor failed to start; showing log"
      tail -n 200 "$proof_requestor_log" >&2 || true
      die "proof-requestor did not stay running"
    fi
    if ! kill -0 "$proof_funder_pid" >/dev/null 2>&1; then
      log "proof-funder failed to start; showing log"
      tail -n 200 "$proof_funder_log" >&2 || true
      kill "$proof_requestor_pid" >/dev/null 2>&1 || true
      wait "$proof_requestor_pid" >/dev/null 2>&1 || true
      die "proof-funder did not stay running"
    fi
  fi

  local bridge_status=0
  set +e
  (
    cd "$REPO_ROOT"
    go run ./cmd/bridge-e2e "${bridge_args[@]}"
  )
  bridge_status="$?"
  set -e

  if [[ "$shared_ecs_enabled" == "true" ]]; then
    if [[ "$shared_ecs_started" == "true" ]]; then
      scale_shared_proof_services_ecs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name" \
        "0" || true
    fi
  else
    kill "$proof_requestor_pid" "$proof_funder_pid" >/dev/null 2>&1 || true
    wait "$proof_requestor_pid" >/dev/null 2>&1 || true
    wait "$proof_funder_pid" >/dev/null 2>&1 || true
  fi
  if (( bridge_status != 0 )); then
    if [[ "$shared_ecs_enabled" == "true" ]]; then
      log "bridge-e2e failed; showing shared ECS proof service logs"
      dump_shared_proof_services_ecs_logs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name"
    else
      log "bridge-e2e failed; showing proof-requestor and proof-funder logs"
      tail -n 200 "$proof_requestor_log" >&2 || true
      tail -n 200 "$proof_funder_log" >&2 || true
    fi
    die "bridge-e2e failed while centralized proof services were running"
  fi

  local juno_tx_hash=""
  local juno_tx_hash_source=""
  local juno_tx_hash_expected_source="input.juno_execution_tx_hash"
  juno_tx_hash="$(jq -r '.juno.proof_of_execution.tx_hash? // ""' "$bridge_summary" 2>/dev/null || true)"
  juno_tx_hash_source="$(
    jq -r '.juno.proof_of_execution.source? // ""' "$bridge_summary" 2>/dev/null || true
  )"
  if [[ -n "$juno_tx_hash" ]]; then
    if [[ "$juno_tx_hash_source" != "$juno_tx_hash_expected_source" ]]; then
      die "bridge summary juno proof source mismatch: got=$juno_tx_hash_source want=$juno_tx_hash_expected_source ($bridge_summary)"
    fi
    if [[ -n "$juno_tx_hash_source" ]]; then
      log "juno_tx_hash=$juno_tx_hash source=$juno_tx_hash_source"
    else
      log "juno_tx_hash=$juno_tx_hash"
    fi
  else
    log "juno_tx_hash=unavailable"
    die "bridge summary missing juno proof-of-execution tx hash: $bridge_summary"
  fi

  local boundless_deposit_ivk_configured="false"
  local boundless_withdraw_ovk_configured="false"
  local boundless_deposit_witness_item_count boundless_withdraw_witness_item_count
  local guest_witness_auto_generate="false"
  local guest_witness_extract_from_chain="false"
  if [[ -n "$boundless_deposit_owallet_ivk_hex" ]]; then
    boundless_deposit_ivk_configured="true"
  fi
  if [[ -n "$boundless_withdraw_owallet_ovk_hex" ]]; then
    boundless_withdraw_ovk_configured="true"
  fi
  boundless_deposit_witness_item_count="${#boundless_deposit_witness_item_files[@]}"
  boundless_withdraw_witness_item_count="${#boundless_withdraw_witness_item_files[@]}"
  if [[ "$boundless_input_mode" == "guest-witness-v1" && "$guest_witness_manual_mode" != "true" ]]; then
    guest_witness_auto_generate="true"
  fi
  if [[ "$boundless_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    guest_witness_extract_from_chain="true"
  fi

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
    --arg bridge_deposit_final_orchard_root "$bridge_deposit_final_orchard_root" \
    --arg bridge_withdraw_final_orchard_root "$bridge_withdraw_final_orchard_root" \
    --arg bridge_deposit_checkpoint_height "$bridge_deposit_checkpoint_height" \
    --arg bridge_deposit_checkpoint_block_hash "$bridge_deposit_checkpoint_block_hash" \
    --arg bridge_withdraw_checkpoint_height "$bridge_withdraw_checkpoint_height" \
    --arg bridge_withdraw_checkpoint_block_hash "$bridge_withdraw_checkpoint_block_hash" \
    --arg bridge_proof_inputs_output "$bridge_proof_inputs_output" \
    --arg bridge_run_timeout "$bridge_run_timeout" \
    --arg boundless_auto "$boundless_auto" \
    --arg boundless_proof_submission_mode "$boundless_proof_submission_mode" \
    --arg boundless_bin "$boundless_bin" \
    --arg boundless_rpc_url "$boundless_rpc_url" \
    --arg boundless_requestor_address "$boundless_requestor_address" \
    --arg boundless_input_mode "$boundless_input_mode" \
    --arg boundless_deposit_ivk_configured "$boundless_deposit_ivk_configured" \
    --arg boundless_withdraw_ovk_configured "$boundless_withdraw_ovk_configured" \
    --arg guest_witness_auto_generate "$guest_witness_auto_generate" \
    --arg guest_witness_extract_from_chain "$guest_witness_extract_from_chain" \
    --argjson boundless_deposit_witness_item_count "$boundless_deposit_witness_item_count" \
    --argjson boundless_withdraw_witness_item_count "$boundless_withdraw_witness_item_count" \
    --arg boundless_deposit_program_url "$boundless_deposit_program_url" \
    --arg boundless_withdraw_program_url "$boundless_withdraw_program_url" \
    --arg boundless_input_s3_bucket "$boundless_input_s3_bucket" \
    --arg boundless_input_s3_prefix "$boundless_input_s3_prefix" \
    --arg boundless_input_s3_region "$boundless_input_s3_region" \
    --arg boundless_input_s3_presign_ttl "$boundless_input_s3_presign_ttl" \
    --arg boundless_min_price_wei "$boundless_min_price_wei" \
    --arg boundless_max_price_wei "$boundless_max_price_wei" \
    --arg boundless_max_price_cap_wei "$boundless_max_price_cap_wei" \
    --arg boundless_max_price_bump_multiplier "$boundless_max_price_bump_multiplier" \
    --arg boundless_max_price_bump_retries "$boundless_max_price_bump_retries" \
    --arg boundless_lock_stake_wei "$boundless_lock_stake_wei" \
    --arg boundless_bidding_delay_seconds "$boundless_bidding_delay_seconds" \
    --arg boundless_ramp_up_period_seconds "$boundless_ramp_up_period_seconds" \
    --arg boundless_lock_timeout_seconds "$boundless_lock_timeout_seconds" \
    --arg boundless_timeout_seconds "$boundless_timeout_seconds" \
    --arg bridge_recipient_address "$bridge_recipient_address" \
    --arg shared_enabled "$shared_enabled" \
    --arg shared_kafka_brokers "$shared_kafka_brokers" \
    --arg shared_ipfs_api_url "$shared_ipfs_api_url" \
    --arg shared_topic_prefix "$shared_topic_prefix" \
    --arg shared_timeout "$shared_timeout" \
    --arg shared_summary "$shared_summary" \
    --arg proof_request_topic "$proof_request_topic" \
    --arg proof_result_topic "$proof_result_topic" \
    --arg proof_failure_topic "$proof_failure_topic" \
    --arg proof_requestor_group "$proof_requestor_group" \
    --arg proof_bridge_consumer_group "$proof_bridge_consumer_group" \
    --arg proof_services_mode "$proof_services_mode" \
    --arg shared_ecs_cluster_arn "$shared_ecs_cluster_arn" \
    --arg shared_proof_requestor_service_name "$shared_proof_requestor_service_name" \
    --arg shared_proof_funder_service_name "$shared_proof_funder_service_name" \
    --arg proof_requestor_log "$proof_requestor_log" \
    --arg proof_funder_log "$proof_funder_log" \
    --arg juno_tx_hash "$juno_tx_hash" \
    --arg juno_tx_hash_source "$juno_tx_hash_source" \
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
        deposit_final_orchard_root: (if $bridge_deposit_final_orchard_root == "" then null else $bridge_deposit_final_orchard_root end),
        withdraw_final_orchard_root: (if $bridge_withdraw_final_orchard_root == "" then null else $bridge_withdraw_final_orchard_root end),
        deposit_checkpoint_height: (if $bridge_deposit_checkpoint_height == "" then null else ($bridge_deposit_checkpoint_height | tonumber) end),
        deposit_checkpoint_block_hash: (if $bridge_deposit_checkpoint_block_hash == "" then null else $bridge_deposit_checkpoint_block_hash end),
        withdraw_checkpoint_height: (if $bridge_withdraw_checkpoint_height == "" then null else ($bridge_withdraw_checkpoint_height | tonumber) end),
        withdraw_checkpoint_block_hash: (if $bridge_withdraw_checkpoint_block_hash == "" then null else $bridge_withdraw_checkpoint_block_hash end),
        recipient_address: $bridge_recipient_address,
        run_timeout: $bridge_run_timeout,
        proof_inputs_output: $bridge_proof_inputs_output,
        boundless: {
          auto: ($boundless_auto == "true"),
          submission_mode: (if $boundless_proof_submission_mode == "" then null else $boundless_proof_submission_mode end),
          bin: $boundless_bin,
          rpc_url: $boundless_rpc_url,
          requestor_address: (if $boundless_requestor_address == "" then null else $boundless_requestor_address end),
          input_mode: $boundless_input_mode,
          guest_witness: {
            enabled: ($boundless_input_mode == "guest-witness-v1"),
            auto_generate: ($guest_witness_auto_generate == "true"),
            extract_from_chain: ($guest_witness_extract_from_chain == "true"),
            deposit_owallet_ivk_configured: ($boundless_deposit_ivk_configured == "true"),
            withdraw_owallet_ovk_configured: ($boundless_withdraw_ovk_configured == "true"),
            deposit_witness_item_count: $boundless_deposit_witness_item_count,
            withdraw_witness_item_count: $boundless_withdraw_witness_item_count
          },
          deposit_program_url: (if $boundless_deposit_program_url == "" then null else $boundless_deposit_program_url end),
          withdraw_program_url: (if $boundless_withdraw_program_url == "" then null else $boundless_withdraw_program_url end),
          input_s3_bucket: (if $boundless_input_s3_bucket == "" then null else $boundless_input_s3_bucket end),
          input_s3_prefix: (if $boundless_input_s3_prefix == "" then null else $boundless_input_s3_prefix end),
          input_s3_region: (if $boundless_input_s3_region == "" then null else $boundless_input_s3_region end),
          input_s3_presign_ttl: (if $boundless_input_s3_presign_ttl == "" then null else $boundless_input_s3_presign_ttl end),
          min_price_wei: $boundless_min_price_wei,
          max_price_wei: $boundless_max_price_wei,
          max_price_cap_wei: $boundless_max_price_cap_wei,
          max_price_bump_multiplier: $boundless_max_price_bump_multiplier,
          max_price_bump_retries: $boundless_max_price_bump_retries,
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
        ipfs_api_url: (if $shared_ipfs_api_url == "" then null else $shared_ipfs_api_url end),
        topic_prefix: (if $shared_topic_prefix == "" then null else $shared_topic_prefix end),
        timeout: (if $shared_timeout == "" then null else $shared_timeout end),
        proof_topics: {
          request: (if $proof_request_topic == "" then null else $proof_request_topic end),
          result: (if $proof_result_topic == "" then null else $proof_result_topic end),
          failure: (if $proof_failure_topic == "" then null else $proof_failure_topic end)
        },
        proof_services: {
          mode: (if $proof_services_mode == "" then null else $proof_services_mode end),
          requestor_group: (if $proof_requestor_group == "" then null else $proof_requestor_group end),
          bridge_consumer_group: (if $proof_bridge_consumer_group == "" then null else $proof_bridge_consumer_group end),
          ecs_cluster_arn: (if $shared_ecs_cluster_arn == "" then null else $shared_ecs_cluster_arn end),
          requestor_service_name: (if $shared_proof_requestor_service_name == "" then null else $shared_proof_requestor_service_name end),
          funder_service_name: (if $shared_proof_funder_service_name == "" then null else $shared_proof_funder_service_name end),
          requestor_log: (if $proof_requestor_log == "" then null else $proof_requestor_log end),
          funder_log: (if $proof_funder_log == "" then null else $proof_funder_log end)
        },
        summary_path: (if $shared_summary == "" then null else $shared_summary end),
        report: $shared
      },
      juno: {
        funder_env_present: ($juno_funder_present == "true"),
        tx_hash_source: (if $juno_tx_hash_source == "" then null else $juno_tx_hash_source end),
        tx_hash: (if $juno_tx_hash == "" then null else $juno_tx_hash end)
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
