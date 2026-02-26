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
  --existing-bridge-summary-path <path>
                                   optional existing bridge summary JSON (skip deploy bootstrap and reuse deployed contracts)
  --base-operator-fund-wei <wei>   optional pre-fund per operator (default: 1000000000000000)
  --bridge-verifier-address <addr> required verifier router address for proof verification
  --bridge-deposit-image-id <hex>  required deposit image ID (bytes32 hex)
  --bridge-withdraw-image-id <hex> required withdraw image ID (bytes32 hex)
  --bridge-deposit-final-orchard-root <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-final-orchard-root <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-deposit-checkpoint-height <n> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-deposit-checkpoint-block-hash <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-checkpoint-height <n> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-checkpoint-block-hash <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-proof-inputs-output <path> optional proof inputs bundle output path
  --bridge-run-timeout <duration>  bridge-e2e runtime timeout (default: 90m)
  --bridge-operator-signer-bin <path> external operator signer binary for bridge-e2e
                                   (default: prefer juno-txsign; sign-digest support is required)
  --sp1-bin <path>           reserved for optional direct-cli proof chaos scenario
                                   (disabled by default; default: sp1-prover-adapter)
  --sp1-rpc-url <url>        sp1 prover network RPC URL (default: https://rpc.mainnet.succinct.xyz)
  --sp1-market-address <addr> sp1 market contract address
                                   (default: 0xFd152dADc5183870710FE54f939Eae3aB9F0fE82)
  --sp1-verifier-router-address <addr> sp1 verifier router address
                                   (default: 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B)
  --sp1-set-verifier-address <addr> sp1 set verifier address
                                   (default: 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B)
  --sp1-input-mode <mode>     sp1 input mode (guest-witness-v1 only, default: guest-witness-v1)
  --sp1-deposit-owallet-ivk-hex <hex>  64-byte oWallet IVK hex (required for guest-witness-v1)
  --sp1-withdraw-owallet-ovk-hex <hex> 32-byte oWallet OVK hex (required for guest-witness-v1)
  --sp1-witness-juno-scan-url <url> juno-scan URL for witness extraction (required, guest-witness-v1)
  --sp1-witness-juno-rpc-url <url> junocashd RPC URL for witness extraction (required, guest-witness-v1)
  --sp1-witness-juno-scan-urls <csv> optional comma-separated juno-scan URL pool for witness extraction failover
  --sp1-witness-juno-rpc-urls <csv> optional comma-separated junocashd RPC URL pool for witness extraction failover
  --sp1-witness-operator-labels <csv> optional comma-separated labels aligned with witness endpoint pools
  --sp1-witness-quorum-threshold <n> witness endpoint quorum threshold (default: 3)
  --sp1-witness-juno-scan-bearer-token-env <name> env var for optional juno-scan bearer token
                                   (default: JUNO_SCAN_BEARER_TOKEN)
  --sp1-witness-juno-rpc-user-env <name> env var for junocashd RPC username (default: JUNO_RPC_USER)
  --sp1-witness-juno-rpc-pass-env <name> env var for junocashd RPC password (default: JUNO_RPC_PASS)
  --sp1-witness-recipient-ua <address> distributed DKG recipient unified/shielded address used for witness tx generation
  --sp1-witness-recipient-ufvk <ufvk> distributed DKG UFVK used for witness wallet registration/extraction
  --sp1-witness-wallet-id <id> optional juno-scan wallet id override used for run-generated witness txs
  --sp1-witness-metadata-timeout-seconds <n> timeout for run-generated witness tx metadata (default: 900)
  --withdraw-coordinator-tss-url <url> optional tss-host URL override for withdraw coordinator
                                   (defaults to derived https://<witness-rpc-host>:9443)
  --withdraw-coordinator-tss-server-ca-file <path> required tss-host server CA PEM for withdraw coordinator TLS
  --withdraw-blob-bucket <name>   S3 bucket for withdraw coordinator/finalizer durable blob artifacts
                                   (default: --sp1-input-s3-bucket)
  --withdraw-blob-prefix <prefix> S3 prefix for withdraw coordinator/finalizer durable blob artifacts
                                   (default: withdraw-live)
  --sp1-requestor-key-file <path> requestor key file for sp1 (required)
  --sp1-deposit-program-url <url> deposit guest program URL for sp1 (required)
  --sp1-withdraw-program-url <url> withdraw guest program URL for sp1 (required)
  --sp1-input-s3-bucket <name> S3 bucket used for oversized sp1 inputs
                                   (required for guest-witness-v1 / >2048-byte inputs)
  --sp1-input-s3-prefix <prefix> S3 key prefix for oversized sp1 inputs
                                   (default: bridge-e2e/sp1-input)
  --sp1-input-s3-region <region> optional AWS region override for oversized input uploads
  --sp1-input-s3-presign-ttl <duration> presigned URL TTL for oversized input uploads
                                   (default: 2h)
  --sp1-max-price-per-pgu <wei> SP1 max price per PGU (default: 1000000000000)
  --sp1-deposit-pgu-estimate <n> projected deposit proof PGU usage for credit guardrails
                                   (default: 1000000)
  --sp1-withdraw-pgu-estimate <n> projected withdraw proof PGU usage for credit guardrails
                                   (default: 1000000)
  --sp1-groth16-base-fee-wei <wei> projected groth16 base fee per proof in wei
                                   (default: 200000000000000000)
  --sp1-min-auction-period <s> SP1 minimum auction period in seconds (default: 85)
  --sp1-auction-timeout <duration> SP1 auction timeout (default: 625s)
  --sp1-request-timeout <duration> SP1 request timeout (default: 1500s)
  --shared-postgres-dsn <dsn>       shared Postgres DSN (required; proof-requestor/proof-funder store + lease backend)
  --shared-kafka-brokers <list>     shared Kafka brokers CSV (required; centralized proof request/fulfillment topics)
  --shared-ipfs-api-url <url>       shared IPFS API URL (required; operator checkpoint package pin/fetch verification)
  --shared-ecs-cluster-arn <arn>    shared ECS cluster ARN for centralized proof services (optional; enables ECS-managed proof services)
  --shared-proof-requestor-service-name <name> ECS service name for shared proof-requestor
  --shared-proof-funder-service-name <name> ECS service name for shared proof-funder
  --shared-topic-prefix <prefix>    shared infra Kafka topic prefix (default: shared.infra.e2e)
  --shared-timeout <duration>       shared infra validation timeout (default: 300s)
  --shared-output <path>            shared infra report output (default: <workdir>/reports/shared-infra-summary.json)
  --relayer-runtime-mode <mode>     relayer runtime mode (runner|distributed, default: distributed)
  --relayer-runtime-operator-hosts <csv> comma-separated operator host list for distributed relayer runtime
  --relayer-runtime-operator-ssh-user <user> SSH user for distributed relayer runtime operator hosts
  --relayer-runtime-operator-ssh-key-file <path> SSH key file for distributed relayer runtime operator hosts
  --aws-dr-region <region>          optional AWS DR region passthrough (recorded in summary metadata only)
  --refund-after-expiry-window-seconds <n> refund window seconds used only for refund-after-expiry chaos scenario
                                   (default: 120)
  --output <path>                  summary json output (default: <workdir>/reports/testnet-e2e-summary.json)
  --force                          remove existing workdir before starting
  --stop-after-stage <stage>      optional stage checkpoint to stop after successful completion
                                   (witness_ready|shared_services_ready|checkpoint_validated|full; default: full)

Environment:
  JUNO_FUNDER_PRIVATE_KEY_HEX      optional juno funder private key hex used for transparent witness funding.
  JUNO_FUNDER_SEED_PHRASE          optional juno funder seed phrase used for orchard/unified witness funding.
  JUNO_FUNDER_SOURCE_ADDRESS       optional explicit funded source address already present in witness RPC wallets.
  JUNO_E2E_ENABLE_DIRECT_CLI_USER_PROOF
                                   optional explicit opt-in (set to 1) for runner-side direct-cli user proof chaos scenario.
                                   Default is disabled to keep runner orchestration-only for SP1 proofs.

This script orchestrates:
  1) DKG ceremony -> backup packages -> restore from backup-only
  2) Juno witness tx generation on the configured Juno RPC + juno-scan endpoints
  3) Operator-service checkpoint publication (checkpoint-signer + checkpoint-aggregator on operator hosts)
  4) Shared infra validation (Postgres + Kafka + run-bound checkpoint package pin/fetch via IPFS)
  5) Centralized proof-requestor/proof-funder startup on shared topics
  6) Base testnet contract bootstrap + relayer-driven bridge flow
     via cmd/base-relayer + cmd/deposit-relayer + cmd/withdraw-coordinator + cmd/withdraw-finalizer
EOF
}

trimmed_file_value() {
  local path="$1"
  tr -d '\r\n' <"$path"
}

redact_dkg_summary_json() {
  local dkg_summary_path="$1"
  jq '
    del(.workdir, .coordinator_workdir, .completion_report)
    | if (.operators? | type) == "array" then
        .operators |= map(del(.operator_key_file, .backup_package, .runtime_dir, .registration_file))
      else
        .
      end
  ' "$dkg_summary_path"
}

json_array_from_args() {
  jq -n '$ARGS.positional' --args -- "$@"
}

shell_join() {
  local joined=""
  local arg
  for arg in "$@"; do
    if [[ -n "$joined" ]]; then
      joined+=" "
    fi
    joined+="$(printf '%q' "$arg")"
  done
  printf '%s' "$joined"
}

run_with_optional_timeout() {
  local timeout_seconds="$1"
  shift || true
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "timeout seconds must be numeric"
  (( timeout_seconds > 0 )) || die "timeout seconds must be > 0"

  if have_cmd timeout; then
    timeout --signal=TERM --kill-after=20s "$timeout_seconds" "$@"
    return $?
  fi
  if have_cmd gtimeout; then
    gtimeout --signal=TERM --kill-after=20s "$timeout_seconds" "$@"
    return $?
  fi

  "$@"
}

bridge_api_post_json_with_retry() {
  local url="$1"
  local payload="$2"
  local output_path="$3"
  local operation_label="$4"
  local max_attempts="${5:-8}"
  local retry_sleep_seconds="${6:-3}"
  local attempt curl_status http_status response_file response_preview

  [[ "$max_attempts" =~ ^[0-9]+$ ]] || die "bridge-api retry max attempts must be numeric"
  (( max_attempts > 0 )) || die "bridge-api retry max attempts must be > 0"
  [[ "$retry_sleep_seconds" =~ ^[0-9]+$ ]] || die "bridge-api retry sleep seconds must be numeric"
  (( retry_sleep_seconds >= 0 )) || die "bridge-api retry sleep seconds must be >= 0"

  response_file="$(mktemp)"
  for attempt in $(seq 1 "$max_attempts"); do
    : >"$response_file"
    set +e
    http_status="$(
      curl -sS \
        -o "$response_file" \
        -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/json" \
        --data "$payload" \
        "$url"
    )"
    curl_status=$?
    set -e

    if (( curl_status == 0 )) && [[ "$http_status" =~ ^2[0-9][0-9]$ ]]; then
      cp "$response_file" "$output_path"
      rm -f "$response_file"
      return 0
    fi

    response_preview="$(tr '\r\n' ' ' <"$response_file" | tr -s ' ' | cut -c1-400)"
    if (( attempt < max_attempts )) && { (( curl_status != 0 )) || [[ "$http_status" =~ ^5[0-9][0-9]$ ]] || [[ "$http_status" == "429" ]]; }; then
      log "bridge-api write retrying label=$operation_label attempt=${attempt}/${max_attempts} curl_status=$curl_status http_status=${http_status:-000} response_preview=${response_preview:-<empty>}"
      sleep "$retry_sleep_seconds"
      continue
    fi

    if [[ -s "$response_file" ]]; then
      cat "$response_file" >&2
    fi
    log "bridge-api write failed label=$operation_label attempt=${attempt}/${max_attempts} curl_status=$curl_status http_status=${http_status:-000}"
    rm -f "$response_file"
    return 1
  done

  rm -f "$response_file"
  return 1
}

RUN_WORKDIR_LOCK_DIR=""
RUN_WORKDIR_LOCK_PID_FILE=""

release_workdir_run_lock() {
  [[ -n "$RUN_WORKDIR_LOCK_DIR" ]] || return 0

  local lock_owner_pid=""
  if [[ -n "$RUN_WORKDIR_LOCK_PID_FILE" && -f "$RUN_WORKDIR_LOCK_PID_FILE" ]]; then
    lock_owner_pid="$(trimmed_file_value "$RUN_WORKDIR_LOCK_PID_FILE")"
  fi

  if [[ -z "$lock_owner_pid" || "$lock_owner_pid" == "$$" ]]; then
    rm -rf "$RUN_WORKDIR_LOCK_DIR" >/dev/null 2>&1 || true
  fi

  RUN_WORKDIR_LOCK_DIR=""
  RUN_WORKDIR_LOCK_PID_FILE=""
}

acquire_workdir_run_lock() {
  local workdir="$1"
  local lock_dir="$workdir/.run.lock"
  local lock_pid_file="$lock_dir/pid"
  local lock_started_at_file="$lock_dir/started_at"
  local lock_owner_pid=""

  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" >"$lock_pid_file"
    timestamp_utc >"$lock_started_at_file"
    RUN_WORKDIR_LOCK_DIR="$lock_dir"
    RUN_WORKDIR_LOCK_PID_FILE="$lock_pid_file"
    trap release_workdir_run_lock EXIT
    return 0
  fi

  if [[ -f "$lock_pid_file" ]]; then
    lock_owner_pid="$(trimmed_file_value "$lock_pid_file")"
  fi

  if [[ "$lock_owner_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_owner_pid" >/dev/null 2>&1; then
    die "another run-testnet-e2e.sh process is already active for workdir=$workdir pid=$lock_owner_pid"
  fi

  log "detected stale workdir run lock; removing stale lock dir=$lock_dir stale_pid=${lock_owner_pid:-unknown}"
  rm -rf "$lock_dir"
  mkdir "$lock_dir" || die "failed to acquire workdir run lock: $lock_dir"
  printf '%s\n' "$$" >"$lock_pid_file"
  timestamp_utc >"$lock_started_at_file"
  RUN_WORKDIR_LOCK_DIR="$lock_dir"
  RUN_WORKDIR_LOCK_PID_FILE="$lock_pid_file"
  trap release_workdir_run_lock EXIT
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
  local environment_json="${6:-[]}"

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
      --argjson environment "$environment_json" \
      '
        .taskDefinition
        | .containerDefinitions = (
            .containerDefinitions
            | map(
                if .name == $container_name then
                  .command = $command
                  | .environment = $environment
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

shared_ecs_services_recent_events() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"

  aws ecs describe-services \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --services "$proof_requestor_service_name" "$proof_funder_service_name" \
    | jq -r '
      .services[]
      | .serviceName as $name
      | (.events // [])[:8][]
      | "[\($name)] \(.createdAt) \(.message)"
    ' 2>/dev/null || true
}

ecs_events_indicate_transient_bootstrap_failure() {
  local events_text="$1"
  local lowered
  lowered="$(lower "$events_text")"

  [[ "$events_text" == *"ResourceInitializationError"* ]] ||
    [[ "$lowered" == *"resourceinitializationerror"* ]] ||
    [[ "$lowered" == *"cannotpullcontainererror"* ]] ||
    [[ "$lowered" == *"unable to retrieve ecr registry auth"* ]] ||
    [[ "$lowered" == *"dial tcp"* && "$lowered" == *"i/o timeout"* ]] ||
    [[ "$lowered" == *"context deadline exceeded"* && "$lowered" == *"ecr"* ]]
}

wait_for_shared_proof_services_ecs_stable() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"
  local max_attempts="${5:-6}"
  local retry_sleep_seconds="${6:-20}"

  local attempt wait_status events_text
  for attempt in $(seq 1 "$max_attempts"); do
    set +e
    aws ecs wait services-stable \
      --region "$aws_region" \
      --cluster "$cluster_arn" \
      --services "$proof_requestor_service_name" "$proof_funder_service_name"
    wait_status=$?
    set -e
    if (( wait_status == 0 )); then
      return 0
    fi

    events_text="$(
      shared_ecs_services_recent_events \
        "$aws_region" \
        "$cluster_arn" \
        "$proof_requestor_service_name" \
        "$proof_funder_service_name"
    )"
    if [[ -n "$events_text" ]]; then
      log "shared ecs services not stable (attempt ${attempt}/${max_attempts}); recent events:"
      while IFS= read -r event_line; do
        [[ -n "$event_line" ]] || continue
        log "  $event_line"
      done <<<"$events_text"
    else
      log "shared ecs services not stable (attempt ${attempt}/${max_attempts}); recent events unavailable"
    fi

    if (( attempt >= max_attempts )); then
      return 1
    fi

    if ecs_events_indicate_transient_bootstrap_failure "$events_text"; then
      log "rolling out shared proof services retry deployment after transient startup failure"
    else
      log "rolling out shared proof services retry deployment after unstable service wait"
    fi

    aws ecs update-service \
      --region "$aws_region" \
      --cluster "$cluster_arn" \
      --service "$proof_requestor_service_name" \
      --force-new-deployment >/dev/null
    aws ecs update-service \
      --region "$aws_region" \
      --cluster "$cluster_arn" \
      --service "$proof_funder_service_name" \
      --force-new-deployment >/dev/null
    sleep "$retry_sleep_seconds"
  done

  return 1
}

rollout_shared_proof_services_ecs() {
  local aws_region="$1"
  local cluster_arn="$2"
  local proof_requestor_service_name="$3"
  local proof_funder_service_name="$4"
  local proof_requestor_command_json="$5"
  local proof_funder_command_json="$6"
  local proof_requestor_environment_json="${7:-[]}"
  local proof_funder_environment_json="${8:-[]}"

  local requestor_task_definition_arn funder_task_definition_arn
  requestor_task_definition_arn="$(
    ecs_register_service_task_definition \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_requestor_service_name" \
      "proof-requestor" \
      "$proof_requestor_command_json" \
      "$proof_requestor_environment_json"
  )"
  [[ -n "$requestor_task_definition_arn" ]] || die "failed to register proof-requestor task definition revision"

  funder_task_definition_arn="$(
    ecs_register_service_task_definition \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_funder_service_name" \
      "proof-funder" \
      "$proof_funder_command_json" \
      "$proof_funder_environment_json"
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

  if ! wait_for_shared_proof_services_ecs_stable \
    "$aws_region" \
    "$cluster_arn" \
    "$proof_requestor_service_name" \
    "$proof_funder_service_name"; then
    dump_shared_proof_services_ecs_logs \
      "$aws_region" \
      "$cluster_arn" \
      "$proof_requestor_service_name" \
      "$proof_funder_service_name"
    die "shared ecs services failed to stabilize after retries"
  fi
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

juno_tx_already_known_error() {
  local msg lowered
  msg="${1:-}"
  lowered="$(lower "$msg")"
  [[ "$lowered" == *"already in block chain"* ]] ||
    [[ "$lowered" == *"already known"* ]] ||
    [[ "$lowered" == *"txn-already-known"* ]] ||
    [[ "$lowered" == *"transaction already exists"* ]]
}

juno_rpc_json_call() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local method="$4"
  local params_json="$5"
  local payload

  payload="$(
    jq -cn \
      --arg method "$method" \
      --argjson params "$params_json" \
      '{jsonrpc: "1.0", id: "testnet-e2e", method: $method, params: $params}'
  )"
  curl -fsS \
    --user "$rpc_user:$rpc_pass" \
    --header "content-type: application/json" \
    --data-binary "$payload" \
    "$rpc_url"
}

juno_rpc_result() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local method="$4"
  local params_json="$5"
  local response rpc_error

  response="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "$method" "$params_json")"
  rpc_error="$(jq -r '.error.message // empty' <<<"$response" 2>/dev/null || true)"
  if [[ -n "$rpc_error" ]]; then
    die "juno rpc call failed method=$method error=$rpc_error"
  fi
  jq -c '.result' <<<"$response"
}

juno_wait_operation_txid() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local opid="$4"
  local timeout_seconds="$5"
  local started_at now params_json op_status op_json status txid err_msg

  started_at="$(date +%s)"
  params_json="$(jq -cn --arg opid "$opid" '[ [ $opid ] ]')"
  while true; do
    now="$(date +%s)"
    if (( now - started_at >= timeout_seconds )); then
      die "timed out waiting for Juno operation opid=$opid"
    fi
    op_status="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "z_getoperationstatus" "$params_json" || true)"
    if [[ -z "$op_status" || "$op_status" == "null" ]]; then
      sleep 2
      continue
    fi
    op_json="$(jq -c '.[0] // empty' <<<"$op_status" 2>/dev/null || true)"
    if [[ -z "$op_json" || "$op_json" == "null" ]]; then
      sleep 2
      continue
    fi
    status="$(jq -r '.status // empty' <<<"$op_json")"
    case "$status" in
      success)
        txid="$(jq -r '.result.txid // empty' <<<"$op_json")"
        [[ -n "$txid" ]] || die "Juno operation succeeded without txid opid=$opid"
        printf '%s' "$(lower "${txid#0x}")"
        return 0
        ;;
      failed)
        err_msg="$(jq -r '.error.message // "unknown error"' <<<"$op_json")"
        die "Juno operation failed opid=$opid error=$err_msg"
        ;;
      *)
        sleep 2
        ;;
    esac
  done
}

juno_wait_tx_confirmed() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid_raw="$4"
  local timeout_seconds="$5"
  local txid started_at now params_json view_params_json resp confirmations tx_status

  txid="$(lower "$(trim "$txid_raw")")"
  txid="${txid#0x}"
  [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || die "invalid txid for confirmation wait: $txid_raw"
  started_at="$(date +%s)"
  params_json="$(jq -cn --arg txid "$txid" '[ $txid, 1 ]')"
  view_params_json="$(jq -cn --arg txid "$txid" '[ $txid ]')"

  while true; do
    now="$(date +%s)"
    if (( now - started_at >= timeout_seconds )); then
      die "timed out waiting for Juno tx confirmation txid=$txid"
    fi

    resp="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "z_viewtransaction" "$view_params_json" || true)"
    tx_status="$(jq -r '.status // empty' <<<"${resp:-null}" 2>/dev/null || true)"
    if [[ "$tx_status" == "mined" ]]; then
      return 0
    fi
    confirmations="$(jq -r '.confirmations // 0' <<<"${resp:-null}" 2>/dev/null || echo 0)"
    if [[ "$confirmations" =~ ^[0-9]+$ ]] && (( confirmations >= 1 )); then
      return 0
    fi

    resp="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "getrawtransaction" "$params_json" || true)"
    confirmations="$(jq -r '.confirmations // 0' <<<"${resp:-null}" 2>/dev/null || echo 0)"
    if [[ "$confirmations" =~ ^[0-9]+$ ]] && (( confirmations >= 1 )); then
      return 0
    fi
    sleep 2
  done
}

submit_juno_shielded_memo_tx() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local from_address="$4"
  local recipient_ua="$5"
  local amount_zat="$6"
  local memo_hex="$7"
  local timeout_seconds="$8"
  local amount_decimal opid txid

  [[ "$amount_zat" =~ ^[0-9]+$ ]] || die "invalid Juno amount_zat: $amount_zat"
  (( amount_zat > 0 )) || die "Juno amount_zat must be > 0"
  amount_decimal="$(python3 - "$amount_zat" <<'PY'
import sys
zat = int(sys.argv[1])
whole = zat // 100000000
frac = zat % 100000000
print(f"{whole}.{frac:08d}")
PY
)"
  opid="$(
    juno_rpc_result \
      "$rpc_url" \
      "$rpc_user" \
      "$rpc_pass" \
      "z_sendmany" \
      "$(jq -cn --arg from "$from_address" --arg to "$recipient_ua" --arg amt "$amount_decimal" --arg memo_hex "$memo_hex" '[ $from, [ { address: $to, amount: ($amt | tonumber), memo: $memo_hex } ], 1 ]')" \
      | jq -r '.'
  )"
  [[ -n "$opid" && "$opid" != "null" ]] || die "failed to submit Juno shielded memo tx"
  txid="$(juno_wait_operation_txid "$rpc_url" "$rpc_user" "$rpc_pass" "$opid" "$timeout_seconds")"
  juno_wait_tx_confirmed "$rpc_url" "$rpc_user" "$rpc_pass" "$txid" "$timeout_seconds"
  printf '%s' "$txid"
}

juno_rebroadcast_tx() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid_raw="$4"
  local txid getraw_params getraw_resp getraw_error getraw_result
  local send_params send_resp send_error send_result

  txid="$(trim "$txid_raw")"
  txid="${txid#0x}"
  [[ -n "$txid" ]] || die "cannot rebroadcast Juno tx: empty txid"

  getraw_params="$(jq -cn --arg txid "$txid" '[ $txid ]')"
  getraw_resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "getrawtransaction" "$getraw_params")"
  getraw_error="$(jq -r '.error.message // empty' <<<"$getraw_resp")"
  if [[ -n "$getraw_error" ]]; then
    die "failed to fetch raw Juno transaction for txid=$txid: $getraw_error"
  fi
  getraw_result="$(jq -r '.result // empty' <<<"$getraw_resp")"
  [[ "$getraw_result" =~ ^[0-9a-fA-F]+$ ]] || die "invalid raw Juno transaction hex returned for txid=$txid"

  send_params="$(jq -cn --arg raw "$getraw_result" '[ $raw ]')"
  send_resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "sendrawtransaction" "$send_params")"
  send_error="$(jq -r '.error.message // empty' <<<"$send_resp")"
  if [[ -n "$send_error" ]]; then
    if juno_tx_already_known_error "$send_error"; then
      log "juno tx rebroadcast accepted as already known txid=$txid"
      return 0
    fi
    die "failed to rebroadcast Juno tx txid=$txid: $send_error"
  fi
  send_result="$(jq -r '.result // empty' <<<"$send_resp")"
  [[ -n "$send_result" ]] || die "failed to rebroadcast Juno tx txid=$txid: empty sendrawtransaction result"
  log "juno tx rebroadcast accepted txid=$send_result"
}

witness_scan_healthcheck() {
  local scan_url="$1"
  local scan_bearer_token="${2:-}"
  local -a headers=()
  if [[ -n "$scan_bearer_token" ]]; then
    headers+=(--header "Authorization: Bearer $scan_bearer_token")
  fi
  curl -fsS --max-time 5 "${headers[@]}" "${scan_url%/}/v1/health" >/dev/null
}

witness_rpc_healthcheck() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local params_json response rpc_error rpc_result

  params_json='[]'
  response="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "getblockcount" "$params_json" 2>/dev/null || true)"
  [[ -n "$response" ]] || return 1

  rpc_error="$(jq -r '.error.message // empty' <<<"$response" 2>/dev/null || true)"
  [[ -z "$rpc_error" ]] || return 1
  rpc_result="$(jq -r '.result // empty' <<<"$response" 2>/dev/null || true)"
  [[ "$rpc_result" =~ ^[0-9]+$ ]]
}

witness_pair_healthcheck() {
  local scan_url="$1"
  local rpc_url="$2"
  local rpc_user="$3"
  local rpc_pass="$4"
  local scan_bearer_token="${5:-}"

  witness_scan_healthcheck "$scan_url" "$scan_bearer_token" || return 1
  witness_rpc_healthcheck "$rpc_url" "$rpc_user" "$rpc_pass" || return 1
}

witness_scan_upsert_wallet() {
  local scan_url="$1"
  local scan_bearer_token="$2"
  local wallet_id="$3"
  local ufvk="$4"
  local payload

  payload="$(jq -cn --arg wallet_id "$wallet_id" --arg ufvk "$ufvk" '{wallet_id: $wallet_id, ufvk: $ufvk}')"
  if [[ -n "$scan_bearer_token" ]]; then
    curl -fsS \
      --max-time 10 \
      --header "Content-Type: application/json" \
      --header "Authorization: Bearer $scan_bearer_token" \
      --data "$payload" \
      "${scan_url%/}/v1/wallets" >/dev/null
  else
    curl -fsS \
      --max-time 10 \
      --header "Content-Type: application/json" \
      --data "$payload" \
      "${scan_url%/}/v1/wallets" >/dev/null
  fi
}

witness_scan_find_wallet_for_txid() {
  local scan_url="$1"
  local scan_bearer_token="$2"
  local txid_raw="$3"
  local preferred_wallet_id="${4:-}"
  local txid wallets_response wallet_id encoded_wallet_id notes_response match_count
  local -a headers=()
  local -a wallet_candidates=()
  local wallet_candidate

  txid="$(lower "$(trim "$txid_raw")")"
  txid="${txid#0x}"
  [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || return 1

  if [[ -n "$scan_bearer_token" ]]; then
    headers+=(--header "Authorization: Bearer $scan_bearer_token")
  fi

  wallets_response="$(
    curl -fsS \
      --max-time 10 \
      "${headers[@]}" \
      "${scan_url%/}/v1/wallets" 2>/dev/null || true
  )"
  [[ -n "$wallets_response" ]] || return 1

  if [[ -n "$preferred_wallet_id" ]]; then
    wallet_candidates+=("$preferred_wallet_id")
  fi
  while IFS= read -r wallet_candidate; do
    [[ -n "$wallet_candidate" ]] || continue
    wallet_candidates+=("$wallet_candidate")
  done < <(jq -r '.wallets[]?.wallet_id // empty' <<<"$wallets_response" 2>/dev/null || true)

  (( ${#wallet_candidates[@]} > 0 )) || return 1

  local -A seen_wallet_ids=()
  for wallet_id in "${wallet_candidates[@]}"; do
    [[ -n "$wallet_id" ]] || continue
    if [[ -n "${seen_wallet_ids[$wallet_id]+x}" ]]; then
      continue
    fi
    seen_wallet_ids["$wallet_id"]=1

    encoded_wallet_id="$(jq -rn --arg value "$wallet_id" '$value|@uri' 2>/dev/null || true)"
    [[ -n "$encoded_wallet_id" ]] || continue
    notes_response="$(
      curl -fsS \
        --max-time 20 \
        "${headers[@]}" \
        "${scan_url%/}/v1/wallets/${encoded_wallet_id}/notes?limit=2000" 2>/dev/null || true
    )"
    [[ -n "$notes_response" ]] || continue

    match_count="$(jq -r --arg tx "$txid" '[.notes[]? | select((.txid // "" | ascii_downcase) == ($tx | ascii_downcase))] | length' <<<"$notes_response" 2>/dev/null || echo 0)"
    [[ "$match_count" =~ ^[0-9]+$ ]] || match_count=0
    if (( match_count > 0 )); then
      printf '%s' "$wallet_id"
      return 0
    fi
  done

  return 1
}

witness_rpc_tx_height() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid_raw="$4"
  local txid params_json resp rpc_error height

  txid="$(lower "$(trim "$txid_raw")")"
  txid="${txid#0x}"
  [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || return 1

  params_json="$(jq -cn --arg txid "$txid" '[ $txid, 1 ]')"
  resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "getrawtransaction" "$params_json" 2>/dev/null || true)"
  [[ -n "$resp" ]] || return 1

  rpc_error="$(jq -r '.error.message // empty' <<<"$resp" 2>/dev/null || true)"
  [[ -z "$rpc_error" ]] || return 1

  height="$(jq -r '.result.height // empty' <<<"$resp" 2>/dev/null || true)"
  [[ "$height" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$height"
}

witness_scan_backfill_wallet() {
  local scan_url="$1"
  local scan_bearer_token="$2"
  local wallet_id="$3"
  local from_height_raw="$4"
  local from_height encoded_wallet_id payload
  local -a headers=()

  from_height="$(trim "$from_height_raw")"
  [[ -n "$wallet_id" ]] || return 1
  [[ "$from_height" =~ ^[0-9]+$ ]] || return 1

  encoded_wallet_id="$(jq -rn --arg value "$wallet_id" '$value|@uri' 2>/dev/null || true)"
  [[ -n "$encoded_wallet_id" ]] || return 1
  if [[ -n "$scan_bearer_token" ]]; then
    headers+=(--header "Authorization: Bearer $scan_bearer_token")
  fi
  payload="$(jq -cn --argjson from_height "$from_height" '{from_height: $from_height, batch_size: 5000}')"

  curl -fsS \
    --max-time 30 \
    --header "Content-Type: application/json" \
    "${headers[@]}" \
    --data "$payload" \
    "${scan_url%/}/v1/wallets/${encoded_wallet_id}/backfill" >/dev/null
}

witness_rpc_action_index_candidates() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid_raw="$4"
  local txid payload resp rpc_error action_count idx

  txid="$(lower "$(trim "$txid_raw")")"
  txid="${txid#0x}"
  [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || return 1

  payload="$(jq -cn --arg txid "$txid" '{jsonrpc:"1.0",id:"witness-action-index",method:"getrawtransaction",params:[$txid,1]}')"
  resp="$(
    curl -fsS \
      --user "$rpc_user:$rpc_pass" \
      --header "content-type: application/json" \
      --data-binary "$payload" \
      "$rpc_url" || true
  )"
  [[ -n "$resp" ]] || return 1

  rpc_error="$(jq -r '.error.message // empty' <<<"$resp" 2>/dev/null || true)"
  [[ -z "$rpc_error" ]] || return 1

  action_count="$(jq -r '.result.orchard.actions | if type == "array" then length else 0 end' <<<"$resp" 2>/dev/null || true)"
  [[ "$action_count" =~ ^[0-9]+$ ]] || return 1
  (( action_count > 0 )) || return 1

  for ((idx = 0; idx < action_count; idx++)); do
    printf '%s\n' "$idx"
  done
}

wait_for_log_pattern() {
  local log_path="$1"
  local pattern="$2"
  local timeout_seconds="$3"
  local elapsed=0

  while (( elapsed < timeout_seconds )); do
    if [[ -f "$log_path" ]] && grep -Fq "$pattern" "$log_path"; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

supports_sign_digest_subcommand() {
  local signer_bin="$1"
  local probe_digest output status lowered

  [[ -n "$signer_bin" ]] || return 1
  probe_digest="0x$(printf '00%.0s' {1..32})"
  set +e
  output="$("$signer_bin" sign-digest --digest "$probe_digest" --json 2>&1)"
  status=$?
  set -e
  if (( status == 0 )); then
    return 0
  fi

  lowered="$(lower "$output")"
  if [[ "$lowered" == *"unrecognized subcommand"* ]] || [[ "$lowered" == *"unknown command"* ]]; then
    return 1
  fi
  if [[ "$lowered" == *"flag provided but not defined"* && "$lowered" == *"sign-digest"* ]]; then
    return 1
  fi
  return 0
}

supports_operator_endpoint_flag() {
  local signer_bin="$1"
  local probe_digest output status lowered

  [[ -n "$signer_bin" ]] || return 1
  probe_digest="0x$(printf '00%.0s' {1..32})"
  set +e
  output="$("$signer_bin" sign-digest --digest "$probe_digest" --json --operator-endpoint "https://127.0.0.1:1" 2>&1)"
  status=$?
  set -e
  if (( status == 0 )); then
    return 0
  fi

  lowered="$(lower "$output")"
  if [[ "$lowered" == *"unrecognized subcommand"* ]] || [[ "$lowered" == *"unknown command"* ]]; then
    return 1
  fi
  if [[ "$lowered" == *"flag provided but not defined"* && "$lowered" == *"operator-endpoint"* ]]; then
    return 1
  fi
  if [[ "$lowered" == *"unknown option"* && "$lowered" == *"operator-endpoint"* ]]; then
    return 1
  fi
  if [[ "$lowered" == *"unrecognized option"* && "$lowered" == *"operator-endpoint"* ]]; then
    return 1
  fi
  return 0
}

operator_signer_key_hex_from_file() {
  local key_file="$1"
  local key_hex

  [[ -n "$key_file" ]] || return 1
  [[ -f "$key_file" ]] || return 1
  key_hex="$(trimmed_file_value "$key_file")"
  key_hex="$(normalize_hex_prefixed "$key_hex" || true)"
  [[ "$key_hex" =~ ^0x[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$key_hex"
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
    balance="$(read_balance_wei_with_retry "$rpc_url" "$recipient" "$label balance")"
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

read_balance_wei_with_retry() {
  local rpc_url="$1"
  local address="$2"
  local label="$3"
  local balance_raw

  if ! balance_raw="$(run_with_rpc_retry 6 3 "cast balance" cast balance --rpc-url "$rpc_url" "$address")"; then
    balance_raw="$(trim "$balance_raw")"
    die "failed to read $label from cast after retries: address=$address error=$balance_raw"
  fi

  balance_raw="$(trim "$balance_raw")"
  [[ "$balance_raw" =~ ^[0-9]+$ ]] || \
    die "failed to read $label from cast after retries: address=$address error=$balance_raw"
  printf '%s' "$balance_raw"
}

assert_prefund_sender_budget() {
  local rpc_url="$1"
  local funding_sender_address="$2"
  local prefund_operator_count="$3"
  local per_operator_prefund_wei="$4"
  local bridge_deployer_required_wei="$5"

  local per_transfer_gas_limit_wei="21000"
  local conservative_gas_price_wei="5000000000"
  local transfer_retry_budget="3"
  local transfer_count gas_reserve_wei min_gas_reserve_wei
  local operator_prefund_total_wei required_total_wei funding_sender_balance_wei

  transfer_count=$((prefund_operator_count + 1))
  gas_reserve_wei=$((transfer_count * per_transfer_gas_limit_wei * conservative_gas_price_wei * transfer_retry_budget))
  min_gas_reserve_wei="5000000000000000"
  if (( gas_reserve_wei < min_gas_reserve_wei )); then
    gas_reserve_wei="$min_gas_reserve_wei"
  fi

  operator_prefund_total_wei=$((prefund_operator_count * per_operator_prefund_wei))
  required_total_wei=$((operator_prefund_total_wei + bridge_deployer_required_wei + gas_reserve_wei))

  funding_sender_balance_wei="$(read_balance_wei_with_retry "$rpc_url" "$funding_sender_address" "base funder balance for pre-fund budget check")"

  if (( funding_sender_balance_wei < required_total_wei )); then
    local shortfall_wei
    shortfall_wei=$((required_total_wei - funding_sender_balance_wei))
    die "insufficient base funder balance for operator/deployer pre-funding: address=$funding_sender_address balance_wei=$funding_sender_balance_wei required_wei=$required_total_wei shortfall_wei=$shortfall_wei operator_prefund_total_wei=$operator_prefund_total_wei bridge_deployer_required_wei=$bridge_deployer_required_wei gas_reserve_wei=$gas_reserve_wei"
  fi
}

compute_sp1_credit_guardrail_wei() {
  local max_price_per_pgu="$1"
  local deposit_pgu_estimate="$2"
  local withdraw_pgu_estimate="$3"
  local groth16_base_fee_wei="$4"

  python3 - "$max_price_per_pgu" "$deposit_pgu_estimate" "$withdraw_pgu_estimate" "$groth16_base_fee_wei" <<'PY'
import sys

max_price_per_pgu = int(sys.argv[1])
deposit_pgu_estimate = int(sys.argv[2])
withdraw_pgu_estimate = int(sys.argv[3])
groth16_base_fee_wei = int(sys.argv[4])

projected_pair_cost_wei = (groth16_base_fee_wei * 2) + (
    max_price_per_pgu * (deposit_pgu_estimate + withdraw_pgu_estimate)
)
projected_with_overhead_wei = ((projected_pair_cost_wei * 120) + 99) // 100
required_credit_buffer_wei = projected_with_overhead_wei * 3

print(required_credit_buffer_wei)
print(projected_with_overhead_wei)
print(projected_pair_cost_wei)
PY
}

derive_tss_url_from_juno_rpc_url() {
  local rpc_url="$1"
  if [[ "$rpc_url" =~ ^https?://([^/:]+)(:[0-9]+)?(/.*)?$ ]]; then
    printf 'https://%s:9443' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

normalize_hex_prefixed() {
  local raw="$1"
  raw="$(trim "$raw")"
  raw="${raw#0x}"
  raw="${raw#0X}"
  if [[ -z "$raw" ]]; then
    return 1
  fi
  if [[ ! "$raw" =~ ^[0-9a-fA-F]+$ ]]; then
    return 1
  fi
  printf '0x%s' "$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
}

predict_bridge_address_for_start_nonce() {
  local deployer_address="$1"
  local deployer_start_nonce="$2"
  local bridge_deploy_nonce
  local predicted

  [[ "$deployer_start_nonce" =~ ^[0-9]+$ ]] || return 1
  bridge_deploy_nonce=$((deployer_start_nonce + 3))
  predicted="$(cast compute-address --nonce "$bridge_deploy_nonce" "$deployer_address" 2>/dev/null || true)"
  # cast 1.5+ prints "Computed Address: <addr>", while older versions print only the address.
  predicted="$(printf '%s\n' "$predicted" | grep -Eo '0x[0-9a-fA-F]{40}' | tail -n1 || true)"
  predicted="$(normalize_hex_prefixed "$predicted" || true)"
  [[ "$predicted" =~ ^0x[0-9a-f]{40}$ ]] || return 1
  printf '%s' "$predicted"
}

compute_single_withdraw_batch_id() {
  local withdrawal_id_hex="$1"
  local withdrawal_id_norm ids_hash domain_tag batch_id

  withdrawal_id_norm="$(normalize_hex_prefixed "$withdrawal_id_hex" || true)"
  [[ "$withdrawal_id_norm" =~ ^0x[0-9a-f]{64}$ ]] || return 1

  ids_hash="$(cast keccak "$withdrawal_id_norm" 2>/dev/null || true)"
  ids_hash="$(normalize_hex_prefixed "$ids_hash" || true)"
  [[ "$ids_hash" =~ ^0x[0-9a-f]{64}$ ]] || return 1

  domain_tag="$(cast from-utf8 WJUNO_WITHDRAW_BATCH_V1 2>/dev/null || true)"
  domain_tag="$(normalize_hex_prefixed "$domain_tag" || true)"
  [[ "$domain_tag" =~ ^0x[0-9a-f]+$ ]] || return 1

  batch_id="$(cast keccak "$(cast concat-hex "$domain_tag" "$ids_hash")" 2>/dev/null || true)"
  batch_id="$(normalize_hex_prefixed "$batch_id" || true)"
  [[ "$batch_id" =~ ^0x[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$batch_id"
}

cast_contract_call_json() {
  local rpc_url="$1"
  local contract_addr="$2"
  local calldata_sig="$3"
  local decode_sig="$4"
  shift 4

  local call_data raw_response
  call_data="$(cast calldata "$calldata_sig" "$@")"
  raw_response="$(cast call --rpc-url "$rpc_url" "$contract_addr" --data "$call_data")"
  cast decode-abi --json "$decode_sig" "$raw_response"
}

cast_contract_call_one() {
  local rpc_url="$1"
  local contract_addr="$2"
  local calldata_sig="$3"
  local decode_sig="$4"
  shift 4

  local decoded_json
  decoded_json="$(
    cast_contract_call_json \
      "$rpc_url" \
      "$contract_addr" \
      "$calldata_sig" \
      "$decode_sig" \
      "$@"
  )"
  jq -r '.[0] | if type == "number" then tostring else . end' <<<"$decoded_json"
}

wait_for_condition() {
  local timeout_seconds="$1"
  local interval_seconds="$2"
  local label="$3"
  shift 3

  local elapsed=0
  local status
  local output=""

  while (( elapsed < timeout_seconds )); do
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e
    if (( status == 0 )); then
      return 0
    fi
    if [[ -n "$output" ]]; then
      log "$label pending: $output"
    else
      log "$label pending"
    fi
    sleep "$interval_seconds"
    elapsed=$((elapsed + interval_seconds))
  done

  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if (( status != 0 )); then
    if [[ -n "$output" ]]; then
      log "$label failed: $output"
    else
      log "$label failed"
    fi
    return 1
  fi
  return 0
}

parse_csv_list() {
  local csv="$1"
  local -a raw_entries=()
  local entry

  IFS=',' read -r -a raw_entries <<<"$csv"
  for entry in "${raw_entries[@]}"; do
    entry="$(trim "$entry")"
    [[ -n "$entry" ]] || continue
    printf '%s\n' "$entry"
  done
}

start_remote_relayer_service() {
  local host="$1"
  local ssh_user="$2"
  local ssh_key_file="$3"
  local log_path="$4"
  shift 4
  local remote_joined_args
  remote_joined_args="$(shell_join "$@")"
  [[ -n "$remote_joined_args" ]] || die "remote relayer service command must not be empty (host=$host)"

  (
    ssh \
      -i "$ssh_key_file" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$ssh_user@$host" \
      "bash -lc $(printf '%q' "$remote_joined_args")"
  ) >"$log_path" 2>&1 &
  printf '%s' "$!"
}

stop_remote_relayer_binaries_on_host() {
  local host="$1"
  local ssh_user="$2"
  local ssh_key_file="$3"
  shift 3
  local -a cleanup_ports=("$@")
  local cleanup_ports_joined=""
  local remote_cleanup_cmd=""
  local cleanup_attempt
  if (( ${#cleanup_ports[@]} > 0 )); then
    cleanup_ports_joined="$(shell_join "${cleanup_ports[@]}")"
  fi

  remote_cleanup_cmd+="set -euo pipefail;"
  remote_cleanup_cmd+=" cleanup_patterns=("
  remote_cleanup_cmd+=" '/usr/local/bin/[b]ase-relayer'"
  remote_cleanup_cmd+=" '/usr/local/bin/[d]eposit-relayer'"
  remote_cleanup_cmd+=" '/usr/local/bin/[w]ithdraw-coordinator'"
  remote_cleanup_cmd+=" '/usr/local/bin/[w]ithdraw-finalizer'"
  remote_cleanup_cmd+=" '/usr/local/bin/[b]ridge-api'"
  remote_cleanup_cmd+=" 'go run ./cmd/[b]ase-relayer'"
  remote_cleanup_cmd+=" 'go run ./cmd/[d]eposit-relayer'"
  remote_cleanup_cmd+=" 'go run ./cmd/[w]ithdraw-coordinator'"
  remote_cleanup_cmd+=" 'go run ./cmd/[w]ithdraw-finalizer'"
  remote_cleanup_cmd+=" 'go run ./cmd/[b]ridge-api'"
  remote_cleanup_cmd+=" );"
  remote_cleanup_cmd+=" for cleanup_pattern in \"\${cleanup_patterns[@]}\"; do"
  remote_cleanup_cmd+=" pkill -f \"\$cleanup_pattern\" >/dev/null 2>&1 || true;"
  remote_cleanup_cmd+=" done;"
  remote_cleanup_cmd+=" cleanup_ports=($cleanup_ports_joined);"
  remote_cleanup_cmd+=" for cleanup_port in \"\${cleanup_ports[@]}\"; do"
  remote_cleanup_cmd+=" [[ \"\$cleanup_port\" =~ ^[0-9]+$ ]] || continue;"
  remote_cleanup_cmd+=" if command -v lsof >/dev/null 2>&1; then"
  remote_cleanup_cmd+=" while IFS= read -r cleanup_pid; do"
  remote_cleanup_cmd+=" [[ \"\$cleanup_pid\" =~ ^[0-9]+$ ]] || continue;"
  remote_cleanup_cmd+=" kill \"\$cleanup_pid\" >/dev/null 2>&1 || true;"
  remote_cleanup_cmd+=" done < <(lsof -t -iTCP:\"\$cleanup_port\" -sTCP:LISTEN 2>/dev/null || true);"
  remote_cleanup_cmd+=" sleep 1;"
  remote_cleanup_cmd+=" fi;"
  remote_cleanup_cmd+=" if command -v fuser >/dev/null 2>&1; then"
  remote_cleanup_cmd+=" fuser -k \"\${cleanup_port}/tcp\" >/dev/null 2>&1 || true;"
  remote_cleanup_cmd+=" fi;"
  remote_cleanup_cmd+=" done"

  for cleanup_attempt in 1 2 3; do
    if ssh \
      -i "$ssh_key_file" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$ssh_user@$host" \
      "bash -lc $(printf '%q' "$remote_cleanup_cmd")"; then
      return 0
    fi
    sleep 2
  done

  return 1
}

stop_local_relayer_binaries() {
  local -a local_cleanup_patterns=(
    "/usr/local/bin/base-relayer"
    "/usr/local/bin/deposit-relayer"
    "/usr/local/bin/withdraw-coordinator"
    "/usr/local/bin/withdraw-finalizer"
    "/usr/local/bin/bridge-api"
    "go run ./cmd/base-relayer"
    "go run ./cmd/deposit-relayer"
    "go run ./cmd/withdraw-coordinator"
    "go run ./cmd/withdraw-finalizer"
    "go run ./cmd/bridge-api"
  )
  local cleanup_pattern
  for cleanup_pattern in "${local_cleanup_patterns[@]}"; do
    pkill -f "$cleanup_pattern" >/dev/null 2>&1 || true
  done
}

free_local_tcp_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || return 0

  local -a listen_pids=()
  local pid=""
  if command -v lsof >/dev/null 2>&1; then
    while IFS= read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] || continue
      listen_pids+=("$pid")
    done < <(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
  fi

  if (( ${#listen_pids[@]} > 0 )); then
    for pid in "${listen_pids[@]}"; do
      kill "$pid" >/dev/null 2>&1 || true
    done
    sleep 1
  fi

  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
  fi
}

stop_remote_relayer_service() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

stage_remote_runtime_file() {
  local src_path="$1"
  local host="$2"
  local ssh_user="$3"
  local ssh_key_file="$4"
  local remote_path="$5"

  scp \
    -i "$ssh_key_file" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$src_path" \
    "$ssh_user@$host:$remote_path" >/dev/null
}

configure_remote_operator_checkpoint_services_for_bridge() {
  local host="$1"
  local ssh_user="$2"
  local ssh_key_file="$3"
  local bridge_address="$4"
  local base_chain_id="$5"
  local operator_address="$6"
  local operator_signer_key_hex="$7"
  local aws_region="$8"
  local shared_postgres_dsn="$9"
  local shared_kafka_brokers="${10}"
  local shared_ipfs_api_url="${11}"

  operator_address="$(normalize_hex_prefixed "$operator_address" || true)"
  [[ "$operator_address" =~ ^0x[0-9a-f]{40}$ ]] || \
    die "checkpoint bridge config update requires valid operator address for host=$host"
  operator_signer_key_hex="$(normalize_hex_prefixed "$operator_signer_key_hex" || true)"
  [[ "$operator_signer_key_hex" =~ ^0x[0-9a-f]{64}$ ]] || \
    die "checkpoint bridge config update requires valid operator signer key for host=$host"
  if [[ -n "$aws_region" ]]; then
    aws_region="$(trim "$aws_region")"
  fi
  if [[ -z "$aws_region" ]]; then
    aws_region="$(trim "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}")"
  fi
  [[ -n "$aws_region" ]] || die "checkpoint bridge config update requires resolvable aws region for host=$host"
  [[ -n "$shared_postgres_dsn" ]] || die "checkpoint bridge config update requires shared postgres dsn for host=$host"
  [[ -n "$shared_kafka_brokers" ]] || die "checkpoint bridge config update requires shared kafka brokers for host=$host"
  [[ -n "$shared_ipfs_api_url" ]] || die "checkpoint bridge config update requires shared ipfs api url for host=$host"

  local remote_script
  remote_script="$(cat <<'EOF'
set -euo pipefail
bridge_address="$1"
base_chain_id="$2"
operator_address="$3"
operator_signer_key_hex="$4"
aws_region="$5"
shared_postgres_dsn="$6"
shared_kafka_brokers="$7"
shared_ipfs_api_url="$8"

[[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || {
  echo "operator address must be 20-byte hex: $operator_address" >&2
  exit 1
}
[[ "$operator_signer_key_hex" =~ ^0x[0-9a-fA-F]{64}$ ]] || {
  echo "operator signer key must be 32-byte hex" >&2
  exit 1
}
operator_address="${operator_address,,}"
operator_signer_key_hex="${operator_signer_key_hex,,}"
checkpoint_signer_lease_name="checkpoint-signer-${operator_address#0x}"

stack_env_file="/etc/intents-juno/operator-stack.env"
hydrator_env_file="/etc/intents-juno/operator-stack-hydrator.env"
config_json_path="/etc/intents-juno/operator-stack-config.json"

if [[ -f "$hydrator_env_file" ]]; then
  configured_json_path="$(sudo awk -F= '/^OPERATOR_STACK_CONFIG_JSON_PATH=/{print substr($0, index($0, "=")+1); exit}' "$hydrator_env_file")"
  if [[ -n "$configured_json_path" ]]; then
    config_json_path="$configured_json_path"
  fi
fi

[[ -s "$stack_env_file" ]] || {
  echo "operator stack env is missing: $stack_env_file" >&2
  exit 1
}
[[ -s "$config_json_path" ]] || {
  echo "operator stack config json is missing: $config_json_path" >&2
  exit 1
}

normalize_region() {
  local value="${1:-}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | xargs)"
  if [[ "$value" =~ ^([a-z0-9-]+-[0-9])[a-z]$ ]]; then
    value="${BASH_REMATCH[1]}"
  fi
  printf '%s' "$value"
}

resolve_aws_region() {
  local candidate="${1:-}"
  candidate="$(normalize_region "$candidate")"
  if [[ -n "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  candidate="$(normalize_region "$(awk -F= '/^AWS_REGION=/{print substr($0, index($0, "=")+1); exit}' "$stack_env_file" 2>/dev/null || true)")"
  if [[ -n "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi
  candidate="$(normalize_region "$(awk -F= '/^AWS_DEFAULT_REGION=/{print substr($0, index($0, "=")+1); exit}' "$stack_env_file" 2>/dev/null || true)")"
  if [[ -n "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  candidate="$(normalize_region "${AWS_REGION:-}")"
  if [[ -n "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi
  candidate="$(normalize_region "${AWS_DEFAULT_REGION:-}")"
  if [[ -n "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    local token identity_doc imds_region
    token="$(curl -fsS --max-time 2 -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' || true)"
    if [[ -n "$token" ]]; then
      identity_doc="$(curl -fsS --max-time 2 -H "X-aws-ec2-metadata-token: $token" 'http://169.254.169.254/latest/dynamic/instance-identity/document' || true)"
      if [[ -n "$identity_doc" ]]; then
        imds_region="$(jq -r '.region // empty' <<<"$identity_doc" 2>/dev/null || true)"
        candidate="$(normalize_region "$imds_region")"
        if [[ -n "$candidate" ]]; then
          printf '%s' "$candidate"
          return 0
        fi
      fi
    fi
  fi
  return 1
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN {
      updated = 0
    }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    {
      print
    }
    END {
      if (updated == 0) {
        print key "=" value
      }
    }
  ' "$file" > "$tmp"
  install -m 0600 "$tmp" "$file"
  rm -f "$tmp"
}

aws_region="$(resolve_aws_region "$aws_region" || true)"
if [[ -z "$aws_region" ]]; then
  echo "failed to resolve aws region for checkpoint aggregator s3 persistence" >&2
  exit 1
fi

tmp_json="$(mktemp)"
tmp_next="$(mktemp)"
sudo cp "$config_json_path" "$tmp_json"
sudo chown "$(id -u):$(id -g)" "$tmp_json"
chmod 600 "$tmp_json"

jq \
  --arg bridge "$bridge_address" \
  --arg chain "$base_chain_id" \
  --arg shared_postgres_dsn "$shared_postgres_dsn" \
  --arg shared_kafka_brokers "$shared_kafka_brokers" \
  --arg shared_ipfs_api_url "$shared_ipfs_api_url" \
  '
  .BRIDGE_ADDRESS = $bridge
  | .BASE_CHAIN_ID = $chain
  | .CHECKPOINT_POSTGRES_DSN = $shared_postgres_dsn
  | .CHECKPOINT_KAFKA_BROKERS = $shared_kafka_brokers
  | .CHECKPOINT_IPFS_API_URL = $shared_ipfs_api_url
  | .JUNO_QUEUE_KAFKA_TLS = (
      if (.JUNO_QUEUE_KAFKA_TLS // "") == "" then
        "true"
      else
        .JUNO_QUEUE_KAFKA_TLS
      end
    )
  ' "$tmp_json" >"$tmp_next"

sudo install -d -m 0750 -o root -g ubuntu "$(dirname "$config_json_path")"
sudo install -m 0640 -o root -g ubuntu "$tmp_next" "$config_json_path"
rm -f "$tmp_json" "$tmp_next"

tmp_env="$(mktemp)"
sudo cp "$stack_env_file" "$tmp_env"
sudo chown "$(id -u):$(id -g)" "$tmp_env"
chmod 600 "$tmp_env"
set_env_value "$tmp_env" BRIDGE_ADDRESS "$bridge_address"
set_env_value "$tmp_env" BASE_CHAIN_ID "$base_chain_id"
set_env_value "$tmp_env" AWS_REGION "$aws_region"
set_env_value "$tmp_env" AWS_DEFAULT_REGION "$aws_region"
set_env_value "$tmp_env" CHECKPOINT_POSTGRES_DSN "$shared_postgres_dsn"
set_env_value "$tmp_env" CHECKPOINT_KAFKA_BROKERS "$shared_kafka_brokers"
set_env_value "$tmp_env" CHECKPOINT_IPFS_API_URL "$shared_ipfs_api_url"
set_env_value "$tmp_env" JUNO_QUEUE_KAFKA_TLS "true"
set_env_value "$tmp_env" CHECKPOINT_SIGNER_PRIVATE_KEY "$operator_signer_key_hex"
set_env_value "$tmp_env" OPERATOR_ADDRESS "$operator_address"
set_env_value "$tmp_env" CHECKPOINT_SIGNER_LEASE_NAME "$checkpoint_signer_lease_name"
sudo install -m 0640 -o root -g ubuntu "$tmp_env" "$stack_env_file"
rm -f "$tmp_env"

checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"
checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"
[[ -f "$checkpoint_signer_script" ]] || {
  echo "checkpoint signer wrapper is missing: $checkpoint_signer_script" >&2
  exit 1
}
[[ -f "$checkpoint_aggregator_script" ]] || {
  echo "checkpoint aggregator wrapper is missing: $checkpoint_aggregator_script" >&2
  exit 1
}

sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_signer_script"
sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_signer_script"
if grep -qE '^[[:space:]]*--lease-name ' "$checkpoint_signer_script"; then
  sudo sed -i "s|^[[:space:]]*--lease-name .*|  --lease-name \"${checkpoint_signer_lease_name}\" \\\\|g" "$checkpoint_signer_script"
else
  lease_tmp="$(mktemp)"
  awk -v lease="$checkpoint_signer_lease_name" '
    BEGIN {
      inserted = 0
    }
    {
      if (inserted == 0 && $0 ~ /--owner-id /) {
        print
        printf "  --lease-name \"%s\" %c\n", lease, 92
        inserted = 1
        next
      }
      if (inserted == 0 && $0 ~ /--postgres-dsn /) {
        printf "  --lease-name \"%s\" %c\n", lease, 92
        inserted = 1
      }
      print
    }
    END {
      if (inserted == 0) {
        printf "  --lease-name \"%s\" %c\n", lease, 92
      }
    }
  ' "$checkpoint_signer_script" >"$lease_tmp"
  sudo install -m 0755 "$lease_tmp" "$checkpoint_signer_script"
  rm -f "$lease_tmp"
fi
sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_aggregator_script"
sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_aggregator_script"

sudo systemctl daemon-reload
sudo systemctl restart intents-juno-config-hydrator.service
if ! sudo systemctl is-active --quiet intents-juno-config-hydrator.service; then
  echo "operator stack config hydrator failed after bridge config update" >&2
  sudo systemctl status intents-juno-config-hydrator.service --no-pager || true
  exit 1
fi

sudo systemctl restart checkpoint-signer.service checkpoint-aggregator.service
sleep 2

for svc in checkpoint-signer.service checkpoint-aggregator.service; do
  if ! sudo systemctl is-active --quiet "$svc"; then
    echo "operator checkpoint service failed after bridge config update: $svc" >&2
    sudo systemctl status "$svc" --no-pager || true
    sudo journalctl -u "$svc" -n 120 --no-pager || true
    exit 1
  fi
done
EOF
)"

  ssh \
    -i "$ssh_key_file" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$ssh_user@$host" \
    "bash -s -- $(printf '%q' "$bridge_address") $(printf '%q' "$base_chain_id") $(printf '%q' "$operator_address") $(printf '%q' "$operator_signer_key_hex") $(printf '%q' "$aws_region") $(printf '%q' "$shared_postgres_dsn") $(printf '%q' "$shared_kafka_brokers") $(printf '%q' "$shared_ipfs_api_url")" <<<"$remote_script"
}

endpoint_host_port() {
  local endpoint="$1"
  if [[ "$endpoint" =~ ^https?://([^/:]+):([0-9]+)(/.*)?$ ]]; then
    printf '%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  return 1
}

is_withdraw_not_expired_error() {
  local msg lowered
  msg="${1:-}"
  lowered="$(lower "$msg")"
  [[ "$lowered" == *"withdrawnotexpired"* ]] ||
    [[ "$lowered" == *"withdraw not expired"* ]]
}

inject_operator_endpoint_failure() {
  local endpoint="$1"
  local ssh_key_path="$2"
  local ssh_user="$3"
  local host port
  local endpoint_pid=""
  local endpoint_down="false"

  if ! read -r host port < <(endpoint_host_port "$endpoint"); then
    printf 'invalid operator endpoint for failure injection: %s\n' "$endpoint" >&2
    return 1
  fi

  if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]]; then
    endpoint_pid="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)"
    if [[ -z "$endpoint_pid" ]]; then
      printf 'no local listener found for operator endpoint failure injection: %s\n' "$endpoint" >&2
      return 1
    fi
    kill "$endpoint_pid" >/dev/null 2>&1 || true
  else
    [[ -n "$ssh_user" ]] || ssh_user="$(id -un)"
    if [[ -z "$ssh_key_path" || ! -f "$ssh_key_path" ]]; then
      printf 'ssh key is required for remote operator failure injection: endpoint=%s key=%s\n' "$endpoint" "$ssh_key_path" >&2
      return 1
    fi

    endpoint_pid="$(
      ssh \
        -i "$ssh_key_path" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -o TCPKeepAlive=yes \
        "$ssh_user@$host" \
        "sudo lsof -tiTCP:$port -sTCP:LISTEN | head -n 1" 2>/dev/null || true
    )"
    endpoint_pid="$(trim "$endpoint_pid")"
    if [[ -z "$endpoint_pid" ]]; then
      printf 'no remote listener found for operator endpoint failure injection: %s\n' "$endpoint" >&2
      return 1
    fi

    ssh \
      -i "$ssh_key_path" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$ssh_user@$host" \
      "sudo kill $endpoint_pid" >/dev/null 2>&1 || true
  fi

  local probe_attempt
  for probe_attempt in $(seq 1 10); do
    if ! timeout 2 bash -lc "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
      endpoint_down="true"
      break
    fi
    sleep 1
  done
  if [[ "$endpoint_down" != "true" ]]; then
    printf 'operator endpoint remained reachable after injected failure: %s\n' "$endpoint" >&2
    return 1
  fi

  printf '%s' "$endpoint_pid"
}

query_withdrawal_payout_txid() {
  local postgres_dsn="$1"
  local withdrawal_id="$2"
  local withdrawal_id_hex txid

  withdrawal_id_hex="$(trim "$withdrawal_id")"
  withdrawal_id_hex="${withdrawal_id_hex#0x}"
  withdrawal_id_hex="${withdrawal_id_hex#0X}"
  [[ "$withdrawal_id_hex" =~ ^[0-9a-fA-F]{64}$ ]] || \
    die "invalid withdrawal id for payout tx query: $withdrawal_id"

  txid="$(
    psql "$postgres_dsn" -Atqc "
      SELECT wb.juno_txid
      FROM withdrawal_batch_items wbi
      JOIN withdrawal_batches wb ON wb.batch_id = wbi.batch_id
      WHERE wbi.withdrawal_id = decode('${withdrawal_id_hex}', 'hex')
        AND wb.juno_txid IS NOT NULL
        AND wb.juno_txid <> ''
      ORDER BY wb.updated_at DESC
      LIMIT 1;
    " 2>/dev/null || true
  )"
  printf '%s' "$(trim "$txid")"
}

wait_for_withdrawal_payout_txid() {
  local postgres_dsn="$1"
  local withdrawal_id="$2"
  local timeout_seconds="$3"
  local interval_seconds=2
  local elapsed=0
  local txid normalized_txid

  while (( elapsed < timeout_seconds )); do
    txid="$(query_withdrawal_payout_txid "$postgres_dsn" "$withdrawal_id")"
    if [[ -n "$txid" ]]; then
      normalized_txid="$(normalize_hex_prefixed "$txid" || true)"
      if [[ "$normalized_txid" =~ ^0x[0-9a-f]{64}$ ]]; then
        printf '%s' "$normalized_txid"
        return 0
      fi
      die "invalid Juno payout txid in withdraw coordinator state: $txid"
    fi
    sleep "$interval_seconds"
    elapsed=$((elapsed + interval_seconds))
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
  local existing_bridge_summary_path=""
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
  local bridge_run_timeout=""
  local bridge_operator_signer_bin=""
  local sp1_auto="true"
  local sp1_proof_submission_mode="queue"
  local sp1_bin="sp1-prover-adapter"
  local sp1_rpc_url="https://rpc.mainnet.succinct.xyz"
  local sp1_market_address="0xFd152dADc5183870710FE54f939Eae3aB9F0fE82"
  local sp1_verifier_router_address="0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"
  local sp1_set_verifier_address="0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"
  local sp1_input_mode="guest-witness-v1"
  local sp1_deposit_owallet_ivk_hex=""
  local sp1_withdraw_owallet_ovk_hex=""
  local -a sp1_deposit_witness_item_files=()
  local -a sp1_withdraw_witness_item_files=()
  local sp1_witness_juno_scan_url=""
  local sp1_witness_juno_rpc_url=""
  local sp1_witness_juno_scan_urls_csv=""
  local sp1_witness_juno_rpc_urls_csv=""
  local sp1_witness_operator_labels_csv=""
  local sp1_witness_quorum_threshold="3"
  local sp1_witness_juno_scan_bearer_token_env="JUNO_SCAN_BEARER_TOKEN"
  local sp1_witness_juno_rpc_user_env="JUNO_RPC_USER"
  local sp1_witness_juno_rpc_pass_env="JUNO_RPC_PASS"
  local sp1_witness_recipient_ua=""
  local sp1_witness_recipient_ufvk=""
  local sp1_witness_wallet_id=""
  local sp1_witness_metadata_timeout_seconds="900"
  local withdraw_coordinator_tss_url=""
  local withdraw_coordinator_tss_server_ca_file=""
  local withdraw_blob_bucket=""
  local withdraw_blob_prefix="withdraw-live"
  local sp1_requestor_key_file=""
  local sp1_deposit_program_url=""
  local sp1_withdraw_program_url=""
  local sp1_input_s3_bucket=""
  local sp1_input_s3_prefix="bridge-e2e/sp1-input"
  local sp1_input_s3_region=""
  local sp1_input_s3_presign_ttl="2h"
  local sp1_max_price_per_pgu="1000000000000"
  local sp1_deposit_pgu_estimate="1000000"
  local sp1_withdraw_pgu_estimate="1000000"
  local sp1_groth16_base_fee_wei="200000000000000000"
  local sp1_min_auction_period="85"
  local sp1_auction_timeout="625s"
  local sp1_request_timeout="1500s"
  local shared_postgres_dsn=""
  local shared_kafka_brokers=""
  local shared_ipfs_api_url=""
  local shared_ecs_cluster_arn=""
  local shared_proof_requestor_service_name=""
  local shared_proof_funder_service_name=""
  local shared_topic_prefix="shared.infra.e2e"
  local shared_timeout="300s"
  local shared_output=""
  local relayer_runtime_mode="distributed"
  local relayer_runtime_operator_hosts_csv=""
  local relayer_runtime_operator_ssh_user=""
  local relayer_runtime_operator_ssh_key_file=""
  local aws_dr_region=""
  local refund_after_expiry_window_seconds="120"
  local output_path=""
  local force="false"
  local stop_after_stage="full"

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
      --existing-bridge-summary-path)
        [[ $# -ge 2 ]] || die "missing value for --existing-bridge-summary-path"
        existing_bridge_summary_path="$2"
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
      --sp1-bin)
        [[ $# -ge 2 ]] || die "missing value for --sp1-bin"
        sp1_bin="$2"
        shift 2
        ;;
      --sp1-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --sp1-rpc-url"
        sp1_rpc_url="$2"
        shift 2
        ;;
      --sp1-market-address)
        [[ $# -ge 2 ]] || die "missing value for --sp1-market-address"
        sp1_market_address="$2"
        shift 2
        ;;
      --sp1-verifier-router-address)
        [[ $# -ge 2 ]] || die "missing value for --sp1-verifier-router-address"
        sp1_verifier_router_address="$2"
        shift 2
        ;;
      --sp1-set-verifier-address)
        [[ $# -ge 2 ]] || die "missing value for --sp1-set-verifier-address"
        sp1_set_verifier_address="$2"
        shift 2
        ;;
      --sp1-input-mode)
        [[ $# -ge 2 ]] || die "missing value for --sp1-input-mode"
        sp1_input_mode="$2"
        shift 2
        ;;
      --sp1-deposit-owallet-ivk-hex)
        [[ $# -ge 2 ]] || die "missing value for --sp1-deposit-owallet-ivk-hex"
        sp1_deposit_owallet_ivk_hex="$2"
        shift 2
        ;;
      --sp1-withdraw-owallet-ovk-hex)
        [[ $# -ge 2 ]] || die "missing value for --sp1-withdraw-owallet-ovk-hex"
        sp1_withdraw_owallet_ovk_hex="$2"
        shift 2
        ;;
      --sp1-witness-juno-scan-url)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-scan-url"
        sp1_witness_juno_scan_url="$2"
        shift 2
        ;;
      --sp1-witness-juno-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-rpc-url"
        sp1_witness_juno_rpc_url="$2"
        shift 2
        ;;
      --sp1-witness-juno-scan-urls)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-scan-urls"
        sp1_witness_juno_scan_urls_csv="$2"
        shift 2
        ;;
      --sp1-witness-juno-rpc-urls)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-rpc-urls"
        sp1_witness_juno_rpc_urls_csv="$2"
        shift 2
        ;;
      --sp1-witness-operator-labels)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-operator-labels"
        sp1_witness_operator_labels_csv="$2"
        shift 2
        ;;
      --sp1-witness-quorum-threshold)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-quorum-threshold"
        sp1_witness_quorum_threshold="$2"
        shift 2
        ;;
      --sp1-witness-juno-scan-bearer-token-env)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-scan-bearer-token-env"
        sp1_witness_juno_scan_bearer_token_env="$2"
        shift 2
        ;;
      --sp1-witness-juno-rpc-user-env)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-rpc-user-env"
        sp1_witness_juno_rpc_user_env="$2"
        shift 2
        ;;
      --sp1-witness-juno-rpc-pass-env)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-juno-rpc-pass-env"
        sp1_witness_juno_rpc_pass_env="$2"
        shift 2
        ;;
      --sp1-witness-recipient-ua)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-recipient-ua"
        sp1_witness_recipient_ua="$2"
        shift 2
        ;;
      --sp1-witness-recipient-ufvk)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-recipient-ufvk"
        sp1_witness_recipient_ufvk="$2"
        shift 2
        ;;
      --sp1-witness-wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-wallet-id"
        sp1_witness_wallet_id="$2"
        shift 2
        ;;
      --sp1-witness-metadata-timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --sp1-witness-metadata-timeout-seconds"
        sp1_witness_metadata_timeout_seconds="$2"
        shift 2
        ;;
      --withdraw-coordinator-tss-url)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-coordinator-tss-url"
        withdraw_coordinator_tss_url="$2"
        shift 2
        ;;
      --withdraw-coordinator-tss-server-ca-file)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-coordinator-tss-server-ca-file"
        withdraw_coordinator_tss_server_ca_file="$2"
        shift 2
        ;;
      --withdraw-blob-bucket)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-blob-bucket"
        withdraw_blob_bucket="$2"
        shift 2
        ;;
      --withdraw-blob-prefix)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-blob-prefix"
        withdraw_blob_prefix="$2"
        shift 2
        ;;
      --runtime-mode|--withdraw-coordinator-runtime-mode)
        [[ $# -ge 2 ]] || die "missing value for $1"
        die "withdraw coordinator mock runtime is forbidden in live e2e (full mode only)"
        ;;
      --sp1-requestor-key-file)
        [[ $# -ge 2 ]] || die "missing value for --sp1-requestor-key-file"
        sp1_requestor_key_file="$2"
        shift 2
        ;;
      --sp1-deposit-program-url)
        [[ $# -ge 2 ]] || die "missing value for --sp1-deposit-program-url"
        sp1_deposit_program_url="$2"
        shift 2
        ;;
      --sp1-withdraw-program-url)
        [[ $# -ge 2 ]] || die "missing value for --sp1-withdraw-program-url"
        sp1_withdraw_program_url="$2"
        shift 2
        ;;
      --sp1-input-s3-bucket)
        [[ $# -ge 2 ]] || die "missing value for --sp1-input-s3-bucket"
        sp1_input_s3_bucket="$2"
        shift 2
        ;;
      --sp1-input-s3-prefix)
        [[ $# -ge 2 ]] || die "missing value for --sp1-input-s3-prefix"
        sp1_input_s3_prefix="$2"
        shift 2
        ;;
      --sp1-input-s3-region)
        [[ $# -ge 2 ]] || die "missing value for --sp1-input-s3-region"
        sp1_input_s3_region="$2"
        shift 2
        ;;
      --sp1-input-s3-presign-ttl)
        [[ $# -ge 2 ]] || die "missing value for --sp1-input-s3-presign-ttl"
        sp1_input_s3_presign_ttl="$2"
        shift 2
        ;;
      --sp1-max-price-per-pgu)
        [[ $# -ge 2 ]] || die "missing value for --sp1-max-price-per-pgu"
        sp1_max_price_per_pgu="$2"
        shift 2
        ;;
      --sp1-deposit-pgu-estimate)
        [[ $# -ge 2 ]] || die "missing value for --sp1-deposit-pgu-estimate"
        sp1_deposit_pgu_estimate="$2"
        shift 2
        ;;
      --sp1-withdraw-pgu-estimate)
        [[ $# -ge 2 ]] || die "missing value for --sp1-withdraw-pgu-estimate"
        sp1_withdraw_pgu_estimate="$2"
        shift 2
        ;;
      --sp1-groth16-base-fee-wei)
        [[ $# -ge 2 ]] || die "missing value for --sp1-groth16-base-fee-wei"
        sp1_groth16_base_fee_wei="$2"
        shift 2
        ;;
      --sp1-min-auction-period)
        [[ $# -ge 2 ]] || die "missing value for --sp1-min-auction-period"
        sp1_min_auction_period="$2"
        shift 2
        ;;
      --sp1-auction-timeout)
        [[ $# -ge 2 ]] || die "missing value for --sp1-auction-timeout"
        sp1_auction_timeout="$2"
        shift 2
        ;;
      --sp1-request-timeout)
        [[ $# -ge 2 ]] || die "missing value for --sp1-request-timeout"
        sp1_request_timeout="$2"
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
      --relayer-runtime-mode)
        [[ $# -ge 2 ]] || die "missing value for --relayer-runtime-mode"
        relayer_runtime_mode="$(lower "$2")"
        shift 2
        ;;
      --relayer-runtime-operator-hosts)
        [[ $# -ge 2 ]] || die "missing value for --relayer-runtime-operator-hosts"
        relayer_runtime_operator_hosts_csv="$2"
        shift 2
        ;;
      --relayer-runtime-operator-ssh-user)
        [[ $# -ge 2 ]] || die "missing value for --relayer-runtime-operator-ssh-user"
        relayer_runtime_operator_ssh_user="$2"
        shift 2
        ;;
      --relayer-runtime-operator-ssh-key-file)
        [[ $# -ge 2 ]] || die "missing value for --relayer-runtime-operator-ssh-key-file"
        relayer_runtime_operator_ssh_key_file="$2"
        shift 2
        ;;
      --aws-dr-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-dr-region"
        aws_dr_region="$2"
        shift 2
        ;;
      --refund-after-expiry-window-seconds)
        [[ $# -ge 2 ]] || die "missing value for --refund-after-expiry-window-seconds"
        refund_after_expiry_window_seconds="$2"
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
      --stop-after-stage)
        [[ $# -ge 2 ]] || die "missing value for --stop-after-stage"
        stop_after_stage="$(lower "$2")"
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
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  [[ "$base_chain_id" =~ ^[0-9]+$ ]] || die "--base-chain-id must be numeric"
  [[ "$operator_count" =~ ^[0-9]+$ ]] || die "--operator-count must be numeric"
  [[ "$threshold" =~ ^[0-9]+$ ]] || die "--threshold must be numeric"
  [[ "$base_port" =~ ^[0-9]+$ ]] || die "--base-port must be numeric"
  [[ "$base_operator_fund_wei" =~ ^[0-9]+$ ]] || die "--base-operator-fund-wei must be numeric"
  [[ "$sp1_max_price_per_pgu" =~ ^[0-9]+$ ]] || die "--sp1-max-price-per-pgu must be numeric"
  [[ "$sp1_deposit_pgu_estimate" =~ ^[0-9]+$ ]] || die "--sp1-deposit-pgu-estimate must be numeric"
  [[ "$sp1_withdraw_pgu_estimate" =~ ^[0-9]+$ ]] || die "--sp1-withdraw-pgu-estimate must be numeric"
  [[ "$sp1_groth16_base_fee_wei" =~ ^[0-9]+$ ]] || die "--sp1-groth16-base-fee-wei must be numeric"
  [[ "$sp1_min_auction_period" =~ ^[0-9]+$ ]] || die "--sp1-min-auction-period must be numeric"
  [[ "$sp1_auction_timeout" =~ ^[0-9]+s$ ]] || die "--sp1-auction-timeout must be seconds with s suffix (example: 625s)"
  [[ "$sp1_request_timeout" =~ ^[0-9]+s$ ]] || die "--sp1-request-timeout must be seconds with s suffix (example: 1500s)"
  (( sp1_max_price_per_pgu > 0 )) || die "--sp1-max-price-per-pgu must be > 0"
  (( sp1_deposit_pgu_estimate > 0 )) || die "--sp1-deposit-pgu-estimate must be > 0"
  (( sp1_withdraw_pgu_estimate > 0 )) || die "--sp1-withdraw-pgu-estimate must be > 0"
  (( sp1_groth16_base_fee_wei > 0 )) || die "--sp1-groth16-base-fee-wei must be > 0"
  [[ "$refund_after_expiry_window_seconds" =~ ^[0-9]+$ ]] || die "--refund-after-expiry-window-seconds must be numeric"
  (( refund_after_expiry_window_seconds > 0 )) || die "--refund-after-expiry-window-seconds must be > 0"
  case "$relayer_runtime_mode" in
    distributed) ;;
    runner)
      die "--relayer-runtime-mode=runner is forbidden in live e2e (runner is orchestration-only)"
      ;;
    *) die "--relayer-runtime-mode must be runner or distributed" ;;
  esac
  [[ -z "$bridge_deposit_checkpoint_height" || "$bridge_deposit_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-deposit-checkpoint-height must be numeric"
  [[ -z "$bridge_withdraw_checkpoint_height" || "$bridge_withdraw_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-withdraw-checkpoint-height must be numeric"
  if [[ "$sp1_input_mode" != "guest-witness-v1" ]]; then
    die "--sp1-input-mode must be guest-witness-v1"
  fi
  local -a relayer_runtime_operator_hosts=()
  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    [[ -n "$relayer_runtime_operator_hosts_csv" ]] || \
      die "--relayer-runtime-operator-hosts is required when --relayer-runtime-mode=distributed"
    [[ -n "$relayer_runtime_operator_ssh_user" ]] || \
      die "--relayer-runtime-operator-ssh-user is required when --relayer-runtime-mode=distributed"
    [[ -n "$relayer_runtime_operator_ssh_key_file" ]] || \
      die "--relayer-runtime-operator-ssh-key-file is required when --relayer-runtime-mode=distributed"
    [[ -f "$relayer_runtime_operator_ssh_key_file" ]] || \
      die "relayer runtime operator ssh key file not found: $relayer_runtime_operator_ssh_key_file"
    mapfile -t relayer_runtime_operator_hosts < <(parse_csv_list "$relayer_runtime_operator_hosts_csv")
    (( ${#relayer_runtime_operator_hosts[@]} > 0 )) || \
      die "--relayer-runtime-operator-hosts must include at least one host when --relayer-runtime-mode=distributed"
  fi
  if [[ -z "$bridge_run_timeout" ]]; then
    bridge_run_timeout="90m"
  fi

  if [[ -n "$existing_bridge_summary_path" ]]; then
    [[ -f "$existing_bridge_summary_path" ]] || \
      die "existing bridge summary file not found: $existing_bridge_summary_path"
  fi

  case "$stop_after_stage" in
    witness_ready|shared_services_ready|checkpoint_validated|full) ;;
    *) die "--stop-after-stage must be one of: witness_ready, shared_services_ready, checkpoint_validated, full" ;;
  esac

  local require_bridge_proof_inputs="true"
  if [[ -n "$existing_bridge_summary_path" && "$stop_after_stage" != "full" ]]; then
    require_bridge_proof_inputs="false"
    log "skipping bridge proof/deploy input validation for stop-after-stage=$stop_after_stage with existing bridge summary path=$existing_bridge_summary_path"
  fi

  [[ -n "$sp1_requestor_key_file" ]] || die "--sp1-requestor-key-file is required"
  [[ -f "$sp1_requestor_key_file" ]] || die "sp1 requestor key file not found: $sp1_requestor_key_file"
  [[ -n "$sp1_input_s3_prefix" ]] || die "--sp1-input-s3-prefix must not be empty"
  [[ -n "$sp1_input_s3_presign_ttl" ]] || die "--sp1-input-s3-presign-ttl must not be empty"
  if [[ "$require_bridge_proof_inputs" == "true" ]]; then
    [[ -n "$sp1_deposit_program_url" ]] || die "--sp1-deposit-program-url is required"
    [[ -n "$sp1_withdraw_program_url" ]] || die "--sp1-withdraw-program-url is required"
    [[ -n "$bridge_verifier_address" ]] || die "--bridge-verifier-address is required"
    [[ -n "$bridge_deposit_image_id" ]] || die "--bridge-deposit-image-id is required"
    [[ -n "$bridge_withdraw_image_id" ]] || die "--bridge-withdraw-image-id is required"
  fi
  local sp1_rpc_url_lc
  sp1_rpc_url_lc="$(lower "$sp1_rpc_url")"
  if [[ "$sp1_rpc_url_lc" == *"mainnet.base.org"* || "$sp1_rpc_url_lc" == *"base-sepolia"* ]]; then
    die "--sp1-rpc-url must be a Succinct prover network RPC (for example https://rpc.mainnet.succinct.xyz), not Base chain RPC: $sp1_rpc_url"
  fi
  local guest_witness_extract_mode="true"
  [[ -n "$sp1_input_s3_bucket" ]] || die "--sp1-input-s3-bucket is required when --sp1-input-mode guest-witness-v1"
  if [[ -z "$withdraw_blob_bucket" ]]; then
    withdraw_blob_bucket="$sp1_input_s3_bucket"
  fi
  [[ -n "$withdraw_blob_bucket" ]] || die "--withdraw-blob-bucket must not be empty"
  [[ -n "$withdraw_blob_prefix" ]] || die "--withdraw-blob-prefix must not be empty"
  [[ -n "$sp1_deposit_owallet_ivk_hex" ]] || die "--sp1-deposit-owallet-ivk-hex is required when --sp1-input-mode guest-witness-v1"
  [[ -n "$sp1_withdraw_owallet_ovk_hex" ]] || die "--sp1-withdraw-owallet-ovk-hex is required when --sp1-input-mode guest-witness-v1"
  [[ "$sp1_witness_metadata_timeout_seconds" =~ ^[0-9]+$ ]] || die "--sp1-witness-metadata-timeout-seconds must be numeric"
  (( sp1_witness_metadata_timeout_seconds > 0 )) || die "--sp1-witness-metadata-timeout-seconds must be > 0"
  [[ "$sp1_witness_quorum_threshold" =~ ^[0-9]+$ ]] || die "--sp1-witness-quorum-threshold must be numeric"
  (( sp1_witness_quorum_threshold > 0 )) || die "--sp1-witness-quorum-threshold must be > 0"
  if [[ -z "$sp1_witness_juno_scan_urls_csv" ]]; then
    sp1_witness_juno_scan_urls_csv="$sp1_witness_juno_scan_url"
  fi
  if [[ -z "$sp1_witness_juno_rpc_urls_csv" ]]; then
    sp1_witness_juno_rpc_urls_csv="$sp1_witness_juno_rpc_url"
  fi
  [[ -n "$sp1_witness_juno_scan_urls_csv" ]] || die "one of --sp1-witness-juno-scan-url or --sp1-witness-juno-scan-urls is required when guest witness extraction is enabled"
  [[ -n "$sp1_witness_juno_rpc_urls_csv" ]] || die "one of --sp1-witness-juno-rpc-url or --sp1-witness-juno-rpc-urls is required when guest witness extraction is enabled"
  if [[ -z "$sp1_witness_juno_scan_url" ]]; then
    sp1_witness_juno_scan_url="$(trim "${sp1_witness_juno_scan_urls_csv%%,*}")"
  fi
  if [[ -z "$sp1_witness_juno_rpc_url" ]]; then
    sp1_witness_juno_rpc_url="$(trim "${sp1_witness_juno_rpc_urls_csv%%,*}")"
  fi
  [[ -n "$sp1_witness_juno_scan_url" ]] || die "failed to resolve witness juno-scan URL from configured endpoint pool"
  [[ -n "$sp1_witness_juno_rpc_url" ]] || die "failed to resolve witness junocashd RPC URL from configured endpoint pool"
  if [[ -z "$sp1_witness_recipient_ua" || -z "$sp1_witness_recipient_ufvk" ]]; then
    die "--sp1-witness-recipient-ua and --sp1-witness-recipient-ufvk are required for guest witness extraction mode"
  fi
  if [[ -z "${JUNO_FUNDER_PRIVATE_KEY_HEX:-}" && -z "${JUNO_FUNDER_SEED_PHRASE:-}" && -z "${JUNO_FUNDER_SOURCE_ADDRESS:-}" ]]; then
    die "one of JUNO_FUNDER_PRIVATE_KEY_HEX, JUNO_FUNDER_SEED_PHRASE, or JUNO_FUNDER_SOURCE_ADDRESS is required for run-generated witness metadata"
  fi
  if [[ "${WITHDRAW_COORDINATOR_RUNTIME_MODE:-full}" != "full" ]]; then
    die "WITHDRAW_COORDINATOR_RUNTIME_MODE must be full; mock runtime is forbidden"
  fi
  if [[ -n "$bridge_deposit_final_orchard_root" || -n "$bridge_withdraw_final_orchard_root" || -n "$bridge_deposit_checkpoint_height" || -n "$bridge_deposit_checkpoint_block_hash" || -n "$bridge_withdraw_checkpoint_height" || -n "$bridge_withdraw_checkpoint_block_hash" ]]; then
    die "manual bridge checkpoint/orchard root overrides are not supported when --sp1-input-mode guest-witness-v1"
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
  [[ -n "$shared_ipfs_api_url" ]] || die "--shared-ipfs-api-url is required (operator checkpoint package pin/fetch verification)"
  [[ -n "$shared_topic_prefix" ]] || die "--shared-topic-prefix must not be empty"
  command -v psql >/dev/null 2>&1 || die "psql is required for live withdrawal payout-state checks (install postgresql client)"
  [[ -n "$shared_ecs_cluster_arn" ]] || die "--shared-ecs-cluster-arn is required (shared services own all SP1 request/auction/balance/fulfillment logic)"
  [[ -n "$shared_proof_requestor_service_name" ]] || die "--shared-proof-requestor-service-name is required (shared services own all SP1 request/auction/balance/fulfillment logic)"
  [[ -n "$shared_proof_funder_service_name" ]] || die "--shared-proof-funder-service-name is required (shared services own all SP1 request/auction/balance/fulfillment logic)"
  local shared_ecs_enabled="true"
  local shared_enabled="true"

  ensure_base_dependencies
  ensure_command go
  ensure_command openssl
  ensure_command cast
  ensure_command aws

  local bridge_recipient_address=""
  local sp1_requestor_key_hex
  sp1_requestor_key_hex="$(trimmed_file_value "$sp1_requestor_key_file")"
  [[ -n "$sp1_requestor_key_hex" ]] || die "sp1 requestor key file is empty: $sp1_requestor_key_file"
  local sp1_requestor_address
  sp1_requestor_address="$(cast wallet address --private-key "$sp1_requestor_key_hex" 2>/dev/null || true)"
  [[ -n "$sp1_requestor_address" ]] || die "failed to derive sp1 requestor address from key file: $sp1_requestor_key_file"
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
  acquire_workdir_run_lock "$workdir"

  local proof_topic_seed
  proof_topic_seed="$(date +%s)-$RANDOM"
  local proof_request_topic="${shared_topic_prefix}.proof.requests.${proof_topic_seed}"
  local proof_result_topic="${shared_topic_prefix}.proof.fulfillments.${proof_topic_seed}"
  local proof_failure_topic="${shared_topic_prefix}.proof.failures.${proof_topic_seed}"
  local proof_requestor_group="${shared_topic_prefix}.proof-requestor.${proof_topic_seed}"
  local proof_bridge_consumer_group="${shared_topic_prefix}.bridge-e2e.${proof_topic_seed}"
  local checkpoint_signature_topic="checkpoints.signatures.v1"
  local checkpoint_package_topic="checkpoints.packages.v1"
  local deposit_event_topic="${shared_topic_prefix}.deposits.events.${proof_topic_seed}"
  local withdraw_request_topic="${shared_topic_prefix}.withdrawals.requested.${proof_topic_seed}"
  local deposit_relayer_group="${shared_topic_prefix}.deposit-relayer.${proof_topic_seed}"
  local deposit_relayer_proof_group="${shared_topic_prefix}.deposit-relayer.proof.${proof_topic_seed}"
  local withdraw_coordinator_group="${shared_topic_prefix}.withdraw-coordinator.${proof_topic_seed}"
  local withdraw_finalizer_group="${shared_topic_prefix}.withdraw-finalizer.${proof_topic_seed}"
  local withdraw_finalizer_proof_group="${shared_topic_prefix}.withdraw-finalizer.proof.${proof_topic_seed}"
  ensure_command python3
  local -a sp1_credit_guardrail=()
  mapfile -t sp1_credit_guardrail < <(
    compute_sp1_credit_guardrail_wei \
      "$sp1_max_price_per_pgu" \
      "$sp1_deposit_pgu_estimate" \
      "$sp1_withdraw_pgu_estimate" \
      "$sp1_groth16_base_fee_wei"
  )
  (( ${#sp1_credit_guardrail[@]} == 3 )) || die "failed to compute SP1 credit guardrail"
  local sp1_required_credit_buffer_wei="${sp1_credit_guardrail[0]}"
  local sp1_critical_credit_threshold_wei="${sp1_credit_guardrail[1]}"
  local sp1_projected_pair_cost_wei="${sp1_credit_guardrail[2]}"
  log "sp1 credit guardrail projected_pair_cost_wei=$sp1_projected_pair_cost_wei critical_threshold_wei=$sp1_critical_credit_threshold_wei required_buffer_wei=$sp1_required_credit_buffer_wei"

  local dkg_summary="$workdir/reports/dkg-summary.json"
  local bridge_summary="$workdir/reports/base-bridge-summary.json"
  local shared_summary="$shared_output"
  if [[ -n "$existing_bridge_summary_path" ]]; then
    bridge_summary="$existing_bridge_summary_path"
  fi

  local bridge_juno_execution_tx_hash=""
  local proof_services_mode="not-started"
  local proof_requestor_log=""
  local proof_funder_log=""
  local shared_ecs_region=""
  local shared_ecs_started="false"
  local stage_witness_ready="false"
  local stage_shared_services_ready="false"
  local stage_checkpoint_validated="false"
  local stage_full="false"
  local stage_stop_after_stage_reached="false"
  local stage_shared_services_stable="false"
  local stage_checkpoint_bridge_config_update_target="0"
  local stage_checkpoint_bridge_config_update_success="0"
  local stage_checkpoint_shared_validation_passed="false"

  stop_centralized_proof_services() {
    if [[ "$shared_ecs_started" == "true" ]]; then
      scale_shared_proof_services_ecs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name" \
        "0" || true
    fi
  }

  write_stage_checkpoint_summary() {
    local completed_stage="$1"
    local witness_pool_operator_labels_json witness_healthy_operator_labels_json
    local witness_quorum_operator_labels_json witness_failed_operator_labels_json
    witness_pool_operator_labels_json="$(json_array_from_args "${witness_pool_operator_labels[@]}")"
    witness_healthy_operator_labels_json="$(json_array_from_args "${witness_healthy_operator_labels[@]}")"
    witness_quorum_operator_labels_json="$(json_array_from_args "${witness_quorum_operator_labels[@]}")"
    witness_failed_operator_labels_json="$(json_array_from_args "${witness_failed_operator_labels[@]}")"

    jq -n \
      --arg generated_at "$(timestamp_utc)" \
      --arg workdir "$workdir" \
      --arg stop_after_stage "$stop_after_stage" \
      --arg completed_stage "$completed_stage" \
      --arg stage_witness_ready "$stage_witness_ready" \
      --arg stage_shared_services_ready "$stage_shared_services_ready" \
      --arg stage_checkpoint_validated "$stage_checkpoint_validated" \
      --arg stage_full "$stage_full" \
      --arg stage_shared_services_stable "$stage_shared_services_stable" \
      --arg stage_checkpoint_bridge_config_update_target "$stage_checkpoint_bridge_config_update_target" \
      --arg stage_checkpoint_bridge_config_update_success "$stage_checkpoint_bridge_config_update_success" \
      --arg stage_checkpoint_shared_validation_passed "$stage_checkpoint_shared_validation_passed" \
      --arg proof_services_mode "$proof_services_mode" \
      --arg shared_ecs_enabled "$shared_ecs_enabled" \
      --arg shared_summary "$shared_summary" \
      --arg bridge_summary "$bridge_summary" \
      --argjson witness_quorum_threshold "$sp1_witness_quorum_threshold" \
      --argjson witness_quorum_validated_count "$witness_quorum_validated_count" \
      --arg witness_quorum_validated "$witness_quorum_validated" \
      --argjson witness_pool_operator_labels "$witness_pool_operator_labels_json" \
      --argjson witness_healthy_operator_labels "$witness_healthy_operator_labels_json" \
      --argjson witness_quorum_operator_labels "$witness_quorum_operator_labels_json" \
      --argjson witness_failed_operator_labels "$witness_failed_operator_labels_json" \
      '{
        summary_version: 1,
        generated_at: $generated_at,
        workdir: $workdir,
        stage_control: {
          requested_stop_after_stage: $stop_after_stage,
          completed_stage: $completed_stage,
          stopped_early: ($completed_stage != "full"),
          stages: {
            witness_ready: ($stage_witness_ready == "true"),
            shared_services_ready: ($stage_shared_services_ready == "true"),
            checkpoint_validated: ($stage_checkpoint_validated == "true"),
            full: ($stage_full == "true")
          },
          shared_services: {
            mode: (if $proof_services_mode == "not-started" then null else $proof_services_mode end),
            ecs_enabled: ($shared_ecs_enabled == "true"),
            stable: ($stage_shared_services_stable == "true")
          },
          checkpoint_validation: {
            bridge_config_updates_target: ($stage_checkpoint_bridge_config_update_target | tonumber),
            bridge_config_updates_succeeded: ($stage_checkpoint_bridge_config_update_success | tonumber),
            shared_validation_passed: ($stage_checkpoint_shared_validation_passed == "true")
          }
        },
        bridge: {
          summary_path: (if $bridge_summary == "" then null else $bridge_summary end),
          sp1: {
            guest_witness: {
              endpoint_quorum_threshold: $witness_quorum_threshold,
              quorum_validated_count: $witness_quorum_validated_count,
              quorum_validated: ($witness_quorum_validated == "true"),
              pool_operator_labels: $witness_pool_operator_labels,
              healthy_operator_labels: $witness_healthy_operator_labels,
              quorum_operator_labels: $witness_quorum_operator_labels,
              failed_operator_labels: $witness_failed_operator_labels
            }
          }
        },
        shared_infra: {
          summary_path: (if $shared_summary == "" then null else $shared_summary end)
        }
      }' >"$output_path"
  }

  maybe_stop_after_stage() {
    local completed_stage="$1"
    case "$completed_stage" in
      witness_ready)
        stage_witness_ready="true"
        ;;
      shared_services_ready)
        stage_shared_services_ready="true"
        ;;
      checkpoint_validated)
        stage_checkpoint_validated="true"
        ;;
      full)
        stage_full="true"
        ;;
      *)
        die "unsupported stage checkpoint: $completed_stage"
        ;;
    esac
    if [[ "$stop_after_stage" != "$completed_stage" ]]; then
      return 0
    fi
    if [[ "$completed_stage" == "shared_services_ready" || "$completed_stage" == "checkpoint_validated" ]]; then
      stop_centralized_proof_services
    fi
    stage_stop_after_stage_reached="true"
    write_stage_checkpoint_summary "$completed_stage"
    log "stage checkpoint reached; stopping run at stage=$completed_stage summary=$output_path"
    printf '%s\n' "$output_path"
  }

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

  local bridge_operator_signer_supports_operator_endpoint="false"
  local bridge_operator_signer_ready="false"
  ensure_bridge_operator_signer_ready() {
    if [[ "$bridge_operator_signer_ready" == "true" ]]; then
      return 0
    fi
    if [[ -z "$bridge_operator_signer_bin" ]]; then
      local ensured_bridge_operator_signer_bin
      ensured_bridge_operator_signer_bin="$(ensure_juno_txsign_binary "$JUNO_TXSIGN_VERSION_DEFAULT" "$workdir/bin")"
      export PATH="$(dirname "$ensured_bridge_operator_signer_bin"):$PATH"
      bridge_operator_signer_bin="juno-txsign"
    fi
    if [[ "$bridge_operator_signer_bin" == */* ]]; then
      [[ -x "$bridge_operator_signer_bin" ]] || die "bridge operator signer binary is not executable: $bridge_operator_signer_bin"
    else
      command -v "$bridge_operator_signer_bin" >/dev/null 2>&1 || die "bridge operator signer binary not found in PATH: $bridge_operator_signer_bin"
    fi
    if ! supports_sign_digest_subcommand "$bridge_operator_signer_bin"; then
      die "bridge operator signer binary must support sign-digest: $bridge_operator_signer_bin"
    fi
    if supports_operator_endpoint_flag "$bridge_operator_signer_bin"; then
      bridge_operator_signer_supports_operator_endpoint="true"
    else
      bridge_operator_signer_supports_operator_endpoint="false"
      log "bridge operator signer does not support --operator-endpoint; using local key material mode"
    fi
    bridge_operator_signer_ready="true"
  }

  local checkpoint_operators_csv
  checkpoint_operators_csv="$(jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary")"
  [[ -n "$checkpoint_operators_csv" ]] || die "failed to derive checkpoint operators from dkg summary"

  local base_key
  base_key="$(trimmed_file_value "$base_funder_key_file")"

  local bridge_deployer_address
  local bridge_deployer_required_wei="0"
  bridge_deployer_address="$(jq -r '.operators[0].operator_id // empty' "$dkg_summary")"
  [[ -n "$bridge_deployer_address" ]] || die "dkg summary missing operators[0].operator_id"
  bridge_recipient_address="$bridge_deployer_address"

  if (( base_operator_fund_wei > 0 )); then
    ensure_command cast
    local prefund_funding_sender_address
    local prefund_operator_count
    prefund_funding_sender_address="$(cast wallet address --private-key "$base_key")"
    [[ -n "$prefund_funding_sender_address" ]] || die "failed to derive funding sender address"

    prefund_operator_count="$(jq -r '.operators | length' "$dkg_summary")"
    [[ "$prefund_operator_count" =~ ^[0-9]+$ ]] || \
      die "dkg summary operators length is invalid: $prefund_operator_count"
    (( prefund_operator_count >= 1 )) || die "dkg summary operators length must be >= 1"

    bridge_deployer_required_wei=$((base_operator_fund_wei * 10))
    # Bridge deployment retries can require a high fee cap on Base testnet; keep
    # a hard floor so replacement transactions do not fail with insufficient funds.
    local bridge_deployer_min_wei="70000000000000000"
    if (( bridge_deployer_required_wei < bridge_deployer_min_wei )); then
      bridge_deployer_required_wei="$bridge_deployer_min_wei"
    fi

    assert_prefund_sender_budget \
      "$base_rpc_url" \
      "$prefund_funding_sender_address" \
      "$prefund_operator_count" \
      "$base_operator_fund_wei" \
      "$bridge_deployer_required_wei"
  fi

  local witness_endpoint_pool_size=0
  local witness_endpoint_healthy_count=0
  local witness_quorum_validated_count=0
  local witness_quorum_validated="false"
  local witness_metadata_source_operator=""
  local witness_funder_source_address=""
  local withdraw_coordinator_juno_wallet_id=""
  local withdraw_coordinator_juno_change_address=""
  local -a witness_pool_operator_labels=()
  local -a witness_healthy_operator_labels=()
  local -a witness_quorum_operator_labels=()
  local -a witness_failed_operator_labels=()

  if [[ "$sp1_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    ensure_dir "$workdir/reports/witness"
    local witness_metadata_json witness_wallet_id
    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    witness_wallet_id="$sp1_witness_wallet_id"
    if [[ -z "$witness_wallet_id" ]]; then
      witness_wallet_id="testnet-e2e-${proof_topic_seed}"
    fi

    local juno_rpc_user_var juno_rpc_pass_var juno_scan_bearer_token_var
    local juno_rpc_user juno_rpc_pass juno_scan_bearer_token
    juno_rpc_user_var="$sp1_witness_juno_rpc_user_env"
    juno_rpc_pass_var="$sp1_witness_juno_rpc_pass_env"
    juno_scan_bearer_token_var="$sp1_witness_juno_scan_bearer_token_env"
    juno_rpc_user="${!juno_rpc_user_var:-}"
    juno_rpc_pass="${!juno_rpc_pass_var:-}"
    juno_scan_bearer_token="${!juno_scan_bearer_token_var:-}"
    [[ -n "$juno_rpc_user" ]] || die "missing Juno RPC user env var: $juno_rpc_user_var"
    [[ -n "$juno_rpc_pass" ]] || die "missing Juno RPC pass env var: $juno_rpc_pass_var"

    ensure_command cast
    local predicted_witness_bridge_nonce predicted_witness_bridge_address
    local predicted_witness_recipient_raw_address_hex
    local predicted_witness_withdrawal_id predicted_witness_withdraw_batch_id
    predicted_witness_bridge_nonce="$(cast nonce --rpc-url "$base_rpc_url" "$bridge_deployer_address" 2>/dev/null || true)"
    predicted_witness_bridge_nonce="$(trim "$predicted_witness_bridge_nonce")"
    [[ "$predicted_witness_bridge_nonce" =~ ^[0-9]+$ ]] || \
      die "failed to query bridge deployer nonce for witness planning: deployer=$bridge_deployer_address nonce=$predicted_witness_bridge_nonce"
    predicted_witness_bridge_address="$(predict_bridge_address_for_start_nonce "$bridge_deployer_address" "$predicted_witness_bridge_nonce" || true)"
    [[ "$predicted_witness_bridge_address" =~ ^0x[0-9a-f]{40}$ ]] || \
      die "failed to predict bridge deployment address for witness planning"
    predicted_witness_recipient_raw_address_hex="$(
      cd "$REPO_ROOT"
      deploy/operators/dkg/e2e/generate-juno-witness-metadata.sh decode-orchard-raw --address "$sp1_witness_recipient_ua"
    )"
    predicted_witness_recipient_raw_address_hex="$(trim "$predicted_witness_recipient_raw_address_hex")"
    [[ "$predicted_witness_recipient_raw_address_hex" =~ ^[0-9a-fA-F]{86}$ ]] || \
      die "failed to decode recipient raw address for witness memo planning: ua=$sp1_witness_recipient_ua"
    predicted_witness_withdrawal_id="$(
      "$SCRIPT_DIR/compute-bridge-withdrawal-id.sh" run \
        --base-chain-id "$base_chain_id" \
        --bridge-address "$predicted_witness_bridge_address" \
        --requester-address "$bridge_deployer_address" \
        --recipient-raw-address-hex "0x$predicted_witness_recipient_raw_address_hex" \
        --amount-zat "10000" \
        --withdraw-nonce "1"
    )"
    predicted_witness_withdrawal_id="$(normalize_hex_prefixed "$predicted_witness_withdrawal_id" || true)"
    [[ "$predicted_witness_withdrawal_id" =~ ^0x[0-9a-f]{64}$ ]] || \
      die "failed to compute predicted withdrawal id for witness memo planning"
    predicted_witness_withdraw_batch_id="$(compute_single_withdraw_batch_id "$predicted_witness_withdrawal_id" || true)"
    [[ "$predicted_witness_withdraw_batch_id" =~ ^0x[0-9a-f]{64}$ ]] || \
      die "failed to compute predicted withdraw batch id for witness memo planning"

    local witness_quorum_threshold
    witness_quorum_threshold="$sp1_witness_quorum_threshold"

    local -a witness_scan_urls_raw=()
    local -a witness_rpc_urls_raw=()
    local -a witness_operator_labels_raw=()
    local -a witness_scan_urls=()
    local -a witness_rpc_urls=()
    local -a witness_operator_labels=()
    local witness_entry

    IFS=',' read -r -a witness_scan_urls_raw <<<"$sp1_witness_juno_scan_urls_csv"
    for witness_entry in "${witness_scan_urls_raw[@]}"; do
      witness_entry="$(trim "$witness_entry")"
      [[ -n "$witness_entry" ]] || continue
      witness_scan_urls+=("$witness_entry")
    done

    IFS=',' read -r -a witness_rpc_urls_raw <<<"$sp1_witness_juno_rpc_urls_csv"
    for witness_entry in "${witness_rpc_urls_raw[@]}"; do
      witness_entry="$(trim "$witness_entry")"
      [[ -n "$witness_entry" ]] || continue
      witness_rpc_urls+=("$witness_entry")
    done

    (( ${#witness_scan_urls[@]} > 0 )) || die "witness endpoint pool is empty: --sp1-witness-juno-scan-urls"
    (( ${#witness_scan_urls[@]} == ${#witness_rpc_urls[@]} )) || \
      die "witness endpoint pool mismatch: scan_urls=${#witness_scan_urls[@]} rpc_urls=${#witness_rpc_urls[@]}"

    if [[ -n "$sp1_witness_operator_labels_csv" ]]; then
      IFS=',' read -r -a witness_operator_labels_raw <<<"$sp1_witness_operator_labels_csv"
      for witness_entry in "${witness_operator_labels_raw[@]}"; do
        witness_entry="$(trim "$witness_entry")"
        [[ -n "$witness_entry" ]] || continue
        witness_operator_labels+=("$witness_entry")
      done
      (( ${#witness_operator_labels[@]} == ${#witness_scan_urls[@]} )) || \
        die "witness operator labels count mismatch: labels=${#witness_operator_labels[@]} endpoints=${#witness_scan_urls[@]}"
    else
      local witness_idx
      for ((witness_idx = 0; witness_idx < ${#witness_scan_urls[@]}; witness_idx++)); do
        witness_operator_labels+=("witness-op$((witness_idx + 1))")
      done
    fi

    witness_endpoint_pool_size="${#witness_scan_urls[@]}"
    witness_pool_operator_labels=("${witness_operator_labels[@]}")
    (( witness_endpoint_pool_size >= witness_quorum_threshold )) || \
      die "configured witness endpoint pool is below quorum threshold: configured=$witness_endpoint_pool_size threshold=$witness_quorum_threshold"

    local -a witness_healthy_scan_urls=()
    local -a witness_healthy_rpc_urls=()
    local -a witness_healthy_labels=()
    local -a witness_endpoint_is_healthy=()
    local witness_health_retry_timeout_seconds=120
    local witness_health_retry_interval_seconds=3
    local witness_idx
    for ((witness_idx = 0; witness_idx < witness_endpoint_pool_size; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      witness_scan_url="${witness_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_operator_labels[$witness_idx]}"
      if witness_pair_healthcheck "$witness_scan_url" "$witness_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$juno_scan_bearer_token"; then
        witness_endpoint_is_healthy[$witness_idx]="1"
        witness_healthy_scan_urls+=("$witness_scan_url")
        witness_healthy_rpc_urls+=("$witness_rpc_url")
        witness_healthy_labels+=("$witness_operator_label")
        log "witness endpoint healthy operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
      else
        witness_endpoint_is_healthy[$witness_idx]="0"
        log "witness endpoint unhealthy operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
      fi
    done

    witness_endpoint_healthy_count="${#witness_healthy_scan_urls[@]}"
    witness_healthy_operator_labels=("${witness_healthy_labels[@]}")
    if (( witness_endpoint_healthy_count < witness_quorum_threshold )); then
      local witness_health_retry_deadline_epoch witness_now_epoch
      witness_health_retry_deadline_epoch=$(( $(date +%s) + witness_health_retry_timeout_seconds ))
      log "witness endpoint quorum not met on first pass; retrying endpoint health checks for up to ${witness_health_retry_timeout_seconds}s (healthy=$witness_endpoint_healthy_count threshold=$witness_quorum_threshold)"
      while (( witness_endpoint_healthy_count < witness_quorum_threshold )); do
        witness_now_epoch="$(date +%s)"
        (( witness_now_epoch < witness_health_retry_deadline_epoch )) || break
        sleep "$witness_health_retry_interval_seconds"
        for ((witness_idx = 0; witness_idx < witness_endpoint_pool_size; witness_idx++)); do
          [[ "${witness_endpoint_is_healthy[$witness_idx]:-0}" == "1" ]] && continue
          local witness_scan_url witness_rpc_url witness_operator_label
          witness_scan_url="${witness_scan_urls[$witness_idx]}"
          witness_rpc_url="${witness_rpc_urls[$witness_idx]}"
          witness_operator_label="${witness_operator_labels[$witness_idx]}"
          if witness_pair_healthcheck "$witness_scan_url" "$witness_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$juno_scan_bearer_token"; then
            witness_endpoint_is_healthy[$witness_idx]="1"
            witness_healthy_scan_urls+=("$witness_scan_url")
            witness_healthy_rpc_urls+=("$witness_rpc_url")
            witness_healthy_labels+=("$witness_operator_label")
            log "witness endpoint became healthy during retry operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
          fi
        done
        witness_endpoint_healthy_count="${#witness_healthy_scan_urls[@]}"
        witness_healthy_operator_labels=("${witness_healthy_labels[@]}")
      done
    fi
    (( witness_endpoint_healthy_count >= witness_quorum_threshold )) || \
      die "failed to build healthy witness endpoint pool with quorum after retry window=${witness_health_retry_timeout_seconds}s: healthy=$witness_endpoint_healthy_count threshold=$witness_quorum_threshold configured=$witness_endpoint_pool_size"

    local witness_timeout_slice_seconds
    witness_timeout_slice_seconds="$sp1_witness_metadata_timeout_seconds"
    if (( witness_endpoint_healthy_count > 1 )); then
      witness_timeout_slice_seconds=$((sp1_witness_metadata_timeout_seconds / witness_endpoint_healthy_count))
    fi
    (( witness_timeout_slice_seconds >= 300 )) || witness_timeout_slice_seconds=300
    if (( witness_timeout_slice_seconds > sp1_witness_metadata_timeout_seconds )); then
      witness_timeout_slice_seconds="$sp1_witness_metadata_timeout_seconds"
    fi
    log "witness timeout slice seconds=$witness_timeout_slice_seconds total_timeout_seconds=$sp1_witness_metadata_timeout_seconds healthy_endpoints=$witness_endpoint_healthy_count"

    local witness_metadata_attempt_timeout_seconds
    witness_metadata_attempt_timeout_seconds=$((witness_timeout_slice_seconds + 90))

    local witness_metadata_generated="false"
    local witness_metadata_source_scan_url=""
    local witness_metadata_source_rpc_url=""
    local witness_metadata_pre_upsert_scan_urls_csv=""
    witness_metadata_pre_upsert_scan_urls_csv="$(IFS=,; printf '%s' "${witness_healthy_scan_urls[*]}")"
    for ((witness_idx = 0; witness_idx < witness_endpoint_healthy_count; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      local witness_operator_safe_label witness_wallet_id_attempt witness_metadata_attempt_json
      witness_scan_url="${witness_healthy_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_healthy_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_idx]}"
      witness_operator_safe_label="$(printf '%s' "$witness_operator_label" | tr -cs '[:alnum:]_-' '_')"
      witness_operator_safe_label="${witness_operator_safe_label#_}"
      witness_operator_safe_label="${witness_operator_safe_label%_}"
      [[ -n "$witness_operator_safe_label" ]] || witness_operator_safe_label="op$((witness_idx + 1))"
      witness_metadata_attempt_json="$workdir/reports/witness/generated-witness-metadata-${witness_operator_safe_label}.json"
      # Keep a single wallet id across failover attempts for the same UFVK.
      # Some scan backends index UFVK notes against the first wallet id only.
      witness_wallet_id_attempt="$witness_wallet_id"

      local -a witness_metadata_args=(
        run
        --juno-rpc-url "$witness_rpc_url"
        --juno-rpc-user "$juno_rpc_user"
        --juno-rpc-pass "$juno_rpc_pass"
        --juno-scan-url "$witness_scan_url"
        --pre-upsert-scan-urls "$witness_metadata_pre_upsert_scan_urls_csv"
        --wallet-id "$witness_wallet_id_attempt"
        --recipient-ua "$sp1_witness_recipient_ua"
        --recipient-ufvk "$sp1_witness_recipient_ufvk"
        --base-chain-id "$base_chain_id"
        --bridge-address "$predicted_witness_bridge_address"
        --base-recipient-address "$bridge_recipient_address"
        --withdrawal-id-hex "$predicted_witness_withdrawal_id"
        --withdraw-batch-id-hex "$predicted_witness_withdraw_batch_id"
        --skip-action-index-lookup
        --deposit-amount-zat "100000"
        --withdraw-amount-zat "10000"
        --timeout-seconds "$witness_timeout_slice_seconds"
        --output "$witness_metadata_attempt_json"
      )
      if [[ -n "${JUNO_FUNDER_SOURCE_ADDRESS:-}" ]]; then
        witness_metadata_args+=("--funder-source-address" "${JUNO_FUNDER_SOURCE_ADDRESS}")
      elif [[ -n "${JUNO_FUNDER_SEED_PHRASE:-}" ]]; then
        witness_metadata_args+=("--funder-seed-phrase" "${JUNO_FUNDER_SEED_PHRASE}")
      else
        witness_metadata_args+=("--funder-private-key-hex" "${JUNO_FUNDER_PRIVATE_KEY_HEX}")
      fi
      if [[ -n "$juno_scan_bearer_token" ]]; then
        witness_metadata_args+=("--juno-scan-bearer-token" "$juno_scan_bearer_token")
      fi

      local witness_metadata_status=0
      set +e
      (
        cd "$REPO_ROOT"
        run_with_optional_timeout "$witness_metadata_attempt_timeout_seconds" \
          deploy/operators/dkg/e2e/generate-juno-witness-metadata.sh "${witness_metadata_args[@]}" >/dev/null
      )
      witness_metadata_status=$?
      set -e
      if (( witness_metadata_status == 0 )); then
        cp "$witness_metadata_attempt_json" "$witness_metadata_json"
        witness_metadata_source_scan_url="$witness_scan_url"
        witness_metadata_source_rpc_url="$witness_rpc_url"
        witness_metadata_source_operator="$witness_operator_label"
        witness_metadata_generated="true"
        log "generated witness metadata from operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
        break
      fi
      if (( witness_metadata_status == 124 )); then
        log "witness metadata generation timed out for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url timeout_seconds=$witness_metadata_attempt_timeout_seconds; trying next healthy endpoint"
      else
        log "witness metadata generation failed for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url; trying next healthy endpoint"
      fi
    done

    [[ "$witness_metadata_generated" == "true" ]] || \
      die "failed to generate witness metadata from healthy witness endpoint pool"
    sp1_witness_juno_scan_url="$witness_metadata_source_scan_url"
    sp1_witness_juno_rpc_url="$witness_metadata_source_rpc_url"

    local generated_wallet_id generated_recipient_ua generated_deposit_txid generated_deposit_action_index
    local generated_recipient_raw_address_hex generated_ufvk generated_funder_source_address
    generated_wallet_id="$(jq -r '.wallet_id // empty' "$witness_metadata_json")"
    generated_recipient_ua="$(jq -r '.recipient_ua // empty' "$witness_metadata_json")"
    generated_deposit_txid="$(jq -r '.deposit_txid // empty' "$witness_metadata_json")"
    generated_deposit_action_index="$(jq -r '.deposit_action_index // empty' "$witness_metadata_json")"
    generated_recipient_raw_address_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json")"
    generated_ufvk="$(jq -r '.ufvk // empty' "$witness_metadata_json")"
    generated_funder_source_address="$(jq -r '.funder_source_address // empty' "$witness_metadata_json")"

    [[ -n "$generated_wallet_id" ]] || die "generated witness metadata missing wallet_id: $witness_metadata_json"
    [[ -n "$generated_recipient_ua" ]] || die "generated witness metadata missing recipient_ua: $witness_metadata_json"
    [[ -n "$generated_deposit_txid" ]] || die "generated witness metadata missing deposit_txid: $witness_metadata_json"
    if [[ ! "$generated_deposit_action_index" =~ ^[0-9]+$ ]]; then
      generated_deposit_action_index="0"
    fi
    [[ "$generated_recipient_raw_address_hex" =~ ^[0-9a-fA-F]{86}$ ]] || \
      die "generated witness metadata recipient_raw_address_hex must be 43 bytes hex: $generated_recipient_raw_address_hex"
    [[ -n "$generated_ufvk" ]] || die "generated witness metadata missing ufvk: $witness_metadata_json"
    [[ -n "$generated_funder_source_address" ]] || \
      die "generated witness metadata missing funder_source_address: $witness_metadata_json"
    [[ "$(lower "$generated_recipient_ua")" == "$(lower "$sp1_witness_recipient_ua")" ]] || \
      die "generated witness metadata recipient_ua mismatch: generated=$generated_recipient_ua expected=$sp1_witness_recipient_ua"
    [[ "$(lower "$generated_ufvk")" == "$(lower "$sp1_witness_recipient_ufvk")" ]] || \
      die "generated witness metadata ufvk mismatch against distributed DKG value"

    local indexed_wallet_id
    indexed_wallet_id="$(
      witness_scan_find_wallet_for_txid \
        "$sp1_witness_juno_scan_url" \
        "$juno_scan_bearer_token" \
        "$generated_deposit_txid" \
        "$generated_wallet_id" || true
    )"
    if [[ -n "$indexed_wallet_id" && "$indexed_wallet_id" != "$generated_wallet_id" ]]; then
      log "reusing indexed witness wallet id for tx visibility generated_wallet_id=$generated_wallet_id indexed_wallet_id=$indexed_wallet_id txid=$generated_deposit_txid"
      generated_wallet_id="$indexed_wallet_id"
    fi
    witness_funder_source_address="$generated_funder_source_address"
    withdraw_coordinator_juno_wallet_id="$generated_wallet_id"
    withdraw_coordinator_juno_change_address="$generated_recipient_ua"

    local -a generated_deposit_action_indexes=()
    local -a generated_deposit_action_indexes_rpc=()
    local deposit_action_candidate
    generated_deposit_action_indexes+=("$generated_deposit_action_index")
    mapfile -t generated_deposit_action_indexes_rpc < <(
      witness_rpc_action_index_candidates \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$generated_deposit_txid" || true
    )
    for deposit_action_candidate in "${generated_deposit_action_indexes_rpc[@]}"; do
      [[ "$deposit_action_candidate" =~ ^[0-9]+$ ]] || continue
      local known_candidate="false"
      local existing_candidate
      for existing_candidate in "${generated_deposit_action_indexes[@]}"; do
        if [[ "$existing_candidate" == "$deposit_action_candidate" ]]; then
          known_candidate="true"
          break
        fi
      done
      if [[ "$known_candidate" != "true" ]]; then
        generated_deposit_action_indexes+=("$deposit_action_candidate")
      fi
    done
    for deposit_action_candidate in 0 1 2 3; do
      local known_candidate="false"
      local existing_candidate
      for existing_candidate in "${generated_deposit_action_indexes[@]}"; do
        if [[ "$existing_candidate" == "$deposit_action_candidate" ]]; then
          known_candidate="true"
          break
        fi
      done
      if [[ "$known_candidate" != "true" ]]; then
        generated_deposit_action_indexes+=("$deposit_action_candidate")
      fi
    done
    if (( ${#generated_deposit_action_indexes[@]} == 0 )); then
      generated_deposit_action_indexes=(0 1 2 3)
    fi
    log "using action-index candidates for deposit extraction: $(IFS=,; printf '%s' "${generated_deposit_action_indexes[*]}")"

    local deposit_witness_auto_file="$workdir/reports/witness/deposit.witness.bin"
    local deposit_witness_auto_json="$workdir/reports/witness/deposit-witness.json"

    local witness_upsert_idx
    for ((witness_upsert_idx = 0; witness_upsert_idx < witness_endpoint_healthy_count; witness_upsert_idx++)); do
      local witness_scan_url witness_operator_label
      witness_scan_url="${witness_healthy_scan_urls[$witness_upsert_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_upsert_idx]}"
      if ! witness_scan_upsert_wallet "$witness_scan_url" "$juno_scan_bearer_token" "$generated_wallet_id" "$generated_ufvk"; then
        log "witness wallet upsert failed for operator=$witness_operator_label scan_url=$witness_scan_url (continuing; extraction will determine usable quorum)"
      fi
    done

    local generated_deposit_tx_height witness_backfill_from_height
    generated_deposit_tx_height="$(
      witness_rpc_tx_height \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$generated_deposit_txid" || true
    )"
    witness_backfill_from_height=""
    if [[ "$generated_deposit_tx_height" =~ ^[0-9]+$ ]]; then
      witness_backfill_from_height="$generated_deposit_tx_height"
      if (( witness_backfill_from_height > 32 )); then
        witness_backfill_from_height=$((witness_backfill_from_height - 32))
      else
        witness_backfill_from_height=0
      fi
      for ((witness_upsert_idx = 0; witness_upsert_idx < witness_endpoint_healthy_count; witness_upsert_idx++)); do
        local witness_scan_url witness_operator_label
        witness_scan_url="${witness_healthy_scan_urls[$witness_upsert_idx]}"
        witness_operator_label="${witness_healthy_labels[$witness_upsert_idx]}"
        if ! witness_scan_backfill_wallet "$witness_scan_url" "$juno_scan_bearer_token" "$generated_wallet_id" "$witness_backfill_from_height"; then
          log "witness backfill best-effort failed for operator=$witness_operator_label scan_url=$witness_scan_url wallet=$generated_wallet_id from_height=$witness_backfill_from_height"
        fi
      done
    else
      log "witness backfill tx height unknown; skipping proactive backfill txid=$generated_deposit_txid"
    fi

    local witness_quorum_dir
    witness_quorum_dir="$workdir/reports/witness/quorum"
    ensure_dir "$witness_quorum_dir"
    rm -f "$witness_quorum_dir"/deposit-*.json "$witness_quorum_dir"/deposit-*.witness.bin "$witness_quorum_dir"/deposit-*.extract.err || true
    local -a witness_success_labels=()
    local -a witness_success_fingerprints=()
    local -a witness_success_anchor_fingerprints=()
    local -a witness_success_deposit_json=()
    local -a witness_success_deposit_witness=()

    for ((witness_idx = 0; witness_idx < witness_endpoint_healthy_count; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      local witness_operator_safe_label deposit_candidate_witness
      local deposit_candidate_json
      local witness_extract_attempt witness_extract_ok
      local witness_extract_deadline_epoch witness_extract_error_file witness_extract_last_error
      local witness_extract_wait_logged witness_extract_sleep_seconds
      local witness_selected_action_index
      witness_scan_url="${witness_healthy_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_healthy_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_idx]}"
      witness_operator_safe_label="$(printf '%s' "$witness_operator_label" | tr -cs '[:alnum:]_-' '_')"
      witness_operator_safe_label="${witness_operator_safe_label#_}"
      witness_operator_safe_label="${witness_operator_safe_label%_}"
      [[ -n "$witness_operator_safe_label" ]] || witness_operator_safe_label="op$((witness_idx + 1))"

      deposit_candidate_witness="$witness_quorum_dir/deposit-${witness_operator_safe_label}.witness.bin"
      deposit_candidate_json="$witness_quorum_dir/deposit-${witness_operator_safe_label}.json"

      witness_extract_ok="false"
      witness_extract_last_error=""
      witness_extract_wait_logged="false"
      witness_extract_sleep_seconds=5
      witness_extract_deadline_epoch=$(( $(date +%s) + witness_timeout_slice_seconds ))
      witness_extract_error_file="$witness_quorum_dir/deposit-${witness_operator_safe_label}.extract.err"
      witness_selected_action_index=""

      witness_extract_attempt=0
      while true; do
        local witness_candidate_note_pending
        local witness_action_index_candidate
        witness_extract_attempt=$((witness_extract_attempt + 1))
        witness_candidate_note_pending="false"
        witness_extract_ok="false"
        for witness_action_index_candidate in "${generated_deposit_action_indexes[@]}"; do
          rm -f "$deposit_candidate_json"
          if (
            cd "$REPO_ROOT"
            go run ./cmd/juno-witness-extract deposit \
              --juno-scan-url "$witness_scan_url" \
              --wallet-id "$generated_wallet_id" \
              --juno-scan-bearer-token-env "$sp1_witness_juno_scan_bearer_token_env" \
              --juno-rpc-url "$witness_rpc_url" \
              --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
              --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
              --txid "$generated_deposit_txid" \
              --action-index "$witness_action_index_candidate" \
              --output-witness-item-file "$deposit_candidate_witness" >"$deposit_candidate_json" 2>"$witness_extract_error_file"
          ); then
            witness_extract_ok="true"
            witness_selected_action_index="$witness_action_index_candidate"
            rm -f "$witness_extract_error_file"
            break
          fi
          witness_extract_last_error="$(tail -n 1 "$witness_extract_error_file" 2>/dev/null | tr -d '\r\n')"
          if grep -qi "note not found" "$witness_extract_error_file"; then
            witness_candidate_note_pending="true"
          fi
        done
        if [[ "$witness_extract_ok" == "true" ]]; then
          break
        fi
        if [[ "$witness_candidate_note_pending" == "true" ]]; then
          local witness_indexed_wallet_id
          witness_indexed_wallet_id="$(
            witness_scan_find_wallet_for_txid \
              "$witness_scan_url" \
              "$juno_scan_bearer_token" \
              "$generated_deposit_txid" \
              "$generated_wallet_id" || true
          )"
          if [[ -n "$witness_indexed_wallet_id" && "$witness_indexed_wallet_id" != "$generated_wallet_id" ]]; then
            log "switching witness wallet id during extraction generated_wallet_id=$generated_wallet_id indexed_wallet_id=$witness_indexed_wallet_id txid=$generated_deposit_txid operator=$witness_operator_label"
            generated_wallet_id="$witness_indexed_wallet_id"
            withdraw_coordinator_juno_wallet_id="$generated_wallet_id"
            witness_extract_wait_logged="false"
            continue
          fi
        fi
        if [[ "$witness_candidate_note_pending" == "true" && "$witness_extract_wait_logged" != "true" ]]; then
          log "waiting for note visibility on operator=$witness_operator_label wallet=$generated_wallet_id txid=$generated_deposit_txid action_index_candidates=$(IFS=,; printf '%s' "${generated_deposit_action_indexes[*]}")"
          witness_extract_wait_logged="true"
        fi
        if (( $(date +%s) >= witness_extract_deadline_epoch )); then
          break
        fi
        sleep "$witness_extract_sleep_seconds"
      done

      if [[ "$witness_extract_ok" != "true" ]]; then
        witness_failed_operator_labels+=("$witness_operator_label")
        if [[ -n "$witness_extract_last_error" ]]; then
          log "witness extraction failed for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url last_error=$witness_extract_last_error"
        else
          log "witness extraction failed for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
        fi
        continue
      fi
      if [[ -n "$witness_selected_action_index" ]]; then
        generated_deposit_action_index="$witness_selected_action_index"
      fi

      local deposit_witness_hex deposit_anchor_height deposit_anchor_hash deposit_final_root
      deposit_witness_hex="$(jq -r '.witness_item_hex // empty' "$deposit_candidate_json")"
      deposit_anchor_height="$(jq -r '.anchor_height // empty' "$deposit_candidate_json")"
      deposit_anchor_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_candidate_json")"
      deposit_final_root="$(jq -r '.final_orchard_root // empty' "$deposit_candidate_json")"

      [[ -n "$deposit_witness_hex" ]] || die "deposit witness output missing witness_item_hex: $deposit_candidate_json"
      [[ -n "$deposit_anchor_height" ]] || die "deposit witness output missing anchor_height: $deposit_candidate_json"
      [[ -n "$deposit_anchor_hash" ]] || die "deposit witness output missing anchor_block_hash: $deposit_candidate_json"
      [[ -n "$deposit_final_root" ]] || die "deposit witness output missing final_orchard_root: $deposit_candidate_json"

      local witness_fingerprint
      witness_fingerprint="${generated_deposit_txid}|${deposit_witness_hex}|${deposit_final_root}"
      witness_success_labels+=("$witness_operator_label")
      witness_success_fingerprints+=("$witness_fingerprint")
      witness_success_anchor_fingerprints+=("${deposit_anchor_height}|${deposit_anchor_hash}|${deposit_final_root}")
      witness_success_deposit_json+=("$deposit_candidate_json")
      witness_success_deposit_witness+=("$deposit_candidate_witness")
      log "witness extraction succeeded for operator=$witness_operator_label"
    done

    witness_quorum_validated_count="${#witness_success_labels[@]}"
    witness_quorum_operator_labels=("${witness_success_labels[@]}")
    (( witness_quorum_validated_count >= witness_quorum_threshold )) || \
      die "failed to extract witness from quorum of operators: success=$witness_quorum_validated_count threshold=$witness_quorum_threshold"

    local -a witness_unique_fingerprints=()
    local -a witness_unique_fingerprint_counts=()
    local -a witness_unique_fingerprint_first_indexes=()
    local witness_fingerprint witness_existing_fingerprint witness_known_fingerprint witness_unique_idx
    for witness_idx in "${!witness_success_fingerprints[@]}"; do
      witness_fingerprint="${witness_success_fingerprints[$witness_idx]}"
      witness_known_fingerprint="false"
      for witness_unique_idx in "${!witness_unique_fingerprints[@]}"; do
        witness_existing_fingerprint="${witness_unique_fingerprints[$witness_unique_idx]}"
        if [[ "$witness_existing_fingerprint" == "$witness_fingerprint" ]]; then
          witness_unique_fingerprint_counts[$witness_unique_idx]=$(( ${witness_unique_fingerprint_counts[$witness_unique_idx]} + 1 ))
          witness_known_fingerprint="true"
          break
        fi
      done
      if [[ "$witness_known_fingerprint" != "true" ]]; then
        witness_unique_fingerprints+=("$witness_fingerprint")
        witness_unique_fingerprint_counts+=(1)
        witness_unique_fingerprint_first_indexes+=("$witness_idx")
      fi
    done

    local witness_consensus_idx=0
    local witness_consensus_count="${witness_unique_fingerprint_counts[0]}"
    local witness_consensus_first_index="${witness_unique_fingerprint_first_indexes[0]}"
    for witness_unique_idx in "${!witness_unique_fingerprint_counts[@]}"; do
      local witness_candidate_count witness_candidate_first_index
      witness_candidate_count="${witness_unique_fingerprint_counts[$witness_unique_idx]}"
      witness_candidate_first_index="${witness_unique_fingerprint_first_indexes[$witness_unique_idx]}"
      if (( witness_candidate_count > witness_consensus_count )); then
        witness_consensus_idx="$witness_unique_idx"
        witness_consensus_count="$witness_candidate_count"
        witness_consensus_first_index="$witness_candidate_first_index"
      fi
    done
    if (( witness_consensus_count < witness_quorum_threshold )); then
      die "witness quorum consistency mismatch across operators: operators=$(IFS=,; printf '%s' "${witness_success_labels[*]}") consensus=$witness_consensus_count threshold=$witness_quorum_threshold"
    fi

    local -a witness_consensus_indexes=()
    local -a witness_consensus_labels=()
    for witness_idx in "${!witness_success_fingerprints[@]}"; do
      if [[ "${witness_success_fingerprints[$witness_idx]}" == "${witness_unique_fingerprints[$witness_consensus_idx]}" ]]; then
        witness_consensus_indexes+=("$witness_idx")
        witness_consensus_labels+=("${witness_success_labels[$witness_idx]}")
      fi
    done
    witness_quorum_validated_count="${#witness_consensus_indexes[@]}"
    witness_quorum_operator_labels=("${witness_consensus_labels[@]}")
    if (( ${#witness_unique_fingerprints[@]} > 1 )); then
      log "witness quorum witness/root divergence detected across operators; selecting consensus fingerprint count=$witness_consensus_count threshold=$witness_quorum_threshold operators=$(IFS=,; printf '%s' "${witness_consensus_labels[*]}")"
    fi

    local -a witness_unique_anchor_fingerprints=()
    local witness_anchor_fingerprint witness_existing_anchor_fingerprint witness_known_anchor_fingerprint
    for witness_idx in "${witness_consensus_indexes[@]}"; do
      witness_anchor_fingerprint="${witness_success_anchor_fingerprints[$witness_idx]}"
      witness_known_anchor_fingerprint="false"
      for witness_existing_anchor_fingerprint in "${witness_unique_anchor_fingerprints[@]}"; do
        if [[ "$witness_existing_anchor_fingerprint" == "$witness_anchor_fingerprint" ]]; then
          witness_known_anchor_fingerprint="true"
          break
        fi
      done
      if [[ "$witness_known_anchor_fingerprint" != "true" ]]; then
        witness_unique_anchor_fingerprints+=("$witness_anchor_fingerprint")
      fi
    done
    if (( ${#witness_unique_anchor_fingerprints[@]} > 1 )); then
      log "witness quorum anchor divergence detected across operators (using first successful anchor)"
    fi
    witness_quorum_validated="true"

    cp "${witness_success_deposit_witness[$witness_consensus_first_index]}" "$deposit_witness_auto_file"
    cp "${witness_success_deposit_json[$witness_consensus_first_index]}" "$deposit_witness_auto_json"

    sp1_deposit_witness_item_files=("$deposit_witness_auto_file")
    sp1_withdraw_witness_item_files=()

    bridge_deposit_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$deposit_witness_auto_json")"
    bridge_deposit_checkpoint_height="$(jq -r '.anchor_height // empty' "$deposit_witness_auto_json")"
    bridge_deposit_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_witness_auto_json")"
    bridge_withdraw_final_orchard_root="$bridge_deposit_final_orchard_root"
    bridge_withdraw_checkpoint_height="$bridge_deposit_checkpoint_height"
    bridge_withdraw_checkpoint_block_hash="$bridge_deposit_checkpoint_block_hash"
  fi

  if [[ -z "$withdraw_coordinator_tss_url" ]]; then
    withdraw_coordinator_tss_url="$(derive_tss_url_from_juno_rpc_url "$sp1_witness_juno_rpc_url" || true)"
  fi
  if [[ -z "$withdraw_coordinator_tss_server_ca_file" ]]; then
    local default_tss_runtime_dir
    default_tss_runtime_dir="$(jq -r '.operators[0].runtime_dir // empty' "$dkg_summary" 2>/dev/null || true)"
    if [[ -n "$default_tss_runtime_dir" ]]; then
      withdraw_coordinator_tss_server_ca_file="$default_tss_runtime_dir/bundle/tls/ca.pem"
    fi
  fi
  [[ -n "$withdraw_coordinator_juno_wallet_id" ]] || \
    die "withdraw coordinator juno wallet id is required from generated witness metadata"
  [[ -n "$withdraw_coordinator_juno_change_address" ]] || \
    die "withdraw coordinator juno change address is required from generated witness metadata"
  [[ -n "$withdraw_coordinator_tss_url" ]] || \
    die "--withdraw-coordinator-tss-url is required for live withdraw coordinator full mode"
  [[ "$withdraw_coordinator_tss_url" == https://* ]] || \
    die "withdraw coordinator tss url must use https: $withdraw_coordinator_tss_url"
  [[ -n "$withdraw_coordinator_tss_server_ca_file" ]] || \
    die "--withdraw-coordinator-tss-server-ca-file is required for live withdraw coordinator full mode"
  [[ -f "$withdraw_coordinator_tss_server_ca_file" ]] || \
    die "withdraw coordinator tss server ca file not found: $withdraw_coordinator_tss_server_ca_file"
  local withdraw_coordinator_juno_rpc_user_var withdraw_coordinator_juno_rpc_pass_var
  local withdraw_coordinator_juno_rpc_user_value withdraw_coordinator_juno_rpc_pass_value
  local withdraw_finalizer_juno_scan_bearer_value=""
  withdraw_coordinator_juno_rpc_user_var="$sp1_witness_juno_rpc_user_env"
  withdraw_coordinator_juno_rpc_pass_var="$sp1_witness_juno_rpc_pass_env"
  [[ -n "${!withdraw_coordinator_juno_rpc_user_var:-}" ]] || \
    die "missing env var for withdraw coordinator Juno RPC user: $withdraw_coordinator_juno_rpc_user_var"
  [[ -n "${!withdraw_coordinator_juno_rpc_pass_var:-}" ]] || \
    die "missing env var for withdraw coordinator Juno RPC pass: $withdraw_coordinator_juno_rpc_pass_var"
  withdraw_coordinator_juno_rpc_user_value="${!withdraw_coordinator_juno_rpc_user_var}"
  withdraw_coordinator_juno_rpc_pass_value="${!withdraw_coordinator_juno_rpc_pass_var}"
  withdraw_finalizer_juno_scan_bearer_value="${!sp1_witness_juno_scan_bearer_token_env:-}"

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
  maybe_stop_after_stage "witness_ready"
  if [[ "$stage_stop_after_stage_reached" == "true" ]]; then
    return 0
  fi

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
    ensure_recipient_min_balance "$base_rpc_url" "$base_key" "$funding_sender_address" "$bridge_deployer_address" "$bridge_deployer_required_wei" "bridge deployer" || \
      die "failed to fund bridge deployer: address=$bridge_deployer_address required_wei=$bridge_deployer_required_wei"
  fi

  local bridge_deployer_key_file
  bridge_deployer_key_file="$(jq -r '.operators[0].operator_key_file // empty' "$dkg_summary")"
  [[ -n "$bridge_deployer_key_file" ]] || die "dkg summary missing operators[0].operator_key_file"
  [[ -f "$bridge_deployer_key_file" ]] || die "bridge deployer key file not found: $bridge_deployer_key_file"

  local -a bridge_args=()
  export SP1_DEPOSIT_PROGRAM_URL="$sp1_deposit_program_url"
  export SP1_WITHDRAW_PROGRAM_URL="$sp1_withdraw_program_url"
  export SP1_DEPOSIT_PROGRAM_VKEY="$bridge_deposit_image_id"
  export SP1_WITHDRAW_PROGRAM_VKEY="$bridge_withdraw_image_id"
  bridge_args+=(
    "--rpc-url" "$base_rpc_url"
    "--chain-id" "$base_chain_id"
    "--deploy-only"
    "--deployer-key-file" "$bridge_deployer_key_file"
    "--threshold" "$threshold"
    "--contracts-out" "$contracts_out"
    "--recipient" "$bridge_recipient_address"
    "--sp1-auto"
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
    "--sp1-rpc-url" "$sp1_rpc_url"
    "--sp1-proof-submission-mode" "$sp1_proof_submission_mode"
    "--sp1-proof-queue-brokers" "$shared_kafka_brokers"
    "--sp1-proof-request-topic" "$proof_request_topic"
    "--sp1-proof-result-topic" "$proof_result_topic"
    "--sp1-proof-failure-topic" "$proof_failure_topic"
    "--sp1-proof-consumer-group" "$proof_bridge_consumer_group"
    "--sp1-market-address" "$sp1_market_address"
    "--sp1-verifier-router-address" "$sp1_verifier_router_address"
    "--sp1-set-verifier-address" "$sp1_set_verifier_address"
    "--sp1-input-mode" "$sp1_input_mode"
    "--sp1-deposit-program-url" "$sp1_deposit_program_url"
    "--sp1-withdraw-program-url" "$sp1_withdraw_program_url"
    "--sp1-input-s3-bucket" "$sp1_input_s3_bucket"
    "--sp1-input-s3-prefix" "$sp1_input_s3_prefix"
    "--sp1-input-s3-region" "$sp1_input_s3_region"
    "--sp1-input-s3-presign-ttl" "$sp1_input_s3_presign_ttl"
    "--sp1-max-price-per-pgu" "$sp1_max_price_per_pgu"
    "--sp1-min-auction-period" "$sp1_min_auction_period"
    "--sp1-auction-timeout" "$sp1_auction_timeout"
    "--sp1-request-timeout" "$sp1_request_timeout"
  )
  bridge_args+=(
    "--sp1-deposit-owallet-ivk-hex" "$sp1_deposit_owallet_ivk_hex"
    "--sp1-withdraw-owallet-ovk-hex" "$sp1_withdraw_owallet_ovk_hex"
  )
  for witness_file in "${sp1_deposit_witness_item_files[@]}"; do
    bridge_args+=("--sp1-deposit-witness-item-file" "$witness_file")
  done
  for witness_file in "${sp1_withdraw_witness_item_files[@]}"; do
    bridge_args+=("--sp1-withdraw-witness-item-file" "$witness_file")
  done

  local operator_id operator_endpoint operator_key_file operator_key_hex
  local -a bridge_operator_endpoints=()
  local -a bridge_operator_key_hexes=()
  while IFS=$'\t' read -r operator_id operator_endpoint operator_key_file; do
    [[ -n "$operator_id" ]] || continue
    bridge_args+=("--operator-address" "$operator_id")
    if [[ -n "$operator_endpoint" ]]; then
      bridge_operator_endpoints+=("$operator_endpoint")
    fi
    operator_key_hex="$(operator_signer_key_hex_from_file "$operator_key_file" || true)"
    [[ -n "$operator_key_hex" ]] || \
      die "invalid or missing operator key file for operator_id=$operator_id path=$operator_key_file"
    bridge_operator_key_hexes+=("$operator_key_hex")
  done < <(jq -r '.operators[] | [.operator_id, (.endpoint // .grpc_endpoint // ""), (.operator_key_file // "")] | @tsv' "$dkg_summary")

  if (( ${#bridge_operator_key_hexes[@]} < threshold )); then
    die "operator key count is below threshold for bridge signer: keys=${#bridge_operator_key_hexes[@]} threshold=$threshold"
  fi

  local bridge_operator_signer_keys_csv
  bridge_operator_signer_keys_csv="$(IFS=,; printf '%s' "${bridge_operator_key_hexes[*]}")"
  [[ -n "$bridge_operator_signer_keys_csv" ]] || die "failed to derive operator signer key list"
  local -a bridge_operator_signer_env=()
  bridge_operator_signer_env=(JUNO_TXSIGN_SIGNER_KEYS="$bridge_operator_signer_keys_csv")

  local direct_cli_user_proof_status="not-run"
  local direct_cli_user_proof_summary_path=""
  local direct_cli_user_proof_log=""
  local direct_cli_user_proof_submission_mode=""
  local direct_cli_user_proof_deposit_request_id=""
  local direct_cli_user_proof_withdraw_request_id=""

  run_direct_cli_user_proof_scenario() {
    local witness_metadata_json direct_cli_generated_witness_metadata_json
    local direct_cli_generated_deposit_txid direct_cli_generated_withdraw_txid
    local direct_cli_generated_deposit_action_index direct_cli_generated_withdraw_action_index
    local direct_cli_generated_recipient_raw_hex
    local direct_cli_generated_witness_wallet_id
    local direct_cli_generated_withdrawal_id direct_cli_generated_withdraw_batch_id
    local direct_cli_generated_withdrawal_id_no_prefix direct_cli_generated_withdraw_batch_id_no_prefix
    local direct_cli_witness_source_recipient_raw_hex
    local direct_cli_withdraw_txid direct_cli_withdraw_action_index
    local -a direct_cli_withdraw_action_indexes=()
    local -a direct_cli_withdraw_action_indexes_rpc=()
    local -a direct_cli_deposit_action_indexes=()
    local -a direct_cli_deposit_action_indexes_rpc=()
    local direct_cli_recipient_raw_hex direct_cli_recipient_raw_hex_prefixed
    local direct_cli_bridge_deploy_summary direct_cli_bridge_deploy_log
    local direct_cli_deployed_wjuno_address direct_cli_deployed_operator_registry_address
    local direct_cli_deployed_fee_distributor_address direct_cli_deployed_bridge_address
    local direct_cli_domain_tag direct_cli_recipient_hash direct_cli_predicted_withdrawal_id
    local direct_cli_withdraw_witness_file direct_cli_withdraw_witness_json
    local direct_cli_deposit_witness_file direct_cli_deposit_witness_json
    local direct_cli_deposit_action_index_used=""
    local direct_cli_deposit_extract_ok="false"
    local direct_cli_deposit_extract_deadline_epoch direct_cli_deposit_extract_wait_logged
    local direct_cli_deposit_extract_sleep_seconds direct_cli_deposit_extract_error_file
    local direct_cli_deposit_last_error
    local direct_cli_withdraw_extract_ok="false"
    local direct_cli_withdraw_action_index_used=""
    local direct_cli_withdraw_extract_deadline_epoch direct_cli_withdraw_extract_wait_logged
    local direct_cli_withdraw_extract_sleep_seconds direct_cli_withdraw_extract_error_file
    local direct_cli_withdraw_last_error
    local direct_cli_bridge_summary direct_cli_bridge_log
    local direct_cli_deposit_final_orchard_root direct_cli_deposit_anchor_height direct_cli_deposit_anchor_hash
    local direct_cli_withdraw_final_orchard_root direct_cli_withdraw_anchor_height direct_cli_withdraw_anchor_hash
    local direct_cli_withdraw_amount="10000"
    local direct_cli_proof_submission_mode="$sp1_proof_submission_mode"
    local direct_cli_proof_bridge_consumer_group="${proof_bridge_consumer_group}-direct-cli"
    local direct_cli_status
    local direct_cli_requestor_key_file="$sp1_requestor_key_file"
    local witness_file
    local operator_id operator_endpoint
    local -a direct_cli_bridge_base_args=()
    local -a direct_cli_bridge_deploy_args=()
    local -a direct_cli_bridge_run_args=()

    ensure_bridge_operator_signer_ready

    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    direct_cli_witness_source_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json" 2>/dev/null || true)"
    direct_cli_recipient_raw_hex_prefixed="$(normalize_hex_prefixed "$direct_cli_witness_source_recipient_raw_hex" || true)"
    [[ "$direct_cli_recipient_raw_hex_prefixed" =~ ^0x[0-9a-f]{86}$ ]] || return 1

    direct_cli_bridge_base_args+=(
      "--rpc-url" "$base_rpc_url"
      "--chain-id" "$base_chain_id"
      "--deployer-key-file" "$bridge_deployer_key_file"
      "--operator-signer-bin" "$bridge_operator_signer_bin"
      "--threshold" "$threshold"
      "--contracts-out" "$contracts_out"
      "--recipient" "$bridge_recipient_address"
      "--sp1-auto"
      "--run-timeout" "$bridge_run_timeout"
      "--verifier-address" "$bridge_verifier_address"
      "--deposit-image-id" "$bridge_deposit_image_id"
      "--withdraw-image-id" "$bridge_withdraw_image_id"
      "--deposit-final-orchard-root" "$bridge_deposit_final_orchard_root"
      "--withdraw-final-orchard-root" "$bridge_withdraw_final_orchard_root"
      "--deposit-checkpoint-height" "$bridge_deposit_checkpoint_height"
      "--deposit-checkpoint-block-hash" "$bridge_deposit_checkpoint_block_hash"
      "--withdraw-checkpoint-height" "$bridge_withdraw_checkpoint_height"
      "--withdraw-checkpoint-block-hash" "$bridge_withdraw_checkpoint_block_hash"
      "--sp1-bin" "$sp1_bin"
      "--sp1-rpc-url" "$sp1_rpc_url"
      "--sp1-proof-submission-mode" "$direct_cli_proof_submission_mode"
      "--sp1-proof-queue-brokers" "$shared_kafka_brokers"
      "--sp1-proof-request-topic" "$proof_request_topic"
      "--sp1-proof-result-topic" "$proof_result_topic"
      "--sp1-proof-failure-topic" "$proof_failure_topic"
      "--sp1-proof-consumer-group" "$direct_cli_proof_bridge_consumer_group"
      "--sp1-market-address" "$sp1_market_address"
      "--sp1-verifier-router-address" "$sp1_verifier_router_address"
      "--sp1-set-verifier-address" "$sp1_set_verifier_address"
      "--sp1-input-mode" "$sp1_input_mode"
      "--sp1-deposit-program-url" "$sp1_deposit_program_url"
      "--sp1-withdraw-program-url" "$sp1_withdraw_program_url"
      "--sp1-input-s3-bucket" "$sp1_input_s3_bucket"
      "--sp1-input-s3-prefix" "$sp1_input_s3_prefix"
      "--sp1-input-s3-region" "$sp1_input_s3_region"
      "--sp1-input-s3-presign-ttl" "$sp1_input_s3_presign_ttl"
      "--sp1-max-price-per-pgu" "$sp1_max_price_per_pgu"
      "--sp1-min-auction-period" "$sp1_min_auction_period"
      "--sp1-auction-timeout" "$sp1_auction_timeout"
      "--sp1-request-timeout" "$sp1_request_timeout"
      "--sp1-requestor-key-file" "$direct_cli_requestor_key_file"
    )
    while IFS=$'\t' read -r operator_id operator_endpoint; do
      [[ -n "$operator_id" ]] || continue
      direct_cli_bridge_base_args+=("--operator-address" "$operator_id")
      if [[ "$bridge_operator_signer_supports_operator_endpoint" == "true" ]]; then
        [[ -n "$operator_endpoint" ]] || return 1
        direct_cli_bridge_base_args+=("--operator-signer-endpoint" "$operator_endpoint")
      fi
    done < <(jq -r '.operators[] | [.operator_id, (.endpoint // .grpc_endpoint // "")] | @tsv' "$dkg_summary")

    direct_cli_bridge_deploy_summary="$workdir/reports/direct-cli-user-proof-deploy-summary.json"
    direct_cli_bridge_deploy_log="$workdir/reports/direct-cli-user-proof-deploy.log"
    direct_cli_bridge_deploy_args=("${direct_cli_bridge_base_args[@]}")
    direct_cli_bridge_deploy_args+=(
      "--deploy-only"
      "--output" "$direct_cli_bridge_deploy_summary"
    )
    set +e
    (
      cd "$REPO_ROOT"
      env "${bridge_operator_signer_env[@]}" go run ./cmd/bridge-e2e "${direct_cli_bridge_deploy_args[@]}"
    ) >"$direct_cli_bridge_deploy_log" 2>&1
    direct_cli_status="$?"
    set -e
    if (( direct_cli_status != 0 )); then
      tail -n 200 "$direct_cli_bridge_deploy_log" >&2 || true
      return 1
    fi

    direct_cli_deployed_wjuno_address="$(jq -r '.contracts.wjuno // empty' "$direct_cli_bridge_deploy_summary" 2>/dev/null || true)"
    direct_cli_deployed_operator_registry_address="$(jq -r '.contracts.operator_registry // empty' "$direct_cli_bridge_deploy_summary" 2>/dev/null || true)"
    direct_cli_deployed_fee_distributor_address="$(jq -r '.contracts.fee_distributor // empty' "$direct_cli_bridge_deploy_summary" 2>/dev/null || true)"
    direct_cli_deployed_bridge_address="$(jq -r '.contracts.bridge // empty' "$direct_cli_bridge_deploy_summary" 2>/dev/null || true)"
    [[ "$direct_cli_deployed_wjuno_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || return 1
    [[ "$direct_cli_deployed_operator_registry_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || return 1
    [[ "$direct_cli_deployed_fee_distributor_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || return 1
    [[ "$direct_cli_deployed_bridge_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || return 1

    direct_cli_domain_tag="$(cast format-bytes32-string "WJUNO_WITHDRAW_V1" 2>/dev/null || true)"
    [[ "$direct_cli_domain_tag" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1

    direct_cli_recipient_hash="$(cast keccak "$direct_cli_recipient_raw_hex_prefixed" 2>/dev/null || true)"
    direct_cli_recipient_hash="$(normalize_hex_prefixed "$direct_cli_recipient_hash" || true)"
    [[ "$direct_cli_recipient_hash" =~ ^0x[0-9a-f]{64}$ ]] || return 1

    direct_cli_predicted_withdrawal_id="$(
      cast keccak "$(
        cast abi-encode \
          "f(bytes32,uint256,address,uint256,address,uint256,bytes32)" \
          "$direct_cli_domain_tag" \
          "$base_chain_id" \
          "$direct_cli_deployed_bridge_address" \
          "1" \
          "$bridge_deployer_address" \
          "$direct_cli_withdraw_amount" \
          "$direct_cli_recipient_hash"
      )" 2>/dev/null || true
    )"
    direct_cli_predicted_withdrawal_id="$(normalize_hex_prefixed "$direct_cli_predicted_withdrawal_id" || true)"
    [[ "$direct_cli_predicted_withdrawal_id" =~ ^0x[0-9a-f]{64}$ ]] || return 1

    direct_cli_generated_withdraw_batch_id="$(compute_single_withdraw_batch_id "$direct_cli_predicted_withdrawal_id" || true)"
    [[ "$direct_cli_generated_withdraw_batch_id" =~ ^0x[0-9a-f]{64}$ ]] || return 1
    direct_cli_generated_withdrawal_id_no_prefix="${direct_cli_predicted_withdrawal_id#0x}"
    direct_cli_generated_withdraw_batch_id_no_prefix="${direct_cli_generated_withdraw_batch_id#0x}"

    direct_cli_generated_witness_metadata_json="$workdir/reports/witness/direct-cli-generated-witness-metadata.json"
    direct_cli_generated_witness_wallet_id="$withdraw_coordinator_juno_wallet_id"
    local -a direct_cli_witness_metadata_args=(
      run
      --juno-rpc-url "$sp1_witness_juno_rpc_url"
      --juno-rpc-user "$juno_rpc_user"
      --juno-rpc-pass "$juno_rpc_pass"
      --juno-scan-url "$sp1_witness_juno_scan_url"
      --wallet-id "$direct_cli_generated_witness_wallet_id"
      --recipient-ua "$sp1_witness_recipient_ua"
      --recipient-ufvk "$sp1_witness_recipient_ufvk"
      --base-chain-id "$base_chain_id"
      --bridge-address "$direct_cli_deployed_bridge_address"
      --base-recipient-address "$bridge_recipient_address"
      --withdrawal-id-hex "$direct_cli_generated_withdrawal_id_no_prefix"
      --withdraw-batch-id-hex "$direct_cli_generated_withdraw_batch_id_no_prefix"
      --skip-action-index-lookup
      --deposit-amount-zat "100000"
      --withdraw-amount-zat "$direct_cli_withdraw_amount"
      --timeout-seconds "$sp1_witness_metadata_timeout_seconds"
      --output "$direct_cli_generated_witness_metadata_json"
    )
    if [[ -n "${JUNO_FUNDER_SOURCE_ADDRESS:-}" ]]; then
      direct_cli_witness_metadata_args+=("--funder-source-address" "${JUNO_FUNDER_SOURCE_ADDRESS}")
    elif [[ -n "${JUNO_FUNDER_SEED_PHRASE:-}" ]]; then
      direct_cli_witness_metadata_args+=("--funder-seed-phrase" "${JUNO_FUNDER_SEED_PHRASE}")
    else
      direct_cli_witness_metadata_args+=("--funder-private-key-hex" "${JUNO_FUNDER_PRIVATE_KEY_HEX}")
    fi
    if [[ -n "$juno_scan_bearer_token" ]]; then
      direct_cli_witness_metadata_args+=("--juno-scan-bearer-token" "$juno_scan_bearer_token")
    fi
    local direct_cli_witness_metadata_timeout_seconds
    local direct_cli_witness_metadata_status
    direct_cli_witness_metadata_timeout_seconds=$((sp1_witness_metadata_timeout_seconds + 90))
    set +e
    (
      cd "$REPO_ROOT"
      run_with_optional_timeout "$direct_cli_witness_metadata_timeout_seconds" \
        deploy/operators/dkg/e2e/generate-juno-witness-metadata.sh "${direct_cli_witness_metadata_args[@]}" >/dev/null
    )
    direct_cli_witness_metadata_status=$?
    set -e
    if (( direct_cli_witness_metadata_status != 0 )); then
      if (( direct_cli_witness_metadata_status == 124 )); then
        log "direct-cli witness metadata generation timed out timeout_seconds=$direct_cli_witness_metadata_timeout_seconds"
      fi
      return 1
    fi

    direct_cli_generated_deposit_txid="$(jq -r '.deposit_txid // empty' "$direct_cli_generated_witness_metadata_json" 2>/dev/null || true)"
    direct_cli_generated_withdraw_txid="$(jq -r '.withdraw_txid // empty' "$direct_cli_generated_witness_metadata_json" 2>/dev/null || true)"
    direct_cli_generated_deposit_action_index="$(jq -r '.deposit_action_index // empty' "$direct_cli_generated_witness_metadata_json" 2>/dev/null || true)"
    direct_cli_generated_withdraw_action_index="$(jq -r '.withdraw_action_index // empty' "$direct_cli_generated_witness_metadata_json" 2>/dev/null || true)"
    direct_cli_generated_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$direct_cli_generated_witness_metadata_json" 2>/dev/null || true)"
    [[ -n "$direct_cli_generated_deposit_txid" ]] || return 1
    [[ -n "$direct_cli_generated_withdraw_txid" ]] || return 1
    direct_cli_recipient_raw_hex="$direct_cli_generated_recipient_raw_hex"
    direct_cli_recipient_raw_hex_prefixed="$(normalize_hex_prefixed "$direct_cli_recipient_raw_hex" || true)"
    [[ "$direct_cli_recipient_raw_hex_prefixed" =~ ^0x[0-9a-f]{86}$ ]] || return 1

    local direct_cli_deposit_tx_height direct_cli_withdraw_tx_height direct_cli_backfill_from_height
    direct_cli_deposit_tx_height="$(
      witness_rpc_tx_height \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$direct_cli_generated_deposit_txid" || true
    )"
    direct_cli_withdraw_tx_height="$(
      witness_rpc_tx_height \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$direct_cli_generated_withdraw_txid" || true
    )"
    direct_cli_backfill_from_height=""
    if [[ "$direct_cli_deposit_tx_height" =~ ^[0-9]+$ && "$direct_cli_withdraw_tx_height" =~ ^[0-9]+$ ]]; then
      if (( direct_cli_deposit_tx_height <= direct_cli_withdraw_tx_height )); then
        direct_cli_backfill_from_height="$direct_cli_deposit_tx_height"
      else
        direct_cli_backfill_from_height="$direct_cli_withdraw_tx_height"
      fi
    elif [[ "$direct_cli_deposit_tx_height" =~ ^[0-9]+$ ]]; then
      direct_cli_backfill_from_height="$direct_cli_deposit_tx_height"
    elif [[ "$direct_cli_withdraw_tx_height" =~ ^[0-9]+$ ]]; then
      direct_cli_backfill_from_height="$direct_cli_withdraw_tx_height"
    fi
    if [[ "$direct_cli_backfill_from_height" =~ ^[0-9]+$ ]]; then
      if (( direct_cli_backfill_from_height > 32 )); then
        direct_cli_backfill_from_height=$((direct_cli_backfill_from_height - 32))
      else
        direct_cli_backfill_from_height=0
      fi
      if ! witness_scan_backfill_wallet "$sp1_witness_juno_scan_url" "$juno_scan_bearer_token" "$direct_cli_generated_witness_wallet_id" "$direct_cli_backfill_from_height"; then
        log "direct-cli witness backfill best-effort failed scan_url=$sp1_witness_juno_scan_url wallet=$direct_cli_generated_witness_wallet_id from_height=$direct_cli_backfill_from_height"
      fi
    else
      log "direct-cli witness backfill skipped: tx height unavailable deposit_txid=$direct_cli_generated_deposit_txid withdraw_txid=$direct_cli_generated_withdraw_txid"
    fi

    if [[ "$direct_cli_generated_deposit_action_index" =~ ^[0-9]+$ ]]; then
      direct_cli_deposit_action_indexes+=("$direct_cli_generated_deposit_action_index")
    fi
    mapfile -t direct_cli_deposit_action_indexes_rpc < <(
      witness_rpc_action_index_candidates \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$direct_cli_generated_deposit_txid" || true
    )
    for direct_cli_action_candidate in "${direct_cli_deposit_action_indexes_rpc[@]}"; do
      [[ "$direct_cli_action_candidate" =~ ^[0-9]+$ ]] || continue
      local known_direct_cli_deposit_candidate="false"
      local existing_direct_cli_deposit_candidate
      for existing_direct_cli_deposit_candidate in "${direct_cli_deposit_action_indexes[@]}"; do
        if [[ "$existing_direct_cli_deposit_candidate" == "$direct_cli_action_candidate" ]]; then
          known_direct_cli_deposit_candidate="true"
          break
        fi
      done
      if [[ "$known_direct_cli_deposit_candidate" != "true" ]]; then
        direct_cli_deposit_action_indexes+=("$direct_cli_action_candidate")
      fi
    done
    for direct_cli_action_candidate in 0 1 2 3; do
      local known_direct_cli_deposit_default="false"
      local existing_direct_cli_deposit_default
      for existing_direct_cli_deposit_default in "${direct_cli_deposit_action_indexes[@]}"; do
        if [[ "$existing_direct_cli_deposit_default" == "$direct_cli_action_candidate" ]]; then
          known_direct_cli_deposit_default="true"
          break
        fi
      done
      if [[ "$known_direct_cli_deposit_default" != "true" ]]; then
        direct_cli_deposit_action_indexes+=("$direct_cli_action_candidate")
      fi
    done
    if (( ${#direct_cli_deposit_action_indexes[@]} == 0 )); then
      direct_cli_deposit_action_indexes=(0 1 2 3)
    fi
    log "direct-cli deposit extraction action-index candidates: $(IFS=,; printf '%s' "${direct_cli_deposit_action_indexes[*]}")"

    direct_cli_deposit_witness_file="$workdir/reports/witness/direct-cli-deposit.witness.bin"
    direct_cli_deposit_witness_json="$workdir/reports/witness/direct-cli-deposit.json"
    local -a direct_cli_deposit_extract_cmd=(go run ./cmd/juno-witness-extract)
    direct_cli_deposit_extract_deadline_epoch=$(( $(date +%s) + witness_timeout_slice_seconds ))
    direct_cli_deposit_extract_sleep_seconds=5
    direct_cli_deposit_extract_wait_logged="false"
    direct_cli_deposit_extract_error_file="$workdir/reports/witness/direct-cli-deposit.extract.err"
    direct_cli_deposit_last_error=""
    while true; do
      local direct_cli_deposit_note_pending="false"
      direct_cli_deposit_extract_ok="false"
      for direct_cli_action_candidate in "${direct_cli_deposit_action_indexes[@]}"; do
        rm -f "$direct_cli_deposit_witness_json"
        if (
          cd "$REPO_ROOT"
          "${direct_cli_deposit_extract_cmd[@]}" deposit \
            --juno-scan-url "$sp1_witness_juno_scan_url" \
            --wallet-id "$direct_cli_generated_witness_wallet_id" \
            --juno-scan-bearer-token-env "$sp1_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$sp1_witness_juno_rpc_url" \
            --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
            --txid "$direct_cli_generated_deposit_txid" \
            --action-index "$direct_cli_action_candidate" \
            --output-witness-item-file "$direct_cli_deposit_witness_file" \
            >"$direct_cli_deposit_witness_json" 2>"$direct_cli_deposit_extract_error_file"
        ); then
          direct_cli_deposit_extract_ok="true"
          direct_cli_deposit_action_index_used="$direct_cli_action_candidate"
          rm -f "$direct_cli_deposit_extract_error_file"
          break
        fi
        direct_cli_deposit_last_error="$(tail -n 1 "$direct_cli_deposit_extract_error_file" 2>/dev/null | tr -d '\r\n')"
        if grep -qi "note not found" "$direct_cli_deposit_extract_error_file"; then
          direct_cli_deposit_note_pending="true"
        fi
      done
      if [[ "$direct_cli_deposit_extract_ok" == "true" ]]; then
        break
      fi
      if [[ "$direct_cli_deposit_note_pending" == "true" && "$direct_cli_deposit_extract_wait_logged" != "true" ]]; then
        log "direct-cli waiting for deposit note visibility wallet=$direct_cli_generated_witness_wallet_id txid=$direct_cli_generated_deposit_txid action_index_candidates=$(IFS=,; printf '%s' "${direct_cli_deposit_action_indexes[*]}")"
        direct_cli_deposit_extract_wait_logged="true"
      fi
      if (( $(date +%s) >= direct_cli_deposit_extract_deadline_epoch )); then
        break
      fi
      sleep "$direct_cli_deposit_extract_sleep_seconds"
    done
    if [[ "$direct_cli_deposit_extract_ok" != "true" ]]; then
      if [[ -n "$direct_cli_deposit_last_error" ]]; then
        log "direct-cli deposit witness extraction failed last_error=$direct_cli_deposit_last_error"
      else
        log "direct-cli deposit witness extraction failed"
      fi
      return 1
    fi
    log "direct-cli deposit witness extraction selected action-index=$direct_cli_deposit_action_index_used"

    direct_cli_deposit_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$direct_cli_deposit_witness_json" 2>/dev/null || true)"
    direct_cli_deposit_anchor_height="$(jq -r '.anchor_height // empty' "$direct_cli_deposit_witness_json" 2>/dev/null || true)"
    direct_cli_deposit_anchor_hash="$(jq -r '.anchor_block_hash // empty' "$direct_cli_deposit_witness_json" 2>/dev/null || true)"
    [[ "$direct_cli_deposit_final_orchard_root" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1
    [[ "$direct_cli_deposit_anchor_height" =~ ^[0-9]+$ ]] || return 1
    [[ "$direct_cli_deposit_anchor_hash" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1

    direct_cli_withdraw_txid="$direct_cli_generated_withdraw_txid"
    direct_cli_withdraw_action_index="$direct_cli_generated_withdraw_action_index"
    if [[ "$direct_cli_withdraw_action_index" =~ ^[0-9]+$ ]]; then
      direct_cli_withdraw_action_indexes+=("$direct_cli_withdraw_action_index")
    fi
    mapfile -t direct_cli_withdraw_action_indexes_rpc < <(
      witness_rpc_action_index_candidates \
        "$sp1_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$direct_cli_withdraw_txid" || true
    )
    for direct_cli_action_candidate in "${direct_cli_withdraw_action_indexes_rpc[@]}"; do
      [[ "$direct_cli_action_candidate" =~ ^[0-9]+$ ]] || continue
      local known_direct_cli_candidate="false"
      local existing_direct_cli_candidate
      for existing_direct_cli_candidate in "${direct_cli_withdraw_action_indexes[@]}"; do
        if [[ "$existing_direct_cli_candidate" == "$direct_cli_action_candidate" ]]; then
          known_direct_cli_candidate="true"
          break
        fi
      done
      if [[ "$known_direct_cli_candidate" != "true" ]]; then
        direct_cli_withdraw_action_indexes+=("$direct_cli_action_candidate")
      fi
    done
    for direct_cli_action_candidate in 0 1 2 3; do
      local known_direct_cli_withdraw_default="false"
      local existing_direct_cli_withdraw_default
      for existing_direct_cli_withdraw_default in "${direct_cli_withdraw_action_indexes[@]}"; do
        if [[ "$existing_direct_cli_withdraw_default" == "$direct_cli_action_candidate" ]]; then
          known_direct_cli_withdraw_default="true"
          break
        fi
      done
      if [[ "$known_direct_cli_withdraw_default" != "true" ]]; then
        direct_cli_withdraw_action_indexes+=("$direct_cli_action_candidate")
      fi
    done
    if (( ${#direct_cli_withdraw_action_indexes[@]} == 0 )); then
      direct_cli_withdraw_action_indexes=(0 1 2 3)
    fi
    log "direct-cli withdraw extraction action-index candidates: $(IFS=,; printf '%s' "${direct_cli_withdraw_action_indexes[*]}")"

    direct_cli_withdraw_witness_file="$workdir/reports/witness/direct-cli-withdraw.witness.bin"
    direct_cli_withdraw_witness_json="$workdir/reports/witness/direct-cli-withdraw.json"
    local -a direct_cli_withdraw_extract_cmd=(go run ./cmd/juno-witness-extract)
    direct_cli_withdraw_extract_deadline_epoch=$(( $(date +%s) + witness_timeout_slice_seconds ))
    direct_cli_withdraw_extract_sleep_seconds=5
    direct_cli_withdraw_extract_wait_logged="false"
    direct_cli_withdraw_extract_error_file="$workdir/reports/witness/direct-cli-withdraw.extract.err"
    direct_cli_withdraw_last_error=""
    while true; do
      local direct_cli_withdraw_note_pending="false"
      direct_cli_withdraw_extract_ok="false"
      for direct_cli_action_candidate in "${direct_cli_withdraw_action_indexes[@]}"; do
        rm -f "$direct_cli_withdraw_witness_json"
        if (
          cd "$REPO_ROOT"
          "${direct_cli_withdraw_extract_cmd[@]}" withdraw \
            --juno-scan-url "$sp1_witness_juno_scan_url" \
            --wallet-id "$direct_cli_generated_witness_wallet_id" \
            --juno-scan-bearer-token-env "$sp1_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$sp1_witness_juno_rpc_url" \
            --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
            --txid "$direct_cli_withdraw_txid" \
            --action-index "$direct_cli_action_candidate" \
            --withdrawal-id-hex "$direct_cli_predicted_withdrawal_id" \
            --recipient-raw-address-hex "$direct_cli_recipient_raw_hex" \
            --output-witness-item-file "$direct_cli_withdraw_witness_file" \
            >"$direct_cli_withdraw_witness_json" 2>"$direct_cli_withdraw_extract_error_file"
        ); then
          direct_cli_withdraw_extract_ok="true"
          direct_cli_withdraw_action_index_used="$direct_cli_action_candidate"
          rm -f "$direct_cli_withdraw_extract_error_file"
          break
        fi
        direct_cli_withdraw_last_error="$(tail -n 1 "$direct_cli_withdraw_extract_error_file" 2>/dev/null | tr -d '\r\n')"
        if grep -qi "note not found" "$direct_cli_withdraw_extract_error_file"; then
          direct_cli_withdraw_note_pending="true"
        fi
      done
      if [[ "$direct_cli_withdraw_extract_ok" == "true" ]]; then
        break
      fi
      if [[ "$direct_cli_withdraw_note_pending" == "true" && "$direct_cli_withdraw_extract_wait_logged" != "true" ]]; then
        log "direct-cli waiting for withdraw note visibility wallet=$direct_cli_generated_witness_wallet_id txid=$direct_cli_withdraw_txid action_index_candidates=$(IFS=,; printf '%s' "${direct_cli_withdraw_action_indexes[*]}")"
        direct_cli_withdraw_extract_wait_logged="true"
      fi
      if (( $(date +%s) >= direct_cli_withdraw_extract_deadline_epoch )); then
        break
      fi
      sleep "$direct_cli_withdraw_extract_sleep_seconds"
    done
    if [[ "$direct_cli_withdraw_extract_ok" != "true" ]]; then
      if [[ -n "$direct_cli_withdraw_last_error" ]]; then
        log "direct-cli withdraw witness extraction failed last_error=$direct_cli_withdraw_last_error"
      else
        log "direct-cli withdraw witness extraction failed"
      fi
      return 1
    fi
    log "direct-cli withdraw witness extraction selected action-index=$direct_cli_withdraw_action_index_used"
    direct_cli_withdraw_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$direct_cli_withdraw_witness_json" 2>/dev/null || true)"
    direct_cli_withdraw_anchor_height="$(jq -r '.anchor_height // empty' "$direct_cli_withdraw_witness_json" 2>/dev/null || true)"
    direct_cli_withdraw_anchor_hash="$(jq -r '.anchor_block_hash // empty' "$direct_cli_withdraw_witness_json" 2>/dev/null || true)"
    [[ "$direct_cli_withdraw_final_orchard_root" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1
    [[ "$direct_cli_withdraw_anchor_height" =~ ^[0-9]+$ ]] || return 1
    [[ "$direct_cli_withdraw_anchor_hash" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1

    direct_cli_bridge_summary="$workdir/reports/direct-cli-user-proof-summary.json"
    direct_cli_bridge_log="$workdir/reports/direct-cli-user-proof.log"
    direct_cli_bridge_run_args=("${direct_cli_bridge_base_args[@]}")
    direct_cli_bridge_run_args+=(
      "--output" "$direct_cli_bridge_summary"
      "--existing-wjuno-address" "$direct_cli_deployed_wjuno_address"
      "--existing-operator-registry-address" "$direct_cli_deployed_operator_registry_address"
      "--existing-fee-distributor-address" "$direct_cli_deployed_fee_distributor_address"
      "--existing-bridge-address" "$direct_cli_deployed_bridge_address"
      "--deposit-final-orchard-root" "$direct_cli_deposit_final_orchard_root"
      "--withdraw-final-orchard-root" "$direct_cli_withdraw_final_orchard_root"
      "--deposit-checkpoint-height" "$direct_cli_deposit_anchor_height"
      "--deposit-checkpoint-block-hash" "$direct_cli_deposit_anchor_hash"
      "--withdraw-checkpoint-height" "$direct_cli_withdraw_anchor_height"
      "--withdraw-checkpoint-block-hash" "$direct_cli_withdraw_anchor_hash"
    )
    direct_cli_bridge_run_args+=("--sp1-deposit-owallet-ivk-hex" "$sp1_deposit_owallet_ivk_hex")
    direct_cli_bridge_run_args+=("--sp1-withdraw-owallet-ovk-hex" "$sp1_withdraw_owallet_ovk_hex")
    direct_cli_bridge_run_args+=("--sp1-deposit-witness-item-file" "$direct_cli_deposit_witness_file")
    direct_cli_bridge_run_args+=("--sp1-withdraw-witness-item-file" "$direct_cli_withdraw_witness_file")

    set +e
    (
      cd "$REPO_ROOT"
      env "${bridge_operator_signer_env[@]}" go run ./cmd/bridge-e2e "${direct_cli_bridge_run_args[@]}"
    ) >"$direct_cli_bridge_log" 2>&1
    direct_cli_status="$?"
    set -e
    if (( direct_cli_status != 0 )); then
      tail -n 200 "$direct_cli_bridge_log" >&2 || true
      return 1
    fi

    direct_cli_user_proof_submission_mode="$(jq -r '.proof.sp1.submission_mode // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    direct_cli_user_proof_deposit_request_id="$(jq -r '.proof.sp1.deposit_request_id // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    direct_cli_user_proof_withdraw_request_id="$(jq -r '.proof.sp1.withdraw_request_id // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    [[ "$direct_cli_user_proof_submission_mode" == "$direct_cli_proof_submission_mode" ]] || return 1
    [[ -n "$direct_cli_user_proof_deposit_request_id" ]] || return 1
    [[ -n "$direct_cli_user_proof_withdraw_request_id" ]] || return 1

    direct_cli_user_proof_status="passed"
    direct_cli_user_proof_summary_path="$direct_cli_bridge_summary"
    direct_cli_user_proof_log="$direct_cli_bridge_log"
    return 0
  }

  proof_requestor_log=""
  proof_funder_log=""
  proof_services_mode="shared-ecs"
  local proof_requestor_owner="testnet-e2e-proof-requestor-${proof_topic_seed}"
  local proof_funder_owner="testnet-e2e-proof-funder-${proof_topic_seed}"
  shared_ecs_region=""
  shared_ecs_started="false"

  shared_ecs_region="$(resolve_aws_region)"

    local -a proof_requestor_ecs_command=(
      "/usr/local/bin/proof-requestor"
      "--postgres-dsn" "$shared_postgres_dsn"
      "--store-driver" "postgres"
      "--owner" "$proof_requestor_owner"
      "--sp1-requestor-address" "$sp1_requestor_address"
      "--sp1-requestor-key-secret-arn" "PROOF_REQUESTOR_KEY"
      "--sp1-requestor-key-env" "PROOF_REQUESTOR_KEY"
      "--secrets-driver" "env"
      "--chain-id" "$base_chain_id"
      "--input-topic" "$proof_request_topic"
      "--result-topic" "$proof_result_topic"
      "--failure-topic" "$proof_failure_topic"
      "--max-inflight-requests" "32"
      "--request-timeout" "$sp1_request_timeout"
      "--queue-driver" "kafka"
      "--queue-brokers" "$shared_kafka_brokers"
      "--queue-group" "$proof_requestor_group"
      "--sp1-bin" "/usr/local/bin/sp1-prover-adapter"
    )
    local -a proof_funder_ecs_command=(
      "/usr/local/bin/proof-funder"
      "--postgres-dsn" "$shared_postgres_dsn"
      "--lease-driver" "postgres"
      "--owner-id" "$proof_funder_owner"
      "--sp1-requestor-address" "$sp1_requestor_address"
      "--min-balance-wei" "$sp1_required_credit_buffer_wei"
      "--critical-balance-wei" "$sp1_critical_credit_threshold_wei"
      "--queue-driver" "kafka"
      "--queue-brokers" "$shared_kafka_brokers"
      "--sp1-bin" "/usr/local/bin/sp1-prover-adapter"
    )
    local proof_requestor_ecs_command_json
    local proof_funder_ecs_command_json
    local proof_requestor_ecs_environment_json
    local proof_funder_ecs_environment_json
    proof_requestor_ecs_command_json="$(json_array_from_args "${proof_requestor_ecs_command[@]}")"
    proof_funder_ecs_command_json="$(json_array_from_args "${proof_funder_ecs_command[@]}")"
	    proof_requestor_ecs_environment_json="$(jq -n \
	      --arg sp1_network_rpc_url "$sp1_rpc_url" \
	      --arg sp1_max_price_per_pgu "$sp1_max_price_per_pgu" \
	      --arg sp1_min_auction_period "$sp1_min_auction_period" \
	      --arg sp1_auction_timeout_seconds "${sp1_auction_timeout%s}" \
	      --arg sp1_request_timeout_seconds "${sp1_request_timeout%s}" \
	      --arg deposit_program_url "$sp1_deposit_program_url" \
	      --arg withdraw_program_url "$sp1_withdraw_program_url" \
	      --arg deposit_vkey "$bridge_deposit_image_id" \
	      --arg withdraw_vkey "$bridge_withdraw_image_id" \
	      '[
	        {name:"JUNO_QUEUE_KAFKA_TLS", value:"true"},
	        {name:"SP1_NETWORK_RPC_URL", value:$sp1_network_rpc_url},
	        {name:"SP1_MAX_PRICE_PER_PGU", value:$sp1_max_price_per_pgu},
	        {name:"SP1_MIN_AUCTION_PERIOD", value:$sp1_min_auction_period},
	        {name:"SP1_AUCTION_TIMEOUT_SECONDS", value:$sp1_auction_timeout_seconds},
        {name:"SP1_REQUEST_TIMEOUT_SECONDS", value:$sp1_request_timeout_seconds},
        {name:"SP1_DEPOSIT_PROGRAM_URL", value:$deposit_program_url},
        {name:"SP1_WITHDRAW_PROGRAM_URL", value:$withdraw_program_url},
        {name:"SP1_DEPOSIT_PROGRAM_VKEY", value:$deposit_vkey},
        {name:"SP1_WITHDRAW_PROGRAM_VKEY", value:$withdraw_vkey}
      ]')"
	    proof_funder_ecs_environment_json="$(jq -n \
	      --arg sp1_network_rpc_url "$sp1_rpc_url" \
	      --arg deposit_program_url "$sp1_deposit_program_url" \
	      --arg withdraw_program_url "$sp1_withdraw_program_url" \
	      --arg deposit_vkey "$bridge_deposit_image_id" \
	      --arg withdraw_vkey "$bridge_withdraw_image_id" \
	      '[
	        {name:"JUNO_QUEUE_KAFKA_TLS", value:"true"},
	        {name:"SP1_NETWORK_RPC_URL", value:$sp1_network_rpc_url},
	        {name:"SP1_DEPOSIT_PROGRAM_URL", value:$deposit_program_url},
	        {name:"SP1_WITHDRAW_PROGRAM_URL", value:$withdraw_program_url},
	        {name:"SP1_DEPOSIT_PROGRAM_VKEY", value:$deposit_vkey},
        {name:"SP1_WITHDRAW_PROGRAM_VKEY", value:$withdraw_vkey}
      ]')"

    log "rolling out shared ECS proof-requestor/proof-funder services"
    rollout_shared_proof_services_ecs \
      "$shared_ecs_region" \
      "$shared_ecs_cluster_arn" \
      "$shared_proof_requestor_service_name" \
      "$shared_proof_funder_service_name" \
      "$proof_requestor_ecs_command_json" \
      "$proof_funder_ecs_command_json" \
      "$proof_requestor_ecs_environment_json" \
      "$proof_funder_ecs_environment_json"
  shared_ecs_started="true"
  stage_shared_services_stable="true"
  maybe_stop_after_stage "shared_services_ready"
  if [[ "$stage_stop_after_stage_reached" == "true" ]]; then
    return 0
  fi

  if [[ "${JUNO_E2E_ENABLE_DIRECT_CLI_USER_PROOF:-0}" != "1" ]]; then
    direct_cli_user_proof_status="skipped-runner-orchestration-only"
    log "skipping direct-cli user proof scenario; runner SP1 proof submission is disabled (shared services own SP1 lifecycle)"
  elif [[ "$stop_after_stage" == "checkpoint_validated" ]]; then
    direct_cli_user_proof_status="skipped-stop-after-stage-checkpoint_validated"
    log "skipping direct-cli user proof scenario for stop-after-stage=checkpoint_validated"
  elif [[ -n "$existing_bridge_summary_path" ]]; then
    direct_cli_user_proof_status="skipped-resume-existing-bridge-summary"
    log "skipping direct-cli user proof scenario during resume with existing bridge summary path=$existing_bridge_summary_path"
  else
    direct_cli_user_proof_status="running"
    if ! run_direct_cli_user_proof_scenario; then
      direct_cli_user_proof_status="failed"
      log "direct-cli user proof scenario failed; showing shared ECS proof service logs"
      dump_shared_proof_services_ecs_logs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name"
      die "direct-cli user proof scenario failed"
    fi
  fi

  local bridge_status=0
  if [[ -n "$existing_bridge_summary_path" ]]; then
    log "skipping bridge deploy bootstrap; using existing bridge summary path=$bridge_summary"
  else
    set +e
    (
      cd "$REPO_ROOT"
      go run ./cmd/bridge-e2e --deploy-only "${bridge_args[@]}"
    )
    bridge_status="$?"
    set -e
    if (( bridge_status != 0 )); then
      log "bridge-e2e deploy bootstrap failed; showing shared ECS proof service logs"
      dump_shared_proof_services_ecs_logs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name"
      die "bridge-e2e deploy bootstrap failed while centralized proof services were running"
    fi
  fi

  local deployed_bridge_address deployed_wjuno_address
  deployed_bridge_address="$(jq -r '.contracts.bridge // empty' "$bridge_summary")"
  deployed_wjuno_address="$(jq -r '.contracts.wjuno // empty' "$bridge_summary")"
  [[ "$deployed_bridge_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
    die "bridge summary missing deployed contracts.bridge address: $bridge_summary"
  [[ "$deployed_wjuno_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
    die "bridge summary missing deployed contracts.wjuno address: $bridge_summary"

  if [[ "$shared_enabled" == "true" ]]; then
    local checkpoint_started_at
    checkpoint_started_at="$(timestamp_utc)"
    stage_checkpoint_bridge_config_update_target="0"
    stage_checkpoint_bridge_config_update_success="0"

    if [[ "$relayer_runtime_mode" == "distributed" ]]; then
      (( ${#relayer_runtime_operator_hosts[@]} > 0 )) || \
        die "shared checkpoint validation requires --relayer-runtime-operator-hosts when --relayer-runtime-mode=distributed"
      [[ -n "$relayer_runtime_operator_ssh_user" ]] || \
        die "shared checkpoint validation requires --relayer-runtime-operator-ssh-user when --relayer-runtime-mode=distributed"
      [[ -f "$relayer_runtime_operator_ssh_key_file" ]] || \
        die "shared checkpoint validation requires readable --relayer-runtime-operator-ssh-key-file when --relayer-runtime-mode=distributed"

      local -a checkpoint_operator_ids=()
      local -a checkpoint_operator_key_files=()
      mapfile -t checkpoint_operator_ids < <(jq -r '.operators[].operator_id' "$dkg_summary")
      mapfile -t checkpoint_operator_key_files < <(jq -r '.operators[].operator_key_file // empty' "$dkg_summary")
      (( ${#checkpoint_operator_ids[@]} == ${#relayer_runtime_operator_hosts[@]} )) || \
        die "checkpoint host list length does not match dkg summary operators: hosts=${#relayer_runtime_operator_hosts[@]} operators=${#checkpoint_operator_ids[@]}"
      (( ${#checkpoint_operator_key_files[@]} == ${#relayer_runtime_operator_hosts[@]} )) || \
        die "checkpoint key list length does not match dkg summary operators: hosts=${#relayer_runtime_operator_hosts[@]} keys=${#checkpoint_operator_key_files[@]}"
      stage_checkpoint_bridge_config_update_target="${#relayer_runtime_operator_hosts[@]}"
      local checkpoint_runtime_aws_region
      checkpoint_runtime_aws_region="$(trim "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}")"

      local checkpoint_host checkpoint_operator_id checkpoint_operator_key_file checkpoint_operator_key_hex checkpoint_idx
      for ((checkpoint_idx = 0; checkpoint_idx < ${#relayer_runtime_operator_hosts[@]}; checkpoint_idx++)); do
        checkpoint_host="${relayer_runtime_operator_hosts[$checkpoint_idx]}"
        checkpoint_operator_id="${checkpoint_operator_ids[$checkpoint_idx]}"
        checkpoint_operator_key_file="${checkpoint_operator_key_files[$checkpoint_idx]}"
        [[ -n "$checkpoint_operator_id" ]] || \
          die "checkpoint operator id is missing for host=$checkpoint_host index=$checkpoint_idx"
        checkpoint_operator_key_hex="$(operator_signer_key_hex_from_file "$checkpoint_operator_key_file" || true)"
        [[ "$checkpoint_operator_key_hex" =~ ^0x[0-9a-f]{64}$ ]] || \
          die "checkpoint operator signer key is invalid for host=$checkpoint_host path=$checkpoint_operator_key_file"
        log "updating operator checkpoint bridge config host=$checkpoint_host operator=$checkpoint_operator_id bridge=$deployed_bridge_address"
        configure_remote_operator_checkpoint_services_for_bridge \
          "$checkpoint_host" \
          "$relayer_runtime_operator_ssh_user" \
          "$relayer_runtime_operator_ssh_key_file" \
          "$deployed_bridge_address" \
          "$base_chain_id" \
          "$checkpoint_operator_id" \
          "$checkpoint_operator_key_hex" \
          "$checkpoint_runtime_aws_region" \
          "$shared_postgres_dsn" \
          "$shared_kafka_brokers" \
          "$shared_ipfs_api_url" || \
          die "failed to update checkpoint bridge config on host=$checkpoint_host"
        stage_checkpoint_bridge_config_update_success="$((stage_checkpoint_bridge_config_update_success + 1))"
      done
    fi

    log "validating operator-service checkpoint publication via shared infra"
    local shared_status=0
    local shared_validation_no_fresh_package_pattern
    shared_validation_no_fresh_package_pattern='no operator checkpoint package with IPFS CID found in checkpoint_packages persisted_at >='
    local shared_validation_log
    shared_validation_log="$(mktemp)"
    run_shared_infra_validation_attempt() {
      local checkpoint_min_persisted_at="$1"
      local shared_validation_output_path="${2:-$shared_summary}"
      (
        cd "$REPO_ROOT"
	        go run ./cmd/shared-infra-e2e \
	          --postgres-dsn "$shared_postgres_dsn" \
	          --kafka-brokers "$shared_kafka_brokers" \
	          --checkpoint-ipfs-api-url "$shared_ipfs_api_url" \
	          --checkpoint-operators "$checkpoint_operators_csv" \
	          --checkpoint-threshold "$threshold" \
	          --checkpoint-min-persisted-at "$checkpoint_min_persisted_at" \
	          --required-kafka-topics "${checkpoint_signature_topic},${checkpoint_package_topic},${proof_request_topic},${proof_result_topic},${proof_failure_topic},${deposit_event_topic},${withdraw_request_topic}" \
	          --topic-prefix "$shared_topic_prefix" \
	          --timeout "$shared_timeout" \
	          --output "$shared_validation_output_path"
	      )
	    }

    set +e
    run_shared_infra_validation_attempt "$checkpoint_started_at" 2>&1 | tee "$shared_validation_log"
    shared_status="${PIPESTATUS[0]}"
    set -e

    if (( shared_status != 0 )) && grep -q "$shared_validation_no_fresh_package_pattern" "$shared_validation_log"; then
      local checkpoint_relaxed_min_persisted_at
      checkpoint_relaxed_min_persisted_at="$(date -u -d "$checkpoint_started_at - 30 minutes" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
      if [[ -z "$checkpoint_relaxed_min_persisted_at" ]]; then
        checkpoint_relaxed_min_persisted_at="$(date -u -d '30 minutes ago' +"%Y-%m-%dT%H:%M:%SZ")"
      fi
      log "shared infra validation found no fresh checkpoint package after checkpoint_started_at=$checkpoint_started_at; retrying with relaxed checkpoint-min-persisted-at=$checkpoint_relaxed_min_persisted_at"

      set +e
      run_shared_infra_validation_attempt "$checkpoint_relaxed_min_persisted_at" 2>&1 | tee -a "$shared_validation_log"
      shared_status="${PIPESTATUS[0]}"
      set -e
    fi
    if (( shared_status != 0 )) &&
      [[ "$stop_after_stage" == "checkpoint_validated" ]] &&
      [[ -n "$existing_bridge_summary_path" ]] &&
      grep -q "$shared_validation_no_fresh_package_pattern" "$shared_validation_log"; then
      local checkpoint_canary_min_persisted_at
      checkpoint_canary_min_persisted_at="$(date -u -d "$checkpoint_started_at - 6 hours" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
      if [[ -z "$checkpoint_canary_min_persisted_at" ]]; then
        checkpoint_canary_min_persisted_at="$(date -u -d '6 hours ago' +"%Y-%m-%dT%H:%M:%SZ")"
      fi
      log "checkpoint-stage canary with existing bridge summary still found no fresh package; retrying with extended checkpoint-min-persisted-at=$checkpoint_canary_min_persisted_at"

      set +e
      run_shared_infra_validation_attempt "$checkpoint_canary_min_persisted_at" 2>&1 | tee -a "$shared_validation_log"
      shared_status="${PIPESTATUS[0]}"
      set -e
    fi
    rm -f "$shared_validation_log"

    if (( shared_status != 0 )); then
      die "shared infra validation failed (operator-service checkpoint publication)"
    fi
    stage_checkpoint_shared_validation_passed="true"
    maybe_stop_after_stage "checkpoint_validated"
    if [[ "$stage_stop_after_stage_reached" == "true" ]]; then
      return 0
    fi
  fi

  local bridge_deployer_key_hex
  bridge_deployer_key_hex="$(trimmed_file_value "$bridge_deployer_key_file")"
  [[ -n "$bridge_deployer_key_hex" ]] || die "bridge deployer key file is empty: $bridge_deployer_key_file"

  local bridge_fee_bps bridge_relayer_tip_bps bridge_fee_distributor
  local bridge_refund_window_seconds bridge_max_expiry_extension_seconds
  local owner_wjuno_balance_before recipient_wjuno_balance_before
  local fee_distributor_wjuno_balance_before bridge_wjuno_balance_before
  bridge_fee_bps="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_bridge_address" \
      "feeBps()" \
      "feeBps()(uint96)"
  )"
  bridge_relayer_tip_bps="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_bridge_address" \
      "relayerTipBps()" \
      "relayerTipBps()(uint96)"
  )"
  bridge_fee_distributor="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_bridge_address" \
      "feeDistributor()" \
      "feeDistributor()(address)"
  )"
  bridge_refund_window_seconds="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_bridge_address" \
      "refundWindowSeconds()" \
      "refundWindowSeconds()(uint64)"
  )"
  bridge_max_expiry_extension_seconds="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_bridge_address" \
      "maxExpiryExtensionSeconds()" \
      "maxExpiryExtensionSeconds()(uint64)"
  )"
  [[ "$bridge_fee_bps" =~ ^[0-9]+$ ]] || die "bridge feeBps is invalid: $bridge_fee_bps"
  [[ "$bridge_relayer_tip_bps" =~ ^[0-9]+$ ]] || die "bridge relayerTipBps is invalid: $bridge_relayer_tip_bps"
  [[ "$bridge_fee_distributor" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "bridge feeDistributor is invalid: $bridge_fee_distributor"
  [[ "$bridge_refund_window_seconds" =~ ^[0-9]+$ ]] || \
    die "bridge refundWindowSeconds is invalid: $bridge_refund_window_seconds"
  [[ "$bridge_max_expiry_extension_seconds" =~ ^[0-9]+$ ]] || \
    die "bridge maxExpiryExtensionSeconds is invalid: $bridge_max_expiry_extension_seconds"
  owner_wjuno_balance_before="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_wjuno_address" \
      "balanceOf(address)" \
      "balanceOf(address)(uint256)" \
      "$bridge_deployer_address"
  )"
  recipient_wjuno_balance_before="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_wjuno_address" \
      "balanceOf(address)" \
      "balanceOf(address)(uint256)" \
      "$bridge_recipient_address"
  )"
  fee_distributor_wjuno_balance_before="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_wjuno_address" \
      "balanceOf(address)" \
      "balanceOf(address)(uint256)" \
      "$bridge_fee_distributor"
  )"
  bridge_wjuno_balance_before="$(
    cast_contract_call_one \
      "$base_rpc_url" \
      "$deployed_wjuno_address" \
      "balanceOf(address)" \
      "balanceOf(address)(uint256)" \
      "$deployed_bridge_address"
  )"
  [[ "$owner_wjuno_balance_before" =~ ^-?[0-9]+$ ]] || die "owner wjuno balance is invalid before run: $owner_wjuno_balance_before"
  [[ "$recipient_wjuno_balance_before" =~ ^-?[0-9]+$ ]] || die "recipient wjuno balance is invalid before run: $recipient_wjuno_balance_before"
  [[ "$fee_distributor_wjuno_balance_before" =~ ^-?[0-9]+$ ]] || \
    die "fee distributor wjuno balance is invalid before run: $fee_distributor_wjuno_balance_before"
  [[ "$bridge_wjuno_balance_before" =~ ^-?[0-9]+$ ]] || die "bridge wjuno balance is invalid before run: $bridge_wjuno_balance_before"

  local run_deposit_id=""
  local run_deposit_amount=""
  local run_deposit_nonce=""
  local run_deposit_juno_tx_hash=""
  local run_deposit_witness_file=""
  local run_withdrawal_id=""
  local run_withdraw_requester=""
  local run_withdraw_amount=""
  local run_withdraw_fee_bps=""
  local run_withdraw_recipient_ua=""
  local run_withdraw_request_expiry=""
  local bridge_api_deposit_state=""
  local bridge_api_withdraw_state=""
  local invariant_deposit_used="false"
  local invariant_withdraw_requester=""
  local invariant_withdraw_amount=""
  local invariant_withdraw_fee_bps=""
  local invariant_withdraw_expiry=""
  local invariant_withdraw_expiry_extended_vs_request="false"
  local invariant_withdraw_finalized="false"
  local invariant_withdraw_refunded="true"
  local invariant_withdraw_recipient_ua=""
  local invariant_owner_delta_expected=""
  local invariant_owner_delta_actual=""
  local invariant_recipient_delta_expected=""
  local invariant_recipient_delta_actual=""
  local invariant_recipient_delta_raw=""
  local invariant_fee_distributor_delta_expected=""
  local invariant_fee_distributor_delta_actual=""
  local invariant_bridge_delta_expected=""
  local invariant_bridge_delta_actual=""
  local invariant_balance_delta_match="false"
  local coordinator_payout_juno_tx_hash=""
  local operator_down_1_status="not-run"
  local operator_down_2_status="not-run"
  local operator_down_1_endpoint=""
  local operator_down_2_endpoint=""
  local operator_down_1_signature_count=""
  local operator_down_2_signature_count=""
  local refund_after_expiry_status="not-run"
  local refund_after_expiry_withdrawal_id=""
  local refund_after_expiry_request_expiry=""
  local refund_after_expiry_refund_tx_hash=""
  local refund_after_expiry_on_chain_refunded="false"
  local operator_down_ssh_key_path="$REPO_ROOT/.ci/secrets/operator-fleet-ssh.key"
  local operator_down_ssh_user=""
  local -a operator_signer_endpoints=()
  local -a operator_signer_key_hexes=()
  local -a operator_signer_active_key_hexes=()
  local operator_signer_supports_endpoints="$bridge_operator_signer_supports_operator_endpoint"
  local operator_failures_injected=0

  local base_relayer_log="$workdir/reports/base-relayer.log"
  local deposit_relayer_log="$workdir/reports/deposit-relayer.log"
  local withdraw_coordinator_log="$workdir/reports/withdraw-coordinator.log"
  local withdraw_finalizer_log="$workdir/reports/withdraw-finalizer.log"
  local bridge_api_log="$workdir/reports/bridge-api.log"
  local base_relayer_pid=""
  local deposit_relayer_pid=""
  local withdraw_coordinator_pid=""
  local withdraw_finalizer_pid=""
  local bridge_api_pid=""
  local bridge_api_port="$((base_port + 1250))"
  local bridge_api_url="http://127.0.0.1:${bridge_api_port}"
  local relayer_status=0
  local base_relayer_host=""
  local deposit_relayer_host=""
  local withdraw_coordinator_host=""
  local withdraw_finalizer_host=""
  local distributed_withdraw_coordinator_tss_server_ca_file="$withdraw_coordinator_tss_server_ca_file"
  local distributed_withdraw_coordinator_tss_url="$withdraw_coordinator_tss_url"
  local distributed_withdraw_coordinator_juno_rpc_url="$sp1_witness_juno_rpc_url"
  local distributed_withdraw_finalizer_juno_scan_url="$sp1_witness_juno_scan_url"
  local distributed_withdraw_finalizer_juno_rpc_url="$sp1_witness_juno_rpc_url"
  : >"$base_relayer_log"
  : >"$deposit_relayer_log"
  : >"$withdraw_coordinator_log"
  : >"$withdraw_finalizer_log"
  : >"$bridge_api_log"
  log "stopping stale local relayer processes before launch"
  stop_local_relayer_binaries
  free_local_tcp_port "$bridge_api_port"

  operator_down_ssh_user="$(id -un 2>/dev/null || true)"
  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    operator_down_ssh_user="$relayer_runtime_operator_ssh_user"
    operator_down_ssh_key_path="$relayer_runtime_operator_ssh_key_file"
  fi
  operator_signer_endpoints=("${bridge_operator_endpoints[@]}")
  operator_signer_key_hexes=("${bridge_operator_key_hexes[@]}")
  operator_signer_active_key_hexes=("${operator_signer_key_hexes[@]}")
  if (( ${#operator_signer_endpoints[@]} < threshold )); then
    die "operator endpoint count is below threshold for chaos scenarios: endpoints=${#operator_signer_endpoints[@]} threshold=$threshold"
  fi
  if (( ${#operator_signer_key_hexes[@]} < threshold )); then
    die "operator key count is below threshold for chaos scenarios: keys=${#operator_signer_key_hexes[@]} threshold=$threshold"
  fi

  local base_relayer_port base_relayer_url base_relayer_auth_token
  base_relayer_port="$((base_port + 1200))"
  base_relayer_auth_token="$(openssl rand -hex 24)"
  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    local relayer_host_count
    relayer_host_count="${#relayer_runtime_operator_hosts[@]}"
    (( relayer_host_count > 0 )) || \
      die "--relayer-runtime-operator-hosts must include at least one host when --relayer-runtime-mode=distributed"
    base_relayer_host="${relayer_runtime_operator_hosts[0]}"
    base_relayer_url="http://${base_relayer_host}:${base_relayer_port}"

    deposit_relayer_host="${relayer_runtime_operator_hosts[0]}"
    withdraw_coordinator_host="${relayer_runtime_operator_hosts[0]}"
    withdraw_finalizer_host="${relayer_runtime_operator_hosts[$((1 % relayer_host_count))]}"
    distributed_withdraw_coordinator_tss_url="https://127.0.0.1:9443"
    distributed_withdraw_coordinator_juno_rpc_url="http://127.0.0.1:18232"
    distributed_withdraw_finalizer_juno_scan_url="http://127.0.0.1:8080"
    distributed_withdraw_finalizer_juno_rpc_url="http://127.0.0.1:18232"
    distributed_withdraw_coordinator_tss_server_ca_file="/tmp/testnet-e2e-witness-tss-ca.pem"

    log "distributed relayer runtime enabled; launching relayers on operator hosts"
    log "base-relayer host=$base_relayer_host"
    log "deposit-relayer host=$deposit_relayer_host"
    log "withdraw-coordinator host=$withdraw_coordinator_host"
    log "withdraw-finalizer host=$withdraw_finalizer_host"
    log "distributed relayer runtime enabled; stopping stale remote relayer processes before launch"

    local -a relayer_cleanup_hosts=()
    local -A relayer_cleanup_seen=()
    local relayer_cleanup_host=""
    for relayer_cleanup_host in "$base_relayer_host" "$deposit_relayer_host" "$withdraw_coordinator_host" "$withdraw_finalizer_host"; do
      [[ -n "$relayer_cleanup_host" ]] || continue
      if [[ -n "${relayer_cleanup_seen[$relayer_cleanup_host]:-}" ]]; then
        continue
      fi
      relayer_cleanup_hosts+=("$relayer_cleanup_host")
      relayer_cleanup_seen["$relayer_cleanup_host"]="1"
    done
    for relayer_cleanup_host in "${relayer_cleanup_hosts[@]}"; do
      if ! stop_remote_relayer_binaries_on_host \
        "$relayer_cleanup_host" \
        "$relayer_runtime_operator_ssh_user" \
        "$relayer_runtime_operator_ssh_key_file" \
        "$base_relayer_port" \
        "$bridge_api_port"; then
        log "failed to stop stale remote relayer processes host=$relayer_cleanup_host; marking relayer launch failed"
        relayer_status=1
      fi
    done

    if (( relayer_status == 0 )); then
      if ! stage_remote_runtime_file \
        "$withdraw_coordinator_tss_server_ca_file" \
        "$withdraw_coordinator_host" \
        "$relayer_runtime_operator_ssh_user" \
        "$relayer_runtime_operator_ssh_key_file" \
        "$distributed_withdraw_coordinator_tss_server_ca_file"; then
        relayer_status=1
      fi
    fi
  else
    base_relayer_url="http://127.0.0.1:${base_relayer_port}"
  fi

  if (( relayer_status == 0 )); then
    log "ensuring bridge operator signer for withdraw coordinator relayer flow"
    ensure_bridge_operator_signer_ready
  fi

  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    base_relayer_pid="$(
      start_remote_relayer_service \
        "$base_relayer_host" \
        "$relayer_runtime_operator_ssh_user" \
        "$relayer_runtime_operator_ssh_key_file" \
        "$base_relayer_log" \
        env \
        BASE_RELAYER_PRIVATE_KEYS="$bridge_deployer_key_hex" \
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
        /usr/local/bin/base-relayer \
        --rpc-url "$base_rpc_url" \
        --chain-id "$base_chain_id" \
        --listen "0.0.0.0:${base_relayer_port}"
    )"
  else
    (
      cd "$REPO_ROOT"
      BASE_RELAYER_PRIVATE_KEYS="$bridge_deployer_key_hex" \
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
        go run ./cmd/base-relayer \
          --rpc-url "$base_rpc_url" \
          --chain-id "$base_chain_id" \
          --listen "127.0.0.1:${base_relayer_port}" \
          >"$base_relayer_log" 2>&1
    ) &
    base_relayer_pid="$!"
  fi
  sleep 3
  if ! kill -0 "$base_relayer_pid" >/dev/null 2>&1; then
    relayer_status=1
  fi

  if (( relayer_status == 0 )); then
    if [[ "$relayer_runtime_mode" == "distributed" ]]; then
      deposit_relayer_pid="$(
        start_remote_relayer_service \
          "$deposit_relayer_host" \
          "$relayer_runtime_operator_ssh_user" \
          "$relayer_runtime_operator_ssh_key_file" \
          "$deposit_relayer_log" \
          env \
          BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
          /usr/local/bin/deposit-relayer \
          --postgres-dsn "$shared_postgres_dsn" \
          --store-driver postgres \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --operators "$checkpoint_operators_csv" \
          --operator-threshold "$threshold" \
          --deposit-image-id "$bridge_deposit_image_id" \
          --owallet-ivk "$sp1_deposit_owallet_ivk_hex" \
          --base-relayer-url "$base_relayer_url" \
          --owner "testnet-e2e-deposit-relayer-${proof_topic_seed}" \
          --proof-driver queue \
          --proof-request-topic "$proof_request_topic" \
          --proof-result-topic "$proof_result_topic" \
          --proof-failure-topic "$proof_failure_topic" \
          --proof-response-group "$deposit_relayer_proof_group" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$deposit_relayer_group" \
          --queue-topics "$deposit_event_topic,$checkpoint_package_topic"
      )"

      withdraw_coordinator_pid="$(
        start_remote_relayer_service \
          "$withdraw_coordinator_host" \
          "$relayer_runtime_operator_ssh_user" \
          "$relayer_runtime_operator_ssh_key_file" \
          "$withdraw_coordinator_log" \
          env \
          BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
          "$sp1_witness_juno_rpc_user_env=$withdraw_coordinator_juno_rpc_user_value" \
          "$sp1_witness_juno_rpc_pass_env=$withdraw_coordinator_juno_rpc_pass_value" \
          /usr/local/bin/withdraw-coordinator \
          --postgres-dsn "$shared_postgres_dsn" \
          --owner "testnet-e2e-withdraw-coordinator-${proof_topic_seed}" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$withdraw_coordinator_group" \
          --queue-topics "$withdraw_request_topic" \
          --juno-rpc-url "$distributed_withdraw_coordinator_juno_rpc_url" \
          --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
          --juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-change-address "$withdraw_coordinator_juno_change_address" \
          --tss-url "$distributed_withdraw_coordinator_tss_url" \
          --tss-server-ca-file "$distributed_withdraw_coordinator_tss_server_ca_file" \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --base-relayer-url "$base_relayer_url" \
          --extend-signer-bin "$bridge_operator_signer_bin" \
          --extend-signer-max-response-bytes "1048576" \
          --expiry-safety-margin "30h" \
          --max-expiry-extension "12h" \
          --blob-driver s3 \
          --blob-bucket "$withdraw_blob_bucket" \
          --blob-prefix "$withdraw_blob_prefix"
      )"

      local -a withdraw_finalizer_remote_env=(
        env
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token"
        "$sp1_witness_juno_rpc_user_env=$withdraw_coordinator_juno_rpc_user_value"
        "$sp1_witness_juno_rpc_pass_env=$withdraw_coordinator_juno_rpc_pass_value"
      )
      if [[ -n "$withdraw_finalizer_juno_scan_bearer_value" ]]; then
        withdraw_finalizer_remote_env+=("$sp1_witness_juno_scan_bearer_token_env=$withdraw_finalizer_juno_scan_bearer_value")
      fi
      withdraw_finalizer_pid="$(
        start_remote_relayer_service \
          "$withdraw_finalizer_host" \
          "$relayer_runtime_operator_ssh_user" \
          "$relayer_runtime_operator_ssh_key_file" \
          "$withdraw_finalizer_log" \
          "${withdraw_finalizer_remote_env[@]}" \
          /usr/local/bin/withdraw-finalizer \
          --postgres-dsn "$shared_postgres_dsn" \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --operators "$checkpoint_operators_csv" \
          --operator-threshold "$threshold" \
          --withdraw-image-id "$bridge_withdraw_image_id" \
          --owallet-ovk "$sp1_withdraw_owallet_ovk_hex" \
          --withdraw-witness-extractor-enabled \
          --juno-scan-url "$distributed_withdraw_finalizer_juno_scan_url" \
          --juno-scan-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-scan-bearer-env "$sp1_witness_juno_scan_bearer_token_env" \
          --juno-rpc-url "$distributed_withdraw_finalizer_juno_rpc_url" \
          --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
          --base-relayer-url "$base_relayer_url" \
          --owner "testnet-e2e-withdraw-finalizer-${proof_topic_seed}" \
          --proof-driver queue \
          --proof-request-topic "$proof_request_topic" \
          --proof-result-topic "$proof_result_topic" \
          --proof-failure-topic "$proof_failure_topic" \
          --proof-response-group "$withdraw_finalizer_proof_group" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$withdraw_finalizer_group" \
          --queue-topics "$checkpoint_package_topic" \
          --blob-driver s3 \
          --blob-bucket "$withdraw_blob_bucket" \
          --blob-prefix "$withdraw_blob_prefix"
      )"
    else
      (
        cd "$REPO_ROOT"
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
          go run ./cmd/deposit-relayer \
            --postgres-dsn "$shared_postgres_dsn" \
            --store-driver postgres \
            --base-chain-id "$base_chain_id" \
            --bridge-address "$deployed_bridge_address" \
            --operators "$checkpoint_operators_csv" \
            --operator-threshold "$threshold" \
            --deposit-image-id "$bridge_deposit_image_id" \
            --owallet-ivk "$sp1_deposit_owallet_ivk_hex" \
            --base-relayer-url "$base_relayer_url" \
            --owner "testnet-e2e-deposit-relayer-${proof_topic_seed}" \
            --proof-driver queue \
            --proof-request-topic "$proof_request_topic" \
            --proof-result-topic "$proof_result_topic" \
            --proof-failure-topic "$proof_failure_topic" \
            --proof-response-group "$deposit_relayer_proof_group" \
            --queue-driver kafka \
            --queue-brokers "$shared_kafka_brokers" \
            --queue-group "$deposit_relayer_group" \
            --queue-topics "$deposit_event_topic,$checkpoint_package_topic" \
            >"$deposit_relayer_log" 2>&1
      ) &
      deposit_relayer_pid="$!"

      (
        cd "$REPO_ROOT"
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
        go run ./cmd/withdraw-coordinator \
          --postgres-dsn "$shared_postgres_dsn" \
          --owner "testnet-e2e-withdraw-coordinator-${proof_topic_seed}" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$withdraw_coordinator_group" \
          --queue-topics "$withdraw_request_topic" \
          --juno-rpc-url "$sp1_witness_juno_rpc_url" \
          --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
          --juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-change-address "$withdraw_coordinator_juno_change_address" \
          --tss-url "$withdraw_coordinator_tss_url" \
          --tss-server-ca-file "$withdraw_coordinator_tss_server_ca_file" \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --base-relayer-url "$base_relayer_url" \
          --extend-signer-bin "$bridge_operator_signer_bin" \
          --extend-signer-max-response-bytes "1048576" \
          --expiry-safety-margin "30h" \
          --max-expiry-extension "12h" \
          --blob-driver s3 \
          --blob-bucket "$withdraw_blob_bucket" \
          --blob-prefix "$withdraw_blob_prefix" \
          >"$withdraw_coordinator_log" 2>&1
      ) &
      withdraw_coordinator_pid="$!"

      (
        cd "$REPO_ROOT"
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
          go run ./cmd/withdraw-finalizer \
            --postgres-dsn "$shared_postgres_dsn" \
            --base-chain-id "$base_chain_id" \
            --bridge-address "$deployed_bridge_address" \
            --operators "$checkpoint_operators_csv" \
            --operator-threshold "$threshold" \
            --withdraw-image-id "$bridge_withdraw_image_id" \
            --owallet-ovk "$sp1_withdraw_owallet_ovk_hex" \
            --withdraw-witness-extractor-enabled \
            --juno-scan-url "$sp1_witness_juno_scan_url" \
            --juno-scan-wallet-id "$withdraw_coordinator_juno_wallet_id" \
            --juno-scan-bearer-env "$sp1_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$sp1_witness_juno_rpc_url" \
            --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
            --base-relayer-url "$base_relayer_url" \
            --owner "testnet-e2e-withdraw-finalizer-${proof_topic_seed}" \
            --proof-driver queue \
            --proof-request-topic "$proof_request_topic" \
            --proof-result-topic "$proof_result_topic" \
            --proof-failure-topic "$proof_failure_topic" \
            --proof-response-group "$withdraw_finalizer_proof_group" \
            --queue-driver kafka \
            --queue-brokers "$shared_kafka_brokers" \
            --queue-group "$withdraw_finalizer_group" \
            --queue-topics "$checkpoint_package_topic" \
            --blob-driver s3 \
            --blob-bucket "$withdraw_blob_bucket" \
            --blob-prefix "$withdraw_blob_prefix" \
            >"$withdraw_finalizer_log" 2>&1
      ) &
      withdraw_finalizer_pid="$!"
    fi

    sleep 5
    if ! kill -0 "$deposit_relayer_pid" >/dev/null 2>&1; then
      relayer_status=1
    fi
    if ! kill -0 "$withdraw_coordinator_pid" >/dev/null 2>&1; then
      relayer_status=1
    fi
    if ! kill -0 "$withdraw_finalizer_pid" >/dev/null 2>&1; then
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    (
      cd "$REPO_ROOT"
      go run ./cmd/bridge-api \
        --listen "127.0.0.1:${bridge_api_port}" \
        --postgres-dsn "$shared_postgres_dsn" \
        --base-chain-id "$base_chain_id" \
        --bridge-address "$deployed_bridge_address" \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --deposit-event-topic "$deposit_event_topic" \
        --withdraw-request-topic "$withdraw_request_topic" \
        --withdraw-rpc-url "$base_rpc_url" \
        --withdraw-chain-id "$base_chain_id" \
        --withdraw-owner-key-file "$bridge_deployer_key_file" \
        --wjuno-address "$deployed_wjuno_address" \
        --owallet-ua "$withdraw_coordinator_juno_change_address" \
        --refund-window-seconds "$bridge_refund_window_seconds" \
        >"$bridge_api_log" 2>&1
    ) &
    bridge_api_pid="$!"
    sleep 3
    if ! kill -0 "$bridge_api_pid" >/dev/null 2>&1; then
      relayer_status=1
    else
      check_bridge_api_health() {
        curl -fsS "${bridge_api_url}/healthz" >/dev/null
      }
      if ! wait_for_condition 60 2 "bridge-api health" check_bridge_api_health; then
        relayer_status=1
      fi
    fi
  fi

  if (( relayer_status == 0 )) && [[ "$shared_enabled" == "true" ]]; then
    local relayer_checkpoint_seed_started_at relayer_checkpoint_seed_summary
    relayer_checkpoint_seed_started_at="$(timestamp_utc)"
    relayer_checkpoint_seed_summary="$workdir/reports/shared-infra-relayer-runtime-summary.json"
    log "seeding checkpoint package after relayer startup to ensure relayers ingest a fresh checkpoint"
    if ! run_shared_infra_validation_attempt "$relayer_checkpoint_seed_started_at" "$relayer_checkpoint_seed_summary"; then
      log "failed to seed relayer runtime checkpoint package after relayer startup"
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    if ! wait_for_log_pattern "$deposit_relayer_log" "updated checkpoint" 180; then
      log "deposit relayer did not ingest a checkpoint package after startup"
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    if ! wait_for_log_pattern "$withdraw_finalizer_log" "updated checkpoint" 180; then
      log "withdraw finalizer did not ingest a checkpoint package after startup"
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    local deposit_event_payload run_deposit_memo_json run_deposit_memo_hex
    local run_deposit_extract_json run_deposit_extract_error_file run_deposit_extract_last_error
    local run_deposit_amount_zat="100000"
    local run_deposit_extract_ok="false"
    local run_deposit_extract_wait_logged="false"
    local run_deposit_extract_sleep_seconds=5
    local run_deposit_extract_deadline_epoch
    local run_deposit_action_index_selected=""
    local -a run_deposit_action_indexes=()
    local -a run_deposit_action_indexes_rpc=()
    local -a run_deposit_scan_urls=()
    local -a run_deposit_rpc_urls=()
    local run_deposit_scan_upsert_count=0
    local run_deposit_scan_backfill_tx_height=""
    local run_deposit_scan_backfill_from_height=""
    local run_deposit_action_candidate

    [[ -n "$witness_funder_source_address" ]] || relayer_status=1
    [[ -n "$withdraw_coordinator_juno_wallet_id" ]] || relayer_status=1
    [[ -n "$withdraw_coordinator_juno_change_address" ]] || relayer_status=1

    if (( relayer_status == 0 )); then
      run_deposit_memo_json="$(curl -fsS "${bridge_api_url}/v1/deposit-memo?baseRecipient=${bridge_recipient_address}" || true)"
      [[ -n "$run_deposit_memo_json" ]] || relayer_status=1
      run_deposit_nonce="$(jq -r '.nonce // empty' <<<"$run_deposit_memo_json" 2>/dev/null || true)"
      run_deposit_memo_hex="$(jq -r '.memoHex // empty' <<<"$run_deposit_memo_json" 2>/dev/null || true)"
      [[ "$run_deposit_nonce" =~ ^[0-9]+$ ]] || relayer_status=1
      [[ "$run_deposit_memo_hex" =~ ^[0-9a-fA-F]{1024}$ ]] || relayer_status=1
    fi

    if (( relayer_status == 0 )); then
      run_deposit_juno_tx_hash="$(
        submit_juno_shielded_memo_tx \
          "$sp1_witness_juno_rpc_url" \
          "$withdraw_coordinator_juno_rpc_user_value" \
          "$withdraw_coordinator_juno_rpc_pass_value" \
          "$witness_funder_source_address" \
          "$withdraw_coordinator_juno_change_address" \
          "$run_deposit_amount_zat" \
          "$run_deposit_memo_hex" \
          900 || true
      )"
      run_deposit_juno_tx_hash="$(normalize_hex_prefixed "$run_deposit_juno_tx_hash" || true)"
      [[ "$run_deposit_juno_tx_hash" =~ ^0x[0-9a-f]{64}$ ]] || relayer_status=1
    fi

    if (( relayer_status == 0 )); then
      run_deposit_action_indexes=("0")
      mapfile -t run_deposit_action_indexes_rpc < <(
        witness_rpc_action_index_candidates \
          "$sp1_witness_juno_rpc_url" \
          "$withdraw_coordinator_juno_rpc_user_value" \
          "$withdraw_coordinator_juno_rpc_pass_value" \
          "$run_deposit_juno_tx_hash" || true
      )
      for run_deposit_action_candidate in "${run_deposit_action_indexes_rpc[@]}"; do
        [[ "$run_deposit_action_candidate" =~ ^[0-9]+$ ]] || continue
        if [[ ! " ${run_deposit_action_indexes[*]} " =~ " ${run_deposit_action_candidate} " ]]; then
          run_deposit_action_indexes+=("$run_deposit_action_candidate")
        fi
      done
      for run_deposit_action_candidate in 1 2 3; do
        if [[ ! " ${run_deposit_action_indexes[*]} " =~ " ${run_deposit_action_candidate} " ]]; then
          run_deposit_action_indexes+=("$run_deposit_action_candidate")
        fi
      done
      log "run deposit extraction action-index candidates: $(IFS=,; printf '%s' "${run_deposit_action_indexes[*]}")"
    fi

    if (( relayer_status == 0 )); then
      local run_deposit_scan_idx run_deposit_scan_url run_deposit_rpc_url
      if (( ${#witness_healthy_scan_urls[@]} > 0 )); then
        run_deposit_scan_urls=("${witness_healthy_scan_urls[@]}")
      else
        run_deposit_scan_urls=("$sp1_witness_juno_scan_url")
      fi
      if (( ${#witness_healthy_rpc_urls[@]} > 0 )); then
        run_deposit_rpc_urls=("${witness_healthy_rpc_urls[@]}")
      else
        run_deposit_rpc_urls=("$sp1_witness_juno_rpc_url")
      fi
      while (( ${#run_deposit_rpc_urls[@]} < ${#run_deposit_scan_urls[@]} )); do
        run_deposit_rpc_urls+=("$sp1_witness_juno_rpc_url")
      done

      run_deposit_scan_upsert_count="${#run_deposit_scan_urls[@]}"
      for ((run_deposit_scan_idx = 0; run_deposit_scan_idx < run_deposit_scan_upsert_count; run_deposit_scan_idx++)); do
        run_deposit_scan_url="${run_deposit_scan_urls[$run_deposit_scan_idx]}"
        if ! witness_scan_upsert_wallet "$run_deposit_scan_url" "$juno_scan_bearer_token" "$withdraw_coordinator_juno_wallet_id" "$sp1_witness_recipient_ufvk"; then
          log "run deposit witness wallet upsert failed for scan_url=$run_deposit_scan_url wallet=$withdraw_coordinator_juno_wallet_id (continuing)"
        fi
      done

      run_deposit_scan_backfill_tx_height="$(
        witness_rpc_tx_height \
          "$sp1_witness_juno_rpc_url" \
          "$withdraw_coordinator_juno_rpc_user_value" \
          "$withdraw_coordinator_juno_rpc_pass_value" \
          "$run_deposit_juno_tx_hash" || true
      )"
      if [[ "$run_deposit_scan_backfill_tx_height" =~ ^[0-9]+$ ]]; then
        run_deposit_scan_backfill_from_height="$run_deposit_scan_backfill_tx_height"
        if (( run_deposit_scan_backfill_from_height > 32 )); then
          run_deposit_scan_backfill_from_height=$((run_deposit_scan_backfill_from_height - 32))
        else
          run_deposit_scan_backfill_from_height=0
        fi
        for ((run_deposit_scan_idx = 0; run_deposit_scan_idx < run_deposit_scan_upsert_count; run_deposit_scan_idx++)); do
          run_deposit_scan_url="${run_deposit_scan_urls[$run_deposit_scan_idx]}"
          if ! witness_scan_backfill_wallet "$run_deposit_scan_url" "$juno_scan_bearer_token" "$withdraw_coordinator_juno_wallet_id" "$run_deposit_scan_backfill_from_height"; then
            log "run deposit witness backfill best-effort failed for scan_url=$run_deposit_scan_url wallet=$withdraw_coordinator_juno_wallet_id from_height=$run_deposit_scan_backfill_from_height"
          fi
        done
      else
        log "run deposit witness backfill tx height unknown; skipping proactive backfill txid=$run_deposit_juno_tx_hash"
      fi
    fi

    if (( relayer_status == 0 )); then
      local run_deposit_scan_idx run_deposit_scan_url run_deposit_rpc_url
      local run_deposit_selected_scan_url=""
      local run_deposit_indexed_wallet_id=""
      run_deposit_witness_file="$workdir/reports/witness/run-deposit.witness.bin"
      run_deposit_extract_json="$workdir/reports/witness/run-deposit-witness.json"
      run_deposit_extract_error_file="$workdir/reports/witness/run-deposit-witness.extract.err"
      run_deposit_extract_deadline_epoch=$(( $(date +%s) + 900 ))
      while true; do
        local run_deposit_note_pending="false"
        run_deposit_extract_ok="false"
        for ((run_deposit_scan_idx = 0; run_deposit_scan_idx < ${#run_deposit_scan_urls[@]}; run_deposit_scan_idx++)); do
          run_deposit_scan_url="${run_deposit_scan_urls[$run_deposit_scan_idx]}"
          run_deposit_rpc_url="${run_deposit_rpc_urls[$run_deposit_scan_idx]:-$sp1_witness_juno_rpc_url}"
          for run_deposit_action_candidate in "${run_deposit_action_indexes[@]}"; do
            rm -f "$run_deposit_extract_json"
            if (
              cd "$REPO_ROOT"
              go run ./cmd/juno-witness-extract deposit \
                --juno-scan-url "$run_deposit_scan_url" \
                --wallet-id "$withdraw_coordinator_juno_wallet_id" \
                --juno-scan-bearer-token-env "$sp1_witness_juno_scan_bearer_token_env" \
                --juno-rpc-url "$run_deposit_rpc_url" \
                --juno-rpc-user-env "$sp1_witness_juno_rpc_user_env" \
                --juno-rpc-pass-env "$sp1_witness_juno_rpc_pass_env" \
                --txid "$run_deposit_juno_tx_hash" \
                --action-index "$run_deposit_action_candidate" \
                --output-witness-item-file "$run_deposit_witness_file" \
                >"$run_deposit_extract_json" 2>"$run_deposit_extract_error_file"
            ); then
              run_deposit_extract_ok="true"
              run_deposit_action_index_selected="$run_deposit_action_candidate"
              run_deposit_selected_scan_url="$run_deposit_scan_url"
              rm -f "$run_deposit_extract_error_file"
              break
            fi
            run_deposit_extract_last_error="$(tail -n 1 "$run_deposit_extract_error_file" 2>/dev/null | tr -d '\r\n')"
            if grep -qi "note not found" "$run_deposit_extract_error_file"; then
              run_deposit_note_pending="true"
            fi
          done
          if [[ "$run_deposit_extract_ok" == "true" ]]; then
            break
          fi
          if [[ "$run_deposit_note_pending" == "true" ]]; then
            run_deposit_indexed_wallet_id="$(
              witness_scan_find_wallet_for_txid "$run_deposit_scan_url" "$juno_scan_bearer_token" "$run_deposit_juno_tx_hash" "$withdraw_coordinator_juno_wallet_id" || true
            )"
            if [[ -n "$run_deposit_indexed_wallet_id" && "$run_deposit_indexed_wallet_id" != "$withdraw_coordinator_juno_wallet_id" ]]; then
              log "run deposit switching witness wallet id during extraction old_wallet_id=$withdraw_coordinator_juno_wallet_id indexed_wallet_id=$run_deposit_indexed_wallet_id txid=$run_deposit_juno_tx_hash scan_url=$run_deposit_scan_url"
              withdraw_coordinator_juno_wallet_id="$run_deposit_indexed_wallet_id"
              run_deposit_extract_wait_logged="false"
              continue
            fi
          fi
        done
        if [[ "$run_deposit_extract_ok" == "true" ]]; then
          break
        fi
        if [[ "$run_deposit_note_pending" == "true" && "$run_deposit_extract_wait_logged" != "true" ]]; then
          log "run deposit witness note pending wallet=$withdraw_coordinator_juno_wallet_id txid=$run_deposit_juno_tx_hash scan_urls=$(IFS=,; printf '%s' "${run_deposit_scan_urls[*]}") action_index_candidates=$(IFS=,; printf '%s' "${run_deposit_action_indexes[*]}")"
          run_deposit_extract_wait_logged="true"
        fi
        if (( $(date +%s) >= run_deposit_extract_deadline_epoch )); then
          relayer_status=1
          break
        fi
        sleep "$run_deposit_extract_sleep_seconds"
      done
    fi

    deposit_event_payload="$workdir/reports/deposit-event.json"
    if (( relayer_status == 0 )); then
      local run_deposit_witness_hex run_deposit_submit_body
      run_deposit_witness_hex="$(od -An -vtx1 "$run_deposit_witness_file" | tr -d '\r\n[:space:]')"
      [[ -n "$run_deposit_witness_hex" ]] || relayer_status=1
      if (( relayer_status == 0 )); then
        run_deposit_submit_body="$(
          jq -cn \
            --arg base_recipient "$bridge_recipient_address" \
            --arg amount "$run_deposit_amount_zat" \
            --arg nonce "$run_deposit_nonce" \
            --arg proof_witness_item "0x$run_deposit_witness_hex" \
            '{baseRecipient:$base_recipient,amount:$amount,nonce:$nonce,proofWitnessItem:$proof_witness_item}'
        )"
        if ! bridge_api_post_json_with_retry "${bridge_api_url}/v1/deposits/submit" "$run_deposit_submit_body" "$deposit_event_payload" "deposit_submit"; then
          relayer_status=1
        fi
      fi
    fi
    if (( relayer_status == 0 )); then
      run_deposit_id="$(jq -r '.depositId // empty' "$deposit_event_payload" 2>/dev/null || true)"
      run_deposit_amount="$(jq -r '.amount // empty' "$deposit_event_payload" 2>/dev/null || true)"
      [[ "$run_deposit_id" =~ ^0x[0-9a-fA-F]{64}$ ]] || relayer_status=1
      [[ "$run_deposit_amount" =~ ^[0-9]+$ ]] || relayer_status=1
      if [[ "$run_deposit_extract_ok" == "true" && -n "$run_deposit_action_index_selected" ]]; then
        log "run deposit witness extracted action_index=$run_deposit_action_index_selected txid=$run_deposit_juno_tx_hash scan_url=$run_deposit_selected_scan_url"
      fi
    fi

    if (( relayer_status == 0 )); then
      wait_bridge_api_deposit_finalized() {
        local status_json found state
        status_json="$(curl -fsS "${bridge_api_url}/v1/status/deposit/${run_deposit_id}" || true)"
        [[ -n "$status_json" ]] || return 1
        found="$(jq -r '.found // false' <<<"$status_json" 2>/dev/null || true)"
        state="$(jq -r '.state // empty' <<<"$status_json" 2>/dev/null || true)"
        bridge_api_deposit_state="$state"
        [[ "$found" == "true" ]] || return 1
        [[ "$state" == "finalized" ]]
      }
      if ! wait_for_condition 1200 5 "bridge-api deposit status" wait_bridge_api_deposit_finalized; then
        relayer_status=1
      fi
    fi

    local witness_metadata_json withdraw_recipient_raw_hex withdraw_request_payload
    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    withdraw_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json" 2>/dev/null || true)"
    if [[ ! "$withdraw_recipient_raw_hex" =~ ^[0-9a-fA-F]{86}$ ]]; then
      relayer_status=1
    fi
    withdraw_request_payload="$workdir/reports/withdraw-request-event.json"
    if (( relayer_status == 0 )); then
      local withdraw_submit_body
      withdraw_submit_body="$(
        jq -cn \
          --arg amount "10000" \
          --arg recipient_raw_address_hex "$withdraw_recipient_raw_hex" \
          '{amount:$amount,recipientRawAddressHex:$recipient_raw_address_hex}'
      )"
      if ! bridge_api_post_json_with_retry "${bridge_api_url}/v1/withdrawals/request" "$withdraw_submit_body" "$withdraw_request_payload" "withdraw_request"; then
        relayer_status=1
      fi
    fi
    if (( relayer_status == 0 )); then
      run_withdrawal_id="$(jq -r '.withdrawalId // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_requester="$(jq -r '.requester // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_amount="$(jq -r '.amount // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_fee_bps="$(jq -r '.feeBps // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_request_expiry="$(jq -r '.expiry // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_recipient_ua="$(jq -r '.recipientUA // empty' "$withdraw_request_payload" 2>/dev/null || true)"
      run_withdraw_recipient_ua="$(normalize_hex_prefixed "$run_withdraw_recipient_ua" || true)"
      [[ "$run_withdrawal_id" =~ ^0x[0-9a-fA-F]{64}$ ]] || relayer_status=1
      [[ "$run_withdraw_requester" =~ ^0x[0-9a-fA-F]{40}$ ]] || relayer_status=1
      [[ "$run_withdraw_amount" =~ ^[0-9]+$ ]] || relayer_status=1
      [[ "$run_withdraw_fee_bps" =~ ^[0-9]+$ ]] || relayer_status=1
      [[ "$run_withdraw_request_expiry" =~ ^[0-9]+$ ]] || relayer_status=1
      [[ "$run_withdraw_recipient_ua" =~ ^0x[0-9a-f]{2,}$ ]] || relayer_status=1
    fi

    if (( relayer_status == 0 )); then
      wait_bridge_api_withdraw_finalized() {
        local status_json found state
        status_json="$(curl -fsS "${bridge_api_url}/v1/status/withdrawal/${run_withdrawal_id}" || true)"
        [[ -n "$status_json" ]] || return 1
        found="$(jq -r '.found // false' <<<"$status_json" 2>/dev/null || true)"
        state="$(jq -r '.state // empty' <<<"$status_json" 2>/dev/null || true)"
        bridge_api_withdraw_state="$state"
        [[ "$found" == "true" ]] || return 1
        [[ "$state" == "finalized" ]]
      }
      if ! wait_for_condition 1800 5 "bridge-api withdrawal status" wait_bridge_api_withdraw_finalized; then
        relayer_status=1
      fi
    fi
  fi

  if (( relayer_status == 0 )); then
    if ! wait_for_log_pattern "$deposit_relayer_log" "submitted mintBatch" 900; then
      relayer_status=1
    fi
    if ! wait_for_log_pattern "$withdraw_finalizer_log" "submitted finalizeWithdrawBatch" 1500; then
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    compute_fee_components() {
      local amount="$1"
      local fee_bps="$2"
      local tip_bps="$3"
      local fee tip fee_to_distributor net
      fee=$((amount * fee_bps / 10000))
      tip=$((fee * tip_bps / 10000))
      fee_to_distributor=$((fee - tip))
      net=$((amount - fee))
      printf '%s %s %s %s\n' "$fee" "$tip" "$fee_to_distributor" "$net"
    }

    check_relayer_flow_invariants() {
      local deposit_used
      deposit_used="$(
        cast_contract_call_one \
          "$base_rpc_url" \
          "$deployed_bridge_address" \
          "depositUsed(bytes32)" \
          "depositUsed(bytes32)(bool)" \
          "$run_deposit_id"
      )"
      if [[ "$deposit_used" != "true" ]]; then
        printf 'depositUsed invariant failed for depositId=%s (got=%s)\n' "$run_deposit_id" "$deposit_used"
        return 1
      fi

      local withdrawal_view_json requester_on_chain amount_on_chain fee_bps_on_chain
      local expiry_on_chain
      local finalized_on_chain refunded_on_chain recipient_ua_on_chain
      withdrawal_view_json="$(
        cast_contract_call_json \
          "$base_rpc_url" \
          "$deployed_bridge_address" \
          "getWithdrawal(bytes32)" \
          "getWithdrawal(bytes32)(address,uint256,uint64,uint96,bool,bool,bytes)" \
          "$run_withdrawal_id"
      )"
      requester_on_chain="$(jq -r '.[0]' <<<"$withdrawal_view_json")"
      amount_on_chain="$(jq -r '.[1] | tostring' <<<"$withdrawal_view_json")"
      expiry_on_chain="$(jq -r '.[2] | tostring' <<<"$withdrawal_view_json")"
      fee_bps_on_chain="$(jq -r '.[3] | tostring' <<<"$withdrawal_view_json")"
      finalized_on_chain="$(jq -r '.[4] | tostring' <<<"$withdrawal_view_json")"
      refunded_on_chain="$(jq -r '.[5] | tostring' <<<"$withdrawal_view_json")"
      recipient_ua_on_chain="$(jq -r '.[6]' <<<"$withdrawal_view_json")"
      recipient_ua_on_chain="$(normalize_hex_prefixed "$recipient_ua_on_chain" || true)"
      requester_on_chain="$(lower "$requester_on_chain")"
      recipient_ua_on_chain="$(lower "$recipient_ua_on_chain")"

      if [[ "$requester_on_chain" != "$(lower "$run_withdraw_requester")" ]]; then
        printf 'getWithdrawal requester mismatch for withdrawalId=%s (got=%s want=%s)\n' \
          "$run_withdrawal_id" \
          "$requester_on_chain" \
          "$(lower "$run_withdraw_requester")"
        return 1
      fi
      if [[ "$amount_on_chain" != "$run_withdraw_amount" ]]; then
        printf 'getWithdrawal amount mismatch for withdrawalId=%s (got=%s want=%s)\n' \
          "$run_withdrawal_id" \
          "$amount_on_chain" \
          "$run_withdraw_amount"
        return 1
      fi
      if [[ "$fee_bps_on_chain" != "$run_withdraw_fee_bps" ]]; then
        printf 'getWithdrawal feeBps mismatch for withdrawalId=%s (got=%s want=%s)\n' \
          "$run_withdrawal_id" \
          "$fee_bps_on_chain" \
          "$run_withdraw_fee_bps"
        return 1
      fi
      if [[ ! "$expiry_on_chain" =~ ^[0-9]+$ ]]; then
        printf 'getWithdrawal expiry is invalid for withdrawalId=%s (got=%s)\n' \
          "$run_withdrawal_id" \
          "$expiry_on_chain"
        return 1
      fi
      if (( expiry_on_chain <= run_withdraw_request_expiry )); then
        printf 'withdraw expiry did not increase after forced extension for withdrawalId=%s (on_chain=%s request=%s)\n' \
          "$run_withdrawal_id" \
          "$expiry_on_chain" \
          "$run_withdraw_request_expiry"
        return 1
      fi
      if [[ "$finalized_on_chain" != "true" ]]; then
        printf 'getWithdrawal finalized mismatch for withdrawalId=%s (got=%s want=true)\n' \
          "$run_withdrawal_id" \
          "$finalized_on_chain"
        return 1
      fi
      if [[ "$refunded_on_chain" != "false" ]]; then
        printf 'getWithdrawal refunded mismatch for withdrawalId=%s (got=%s want=false)\n' \
          "$run_withdrawal_id" \
          "$refunded_on_chain"
        return 1
      fi
      if [[ "$recipient_ua_on_chain" != "$(lower "$run_withdraw_recipient_ua")" ]]; then
        printf 'getWithdrawal recipientUA mismatch for withdrawalId=%s (got=%s want=%s)\n' \
          "$run_withdrawal_id" \
          "$recipient_ua_on_chain" \
          "$(lower "$run_withdraw_recipient_ua")"
        return 1
      fi

      local owner_wjuno_balance_after recipient_wjuno_balance_after
      local fee_distributor_wjuno_balance_after bridge_wjuno_balance_after
      owner_wjuno_balance_after="$(
        cast_contract_call_one \
          "$base_rpc_url" \
          "$deployed_wjuno_address" \
          "balanceOf(address)" \
          "balanceOf(address)(uint256)" \
          "$bridge_deployer_address"
      )"
      recipient_wjuno_balance_after="$(
        cast_contract_call_one \
          "$base_rpc_url" \
          "$deployed_wjuno_address" \
          "balanceOf(address)" \
          "balanceOf(address)(uint256)" \
          "$bridge_recipient_address"
      )"
      fee_distributor_wjuno_balance_after="$(
        cast_contract_call_one \
          "$base_rpc_url" \
          "$deployed_wjuno_address" \
          "balanceOf(address)" \
          "balanceOf(address)(uint256)" \
          "$bridge_fee_distributor"
      )"
      bridge_wjuno_balance_after="$(
        cast_contract_call_one \
          "$base_rpc_url" \
          "$deployed_wjuno_address" \
          "balanceOf(address)" \
          "balanceOf(address)(uint256)" \
          "$deployed_bridge_address"
      )"
      [[ "$owner_wjuno_balance_after" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$recipient_wjuno_balance_after" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$fee_distributor_wjuno_balance_after" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$bridge_wjuno_balance_after" =~ ^-?[0-9]+$ ]] || return 1

      local deposit_fee deposit_tip deposit_fee_to_distributor deposit_net
      local withdraw_fee withdraw_tip withdraw_fee_to_distributor withdraw_net
      read -r deposit_fee deposit_tip deposit_fee_to_distributor deposit_net < <(
        compute_fee_components "$run_deposit_amount" "$bridge_fee_bps" "$bridge_relayer_tip_bps"
      )
      read -r withdraw_fee withdraw_tip withdraw_fee_to_distributor withdraw_net < <(
        compute_fee_components "$run_withdraw_amount" "$run_withdraw_fee_bps" "$bridge_relayer_tip_bps"
      )
      [[ "$deposit_fee" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$deposit_tip" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$deposit_fee_to_distributor" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$deposit_net" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$withdraw_fee" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$withdraw_tip" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$withdraw_fee_to_distributor" =~ ^-?[0-9]+$ ]] || return 1
      [[ "$withdraw_net" =~ ^-?[0-9]+$ ]] || return 1

      local recipient_equals_owner="false"
      if [[ "$(lower "$bridge_recipient_address")" == "$(lower "$bridge_deployer_address")" ]]; then
        recipient_equals_owner="true"
      fi

      local owner_delta_expected recipient_delta_expected fee_distributor_delta_expected bridge_delta_expected
      owner_delta_expected=$((deposit_tip - run_withdraw_amount + withdraw_tip))
      if [[ "$recipient_equals_owner" == "true" ]]; then
        owner_delta_expected=$((owner_delta_expected + deposit_net))
        recipient_delta_expected=0
      else
        recipient_delta_expected=$deposit_net
      fi
      fee_distributor_delta_expected=$((deposit_fee_to_distributor + withdraw_fee_to_distributor))
      bridge_delta_expected=0

      local owner_delta_actual recipient_delta_raw recipient_delta_actual
      local fee_distributor_delta_actual bridge_delta_actual
      owner_delta_actual=$((owner_wjuno_balance_after - owner_wjuno_balance_before))
      recipient_delta_raw=$((recipient_wjuno_balance_after - recipient_wjuno_balance_before))
      if [[ "$recipient_equals_owner" == "true" ]]; then
        recipient_delta_actual=0
      else
        recipient_delta_actual="$recipient_delta_raw"
      fi
      fee_distributor_delta_actual=$((fee_distributor_wjuno_balance_after - fee_distributor_wjuno_balance_before))
      bridge_delta_actual=$((bridge_wjuno_balance_after - bridge_wjuno_balance_before))

      if (( owner_delta_actual != owner_delta_expected ||
            recipient_delta_actual != recipient_delta_expected ||
            fee_distributor_delta_actual != fee_distributor_delta_expected ||
            bridge_delta_actual != bridge_delta_expected )); then
        printf 'balance delta invariant failed: owner got=%s want=%s recipient got=%s raw=%s want=%s feeDistributor got=%s want=%s bridge got=%s want=%s\n' \
          "$owner_delta_actual" \
          "$owner_delta_expected" \
          "$recipient_delta_actual" \
          "$recipient_delta_raw" \
          "$recipient_delta_expected" \
          "$fee_distributor_delta_actual" \
          "$fee_distributor_delta_expected" \
          "$bridge_delta_actual" \
          "$bridge_delta_expected"
        return 1
      fi

      invariant_deposit_used="true"
      invariant_withdraw_requester="$requester_on_chain"
      invariant_withdraw_amount="$amount_on_chain"
      invariant_withdraw_fee_bps="$fee_bps_on_chain"
      invariant_withdraw_expiry="$expiry_on_chain"
      invariant_withdraw_expiry_extended_vs_request="true"
      invariant_withdraw_finalized="$finalized_on_chain"
      invariant_withdraw_refunded="$refunded_on_chain"
      invariant_withdraw_recipient_ua="$recipient_ua_on_chain"
      invariant_owner_delta_expected="$owner_delta_expected"
      invariant_owner_delta_actual="$owner_delta_actual"
      invariant_recipient_delta_expected="$recipient_delta_expected"
      invariant_recipient_delta_actual="$recipient_delta_actual"
      invariant_recipient_delta_raw="$recipient_delta_raw"
      invariant_fee_distributor_delta_expected="$fee_distributor_delta_expected"
      invariant_fee_distributor_delta_actual="$fee_distributor_delta_actual"
      invariant_bridge_delta_expected="$bridge_delta_expected"
      invariant_bridge_delta_actual="$bridge_delta_actual"
      invariant_balance_delta_match="true"
      return 0
    }

    if ! wait_for_condition 900 5 "run-scoped bridge invariants" check_relayer_flow_invariants; then
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    coordinator_payout_juno_tx_hash="$(
      wait_for_withdrawal_payout_txid \
        "$shared_postgres_dsn" \
        "$run_withdrawal_id" \
        300 || true
    )"
    if [[ -z "$coordinator_payout_juno_tx_hash" ]]; then
      log "missing payout txid for withdrawalId=$run_withdrawal_id from withdraw coordinator state"
      relayer_status=1
    fi
  fi

  run_operator_down_threshold_scenario() {
    local target_down_count="$1"
    local scenario_endpoint scenario_pid
    local scenario_digest scenario_output scenario_status scenario_signature_count
    local operator_signer_probe_bin="$bridge_operator_signer_bin"
    local endpoint_idx
    local -a scenario_probe_args=()
    local -a scenario_signer_env=()

    while (( operator_failures_injected < target_down_count )); do
      endpoint_idx=$(( ${#operator_signer_endpoints[@]} - operator_failures_injected - 1 ))
      if (( endpoint_idx < 0 )); then
        printf 'insufficient operator endpoints for failure injection: have=%d requested=%d\n' \
          "${#operator_signer_endpoints[@]}" \
          "$target_down_count"
        return 1
      fi

      scenario_endpoint="${operator_signer_endpoints[$endpoint_idx]}"
      [[ -n "$scenario_endpoint" ]] || return 1
      scenario_pid="$(inject_operator_endpoint_failure "$scenario_endpoint" "$operator_down_ssh_key_path" "$operator_down_ssh_user" || true)"
      [[ -n "$scenario_pid" ]] || return 1
      operator_failures_injected=$((operator_failures_injected + 1))

      if [[ "$operator_signer_supports_endpoints" != "true" ]]; then
        local key_idx
        key_idx="$endpoint_idx"
        if (( key_idx < 0 || key_idx >= ${#operator_signer_active_key_hexes[@]} )); then
          printf 'operator signer key index out of range during down-scenario: idx=%s keys=%d\n' \
            "$key_idx" \
            "${#operator_signer_active_key_hexes[@]}"
          return 1
        fi
        local -a remaining_operator_keys=()
        local key_i
        for key_i in "${!operator_signer_active_key_hexes[@]}"; do
          if (( key_i == key_idx )); then
            continue
          fi
          remaining_operator_keys+=("${operator_signer_active_key_hexes[$key_i]}")
        done
        operator_signer_active_key_hexes=("${remaining_operator_keys[@]}")
      fi

      if (( operator_failures_injected == 1 )); then
        operator_down_1_endpoint="$scenario_endpoint"
      elif (( operator_failures_injected == 2 )); then
        operator_down_2_endpoint="$scenario_endpoint"
      fi
      log "injected operator endpoint failure count=$operator_failures_injected endpoint=$scenario_endpoint listener_pid=$scenario_pid"
    done

    if [[ "$operator_signer_supports_endpoints" != "true" ]] && (( ${#operator_signer_active_key_hexes[@]} < threshold )); then
      printf 'threshold signer probe cannot continue after operator-down injection: keys=%d threshold=%d\n' \
        "${#operator_signer_active_key_hexes[@]}" \
        "$threshold"
      return 1
    fi

    scenario_digest="0x$(openssl rand -hex 32)"
    scenario_probe_args=("$operator_signer_probe_bin" sign-digest --digest "$scenario_digest" --json)
    if [[ "$operator_signer_supports_endpoints" == "true" ]]; then
      for scenario_endpoint in "${operator_signer_endpoints[@]}"; do
        scenario_probe_args+=("--operator-endpoint" "$scenario_endpoint")
      done
    else
      local scenario_keys_csv
      scenario_keys_csv="$(IFS=,; printf '%s' "${operator_signer_active_key_hexes[*]}")"
      [[ -n "$scenario_keys_csv" ]] || return 1
      scenario_signer_env=(JUNO_TXSIGN_SIGNER_KEYS="$scenario_keys_csv")
    fi

    set +e
    if (( ${#scenario_signer_env[@]} > 0 )); then
      scenario_output="$(env "${scenario_signer_env[@]}" "${scenario_probe_args[@]}" 2>&1)"
    else
      scenario_output="$("${scenario_probe_args[@]}" 2>&1)"
    fi
    scenario_status=$?
    set -e
    if (( scenario_status != 0 )); then
      printf 'threshold signer probe failed under operator-down scenario count=%s status=%s output=%s\n' \
        "$target_down_count" \
        "$scenario_status" \
        "$scenario_output"
      return 1
    fi

    scenario_signature_count="$(
      jq -r '
        if .status == "ok" and ((.data.signatures? | type) == "array") then
          (.data.signatures | length)
        elif .status == "ok" and ((.data.signature? // "") != "") then
          1
        else
          0
        end
      ' <<<"$scenario_output" 2>/dev/null || true
    )"
    [[ "$scenario_signature_count" =~ ^[0-9]+$ ]] || return 1
    if (( scenario_signature_count < threshold )); then
      printf 'threshold signer probe failed under operator-down scenario count=%s signatures=%s threshold=%s\n' \
        "$target_down_count" \
        "$scenario_signature_count" \
        "$threshold"
      return 1
    fi

    if (( target_down_count == 1 )); then
      operator_down_1_signature_count="$scenario_signature_count"
    elif (( target_down_count == 2 )); then
      operator_down_2_signature_count="$scenario_signature_count"
    fi
    return 0
  }

  run_refund_after_expiry_scenario() {
    local scenario_refund_window_seconds="$1"
    local witness_metadata_json scenario_recipient_raw_hex
    local scenario_withdraw_request_payload scenario_request_status
    local scenario_withdrawal_view_json scenario_refunded_on_chain scenario_finalized_on_chain
    local scenario_refund_output scenario_refund_status scenario_refund_attempt
    local scenario_wait_deadline scenario_now
    local scenario_restore_output scenario_restore_status
    local scenario_params_mutated="false"

    restore_refund_after_expiry_params() {
      if [[ "$scenario_params_mutated" != "true" ]]; then
        return 0
      fi
      log "refund-after-expiry scenario restoring Bridge.setParams(uint96,uint96,uint64,uint64) refund_window_seconds=$bridge_refund_window_seconds"
      set +e
      scenario_restore_output="$(
        cast send \
          --rpc-url "$base_rpc_url" \
          --private-key "$bridge_deployer_key_hex" \
          "$deployed_bridge_address" \
          "setParams(uint96,uint96,uint64,uint64)" \
          "$bridge_fee_bps" \
          "$bridge_relayer_tip_bps" \
          "$bridge_refund_window_seconds" \
          "$bridge_max_expiry_extension_seconds" 2>&1
      )"
      scenario_restore_status=$?
      set -e
      if (( scenario_restore_status != 0 )); then
        printf 'refund-after-expiry scenario failed to restore bridge params: status=%s output=%s\n' \
          "$scenario_restore_status" \
          "$scenario_restore_output"
        return 1
      fi
      scenario_params_mutated="false"
      return 0
    }

    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    scenario_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json" 2>/dev/null || true)"
    [[ "$scenario_recipient_raw_hex" =~ ^[0-9a-fA-F]{86}$ ]] || return 1

    log "refund-after-expiry scenario configuring Bridge.setParams(uint96,uint96,uint64,uint64) refund_window_seconds=$scenario_refund_window_seconds"
    set +e
    scenario_refund_output="$(
      cast send \
        --rpc-url "$base_rpc_url" \
        --private-key "$bridge_deployer_key_hex" \
        "$deployed_bridge_address" \
        "setParams(uint96,uint96,uint64,uint64)" \
        "$bridge_fee_bps" \
        "$bridge_relayer_tip_bps" \
        "$scenario_refund_window_seconds" \
        "$bridge_max_expiry_extension_seconds" 2>&1
    )"
    scenario_refund_status=$?
    set -e
    if (( scenario_refund_status != 0 )); then
      printf 'refund-after-expiry scenario failed to configure refund window: status=%s output=%s\n' \
        "$scenario_refund_status" \
        "$scenario_refund_output"
      return 1
    fi
    scenario_params_mutated="true"

    scenario_withdraw_request_payload="$workdir/reports/refund-after-expiry-withdraw-request.json"
    set +e
    (
      cd "$REPO_ROOT"
      go run ./cmd/withdraw-request \
        --rpc-url "$base_rpc_url" \
        --chain-id "$base_chain_id" \
        --owner-key-file "$bridge_deployer_key_file" \
        --wjuno-address "$deployed_wjuno_address" \
        --bridge-address "$deployed_bridge_address" \
        --amount "1000" \
        --recipient-raw-address-hex "$scenario_recipient_raw_hex" \
        --output "$scenario_withdraw_request_payload"
    ) >/dev/null 2>&1
    scenario_request_status=$?
    set -e
    if (( scenario_request_status != 0 )); then
      printf 'refund-after-expiry scenario failed to request withdrawal: status=%s\n' "$scenario_request_status"
      restore_refund_after_expiry_params || true
      return 1
    fi

    refund_after_expiry_withdrawal_id="$(jq -r '.withdrawalId // empty' "$scenario_withdraw_request_payload" 2>/dev/null || true)"
    refund_after_expiry_request_expiry="$(jq -r '.expiry // empty' "$scenario_withdraw_request_payload" 2>/dev/null || true)"
    if [[ ! "$refund_after_expiry_withdrawal_id" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
      restore_refund_after_expiry_params || true
      return 1
    fi
    if [[ ! "$refund_after_expiry_request_expiry" =~ ^[0-9]+$ ]]; then
      restore_refund_after_expiry_params || true
      return 1
    fi

    scenario_wait_deadline=$(( $(date +%s) + scenario_refund_window_seconds + 240 ))
    for scenario_refund_attempt in $(seq 1 180); do
      set +e
      scenario_refund_output="$(
        cast send \
          --rpc-url "$base_rpc_url" \
          --private-key "$bridge_deployer_key_hex" \
          "$deployed_bridge_address" \
          "refund(bytes32)" \
          "$refund_after_expiry_withdrawal_id" 2>&1
      )"
      scenario_refund_status=$?
      set -e
      if (( scenario_refund_status == 0 )); then
        if [[ "$scenario_refund_output" =~ (0x[0-9a-fA-F]{64}) ]]; then
          refund_after_expiry_refund_tx_hash="$(normalize_hex_prefixed "${BASH_REMATCH[1]}" || true)"
        fi
        break
      fi

      if ! is_withdraw_not_expired_error "$scenario_refund_output"; then
        printf 'refund-after-expiry scenario refund tx failed: status=%s output=%s\n' \
          "$scenario_refund_status" \
          "$scenario_refund_output"
        restore_refund_after_expiry_params || true
        return 1
      fi

      scenario_now="$(date +%s)"
      if (( scenario_now >= scenario_wait_deadline )); then
        printf 'refund-after-expiry scenario timed out waiting for expiry withdrawalId=%s expiry=%s\n' \
          "$refund_after_expiry_withdrawal_id" \
          "$refund_after_expiry_request_expiry"
        restore_refund_after_expiry_params || true
        return 1
      fi
      sleep 2
    done
    if [[ -z "$refund_after_expiry_refund_tx_hash" ]]; then
      restore_refund_after_expiry_params || true
      return 1
    fi

    scenario_withdrawal_view_json="$(
      cast_contract_call_json \
        "$base_rpc_url" \
        "$deployed_bridge_address" \
        "getWithdrawal(bytes32)" \
        "getWithdrawal(bytes32)(address,uint256,uint64,uint96,bool,bool,bytes)" \
        "$refund_after_expiry_withdrawal_id"
    )"
    scenario_finalized_on_chain="$(jq -r '.[4] | tostring' <<<"$scenario_withdrawal_view_json")"
    scenario_refunded_on_chain="$(jq -r '.[5] | tostring' <<<"$scenario_withdrawal_view_json")"
    if [[ "$scenario_refunded_on_chain" != "true" ]]; then
      printf 'withdrawal refund did not transition to refunded=true for withdrawalId=%s (got=%s)\n' \
        "$refund_after_expiry_withdrawal_id" \
        "$scenario_refunded_on_chain"
      restore_refund_after_expiry_params || true
      return 1
    fi
    if [[ "$scenario_finalized_on_chain" != "false" ]]; then
      printf 'refund-after-expiry scenario expected finalized=false for withdrawalId=%s (got=%s)\n' \
        "$refund_after_expiry_withdrawal_id" \
        "$scenario_finalized_on_chain"
      restore_refund_after_expiry_params || true
      return 1
    fi

    refund_after_expiry_on_chain_refunded="true"
    if ! restore_refund_after_expiry_params; then
      return 1
    fi
    return 0
  }

  if (( relayer_status == 0 )); then
    ensure_bridge_operator_signer_ready
    operator_signer_supports_endpoints="$bridge_operator_signer_supports_operator_endpoint"
    operator_down_1_status="running"
    if run_operator_down_threshold_scenario 1; then
      operator_down_1_status="passed"
    else
      operator_down_1_status="failed"
      relayer_status=1
    fi
  fi

  if (( relayer_status == 0 )); then
    operator_down_2_status="running"
    if run_operator_down_threshold_scenario 2; then
      operator_down_2_status="passed"
    else
      operator_down_2_status="failed"
      relayer_status=1
    fi
  fi

  stop_remote_relayer_service "$base_relayer_pid"
  stop_remote_relayer_service "$deposit_relayer_pid"
  stop_remote_relayer_service "$withdraw_coordinator_pid"
  stop_remote_relayer_service "$withdraw_finalizer_pid"
  stop_remote_relayer_service "$bridge_api_pid"

  if (( relayer_status != 0 )); then
    log "relayer service orchestration failed; showing service logs"
    tail -n 200 "$base_relayer_log" >&2 || true
    tail -n 200 "$deposit_relayer_log" >&2 || true
    tail -n 200 "$withdraw_coordinator_log" >&2 || true
    tail -n 200 "$withdraw_finalizer_log" >&2 || true
    tail -n 200 "$bridge_api_log" >&2 || true
    bridge_status=1
  else
    bridge_status=0
  fi

  if (( bridge_status == 0 )); then
    refund_after_expiry_status="running"
    if run_refund_after_expiry_scenario "$refund_after_expiry_window_seconds"; then
      refund_after_expiry_status="passed"
    else
      refund_after_expiry_status="failed"
      bridge_status=1
    fi
  fi

  stop_centralized_proof_services
  if (( bridge_status != 0 )); then
    log "relayer-driven bridge e2e failed; showing shared ECS proof service logs"
    dump_shared_proof_services_ecs_logs \
      "$shared_ecs_region" \
      "$shared_ecs_cluster_arn" \
      "$shared_proof_requestor_service_name" \
      "$shared_proof_funder_service_name"
    die "relayer-driven bridge e2e failed while centralized proof services were running"
  fi

  local juno_tx_hash=""
  local juno_tx_hash_source="withdraw_coordinator.payout_state"
  juno_tx_hash="$(normalize_hex_prefixed "$coordinator_payout_juno_tx_hash" || true)"
  if [[ "$juno_tx_hash" =~ ^0x[0-9a-f]{64}$ ]]; then
    log "juno_tx_hash=$juno_tx_hash source=$juno_tx_hash_source"
  else
    log "juno_tx_hash=unavailable"
    die "withdraw coordinator payout state missing juno tx hash for withdrawalId=$run_withdrawal_id"
  fi

  local dkg_report_public_json
  dkg_report_public_json="$(redact_dkg_summary_json "$dkg_summary")"
  if [[ "$dkg_summary" == "$workdir/reports/dkg-summary.json" ]]; then
    printf '%s\n' "$dkg_report_public_json" >"$dkg_summary"
  fi

  local sp1_deposit_ivk_configured="false"
  local sp1_withdraw_ovk_configured="false"
  local sp1_deposit_witness_item_count sp1_withdraw_witness_item_count
  local guest_witness_auto_generate="true"
  local guest_witness_extract_from_chain="false"
  if [[ -n "$sp1_deposit_owallet_ivk_hex" ]]; then
    sp1_deposit_ivk_configured="true"
  fi
  if [[ -n "$sp1_withdraw_owallet_ovk_hex" ]]; then
    sp1_withdraw_ovk_configured="true"
  fi
  sp1_deposit_witness_item_count="${#sp1_deposit_witness_item_files[@]}"
  sp1_withdraw_witness_item_count="${#sp1_withdraw_witness_item_files[@]}"
  if [[ "$sp1_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    guest_witness_extract_from_chain="true"
  fi

  local witness_pool_operator_labels_json witness_healthy_operator_labels_json
  local witness_quorum_operator_labels_json witness_failed_operator_labels_json
  witness_pool_operator_labels_json="$(json_array_from_args "${witness_pool_operator_labels[@]}")"
  witness_healthy_operator_labels_json="$(json_array_from_args "${witness_healthy_operator_labels[@]}")"
  witness_quorum_operator_labels_json="$(json_array_from_args "${witness_quorum_operator_labels[@]}")"
  witness_failed_operator_labels_json="$(json_array_from_args "${witness_failed_operator_labels[@]}")"

  local run_invariants_json
  run_invariants_json="$(
    jq -n \
      --arg deposit_id "$run_deposit_id" \
      --arg deposit_amount "$run_deposit_amount" \
      --arg deposit_juno_tx_hash "$run_deposit_juno_tx_hash" \
      --arg deposit_nonce "$run_deposit_nonce" \
      --arg withdrawal_id "$run_withdrawal_id" \
      --arg withdraw_requester "$run_withdraw_requester" \
      --arg withdraw_amount "$run_withdraw_amount" \
      --arg withdraw_fee_bps "$run_withdraw_fee_bps" \
      --arg withdraw_request_expiry "$run_withdraw_request_expiry" \
      --arg withdraw_recipient_ua "$run_withdraw_recipient_ua" \
      --arg bridge_fee_bps "$bridge_fee_bps" \
      --arg bridge_relayer_tip_bps "$bridge_relayer_tip_bps" \
      --arg bridge_fee_distributor "$bridge_fee_distributor" \
      --arg deposit_used "$invariant_deposit_used" \
      --arg invariant_withdraw_requester "$invariant_withdraw_requester" \
      --arg invariant_withdraw_amount "$invariant_withdraw_amount" \
      --arg invariant_withdraw_fee_bps "$invariant_withdraw_fee_bps" \
      --arg invariant_withdraw_expiry "$invariant_withdraw_expiry" \
      --arg invariant_withdraw_expiry_extended_vs_request "$invariant_withdraw_expiry_extended_vs_request" \
      --arg invariant_withdraw_finalized "$invariant_withdraw_finalized" \
      --arg invariant_withdraw_refunded "$invariant_withdraw_refunded" \
      --arg invariant_withdraw_recipient_ua "$invariant_withdraw_recipient_ua" \
      --arg invariant_owner_delta_expected "$invariant_owner_delta_expected" \
      --arg invariant_owner_delta_actual "$invariant_owner_delta_actual" \
      --arg invariant_recipient_delta_expected "$invariant_recipient_delta_expected" \
      --arg invariant_recipient_delta_actual "$invariant_recipient_delta_actual" \
      --arg invariant_recipient_delta_raw "$invariant_recipient_delta_raw" \
      --arg invariant_fee_distributor_delta_expected "$invariant_fee_distributor_delta_expected" \
      --arg invariant_fee_distributor_delta_actual "$invariant_fee_distributor_delta_actual" \
      --arg invariant_bridge_delta_expected "$invariant_bridge_delta_expected" \
      --arg invariant_bridge_delta_actual "$invariant_bridge_delta_actual" \
      --arg invariant_balance_delta_match "$invariant_balance_delta_match" \
      --arg bridge_api_deposit_state "$bridge_api_deposit_state" \
      --arg bridge_api_withdraw_state "$bridge_api_withdraw_state" \
      '{
        deposit_id: (if $deposit_id == "" then null else $deposit_id end),
        deposit_amount: (if $deposit_amount == "" then null else ($deposit_amount | tonumber) end),
        deposit_juno_tx_hash: (if $deposit_juno_tx_hash == "" then null else $deposit_juno_tx_hash end),
        deposit_nonce: (if $deposit_nonce == "" then null else ($deposit_nonce | tonumber) end),
        withdrawal_id: (if $withdrawal_id == "" then null else $withdrawal_id end),
        withdrawal_request: {
          requester: (if $withdraw_requester == "" then null else $withdraw_requester end),
          amount: (if $withdraw_amount == "" then null else ($withdraw_amount | tonumber) end),
          fee_bps: (if $withdraw_fee_bps == "" then null else ($withdraw_fee_bps | tonumber) end),
          expiry: (if $withdraw_request_expiry == "" then null else ($withdraw_request_expiry | tonumber) end),
          recipient_ua: (if $withdraw_recipient_ua == "" then null else $withdraw_recipient_ua end)
        },
        bridge_fee_params: {
          fee_bps: (if $bridge_fee_bps == "" then null else ($bridge_fee_bps | tonumber) end),
          relayer_tip_bps: (if $bridge_relayer_tip_bps == "" then null else ($bridge_relayer_tip_bps | tonumber) end),
          fee_distributor: (if $bridge_fee_distributor == "" then null else $bridge_fee_distributor end)
        },
        checks: {
          deposit_used: ($deposit_used == "true"),
          withdrawal: {
            requester: (if $invariant_withdraw_requester == "" then null else $invariant_withdraw_requester end),
            amount: (if $invariant_withdraw_amount == "" then null else ($invariant_withdraw_amount | tonumber) end),
            fee_bps: (if $invariant_withdraw_fee_bps == "" then null else ($invariant_withdraw_fee_bps | tonumber) end),
            expiry: (if $invariant_withdraw_expiry == "" then null else ($invariant_withdraw_expiry | tonumber) end),
            extended_vs_request: ($invariant_withdraw_expiry_extended_vs_request == "true"),
            finalized: ($invariant_withdraw_finalized == "true"),
            refunded: ($invariant_withdraw_refunded == "true"),
            recipient_ua: (if $invariant_withdraw_recipient_ua == "" then null else $invariant_withdraw_recipient_ua end)
          },
          balance_deltas: {
            owner: {
              expected: (if $invariant_owner_delta_expected == "" then null else ($invariant_owner_delta_expected | tonumber) end),
              actual: (if $invariant_owner_delta_actual == "" then null else ($invariant_owner_delta_actual | tonumber) end)
            },
            recipient: {
              expected: (if $invariant_recipient_delta_expected == "" then null else ($invariant_recipient_delta_expected | tonumber) end),
              actual: (if $invariant_recipient_delta_actual == "" then null else ($invariant_recipient_delta_actual | tonumber) end),
              raw_actual: (if $invariant_recipient_delta_raw == "" then null else ($invariant_recipient_delta_raw | tonumber) end)
            },
            fee_distributor: {
              expected: (if $invariant_fee_distributor_delta_expected == "" then null else ($invariant_fee_distributor_delta_expected | tonumber) end),
              actual: (if $invariant_fee_distributor_delta_actual == "" then null else ($invariant_fee_distributor_delta_actual | tonumber) end)
            },
            bridge: {
              expected: (if $invariant_bridge_delta_expected == "" then null else ($invariant_bridge_delta_expected | tonumber) end),
              actual: (if $invariant_bridge_delta_actual == "" then null else ($invariant_bridge_delta_actual | tonumber) end)
            },
            match: ($invariant_balance_delta_match == "true")
          }
        },
        bridge_api: {
          deposit_state: (if $bridge_api_deposit_state == "" then null else $bridge_api_deposit_state end),
          withdrawal_state: (if $bridge_api_withdraw_state == "" then null else $bridge_api_withdraw_state end)
        }
      }'
  )"

  local expiry_extension_status="failed"
  if [[ "$invariant_withdraw_expiry_extended_vs_request" == "true" ]]; then
    expiry_extension_status="passed"
  fi

  local chaos_scenarios_json
  chaos_scenarios_json="$(
    jq -n \
      --arg direct_cli_user_proof_status "$direct_cli_user_proof_status" \
      --arg direct_cli_user_proof_summary_path "$direct_cli_user_proof_summary_path" \
      --arg direct_cli_user_proof_log "$direct_cli_user_proof_log" \
      --arg direct_cli_user_proof_submission_mode "$direct_cli_user_proof_submission_mode" \
      --arg direct_cli_user_proof_deposit_request_id "$direct_cli_user_proof_deposit_request_id" \
      --arg direct_cli_user_proof_withdraw_request_id "$direct_cli_user_proof_withdraw_request_id" \
      --arg expiry_extension_status "$expiry_extension_status" \
      --arg run_withdraw_request_expiry "$run_withdraw_request_expiry" \
      --arg invariant_withdraw_expiry "$invariant_withdraw_expiry" \
      --arg invariant_withdraw_expiry_extended_vs_request "$invariant_withdraw_expiry_extended_vs_request" \
      --arg refund_after_expiry_status "$refund_after_expiry_status" \
      --arg refund_after_expiry_withdrawal_id "$refund_after_expiry_withdrawal_id" \
      --arg refund_after_expiry_request_expiry "$refund_after_expiry_request_expiry" \
      --arg refund_after_expiry_refund_tx_hash "$refund_after_expiry_refund_tx_hash" \
      --arg refund_after_expiry_on_chain_refunded "$refund_after_expiry_on_chain_refunded" \
      --arg refund_after_expiry_window_seconds "$refund_after_expiry_window_seconds" \
      --arg operator_down_1_status "$operator_down_1_status" \
      --arg operator_down_1_endpoint "$operator_down_1_endpoint" \
      --arg operator_down_1_signature_count "$operator_down_1_signature_count" \
      --arg operator_down_2_status "$operator_down_2_status" \
      --arg operator_down_2_endpoint "$operator_down_2_endpoint" \
      --arg operator_down_2_signature_count "$operator_down_2_signature_count" \
      '{
        direct_cli_user_proof: {
          status: (if $direct_cli_user_proof_status == "" then null else $direct_cli_user_proof_status end),
          submission_mode: (if $direct_cli_user_proof_submission_mode == "" then null else $direct_cli_user_proof_submission_mode end),
          deposit_request_id: (if $direct_cli_user_proof_deposit_request_id == "" then null else $direct_cli_user_proof_deposit_request_id end),
          withdraw_request_id: (if $direct_cli_user_proof_withdraw_request_id == "" then null else $direct_cli_user_proof_withdraw_request_id end),
          summary_path: (if $direct_cli_user_proof_summary_path == "" then null else $direct_cli_user_proof_summary_path end),
          log_path: (if $direct_cli_user_proof_log == "" then null else $direct_cli_user_proof_log end)
        },
        expiry_extension: {
          status: (if $expiry_extension_status == "" then null else $expiry_extension_status end),
          request_expiry: (if $run_withdraw_request_expiry == "" then null else ($run_withdraw_request_expiry | tonumber) end),
          on_chain_expiry: (if $invariant_withdraw_expiry == "" then null else ($invariant_withdraw_expiry | tonumber) end),
          extended_vs_request: ($invariant_withdraw_expiry_extended_vs_request == "true")
        },
        refund_after_expiry: {
          status: (if $refund_after_expiry_status == "" then null else $refund_after_expiry_status end),
          withdrawal_id: (if $refund_after_expiry_withdrawal_id == "" then null else $refund_after_expiry_withdrawal_id end),
          request_expiry: (if $refund_after_expiry_request_expiry == "" then null else ($refund_after_expiry_request_expiry | tonumber) end),
          refund_tx_hash: (if $refund_after_expiry_refund_tx_hash == "" then null else $refund_after_expiry_refund_tx_hash end),
          on_chain_refunded: ($refund_after_expiry_on_chain_refunded == "true"),
          refund_window_seconds: (if $refund_after_expiry_window_seconds == "" then null else ($refund_after_expiry_window_seconds | tonumber) end)
        },
        operator_down_1: {
          status: (if $operator_down_1_status == "" then null else $operator_down_1_status end),
          endpoint: (if $operator_down_1_endpoint == "" then null else $operator_down_1_endpoint end),
          signature_count: (if $operator_down_1_signature_count == "" then null else ($operator_down_1_signature_count | tonumber) end)
        },
        operator_down_2: {
          status: (if $operator_down_2_status == "" then null else $operator_down_2_status end),
          endpoint: (if $operator_down_2_endpoint == "" then null else $operator_down_2_endpoint end),
          signature_count: (if $operator_down_2_signature_count == "" then null else ($operator_down_2_signature_count | tonumber) end)
        }
      }'
  )"
  stage_full="true"

  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg workdir "$workdir" \
    --arg stop_after_stage "$stop_after_stage" \
    --arg stage_witness_ready "$stage_witness_ready" \
    --arg stage_shared_services_ready "$stage_shared_services_ready" \
    --arg stage_checkpoint_validated "$stage_checkpoint_validated" \
    --arg stage_full "$stage_full" \
    --arg stage_shared_services_stable "$stage_shared_services_stable" \
    --arg stage_checkpoint_bridge_config_update_target "$stage_checkpoint_bridge_config_update_target" \
    --arg stage_checkpoint_bridge_config_update_success "$stage_checkpoint_bridge_config_update_success" \
    --arg stage_checkpoint_shared_validation_passed "$stage_checkpoint_shared_validation_passed" \
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
    --arg sp1_auto "$sp1_auto" \
    --arg sp1_proof_submission_mode "$sp1_proof_submission_mode" \
    --arg sp1_rpc_url "$sp1_rpc_url" \
    --arg sp1_requestor_address "$sp1_requestor_address" \
    --arg sp1_input_mode "$sp1_input_mode" \
    --arg sp1_deposit_ivk_configured "$sp1_deposit_ivk_configured" \
    --arg sp1_withdraw_ovk_configured "$sp1_withdraw_ovk_configured" \
    --arg guest_witness_auto_generate "$guest_witness_auto_generate" \
    --arg guest_witness_extract_from_chain "$guest_witness_extract_from_chain" \
    --argjson sp1_deposit_witness_item_count "$sp1_deposit_witness_item_count" \
    --argjson sp1_withdraw_witness_item_count "$sp1_withdraw_witness_item_count" \
    --argjson sp1_witness_quorum_threshold "$sp1_witness_quorum_threshold" \
    --argjson witness_endpoint_pool_size "$witness_endpoint_pool_size" \
    --argjson witness_endpoint_healthy_count "$witness_endpoint_healthy_count" \
    --arg witness_metadata_source_operator "$witness_metadata_source_operator" \
    --argjson witness_pool_operator_labels "$witness_pool_operator_labels_json" \
    --argjson witness_healthy_operator_labels "$witness_healthy_operator_labels_json" \
    --argjson witness_quorum_operator_labels "$witness_quorum_operator_labels_json" \
    --argjson witness_failed_operator_labels "$witness_failed_operator_labels_json" \
    --argjson witness_quorum_validated_count "$witness_quorum_validated_count" \
    --arg witness_quorum_validated "$witness_quorum_validated" \
    --arg sp1_deposit_program_url "$sp1_deposit_program_url" \
    --arg sp1_withdraw_program_url "$sp1_withdraw_program_url" \
    --arg sp1_input_s3_bucket "$sp1_input_s3_bucket" \
    --arg sp1_input_s3_prefix "$sp1_input_s3_prefix" \
    --arg sp1_input_s3_region "$sp1_input_s3_region" \
    --arg sp1_input_s3_presign_ttl "$sp1_input_s3_presign_ttl" \
    --arg sp1_max_price_per_pgu "$sp1_max_price_per_pgu" \
    --arg sp1_deposit_pgu_estimate "$sp1_deposit_pgu_estimate" \
    --arg sp1_withdraw_pgu_estimate "$sp1_withdraw_pgu_estimate" \
    --arg sp1_groth16_base_fee_wei "$sp1_groth16_base_fee_wei" \
    --arg sp1_projected_pair_cost_wei "$sp1_projected_pair_cost_wei" \
    --arg sp1_critical_credit_threshold_wei "$sp1_critical_credit_threshold_wei" \
    --arg sp1_required_credit_buffer_wei "$sp1_required_credit_buffer_wei" \
    --arg sp1_min_auction_period "$sp1_min_auction_period" \
    --arg sp1_auction_timeout "$sp1_auction_timeout" \
    --arg sp1_request_timeout "$sp1_request_timeout" \
    --arg withdraw_blob_bucket "$withdraw_blob_bucket" \
    --arg withdraw_blob_prefix "$withdraw_blob_prefix" \
    --arg bridge_recipient_address "$bridge_recipient_address" \
    --arg shared_enabled "$shared_enabled" \
    --arg shared_kafka_brokers "$shared_kafka_brokers" \
    --arg shared_ipfs_api_url "$shared_ipfs_api_url" \
    --arg shared_topic_prefix "$shared_topic_prefix" \
    --arg shared_timeout "$shared_timeout" \
    --arg aws_dr_region "$aws_dr_region" \
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
    --arg juno_funder_present "$([[ -n "${JUNO_FUNDER_PRIVATE_KEY_HEX:-}" || -n "${JUNO_FUNDER_SEED_PHRASE:-}" || -n "${JUNO_FUNDER_SOURCE_ADDRESS:-}" ]] && printf 'true' || printf '')" \
    --argjson run_invariants "$run_invariants_json" \
    --argjson chaos_scenarios "$chaos_scenarios_json" \
    --argjson shared "$(if [[ -f "$shared_summary" ]]; then cat "$shared_summary"; else printf 'null'; fi)" \
    --argjson dkg "$dkg_report_public_json" \
    --argjson bridge "$(cat "$bridge_summary")" \
    '{
      summary_version: 1,
      generated_at: $generated_at,
      workdir: $workdir,
      stage_control: {
        requested_stop_after_stage: $stop_after_stage,
        completed_stage: "full",
        stopped_early: false,
        stages: {
          witness_ready: ($stage_witness_ready == "true"),
          shared_services_ready: ($stage_shared_services_ready == "true"),
          checkpoint_validated: ($stage_checkpoint_validated == "true"),
          full: ($stage_full == "true")
        },
        shared_services: {
          mode: (if $proof_services_mode == "not-started" then null else $proof_services_mode end),
          stable: ($stage_shared_services_stable == "true")
        },
        checkpoint_validation: {
          bridge_config_updates_target: ($stage_checkpoint_bridge_config_update_target | tonumber),
          bridge_config_updates_succeeded: ($stage_checkpoint_bridge_config_update_success | tonumber),
          shared_validation_passed: ($stage_checkpoint_shared_validation_passed == "true")
        }
      },
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
        sp1: {
          auto: ($sp1_auto == "true"),
          submission_mode: (if $sp1_proof_submission_mode == "" then null else $sp1_proof_submission_mode end),
          bin: null,
          rpc_url: $sp1_rpc_url,
          requestor_address: (if $sp1_requestor_address == "" then null else $sp1_requestor_address end),
          input_mode: $sp1_input_mode,
          guest_witness: {
            enabled: ($sp1_input_mode == "guest-witness-v1"),
            auto_generate: ($guest_witness_auto_generate == "true"),
            extract_from_chain: ($guest_witness_extract_from_chain == "true"),
            deposit_owallet_ivk_configured: ($sp1_deposit_ivk_configured == "true"),
            withdraw_owallet_ovk_configured: ($sp1_withdraw_ovk_configured == "true"),
            deposit_witness_item_count: $sp1_deposit_witness_item_count,
            withdraw_witness_item_count: $sp1_withdraw_witness_item_count,
            endpoint_quorum_threshold: $sp1_witness_quorum_threshold,
            endpoint_pool_size: $witness_endpoint_pool_size,
            endpoint_healthy_count: $witness_endpoint_healthy_count,
            metadata_source_operator: (if $witness_metadata_source_operator == "" then null else $witness_metadata_source_operator end),
            pool_operator_labels: $witness_pool_operator_labels,
            healthy_operator_labels: $witness_healthy_operator_labels,
            quorum_operator_labels: $witness_quorum_operator_labels,
            failed_operator_labels: $witness_failed_operator_labels,
            quorum_validated_count: $witness_quorum_validated_count,
            quorum_validated: ($witness_quorum_validated == "true")
          },
          deposit_program_url: (if $sp1_deposit_program_url == "" then null else $sp1_deposit_program_url end),
          withdraw_program_url: (if $sp1_withdraw_program_url == "" then null else $sp1_withdraw_program_url end),
          input_s3_bucket: (if $sp1_input_s3_bucket == "" then null else $sp1_input_s3_bucket end),
          input_s3_prefix: (if $sp1_input_s3_prefix == "" then null else $sp1_input_s3_prefix end),
          input_s3_region: (if $sp1_input_s3_region == "" then null else $sp1_input_s3_region end),
          input_s3_presign_ttl: (if $sp1_input_s3_presign_ttl == "" then null else $sp1_input_s3_presign_ttl end),
          max_price_per_pgu: $sp1_max_price_per_pgu,
          deposit_pgu_estimate: $sp1_deposit_pgu_estimate,
          withdraw_pgu_estimate: $sp1_withdraw_pgu_estimate,
          groth16_base_fee_wei: $sp1_groth16_base_fee_wei,
          projected_pair_cost_wei: $sp1_projected_pair_cost_wei,
          critical_credit_threshold_wei: $sp1_critical_credit_threshold_wei,
          required_credit_buffer_wei: $sp1_required_credit_buffer_wei,
          min_auction_period: $sp1_min_auction_period,
          auction_timeout: $sp1_auction_timeout,
          request_timeout: $sp1_request_timeout
        },
        withdraw_blob: {
          bucket: (if $withdraw_blob_bucket == "" then null else $withdraw_blob_bucket end),
          prefix: (if $withdraw_blob_prefix == "" then null else $withdraw_blob_prefix end)
        },
        live_run_invariants: $run_invariants,
        chaos_scenarios: $chaos_scenarios,
        report: $bridge
      },
      shared_infra: {
        enabled: ($shared_enabled == "true"),
        postgres_configured: ($shared_enabled == "true"),
        kafka_brokers: (if $shared_kafka_brokers == "" then null else $shared_kafka_brokers end),
        ipfs_api_url: (if $shared_ipfs_api_url == "" then null else $shared_ipfs_api_url end),
        topic_prefix: (if $shared_topic_prefix == "" then null else $shared_topic_prefix end),
        timeout: (if $shared_timeout == "" then null else $shared_timeout end),
        dr_region: (if $aws_dr_region == "" then null else $aws_dr_region end),
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
