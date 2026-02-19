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
  --bridge-deposit-final-orchard-root <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-final-orchard-root <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-deposit-checkpoint-height <n> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-deposit-checkpoint-block-hash <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-checkpoint-height <n> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-withdraw-checkpoint-block-hash <hex> reserved; manual override not supported in guest-witness-v1 mode
  --bridge-proof-inputs-output <path> optional proof inputs bundle output path
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
  --boundless-witness-juno-scan-url <url> juno-scan URL for witness extraction (required, guest-witness-v1)
  --boundless-witness-juno-rpc-url <url> junocashd RPC URL for witness extraction (required, guest-witness-v1)
  --boundless-witness-juno-scan-urls <csv> optional comma-separated juno-scan URL pool for witness extraction failover
  --boundless-witness-juno-rpc-urls <csv> optional comma-separated junocashd RPC URL pool for witness extraction failover
  --boundless-witness-operator-labels <csv> optional comma-separated labels aligned with witness endpoint pools
  --boundless-witness-quorum-threshold <n> witness endpoint quorum threshold (default: 3)
  --boundless-witness-juno-scan-bearer-token-env <name> env var for optional juno-scan bearer token
                                   (default: JUNO_SCAN_BEARER_TOKEN)
  --boundless-witness-juno-rpc-user-env <name> env var for junocashd RPC username (default: JUNO_RPC_USER)
  --boundless-witness-juno-rpc-pass-env <name> env var for junocashd RPC password (default: JUNO_RPC_PASS)
  --boundless-witness-wallet-id <id> optional juno-scan wallet id override used for run-generated witness txs
  --boundless-witness-metadata-timeout-seconds <n> timeout for run-generated witness tx metadata (default: 900)
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
  --shared-ipfs-api-url <url>       shared IPFS API URL (required; operator checkpoint package pin/fetch verification)
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
  2) Juno witness tx generation on the configured Juno RPC + juno-scan endpoints
  3) Checkpoint quorum startup (N signers from DKG operator keys + threshold aggregator)
  4) Shared infra validation (Postgres + Kafka + run-bound checkpoint package pin/fetch via IPFS)
  5) Centralized proof-requestor/proof-funder startup on shared topics
  6) Base testnet deploy bootstrap via cmd/bridge-e2e --deploy-only, then relayer-driven bridge flow
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

  getraw_params="$(jq -cn --arg txid "$txid" '[ $txid, false ]')"
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

build_checkpoint_package_payload_file() {
  local base_chain_id="$1"
  local bridge_contract="$2"
  local threshold="$3"
  local dkg_summary="$4"
  local operator_signer_bin="$5"
  local checkpoint_height="$6"
  local checkpoint_block_hash="$7"
  local checkpoint_final_orchard_root="$8"
  local output_path="$9"

  [[ "$checkpoint_height" =~ ^[0-9]+$ ]] || die "checkpoint height must be numeric: $checkpoint_height"
  [[ "$checkpoint_block_hash" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "checkpoint block hash must be bytes32: $checkpoint_block_hash"
  [[ "$checkpoint_final_orchard_root" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "checkpoint final orchard root must be bytes32: $checkpoint_final_orchard_root"

  local eip712_domain_type_hash eip712_name_hash eip712_version_hash checkpoint_type_hash
  local checkpoint_domain_encoded checkpoint_domain_separator checkpoint_struct_encoded checkpoint_struct_hash checkpoint_digest
  eip712_domain_type_hash="$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")"
  eip712_name_hash="$(cast keccak "WJUNO Bridge")"
  eip712_version_hash="$(cast keccak "1")"
  checkpoint_type_hash="$(cast keccak "Checkpoint(uint64 height,bytes32 blockHash,bytes32 finalOrchardRoot,uint256 baseChainId,address bridgeContract)")"
  checkpoint_domain_encoded="$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address)" "$eip712_domain_type_hash" "$eip712_name_hash" "$eip712_version_hash" "$base_chain_id" "$bridge_contract")"
  checkpoint_domain_separator="$(cast keccak "$checkpoint_domain_encoded")"
  checkpoint_struct_encoded="$(cast abi-encode "f(bytes32,uint64,bytes32,bytes32,uint256,address)" "$checkpoint_type_hash" "$checkpoint_height" "$checkpoint_block_hash" "$checkpoint_final_orchard_root" "$base_chain_id" "$bridge_contract")"
  checkpoint_struct_hash="$(cast keccak "$checkpoint_struct_encoded")"
  checkpoint_digest="$(cast keccak "0x1901${checkpoint_domain_separator#0x}${checkpoint_struct_hash#0x}")"
  [[ "$checkpoint_digest" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "invalid checkpoint digest: $checkpoint_digest"

  local -a checkpoint_signers=()
  local -a checkpoint_signatures=()
  local operator_id operator_endpoint checkpoint_sign_resp checkpoint_sign_status checkpoint_sign_env_status checkpoint_sign_env_err checkpoint_signature_hex
  while IFS=$'\t' read -r operator_id operator_endpoint; do
    [[ -n "$operator_id" ]] || continue
    [[ -n "$operator_endpoint" ]] || die "checkpoint signing missing operator endpoint for operator_id=$operator_id"

    set +e
    checkpoint_sign_resp="$("$operator_signer_bin" sign-digest --digest "$checkpoint_digest" --json --operator-endpoint "$operator_endpoint" 2>&1)"
    checkpoint_sign_status=$?
    set -e
    (( checkpoint_sign_status == 0 )) || \
      die "checkpoint signing failed via operator signer for operator_id=$operator_id endpoint=$operator_endpoint: $checkpoint_sign_resp"

    checkpoint_sign_env_status="$(jq -r '.status // empty' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
    if [[ "$checkpoint_sign_env_status" != "ok" ]]; then
      checkpoint_sign_env_err="$(jq -r '.error.message // empty' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
      [[ -n "$checkpoint_sign_env_err" ]] || checkpoint_sign_env_err="$checkpoint_sign_resp"
      die "checkpoint signing returned non-ok status for operator_id=$operator_id endpoint=$operator_endpoint: $checkpoint_sign_env_err"
    fi

    checkpoint_signature_hex="$(jq -r '.data.signature // (.data.signatures[0] // empty)' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
    checkpoint_signature_hex="${checkpoint_signature_hex#0x}"
    [[ "$checkpoint_signature_hex" =~ ^[0-9a-fA-F]{130}$ ]] || \
      die "checkpoint signing returned invalid signature for operator_id=$operator_id endpoint=$operator_endpoint"
    checkpoint_signers+=("$operator_id")
    checkpoint_signatures+=("0x$checkpoint_signature_hex")
  done < <(jq -r '.operators[] | [(.operator_id | ascii_downcase), (.endpoint // .grpc_endpoint // "")] | @tsv' "$dkg_summary" | sort)

  (( ${#checkpoint_signatures[@]} >= threshold )) || \
    die "checkpoint signatures below threshold: got=${#checkpoint_signatures[@]} threshold=$threshold"

  local signers_json signatures_json
  signers_json="$(json_array_from_args "${checkpoint_signers[@]}")"
  signatures_json="$(json_array_from_args "${checkpoint_signatures[@]}")"
  jq -n \
    --arg digest "$checkpoint_digest" \
    --argjson height "$checkpoint_height" \
    --arg block_hash "$checkpoint_block_hash" \
    --arg final_orchard_root "$checkpoint_final_orchard_root" \
    --argjson base_chain_id "$base_chain_id" \
    --arg bridge_contract "$bridge_contract" \
    --argjson signers "$signers_json" \
    --argjson signatures "$signatures_json" \
    --arg created_at "$(timestamp_utc)" \
    '{
      version: "checkpoints.package.v1",
      digest: $digest,
      checkpoint: {
        height: $height,
        blockHash: $block_hash,
        finalOrchardRoot: $final_orchard_root,
        baseChainId: $base_chain_id,
        bridgeContract: $bridge_contract
      },
      operatorSetHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      signers: $signers,
      signatures: $signatures,
      createdAt: $created_at
    }' >"$output_path"
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
  local boundless_witness_juno_scan_urls_csv=""
  local boundless_witness_juno_rpc_urls_csv=""
  local boundless_witness_operator_labels_csv=""
  local boundless_witness_quorum_threshold="3"
  local boundless_witness_juno_scan_bearer_token_env="JUNO_SCAN_BEARER_TOKEN"
  local boundless_witness_juno_rpc_user_env="JUNO_RPC_USER"
  local boundless_witness_juno_rpc_pass_env="JUNO_RPC_PASS"
  local boundless_witness_wallet_id=""
  local boundless_witness_metadata_timeout_seconds="900"
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
      --boundless-witness-juno-scan-urls)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-scan-urls"
        boundless_witness_juno_scan_urls_csv="$2"
        shift 2
        ;;
      --boundless-witness-juno-rpc-urls)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-juno-rpc-urls"
        boundless_witness_juno_rpc_urls_csv="$2"
        shift 2
        ;;
      --boundless-witness-operator-labels)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-operator-labels"
        boundless_witness_operator_labels_csv="$2"
        shift 2
        ;;
      --boundless-witness-quorum-threshold)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-quorum-threshold"
        boundless_witness_quorum_threshold="$2"
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
      --boundless-witness-wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-wallet-id"
        boundless_witness_wallet_id="$2"
        shift 2
        ;;
      --boundless-witness-metadata-timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --boundless-witness-metadata-timeout-seconds"
        boundless_witness_metadata_timeout_seconds="$2"
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
  local guest_witness_extract_mode="true"
  [[ -n "$boundless_input_s3_bucket" ]] || die "--boundless-input-s3-bucket is required when --boundless-input-mode guest-witness-v1"
  [[ -n "$boundless_deposit_owallet_ivk_hex" ]] || die "--boundless-deposit-owallet-ivk-hex is required when --boundless-input-mode guest-witness-v1"
  [[ -n "$boundless_withdraw_owallet_ovk_hex" ]] || die "--boundless-withdraw-owallet-ovk-hex is required when --boundless-input-mode guest-witness-v1"
  [[ "$boundless_witness_metadata_timeout_seconds" =~ ^[0-9]+$ ]] || die "--boundless-witness-metadata-timeout-seconds must be numeric"
  (( boundless_witness_metadata_timeout_seconds > 0 )) || die "--boundless-witness-metadata-timeout-seconds must be > 0"
  [[ "$boundless_witness_quorum_threshold" =~ ^[0-9]+$ ]] || die "--boundless-witness-quorum-threshold must be numeric"
  (( boundless_witness_quorum_threshold > 0 )) || die "--boundless-witness-quorum-threshold must be > 0"
  if [[ -z "$boundless_witness_juno_scan_urls_csv" ]]; then
    boundless_witness_juno_scan_urls_csv="$boundless_witness_juno_scan_url"
  fi
  if [[ -z "$boundless_witness_juno_rpc_urls_csv" ]]; then
    boundless_witness_juno_rpc_urls_csv="$boundless_witness_juno_rpc_url"
  fi
  [[ -n "$boundless_witness_juno_scan_urls_csv" ]] || die "one of --boundless-witness-juno-scan-url or --boundless-witness-juno-scan-urls is required when guest witness extraction is enabled"
  [[ -n "$boundless_witness_juno_rpc_urls_csv" ]] || die "one of --boundless-witness-juno-rpc-url or --boundless-witness-juno-rpc-urls is required when guest witness extraction is enabled"
  if [[ -z "$boundless_witness_juno_scan_url" ]]; then
    boundless_witness_juno_scan_url="$(trim "${boundless_witness_juno_scan_urls_csv%%,*}")"
  fi
  if [[ -z "$boundless_witness_juno_rpc_url" ]]; then
    boundless_witness_juno_rpc_url="$(trim "${boundless_witness_juno_rpc_urls_csv%%,*}")"
  fi
  [[ -n "$boundless_witness_juno_scan_url" ]] || die "failed to resolve witness juno-scan URL from configured endpoint pool"
  [[ -n "$boundless_witness_juno_rpc_url" ]] || die "failed to resolve witness junocashd RPC URL from configured endpoint pool"
  [[ -n "${JUNO_FUNDER_PRIVATE_KEY_HEX:-}" ]] || die "JUNO_FUNDER_PRIVATE_KEY_HEX is required for run-generated witness metadata"
  if [[ -n "$bridge_deposit_final_orchard_root" || -n "$bridge_withdraw_final_orchard_root" || -n "$bridge_deposit_checkpoint_height" || -n "$bridge_deposit_checkpoint_block_hash" || -n "$bridge_withdraw_checkpoint_height" || -n "$bridge_withdraw_checkpoint_block_hash" ]]; then
    die "manual bridge checkpoint/orchard root overrides are not supported when --boundless-input-mode guest-witness-v1"
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

  local bridge_recipient_key_hex="0x$(openssl rand -hex 32)"
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
  local checkpoint_package_topic="${shared_topic_prefix}.checkpoints.packages.${proof_topic_seed}"
  local deposit_event_topic="${shared_topic_prefix}.deposits.events.${proof_topic_seed}"
  local withdraw_request_topic="${shared_topic_prefix}.withdrawals.requested.${proof_topic_seed}"
  local deposit_relayer_group="${shared_topic_prefix}.deposit-relayer.${proof_topic_seed}"
  local deposit_relayer_proof_group="${shared_topic_prefix}.deposit-relayer.proof.${proof_topic_seed}"
  local withdraw_coordinator_group="${shared_topic_prefix}.withdraw-coordinator.${proof_topic_seed}"
  local withdraw_finalizer_group="${shared_topic_prefix}.withdraw-finalizer.${proof_topic_seed}"
  local withdraw_finalizer_proof_group="${shared_topic_prefix}.withdraw-finalizer.proof.${proof_topic_seed}"

  local dkg_summary="$workdir/reports/dkg-summary.json"
  local bridge_summary="$workdir/reports/base-bridge-summary.json"
  local shared_summary="$shared_output"

  local bridge_juno_execution_tx_hash=""

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

  local witness_endpoint_pool_size=0
  local witness_endpoint_healthy_count=0
  local witness_quorum_validated_count=0
  local witness_quorum_validated="false"
  local witness_metadata_source_operator=""
  local -a witness_pool_operator_labels=()
  local -a witness_healthy_operator_labels=()
  local -a witness_quorum_operator_labels=()
  local -a witness_failed_operator_labels=()

  if [[ "$boundless_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    ensure_dir "$workdir/reports/witness"
    local witness_metadata_json witness_wallet_id
    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    witness_wallet_id="$boundless_witness_wallet_id"
    if [[ -z "$witness_wallet_id" ]]; then
      witness_wallet_id="testnet-e2e-${proof_topic_seed}"
    fi

    local juno_rpc_user_var juno_rpc_pass_var juno_scan_bearer_token_var
    local juno_rpc_user juno_rpc_pass juno_scan_bearer_token
    juno_rpc_user_var="$boundless_witness_juno_rpc_user_env"
    juno_rpc_pass_var="$boundless_witness_juno_rpc_pass_env"
    juno_scan_bearer_token_var="$boundless_witness_juno_scan_bearer_token_env"
    juno_rpc_user="${!juno_rpc_user_var:-}"
    juno_rpc_pass="${!juno_rpc_pass_var:-}"
    juno_scan_bearer_token="${!juno_scan_bearer_token_var:-}"
    [[ -n "$juno_rpc_user" ]] || die "missing Juno RPC user env var: $juno_rpc_user_var"
    [[ -n "$juno_rpc_pass" ]] || die "missing Juno RPC pass env var: $juno_rpc_pass_var"

    local witness_quorum_threshold
    witness_quorum_threshold="$boundless_witness_quorum_threshold"

    local -a witness_scan_urls_raw=()
    local -a witness_rpc_urls_raw=()
    local -a witness_operator_labels_raw=()
    local -a witness_scan_urls=()
    local -a witness_rpc_urls=()
    local -a witness_operator_labels=()
    local witness_entry

    IFS=',' read -r -a witness_scan_urls_raw <<<"$boundless_witness_juno_scan_urls_csv"
    for witness_entry in "${witness_scan_urls_raw[@]}"; do
      witness_entry="$(trim "$witness_entry")"
      [[ -n "$witness_entry" ]] || continue
      witness_scan_urls+=("$witness_entry")
    done

    IFS=',' read -r -a witness_rpc_urls_raw <<<"$boundless_witness_juno_rpc_urls_csv"
    for witness_entry in "${witness_rpc_urls_raw[@]}"; do
      witness_entry="$(trim "$witness_entry")"
      [[ -n "$witness_entry" ]] || continue
      witness_rpc_urls+=("$witness_entry")
    done

    (( ${#witness_scan_urls[@]} > 0 )) || die "witness endpoint pool is empty: --boundless-witness-juno-scan-urls"
    (( ${#witness_scan_urls[@]} == ${#witness_rpc_urls[@]} )) || \
      die "witness endpoint pool mismatch: scan_urls=${#witness_scan_urls[@]} rpc_urls=${#witness_rpc_urls[@]}"

    if [[ -n "$boundless_witness_operator_labels_csv" ]]; then
      IFS=',' read -r -a witness_operator_labels_raw <<<"$boundless_witness_operator_labels_csv"
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
    local witness_idx
    for ((witness_idx = 0; witness_idx < witness_endpoint_pool_size; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      witness_scan_url="${witness_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_operator_labels[$witness_idx]}"
      if witness_pair_healthcheck "$witness_scan_url" "$witness_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$juno_scan_bearer_token"; then
        witness_healthy_scan_urls+=("$witness_scan_url")
        witness_healthy_rpc_urls+=("$witness_rpc_url")
        witness_healthy_labels+=("$witness_operator_label")
        log "witness endpoint healthy operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
      else
        log "witness endpoint unhealthy operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
      fi
    done

    witness_endpoint_healthy_count="${#witness_healthy_scan_urls[@]}"
    witness_healthy_operator_labels=("${witness_healthy_labels[@]}")
    (( witness_endpoint_healthy_count >= witness_quorum_threshold )) || \
      die "failed to build healthy witness endpoint pool with quorum: healthy=$witness_endpoint_healthy_count threshold=$witness_quorum_threshold configured=$witness_endpoint_pool_size"

    local witness_metadata_generated="false"
    local witness_metadata_source_scan_url=""
    local witness_metadata_source_rpc_url=""
    for ((witness_idx = 0; witness_idx < witness_endpoint_healthy_count; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      local witness_operator_safe_label witness_wallet_id_attempt witness_metadata_attempt_json
      witness_scan_url="${witness_healthy_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_healthy_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_idx]}"
      witness_operator_safe_label="$(printf '%s' "$witness_operator_label" | tr -cs '[:alnum:]_.-' '_')"
      witness_operator_safe_label="${witness_operator_safe_label#_}"
      witness_operator_safe_label="${witness_operator_safe_label%_}"
      [[ -n "$witness_operator_safe_label" ]] || witness_operator_safe_label="op$((witness_idx + 1))"
      witness_metadata_attempt_json="$workdir/reports/witness/generated-witness-metadata-${witness_operator_safe_label}.json"
      if (( witness_idx == 0 )); then
        witness_wallet_id_attempt="$witness_wallet_id"
      else
        witness_wallet_id_attempt="${witness_wallet_id}-${witness_operator_safe_label}"
      fi

      local -a witness_metadata_args=(
        run
        --juno-rpc-url "$witness_rpc_url"
        --juno-rpc-user "$juno_rpc_user"
        --juno-rpc-pass "$juno_rpc_pass"
        --juno-scan-url "$witness_scan_url"
        --funder-private-key-hex "${JUNO_FUNDER_PRIVATE_KEY_HEX}"
        --wallet-id "$witness_wallet_id_attempt"
        --deposit-amount-zat "100000"
        --withdraw-amount-zat "10000"
        --timeout-seconds "$boundless_witness_metadata_timeout_seconds"
        --output "$witness_metadata_attempt_json"
      )
      if [[ -n "$juno_scan_bearer_token" ]]; then
        witness_metadata_args+=("--juno-scan-bearer-token" "$juno_scan_bearer_token")
      fi

      if (
        cd "$REPO_ROOT"
        deploy/operators/dkg/e2e/generate-juno-witness-metadata.sh "${witness_metadata_args[@]}" >/dev/null
      ); then
        cp "$witness_metadata_attempt_json" "$witness_metadata_json"
        witness_metadata_source_scan_url="$witness_scan_url"
        witness_metadata_source_rpc_url="$witness_rpc_url"
        witness_metadata_source_operator="$witness_operator_label"
        witness_metadata_generated="true"
        log "generated witness metadata from operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
        break
      fi
      log "witness metadata generation failed for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url; trying next healthy endpoint"
    done

    [[ "$witness_metadata_generated" == "true" ]] || \
      die "failed to generate witness metadata from healthy witness endpoint pool"
    boundless_witness_juno_scan_url="$witness_metadata_source_scan_url"
    boundless_witness_juno_rpc_url="$witness_metadata_source_rpc_url"

    local generated_wallet_id generated_deposit_txid generated_deposit_action_index
    local generated_withdraw_txid generated_withdraw_action_index generated_recipient_raw_address_hex generated_ufvk
    generated_wallet_id="$(jq -r '.wallet_id // empty' "$witness_metadata_json")"
    generated_deposit_txid="$(jq -r '.deposit_txid // empty' "$witness_metadata_json")"
    generated_deposit_action_index="$(jq -r '.deposit_action_index // empty' "$witness_metadata_json")"
    generated_withdraw_txid="$(jq -r '.withdraw_txid // empty' "$witness_metadata_json")"
    generated_withdraw_action_index="$(jq -r '.withdraw_action_index // empty' "$witness_metadata_json")"
    generated_recipient_raw_address_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json")"
    generated_ufvk="$(jq -r '.ufvk // empty' "$witness_metadata_json")"

    [[ -n "$generated_wallet_id" ]] || die "generated witness metadata missing wallet_id: $witness_metadata_json"
    [[ -n "$generated_deposit_txid" ]] || die "generated witness metadata missing deposit_txid: $witness_metadata_json"
    [[ "$generated_deposit_action_index" =~ ^[0-9]+$ ]] || die "generated witness metadata deposit_action_index is invalid: $generated_deposit_action_index"
    [[ -n "$generated_withdraw_txid" ]] || die "generated witness metadata missing withdraw_txid: $witness_metadata_json"
    [[ "$generated_withdraw_action_index" =~ ^[0-9]+$ ]] || die "generated witness metadata withdraw_action_index is invalid: $generated_withdraw_action_index"
    [[ "$generated_recipient_raw_address_hex" =~ ^[0-9a-fA-F]{86}$ ]] || \
      die "generated witness metadata recipient_raw_address_hex must be 43 bytes hex: $generated_recipient_raw_address_hex"
    [[ -n "$generated_ufvk" ]] || die "generated witness metadata missing ufvk: $witness_metadata_json"

    local bridge_deployer_start_nonce bridge_deploy_nonce bridge_predicted_address
    bridge_deployer_start_nonce="$(cast nonce --rpc-url "$base_rpc_url" --block pending "$bridge_deployer_address" 2>/dev/null || true)"
    [[ "$bridge_deployer_start_nonce" =~ ^[0-9]+$ ]] || \
      die "failed to resolve deployer nonce for predicted bridge address: address=$bridge_deployer_address nonce=$bridge_deployer_start_nonce"
    bridge_deploy_nonce=$((bridge_deployer_start_nonce + 3))
    bridge_predicted_address="$(cast compute-address --nonce "$bridge_deploy_nonce" "$bridge_deployer_address" | sed -n 's/^Computed Address:[[:space:]]*//p')"
    [[ "$bridge_predicted_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
      die "failed to compute predicted bridge address for nonce=$bridge_deploy_nonce deployer=$bridge_deployer_address"

    local boundless_withdraw_witness_withdrawal_id_hex
    boundless_withdraw_witness_withdrawal_id_hex="$(
      cd "$REPO_ROOT"
      deploy/operators/dkg/e2e/compute-bridge-withdrawal-id.sh run \
        --base-chain-id "$base_chain_id" \
        --bridge-address "$bridge_predicted_address" \
        --requester-address "$bridge_deployer_address" \
        --recipient-raw-address-hex "$generated_recipient_raw_address_hex" \
        --amount-zat "10000" \
        --withdraw-nonce "1"
    )"
    [[ "$boundless_withdraw_witness_withdrawal_id_hex" =~ ^0x[0-9a-fA-F]{64}$ ]] || \
      die "computed withdrawal id is invalid: $boundless_withdraw_witness_withdrawal_id_hex"

    local deposit_witness_auto_file="$workdir/reports/witness/deposit.witness.bin"
    local withdraw_witness_auto_file="$workdir/reports/witness/withdraw.witness.bin"
    local deposit_witness_auto_json="$workdir/reports/witness/deposit-witness.json"
    local withdraw_witness_auto_json="$workdir/reports/witness/withdraw-witness.json"
    local recipient_raw_address_hex_prefixed="0x${generated_recipient_raw_address_hex}"

    local witness_upsert_idx
    for ((witness_upsert_idx = 0; witness_upsert_idx < witness_endpoint_healthy_count; witness_upsert_idx++)); do
      local witness_scan_url witness_operator_label
      witness_scan_url="${witness_healthy_scan_urls[$witness_upsert_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_upsert_idx]}"
      if ! witness_scan_upsert_wallet "$witness_scan_url" "$juno_scan_bearer_token" "$generated_wallet_id" "$generated_ufvk"; then
        log "witness wallet upsert failed for operator=$witness_operator_label scan_url=$witness_scan_url (continuing; extraction will determine usable quorum)"
      fi
    done

    local witness_quorum_dir
    witness_quorum_dir="$workdir/reports/witness/quorum"
    ensure_dir "$witness_quorum_dir"
    local -a witness_success_labels=()
    local -a witness_success_fingerprints=()
    local -a witness_success_deposit_json=()
    local -a witness_success_withdraw_json=()
    local -a witness_success_deposit_witness=()
    local -a witness_success_withdraw_witness=()

    for ((witness_idx = 0; witness_idx < witness_endpoint_healthy_count; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      local witness_operator_safe_label deposit_candidate_witness withdraw_candidate_witness
      local deposit_candidate_json withdraw_candidate_json
      local witness_extract_attempt witness_extract_ok
      witness_scan_url="${witness_healthy_scan_urls[$witness_idx]}"
      witness_rpc_url="${witness_healthy_rpc_urls[$witness_idx]}"
      witness_operator_label="${witness_healthy_labels[$witness_idx]}"
      witness_operator_safe_label="$(printf '%s' "$witness_operator_label" | tr -cs '[:alnum:]_.-' '_')"
      witness_operator_safe_label="${witness_operator_safe_label#_}"
      witness_operator_safe_label="${witness_operator_safe_label%_}"
      [[ -n "$witness_operator_safe_label" ]] || witness_operator_safe_label="op$((witness_idx + 1))"

      deposit_candidate_witness="$witness_quorum_dir/deposit-${witness_operator_safe_label}.witness.bin"
      withdraw_candidate_witness="$witness_quorum_dir/withdraw-${witness_operator_safe_label}.witness.bin"
      deposit_candidate_json="$witness_quorum_dir/deposit-${witness_operator_safe_label}.json"
      withdraw_candidate_json="$witness_quorum_dir/withdraw-${witness_operator_safe_label}.json"

      witness_extract_ok="false"
      for witness_extract_attempt in $(seq 1 6); do
        if (
          cd "$REPO_ROOT"
          go run ./cmd/juno-witness-extract deposit \
            --juno-scan-url "$witness_scan_url" \
            --wallet-id "$generated_wallet_id" \
            --juno-scan-bearer-token-env "$boundless_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$witness_rpc_url" \
            --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
            --txid "$generated_deposit_txid" \
            --action-index "$generated_deposit_action_index" \
            --output-witness-item-file "$deposit_candidate_witness" >"$deposit_candidate_json"

          go run ./cmd/juno-witness-extract withdraw \
            --juno-scan-url "$witness_scan_url" \
            --wallet-id "$generated_wallet_id" \
            --juno-scan-bearer-token-env "$boundless_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$witness_rpc_url" \
            --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
            --txid "$generated_withdraw_txid" \
            --action-index "$generated_withdraw_action_index" \
            --withdrawal-id-hex "$boundless_withdraw_witness_withdrawal_id_hex" \
            --recipient-raw-address-hex "$recipient_raw_address_hex_prefixed" \
            --output-witness-item-file "$withdraw_candidate_witness" >"$withdraw_candidate_json"
        ); then
          witness_extract_ok="true"
          break
        fi
        if (( witness_extract_attempt < 6 )); then
          sleep 5
        fi
      done

      if [[ "$witness_extract_ok" != "true" ]]; then
        witness_failed_operator_labels+=("$witness_operator_label")
        log "witness extraction failed for operator=$witness_operator_label scan_url=$witness_scan_url rpc_url=$witness_rpc_url"
        continue
      fi

      local deposit_witness_hex deposit_anchor_height deposit_anchor_hash deposit_final_root
      local withdraw_witness_hex withdraw_anchor_height withdraw_anchor_hash withdraw_final_root
      deposit_witness_hex="$(jq -r '.witness_item_hex // empty' "$deposit_candidate_json")"
      deposit_anchor_height="$(jq -r '.anchor_height // empty' "$deposit_candidate_json")"
      deposit_anchor_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_candidate_json")"
      deposit_final_root="$(jq -r '.final_orchard_root // empty' "$deposit_candidate_json")"
      withdraw_witness_hex="$(jq -r '.witness_item_hex // empty' "$withdraw_candidate_json")"
      withdraw_anchor_height="$(jq -r '.anchor_height // empty' "$withdraw_candidate_json")"
      withdraw_anchor_hash="$(jq -r '.anchor_block_hash // empty' "$withdraw_candidate_json")"
      withdraw_final_root="$(jq -r '.final_orchard_root // empty' "$withdraw_candidate_json")"

      [[ -n "$deposit_witness_hex" ]] || die "deposit witness output missing witness_item_hex: $deposit_candidate_json"
      [[ -n "$deposit_anchor_height" ]] || die "deposit witness output missing anchor_height: $deposit_candidate_json"
      [[ -n "$deposit_anchor_hash" ]] || die "deposit witness output missing anchor_block_hash: $deposit_candidate_json"
      [[ -n "$deposit_final_root" ]] || die "deposit witness output missing final_orchard_root: $deposit_candidate_json"
      [[ -n "$withdraw_witness_hex" ]] || die "withdraw witness output missing witness_item_hex: $withdraw_candidate_json"
      [[ -n "$withdraw_anchor_height" ]] || die "withdraw witness output missing anchor_height: $withdraw_candidate_json"
      [[ -n "$withdraw_anchor_hash" ]] || die "withdraw witness output missing anchor_block_hash: $withdraw_candidate_json"
      [[ -n "$withdraw_final_root" ]] || die "withdraw witness output missing final_orchard_root: $withdraw_candidate_json"

      local witness_fingerprint
      witness_fingerprint="${deposit_witness_hex}|${deposit_anchor_height}|${deposit_anchor_hash}|${deposit_final_root}|${withdraw_witness_hex}|${withdraw_anchor_height}|${withdraw_anchor_hash}|${withdraw_final_root}"
      witness_success_labels+=("$witness_operator_label")
      witness_success_fingerprints+=("$witness_fingerprint")
      witness_success_deposit_json+=("$deposit_candidate_json")
      witness_success_withdraw_json+=("$withdraw_candidate_json")
      witness_success_deposit_witness+=("$deposit_candidate_witness")
      witness_success_withdraw_witness+=("$withdraw_candidate_witness")
      log "witness extraction succeeded for operator=$witness_operator_label"
    done

    witness_quorum_validated_count="${#witness_success_labels[@]}"
    witness_quorum_operator_labels=("${witness_success_labels[@]}")
    (( witness_quorum_validated_count >= witness_quorum_threshold )) || \
      die "failed to extract witness from quorum of operators: success=$witness_quorum_validated_count threshold=$witness_quorum_threshold"

    local -a witness_unique_fingerprints=()
    local witness_fingerprint witness_existing_fingerprint witness_known_fingerprint
    for witness_fingerprint in "${witness_success_fingerprints[@]}"; do
      witness_known_fingerprint="false"
      for witness_existing_fingerprint in "${witness_unique_fingerprints[@]}"; do
        if [[ "$witness_existing_fingerprint" == "$witness_fingerprint" ]]; then
          witness_known_fingerprint="true"
          break
        fi
      done
      if [[ "$witness_known_fingerprint" != "true" ]]; then
        witness_unique_fingerprints+=("$witness_fingerprint")
      fi
    done
    if (( ${#witness_unique_fingerprints[@]} != 1 )); then
      die "witness quorum consistency mismatch across operators: operators=$(IFS=,; printf '%s' "${witness_success_labels[*]}")"
    fi
    witness_quorum_validated="true"

    cp "${witness_success_deposit_witness[0]}" "$deposit_witness_auto_file"
    cp "${witness_success_withdraw_witness[0]}" "$withdraw_witness_auto_file"
    cp "${witness_success_deposit_json[0]}" "$deposit_witness_auto_json"
    cp "${witness_success_withdraw_json[0]}" "$withdraw_witness_auto_json"

    boundless_deposit_witness_item_files=("$deposit_witness_auto_file")
    boundless_withdraw_witness_item_files=("$withdraw_witness_auto_file")

    bridge_deposit_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$deposit_witness_auto_json")"
    bridge_withdraw_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$withdraw_witness_auto_json")"
    bridge_deposit_checkpoint_height="$(jq -r '.anchor_height // empty' "$deposit_witness_auto_json")"
    bridge_deposit_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_witness_auto_json")"
    bridge_withdraw_checkpoint_height="$(jq -r '.anchor_height // empty' "$withdraw_witness_auto_json")"
    bridge_withdraw_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$withdraw_witness_auto_json")"

    bridge_juno_execution_tx_hash="$generated_withdraw_txid"
    log "resolved canonical juno execution tx hash from run-generated withdraw witness txid=$bridge_juno_execution_tx_hash"
  fi

  if [[ -n "$bridge_juno_execution_tx_hash" && -n "$boundless_witness_juno_rpc_url" ]]; then
    local juno_rpc_user_var juno_rpc_pass_var juno_rpc_user juno_rpc_pass
    juno_rpc_user_var="$boundless_witness_juno_rpc_user_env"
    juno_rpc_pass_var="$boundless_witness_juno_rpc_pass_env"
    juno_rpc_user="${!juno_rpc_user_var:-}"
    juno_rpc_pass="${!juno_rpc_pass_var:-}"
    if [[ -n "$juno_rpc_user" && -n "$juno_rpc_pass" ]]; then
      juno_rebroadcast_tx \
        "$boundless_witness_juno_rpc_url" \
        "$juno_rpc_user" \
        "$juno_rpc_pass" \
        "$bridge_juno_execution_tx_hash"
    else
      log "skipping juno tx rebroadcast (missing env vars $juno_rpc_user_var/$juno_rpc_pass_var)"
    fi
  fi
  [[ -n "$bridge_juno_execution_tx_hash" ]] || \
    die "canonical juno execution tx hash is required from run-generated witness metadata"

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
    local checkpoint_started_at checkpoint_operators_csv
    checkpoint_started_at="$(timestamp_utc)"
    checkpoint_operators_csv="$(jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary")"
    [[ -n "$checkpoint_operators_csv" ]] || die "failed to derive checkpoint operators from dkg summary"

    local checkpoint_agg_log checkpoint_agg_pid checkpoint_signatures_fifo
    checkpoint_agg_log="$workdir/reports/checkpoint-aggregator.log"
    checkpoint_signatures_fifo="$workdir/reports/checkpoint-signatures.fifo"
    rm -f "$checkpoint_signatures_fifo"
    mkfifo "$checkpoint_signatures_fifo"
    (
      cd "$REPO_ROOT"
      go run ./cmd/checkpoint-aggregator \
        --base-chain-id "$base_chain_id" \
        --bridge-address "$bridge_verifier_address" \
        --operators "$checkpoint_operators_csv" \
        --threshold "$threshold" \
        --postgres-dsn "$shared_postgres_dsn" \
        --store-driver postgres \
        --blob-driver memory \
        --ipfs-enabled=true \
        --ipfs-api-url "$shared_ipfs_api_url" \
        --queue-driver stdio \
        --queue-output-topic "$checkpoint_package_topic" \
        <"$checkpoint_signatures_fifo" \
        >"$checkpoint_agg_log" 2>&1
    ) &
    checkpoint_agg_pid="$!"
    exec 3>"$checkpoint_signatures_fifo"

    local checkpoint_rpc_user_var checkpoint_rpc_pass_var checkpoint_rpc_user checkpoint_rpc_pass
    checkpoint_rpc_user_var="$boundless_witness_juno_rpc_user_env"
    checkpoint_rpc_pass_var="$boundless_witness_juno_rpc_pass_env"
    checkpoint_rpc_user="${!checkpoint_rpc_user_var:-}"
    checkpoint_rpc_pass="${!checkpoint_rpc_pass_var:-}"
    [[ -n "$checkpoint_rpc_user" ]] || die "missing Juno RPC user env var for checkpoint signing: $checkpoint_rpc_user_var"
    [[ -n "$checkpoint_rpc_pass" ]] || die "missing Juno RPC pass env var for checkpoint signing: $checkpoint_rpc_pass_var"

    local checkpoint_tip_resp checkpoint_tip_error checkpoint_tip_height
    checkpoint_tip_resp="$(juno_rpc_json_call "$boundless_witness_juno_rpc_url" "$checkpoint_rpc_user" "$checkpoint_rpc_pass" "getblockchaininfo" "[]")"
    checkpoint_tip_error="$(jq -r '.error.message // empty' <<<"$checkpoint_tip_resp")"
    [[ -z "$checkpoint_tip_error" ]] || die "checkpoint signing failed to fetch Juno tip: $checkpoint_tip_error"
    checkpoint_tip_height="$(jq -r '.result.blocks // empty' <<<"$checkpoint_tip_resp")"
    [[ "$checkpoint_tip_height" =~ ^[0-9]+$ ]] || die "checkpoint signing got invalid Juno tip height: $checkpoint_tip_height"
    (( checkpoint_tip_height >= 1 )) || die "checkpoint signing requires Juno tip >= 1 (got $checkpoint_tip_height)"

    local checkpoint_height checkpoint_hash_params checkpoint_hash_resp checkpoint_hash_error checkpoint_block_hash_raw
    checkpoint_height=$((checkpoint_tip_height - 1))
    checkpoint_hash_params="$(jq -cn --argjson height "$checkpoint_height" '[ $height ]')"
    checkpoint_hash_resp="$(juno_rpc_json_call "$boundless_witness_juno_rpc_url" "$checkpoint_rpc_user" "$checkpoint_rpc_pass" "getblockhash" "$checkpoint_hash_params")"
    checkpoint_hash_error="$(jq -r '.error.message // empty' <<<"$checkpoint_hash_resp")"
    [[ -z "$checkpoint_hash_error" ]] || die "checkpoint signing failed to fetch block hash at height=$checkpoint_height: $checkpoint_hash_error"
    checkpoint_block_hash_raw="$(jq -r '.result // empty' <<<"$checkpoint_hash_resp")"
    checkpoint_block_hash_raw="${checkpoint_block_hash_raw#0x}"
    [[ "$checkpoint_block_hash_raw" =~ ^[0-9a-fA-F]{64}$ ]] || die "checkpoint signing got invalid block hash for height=$checkpoint_height: $checkpoint_block_hash_raw"

    local checkpoint_block_params checkpoint_block_resp checkpoint_block_error checkpoint_block_hash checkpoint_final_orchard_root
    checkpoint_block_params="$(jq -cn --arg hash "$checkpoint_block_hash_raw" '[ $hash, 1 ]')"
    checkpoint_block_resp="$(juno_rpc_json_call "$boundless_witness_juno_rpc_url" "$checkpoint_rpc_user" "$checkpoint_rpc_pass" "getblock" "$checkpoint_block_params")"
    checkpoint_block_error="$(jq -r '.error.message // empty' <<<"$checkpoint_block_resp")"
    [[ -z "$checkpoint_block_error" ]] || die "checkpoint signing failed to fetch block payload at height=$checkpoint_height: $checkpoint_block_error"
    checkpoint_block_hash="$(jq -r '.result.hash // empty' <<<"$checkpoint_block_resp")"
    checkpoint_block_hash="${checkpoint_block_hash#0x}"
    checkpoint_final_orchard_root="$(jq -r '.result.finalorchardroot // empty' <<<"$checkpoint_block_resp")"
    checkpoint_final_orchard_root="${checkpoint_final_orchard_root#0x}"
    [[ "$checkpoint_block_hash" =~ ^[0-9a-fA-F]{64}$ ]] || die "checkpoint signing block payload missing hash for height=$checkpoint_height"
    [[ "$checkpoint_final_orchard_root" =~ ^[0-9a-fA-F]{64}$ ]] || \
      die "checkpoint signing block payload missing finalorchardroot for height=$checkpoint_height"
    checkpoint_block_hash="0x$checkpoint_block_hash"
    checkpoint_final_orchard_root="0x$checkpoint_final_orchard_root"

    local eip712_domain_type_hash eip712_name_hash eip712_version_hash checkpoint_type_hash
    local checkpoint_domain_encoded checkpoint_domain_separator checkpoint_struct_encoded checkpoint_struct_hash checkpoint_digest
    eip712_domain_type_hash="$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")"
    eip712_name_hash="$(cast keccak "WJUNO Bridge")"
    eip712_version_hash="$(cast keccak "1")"
    checkpoint_type_hash="$(cast keccak "Checkpoint(uint64 height,bytes32 blockHash,bytes32 finalOrchardRoot,uint256 baseChainId,address bridgeContract)")"
    checkpoint_domain_encoded="$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address)" "$eip712_domain_type_hash" "$eip712_name_hash" "$eip712_version_hash" "$base_chain_id" "$bridge_verifier_address")"
    checkpoint_domain_separator="$(cast keccak "$checkpoint_domain_encoded")"
    checkpoint_struct_encoded="$(cast abi-encode "f(bytes32,uint64,bytes32,bytes32,uint256,address)" "$checkpoint_type_hash" "$checkpoint_height" "$checkpoint_block_hash" "$checkpoint_final_orchard_root" "$base_chain_id" "$bridge_verifier_address")"
    checkpoint_struct_hash="$(cast keccak "$checkpoint_struct_encoded")"
    checkpoint_digest="$(cast keccak "0x1901${checkpoint_domain_separator#0x}${checkpoint_struct_hash#0x}")"
    [[ "$checkpoint_digest" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "checkpoint signing produced invalid digest: $checkpoint_digest"

    local checkpoint_signatures_published
    checkpoint_signatures_published=0
    local operator_id operator_endpoint checkpoint_sign_resp checkpoint_sign_status checkpoint_sign_env_status checkpoint_sign_env_err checkpoint_signature_hex checkpoint_signed_at checkpoint_signature_payload
    while IFS=$'\t' read -r operator_id operator_endpoint; do
      [[ -n "$operator_id" ]] || continue
      [[ -n "$operator_endpoint" ]] || die "checkpoint signing missing operator endpoint for operator_id=$operator_id"

      set +e
      checkpoint_sign_resp="$("$bridge_operator_signer_bin" sign-digest --digest "$checkpoint_digest" --json --operator-endpoint "$operator_endpoint" 2>&1)"
      checkpoint_sign_status=$?
      set -e
      (( checkpoint_sign_status == 0 )) || \
        die "checkpoint signing failed via operator signer for operator_id=$operator_id endpoint=$operator_endpoint: $checkpoint_sign_resp"

      checkpoint_sign_env_status="$(jq -r '.status // empty' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
      if [[ "$checkpoint_sign_env_status" != "ok" ]]; then
        checkpoint_sign_env_err="$(jq -r '.error.message // empty' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
        [[ -n "$checkpoint_sign_env_err" ]] || checkpoint_sign_env_err="$checkpoint_sign_resp"
        die "checkpoint signing returned non-ok status for operator_id=$operator_id endpoint=$operator_endpoint: $checkpoint_sign_env_err"
      fi

      checkpoint_signature_hex="$(jq -r '.data.signature // (.data.signatures[0] // empty)' <<<"$checkpoint_sign_resp" 2>/dev/null || true)"
      checkpoint_signature_hex="${checkpoint_signature_hex#0x}"
      [[ "$checkpoint_signature_hex" =~ ^[0-9a-fA-F]{130}$ ]] || \
        die "checkpoint signing returned invalid signature for operator_id=$operator_id endpoint=$operator_endpoint"
      checkpoint_signature_hex="0x$checkpoint_signature_hex"

      checkpoint_signed_at="$(timestamp_utc)"
      checkpoint_signature_payload="$(
        jq -cn \
          --arg operator "$operator_id" \
          --arg digest "$checkpoint_digest" \
          --arg signature "$checkpoint_signature_hex" \
          --arg signed_at "$checkpoint_signed_at" \
          --argjson checkpoint_height "$checkpoint_height" \
          --arg checkpoint_block_hash "$checkpoint_block_hash" \
          --arg checkpoint_final_orchard_root "$checkpoint_final_orchard_root" \
          --argjson checkpoint_base_chain_id "$base_chain_id" \
          --arg checkpoint_bridge_contract "$bridge_verifier_address" \
          '{
            version: "checkpoints.signature.v1",
            operator: $operator,
            digest: $digest,
            signature: $signature,
            checkpoint: {
              height: $checkpoint_height,
              blockHash: $checkpoint_block_hash,
              finalOrchardRoot: $checkpoint_final_orchard_root,
              baseChainId: $checkpoint_base_chain_id,
              bridgeContract: $checkpoint_bridge_contract
            },
            signedAt: $signed_at
          }'
      )"
      printf '%s\n' "$checkpoint_signature_payload" >&3 || die "failed to enqueue checkpoint signature for operator_id=$operator_id"
      checkpoint_signatures_published=$((checkpoint_signatures_published + 1))
    done < <(jq -r '.operators[] | [.operator_id, (.endpoint // .grpc_endpoint // "")] | @tsv' "$dkg_summary")

    (( checkpoint_signatures_published >= threshold )) || \
      die "checkpoint signature publication below threshold: got=$checkpoint_signatures_published threshold=$threshold"

    local shared_status=0
    set +e
    (
      cd "$REPO_ROOT"
      go run ./cmd/shared-infra-e2e \
        --postgres-dsn "$shared_postgres_dsn" \
        --kafka-brokers "$shared_kafka_brokers" \
        --checkpoint-ipfs-api-url "$shared_ipfs_api_url" \
        --checkpoint-operators "$checkpoint_operators_csv" \
        --checkpoint-threshold "$threshold" \
        --checkpoint-min-persisted-at "$checkpoint_started_at" \
        --topic-prefix "$shared_topic_prefix" \
        --timeout "$shared_timeout" \
        --output "$shared_summary"
    )
    shared_status="$?"
    set -e

    exec 3>&-
    kill "$checkpoint_agg_pid" >/dev/null 2>&1 || true
    wait "$checkpoint_agg_pid" >/dev/null 2>&1 || true
    rm -f "$checkpoint_signatures_fifo"

    if (( shared_status != 0 )); then
      log "shared infra validation failed; showing checkpoint quorum logs"
      tail -n 200 "$checkpoint_agg_log" >&2 || true
      die "shared infra validation failed"
    fi
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
    "--deploy-only"
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
  bridge_args+=("--juno-execution-tx-hash" "$bridge_juno_execution_tx_hash")
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
    go run ./cmd/bridge-e2e --deploy-only "${bridge_args[@]}"
  )
  bridge_status="$?"
  set -e
  if (( bridge_status != 0 )); then
    if [[ "$shared_ecs_enabled" == "true" ]]; then
      log "bridge-e2e deploy bootstrap failed; showing shared ECS proof service logs"
      dump_shared_proof_services_ecs_logs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name"
    else
      log "bridge-e2e deploy bootstrap failed; showing proof-requestor and proof-funder logs"
      tail -n 200 "$proof_requestor_log" >&2 || true
      tail -n 200 "$proof_funder_log" >&2 || true
    fi
    die "bridge-e2e deploy bootstrap failed while centralized proof services were running"
  fi

  local deployed_bridge_address deployed_wjuno_address
  deployed_bridge_address="$(jq -r '.contracts.bridge // empty' "$bridge_summary")"
  deployed_wjuno_address="$(jq -r '.contracts.wjuno // empty' "$bridge_summary")"
  [[ "$deployed_bridge_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
    die "bridge summary missing deployed contracts.bridge address: $bridge_summary"
  [[ "$deployed_wjuno_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
    die "bridge summary missing deployed contracts.wjuno address: $bridge_summary"

  local bridge_deployer_key_hex
  bridge_deployer_key_hex="$(trimmed_file_value "$bridge_deployer_key_file")"
  [[ -n "$bridge_deployer_key_hex" ]] || die "bridge deployer key file is empty: $bridge_deployer_key_file"

  local base_relayer_log="$workdir/reports/base-relayer.log"
  local deposit_relayer_log="$workdir/reports/deposit-relayer.log"
  local withdraw_coordinator_log="$workdir/reports/withdraw-coordinator.log"
  local withdraw_finalizer_log="$workdir/reports/withdraw-finalizer.log"
  local base_relayer_pid=""
  local deposit_relayer_pid=""
  local withdraw_coordinator_pid=""
  local withdraw_finalizer_pid=""
  local relayer_status=0

  local base_relayer_port base_relayer_url base_relayer_auth_token
  base_relayer_port="$((base_port + 1200))"
  base_relayer_url="http://127.0.0.1:${base_relayer_port}"
  base_relayer_auth_token="$(openssl rand -hex 24)"

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
  sleep 3
  if ! kill -0 "$base_relayer_pid" >/dev/null 2>&1; then
    relayer_status=1
  fi

  if (( relayer_status == 0 )); then
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
          --owallet-ivk "$boundless_deposit_owallet_ivk_hex" \
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
      go run ./cmd/withdraw-coordinator \
        --runtime-mode mock \
        --postgres-dsn "$shared_postgres_dsn" \
        --owner "testnet-e2e-withdraw-coordinator-${proof_topic_seed}" \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --queue-group "$withdraw_coordinator_group" \
        --queue-topics "$withdraw_request_topic" \
        --blob-driver memory \
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
          --owallet-ovk "$boundless_withdraw_owallet_ovk_hex" \
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
          --blob-driver memory \
          >"$withdraw_finalizer_log" 2>&1
    ) &
    withdraw_finalizer_pid="$!"

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
    local checkpoint_package_deposit_payload checkpoint_package_withdraw_payload
    checkpoint_package_deposit_payload="$workdir/reports/checkpoint-package-deposit.json"
    checkpoint_package_withdraw_payload="$workdir/reports/checkpoint-package-withdraw.json"
    build_checkpoint_package_payload_file \
      "$base_chain_id" \
      "$deployed_bridge_address" \
      "$threshold" \
      "$dkg_summary" \
      "$bridge_operator_signer_bin" \
      "$bridge_deposit_checkpoint_height" \
      "$bridge_deposit_checkpoint_block_hash" \
      "$bridge_deposit_final_orchard_root" \
      "$checkpoint_package_deposit_payload"
    build_checkpoint_package_payload_file \
      "$base_chain_id" \
      "$deployed_bridge_address" \
      "$threshold" \
      "$dkg_summary" \
      "$bridge_operator_signer_bin" \
      "$bridge_withdraw_checkpoint_height" \
      "$bridge_withdraw_checkpoint_block_hash" \
      "$bridge_withdraw_final_orchard_root" \
      "$checkpoint_package_withdraw_payload"

    (
      cd "$REPO_ROOT"
      go run ./cmd/queue-publish \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --topic "$checkpoint_package_topic" \
        --payload-file "$checkpoint_package_deposit_payload"
      go run ./cmd/queue-publish \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --topic "$checkpoint_package_topic" \
        --payload-file "$checkpoint_package_withdraw_payload"
    ) || relayer_status=1
  fi

  if (( relayer_status == 0 )); then
    local deposit_witness_file withdraw_witness_file
    deposit_witness_file="${boundless_deposit_witness_item_files[0]:-}"
    withdraw_witness_file="${boundless_withdraw_witness_item_files[0]:-}"
    [[ -n "$deposit_witness_file" ]] || relayer_status=1
    [[ -n "$withdraw_witness_file" ]] || relayer_status=1
    [[ -f "$deposit_witness_file" ]] || relayer_status=1
    [[ -f "$withdraw_witness_file" ]] || relayer_status=1

    local deposit_event_payload
    deposit_event_payload="$workdir/reports/deposit-event.json"
    (
      cd "$REPO_ROOT"
      go run ./cmd/deposit-event \
        --base-chain-id "$base_chain_id" \
        --bridge-address "$deployed_bridge_address" \
        --recipient "$bridge_recipient_address" \
        --amount "100000" \
        --witness-item-file "$deposit_witness_file" \
        --output "$deposit_event_payload"
      go run ./cmd/queue-publish \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --topic "$deposit_event_topic" \
        --payload-file "$deposit_event_payload"
    ) || relayer_status=1

    local witness_metadata_json withdraw_recipient_raw_hex withdraw_request_payload
    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    withdraw_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json" 2>/dev/null || true)"
    if [[ ! "$withdraw_recipient_raw_hex" =~ ^[0-9a-fA-F]{86}$ ]]; then
      relayer_status=1
    fi
    withdraw_request_payload="$workdir/reports/withdraw-request-event.json"
    (
      cd "$REPO_ROOT"
      go run ./cmd/withdraw-request \
        --rpc-url "$base_rpc_url" \
        --chain-id "$base_chain_id" \
        --owner-key-file "$bridge_deployer_key_file" \
        --wjuno-address "$deployed_wjuno_address" \
        --bridge-address "$deployed_bridge_address" \
        --amount "10000" \
        --recipient-raw-address-hex "$withdraw_recipient_raw_hex" \
        --proof-witness-item-file "$withdraw_witness_file" \
        --output "$withdraw_request_payload"
      go run ./cmd/queue-publish \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --topic "$withdraw_request_topic" \
        --payload-file "$withdraw_request_payload"
    ) || relayer_status=1
  fi

  if (( relayer_status == 0 )); then
    if ! wait_for_log_pattern "$deposit_relayer_log" "submitted mintBatch" 900; then
      relayer_status=1
    fi
    if ! wait_for_log_pattern "$withdraw_finalizer_log" "submitted finalizeWithdrawBatch" 1500; then
      relayer_status=1
    fi
  fi

  kill "$base_relayer_pid" "$deposit_relayer_pid" "$withdraw_coordinator_pid" "$withdraw_finalizer_pid" >/dev/null 2>&1 || true
  wait "$base_relayer_pid" >/dev/null 2>&1 || true
  wait "$deposit_relayer_pid" >/dev/null 2>&1 || true
  wait "$withdraw_coordinator_pid" >/dev/null 2>&1 || true
  wait "$withdraw_finalizer_pid" >/dev/null 2>&1 || true

  if (( relayer_status != 0 )); then
    log "relayer service orchestration failed; showing service logs"
    tail -n 200 "$base_relayer_log" >&2 || true
    tail -n 200 "$deposit_relayer_log" >&2 || true
    tail -n 200 "$withdraw_coordinator_log" >&2 || true
    tail -n 200 "$withdraw_finalizer_log" >&2 || true
    bridge_status=1
  else
    bridge_status=0
  fi

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
      log "relayer-driven bridge e2e failed; showing shared ECS proof service logs"
      dump_shared_proof_services_ecs_logs \
        "$shared_ecs_region" \
        "$shared_ecs_cluster_arn" \
        "$shared_proof_requestor_service_name" \
        "$shared_proof_funder_service_name"
    else
      log "relayer-driven bridge e2e failed; showing proof-requestor and proof-funder logs"
      tail -n 200 "$proof_requestor_log" >&2 || true
      tail -n 200 "$proof_funder_log" >&2 || true
    fi
    die "relayer-driven bridge e2e failed while centralized proof services were running"
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

  local dkg_report_public_json
  dkg_report_public_json="$(redact_dkg_summary_json "$dkg_summary")"
  if [[ "$dkg_summary" == "$workdir/reports/dkg-summary.json" ]]; then
    printf '%s\n' "$dkg_report_public_json" >"$dkg_summary"
  fi

  local boundless_deposit_ivk_configured="false"
  local boundless_withdraw_ovk_configured="false"
  local boundless_deposit_witness_item_count boundless_withdraw_witness_item_count
  local guest_witness_auto_generate="true"
  local guest_witness_extract_from_chain="false"
  if [[ -n "$boundless_deposit_owallet_ivk_hex" ]]; then
    boundless_deposit_ivk_configured="true"
  fi
  if [[ -n "$boundless_withdraw_owallet_ovk_hex" ]]; then
    boundless_withdraw_ovk_configured="true"
  fi
  boundless_deposit_witness_item_count="${#boundless_deposit_witness_item_files[@]}"
  boundless_withdraw_witness_item_count="${#boundless_withdraw_witness_item_files[@]}"
  if [[ "$boundless_input_mode" == "guest-witness-v1" && "$guest_witness_extract_mode" == "true" ]]; then
    guest_witness_extract_from_chain="true"
  fi

  local witness_pool_operator_labels_json witness_healthy_operator_labels_json
  local witness_quorum_operator_labels_json witness_failed_operator_labels_json
  witness_pool_operator_labels_json="$(json_array_from_args "${witness_pool_operator_labels[@]}")"
  witness_healthy_operator_labels_json="$(json_array_from_args "${witness_healthy_operator_labels[@]}")"
  witness_quorum_operator_labels_json="$(json_array_from_args "${witness_quorum_operator_labels[@]}")"
  witness_failed_operator_labels_json="$(json_array_from_args "${witness_failed_operator_labels[@]}")"

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
    --argjson boundless_witness_quorum_threshold "$boundless_witness_quorum_threshold" \
    --argjson witness_endpoint_pool_size "$witness_endpoint_pool_size" \
    --argjson witness_endpoint_healthy_count "$witness_endpoint_healthy_count" \
    --arg witness_metadata_source_operator "$witness_metadata_source_operator" \
    --argjson witness_pool_operator_labels "$witness_pool_operator_labels_json" \
    --argjson witness_healthy_operator_labels "$witness_healthy_operator_labels_json" \
    --argjson witness_quorum_operator_labels "$witness_quorum_operator_labels_json" \
    --argjson witness_failed_operator_labels "$witness_failed_operator_labels_json" \
    --argjson witness_quorum_validated_count "$witness_quorum_validated_count" \
    --arg witness_quorum_validated "$witness_quorum_validated" \
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
    --argjson dkg "$dkg_report_public_json" \
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
            withdraw_witness_item_count: $boundless_withdraw_witness_item_count,
            endpoint_quorum_threshold: $boundless_witness_quorum_threshold,
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
