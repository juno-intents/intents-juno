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
                                   (default: prefer dkg-admin when it supports sign-digest; else auto-generate e2e signer shim)
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
  --withdraw-coordinator-tss-url <url> optional tss-host URL override for withdraw coordinator
                                   (defaults to derived https://<witness-rpc-host>:9443)
  --withdraw-coordinator-tss-server-ca-file <path> required tss-host server CA PEM for withdraw coordinator TLS
  --withdraw-blob-bucket <name>   S3 bucket for withdraw coordinator/finalizer durable blob artifacts
                                   (default: --boundless-input-s3-bucket)
  --withdraw-blob-prefix <prefix> S3 prefix for withdraw coordinator/finalizer durable blob artifacts
                                   (default: withdraw-live)
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
  --shared-timeout <duration>       shared infra validation timeout (default: 300s)
  --shared-output <path>            shared infra report output (default: <workdir>/reports/shared-infra-summary.json)
  --relayer-runtime-mode <mode>     relayer runtime mode (runner|distributed, default: runner)
  --relayer-runtime-operator-hosts <csv> comma-separated operator host list for distributed relayer runtime
  --relayer-runtime-operator-ssh-user <user> SSH user for distributed relayer runtime operator hosts
  --relayer-runtime-operator-ssh-key-file <path> SSH key file for distributed relayer runtime operator hosts
  --aws-dr-region <region>          optional AWS DR region passthrough (recorded in summary metadata only)
  --refund-after-expiry-window-seconds <n> refund window seconds used only for refund-after-expiry chaos scenario
                                   (default: 120)
  --output <path>                  summary json output (default: <workdir>/reports/testnet-e2e-summary.json)
  --force                          remove existing workdir before starting

Environment:
  JUNO_FUNDER_PRIVATE_KEY_HEX      optional juno funder private key hex used for transparent witness funding.
  JUNO_FUNDER_SEED_PHRASE          optional juno funder seed phrase used for orchard/unified witness funding.
  JUNO_FUNDER_SOURCE_ADDRESS       optional explicit funded source address already present in witness RPC wallets.

This script orchestrates:
  1) DKG ceremony -> backup packages -> restore from backup-only
  2) Juno witness tx generation on the configured Juno RPC + juno-scan endpoints
  3) Operator-service checkpoint publication (checkpoint-signer + checkpoint-aggregator on operator hosts)
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
  local output status lowered

  [[ -n "$signer_bin" ]] || return 1
  set +e
  output="$("$signer_bin" sign-digest --help 2>&1)"
  status=$?
  set -e
  if (( status == 0 )); then
    return 0
  fi

  lowered="$(lower "$output")"
  if [[ "$lowered" == *"unrecognized subcommand"* ]] || [[ "$lowered" == *"unknown command"* ]]; then
    return 1
  fi
  [[ "$lowered" == *"sign-digest"* ]]
}

write_e2e_operator_digest_signer() {
  local dkg_summary="$1"
  local out_dir="$2"
  local map_file bin_path
  local operator_count

  ensure_command jq
  ensure_command cast
  ensure_dir "$out_dir"

  map_file="$out_dir/e2e-operator-digest-signer-map.json"
  jq -c '
    [.operators[] | {
      operator_id: (.operator_id // ""),
      endpoint: (.endpoint // .grpc_endpoint // ""),
      key_file: (.operator_key_file // "")
    }]
  ' "$dkg_summary" >"$map_file"

  operator_count="$(jq -r 'length' "$map_file")"
  [[ "$operator_count" =~ ^[0-9]+$ ]] || die "invalid operator signer map generated from dkg summary"
  (( operator_count > 0 )) || die "operator signer map is empty"
  if jq -e '.[] | select((.operator_id | test("^0x[0-9a-fA-F]{40}$") | not) or (.key_file | length == 0))' "$map_file" >/dev/null; then
    die "operator signer map has invalid operator_id/key_file entries"
  fi

  bin_path="$out_dir/e2e-operator-digest-signer.sh"
  cat >"$bin_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail

MAP_FILE="$map_file"

json_error() {
  local code="\$1"
  local message="\$2"
  jq -cn --arg code "\$code" --arg message "\$message" \
    '{version:"v1",status:"err",error:{code:\$code,message:\$message}}'
}

main() {
  local command="\${1:-}"
  local digest=""
  local json_mode="false"
  local -a requested_endpoints=()
  local -a signatures=()
  local entry endpoint key_file key_hex signature
  local include_entry

  if [[ "\$command" != "sign-digest" ]]; then
    json_error "unsupported_command" "expected sign-digest subcommand" >&2
    return 2
  fi
  shift || true

  while [[ \$# -gt 0 ]]; do
    case "\$1" in
      --digest)
        [[ \$# -ge 2 ]] || { json_error "missing_digest" "--digest value is required" >&2; return 2; }
        digest="\$2"
        shift 2
        ;;
      --json)
        json_mode="true"
        shift
        ;;
      --operator-endpoint)
        [[ \$# -ge 2 ]] || { json_error "missing_operator_endpoint" "--operator-endpoint value is required" >&2; return 2; }
        requested_endpoints+=("\$2")
        shift 2
        ;;
      *)
        json_error "invalid_argument" "unsupported argument: \$1" >&2
        return 2
        ;;
    esac
  done

  [[ "\$json_mode" == "true" ]] || { json_error "json_required" "--json flag is required" >&2; return 2; }
  [[ "\$digest" =~ ^0x[0-9a-fA-F]{64}\$ ]] || { json_error "invalid_digest" "--digest must be 32-byte hex" >&2; return 2; }
  [[ -f "\$MAP_FILE" ]] || { json_error "missing_map" "operator signer map not found: \$MAP_FILE" >&2; return 1; }

  while IFS= read -r entry; do
    endpoint="\$(jq -r '.endpoint // empty' <<<"\$entry")"
    key_file="\$(jq -r '.key_file // empty' <<<"\$entry")"
    include_entry="true"
    if (( \${#requested_endpoints[@]} > 0 )); then
      include_entry="false"
      for requested_endpoint in "\${requested_endpoints[@]}"; do
        if [[ "\$requested_endpoint" == "\$endpoint" ]]; then
          include_entry="true"
          break
        fi
      done
    fi
    [[ "\$include_entry" == "true" ]] || continue
    [[ -f "\$key_file" ]] || continue

    key_hex="\$(tr -d '[:space:]' <"\$key_file" 2>/dev/null || true)"
    [[ "\$key_hex" =~ ^0x[0-9a-fA-F]{64}\$ ]] || continue
    signature="\$(cast wallet sign --private-key "\$key_hex" "\$digest" 2>/dev/null || true)"
    if [[ "\$signature" =~ ^0x[0-9a-fA-F]{130}\$ ]]; then
      signatures+=("\$signature")
    fi
  done < <(jq -c '.[]' "\$MAP_FILE")

  if (( \${#signatures[@]} == 0 )); then
    json_error "no_signatures" "no operator signatures were produced"
    return 1
  fi

  local signatures_json
  signatures_json="\$(printf '%s\n' "\${signatures[@]}" | jq -Rsc 'split("\n")[:-1]')"
  jq -cn --argjson signatures "\$signatures_json" '{version:"v1",status:"ok",data:{signatures:\$signatures}}'
}

main "\$@"
EOF
  chmod 0755 "$bin_path"
  printf '%s' "$bin_path"
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

  (
    ssh \
      -i "$ssh_key_file" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$ssh_user@$host" \
      "$@"
  ) >"$log_path" 2>&1 &
  printf '%s' "$!"
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

  local remote_script
  remote_script="$(cat <<'EOF'
set -euo pipefail
bridge_address="$1"
base_chain_id="$2"

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

tmp_json="$(mktemp)"
tmp_next="$(mktemp)"
sudo cp "$config_json_path" "$tmp_json"
sudo chown "$(id -u):$(id -g)" "$tmp_json"
chmod 600 "$tmp_json"

jq \
  --arg bridge "$bridge_address" \
  --arg chain "$base_chain_id" \
  '
  .BRIDGE_ADDRESS = $bridge
  | .BASE_CHAIN_ID = $chain
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
    "bash -s -- $(printf '%q' "$bridge_address") $(printf '%q' "$base_chain_id")" <<<"$remote_script"
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
  local withdraw_coordinator_tss_url=""
  local withdraw_coordinator_tss_server_ca_file=""
  local withdraw_blob_bucket=""
  local withdraw_blob_prefix="withdraw-live"
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
  local shared_timeout="300s"
  local shared_output=""
  local relayer_runtime_mode="runner"
  local relayer_runtime_operator_hosts_csv=""
  local relayer_runtime_operator_ssh_user=""
  local relayer_runtime_operator_ssh_key_file=""
  local aws_dr_region=""
  local refund_after_expiry_window_seconds="120"
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
  [[ "$refund_after_expiry_window_seconds" =~ ^[0-9]+$ ]] || die "--refund-after-expiry-window-seconds must be numeric"
  (( refund_after_expiry_window_seconds > 0 )) || die "--refund-after-expiry-window-seconds must be > 0"
  case "$relayer_runtime_mode" in
    runner|distributed) ;;
    *) die "--relayer-runtime-mode must be runner or distributed" ;;
  esac
  [[ -z "$bridge_deposit_checkpoint_height" || "$bridge_deposit_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-deposit-checkpoint-height must be numeric"
  [[ -z "$bridge_withdraw_checkpoint_height" || "$bridge_withdraw_checkpoint_height" =~ ^[0-9]+$ ]] || die "--bridge-withdraw-checkpoint-height must be numeric"
  (( boundless_max_price_cap_wei >= boundless_max_price_wei )) || die "--boundless-max-price-cap-wei must be >= --boundless-max-price-wei"
  if [[ "$boundless_input_mode" != "guest-witness-v1" ]]; then
    die "--boundless-input-mode must be guest-witness-v1"
  fi
  if (( boundless_max_price_bump_retries > 0 && boundless_max_price_bump_multiplier < 2 )); then
    die "--boundless-max-price-bump-multiplier must be >= 2 when --boundless-max-price-bump-retries > 0"
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
  if [[ -z "$withdraw_blob_bucket" ]]; then
    withdraw_blob_bucket="$boundless_input_s3_bucket"
  fi
  [[ -n "$withdraw_blob_bucket" ]] || die "--withdraw-blob-bucket must not be empty"
  [[ -n "$withdraw_blob_prefix" ]] || die "--withdraw-blob-prefix must not be empty"
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
  if [[ -z "${JUNO_FUNDER_PRIVATE_KEY_HEX:-}" && -z "${JUNO_FUNDER_SEED_PHRASE:-}" && -z "${JUNO_FUNDER_SOURCE_ADDRESS:-}" ]]; then
    die "one of JUNO_FUNDER_PRIVATE_KEY_HEX, JUNO_FUNDER_SEED_PHRASE, or JUNO_FUNDER_SOURCE_ADDRESS is required for run-generated witness metadata"
  fi
  if [[ "${WITHDRAW_COORDINATOR_RUNTIME_MODE:-full}" != "full" ]]; then
    die "WITHDRAW_COORDINATOR_RUNTIME_MODE must be full; mock runtime is forbidden"
  fi
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
  command -v psql >/dev/null 2>&1 || die "psql is required for live withdrawal payout-state checks (install postgresql client)"
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

  local bridge_recipient_address=""
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
  local checkpoint_package_topic="checkpoints.packages.v1"
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
    local -a bridge_operator_signer_candidates=()
    coordinator_workdir_from_summary="$(jq -r '.coordinator_workdir // .coordinator.workdir // empty' "$dkg_summary")"
    if [[ -n "$coordinator_workdir_from_summary" ]]; then
      bridge_operator_signer_candidates+=("$coordinator_workdir_from_summary/bin/dkg-admin")
    fi
    bridge_operator_signer_candidates+=(
      "$workdir/dkg-distributed/coordinator/bin/dkg-admin"
      "$workdir/dkg/coordinator/bin/dkg-admin"
    )
    for bridge_operator_signer_candidate in "${bridge_operator_signer_candidates[@]}"; do
      if [[ -x "$bridge_operator_signer_candidate" ]]; then
        bridge_operator_signer_bin="$bridge_operator_signer_candidate"
        break
      fi
    done
    if [[ -z "$bridge_operator_signer_bin" ]]; then
      bridge_operator_signer_bin="$(ensure_dkg_binary "dkg-admin" "$JUNO_DKG_VERSION_DEFAULT" "$workdir/bin")"
    fi
  fi
  if [[ "$bridge_operator_signer_bin" == */* ]]; then
    [[ -x "$bridge_operator_signer_bin" ]] || die "bridge operator signer binary is not executable: $bridge_operator_signer_bin"
  else
    command -v "$bridge_operator_signer_bin" >/dev/null 2>&1 || die "bridge operator signer binary not found in PATH: $bridge_operator_signer_bin"
  fi
  if ! supports_sign_digest_subcommand "$bridge_operator_signer_bin"; then
    log "bridge operator signer binary does not support sign-digest; using e2e signer shim"
    bridge_operator_signer_bin="$(write_e2e_operator_digest_signer "$dkg_summary" "$workdir/bin")"
  fi
  if [[ "$bridge_operator_signer_bin" == */* ]]; then
    [[ -x "$bridge_operator_signer_bin" ]] || die "bridge operator signer binary is not executable: $bridge_operator_signer_bin"
  else
    command -v "$bridge_operator_signer_bin" >/dev/null 2>&1 || die "bridge operator signer binary not found in PATH: $bridge_operator_signer_bin"
  fi

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
  local withdraw_coordinator_juno_wallet_id=""
  local withdraw_coordinator_juno_change_address=""
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
        --pre-upsert-scan-urls "$witness_metadata_pre_upsert_scan_urls_csv"
        --wallet-id "$witness_wallet_id_attempt"
        --deposit-amount-zat "100000"
        --withdraw-amount-zat "10000"
        --timeout-seconds "$boundless_witness_metadata_timeout_seconds"
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

    local generated_wallet_id generated_recipient_ua generated_deposit_txid generated_deposit_action_index
    local generated_recipient_raw_address_hex generated_ufvk
    generated_wallet_id="$(jq -r '.wallet_id // empty' "$witness_metadata_json")"
    generated_recipient_ua="$(jq -r '.recipient_ua // empty' "$witness_metadata_json")"
    generated_deposit_txid="$(jq -r '.deposit_txid // empty' "$witness_metadata_json")"
    generated_deposit_action_index="$(jq -r '.deposit_action_index // empty' "$witness_metadata_json")"
    generated_recipient_raw_address_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json")"
    generated_ufvk="$(jq -r '.ufvk // empty' "$witness_metadata_json")"

    [[ -n "$generated_wallet_id" ]] || die "generated witness metadata missing wallet_id: $witness_metadata_json"
    [[ -n "$generated_recipient_ua" ]] || die "generated witness metadata missing recipient_ua: $witness_metadata_json"
    [[ -n "$generated_deposit_txid" ]] || die "generated witness metadata missing deposit_txid: $witness_metadata_json"
    [[ "$generated_deposit_action_index" =~ ^[0-9]+$ ]] || die "generated witness metadata deposit_action_index is invalid: $generated_deposit_action_index"
    [[ "$generated_recipient_raw_address_hex" =~ ^[0-9a-fA-F]{86}$ ]] || \
      die "generated witness metadata recipient_raw_address_hex must be 43 bytes hex: $generated_recipient_raw_address_hex"
    [[ -n "$generated_ufvk" ]] || die "generated witness metadata missing ufvk: $witness_metadata_json"
    withdraw_coordinator_juno_wallet_id="$generated_wallet_id"
    withdraw_coordinator_juno_change_address="$generated_recipient_ua"

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

    local witness_quorum_dir
    witness_quorum_dir="$workdir/reports/witness/quorum"
    ensure_dir "$witness_quorum_dir"
    local -a witness_success_labels=()
    local -a witness_success_fingerprints=()
    local -a witness_success_deposit_json=()
    local -a witness_success_deposit_witness=()

    for ((witness_idx = 0; witness_idx < witness_endpoint_healthy_count; witness_idx++)); do
      local witness_scan_url witness_rpc_url witness_operator_label
      local witness_operator_safe_label deposit_candidate_witness
      local deposit_candidate_json
      local witness_extract_attempt witness_extract_ok
      local witness_extract_deadline_epoch witness_extract_error_file witness_extract_last_error
      local witness_extract_wait_logged witness_extract_sleep_seconds
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
      witness_extract_deadline_epoch=$(( $(date +%s) + boundless_witness_metadata_timeout_seconds ))
      witness_extract_error_file="$witness_quorum_dir/deposit-${witness_operator_safe_label}.extract.err"

      witness_extract_attempt=0
      while true; do
        witness_extract_attempt=$((witness_extract_attempt + 1))
        rm -f "$deposit_candidate_json"
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
            --output-witness-item-file "$deposit_candidate_witness" >"$deposit_candidate_json" 2>"$witness_extract_error_file"
        ); then
          witness_extract_ok="true"
          rm -f "$witness_extract_error_file"
          break
        fi
        witness_extract_last_error="$(tail -n 1 "$witness_extract_error_file" 2>/dev/null | tr -d '\r\n')"
        if grep -qi "note not found" "$witness_extract_error_file"; then
          if [[ "$witness_extract_wait_logged" != "true" ]]; then
            log "waiting for note visibility on operator=$witness_operator_label wallet=$generated_wallet_id txid=$generated_deposit_txid action_index=$generated_deposit_action_index"
            witness_extract_wait_logged="true"
          fi
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
      witness_fingerprint="${deposit_witness_hex}|${deposit_anchor_height}|${deposit_anchor_hash}|${deposit_final_root}"
      witness_success_labels+=("$witness_operator_label")
      witness_success_fingerprints+=("$witness_fingerprint")
      witness_success_deposit_json+=("$deposit_candidate_json")
      witness_success_deposit_witness+=("$deposit_candidate_witness")
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
    cp "${witness_success_deposit_json[0]}" "$deposit_witness_auto_json"

    boundless_deposit_witness_item_files=("$deposit_witness_auto_file")
    boundless_withdraw_witness_item_files=()

    bridge_deposit_final_orchard_root="$(jq -r '.final_orchard_root // empty' "$deposit_witness_auto_json")"
    bridge_deposit_checkpoint_height="$(jq -r '.anchor_height // empty' "$deposit_witness_auto_json")"
    bridge_deposit_checkpoint_block_hash="$(jq -r '.anchor_block_hash // empty' "$deposit_witness_auto_json")"
    bridge_withdraw_final_orchard_root="$bridge_deposit_final_orchard_root"
    bridge_withdraw_checkpoint_height="$bridge_deposit_checkpoint_height"
    bridge_withdraw_checkpoint_block_hash="$bridge_deposit_checkpoint_block_hash"
  fi

  if [[ -z "$withdraw_coordinator_tss_url" ]]; then
    withdraw_coordinator_tss_url="$(derive_tss_url_from_juno_rpc_url "$boundless_witness_juno_rpc_url" || true)"
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
  withdraw_coordinator_juno_rpc_user_var="$boundless_witness_juno_rpc_user_env"
  withdraw_coordinator_juno_rpc_pass_var="$boundless_witness_juno_rpc_pass_env"
  [[ -n "${!withdraw_coordinator_juno_rpc_user_var:-}" ]] || \
    die "missing env var for withdraw coordinator Juno RPC user: $withdraw_coordinator_juno_rpc_user_var"
  [[ -n "${!withdraw_coordinator_juno_rpc_pass_var:-}" ]] || \
    die "missing env var for withdraw coordinator Juno RPC pass: $withdraw_coordinator_juno_rpc_pass_var"
  withdraw_coordinator_juno_rpc_user_value="${!withdraw_coordinator_juno_rpc_user_var}"
  withdraw_coordinator_juno_rpc_pass_value="${!withdraw_coordinator_juno_rpc_pass_var}"
  withdraw_finalizer_juno_scan_bearer_value="${!boundless_witness_juno_scan_bearer_token_env:-}"

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

  local direct_cli_user_proof_status="not-run"
  local direct_cli_user_proof_summary_path=""
  local direct_cli_user_proof_log=""
  local direct_cli_user_proof_submission_mode=""
  local direct_cli_user_proof_deposit_request_id=""
  local direct_cli_user_proof_withdraw_request_id=""

  run_direct_cli_user_proof_scenario() {
    local witness_metadata_json direct_cli_withdraw_txid direct_cli_withdraw_action_index
    local direct_cli_recipient_raw_hex direct_cli_recipient_raw_hex_prefixed
    local direct_cli_bridge_deploy_summary direct_cli_bridge_deploy_log
    local direct_cli_deployed_wjuno_address direct_cli_deployed_operator_registry_address
    local direct_cli_deployed_fee_distributor_address direct_cli_deployed_bridge_address
    local direct_cli_domain_tag direct_cli_recipient_hash direct_cli_predicted_withdrawal_id
    local direct_cli_withdraw_witness_file direct_cli_withdraw_witness_json
    local direct_cli_bridge_summary direct_cli_bridge_log
    local direct_cli_withdraw_amount="10000"
    local direct_cli_status
    local direct_cli_requestor_key_file="$boundless_requestor_key_file"
    local witness_file
    local operator_id operator_endpoint
    local -a direct_cli_bridge_base_args=()
    local -a direct_cli_bridge_deploy_args=()
    local -a direct_cli_bridge_run_args=()

    witness_metadata_json="$workdir/reports/witness/generated-witness-metadata.json"
    direct_cli_withdraw_txid="$(jq -r '.withdraw_txid // empty' "$witness_metadata_json" 2>/dev/null || true)"
    direct_cli_withdraw_action_index="$(jq -r '.withdraw_action_index // empty' "$witness_metadata_json" 2>/dev/null || true)"
    direct_cli_recipient_raw_hex="$(jq -r '.recipient_raw_address_hex // empty' "$witness_metadata_json" 2>/dev/null || true)"
    direct_cli_recipient_raw_hex_prefixed="$(normalize_hex_prefixed "$direct_cli_recipient_raw_hex" || true)"
    [[ -n "$direct_cli_withdraw_txid" ]] || return 1
    [[ "$direct_cli_withdraw_action_index" =~ ^[0-9]+$ ]] || return 1
    [[ "$direct_cli_recipient_raw_hex_prefixed" =~ ^0x[0-9a-f]{86}$ ]] || return 1

    (( ${#boundless_deposit_witness_item_files[@]} > 0 )) || return 1

    direct_cli_bridge_base_args+=(
      "--rpc-url" "$base_rpc_url"
      "--chain-id" "$base_chain_id"
      "--deployer-key-file" "$bridge_deployer_key_file"
      "--operator-signer-bin" "$bridge_operator_signer_bin"
      "--threshold" "$threshold"
      "--contracts-out" "$contracts_out"
      "--recipient" "$bridge_recipient_address"
      "--boundless-auto"
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
      "--boundless-bin" "$boundless_bin"
      "--boundless-rpc-url" "$boundless_rpc_url"
      "--boundless-proof-submission-mode" "direct-cli"
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
      "--boundless-requestor-key-file" "$direct_cli_requestor_key_file"
    )
    while IFS=$'\t' read -r operator_id operator_endpoint; do
      [[ -n "$operator_id" ]] || continue
      [[ -n "$operator_endpoint" ]] || return 1
      direct_cli_bridge_base_args+=("--operator-address" "$operator_id")
      direct_cli_bridge_base_args+=("--operator-signer-endpoint" "$operator_endpoint")
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
      go run ./cmd/bridge-e2e "${direct_cli_bridge_deploy_args[@]}"
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

    direct_cli_withdraw_witness_file="$workdir/reports/witness/direct-cli-withdraw.witness.bin"
    direct_cli_withdraw_witness_json="$workdir/reports/witness/direct-cli-withdraw.json"
    local -a direct_cli_withdraw_extract_cmd=(go run ./cmd/juno-witness-extract)
    if ! (
      cd "$REPO_ROOT"
      "${direct_cli_withdraw_extract_cmd[@]}" withdraw \
        --juno-scan-url "$boundless_witness_juno_scan_url" \
        --wallet-id "$withdraw_coordinator_juno_wallet_id" \
        --juno-scan-bearer-token-env "$boundless_witness_juno_scan_bearer_token_env" \
        --juno-rpc-url "$boundless_witness_juno_rpc_url" \
        --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
        --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
        --txid "$direct_cli_withdraw_txid" \
        --action-index "$direct_cli_withdraw_action_index" \
        --withdrawal-id-hex "$direct_cli_predicted_withdrawal_id" \
        --recipient-raw-address-hex "$direct_cli_recipient_raw_hex" \
        --output-witness-item-file "$direct_cli_withdraw_witness_file" \
        >"$direct_cli_withdraw_witness_json"
    ); then
      return 1
    fi

    direct_cli_bridge_summary="$workdir/reports/direct-cli-user-proof-summary.json"
    direct_cli_bridge_log="$workdir/reports/direct-cli-user-proof.log"
    direct_cli_bridge_run_args=("${direct_cli_bridge_base_args[@]}")
    direct_cli_bridge_run_args+=(
      "--output" "$direct_cli_bridge_summary"
      "--existing-wjuno-address" "$direct_cli_deployed_wjuno_address"
      "--existing-operator-registry-address" "$direct_cli_deployed_operator_registry_address"
      "--existing-fee-distributor-address" "$direct_cli_deployed_fee_distributor_address"
      "--existing-bridge-address" "$direct_cli_deployed_bridge_address"
    )
    direct_cli_bridge_run_args+=("--boundless-deposit-owallet-ivk-hex" "$boundless_deposit_owallet_ivk_hex")
    direct_cli_bridge_run_args+=("--boundless-withdraw-owallet-ovk-hex" "$boundless_withdraw_owallet_ovk_hex")
    for witness_file in "${boundless_deposit_witness_item_files[@]}"; do
      direct_cli_bridge_run_args+=("--boundless-deposit-witness-item-file" "$witness_file")
    done
    direct_cli_bridge_run_args+=("--boundless-withdraw-witness-item-file" "$direct_cli_withdraw_witness_file")

    set +e
    (
      cd "$REPO_ROOT"
      go run ./cmd/bridge-e2e "${direct_cli_bridge_run_args[@]}"
    ) >"$direct_cli_bridge_log" 2>&1
    direct_cli_status="$?"
    set -e
    if (( direct_cli_status != 0 )); then
      tail -n 200 "$direct_cli_bridge_log" >&2 || true
      return 1
    fi

    direct_cli_user_proof_submission_mode="$(jq -r '.proof.boundless.submission_mode // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    direct_cli_user_proof_deposit_request_id="$(jq -r '.proof.boundless.deposit_request_id // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    direct_cli_user_proof_withdraw_request_id="$(jq -r '.proof.boundless.withdraw_request_id // empty' "$direct_cli_bridge_summary" 2>/dev/null || true)"
    [[ "$direct_cli_user_proof_submission_mode" == "direct-cli" ]] || return 1
    [[ -n "$direct_cli_user_proof_deposit_request_id" ]] || return 1
    [[ -n "$direct_cli_user_proof_withdraw_request_id" ]] || return 1

    direct_cli_user_proof_status="passed"
    direct_cli_user_proof_summary_path="$direct_cli_bridge_summary"
    direct_cli_user_proof_log="$direct_cli_bridge_log"
    return 0
  }

  direct_cli_user_proof_status="running"
  if ! run_direct_cli_user_proof_scenario; then
    direct_cli_user_proof_status="failed"
    die "direct-cli user proof scenario failed"
  fi

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

  if [[ "$shared_enabled" == "true" ]]; then
    local checkpoint_started_at
    checkpoint_started_at="$(timestamp_utc)"

    if [[ "$relayer_runtime_mode" == "distributed" ]]; then
      (( ${#relayer_runtime_operator_hosts[@]} > 0 )) || \
        die "shared checkpoint validation requires --relayer-runtime-operator-hosts when --relayer-runtime-mode=distributed"
      [[ -n "$relayer_runtime_operator_ssh_user" ]] || \
        die "shared checkpoint validation requires --relayer-runtime-operator-ssh-user when --relayer-runtime-mode=distributed"
      [[ -f "$relayer_runtime_operator_ssh_key_file" ]] || \
        die "shared checkpoint validation requires readable --relayer-runtime-operator-ssh-key-file when --relayer-runtime-mode=distributed"

      local checkpoint_host
      for checkpoint_host in "${relayer_runtime_operator_hosts[@]}"; do
        log "updating operator checkpoint bridge config host=$checkpoint_host bridge=$deployed_bridge_address"
        configure_remote_operator_checkpoint_services_for_bridge \
          "$checkpoint_host" \
          "$relayer_runtime_operator_ssh_user" \
          "$relayer_runtime_operator_ssh_key_file" \
          "$deployed_bridge_address" \
          "$base_chain_id" || \
          die "failed to update checkpoint bridge config on host=$checkpoint_host"
      done
    fi

    log "validating operator-service checkpoint publication via shared infra"
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
    if (( shared_status != 0 )); then
      die "shared infra validation failed (operator-service checkpoint publication)"
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
  local run_withdrawal_id=""
  local run_withdraw_requester=""
  local run_withdraw_amount=""
  local run_withdraw_fee_bps=""
  local run_withdraw_recipient_ua=""
  local run_withdraw_request_expiry=""
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
  local operator_failures_injected=0

  local base_relayer_log="$workdir/reports/base-relayer.log"
  local deposit_relayer_log="$workdir/reports/deposit-relayer.log"
  local withdraw_coordinator_log="$workdir/reports/withdraw-coordinator.log"
  local withdraw_finalizer_log="$workdir/reports/withdraw-finalizer.log"
  local base_relayer_pid=""
  local deposit_relayer_pid=""
  local withdraw_coordinator_pid=""
  local withdraw_finalizer_pid=""
  local relayer_status=0
  local base_relayer_host=""
  local deposit_relayer_host=""
  local withdraw_coordinator_host=""
  local withdraw_finalizer_host=""
  local distributed_withdraw_coordinator_tss_server_ca_file="$withdraw_coordinator_tss_server_ca_file"
  local distributed_withdraw_coordinator_tss_url="$withdraw_coordinator_tss_url"
  local distributed_withdraw_coordinator_juno_rpc_url="$boundless_witness_juno_rpc_url"
  local distributed_withdraw_finalizer_juno_scan_url="$boundless_witness_juno_scan_url"
  local distributed_withdraw_finalizer_juno_rpc_url="$boundless_witness_juno_rpc_url"

  operator_down_ssh_user="$(id -un 2>/dev/null || true)"
  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    operator_down_ssh_user="$relayer_runtime_operator_ssh_user"
    operator_down_ssh_key_path="$relayer_runtime_operator_ssh_key_file"
  fi
  mapfile -t operator_signer_endpoints < <(jq -r '.operators[] | (.endpoint // .grpc_endpoint // "")' "$dkg_summary")
  if (( ${#operator_signer_endpoints[@]} < threshold )); then
    die "operator endpoint count is below threshold for chaos scenarios: endpoints=${#operator_signer_endpoints[@]} threshold=$threshold"
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

    if ! stage_remote_runtime_file \
      "$withdraw_coordinator_tss_server_ca_file" \
      "$withdraw_coordinator_host" \
      "$relayer_runtime_operator_ssh_user" \
      "$relayer_runtime_operator_ssh_key_file" \
      "$distributed_withdraw_coordinator_tss_server_ca_file"; then
      relayer_status=1
    fi
  else
    base_relayer_url="http://127.0.0.1:${base_relayer_port}"
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
          "$boundless_witness_juno_rpc_user_env=$withdraw_coordinator_juno_rpc_user_value" \
          "$boundless_witness_juno_rpc_pass_env=$withdraw_coordinator_juno_rpc_pass_value" \
          /usr/local/bin/withdraw-coordinator \
          --postgres-dsn "$shared_postgres_dsn" \
          --owner "testnet-e2e-withdraw-coordinator-${proof_topic_seed}" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$withdraw_coordinator_group" \
          --queue-topics "$withdraw_request_topic" \
          --juno-rpc-url "$distributed_withdraw_coordinator_juno_rpc_url" \
          --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
          --juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-change-address "$withdraw_coordinator_juno_change_address" \
          --tss-url "$distributed_withdraw_coordinator_tss_url" \
          --tss-server-ca-file "$distributed_withdraw_coordinator_tss_server_ca_file" \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --base-relayer-url "$base_relayer_url" \
          --extend-signer-bin "$bridge_operator_signer_bin" \
          --expiry-safety-margin "30h" \
          --max-expiry-extension "12h" \
          --blob-driver s3 \
          --blob-bucket "$withdraw_blob_bucket" \
          --blob-prefix "$withdraw_blob_prefix"
      )"

      local -a withdraw_finalizer_remote_env=(
        env
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token"
        "$boundless_witness_juno_rpc_user_env=$withdraw_coordinator_juno_rpc_user_value"
        "$boundless_witness_juno_rpc_pass_env=$withdraw_coordinator_juno_rpc_pass_value"
      )
      if [[ -n "$withdraw_finalizer_juno_scan_bearer_value" ]]; then
        withdraw_finalizer_remote_env+=("$boundless_witness_juno_scan_bearer_token_env=$withdraw_finalizer_juno_scan_bearer_value")
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
          --owallet-ovk "$boundless_withdraw_owallet_ovk_hex" \
          --withdraw-witness-extractor-enabled \
          --juno-scan-url "$distributed_withdraw_finalizer_juno_scan_url" \
          --juno-scan-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-scan-bearer-env "$boundless_witness_juno_scan_bearer_token_env" \
          --juno-rpc-url "$distributed_withdraw_finalizer_juno_rpc_url" \
          --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
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
        BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \
        go run ./cmd/withdraw-coordinator \
          --postgres-dsn "$shared_postgres_dsn" \
          --owner "testnet-e2e-withdraw-coordinator-${proof_topic_seed}" \
          --queue-driver kafka \
          --queue-brokers "$shared_kafka_brokers" \
          --queue-group "$withdraw_coordinator_group" \
          --queue-topics "$withdraw_request_topic" \
          --juno-rpc-url "$boundless_witness_juno_rpc_url" \
          --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
          --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
          --juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \
          --juno-change-address "$withdraw_coordinator_juno_change_address" \
          --tss-url "$withdraw_coordinator_tss_url" \
          --tss-server-ca-file "$withdraw_coordinator_tss_server_ca_file" \
          --base-chain-id "$base_chain_id" \
          --bridge-address "$deployed_bridge_address" \
          --base-relayer-url "$base_relayer_url" \
          --extend-signer-bin "$bridge_operator_signer_bin" \
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
            --owallet-ovk "$boundless_withdraw_owallet_ovk_hex" \
            --withdraw-witness-extractor-enabled \
            --juno-scan-url "$boundless_witness_juno_scan_url" \
            --juno-scan-wallet-id "$withdraw_coordinator_juno_wallet_id" \
            --juno-scan-bearer-env "$boundless_witness_juno_scan_bearer_token_env" \
            --juno-rpc-url "$boundless_witness_juno_rpc_url" \
            --juno-rpc-user-env "$boundless_witness_juno_rpc_user_env" \
            --juno-rpc-pass-env "$boundless_witness_juno_rpc_pass_env" \
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
    local deposit_witness_file
    deposit_witness_file="${boundless_deposit_witness_item_files[0]:-}"
    [[ -n "$deposit_witness_file" ]] || relayer_status=1
    [[ -f "$deposit_witness_file" ]] || relayer_status=1

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
    if (( relayer_status == 0 )); then
      run_deposit_id="$(jq -r '.depositId // empty' "$deposit_event_payload" 2>/dev/null || true)"
      run_deposit_amount="$(jq -r '.amount // empty' "$deposit_event_payload" 2>/dev/null || true)"
      [[ "$run_deposit_id" =~ ^0x[0-9a-fA-F]{64}$ ]] || relayer_status=1
      [[ "$run_deposit_amount" =~ ^[0-9]+$ ]] || relayer_status=1
    fi

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
        --output "$withdraw_request_payload"
      go run ./cmd/queue-publish \
        --queue-driver kafka \
        --queue-brokers "$shared_kafka_brokers" \
        --topic "$withdraw_request_topic" \
        --payload-file "$withdraw_request_payload"
    ) || relayer_status=1
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

    while (( operator_failures_injected < target_down_count )); do
      local endpoint_idx
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

      if (( operator_failures_injected == 1 )); then
        operator_down_1_endpoint="$scenario_endpoint"
      elif (( operator_failures_injected == 2 )); then
        operator_down_2_endpoint="$scenario_endpoint"
      fi
      log "injected operator endpoint failure count=$operator_failures_injected endpoint=$scenario_endpoint listener_pid=$scenario_pid"
    done

    scenario_digest="0x$(openssl rand -hex 32)"
    set +e
    scenario_output="$("$operator_signer_probe_bin" sign-digest --digest "$scenario_digest" --json 2>&1)"
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

  if (( bridge_status == 0 )); then
    refund_after_expiry_status="running"
    if run_refund_after_expiry_scenario "$refund_after_expiry_window_seconds"; then
      refund_after_expiry_status="passed"
    else
      refund_after_expiry_status="failed"
      bridge_status=1
    fi
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

  local run_invariants_json
  run_invariants_json="$(
    jq -n \
      --arg deposit_id "$run_deposit_id" \
      --arg deposit_amount "$run_deposit_amount" \
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
      '{
        deposit_id: (if $deposit_id == "" then null else $deposit_id end),
        deposit_amount: (if $deposit_amount == "" then null else ($deposit_amount | tonumber) end),
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
