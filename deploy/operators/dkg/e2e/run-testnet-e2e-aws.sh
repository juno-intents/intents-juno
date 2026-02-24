#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

cleanup_enabled="false"
cleanup_terraform_dir=""
cleanup_aws_profile=""
cleanup_primary_state_file=""
cleanup_primary_tfvars_file=""
cleanup_primary_aws_region=""
cleanup_primary_sp1_requestor_secret_arn=""
cleanup_dr_state_file=""
cleanup_dr_tfvars_file=""
cleanup_dr_aws_region=""
cleanup_dr_sp1_requestor_secret_arn=""
AWS_ENV_ARGS=()
DISTRIBUTED_SP1_DEPOSIT_OWALLET_IVK_HEX=""
DISTRIBUTED_SP1_WITHDRAW_OWALLET_OVK_HEX=""
DISTRIBUTED_COMPLETION_UFVK=""
DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA=""
FAILURE_SIGNATURES_FILE="$SCRIPT_DIR/failure-signatures.yaml"
DEFAULT_SHARED_PROOF_SERVICES_IMAGE_RELEASE_TAG="shared-proof-services-image-latest"

usage() {
  cat <<'EOF'
Usage:
  run-testnet-e2e-aws.sh run [options] -- [run-testnet-e2e.sh args...]
  run-testnet-e2e-aws.sh preflight [options] -- [run-testnet-e2e.sh args...]
  run-testnet-e2e-aws.sh canary [options] -- [run-testnet-e2e.sh args...]
  run-testnet-e2e-aws.sh cleanup [options]

Commands:
  run:
    Provisions an AWS runner via Terraform, executes the live testnet e2e flow
    on the runner, collects artifacts locally, and tears down infra by default.

  cleanup:
    Idempotent fallback destroy for previously created infra state in workdir.

  preflight:
    Runs deterministic hard-block checks only (no provisioning / no remote execution).
    Executes local script test suite and AWS/SP1 prechecks.

  canary:
    Runs required resume canary flow (keep-infra + skip-distributed-dkg) and stops
    remote e2e at checkpoint_validated stage before full bridge flow.

run options:
  --workdir <path>                     local workdir (default: <repo>/tmp/aws-live-e2e)
  --terraform-dir <path>               terraform dir (default: <repo>/deploy/shared/terraform/live-e2e)
  --aws-region <region>                AWS region (required)
  --aws-dr-region <region>             AWS DR secondary region for readiness checks and dual-region provisioning
  --aws-profile <name>                 optional AWS profile for local execution
  --enable-aws-dr-readiness-checks     enforce shared-service DR readiness checks (default)
  --disable-aws-dr-readiness-checks    disable DR readiness checks (allowed only with --without-shared-services)
  --aws-name-prefix <prefix>           terraform name prefix (default: juno-live-e2e)
  --aws-instance-type <type>           runner instance type (default: c7i.4xlarge)
  --runner-ami-id <ami-id>             optional custom AMI for runner host
  --aws-root-volume-gb <n>             root volume size (default: 200)
  --operator-instance-count <n>        operator host count (default: 5)
  --operator-instance-type <type>      operator instance type (default: c7i.large)
  --operator-ami-id <ami-id>           optional custom AMI for operator hosts
  --operator-root-volume-gb <n>        operator root volume size (default: 100)
  --shared-ami-id <ami-id>             optional custom AMI for shared IPFS pinning ASG instances
  --operator-base-port <port>          first operator grpc port (default: 18443)
  --runner-associate-public-ip-address <true|false>
                                        associate public IPv4 address on runner (default: true)
  --operator-associate-public-ip-address <true|false>
                                        associate public IPv4 addresses on operators (default: true)
  --shared-ecs-assign-public-ip <true|false>
                                        assign public IPv4 addresses on shared ECS tasks (default: false)
  --dkg-s3-key-prefix <prefix>         S3 prefix for KMS-exported key packages (default: dkg/keypackages)
  --dkg-release-tag <tag>              DKG release tag for distributed ceremony (default: v0.1.0)
  --ssh-allowed-cidr <cidr>            inbound SSH CIDR (default: caller public IP /32)
  --base-funder-key-file <path>        file with Base funder private key hex (required)
  --juno-funder-key-file <path>        optional file with Juno funder private key hex
  --juno-funder-seed-file <path>       optional file with Juno funder seed phrase
  --juno-funder-source-address-file <path>
                                       optional file with explicit funded Juno source address
  --juno-rpc-user-file <path>          file with junocashd RPC username for witness extraction (required)
  --juno-rpc-pass-file <path>          file with junocashd RPC password for witness extraction (required)
  --juno-scan-bearer-token-file <path> optional file with juno-scan bearer token for witness extraction
  --sp1-requestor-key-file <p>   required file with SP1 requestor private key hex
  --shared-sp1-requestor-secret-arn <arn>
                                       optional pre-existing primary-region secret ARN for shared proof services
  --shared-sp1-requestor-secret-arn-dr <arn>
                                       optional pre-existing DR-region secret ARN for shared proof services
  --shared-proof-services-image <image>
                                       optional explicit shared proof-services image
                                       (deploys this image for shared proof-requestor/proof-funder services)
  --shared-proof-services-image-release-tag <tag>
                                       release tag used to resolve shared proof-services image when
                                       --shared-proof-services-image is omitted
                                       (default: shared-proof-services-image-latest)
  --without-shared-services            skip provisioning managed shared services (Aurora/MSK/ECS/IPFS)
                                       requires forwarded shared args after '--':
                                         --shared-postgres-dsn
                                         --shared-kafka-brokers
                                         --shared-ipfs-api-url
  --shared-postgres-user <user>        shared Aurora Postgres username (default: postgres)
  --shared-postgres-db <name>          shared Aurora Postgres DB name (default: intents_e2e)
  --shared-postgres-port <port>        shared Aurora Postgres TCP port (default: 5432)
  --shared-kafka-port <port>           shared MSK TLS Kafka TCP port (default: 9094)
  --relayer-runtime-mode <mode>        relayer runtime mode for run-testnet-e2e.sh (runner|distributed, default: distributed)
  --distributed-relayer-runtime        shorthand for --relayer-runtime-mode distributed
  --keep-infra                         do not destroy infra at the end
  --skip-distributed-dkg               reuse existing runner DKG artifacts; skip distributed DKG ceremony/backup-restore setup
                                       (requires --keep-infra and an existing runner workdir)
  --reuse-bridge-summary-path <path>   optional local bridge summary json to stage on runner and reuse for contract deploy skip
  --preflight-only                     internal: run-only command parser/checks and exit before provisioning
  --status-json <path>                 optional machine-readable status output path

preflight options:
  same as run options, plus:
  --status-json <path>                 machine-readable status output path (required in CI)

canary options:
  same as run options, plus:
  --status-json <path>                 machine-readable status output path (required in CI)
  constraints:
    - forces --keep-infra
    - forces --skip-distributed-dkg
    - requires --reuse-bridge-summary-path <path>
    - forces forwarded local e2e arg: --stop-after-stage checkpoint_validated

cleanup options:
  --workdir <path>                     local workdir (default: <repo>/tmp/aws-live-e2e)
  --terraform-dir <path>               terraform dir (default: <repo>/deploy/shared/terraform/live-e2e)
  --aws-region <region>                optional AWS region override
  --aws-dr-region <region>             optional AWS DR region override
  --aws-profile <name>                 optional AWS profile override

Notes:
  - Arguments after '--' are forwarded to:
      deploy/operators/dkg/e2e/run-testnet-e2e.sh run ...
  - The wrapper always injects:
      --workdir /home/ubuntu/testnet-e2e-live
      --base-funder-key-file .ci/secrets/base-funder.key
      --output /home/ubuntu/testnet-e2e-live/reports/testnet-e2e-summary.json
      --force
EOF
}

ensure_local_command() {
  local cmd="$1"
  if ! have_cmd "$cmd"; then
    die "missing required command: $cmd"
  fi
}

trimmed_file_value() {
  local path="$1"
  tr -d '\r\n' <"$path"
}

run_with_local_timeout() {
  local timeout_seconds="$1"
  shift || true
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "timeout seconds must be numeric"
  (( timeout_seconds > 0 )) || die "timeout seconds must be > 0"

  if have_cmd timeout; then
    timeout "$timeout_seconds" "$@"
    return $?
  fi

  if have_cmd gtimeout; then
    gtimeout "$timeout_seconds" "$@"
    return $?
  fi

  if have_cmd python3; then
    python3 -c '
import os
import signal
import subprocess
import sys

timeout_seconds = int(sys.argv[1])
command = sys.argv[2:]

if not command:
    sys.exit(0)

proc = subprocess.Popen(command, preexec_fn=os.setsid)
try:
    sys.exit(proc.wait(timeout=timeout_seconds))
except subprocess.TimeoutExpired:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    sys.exit(124)
' "$timeout_seconds" "$@"
    return $?
  fi

  if have_cmd perl; then
    perl -e 'alarm shift; exec @ARGV' "$timeout_seconds" "$@"
    return $?
  fi

  log "warning: local timeout command unavailable; running without timeout: $*"
  "$@"
}

shell_join() {
  local out=""
  local arg
  for arg in "$@"; do
    out+=" $(printf '%q' "$arg")"
  done
  printf '%s' "${out# }"
}

normalize_hex_prefixed_value() {
  local value="${1:-}"
  value="$(trim "$value")"
  [[ -n "$value" ]] || return 1
  value="${value#0x}"
  value="${value#0X}"
  value="$(lower "$value")"
  [[ "$value" =~ ^[0-9a-f]+$ ]] || return 1
  printf '0x%s' "$value"
}

derive_owallet_keys_from_ufvk() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local runner_public_ip="$3"
  local remote_repo="$4"
  local ufvk="$5"

  [[ -n "$ufvk" ]] || return 1

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local derive_script derive_output derived_deposit_ivk derived_withdraw_ovk
  derive_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
cargo run --quiet --manifest-path deploy/operators/dkg/e2e/ufvk-derive-keys/Cargo.toml -- $(printf '%q' "$ufvk")
EOF
)"
  derive_output="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "bash -lc $(printf '%q' "$derive_script")" 2>/dev/null || true
  )"
  [[ -n "$derive_output" ]] || return 1

  derived_deposit_ivk="$(awk -F= '/^SP1_DEPOSIT_OWALLET_IVK_HEX=/{print $2; exit}' <<<"$derive_output")"
  derived_withdraw_ovk="$(awk -F= '/^SP1_WITHDRAW_OWALLET_OVK_HEX=/{print $2; exit}' <<<"$derive_output")"

  derived_deposit_ivk="$(normalize_hex_prefixed_value "$derived_deposit_ivk" || true)"
  derived_withdraw_ovk="$(normalize_hex_prefixed_value "$derived_withdraw_ovk" || true)"
  [[ "$derived_deposit_ivk" =~ ^0x[0-9a-f]{128}$ ]] || return 1
  [[ "$derived_withdraw_ovk" =~ ^0x[0-9a-f]{64}$ ]] || return 1

  DISTRIBUTED_SP1_DEPOSIT_OWALLET_IVK_HEX="$derived_deposit_ivk"
  DISTRIBUTED_SP1_WITHDRAW_OWALLET_OVK_HEX="$derived_withdraw_ovk"
  return 0
}

load_distributed_identity_from_existing_runner_state() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local runner_public_ip="$3"
  local remote_repo="$4"
  local remote_workdir="$5"
  local dkg_summary_remote_path="$6"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local completion_report completion_ufvk completion_juno_shielded_address
  completion_report="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
      "jq -r '.completion_report // empty' $(printf '%q' "$dkg_summary_remote_path")"
  )"
  if [[ -z "$completion_report" ]]; then
    completion_report="$remote_workdir/dkg-distributed/coordinator/reports/test-completiton.json"
  fi

  completion_ufvk="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
      "jq -r '.ufvk // empty' $(printf '%q' "$completion_report")"
  )"
  [[ -n "$completion_ufvk" ]] || \
    die "distributed dkg completion report missing ufvk: $completion_report"
  DISTRIBUTED_COMPLETION_UFVK="$completion_ufvk"

  completion_juno_shielded_address="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
      "jq -r '.juno_shielded_address // empty' $(printf '%q' "$completion_report")"
  )"
  [[ -n "$completion_juno_shielded_address" ]] || \
    die "distributed dkg completion report missing juno_shielded_address: $completion_report"
  DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA="$completion_juno_shielded_address"

  if ! derive_owallet_keys_from_ufvk "$ssh_private_key" "$ssh_user" "$runner_public_ip" "$remote_repo" "$completion_ufvk"; then
    die "distributed dkg completion report produced invalid owallet key derivation output"
  fi
}

forwarded_arg_value() {
  local flag="$1"
  shift
  local -a args=("$@")

  local idx=0
  while (( idx < ${#args[@]} )); do
    if [[ "${args[$idx]}" == "$flag" ]]; then
      if (( idx + 1 >= ${#args[@]} )); then
        die "forwarded argument missing value: $flag"
      fi
      printf '%s' "${args[$((idx + 1))]}"
      return 0
    fi
    idx=$((idx + 1))
  done

  return 1
}

normalize_bool_arg() {
  local flag_name="$1"
  local value="${2:-}"
  value="${value,,}"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      die "$flag_name must be true or false"
      ;;
  esac
}

array_has_value() {
  local needle="$1"
  shift || true
  local candidate
  for candidate in "$@"; do
    if [[ "$candidate" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

strip_flag_with_value() {
  local flag="$1"
  shift || true
  local -a input_args=("$@")
  local -a output_args=()
  local idx=0
  while (( idx < ${#input_args[@]} )); do
    if [[ "${input_args[$idx]}" == "$flag" ]]; then
      (( idx + 1 < ${#input_args[@]} )) || die "missing value for $flag"
      idx=$((idx + 2))
      continue
    fi
    output_args+=("${input_args[$idx]}")
    idx=$((idx + 1))
  done
  printf '%s\0' "${output_args[@]}"
}

write_status_json() {
  local status_path="$1"
  local command_name="$2"
  local status_value="$3"
  local message="$4"
  local summary_path="${5:-}"
  local log_path="${6:-}"
  local classification_json="${7:-null}"

  [[ -n "$status_path" ]] || return 0
  ensure_dir "$(dirname "$status_path")"
  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg command "$command_name" \
    --arg status "$status_value" \
    --arg message "$message" \
    --arg summary_path "$summary_path" \
    --arg log_path "$log_path" \
    --argjson classification "$classification_json" \
    '{
      generated_at: $generated_at,
      command: $command,
      status: $status,
      message: $message,
      summary_path: (if $summary_path == "" then null else $summary_path end),
      log_path: (if $log_path == "" then null else $log_path end),
      classification: $classification
    }' >"$status_path"
}

classify_failure_signature() {
  local log_path="$1"
  if [[ ! -f "$FAILURE_SIGNATURES_FILE" || ! -s "$log_path" ]]; then
    printf 'null'
    return 0
  fi

  local id regex class likely_root_cause owner suggested_immediate_action
  while IFS=$'\t' read -r id regex class likely_root_cause owner suggested_immediate_action; do
    if grep -E -q -- "$regex" "$log_path"; then
      jq -n \
        --arg id "$id" \
        --arg regex "$regex" \
        --arg class "$class" \
        --arg likely_root_cause "$likely_root_cause" \
        --arg owner "$owner" \
        --arg suggested_immediate_action "$suggested_immediate_action" \
        '{
          id: $id,
          regex: $regex,
          class: $class,
          likely_root_cause: $likely_root_cause,
          owner: $owner,
          suggested_immediate_action: $suggested_immediate_action
        }'
      return 0
    fi
  done < <(
    jq -r '.signatures[] | [.id, .regex, .class, .likely_root_cause, .owner, .suggested_immediate_action] | @tsv' \
      "$FAILURE_SIGNATURES_FILE"
  )

  printf 'null'
}

print_failure_classification_hint() {
  local classification_json="${1:-null}"
  if [[ "$classification_json" == "null" || -z "$classification_json" ]]; then
    return 0
  fi
  local class id owner action
  class="$(jq -r '.class // empty' <<<"$classification_json")"
  id="$(jq -r '.id // empty' <<<"$classification_json")"
  owner="$(jq -r '.owner // empty' <<<"$classification_json")"
  action="$(jq -r '.suggested_immediate_action // empty' <<<"$classification_json")"
  log "classified failure signature id=$id class=$class owner=$owner action=$action"
}

extract_summary_path_from_log() {
  local log_path="$1"
  local summary_path
  summary_path="$(awk -F'summary=' '/summary=/{print $2}' "$log_path" | tail -n 1 | tr -d '\r\n')"
  if [[ -n "$summary_path" && -f "$summary_path" ]]; then
    printf '%s' "$summary_path"
    return 0
  fi
  summary_path="$(grep -Eo '/[^[:space:]]*testnet-e2e-summary\.json' "$log_path" | tail -n 1 || true)"
  if [[ -n "$summary_path" && -f "$summary_path" ]]; then
    printf '%s' "$summary_path"
    return 0
  fi
  printf ''
}

validate_canary_summary() {
  local summary_path="$1"
  jq -e '
    .stage_control.completed_stage == "checkpoint_validated"
    and .stage_control.stages.witness_ready
    and .stage_control.stages.shared_services_ready
    and .stage_control.stages.checkpoint_validated
    and .stage_control.shared_services.stable
    and .stage_control.checkpoint_validation.shared_validation_passed
    and (.stage_control.checkpoint_validation.bridge_config_updates_succeeded >= .stage_control.checkpoint_validation.bridge_config_updates_target)
    and .bridge.sp1.guest_witness.quorum_validated
  ' "$summary_path" >/dev/null
}

run_required_aws_probe() {
  local probe_name="$1"
  shift
  local out="" attempt
  for attempt in $(seq 1 3); do
    if out="$(run_with_local_timeout 45 "$@" 2>&1)"; then
      return 0
    fi
    if (( attempt < 3 )); then
      log "aws preflight probe failed (probe=$probe_name attempt $attempt/3); retrying in 5s"
      sleep 5
    fi
  done
  printf '%s\n' "$out" >&2
  die "aws preflight probe failed: $probe_name"
}

run_preflight_aws_reachability_probes() {
  local aws_profile="$1"
  local aws_region="$2"
  local with_shared_services="$3"

  aws_env_args "$aws_profile" "$aws_region"
  run_required_aws_probe \
    "sts:GetCallerIdentity" \
    env "${AWS_ENV_ARGS[@]}" aws sts get-caller-identity --region "$aws_region"

  if [[ "$with_shared_services" == "true" ]]; then
    run_required_aws_probe \
      "rds:DescribeDBEngineVersions" \
      env "${AWS_ENV_ARGS[@]}" aws rds describe-db-engine-versions \
        --region "$aws_region" \
        --engine aurora-postgresql \
        --default-only \
        --max-records 20
    run_required_aws_probe \
      "kafka:ListClustersV2" \
      env "${AWS_ENV_ARGS[@]}" aws kafka list-clusters-v2 \
        --region "$aws_region" \
        --max-results 1
    run_required_aws_probe \
      "ecs:ListClusters" \
      env "${AWS_ENV_ARGS[@]}" aws ecs list-clusters \
        --region "$aws_region" \
        --max-items 1
  fi
}

run_preflight_script_tests() {
  local -a tests=(
    "deploy/operators/dkg/tests/generate_witness_metadata_test.sh"
    "deploy/operators/dkg/tests/run_testnet_e2e_test.sh"
    "deploy/operators/dkg/tests/e2e_aws_test.sh"
    "deploy/operators/dkg/tests/e2e_aws_checkpoint_deferral_test.sh"
    "deploy/operators/dkg/tests/live_e2e_terraform_iam_test.sh"
  )
  local test_script
  for test_script in "${tests[@]}"; do
    log "preflight test: $test_script"
    bash "$REPO_ROOT/$test_script"
  done
}

validate_sp1_credit_guardrail_preflight() {
  local sp1_requestor_key_file="$1"
  local sp1_rpc_url="$2"
  local sp1_max_price_per_pgu="$3"
  local sp1_deposit_pgu_estimate="$4"
  local sp1_withdraw_pgu_estimate="$5"
  local sp1_groth16_base_fee_wei="$6"

  [[ "$sp1_max_price_per_pgu" =~ ^[0-9]+$ ]] || die "forwarded --sp1-max-price-per-pgu must be numeric"
  [[ "$sp1_deposit_pgu_estimate" =~ ^[0-9]+$ ]] || die "forwarded --sp1-deposit-pgu-estimate must be numeric"
  [[ "$sp1_withdraw_pgu_estimate" =~ ^[0-9]+$ ]] || die "forwarded --sp1-withdraw-pgu-estimate must be numeric"
  [[ "$sp1_groth16_base_fee_wei" =~ ^[0-9]+$ ]] || die "forwarded --sp1-groth16-base-fee-wei must be numeric"
  (( sp1_max_price_per_pgu > 0 )) || die "forwarded --sp1-max-price-per-pgu must be > 0"
  (( sp1_deposit_pgu_estimate > 0 )) || die "forwarded --sp1-deposit-pgu-estimate must be > 0"
  (( sp1_withdraw_pgu_estimate > 0 )) || die "forwarded --sp1-withdraw-pgu-estimate must be > 0"
  (( sp1_groth16_base_fee_wei > 0 )) || die "forwarded --sp1-groth16-base-fee-wei must be > 0"
  local sp1_rpc_url_lc
  sp1_rpc_url_lc="$(lower "$sp1_rpc_url")"
  if [[ "$sp1_rpc_url_lc" == *"mainnet.base.org"* || "$sp1_rpc_url_lc" == *"base-sepolia"* ]]; then
    die "--sp1-rpc-url must be a Succinct prover network RPC (for example https://rpc.mainnet.succinct.xyz), not a Base chain RPC endpoint: $sp1_rpc_url"
  fi

  local sp1_requestor_key_hex sp1_requestor_address
  sp1_requestor_key_hex="$(trimmed_file_value "$sp1_requestor_key_file")"
  [[ -n "$sp1_requestor_key_hex" ]] || die "sp1 requestor key file is empty: $sp1_requestor_key_file"
  sp1_requestor_address="$(cast wallet address --private-key "$sp1_requestor_key_hex" 2>/dev/null || true)"
  [[ "$sp1_requestor_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || \
    die "failed to derive sp1 requestor address from key file: $sp1_requestor_key_file"

  local -a guardrail_values=()
  mapfile -t guardrail_values < <(
    python3 - "$sp1_max_price_per_pgu" "$sp1_deposit_pgu_estimate" "$sp1_withdraw_pgu_estimate" "$sp1_groth16_base_fee_wei" <<'PY'
import sys

max_price_per_pgu = int(sys.argv[1])
deposit_pgu_estimate = int(sys.argv[2])
withdraw_pgu_estimate = int(sys.argv[3])
groth16_base_fee_wei = int(sys.argv[4])

projected_pair_cost_wei = (groth16_base_fee_wei * 2) + (
    max_price_per_pgu * (deposit_pgu_estimate + withdraw_pgu_estimate)
)
projected_with_overhead_wei = ((projected_pair_cost_wei * 120) + 99) // 100
required_buffer_wei = projected_with_overhead_wei * 3

print(projected_pair_cost_wei)
print(required_buffer_wei)
PY
  )
  (( ${#guardrail_values[@]} == 2 )) || die "failed to compute sp1 credit guardrail values"
  local projected_pair_cost_wei required_buffer_wei
  projected_pair_cost_wei="${guardrail_values[0]}"
  required_buffer_wei="${guardrail_values[1]}"
  log "sp1 credit guardrail preflight computed requestor_address=$sp1_requestor_address projected_pair_cost_wei=$projected_pair_cost_wei required_wei=$required_buffer_wei"
  log "sp1 requestor balance probe is enforced by shared proof-funder service at runtime (runner performs orchestration-only preflight)"
}

terraform_env_args() {
  local profile="$1"
  local region="$2"
  TF_ENV_ARGS=()
  if [[ -n "$profile" ]]; then
    TF_ENV_ARGS+=("AWS_PROFILE=$profile")
  fi
  if [[ -n "$region" ]]; then
    TF_ENV_ARGS+=("AWS_REGION=$region")
  fi
}

aws_env_args() {
  local profile="$1"
  local region="$2"
  AWS_ENV_ARGS=()
  if [[ -n "$profile" ]]; then
    AWS_ENV_ARGS+=("AWS_PROFILE=$profile")
  fi
  if [[ -n "$region" ]]; then
    AWS_ENV_ARGS+=("AWS_REGION=$region")
    AWS_ENV_ARGS+=("AWS_DEFAULT_REGION=$region")
  fi
}

create_sp1_requestor_secret() {
  local aws_profile="$1"
  local aws_region="$2"
  local secret_name="$3"
  local secret_value="$4"

  [[ -n "$secret_name" ]] || die "sp1 requestor secret name is required"
  [[ -n "$secret_value" ]] || die "sp1 requestor secret value is required"

  aws_env_args "$aws_profile" "$aws_region"
  env "${AWS_ENV_ARGS[@]}" aws secretsmanager create-secret \
    --name "$secret_name" \
    --description "sp1 requestor key for intents-juno live e2e" \
    --secret-string "$secret_value" \
    --query 'ARN' \
    --output text
}

delete_sp1_requestor_secret() {
  local aws_profile="$1"
  local aws_region="$2"
  local secret_id="$3"

  [[ -n "$secret_id" ]] || return 0

  aws_env_args "$aws_profile" "$aws_region"
  env "${AWS_ENV_ARGS[@]}" aws secretsmanager delete-secret \
    --secret-id "$secret_id" \
    --force-delete-without-recovery >/dev/null
}

sp1_requestor_secret_exists() {
  local aws_profile="$1"
  local aws_region="$2"
  local secret_id="$3"

  [[ -n "$secret_id" ]] || return 1

  aws_env_args "$aws_profile" "$aws_region"
  env "${AWS_ENV_ARGS[@]}" aws secretsmanager describe-secret \
    --secret-id "$secret_id" >/dev/null 2>&1
}

run_with_retry() {
  local description="$1"
  local max_attempts="$2"
  local sleep_seconds="$3"
  shift 3

  local attempt
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    if "$@"; then
      return 0
    fi
    if (( attempt < max_attempts )); then
      log "$description failed (attempt $attempt/$max_attempts); retrying in ${sleep_seconds}s"
      sleep "$sleep_seconds"
    fi
  done
  return 1
}

terraform_apply_live_e2e() {
  local terraform_dir="$1"
  local state_file="$2"
  local tfvars_file="$3"
  local aws_profile="$4"
  local aws_region="$5"

  terraform_env_args "$aws_profile" "$aws_region"
  run_with_retry "terraform init (region=$aws_region state=$state_file)" 3 5 \
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform -chdir="$terraform_dir" init -input=false >/dev/null
  run_with_retry "terraform apply (region=$aws_region state=$state_file)" 3 10 \
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      apply \
      -input=false \
      -auto-approve \
      -state="$state_file" \
      -var-file="$tfvars_file"
}

terraform_destroy_live_e2e() {
  local terraform_dir="$1"
  local state_file="$2"
  local tfvars_file="$3"
  local aws_profile="$4"
  local aws_region="$5"

  if [[ ! -f "$state_file" || ! -f "$tfvars_file" ]]; then
    log "terraform state or tfvars missing; nothing to destroy"
    return 0
  fi

  terraform_env_args "$aws_profile" "$aws_region"
  run_with_retry "terraform init (region=$aws_region state=$state_file)" 3 5 \
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform -chdir="$terraform_dir" init -input=false >/dev/null
  run_with_retry "terraform destroy (region=$aws_region state=$state_file)" 3 10 \
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      destroy \
      -input=false \
      -auto-approve \
      -state="$state_file" \
      -var-file="$tfvars_file"
}

sanitize_dkg_summary_file() {
  local summary_path="$1"
  [[ -f "$summary_path" ]] || return 0

  local tmp_path
  tmp_path="${summary_path}.tmp"
  jq '
    del(.workdir, .coordinator_workdir, .completion_report)
    | if (.operators? | type) == "array" then
        .operators |= map(del(.operator_key_file, .backup_package, .runtime_dir, .registration_file))
      else
        .
      end
  ' "$summary_path" >"$tmp_path"
  mv "$tmp_path" "$summary_path"
}

cleanup_trap() {
  if [[ "$cleanup_enabled" != "true" ]]; then
    return 0
  fi

  if [[ -n "$cleanup_dr_state_file" && -n "$cleanup_dr_tfvars_file" ]]; then
    log "cleanup trap: destroying dr live e2e infrastructure"
    if ! terraform_destroy_live_e2e "$cleanup_terraform_dir" "$cleanup_dr_state_file" "$cleanup_dr_tfvars_file" "$cleanup_aws_profile" "$cleanup_dr_aws_region"; then
      log "cleanup trap dr destroy failed (manual cleanup may be required)"
    fi
  fi

  if [[ -n "$cleanup_primary_state_file" && -n "$cleanup_primary_tfvars_file" ]]; then
    log "cleanup trap: destroying primary live e2e infrastructure"
    if ! terraform_destroy_live_e2e "$cleanup_terraform_dir" "$cleanup_primary_state_file" "$cleanup_primary_tfvars_file" "$cleanup_aws_profile" "$cleanup_primary_aws_region"; then
      log "cleanup trap primary destroy failed (manual cleanup may be required)"
    fi
  fi

  if [[ -n "$cleanup_dr_sp1_requestor_secret_arn" ]]; then
    log "cleanup trap: deleting dr sp1 requestor secret"
    if ! delete_sp1_requestor_secret "$cleanup_aws_profile" "$cleanup_dr_aws_region" "$cleanup_dr_sp1_requestor_secret_arn"; then
      log "cleanup trap dr secret delete failed (manual cleanup may be required)"
    fi
  fi

  if [[ -n "$cleanup_primary_sp1_requestor_secret_arn" ]]; then
    log "cleanup trap: deleting primary sp1 requestor secret"
    if ! delete_sp1_requestor_secret "$cleanup_aws_profile" "$cleanup_primary_aws_region" "$cleanup_primary_sp1_requestor_secret_arn"; then
      log "cleanup trap primary secret delete failed (manual cleanup may be required)"
    fi
  fi
}

rollout_shared_proof_services() {
  local aws_profile="$1"
  local aws_region="$2"
  local cluster_arn="$3"
  local proof_requestor_service="$4"
  local proof_funder_service="$5"
  local desired_count="$6"

  [[ -n "$aws_region" ]] || die "aws region is required for shared proof service rollout"
  [[ -n "$cluster_arn" ]] || die "shared ecs cluster arn is required for shared proof service rollout"
  [[ -n "$proof_requestor_service" ]] || die "proof-requestor service name is required for shared proof service rollout"
  [[ -n "$proof_funder_service" ]] || die "proof-funder service name is required for shared proof service rollout"

  aws_env_args "$aws_profile" "$aws_region"

  log "rolling out shared proof-requestor ecs service"
  env "${AWS_ENV_ARGS[@]}" aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_requestor_service" \
    --desired-count "$desired_count" \
    --force-new-deployment >/dev/null

  log "rolling out shared proof-funder ecs service"
  env "${AWS_ENV_ARGS[@]}" aws ecs update-service \
    --region "$aws_region" \
    --cluster "$cluster_arn" \
    --service "$proof_funder_service" \
    --desired-count "$desired_count" \
    --force-new-deployment >/dev/null
}

wait_for_ssh() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local ssh_proxy_jump="${4:-}"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=10
    -o BatchMode=yes
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )
  if [[ -n "$ssh_proxy_jump" ]]; then
    ssh_opts+=(
      -o "ProxyCommand=ssh -i $ssh_private_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -W %h:%p $ssh_proxy_jump"
    )
  fi

  local attempt
  for attempt in $(seq 1 90); do
    if ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" 'echo ready' >/dev/null 2>&1; then
      log "ssh reachable: $ssh_user@$ssh_host"
      return 0
    fi
    sleep 10
  done
  die "timed out waiting for ssh connectivity to $ssh_user@$ssh_host"
}

remote_prepare_runner() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local repo_commit="$4"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=10
    -o BatchMode=yes
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  run_with_retry "remote runner ssh readiness" 6 10 \
    ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" 'echo ready' >/dev/null 2>&1
  wait_for_ssh "$ssh_private_key" "$ssh_user" "$ssh_host"

  local remote_script
  remote_script="$(build_remote_prepare_script "$repo_commit")"

  run_with_retry "remote runner bootstrap" 3 15 \
    ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"
}

remote_prepare_operator_host() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local repo_commit="$4"
  local ssh_proxy_jump="${5:-}"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )
  if [[ -n "$ssh_proxy_jump" ]]; then
    ssh_opts+=(
      -o "ProxyCommand=ssh -i $ssh_private_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -W %h:%p $ssh_proxy_jump"
    )
  fi

  local remote_script
  remote_script="$(build_remote_operator_prepare_script "$repo_commit")"

  wait_for_ssh "$ssh_private_key" "$ssh_user" "$ssh_host" "$ssh_proxy_jump"
  run_with_retry "remote operator host bootstrap" 3 15 \
    ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"
}

wait_for_shared_connectivity_from_runner() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local shared_postgres_host="$4"
  local shared_postgres_port="$5"
  local shared_kafka_brokers="$6"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local remote_script
  remote_script="$(
    build_runner_shared_probe_script \
      "$shared_postgres_host" \
      "$shared_postgres_port" \
      "$shared_kafka_brokers"
  )"

  local attempt
  for attempt in $(seq 1 3); do
    log "checking shared services connectivity from runner (attempt $attempt/3)"
    if ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" 'bash -s' <<<"$remote_script"; then
      return 0
    fi
    if [[ $attempt -lt 3 ]]; then
      sleep 5
    fi
  done

  return 1
}

validate_shared_services_dr_readiness() {
  local aws_profile="$1"
  local aws_region="$2"
  local aws_dr_region="$3"

  [[ -n "$aws_dr_region" ]] || die "--aws-dr-region is required when shared services are enabled"
  [[ "$aws_dr_region" != "$aws_region" ]] || die "--aws-dr-region must differ from --aws-region"

  aws_env_args "$aws_profile" "$aws_dr_region"
  env "${AWS_ENV_ARGS[@]}" aws sts get-caller-identity >/dev/null

  local dr_az_count
  dr_az_count="$(
    env "${AWS_ENV_ARGS[@]}" aws ec2 describe-availability-zones \
      --region "$aws_dr_region" \
      --all-availability-zones \
      --query 'length(AvailabilityZones[?State==`available` && (OptInStatus==`opt-in-not-required` || OptInStatus==`opted-in`)])' \
      --output text
  )"
  [[ "$dr_az_count" =~ ^[0-9]+$ ]] || die "failed to resolve DR AZ count in region: $aws_dr_region"
  (( dr_az_count >= 2 )) || die "DR readiness check failed: region $aws_dr_region must have at least 2 available AZs"

  run_optional_dr_readiness_probe \
    "rds:DescribeDBEngineVersions" \
    env "${AWS_ENV_ARGS[@]}" aws rds describe-db-engine-versions \
      --region "$aws_dr_region" \
      --engine aurora-postgresql \
      --default-only \
      --max-records 20

  run_optional_dr_readiness_probe \
    "kafka:ListClustersV2" \
    env "${AWS_ENV_ARGS[@]}" aws kafka list-clusters-v2 \
      --region "$aws_dr_region" \
      --max-results 1

  run_optional_dr_readiness_probe \
    "ecs:ListClusters" \
    env "${AWS_ENV_ARGS[@]}" aws ecs list-clusters \
      --region "$aws_dr_region" \
      --max-items 1

  log "dr readiness checks passed (primary=$aws_region dr=$aws_dr_region available_azs=$dr_az_count)"
}

run_optional_dr_readiness_probe() {
  local probe_name="$1"
  shift

  local out=""
  local attempt lowered
  for attempt in $(seq 1 3); do
    if out="$(run_with_local_timeout 45 "$@" 2>&1)"; then
      return 0
    fi

    lowered="$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')"
    if [[ "$lowered" == *"accessdenied"* || "$lowered" == *"unauthorizedoperation"* || "$lowered" == *"not authorized"* ]]; then
      log "warning: skipping dr readiness probe due to IAM permission limits (probe=$probe_name)"
      return 0
    fi

    if (( attempt < 3 )); then
      log "dr readiness probe failed (probe=$probe_name attempt $attempt/3); retrying in 5s"
      sleep 5
    fi
  done

  printf '%s\n' "$out" >&2
  die "dr readiness probe failed: $probe_name"
}

ami_exists_in_region() {
  local aws_profile="$1"
  local aws_region="$2"
  local ami_id="$3"

  [[ -n "$ami_id" ]] || return 1

  local image_count
  aws_env_args "$aws_profile" "$aws_region"
  image_count="$(
    env "${AWS_ENV_ARGS[@]}" aws ec2 describe-images \
      --region "$aws_region" \
      --image-ids "$ami_id" \
      --query 'length(Images)' \
      --output text 2>/dev/null || true
  )"

  [[ "$image_count" == "1" ]]
}

resolve_dr_ami_id() {
  local aws_profile="$1"
  local aws_dr_region="$2"
  local ami_role="$3"
  local candidate_ami_id="$4"

  if [[ -z "$candidate_ami_id" ]]; then
    printf ''
    return 0
  fi

  if ami_exists_in_region "$aws_profile" "$aws_dr_region" "$candidate_ami_id"; then
    printf '%s' "$candidate_ami_id"
    return 0
  fi

  log "$ami_role AMI $candidate_ami_id unavailable in DR region $aws_dr_region; falling back to Terraform region default AMI"
  printf ''
}

resolve_latest_operator_stack_ami() {
  local aws_profile="$1"
  local aws_region="$2"

  local image_json
  aws_env_args "$aws_profile" "$aws_region"
  image_json="$(
    env "${AWS_ENV_ARGS[@]}" aws ec2 describe-images \
      --region "$aws_region" \
      --owners self \
      --filters "Name=name,Values=intents-juno-operator-stack-*" "Name=state,Values=available" \
      --query 'reverse(sort_by(Images,&CreationDate))[0].{ImageId:ImageId,Name:Name,CreationDate:CreationDate}' \
      --output json
  )"

  local image_id image_name image_created_at
  image_id="$(jq -r '.ImageId // empty' <<<"$image_json")"
  image_name="$(jq -r '.Name // empty' <<<"$image_json")"
  image_created_at="$(jq -r '.CreationDate // empty' <<<"$image_json")"

  if [[ -z "$image_id" ]]; then
    return 1
  fi

  log "defaulting --operator-ami-id to latest operator stack AMI: $image_id (name=$image_name created=$image_created_at)"
  printf '%s' "$image_id"
}

resolve_github_repo_slug() {
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    printf '%s' "$GITHUB_REPOSITORY"
    return 0
  fi

  local origin_url
  origin_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  [[ -n "$origin_url" ]] || return 1

  origin_url="${origin_url%.git}"
  if [[ "$origin_url" =~ ^git@github\.com:([^/]+/[^/]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$origin_url" =~ ^https://github\.com/([^/]+/[^/]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$origin_url" =~ ^ssh://git@github\.com/([^/]+/[^/]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi

  return 1
}

resolve_latest_shared_proof_services_image() {
  local release_tag="$1"
  local aws_region="$2"

  [[ -n "$release_tag" ]] || return 1
  [[ -n "$aws_region" ]] || return 1

  local gh_repo
  gh_repo="$(resolve_github_repo_slug || true)"
  [[ -n "$gh_repo" ]] || return 1

  local tmpdir manifest_path
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/shared-proof-services-image.XXXXXX")"
  manifest_path="$tmpdir/shared-proof-services-image-manifest.json"

  if ! gh release download "$release_tag" \
    --repo "$gh_repo" \
    --pattern "shared-proof-services-image-manifest.json" \
    --output "$manifest_path" >/dev/null 2>&1; then
    rm -rf "$tmpdir"
    return 1
  fi

  local image_uri
  image_uri="$(
    jq -r --arg region "$aws_region" '
      .regions[$region].image_uri
      // .image_uri
      // empty
    ' "$manifest_path"
  )"
  rm -rf "$tmpdir"

  [[ -n "$image_uri" ]] || return 1
  printf '%s' "$image_uri"
}

build_remote_prepare_script() {
  local repo_commit="$1"
  cat <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if command -v cloud-init >/dev/null 2>&1; then
  sudo cloud-init status --wait || true
fi

run_apt_with_retry() {
  local attempt
  for attempt in \$(seq 1 30); do
    if sudo apt-get "\$@"; then
      return 0
    fi
    if [[ \$attempt -lt 30 ]]; then
      sleep 5
    fi
  done
  return 1
}

run_with_retry() {
  local attempt
  for attempt in \$(seq 1 3); do
    if "\$@"; then
      return 0
    fi
    if [[ \$attempt -lt 3 ]]; then
      sleep 5
    fi
  done
  return 1
}

run_apt_with_retry update -y
run_apt_with_retry install -y build-essential pkg-config libssl-dev jq curl git unzip ca-certificates rsync age golang-go tar

export PATH="\$HOME/.foundry/bin:\$HOME/.local/bin:\$PATH"
if ! command -v foundryup >/dev/null 2>&1; then
  curl -L https://foundry.paradigm.xyz | bash
fi
foundryup

if [[ ! -d "\$HOME/intents-juno/.git" ]]; then
  git clone https://github.com/juno-intents/intents-juno.git "\$HOME/intents-juno"
fi
cd "\$HOME/intents-juno"
git fetch --tags origin
git reset --hard
git clean -fd
if git rev-parse --verify --quiet ${repo_commit}^{commit} >/dev/null; then
  git checkout ${repo_commit}
else
  echo "warning: repo commit ${repo_commit} unavailable on origin; falling back to origin/main" >&2
  git checkout origin/main
fi
git submodule update --init --recursive
mkdir -p .ci/secrets
chmod 700 .ci/secrets
EOF
}

build_remote_operator_prepare_script() {
  local repo_commit="$1"
  cat <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if command -v cloud-init >/dev/null 2>&1; then
  sudo cloud-init status --wait || true
fi

run_apt_with_retry() {
  local attempt
  for attempt in \$(seq 1 30); do
    if sudo apt-get "\$@"; then
      return 0
    fi
    if [[ \$attempt -lt 30 ]]; then
      sleep 5
    fi
  done
  return 1
}

run_apt_with_retry update -y
run_apt_with_retry install -y build-essential pkg-config libssl-dev jq curl git unzip ca-certificates rsync age golang-go tar

if [[ ! -d "\$HOME/intents-juno/.git" ]]; then
  git clone https://github.com/juno-intents/intents-juno.git "\$HOME/intents-juno"
fi
cd "\$HOME/intents-juno"
git fetch --tags origin
git reset --hard
git clean -fd
if git rev-parse --verify --quiet ${repo_commit}^{commit} >/dev/null; then
  git checkout ${repo_commit}
else
  echo "warning: repo commit ${repo_commit} unavailable on origin; falling back to origin/main" >&2
  git checkout origin/main
fi
git submodule update --init --recursive

required_services=(
  junocashd.service
  juno-scan.service
  checkpoint-signer.service
  checkpoint-aggregator.service
  tss-host.service
)
startup_services=(
  junocashd.service
  juno-scan.service
)

missing_services=0
for svc in "\${required_services[@]}"; do
  if ! sudo systemctl cat "\$svc" >/dev/null 2>&1; then
    echo "operator host is missing required stack service unit: \$svc" >&2
    missing_services=1
  fi
done
if (( missing_services != 0 )); then
  exit 1
fi

# Normalize stack config file access so ubuntu-owned services can start on reused AMIs.
sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno
required_stack_access_files=(
  /etc/intents-juno/junocashd.conf
  /etc/intents-juno/operator-stack.env
  /etc/intents-juno/checkpoint-signer.key
)
optional_stack_access_files=(
  /etc/intents-juno/operator-stack-hydrator.env
  /etc/intents-juno/operator-stack-config.json
)
for stack_file in "\${required_stack_access_files[@]}"; do
  [[ -f "\$stack_file" ]] || { echo "operator host missing required stack config file: \$stack_file" >&2; exit 1; }
done
stack_access_files=("\${required_stack_access_files[@]}" "\${optional_stack_access_files[@]}")
for stack_file in "\${stack_access_files[@]}"; do
  if [[ -f "\$stack_file" ]]; then
    sudo chgrp ubuntu "\$stack_file"
    sudo chmod 0640 "\$stack_file"
  fi
done

# Backfill legacy AMIs where checkpoint wrappers source stack env without exporting to child processes.
checkpoint_runtime_wrappers=(
  /usr/local/bin/intents-juno-checkpoint-signer.sh
  /usr/local/bin/intents-juno-checkpoint-aggregator.sh
)
for checkpoint_wrapper in "\${checkpoint_runtime_wrappers[@]}"; do
  [[ -f "\$checkpoint_wrapper" ]] || continue
  if grep -q "source /etc/intents-juno/operator-stack.env" "\$checkpoint_wrapper" \
    && ! grep -q '^set -a$' "\$checkpoint_wrapper"; then
    sudo perl -0pi -e 's/# shellcheck disable=SC1091\nsource \/etc\/intents-juno\/operator-stack\.env/# shellcheck disable=SC1091\nset -a\nsource \/etc\/intents-juno\/operator-stack.env\nset +a/' "\$checkpoint_wrapper"
  fi
done

sudo systemctl daemon-reload
sudo systemctl enable "\${required_services[@]}"
sudo systemctl restart "\${startup_services[@]}"

for svc in "\${startup_services[@]}"; do
  if ! sudo systemctl is-active --quiet "\$svc"; then
    echo "operator stack service failed to start: \$svc" >&2
    sudo systemctl status "\$svc" --no-pager || true
    exit 1
  fi
done
if sudo systemctl is-active --quiet tss-host.service; then
  echo "tss-host service already active"
else
  echo "tss-host startup deferred until signer runtime artifacts are provisioned"
fi
echo "checkpoint-signer/checkpoint-aggregator startup deferred until shared checkpoint config is provisioned"
EOF
}

build_runner_shared_probe_script() {
  local shared_postgres_host="$1"
  local shared_postgres_port="$2"
  local shared_kafka_brokers="$3"

  cat <<EOF
set -euo pipefail
IFS=',' read -r -a broker_list <<<'${shared_kafka_brokers}'
if [[ \${#broker_list[@]} -eq 0 ]]; then
  echo "no kafka brokers provided by terraform output" >&2
  exit 1
fi

for attempt in \$(seq 1 120); do
  postgres_ready="false"
  kafka_ready="true"
  if timeout 2 bash -lc '</dev/tcp/${shared_postgres_host}/${shared_postgres_port}' >/dev/null 2>&1; then
    postgres_ready="true"
  fi

  for broker in "\${broker_list[@]}"; do
    broker="\${broker//[[:space:]]/}"
    [[ -n "\$broker" ]] || continue
    broker_host="\${broker%%:*}"
    broker_port="\${broker##*:}"
    if [[ -z "\$broker_host" || -z "\$broker_port" || "\$broker_host" == "\$broker_port" ]]; then
      kafka_ready="false"
      break
    fi
    if ! timeout 2 bash -lc "</dev/tcp/\${broker_host}/\${broker_port}" >/dev/null 2>&1; then
      kafka_ready="false"
      break
    fi
  done

  if [[ "\$postgres_ready" == "true" && "\$kafka_ready" == "true" ]]; then
    echo "shared services reachable from runner"
    exit 0
  fi
  if [[ \$attempt -lt 120 ]]; then
    sleep 2
  fi
done

echo "timed out waiting for shared services connectivity from runner (postgres=${shared_postgres_host}:${shared_postgres_port}, kafka=${shared_kafka_brokers})" >&2
exit 1
EOF
}

copy_remote_secret_file() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local local_file="$4"
  local remote_file="$5"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local attempt
  for attempt in $(seq 1 6); do
    if run_with_local_timeout 45 scp "${ssh_opts[@]}" "$local_file" "$ssh_user@$ssh_host:$remote_file"; then
      break
    fi
    if (( attempt == 6 )); then
      die "failed to copy remote secret after retries: file=$local_file host=$ssh_host remote=$remote_file"
    fi
    log "remote secret copy failed attempt=$attempt/6 host=$ssh_host remote=$remote_file; retrying"
    sleep 2
  done

  for attempt in $(seq 1 6); do
    if run_with_local_timeout 20 ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "chmod 600 $(printf '%q' "$remote_file")"; then
      return 0
    fi
    if (( attempt == 6 )); then
      die "failed to chmod remote secret after retries: host=$ssh_host remote=$remote_file"
    fi
    log "remote secret chmod failed attempt=$attempt/6 host=$ssh_host remote=$remote_file; retrying"
    sleep 2
  done
}

run_distributed_dkg_backup_restore() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local runner_public_ip="$3"
  local remote_repo="$4"
  local remote_workdir="$5"
  local repo_commit="$6"
  local operator_count="$7"
  local threshold="$8"
  local operator_base_port="$9"
  local release_tag="${10}"
  local dkg_summary_remote_path="${11}"
  local dkg_summary_local_path="${12}"
  local operator_public_ips_csv="${13}"
  local operator_private_ips_csv="${14}"
  local dkg_kms_key_arn="${15}"
  local dkg_s3_bucket="${16}"
  local dkg_s3_key_prefix="${17}"
  local aws_region="${18}"
  local shared_postgres_dsn="${19:-}"
  local shared_kafka_brokers="${20:-}"
  local shared_ipfs_api_url="${21:-}"
  local checkpoint_blob_bucket="${22:-}"
  local checkpoint_blob_prefix="${23:-}"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local -a operator_public_ips=()
  local -a operator_private_ips=()
  if [[ -n "$operator_public_ips_csv" ]]; then
    IFS=',' read -r -a operator_public_ips <<<"$operator_public_ips_csv"
  fi
  if [[ -n "$operator_private_ips_csv" ]]; then
    IFS=',' read -r -a operator_private_ips <<<"$operator_private_ips_csv"
  fi

  (( ${#operator_public_ips[@]} == operator_count )) || die "operator public ip count mismatch: expected=$operator_count got=${#operator_public_ips[@]}"
  (( ${#operator_private_ips[@]} == operator_count )) || die "operator private ip count mismatch: expected=$operator_count got=${#operator_private_ips[@]}"

  local operator_proxy_jump
  operator_proxy_jump="$ssh_user@$runner_public_ip"

  local -a operator_ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
    -o "ProxyCommand=ssh -i $ssh_private_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -W %h:%p $operator_proxy_jump"
  )

  local idx op_index op_public_ip op_private_ip op_port
  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    log "preparing operator host op${op_index} via runner bastion ${runner_public_ip} -> ${op_private_ip} (public=${op_public_ip})"
    wait_for_ssh "$ssh_private_key" "$ssh_user" "$op_private_ip" "$operator_proxy_jump"
    remote_prepare_operator_host "$ssh_private_key" "$ssh_user" "$op_private_ip" "$repo_commit" "$operator_proxy_jump"
  done

  local private_ip_joined
  private_ip_joined="$(shell_join "${operator_private_ips[@]}")"
  local runner_init_script
  runner_init_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_NETWORK_MODE="vpc-private"
if [[ "${JUNO_DKG_ALLOW_INSECURE_NETWORK:-0}" == "1" ]]; then
  export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
fi
dkg_root="$remote_workdir/dkg-distributed"
rm -rf "\$dkg_root"
mkdir -p "\$dkg_root/operators" "\$dkg_root/reports"

operator_private_ips=($private_ip_joined)
for ((i = 1; i <= ${operator_count}; i++)); do
  op_dir="\$dkg_root/operators/op\${i}"
  key_file="\$op_dir/operator.key"
  meta_json="\$op_dir/operator-meta.json"
  registration_json="\$op_dir/registration.json"
  port=\$(( ${operator_base_port} + i - 1 ))
  endpoint="https://\${operator_private_ips[\$((i - 1))]}:\${port}"

  mkdir -p "\$op_dir"
  go run ./cmd/operator-keygen -private-key-path "\$key_file" >"\$meta_json"

  operator_id="\$(jq -r '.operator_id' "\$meta_json")"
  fee_recipient="\$(jq -r '.fee_recipient' "\$meta_json")"
  jq -n \\
    --arg operator_id "\$operator_id" \\
    --arg fee_recipient "\$fee_recipient" \\
    --arg grpc_endpoint "\$endpoint" \\
    '{
      operator_id: \$operator_id,
      fee_recipient: \$fee_recipient,
      grpc_endpoint: \$grpc_endpoint
    }' >"\$registration_json"
done

coordinator_init_args=(
  --workdir "\$dkg_root/coordinator"
  --network testnet
  --threshold "${threshold}"
  --max-signers "${operator_count}"
  --release-tag "${release_tag}"
)
for ((i = 1; i <= ${operator_count}; i++)); do
  coordinator_init_args+=(--registration-file "\$dkg_root/operators/op\${i}/registration.json")
done
deploy/operators/dkg/coordinator.sh init "\${coordinator_init_args[@]}"

for ((i = 1; i <= ${operator_count}; i++)); do
  op_dir="\$dkg_root/operators/op\${i}"
  operator_id="\$(jq -r '.operator_id' "\$op_dir/operator-meta.json")"
  slug="\$(printf '%s' "\$operator_id" | tr -cs '[:alnum:]_.-' '_' | sed -e 's/^_\\+//' -e 's/_\\+\$//')"
  if [[ -z "\$slug" ]]; then
    slug="value"
  fi
  bundle_path="\$(find "\$dkg_root/coordinator/bundles" -maxdepth 1 -type f -name "*_\${slug}.tar.gz" | head -n 1)"
  if [[ -z "\$bundle_path" ]]; then
    echo "bundle not found for operator \${operator_id}" >&2
    exit 1
  fi
  cp "\$bundle_path" "\$op_dir/bundle.tar.gz"
done
EOF
)"

  log "initializing distributed dkg coordinator and operator bundles on runner"
  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "bash -lc $(printf '%q' "$runner_init_script")"

  local staged_bundle_dir
  staged_bundle_dir="$(mktemp -d)"

  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    op_port=$((operator_base_port + op_index - 1))

    local bundle_local bundle_remote operator_root_remote
    bundle_local="$staged_bundle_dir/op${op_index}-bundle.tar.gz"
    bundle_remote="$remote_workdir/dkg-distributed/operators/op${op_index}/bundle.tar.gz"
    operator_root_remote="$remote_workdir/dkg-distributed/operators/op${op_index}"

    wait_for_ssh "$ssh_private_key" "$ssh_user" "$runner_public_ip"
    run_with_retry "copying distributed bundle op${op_index} from runner" 3 5 \
      scp "${ssh_opts[@]}" "$ssh_user@$runner_public_ip:$bundle_remote" "$bundle_local"
    wait_for_ssh "$ssh_private_key" "$ssh_user" "$op_private_ip" "$operator_proxy_jump"
    run_with_retry "staging distributed bundle op${op_index} directory" 3 5 \
      ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" "mkdir -p $(printf '%q' "$operator_root_remote")"
    run_with_retry "copying distributed bundle op${op_index} to operator" 3 5 \
      scp "${operator_ssh_opts[@]}" "$bundle_local" "$ssh_user@$op_private_ip:$bundle_remote"

    local start_operator_script
    start_operator_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_NETWORK_MODE="vpc-private"
if [[ "${JUNO_DKG_ALLOW_INSECURE_NETWORK:-0}" == "1" ]]; then
  export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
fi
op_root="$operator_root_remote"
runtime_dir="\$op_root/runtime"
deploy/operators/dkg/operator.sh stop --workdir "\$runtime_dir" >/dev/null 2>&1 || true
rm -rf "\$runtime_dir"
deploy/operators/dkg/operator.sh run \
  --bundle "\$op_root/bundle.tar.gz" \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --daemon
EOF
)"

    log "starting operator daemon op${op_index} on ${op_private_ip}:${op_port} (public=${op_public_ip})"
    wait_for_ssh "$ssh_private_key" "$ssh_user" "$op_private_ip" "$operator_proxy_jump"
    run_with_retry "starting operator daemon op${op_index}" 3 10 \
      ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" "bash -lc $(printf '%q' "$start_operator_script")"
  done

  local coordinator_workdir completion_report
  coordinator_workdir="$remote_workdir/dkg-distributed/coordinator"
  completion_report="$coordinator_workdir/reports/test-completiton.json"
  local runner_execute_ceremony_script
  runner_execute_ceremony_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_NETWORK_MODE="vpc-private"
if [[ "${JUNO_DKG_ALLOW_INSECURE_NETWORK:-0}" == "1" ]]; then
  export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
fi
deploy/operators/dkg/coordinator.sh preflight --workdir "$coordinator_workdir" --release-tag "${release_tag}"
deploy/operators/dkg/coordinator.sh run --workdir "$coordinator_workdir" --release-tag "${release_tag}"
deploy/operators/dkg/test-completiton.sh run \
  --workdir "$coordinator_workdir" \
  --skip-resume \
  --release-tag "${release_tag}" \
  --output "$completion_report"
EOF
)"
  log "running distributed dkg ceremony from runner coordinator"
  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "bash -lc $(printf '%q' "$runner_execute_ceremony_script")"
  local completion_ufvk completion_juno_shielded_address
  completion_ufvk="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
      "jq -r '.ufvk // empty' $(printf '%q' "$completion_report")"
  )"
  [[ -n "$completion_ufvk" ]] || die "distributed dkg completion report missing ufvk: $completion_report"
  DISTRIBUTED_COMPLETION_UFVK="$completion_ufvk"
  completion_juno_shielded_address="$(
    ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
      "jq -r '.juno_shielded_address // empty' $(printf '%q' "$completion_report")"
  )"
  [[ -n "$completion_juno_shielded_address" ]] || \
    die "distributed dkg completion report missing juno_shielded_address: $completion_report"
  DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA="$completion_juno_shielded_address"
  if ! derive_owallet_keys_from_ufvk "$ssh_private_key" "$ssh_user" "$runner_public_ip" "$remote_repo" "$completion_ufvk"; then
    die "distributed dkg completion report produced invalid owallet key derivation output"
  fi

  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"

    local operator_work_root
    operator_work_root="$remote_workdir/dkg-distributed/operators/op${op_index}"
    local backup_restore_script
    backup_restore_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_NETWORK_MODE="vpc-private"
if [[ "${JUNO_DKG_ALLOW_INSECURE_NETWORK:-0}" == "1" ]]; then
  export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
fi
op_root="$operator_work_root"
runtime_dir="\$op_root/runtime"
age_identity="\$op_root/backup/age-identity.txt"
age_payload="\$op_root/backup/age-recipient.json"
age_backup="\$op_root/exports/keypackage-backup.json"
backup_zip="\$op_root/backup-packages/dkg-backup.zip"
kms_receipt="\$op_root/exports/kms-export-receipt.json"

mkdir -p "\$op_root/backup" "\$op_root/exports" "\$op_root/backup-packages"
# Iterative --keep-infra runs must overwrite prior backup/receipt artifacts.
rm -f "\$age_backup" "\$backup_zip" "\$kms_receipt"

deploy/operators/dkg/operator-export-kms.sh age-recipient \
  --identity-file "\$age_identity" \
  --output "\$age_payload"

age_recipient="\$(jq -r '.age_recipient' "\$age_payload")"
deploy/operators/dkg/operator-export-kms.sh backup-age \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --age-recipient "\$age_recipient" \
  --out "\$age_backup" \
  --force

deploy/operators/dkg/backup-package.sh create \
  --workdir "\$runtime_dir" \
  --age-identity-file "\$age_identity" \
  --age-backup-file "\$age_backup" \
  --admin-config "\$runtime_dir/bundle/admin-config.json" \
  --output "\$backup_zip" \
  --force

deploy/operators/dkg/operator.sh stop --workdir "\$runtime_dir" >/dev/null 2>&1 || true
rm -rf "\$runtime_dir"

deploy/operators/dkg/backup-package.sh restore \
  --package "\$backup_zip" \
  --workdir "\$runtime_dir" \
  --force

deploy/operators/dkg/operator.sh run \
  --bundle "\$runtime_dir/bundle" \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --daemon

deploy/operators/dkg/operator-export-kms.sh export \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --kms-key-id "${dkg_kms_key_arn}" \
  --s3-bucket "${dkg_s3_bucket}" \
  --s3-key-prefix "${dkg_s3_key_prefix}" \
  --s3-sse-kms-key-id "${dkg_kms_key_arn}" \
  --aws-region "${aws_region}" \
  --skip-aws-preflight >"\$kms_receipt"

[[ -x "\$runtime_dir/bin/dkg-admin" ]] || {
  echo "spendauth signer binary is missing from operator runtime: \$runtime_dir/bin/dkg-admin" >&2
  exit 1
}
printf '%s\n' '${completion_ufvk}' >"\$runtime_dir/ufvk.txt"
chmod 0600 "\$runtime_dir/ufvk.txt"
sudo mkdir -p /var/lib/intents-juno
sudo rm -rf /var/lib/intents-juno/operator-runtime
sudo ln -sfn "\$runtime_dir" /var/lib/intents-juno/operator-runtime
sudo chown -h ubuntu:ubuntu /var/lib/intents-juno/operator-runtime
echo "tss-host restart deferred until hydrator config has been staged"

deploy/operators/dkg/operator.sh status --workdir "\$runtime_dir" >"\$op_root/status.json"
EOF
)"

    log "running backup/restore verification on operator host op${op_index} via runner bastion ${runner_public_ip} -> ${op_private_ip} (public=${op_public_ip})"
    ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" "bash -lc $(printf '%q' "$backup_restore_script")"
  done

  local operators_json
  operators_json='[]'
  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    op_port=$((operator_base_port + op_index - 1))

    local operator_id status_json
    operator_id="$(
      ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
        "jq -r '.operator_id // empty' $(printf '%q' "$remote_workdir/dkg-distributed/operators/op${op_index}/operator-meta.json")"
    )"
    [[ -n "$operator_id" ]] || die "missing operator id for op${op_index}"

    status_json="$(
      ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" \
        "cat $(printf '%q' "$remote_workdir/dkg-distributed/operators/op${op_index}/status.json")"
    )"
    if [[ "$(printf '%s' "$status_json" | jq -r '.running')" != "true" ]]; then
      die "restored distributed operator is not running: op${op_index}"
    fi

    local op_json
    op_json="$(jq -n \
      --argjson index "$op_index" \
      --arg operator_id "$operator_id" \
      --arg operator_key_file "$remote_workdir/dkg-distributed/operators/op${op_index}/operator.key" \
      --arg registration_file "$remote_workdir/dkg-distributed/operators/op${op_index}/registration.json" \
      --arg endpoint "https://${op_private_ip}:${op_port}" \
      --arg runtime_dir "$remote_workdir/dkg-distributed/operators/op${op_index}/runtime" \
      --arg backup_package "$remote_workdir/dkg-distributed/operators/op${op_index}/backup-packages/dkg-backup.zip" \
      --arg kms_receipt "$remote_workdir/dkg-distributed/operators/op${op_index}/exports/kms-export-receipt.json" \
      --argjson status "$status_json" \
      '{
        index: $index,
        operator_id: $operator_id,
        operator_key_file: $operator_key_file,
        registration_file: $registration_file,
        endpoint: $endpoint,
        runtime_dir: $runtime_dir,
        backup_package: $backup_package,
        kms_receipt: $kms_receipt,
        status: $status
      }')"
    operators_json="$(jq --argjson op "$op_json" '. + [$op]' <<<"$operators_json")"
  done

  [[ -n "$shared_postgres_dsn" ]] || die "shared checkpoint service config missing postgres dsn"
  [[ -n "$shared_kafka_brokers" ]] || die "shared checkpoint service config missing kafka brokers"
  [[ -n "$shared_ipfs_api_url" ]] || die "shared checkpoint service config missing ipfs api url"
  [[ -n "$checkpoint_blob_bucket" ]] || die "shared checkpoint service config missing blob bucket"
  [[ -n "$checkpoint_blob_prefix" ]] || die "shared checkpoint service config missing blob prefix"

  local checkpoint_operators_csv
  checkpoint_operators_csv="$(jq -r 'map(.operator_id) | join(",")' <<<"$operators_json")"
  [[ -n "$checkpoint_operators_csv" ]] || die "failed to derive checkpoint operator set for operator stack config"

  local configure_operator_stack_services_script
  configure_operator_stack_services_script="$(cat <<EOF
set -euo pipefail
stack_env_file="/etc/intents-juno/operator-stack.env"
hydrator_env_file="/etc/intents-juno/operator-stack-hydrator.env"
default_config_json_path="/etc/intents-juno/operator-stack-config.json"
config_json_path="\$default_config_json_path"

[[ -s "\$stack_env_file" ]] || {
  echo "operator stack env is missing: \$stack_env_file" >&2
  exit 1
}

read_env_value() {
  local key="\$1"
  awk -v key="\$key" -F= '
    \$1 == key {
      print substr(\$0, index(\$0, "=") + 1)
      found = 1
      exit
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "\$stack_env_file"
}

normalize_pcr() {
  local value="\${1:-}"
  value="\${value#0x}"
  printf '%s' "\${value,,}"
}

set_env() {
  local tmp_file="\$1"
  local key="\$2"
  local value="\$3"
  local tmp_next
  tmp_next="\$(mktemp)"
  grep -v "^\${key}=" "\$tmp_file" >"\$tmp_next" || true
  printf '%s=%s\n' "\$key" "\$value" >>"\$tmp_next"
  mv "\$tmp_next" "\$tmp_file"
}

if [[ -f "\$hydrator_env_file" ]]; then
  configured_json_path="\$(sudo awk -F= '/^OPERATOR_STACK_CONFIG_JSON_PATH=/{print substr(\$0, index(\$0, "=")+1); exit}' "\$hydrator_env_file")"
  if [[ -n "\$configured_json_path" ]]; then
    config_json_path="\$configured_json_path"
  fi
fi

stack_runtime_mode="\$(read_env_value TSS_SIGNER_RUNTIME_MODE 2>/dev/null || printf 'nitro-enclave')"
stack_runtime_mode="\${stack_runtime_mode,,}"
[[ -n "\$stack_runtime_mode" ]] || stack_runtime_mode="nitro-enclave"

tss_nitro_expected_pcr0="\$(normalize_pcr "\$(read_env_value TSS_NITRO_EXPECTED_PCR0 2>/dev/null || true)")"
tss_nitro_expected_pcr1="\$(normalize_pcr "\$(read_env_value TSS_NITRO_EXPECTED_PCR1 2>/dev/null || true)")"
tss_nitro_expected_pcr2="\$(normalize_pcr "\$(read_env_value TSS_NITRO_EXPECTED_PCR2 2>/dev/null || true)")"
tss_signer_runtime_mode="\$stack_runtime_mode"

nitro_runtime_ready="true"
[[ -x "/var/lib/intents-juno/operator-runtime/bin/dkg-attested-signer" ]] || nitro_runtime_ready="false"
[[ -s "/var/lib/intents-juno/operator-runtime/enclave/spendauth-signer.eif" ]] || nitro_runtime_ready="false"
[[ -s "/var/lib/intents-juno/operator-runtime/attestation/spendauth-attestation.json" ]] || nitro_runtime_ready="false"
[[ "\$tss_nitro_expected_pcr0" =~ ^[0-9a-f]{96}$ ]] || nitro_runtime_ready="false"
[[ "\$tss_nitro_expected_pcr1" =~ ^[0-9a-f]{96}$ ]] || nitro_runtime_ready="false"
[[ "\$tss_nitro_expected_pcr2" =~ ^[0-9a-f]{96}$ ]] || nitro_runtime_ready="false"

case "\$stack_runtime_mode" in
  nitro-enclave)
    if [[ "\$nitro_runtime_ready" != "true" ]]; then
      tss_signer_runtime_mode="host-process"
      echo "nitro signer artifacts or PCR expectations unavailable; forcing TSS_SIGNER_RUNTIME_MODE=host-process for e2e orchestration"
    fi
    ;;
  host-process)
    tss_signer_runtime_mode="host-process"
    ;;
  *)
    echo "unsupported TSS_SIGNER_RUNTIME_MODE in operator stack env: \$stack_runtime_mode" >&2
    exit 1
    ;;
esac

if [[ "\$tss_signer_runtime_mode" == "host-process" ]]; then
  [[ -x "/var/lib/intents-juno/operator-runtime/bin/dkg-admin" ]] || {
    echo "host-process tss signer requires /var/lib/intents-juno/operator-runtime/bin/dkg-admin executable" >&2
    exit 1
  }
fi

tmp_env="\$(mktemp)"
sudo cp "\$stack_env_file" "\$tmp_env"
sudo chown "\$(id -u):\$(id -g)" "\$tmp_env"
chmod 600 "\$tmp_env"
set_env "\$tmp_env" TSS_SIGNER_RUNTIME_MODE "\$tss_signer_runtime_mode"
sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno
sudo install -m 0640 -o root -g ubuntu "\$tmp_env" "\$stack_env_file"
rm -f "\$tmp_env"

tmp_json="\$(mktemp)"
if [[ "\$tss_signer_runtime_mode" == "nitro-enclave" ]]; then
  jq -n \
    --arg checkpoint_postgres_dsn "$shared_postgres_dsn" \
    --arg checkpoint_kafka_brokers "$shared_kafka_brokers" \
    --arg checkpoint_ipfs_api_url "$shared_ipfs_api_url" \
    --arg checkpoint_blob_bucket "$checkpoint_blob_bucket" \
    --arg checkpoint_blob_prefix "$checkpoint_blob_prefix" \
    --arg checkpoint_operators "$checkpoint_operators_csv" \
    --arg checkpoint_threshold "$threshold" \
    --arg tss_nitro_expected_pcr0 "\$tss_nitro_expected_pcr0" \
    --arg tss_nitro_expected_pcr1 "\$tss_nitro_expected_pcr1" \
    --arg tss_nitro_expected_pcr2 "\$tss_nitro_expected_pcr2" \
    '{
      CHECKPOINT_POSTGRES_DSN: \$checkpoint_postgres_dsn,
      CHECKPOINT_KAFKA_BROKERS: \$checkpoint_kafka_brokers,
      CHECKPOINT_IPFS_API_URL: \$checkpoint_ipfs_api_url,
      CHECKPOINT_BLOB_BUCKET: \$checkpoint_blob_bucket,
      CHECKPOINT_BLOB_PREFIX: \$checkpoint_blob_prefix,
      CHECKPOINT_OPERATORS: \$checkpoint_operators,
      CHECKPOINT_THRESHOLD: \$checkpoint_threshold,
      CHECKPOINT_SIGNATURE_TOPIC: "checkpoints.signatures.v1",
      CHECKPOINT_PACKAGE_TOPIC: "checkpoints.packages.v1",
      JUNO_QUEUE_KAFKA_TLS: "true",
      TSS_NITRO_EXPECTED_PCR0: \$tss_nitro_expected_pcr0,
      TSS_NITRO_EXPECTED_PCR1: \$tss_nitro_expected_pcr1,
      TSS_NITRO_EXPECTED_PCR2: \$tss_nitro_expected_pcr2
    }' >"\$tmp_json"
else
  jq -n \
    --arg checkpoint_postgres_dsn "$shared_postgres_dsn" \
    --arg checkpoint_kafka_brokers "$shared_kafka_brokers" \
    --arg checkpoint_ipfs_api_url "$shared_ipfs_api_url" \
    --arg checkpoint_blob_bucket "$checkpoint_blob_bucket" \
    --arg checkpoint_blob_prefix "$checkpoint_blob_prefix" \
    --arg checkpoint_operators "$checkpoint_operators_csv" \
    --arg checkpoint_threshold "$threshold" \
    '{
      CHECKPOINT_POSTGRES_DSN: \$checkpoint_postgres_dsn,
      CHECKPOINT_KAFKA_BROKERS: \$checkpoint_kafka_brokers,
      CHECKPOINT_IPFS_API_URL: \$checkpoint_ipfs_api_url,
      CHECKPOINT_BLOB_BUCKET: \$checkpoint_blob_bucket,
      CHECKPOINT_BLOB_PREFIX: \$checkpoint_blob_prefix,
      CHECKPOINT_OPERATORS: \$checkpoint_operators,
      CHECKPOINT_THRESHOLD: \$checkpoint_threshold,
      CHECKPOINT_SIGNATURE_TOPIC: "checkpoints.signatures.v1",
      CHECKPOINT_PACKAGE_TOPIC: "checkpoints.packages.v1",
      JUNO_QUEUE_KAFKA_TLS: "true"
    }' >"\$tmp_json"
fi
sudo install -d -m 0750 -o root -g ubuntu "\$(dirname "\$config_json_path")"
sudo install -m 0640 -o root -g ubuntu "\$tmp_json" "\$config_json_path"
rm -f "\$tmp_json"

echo "staged hydrator config at \$config_json_path with TSS_SIGNER_RUNTIME_MODE=\$tss_signer_runtime_mode"

sudo systemctl daemon-reload
sudo systemctl restart intents-juno-config-hydrator.service
if ! sudo systemctl is-active --quiet intents-juno-config-hydrator.service; then
  echo "operator stack config hydrator failed after staged config update" >&2
  sudo systemctl status intents-juno-config-hydrator.service --no-pager || true
  exit 1
fi
if [[ ! -s "\$stack_env_file" ]]; then
  echo "operator stack env missing after hydrator update: \$stack_env_file" >&2
  exit 1
fi
sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno
sudo chgrp ubuntu "\$stack_env_file"
sudo chmod 0640 "\$stack_env_file"

sudo systemctl restart tss-host.service
if ! sudo systemctl is-active --quiet tss-host.service; then
  echo "tss-host failed to start with hydrated runtime config" >&2
  sudo systemctl status tss-host.service --no-pager || true
  exit 1
fi

echo "checkpoint-signer/checkpoint-aggregator restart deferred until bridge config is staged by remote e2e"
EOF
)"

  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    log "staging hydrator config and restarting operator stack services on op${op_index} via runner bastion ${runner_public_ip} -> ${op_private_ip} (public=${op_public_ip})"
    ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" "bash -lc $(printf '%q' "$configure_operator_stack_services_script")"
  done

  ensure_dir "$(dirname "$dkg_summary_local_path")"
  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg workdir "$remote_workdir/dkg-distributed" \
    --arg coordinator_workdir "$coordinator_workdir" \
    --arg completion_report "$completion_report" \
    --arg network "testnet" \
    --arg kms_key_arn "$dkg_kms_key_arn" \
    --arg kms_s3_bucket "$dkg_s3_bucket" \
    --arg kms_s3_key_prefix "$dkg_s3_key_prefix" \
    --argjson operator_count "$operator_count" \
    --argjson threshold "$threshold" \
    --argjson operators "$operators_json" \
    '{
      summary_version: 1,
      generated_at: $generated_at,
      workdir: $workdir,
      coordinator_workdir: $coordinator_workdir,
      completion_report: $completion_report,
      network: $network,
      operator_count: $operator_count,
      threshold: $threshold,
      dkg_secrets: {
        kms_key_arn: $kms_key_arn,
        s3_bucket: $kms_s3_bucket,
        s3_key_prefix: $kms_s3_key_prefix
      },
      operators: $operators
    }' >"$dkg_summary_local_path"

  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "mkdir -p $(printf '%q' "$(dirname "$dkg_summary_remote_path")")"
  scp "${ssh_opts[@]}" "$dkg_summary_local_path" "$ssh_user@$runner_public_ip:$dkg_summary_remote_path"
  sanitize_dkg_summary_file "$dkg_summary_local_path"
  rm -rf "$staged_bundle_dir"
}

command_cleanup() {
  shift || true

  local workdir="$REPO_ROOT/tmp/aws-live-e2e"
  local terraform_dir="$REPO_ROOT/deploy/shared/terraform/live-e2e"
  local aws_profile=""
  local aws_region=""
  local aws_dr_region=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --terraform-dir)
        [[ $# -ge 2 ]] || die "missing value for --terraform-dir"
        terraform_dir="$2"
        shift 2
        ;;
      --aws-profile)
        [[ $# -ge 2 ]] || die "missing value for --aws-profile"
        aws_profile="$2"
        shift 2
        ;;
      --aws-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-region"
        aws_region="$2"
        shift 2
        ;;
      --aws-dr-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-dr-region"
        aws_dr_region="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for cleanup: $1"
        ;;
    esac
  done

  local infra_dir state_file tfvars_file dr_state_file dr_tfvars_file
  infra_dir="$workdir/infra"
  state_file="$infra_dir/terraform.tfstate"
  tfvars_file="$infra_dir/terraform.tfvars.json"
  dr_state_file="$infra_dir/dr/terraform.tfstate"
  dr_tfvars_file="$infra_dir/dr/terraform.tfvars.json"

  if [[ ! -f "$tfvars_file" && ! -f "$dr_tfvars_file" ]]; then
    log "cleanup: primary/dr tfvars files not found; nothing to destroy"
    return 0
  fi

  local primary_region_for_cleanup dr_region_for_cleanup
  primary_region_for_cleanup="$aws_region"
  dr_region_for_cleanup="$aws_dr_region"
  if [[ -z "$primary_region_for_cleanup" && -f "$tfvars_file" ]]; then
    primary_region_for_cleanup="$(jq -r '.aws_region // empty' "$tfvars_file")"
  fi
  if [[ -z "$dr_region_for_cleanup" && -f "$dr_tfvars_file" ]]; then
    dr_region_for_cleanup="$(jq -r '.aws_region // empty' "$dr_tfvars_file")"
  fi

  local sp1_requestor_secret_arn=""
  local sp1_requestor_secret_arn_dr=""
  if [[ -f "$tfvars_file" ]]; then
    sp1_requestor_secret_arn="$(jq -r '.shared_sp1_requestor_secret_arn // empty' "$tfvars_file")"
  fi
  if [[ -f "$dr_tfvars_file" ]]; then
    sp1_requestor_secret_arn_dr="$(jq -r '.shared_sp1_requestor_secret_arn // empty' "$dr_tfvars_file")"
  fi

  if [[ -f "$dr_tfvars_file" ]]; then
    log "cleanup: destroying dr live e2e infrastructure"
    if ! terraform_destroy_live_e2e "$terraform_dir" "$dr_state_file" "$dr_tfvars_file" "$aws_profile" "$dr_region_for_cleanup"; then
      log "cleanup: dr destroy failed (manual cleanup may be required)"
    fi
  fi

  if [[ -f "$tfvars_file" ]]; then
    log "cleanup: destroying primary live e2e infrastructure"
    if ! terraform_destroy_live_e2e "$terraform_dir" "$state_file" "$tfvars_file" "$aws_profile" "$primary_region_for_cleanup"; then
      log "cleanup: primary destroy failed (manual cleanup may be required)"
    fi
  fi

  if [[ -n "$sp1_requestor_secret_arn_dr" ]]; then
    log "cleanup: deleting dr sp1 requestor secret"
    if ! delete_sp1_requestor_secret "$aws_profile" "$dr_region_for_cleanup" "$sp1_requestor_secret_arn_dr"; then
      log "cleanup: dr sp1 requestor secret delete failed or secret already removed"
    fi
  fi

  if [[ -n "$sp1_requestor_secret_arn" ]]; then
    log "cleanup: deleting primary sp1 requestor secret"
    if ! delete_sp1_requestor_secret "$aws_profile" "$primary_region_for_cleanup" "$sp1_requestor_secret_arn"; then
      log "cleanup: primary sp1 requestor secret delete failed or secret already removed"
    fi
  fi
}

command_run() {
  shift || true

  local workdir="$REPO_ROOT/tmp/aws-live-e2e"
  local terraform_dir="$REPO_ROOT/deploy/shared/terraform/live-e2e"
  local aws_region=""
  local aws_dr_region=""
  local aws_profile=""
  local aws_dr_readiness_checks_enabled="true"
  local aws_name_prefix="juno-live-e2e"
  local aws_instance_type="c7i.4xlarge"
  local runner_ami_id=""
  local aws_root_volume_gb="200"
  local operator_instance_count="5"
  local operator_instance_type="c7i.large"
  local operator_ami_id=""
  local operator_root_volume_gb="100"
  local shared_ami_id=""
  local operator_base_port="18443"
  local runner_associate_public_ip_address="true"
  local operator_associate_public_ip_address="true"
  local shared_ecs_assign_public_ip="false"
  local dkg_s3_key_prefix="dkg/keypackages"
  local dkg_release_tag="${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}"
  local operator_count_explicit="false"
  local operator_base_port_explicit="false"
  local ssh_allowed_cidr=""
  local base_funder_key_file=""
  local juno_funder_key_file=""
  local juno_funder_seed_file=""
  local juno_funder_source_address_file=""
  local juno_rpc_user_file=""
  local juno_rpc_pass_file=""
  local juno_scan_bearer_token_file=""
  local sp1_requestor_key_file=""
  local shared_sp1_requestor_secret_arn_override=""
  local shared_sp1_requestor_secret_arn_dr_override=""
  local shared_proof_services_image_override=""
  local shared_proof_services_image_release_tag="$DEFAULT_SHARED_PROOF_SERVICES_IMAGE_RELEASE_TAG"
  local shared_proof_services_image_release_tag_explicit="false"
  local shared_proof_services_image_resolved_from_release="false"
  local with_shared_services="true"
  local shared_postgres_user="postgres"
  local shared_postgres_db="intents_e2e"
  local shared_postgres_port="5432"
  local shared_kafka_port="9094"
  local relayer_runtime_mode="distributed"
  local relayer_runtime_mode_explicit="false"
  local distributed_relayer_runtime_explicit="false"
  local keep_infra="false"
  local skip_distributed_dkg="false"
  local reuse_bridge_summary_path=""
  local preflight_only="false"
  local status_json=""
  local -a e2e_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --terraform-dir)
        [[ $# -ge 2 ]] || die "missing value for --terraform-dir"
        terraform_dir="$2"
        shift 2
        ;;
      --aws-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-region"
        aws_region="$2"
        shift 2
        ;;
      --aws-dr-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-dr-region"
        aws_dr_region="$2"
        shift 2
        ;;
      --aws-profile)
        [[ $# -ge 2 ]] || die "missing value for --aws-profile"
        aws_profile="$2"
        shift 2
        ;;
      --enable-aws-dr-readiness-checks)
        aws_dr_readiness_checks_enabled="true"
        shift
        ;;
      --disable-aws-dr-readiness-checks)
        aws_dr_readiness_checks_enabled="false"
        shift
        ;;
      --aws-name-prefix)
        [[ $# -ge 2 ]] || die "missing value for --aws-name-prefix"
        aws_name_prefix="$2"
        shift 2
        ;;
      --aws-instance-type)
        [[ $# -ge 2 ]] || die "missing value for --aws-instance-type"
        aws_instance_type="$2"
        shift 2
        ;;
      --runner-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --runner-ami-id"
        runner_ami_id="$2"
        shift 2
        ;;
      --aws-root-volume-gb)
        [[ $# -ge 2 ]] || die "missing value for --aws-root-volume-gb"
        aws_root_volume_gb="$2"
        shift 2
        ;;
      --operator-instance-count)
        [[ $# -ge 2 ]] || die "missing value for --operator-instance-count"
        operator_instance_count="$2"
        operator_count_explicit="true"
        shift 2
        ;;
      --operator-instance-type)
        [[ $# -ge 2 ]] || die "missing value for --operator-instance-type"
        operator_instance_type="$2"
        shift 2
        ;;
      --operator-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --operator-ami-id"
        operator_ami_id="$2"
        shift 2
        ;;
      --operator-root-volume-gb)
        [[ $# -ge 2 ]] || die "missing value for --operator-root-volume-gb"
        operator_root_volume_gb="$2"
        shift 2
        ;;
      --shared-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --shared-ami-id"
        shared_ami_id="$2"
        shift 2
        ;;
      --operator-base-port)
        [[ $# -ge 2 ]] || die "missing value for --operator-base-port"
        operator_base_port="$2"
        operator_base_port_explicit="true"
        shift 2
        ;;
      --runner-associate-public-ip-address)
        [[ $# -ge 2 ]] || die "missing value for --runner-associate-public-ip-address"
        runner_associate_public_ip_address="$(normalize_bool_arg "--runner-associate-public-ip-address" "$2")"
        shift 2
        ;;
      --operator-associate-public-ip-address)
        [[ $# -ge 2 ]] || die "missing value for --operator-associate-public-ip-address"
        operator_associate_public_ip_address="$(normalize_bool_arg "--operator-associate-public-ip-address" "$2")"
        shift 2
        ;;
      --shared-ecs-assign-public-ip)
        [[ $# -ge 2 ]] || die "missing value for --shared-ecs-assign-public-ip"
        shared_ecs_assign_public_ip="$(normalize_bool_arg "--shared-ecs-assign-public-ip" "$2")"
        shift 2
        ;;
      --dkg-s3-key-prefix)
        [[ $# -ge 2 ]] || die "missing value for --dkg-s3-key-prefix"
        dkg_s3_key_prefix="$2"
        shift 2
        ;;
      --dkg-release-tag)
        [[ $# -ge 2 ]] || die "missing value for --dkg-release-tag"
        dkg_release_tag="$2"
        shift 2
        ;;
      --ssh-allowed-cidr)
        [[ $# -ge 2 ]] || die "missing value for --ssh-allowed-cidr"
        ssh_allowed_cidr="$2"
        shift 2
        ;;
      --base-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-funder-key-file"
        base_funder_key_file="$2"
        shift 2
        ;;
      --juno-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-funder-key-file"
        juno_funder_key_file="$2"
        shift 2
        ;;
      --juno-funder-seed-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-funder-seed-file"
        juno_funder_seed_file="$2"
        shift 2
        ;;
      --juno-funder-source-address-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-funder-source-address-file"
        juno_funder_source_address_file="$2"
        shift 2
        ;;
      --juno-rpc-user-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-user-file"
        juno_rpc_user_file="$2"
        shift 2
        ;;
      --juno-rpc-pass-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-pass-file"
        juno_rpc_pass_file="$2"
        shift 2
        ;;
      --juno-scan-bearer-token-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-scan-bearer-token-file"
        juno_scan_bearer_token_file="$2"
        shift 2
        ;;
      --sp1-requestor-key-file)
        [[ $# -ge 2 ]] || die "missing value for --sp1-requestor-key-file"
        sp1_requestor_key_file="$2"
        shift 2
        ;;
      --shared-sp1-requestor-secret-arn)
        [[ $# -ge 2 ]] || die "missing value for --shared-sp1-requestor-secret-arn"
        shared_sp1_requestor_secret_arn_override="$2"
        shift 2
        ;;
      --shared-sp1-requestor-secret-arn-dr)
        [[ $# -ge 2 ]] || die "missing value for --shared-sp1-requestor-secret-arn-dr"
        shared_sp1_requestor_secret_arn_dr_override="$2"
        shift 2
        ;;
      --shared-proof-services-image)
        [[ $# -ge 2 ]] || die "missing value for --shared-proof-services-image"
        shared_proof_services_image_override="$2"
        shift 2
        ;;
      --shared-proof-services-image-release-tag)
        [[ $# -ge 2 ]] || die "missing value for --shared-proof-services-image-release-tag"
        shared_proof_services_image_release_tag="$2"
        shared_proof_services_image_release_tag_explicit="true"
        shift 2
        ;;
      --without-shared-services)
        with_shared_services="false"
        shift
        ;;
      --shared-postgres-user)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-user"
        shared_postgres_user="$2"
        shift 2
        ;;
      --shared-postgres-db)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-db"
        shared_postgres_db="$2"
        shift 2
        ;;
      --shared-postgres-port)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-port"
        shared_postgres_port="$2"
        shift 2
        ;;
      --shared-kafka-port)
        [[ $# -ge 2 ]] || die "missing value for --shared-kafka-port"
        shared_kafka_port="$2"
        shift 2
        ;;
      --relayer-runtime-mode)
        [[ $# -ge 2 ]] || die "missing value for --relayer-runtime-mode"
        relayer_runtime_mode="$(lower "$2")"
        relayer_runtime_mode_explicit="true"
        shift 2
        ;;
      --distributed-relayer-runtime)
        relayer_runtime_mode="distributed"
        relayer_runtime_mode_explicit="true"
        distributed_relayer_runtime_explicit="true"
        shift
        ;;
      --keep-infra)
        keep_infra="true"
        shift
        ;;
      --skip-distributed-dkg)
        skip_distributed_dkg="true"
        shift
        ;;
      --reuse-bridge-summary-path)
        [[ $# -ge 2 ]] || die "missing value for --reuse-bridge-summary-path"
        reuse_bridge_summary_path="$2"
        shift 2
        ;;
      --preflight-only)
        preflight_only="true"
        shift
        ;;
      --status-json)
        [[ $# -ge 2 ]] || die "missing value for --status-json"
        status_json="$2"
        shift 2
        ;;
      --)
        shift
        e2e_args=("$@")
        break
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

  [[ -n "$aws_region" ]] || die "--aws-region is required"
  [[ -n "$base_funder_key_file" ]] || die "--base-funder-key-file is required"
  if [[ -z "$juno_funder_key_file" && -z "$juno_funder_seed_file" && -z "$juno_funder_source_address_file" ]]; then
    die "one of --juno-funder-key-file, --juno-funder-seed-file, or --juno-funder-source-address-file is required"
  fi
  [[ -n "$juno_rpc_user_file" ]] || die "--juno-rpc-user-file is required"
  [[ -n "$juno_rpc_pass_file" ]] || die "--juno-rpc-pass-file is required"
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  if [[ -n "$juno_funder_key_file" && ! -f "$juno_funder_key_file" ]]; then
    die "juno funder key file not found: $juno_funder_key_file"
  fi
  if [[ -n "$juno_funder_seed_file" && ! -f "$juno_funder_seed_file" ]]; then
    die "juno funder seed file not found: $juno_funder_seed_file"
  fi
  if [[ -n "$juno_funder_source_address_file" && ! -f "$juno_funder_source_address_file" ]]; then
    die "juno funder source address file not found: $juno_funder_source_address_file"
  fi
  [[ -f "$juno_rpc_user_file" ]] || die "juno rpc user file not found: $juno_rpc_user_file"
  [[ -f "$juno_rpc_pass_file" ]] || die "juno rpc pass file not found: $juno_rpc_pass_file"
  if [[ -n "$juno_scan_bearer_token_file" && ! -f "$juno_scan_bearer_token_file" ]]; then
    die "juno scan bearer token file not found: $juno_scan_bearer_token_file"
  fi
  [[ "$operator_instance_count" =~ ^[0-9]+$ ]] || die "--operator-instance-count must be numeric"
  [[ "$operator_root_volume_gb" =~ ^[0-9]+$ ]] || die "--operator-root-volume-gb must be numeric"
  [[ "$operator_base_port" =~ ^[0-9]+$ ]] || die "--operator-base-port must be numeric"
  (( operator_instance_count >= 1 )) || die "--operator-instance-count must be >= 1"
  (( operator_base_port >= 1 && operator_base_port <= 65535 )) || die "--operator-base-port must be in [1, 65535]"
  [[ "$shared_postgres_port" =~ ^[0-9]+$ ]] || die "--shared-postgres-port must be numeric"
  [[ "$shared_kafka_port" =~ ^[0-9]+$ ]] || die "--shared-kafka-port must be numeric"
  [[ -n "$shared_postgres_user" ]] || die "--shared-postgres-user must not be empty"
  [[ -n "$shared_postgres_db" ]] || die "--shared-postgres-db must not be empty"
  [[ -n "$dkg_s3_key_prefix" ]] || die "--dkg-s3-key-prefix must not be empty"
  case "$relayer_runtime_mode" in
    runner|distributed) ;;
    *) die "--relayer-runtime-mode must be runner or distributed" ;;
  esac
  if [[ "$with_shared_services" == "true" ]]; then
    if [[ "$aws_dr_readiness_checks_enabled" != "true" ]]; then
      die "shared services require DR readiness checks; remove --disable-aws-dr-readiness-checks"
    fi
    [[ -n "$aws_dr_region" ]] || die "--aws-dr-region is required when shared services are enabled"
    [[ "$aws_dr_region" != "$aws_region" ]] || die "--aws-dr-region must differ from --aws-region"
    if [[ -n "$shared_sp1_requestor_secret_arn_override" || -n "$shared_sp1_requestor_secret_arn_dr_override" ]]; then
      [[ -n "$shared_sp1_requestor_secret_arn_override" ]] || die "--shared-sp1-requestor-secret-arn-dr requires --shared-sp1-requestor-secret-arn"
      [[ -n "$shared_sp1_requestor_secret_arn_dr_override" ]] || die "--shared-sp1-requestor-secret-arn requires --shared-sp1-requestor-secret-arn-dr"
    fi
    if [[ -n "$shared_proof_services_image_override" ]]; then
      [[ "$shared_proof_services_image_override" =~ [[:space:]] ]] && die "--shared-proof-services-image must not contain whitespace"
      log "using provided shared proof services image override: $shared_proof_services_image_override"
    fi
    [[ -n "$shared_proof_services_image_release_tag" ]] || die "--shared-proof-services-image-release-tag must not be empty"
  elif [[ -n "$shared_proof_services_image_override" ]]; then
    die "--shared-proof-services-image requires shared services (omit --without-shared-services)"
  elif [[ "$shared_proof_services_image_release_tag_explicit" == "true" ]]; then
    die "--shared-proof-services-image-release-tag requires shared services (omit --without-shared-services)"
  fi
  if [[ -n "$runner_ami_id" && ! "$runner_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--runner-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -n "$operator_ami_id" && ! "$operator_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--operator-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -n "$shared_ami_id" && ! "$shared_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--shared-ami-id must look like an AMI id (ami-...)"
  fi
  [[ -n "$sp1_requestor_key_file" ]] || die "--sp1-requestor-key-file is required"
  [[ -f "$sp1_requestor_key_file" ]] || die "sp1 requestor key file not found: $sp1_requestor_key_file"
  if [[ "$skip_distributed_dkg" == "true" && "$keep_infra" != "true" ]]; then
    die "--skip-distributed-dkg requires --keep-infra"
  fi
  if [[ -n "$reuse_bridge_summary_path" && ! -f "$reuse_bridge_summary_path" ]]; then
    die "bridge summary reuse file not found: $reuse_bridge_summary_path"
  fi

  ensure_base_dependencies
  ensure_local_command terraform
  ensure_local_command aws
  ensure_local_command ssh
  ensure_local_command scp
  ensure_local_command git
  ensure_local_command ssh-keygen
  ensure_local_command openssl
  if [[ "$with_shared_services" == "true" && -z "$shared_proof_services_image_override" ]]; then
    ensure_local_command gh
  fi

  if [[ -z "$operator_ami_id" ]]; then
    operator_ami_id="$(resolve_latest_operator_stack_ami "$aws_profile" "$aws_region" || true)"
    [[ -n "$operator_ami_id" ]] || die "failed to resolve operator stack AMI; pass --operator-ami-id or build one via deploy/shared/runbooks/build-operator-stack-ami.sh"
  fi
  [[ "$operator_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]] || die "--operator-ami-id must look like an AMI id (ami-...)"
  if [[ "$with_shared_services" == "true" && -z "$shared_proof_services_image_override" ]]; then
    shared_proof_services_image_override="$(
      resolve_latest_shared_proof_services_image \
        "$shared_proof_services_image_release_tag" \
        "$aws_region" || true
    )"
    [[ -n "$shared_proof_services_image_override" ]] || die "failed to resolve shared proof services image from release tag '$shared_proof_services_image_release_tag'; run .github/workflows/release-shared-proof-services-image.yml or pass --shared-proof-services-image"
    shared_proof_services_image_resolved_from_release="true"
    log "defaulting --shared-proof-services-image to latest released image: $shared_proof_services_image_override (release_tag=$shared_proof_services_image_release_tag)"
  fi
  if [[ "$with_shared_services" == "true" && "$shared_proof_services_image_resolved_from_release" == "true" ]]; then
    log "using released shared proof services image: $shared_proof_services_image_override"
  fi

  ensure_dir "$workdir"
  workdir="$(cd "$workdir" && pwd)"
  terraform_dir="$(cd "$terraform_dir" && pwd)"

  local dkg_threshold="3"
  local forwarded_operator_count=""
  local forwarded_operator_base_port=""
  local forwarded_threshold=""
  local forwarded_relayer_runtime_mode=""
  local relayer_runtime_mode_forwarded="false"
  local forwarded_shared_postgres_dsn=""
  local forwarded_shared_kafka_brokers=""
  local forwarded_shared_ipfs_api_url=""
  if forwarded_operator_count="$(forwarded_arg_value "--operator-count" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_operator_count" =~ ^[0-9]+$ ]] || die "forwarded --operator-count must be numeric"
    if [[ "$operator_count_explicit" == "true" && "$forwarded_operator_count" != "$operator_instance_count" ]]; then
      die "forwarded --operator-count ($forwarded_operator_count) conflicts with --operator-instance-count ($operator_instance_count)"
    fi
    operator_instance_count="$forwarded_operator_count"
  fi
  if forwarded_operator_base_port="$(forwarded_arg_value "--base-port" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_operator_base_port" =~ ^[0-9]+$ ]] || die "forwarded --base-port must be numeric"
    if [[ "$operator_base_port_explicit" == "true" && "$forwarded_operator_base_port" != "$operator_base_port" ]]; then
      die "forwarded --base-port ($forwarded_operator_base_port) conflicts with --operator-base-port ($operator_base_port)"
    fi
    operator_base_port="$forwarded_operator_base_port"
  fi
  if forwarded_threshold="$(forwarded_arg_value "--threshold" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_threshold" =~ ^[0-9]+$ ]] || die "forwarded --threshold must be numeric"
    dkg_threshold="$forwarded_threshold"
  fi
  if forwarded_relayer_runtime_mode="$(forwarded_arg_value "--relayer-runtime-mode" "${e2e_args[@]}" 2>/dev/null)"; then
    forwarded_relayer_runtime_mode="$(lower "$forwarded_relayer_runtime_mode")"
    case "$forwarded_relayer_runtime_mode" in
      runner|distributed) ;;
      *) die "forwarded --relayer-runtime-mode must be runner or distributed" ;;
    esac
    if [[ "$relayer_runtime_mode_explicit" == "true" && "$forwarded_relayer_runtime_mode" != "$relayer_runtime_mode" ]]; then
      die "forwarded --relayer-runtime-mode ($forwarded_relayer_runtime_mode) conflicts with --relayer-runtime-mode ($relayer_runtime_mode)"
    fi
    relayer_runtime_mode="$forwarded_relayer_runtime_mode"
    relayer_runtime_mode_forwarded="true"
  fi
  if forwarded_shared_postgres_dsn="$(forwarded_arg_value "--shared-postgres-dsn" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ -n "$forwarded_shared_postgres_dsn" ]] || die "forwarded --shared-postgres-dsn must not be empty"
  fi
  if forwarded_shared_kafka_brokers="$(forwarded_arg_value "--shared-kafka-brokers" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ -n "$forwarded_shared_kafka_brokers" ]] || die "forwarded --shared-kafka-brokers must not be empty"
  fi
  if forwarded_shared_ipfs_api_url="$(forwarded_arg_value "--shared-ipfs-api-url" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ -n "$forwarded_shared_ipfs_api_url" ]] || die "forwarded --shared-ipfs-api-url must not be empty"
  fi
  if [[ "$with_shared_services" != "true" ]]; then
    if [[ -z "$forwarded_shared_postgres_dsn" || -z "$forwarded_shared_kafka_brokers" || -z "$forwarded_shared_ipfs_api_url" ]]; then
      die "--without-shared-services requires forwarded --shared-postgres-dsn, --shared-kafka-brokers, and --shared-ipfs-api-url after '--'"
    fi
  fi
  if [[ "$distributed_relayer_runtime_explicit" == "true" && "$relayer_runtime_mode" != "distributed" ]]; then
    die "--distributed-relayer-runtime requires relayer runtime mode distributed"
  fi
  (( dkg_threshold >= 2 )) || die "distributed dkg threshold must be >= 2"
  (( dkg_threshold <= operator_instance_count )) || die "distributed dkg threshold must be <= operator instance count"

  if [[ "$with_shared_services" == "true" ]]; then
    log "shared services are enabled; validating dr readiness"
    validate_shared_services_dr_readiness "$aws_profile" "$aws_region" "$aws_dr_region"
  elif [[ -n "$aws_dr_region" && "$aws_dr_readiness_checks_enabled" == "true" ]]; then
    log "shared services disabled; skipping dr readiness checks for aws-dr-region=$aws_dr_region"
  fi

  if [[ "$preflight_only" == "true" ]]; then
    log "running preflight hard-block checks"
    local required_forwarded_flag
    local -a required_forwarded_flags=(
      "--base-rpc-url"
      "--base-chain-id"
      "--bridge-verifier-address"
      "--bridge-deposit-image-id"
      "--bridge-withdraw-image-id"
      "--sp1-rpc-url"
      "--sp1-deposit-program-url"
      "--sp1-withdraw-program-url"
      "--sp1-max-price-per-pgu"
      "--sp1-deposit-pgu-estimate"
      "--sp1-withdraw-pgu-estimate"
      "--sp1-groth16-base-fee-wei"
    )
    for required_forwarded_flag in "${required_forwarded_flags[@]}"; do
      forwarded_arg_value "$required_forwarded_flag" "${e2e_args[@]}" >/dev/null 2>&1 || \
        die "preflight missing required forwarded argument after '--': $required_forwarded_flag"
    done

    run_preflight_aws_reachability_probes "$aws_profile" "$aws_region" "$with_shared_services"

    if [[ "$skip_distributed_dkg" == "true" ]]; then
      local resume_tfvars_file resume_state_file
      resume_tfvars_file="$workdir/infra/terraform.tfvars.json"
      resume_state_file="$workdir/infra/terraform.tfstate"
      [[ -f "$resume_tfvars_file" ]] || die "preflight resume validation failed: missing terraform tfvars for --skip-distributed-dkg ($resume_tfvars_file)"
      [[ -f "$resume_state_file" ]] || die "preflight resume validation failed: missing terraform state for --skip-distributed-dkg ($resume_state_file)"
    fi

    local preflight_sp1_rpc_url preflight_sp1_max_price_per_pgu preflight_sp1_deposit_pgu_estimate
    local preflight_sp1_withdraw_pgu_estimate preflight_sp1_groth16_base_fee_wei
    preflight_sp1_rpc_url="$(forwarded_arg_value "--sp1-rpc-url" "${e2e_args[@]}")"
    preflight_sp1_max_price_per_pgu="$(forwarded_arg_value "--sp1-max-price-per-pgu" "${e2e_args[@]}")"
    preflight_sp1_deposit_pgu_estimate="$(forwarded_arg_value "--sp1-deposit-pgu-estimate" "${e2e_args[@]}")"
    preflight_sp1_withdraw_pgu_estimate="$(forwarded_arg_value "--sp1-withdraw-pgu-estimate" "${e2e_args[@]}")"
    preflight_sp1_groth16_base_fee_wei="$(forwarded_arg_value "--sp1-groth16-base-fee-wei" "${e2e_args[@]}")"
    [[ -n "$preflight_sp1_rpc_url" ]] || die "preflight missing forwarded --sp1-rpc-url"
    validate_sp1_credit_guardrail_preflight \
      "$sp1_requestor_key_file" \
      "$preflight_sp1_rpc_url" \
      "$preflight_sp1_max_price_per_pgu" \
      "$preflight_sp1_deposit_pgu_estimate" \
      "$preflight_sp1_withdraw_pgu_estimate" \
      "$preflight_sp1_groth16_base_fee_wei"

    local -a preflight_remote_args=(
      run
      --workdir "/home/ubuntu/testnet-e2e-live"
      --dkg-summary-path "/home/ubuntu/testnet-e2e-live/dkg-distributed/reports/dkg-summary-runtime.json"
      --base-funder-key-file ".ci/secrets/base-funder.key"
      --output "/home/ubuntu/testnet-e2e-live/reports/testnet-e2e-summary.json"
      --force
      "${e2e_args[@]}"
    )
    local preflight_remote_joined_args
    preflight_remote_joined_args="$(shell_join "${preflight_remote_args[@]}")"
    [[ -n "$preflight_remote_joined_args" ]] || die "preflight remote command assembly failed"

    run_preflight_script_tests
    if [[ -n "$status_json" ]]; then
      write_status_json \
        "$status_json" \
        "preflight" \
        "passed" \
        "preflight checks passed" \
        "" \
        "" \
        "null"
      log "preflight status json written: $status_json"
    fi
    log "preflight hard-block checks passed"
    return 0
  fi

  if [[ -z "$ssh_allowed_cidr" ]]; then
    local caller_ip
    caller_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '\r\n')"
    [[ "$caller_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "failed to detect caller IP"
    ssh_allowed_cidr="${caller_ip}/32"
  fi

  local infra_dir ssh_dir artifacts_dir
  infra_dir="$workdir/infra"
  ssh_dir="$workdir/ssh"
  artifacts_dir="$workdir/artifacts"
  ensure_dir "$infra_dir"
  ensure_dir "$ssh_dir"
  ensure_dir "$artifacts_dir"

  local ssh_key_private ssh_key_public
  ssh_key_private="$ssh_dir/id_ed25519"
  ssh_key_public="$ssh_dir/id_ed25519.pub"
  if [[ -s "$ssh_key_private" && -s "$ssh_key_public" ]]; then
    log "reusing existing ssh keypair from prior run: $ssh_key_private"
  else
    rm -f "$ssh_key_private"
    rm -f "$ssh_key_public"
    ssh-keygen -t ed25519 -N "" -f "$ssh_key_private" >/dev/null
  fi

  local tfvars_file state_file
  local dr_tfvars_file=""
  local dr_state_file=""
  tfvars_file="$infra_dir/terraform.tfvars.json"
  state_file="$infra_dir/terraform.tfstate"
  if [[ "$with_shared_services" == "true" ]]; then
    dr_tfvars_file="$infra_dir/dr/terraform.tfvars.json"
    dr_state_file="$infra_dir/dr/terraform.tfstate"
    ensure_dir "$(dirname "$dr_tfvars_file")"
  fi

  local existing_deployment_id=""
  local existing_shared_postgres_password=""
  local existing_sp1_requestor_secret_arn=""
  local existing_dr_deployment_id=""
  local existing_sp1_requestor_secret_arn_dr=""
  if [[ -f "$tfvars_file" ]]; then
    existing_deployment_id="$(jq -r '.deployment_id // empty' "$tfvars_file")"
    existing_shared_postgres_password="$(jq -r '.shared_postgres_password // empty' "$tfvars_file")"
    existing_sp1_requestor_secret_arn="$(jq -r '.shared_sp1_requestor_secret_arn // empty' "$tfvars_file")"
  fi
  if [[ "$with_shared_services" == "true" && -f "$dr_tfvars_file" ]]; then
    existing_dr_deployment_id="$(jq -r '.deployment_id // empty' "$dr_tfvars_file")"
    existing_sp1_requestor_secret_arn_dr="$(jq -r '.shared_sp1_requestor_secret_arn // empty' "$dr_tfvars_file")"
  fi

  local deployment_id
  local dr_deployment_id=""
  if [[ -n "$existing_deployment_id" ]]; then
    deployment_id="$existing_deployment_id"
    log "reusing deployment_id from existing tfvars: $deployment_id"
  else
    deployment_id="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
  fi
  if [[ "$with_shared_services" == "true" ]]; then
    if [[ -n "$existing_dr_deployment_id" ]]; then
      dr_deployment_id="$existing_dr_deployment_id"
      log "reusing dr deployment_id from existing tfvars: $dr_deployment_id"
    else
      dr_deployment_id="${deployment_id}-dr"
    fi
  fi

  local shared_postgres_password
  if [[ -n "$existing_shared_postgres_password" ]]; then
    shared_postgres_password="$existing_shared_postgres_password"
  else
    shared_postgres_password="$(openssl rand -hex 16)"
  fi
  local sp1_requestor_key_hex
  sp1_requestor_key_hex="$(trimmed_file_value "$sp1_requestor_key_file")"
  [[ -n "$sp1_requestor_key_hex" ]] || die "sp1 requestor key file is empty: $sp1_requestor_key_file"
  local sp1_requestor_secret_arn=""
  local sp1_requestor_secret_arn_dr=""
  local sp1_requestor_secret_created="false"
  local sp1_requestor_secret_dr_created="false"

  cleanup_terraform_dir="$terraform_dir"
  cleanup_aws_profile="$aws_profile"
  cleanup_primary_state_file="$state_file"
  cleanup_primary_tfvars_file="$tfvars_file"
  cleanup_primary_aws_region="$aws_region"
  cleanup_primary_sp1_requestor_secret_arn=""
  cleanup_dr_state_file="$dr_state_file"
  cleanup_dr_tfvars_file="$dr_tfvars_file"
  cleanup_dr_aws_region="$aws_dr_region"
  cleanup_dr_sp1_requestor_secret_arn=""
  cleanup_enabled="true"
  if [[ "$keep_infra" == "true" ]]; then
    cleanup_enabled="false"
    log "keep-infra enabled; cleanup trap disabled for all run phases"
  fi
  trap cleanup_trap EXIT

  if [[ "$with_shared_services" == "true" ]]; then
    local secret_name_prefix sp1_requestor_secret_name
    local sp1_requestor_secret_name_dr
    secret_name_prefix="$(printf '%s' "$aws_name_prefix" | tr -cs '[:alnum:]-' '-')"
    secret_name_prefix="${secret_name_prefix#-}"
    secret_name_prefix="${secret_name_prefix%-}"
    [[ -n "$secret_name_prefix" ]] || secret_name_prefix="juno-live-e2e"
    if [[ -n "$shared_sp1_requestor_secret_arn_override" ]]; then
      sp1_requestor_secret_arn="$shared_sp1_requestor_secret_arn_override"
      log "using provided sp1 requestor secret arn: $sp1_requestor_secret_arn"
    elif [[ -n "$existing_sp1_requestor_secret_arn" ]] && sp1_requestor_secret_exists "$aws_profile" "$aws_region" "$existing_sp1_requestor_secret_arn"; then
      sp1_requestor_secret_arn="$existing_sp1_requestor_secret_arn"
      log "reusing sp1 requestor secret: $sp1_requestor_secret_arn"
    else
      sp1_requestor_secret_name="${secret_name_prefix}-${deployment_id}-sp1-requestor-key"
      log "creating sp1 requestor secret"
      sp1_requestor_secret_arn="$(
        create_sp1_requestor_secret \
          "$aws_profile" \
          "$aws_region" \
          "$sp1_requestor_secret_name" \
          "$sp1_requestor_key_hex"
      )"
      [[ -n "$sp1_requestor_secret_arn" && "$sp1_requestor_secret_arn" != "None" ]] || die "failed to create sp1 requestor secret"
      sp1_requestor_secret_created="true"
    fi
    if [[ "$sp1_requestor_secret_created" == "true" ]]; then
      cleanup_primary_sp1_requestor_secret_arn="$sp1_requestor_secret_arn"
    fi

    if [[ -n "$shared_sp1_requestor_secret_arn_dr_override" ]]; then
      sp1_requestor_secret_arn_dr="$shared_sp1_requestor_secret_arn_dr_override"
      log "using provided dr sp1 requestor secret arn: $sp1_requestor_secret_arn_dr"
    elif [[ -n "$existing_sp1_requestor_secret_arn_dr" ]] && sp1_requestor_secret_exists "$aws_profile" "$aws_dr_region" "$existing_sp1_requestor_secret_arn_dr"; then
      sp1_requestor_secret_arn_dr="$existing_sp1_requestor_secret_arn_dr"
      log "reusing dr sp1 requestor secret: $sp1_requestor_secret_arn_dr"
    else
      sp1_requestor_secret_name_dr="${secret_name_prefix}-${dr_deployment_id}-sp1-requestor-key"
      log "creating dr sp1 requestor secret"
      sp1_requestor_secret_arn_dr="$(
        create_sp1_requestor_secret \
          "$aws_profile" \
          "$aws_dr_region" \
          "$sp1_requestor_secret_name_dr" \
          "$sp1_requestor_key_hex"
      )"
      [[ -n "$sp1_requestor_secret_arn_dr" && "$sp1_requestor_secret_arn_dr" != "None" ]] || die "failed to create dr sp1 requestor secret"
      sp1_requestor_secret_dr_created="true"
    fi
    if [[ "$sp1_requestor_secret_dr_created" == "true" ]]; then
      cleanup_dr_sp1_requestor_secret_arn="$sp1_requestor_secret_arn_dr"
    fi
  fi

  local provision_shared_services_json
  if [[ "$with_shared_services" == "true" ]]; then
    provision_shared_services_json="true"
  else
    provision_shared_services_json="false"
  fi
  local shared_proof_service_image
  shared_proof_service_image="$shared_proof_services_image_override"

  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$deployment_id" \
    --arg name_prefix "$aws_name_prefix" \
    --arg instance_type "$aws_instance_type" \
    --arg runner_ami_id "$runner_ami_id" \
    --argjson root_volume_size_gb "$aws_root_volume_gb" \
    --argjson operator_instance_count "$operator_instance_count" \
    --arg operator_instance_type "$operator_instance_type" \
    --arg operator_ami_id "$operator_ami_id" \
    --argjson operator_root_volume_size_gb "$operator_root_volume_gb" \
    --arg shared_ami_id "$shared_ami_id" \
    --argjson operator_base_port "$operator_base_port" \
    --arg allowed_ssh_cidr "$ssh_allowed_cidr" \
    --arg ssh_public_key "$(cat "$ssh_key_public")" \
    --argjson provision_shared_services "$provision_shared_services_json" \
    --arg shared_postgres_user "$shared_postgres_user" \
    --arg shared_postgres_password "$shared_postgres_password" \
    --arg shared_postgres_db "$shared_postgres_db" \
    --arg shared_proof_service_image "$shared_proof_service_image" \
    --arg shared_sp1_requestor_secret_arn "$sp1_requestor_secret_arn" \
    --argjson shared_postgres_port "$shared_postgres_port" \
    --argjson shared_kafka_port "$shared_kafka_port" \
    --argjson runner_associate_public_ip_address "$runner_associate_public_ip_address" \
    --argjson operator_associate_public_ip_address "$operator_associate_public_ip_address" \
    --argjson shared_ecs_assign_public_ip "$shared_ecs_assign_public_ip" \
    --arg dkg_s3_key_prefix "$dkg_s3_key_prefix" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      name_prefix: $name_prefix,
      instance_type: $instance_type,
      runner_ami_id: $runner_ami_id,
      root_volume_size_gb: $root_volume_size_gb,
      operator_instance_count: $operator_instance_count,
      operator_instance_type: $operator_instance_type,
      operator_ami_id: $operator_ami_id,
      operator_root_volume_size_gb: $operator_root_volume_size_gb,
      shared_ami_id: $shared_ami_id,
      operator_base_port: $operator_base_port,
      allowed_ssh_cidr: $allowed_ssh_cidr,
      ssh_public_key: $ssh_public_key,
      provision_shared_services: $provision_shared_services,
      shared_postgres_user: $shared_postgres_user,
      shared_postgres_password: $shared_postgres_password,
      shared_postgres_db: $shared_postgres_db,
      shared_proof_service_image: $shared_proof_service_image,
      shared_sp1_requestor_secret_arn: $shared_sp1_requestor_secret_arn,
      shared_postgres_port: $shared_postgres_port,
      shared_kafka_port: $shared_kafka_port,
      runner_associate_public_ip_address: $runner_associate_public_ip_address,
      operator_associate_public_ip_address: $operator_associate_public_ip_address,
      shared_ecs_assign_public_ip: $shared_ecs_assign_public_ip,
      dkg_s3_key_prefix: $dkg_s3_key_prefix
    }' >"$tfvars_file"

  if [[ "$with_shared_services" == "true" ]]; then
    local dr_runner_ami_id dr_operator_ami_id dr_shared_ami_id
    dr_runner_ami_id="$(resolve_dr_ami_id "$aws_profile" "$aws_dr_region" "runner" "$runner_ami_id")"
    dr_operator_ami_id="$(resolve_dr_ami_id "$aws_profile" "$aws_dr_region" "operator" "$operator_ami_id")"
    dr_shared_ami_id="$(resolve_dr_ami_id "$aws_profile" "$aws_dr_region" "shared" "$shared_ami_id")"

    jq \
      --arg aws_region "$aws_dr_region" \
      --arg deployment_id "$dr_deployment_id" \
      --arg shared_sp1_requestor_secret_arn "$sp1_requestor_secret_arn_dr" \
      --arg runner_ami_id "$dr_runner_ami_id" \
      --arg operator_ami_id "$dr_operator_ami_id" \
      --arg shared_ami_id "$dr_shared_ami_id" \
      '.aws_region = $aws_region
      | .deployment_id = $deployment_id
      | .shared_sp1_requestor_secret_arn = $shared_sp1_requestor_secret_arn
      | .runner_ami_id = $runner_ami_id
      | .operator_ami_id = $operator_ami_id
      | .shared_ami_id = $shared_ami_id' \
      "$tfvars_file" >"$dr_tfvars_file"
  fi

  log "provisioning AWS runner (deployment_id=$deployment_id)"
  terraform_apply_live_e2e "$terraform_dir" "$state_file" "$tfvars_file" "$aws_profile" "$aws_region"
  if [[ "$with_shared_services" == "true" ]]; then
    log "provisioning AWS dr stack (deployment_id=$dr_deployment_id)"
    terraform_apply_live_e2e "$terraform_dir" "$dr_state_file" "$dr_tfvars_file" "$aws_profile" "$aws_dr_region"
  fi

  local runner_public_ip runner_ssh_user
  terraform_env_args "$aws_profile" "$aws_region"
  runner_public_ip="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw runner_public_ip
  )"
  runner_ssh_user="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw runner_ssh_user
  )"
  if [[ -z "$runner_public_ip" || "$runner_public_ip" == "null" ]]; then
    die "terraform output runner_public_ip is empty (set --runner-associate-public-ip-address true or provide alternate runner access)"
  fi

  local shared_postgres_endpoint=""
  local shared_kafka_bootstrap_brokers=""
  local shared_ipfs_api_url=""
  local shared_ecs_cluster_arn=""
  local shared_proof_requestor_service_name=""
  local shared_proof_funder_service_name=""
  if [[ "$with_shared_services" == "true" ]]; then
    shared_postgres_endpoint="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_postgres_endpoint
    )"
    [[ -n "$shared_postgres_endpoint" && "$shared_postgres_endpoint" != "null" ]] || die "shared services were requested but terraform output shared_postgres_endpoint is empty"

    shared_kafka_bootstrap_brokers="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_kafka_bootstrap_brokers
    )"
    [[ -n "$shared_kafka_bootstrap_brokers" && "$shared_kafka_bootstrap_brokers" != "null" ]] || die "shared services were requested but terraform output shared_kafka_bootstrap_brokers is empty"

    shared_ipfs_api_url="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_ipfs_api_url
    )"
    [[ -n "$shared_ipfs_api_url" && "$shared_ipfs_api_url" != "null" ]] || die "shared services were requested but terraform output shared_ipfs_api_url is empty"

    shared_ecs_cluster_arn="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_ecs_cluster_arn
    )"
    [[ -n "$shared_ecs_cluster_arn" && "$shared_ecs_cluster_arn" != "null" ]] || die "shared services were requested but terraform output shared_ecs_cluster_arn is empty"

    shared_proof_requestor_service_name="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_proof_requestor_service_name
    )"
    [[ -n "$shared_proof_requestor_service_name" && "$shared_proof_requestor_service_name" != "null" ]] || die "shared services were requested but terraform output shared_proof_requestor_service_name is empty"

    shared_proof_funder_service_name="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_proof_funder_service_name
    )"
    [[ -n "$shared_proof_funder_service_name" && "$shared_proof_funder_service_name" != "null" ]] || die "shared services were requested but terraform output shared_proof_funder_service_name is empty"

    local shared_postgres_port_out
    shared_postgres_port_out="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_postgres_port
    )"
    if [[ -n "$shared_postgres_port_out" && "$shared_postgres_port_out" != "null" ]]; then
      shared_postgres_port="$shared_postgres_port_out"
    fi

    local shared_kafka_port_out
    shared_kafka_port_out="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_kafka_port
    )"
    if [[ -n "$shared_kafka_port_out" && "$shared_kafka_port_out" != "null" ]]; then
      shared_kafka_port="$shared_kafka_port_out"
    fi
  fi

  local operator_public_ips_json operator_private_ips_json
  operator_public_ips_json="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -json operator_public_ips
  )"
  operator_private_ips_json="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -json operator_private_ips
  )"

  local -a operator_public_ips=()
  local -a operator_private_ips=()
  mapfile -t operator_public_ips < <(jq -r '.[]' <<<"$operator_public_ips_json")
  mapfile -t operator_private_ips < <(jq -r '.[]' <<<"$operator_private_ips_json")
  (( ${#operator_public_ips[@]} == operator_instance_count )) || die "terraform operator_public_ips count mismatch: expected=$operator_instance_count got=${#operator_public_ips[@]}"
  (( ${#operator_private_ips[@]} == operator_instance_count )) || die "terraform operator_private_ips count mismatch: expected=$operator_instance_count got=${#operator_private_ips[@]}"

  local dkg_kms_key_arn dkg_s3_bucket dkg_s3_key_prefix_out
  dkg_kms_key_arn="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_kms_key_arn
  )"
  dkg_s3_bucket="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_s3_bucket
  )"
  dkg_s3_key_prefix_out="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_s3_key_prefix
  )"
  [[ -n "$dkg_kms_key_arn" && "$dkg_kms_key_arn" != "null" ]] || die "terraform output dkg_kms_key_arn is empty"
  [[ -n "$dkg_s3_bucket" && "$dkg_s3_bucket" != "null" ]] || die "terraform output dkg_s3_bucket is empty"
  [[ -n "$dkg_s3_key_prefix_out" && "$dkg_s3_key_prefix_out" != "null" ]] || die "terraform output dkg_s3_key_prefix is empty"

  wait_for_ssh "$ssh_key_private" "$runner_ssh_user" "$runner_public_ip"

  local repo_commit
  repo_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  if [[ "$with_shared_services" == "true" ]]; then
    rollout_shared_proof_services \
      "$aws_profile" \
      "$aws_region" \
      "$shared_ecs_cluster_arn" \
      "$shared_proof_requestor_service_name" \
      "$shared_proof_funder_service_name" \
      "0"
  fi

  log "preparing remote runner host"
  remote_prepare_runner "$ssh_key_private" "$runner_ssh_user" "$runner_public_ip" "$repo_commit"

  local remote_repo remote_workdir
  remote_repo="/home/${runner_ssh_user}/intents-juno"
  remote_workdir="/home/${runner_ssh_user}/testnet-e2e-live"

  local operator_public_ips_csv operator_private_ips_csv
  operator_public_ips_csv="$(IFS=,; printf '%s' "${operator_public_ips[*]}")"
  operator_private_ips_csv="$(IFS=,; printf '%s' "${operator_private_ips[*]}")"

  local dkg_summary_remote_path dkg_summary_local_path
  local legacy_dkg_summary_remote_path
  dkg_summary_remote_path="$remote_workdir/dkg-distributed/reports/dkg-summary-runtime.json"
  legacy_dkg_summary_remote_path="$remote_workdir/reports/dkg-summary.json"
  dkg_summary_local_path="$artifacts_dir/dkg-summary-distributed.json"
  local shared_postgres_dsn_for_operator=""
  local shared_kafka_brokers_for_operator=""
  local shared_ipfs_api_url_for_operator=""
  local checkpoint_blob_bucket_for_operator=""
  local checkpoint_blob_prefix_for_operator=""
  if [[ -n "$forwarded_shared_postgres_dsn" ]]; then
    shared_postgres_dsn_for_operator="$forwarded_shared_postgres_dsn"
  elif [[ "$with_shared_services" == "true" ]]; then
    shared_postgres_dsn_for_operator="postgres://${shared_postgres_user}:${shared_postgres_password}@${shared_postgres_endpoint}:${shared_postgres_port}/${shared_postgres_db}?sslmode=require"
  fi
  if [[ -n "$forwarded_shared_kafka_brokers" ]]; then
    shared_kafka_brokers_for_operator="$forwarded_shared_kafka_brokers"
  elif [[ "$with_shared_services" == "true" ]]; then
    shared_kafka_brokers_for_operator="$shared_kafka_bootstrap_brokers"
  fi
  if [[ -n "$forwarded_shared_ipfs_api_url" ]]; then
    shared_ipfs_api_url_for_operator="$forwarded_shared_ipfs_api_url"
  elif [[ "$with_shared_services" == "true" ]]; then
    shared_ipfs_api_url_for_operator="$shared_ipfs_api_url"
  fi
  if [[ -n "$shared_postgres_dsn_for_operator" || -n "$shared_kafka_brokers_for_operator" || -n "$shared_ipfs_api_url_for_operator" ]]; then
    [[ -n "$shared_postgres_dsn_for_operator" ]] || die "operator stack hydration requires shared postgres dsn (set --shared-postgres-dsn)"
    [[ -n "$shared_kafka_brokers_for_operator" ]] || die "operator stack hydration requires shared kafka brokers (set --shared-kafka-brokers)"
    [[ -n "$shared_ipfs_api_url_for_operator" ]] || die "operator stack hydration requires shared ipfs api url (set --shared-ipfs-api-url)"
    checkpoint_blob_bucket_for_operator="$dkg_s3_bucket"
    checkpoint_blob_prefix_for_operator="${dkg_s3_key_prefix_out%/}/checkpoint-packages"
  fi
  [[ -n "$shared_postgres_dsn_for_operator" ]] || die "operator stack hydration requires shared postgres dsn"
  [[ -n "$shared_kafka_brokers_for_operator" ]] || die "operator stack hydration requires shared kafka brokers"
  [[ -n "$shared_ipfs_api_url_for_operator" ]] || die "operator stack hydration requires shared ipfs api url"
  [[ -n "$checkpoint_blob_bucket_for_operator" ]] || die "operator stack hydration requires checkpoint blob bucket"
  [[ -n "$checkpoint_blob_prefix_for_operator" ]] || die "operator stack hydration requires checkpoint blob prefix"

  if [[ "$skip_distributed_dkg" == "true" ]]; then
    log "skipping distributed dkg ceremony and backup/restore setup; reusing existing runner artifacts"
    local resolved_dkg_summary_remote_path
    resolved_dkg_summary_remote_path="$dkg_summary_remote_path"
    if ! ssh -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$runner_ssh_user@$runner_public_ip" \
      "test -f $(printf '%q' "$resolved_dkg_summary_remote_path")"; then
      if ssh -i "$ssh_key_private" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -o TCPKeepAlive=yes \
        "$runner_ssh_user@$runner_public_ip" \
        "test -f $(printf '%q' "$legacy_dkg_summary_remote_path")"; then
        resolved_dkg_summary_remote_path="$legacy_dkg_summary_remote_path"
      else
        die "missing existing distributed dkg summary on runner: $dkg_summary_remote_path"
      fi
    fi
    dkg_summary_remote_path="$resolved_dkg_summary_remote_path"

    load_distributed_identity_from_existing_runner_state \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$remote_repo" \
      "$remote_workdir" \
      "$dkg_summary_remote_path"

    ensure_dir "$(dirname "$dkg_summary_local_path")"
    scp -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$runner_ssh_user@$runner_public_ip:$dkg_summary_remote_path" \
      "$dkg_summary_local_path"
    sanitize_dkg_summary_file "$dkg_summary_local_path"
  else
    run_distributed_dkg_backup_restore \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$remote_repo" \
      "$remote_workdir" \
      "$repo_commit" \
      "$operator_instance_count" \
      "$dkg_threshold" \
      "$operator_base_port" \
      "$dkg_release_tag" \
      "$dkg_summary_remote_path" \
      "$dkg_summary_local_path" \
      "$operator_public_ips_csv" \
      "$operator_private_ips_csv" \
      "$dkg_kms_key_arn" \
      "$dkg_s3_bucket" \
      "$dkg_s3_key_prefix_out" \
      "$aws_region" \
      "$shared_postgres_dsn_for_operator" \
      "$shared_kafka_brokers_for_operator" \
      "$shared_ipfs_api_url_for_operator" \
      "$checkpoint_blob_bucket_for_operator" \
      "$checkpoint_blob_prefix_for_operator"
  fi

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$base_funder_key_file" \
    "$remote_repo/.ci/secrets/base-funder.key"

  if [[ -n "$juno_funder_key_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$juno_funder_key_file" \
      "$remote_repo/.ci/secrets/juno-funder.key"
  fi

  if [[ -n "$juno_funder_seed_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$juno_funder_seed_file" \
      "$remote_repo/.ci/secrets/juno-funder.seed.txt"
  fi

  if [[ -n "$juno_funder_source_address_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$juno_funder_source_address_file" \
      "$remote_repo/.ci/secrets/juno-funder.ua"
  fi

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$juno_rpc_user_file" \
    "$remote_repo/.ci/secrets/juno-rpc-user.txt"

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$juno_rpc_pass_file" \
    "$remote_repo/.ci/secrets/juno-rpc-pass.txt"

  if [[ -n "$juno_scan_bearer_token_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$juno_scan_bearer_token_file" \
      "$remote_repo/.ci/secrets/juno-scan-bearer.txt"
  fi

  if [[ -n "$sp1_requestor_key_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$sp1_requestor_key_file" \
      "$remote_repo/.ci/secrets/sp1-requestor.key"
  fi

  if [[ -n "$reuse_bridge_summary_path" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$reuse_bridge_summary_path" \
      "$remote_repo/.ci/secrets/reuse-bridge-summary.json"
  fi

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$ssh_key_private" \
    "$remote_repo/.ci/secrets/operator-fleet-ssh.key"

  local witness_tss_ca_local_path
  local witness_tss_ca_remote_source_path=""
  local -a witness_tss_ca_remote_source_candidates=(
    "$remote_repo/.ci/secrets/witness-tss-ca.pem"
    "$remote_workdir/dkg-distributed/operators/op1/runtime/bundle/tls/ca.pem"
    "$remote_workdir/dkg/operators/op1/runtime/bundle/tls/ca.pem"
  )
  local witness_tss_ca_candidate_path
  for witness_tss_ca_candidate_path in "${witness_tss_ca_remote_source_candidates[@]}"; do
    if ssh -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$runner_ssh_user@$runner_public_ip" \
      "test -f $(printf '%q' "$witness_tss_ca_candidate_path")"; then
      witness_tss_ca_remote_source_path="$witness_tss_ca_candidate_path"
      break
    fi
  done

  witness_tss_ca_local_path="$(mktemp)"
  if [[ -n "$witness_tss_ca_remote_source_path" ]]; then
    log "using runner-local witness tss ca source path=$witness_tss_ca_remote_source_path"
    run_with_local_timeout 45 scp -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$runner_ssh_user@$runner_public_ip:$witness_tss_ca_remote_source_path" \
      "$witness_tss_ca_local_path" || die "failed to copy runner-local witness tss ca from $witness_tss_ca_remote_source_path"
  else
    log "runner-local witness tss ca path missing; falling back to operator host fetch"
    run_with_local_timeout 45 scp -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o "ProxyCommand=ssh -i $ssh_key_private -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -W %h:%p $runner_ssh_user@$runner_public_ip" \
      "$runner_ssh_user@${operator_private_ips[0]}:/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem" \
      "$witness_tss_ca_local_path" || die "failed to copy operator witness tss ca via proxy"
  fi
  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$witness_tss_ca_local_path" \
    "$remote_repo/.ci/secrets/witness-tss-ca.pem"
  rm -f "$witness_tss_ca_local_path"

  local witness_tunnel_scan_base_port="38080"
  local witness_tunnel_rpc_base_port="38232"
  local witness_tunnel_tss_base_port="39443"
  local witness_quorum_threshold="3"
  local -a witness_juno_scan_urls=()
  local -a witness_juno_rpc_urls=()
  local -a witness_tss_urls=()
  local -a witness_operator_labels=()
  local witness_idx witness_operator_private_ip
  for ((witness_idx = 0; witness_idx < ${#operator_private_ips[@]}; witness_idx++)); do
    witness_operator_private_ip="${operator_private_ips[$witness_idx]}"
    [[ -n "$witness_operator_private_ip" ]] || die "failed to resolve witness operator private ip for index=$witness_idx"
    witness_juno_scan_urls+=("http://127.0.0.1:$((witness_tunnel_scan_base_port + witness_idx))")
    witness_juno_rpc_urls+=("http://127.0.0.1:$((witness_tunnel_rpc_base_port + witness_idx))")
    witness_tss_urls+=("https://127.0.0.1:$((witness_tunnel_tss_base_port + witness_idx))")
    witness_operator_labels+=("op$((witness_idx + 1))@${witness_operator_private_ip}")
  done
  (( ${#witness_juno_scan_urls[@]} >= witness_quorum_threshold )) || \
    die "witness endpoint pool must satisfy quorum threshold: endpoints=${#witness_juno_scan_urls[@]} threshold=$witness_quorum_threshold"
  local witness_juno_scan_url witness_juno_rpc_url witness_tss_url
  witness_juno_scan_url="${witness_juno_scan_urls[0]}"
  witness_juno_rpc_url="${witness_juno_rpc_urls[0]}"
  witness_tss_url="${witness_tss_urls[0]}"
  local witness_juno_scan_urls_csv witness_juno_rpc_urls_csv witness_operator_labels_csv
  witness_juno_scan_urls_csv="$(IFS=,; printf '%s' "${witness_juno_scan_urls[*]}")"
  witness_juno_rpc_urls_csv="$(IFS=,; printf '%s' "${witness_juno_rpc_urls[*]}")"
  witness_operator_labels_csv="$(IFS=,; printf '%s' "${witness_operator_labels[*]}")"
  local witness_tunnel_private_ip_joined
  witness_tunnel_private_ip_joined="$(shell_join "${operator_private_ips[@]}")"

  local -a remote_args
  remote_args=(
    run
    --workdir "$remote_workdir"
    --dkg-summary-path "$dkg_summary_remote_path"
    --base-funder-key-file ".ci/secrets/base-funder.key"
    --output "$remote_workdir/reports/testnet-e2e-summary.json"
    --force
  )
  local bridge_summary_reuse_remote_path=""
  if [[ -n "$reuse_bridge_summary_path" ]]; then
    bridge_summary_reuse_remote_path=".ci/secrets/reuse-bridge-summary.json"
    remote_args+=("--existing-bridge-summary-path" ".ci/secrets/reuse-bridge-summary.json")
  elif [[ "$skip_distributed_dkg" == "true" ]]; then
    local remote_existing_bridge_summary_candidate
    remote_existing_bridge_summary_candidate="$remote_workdir/reports/base-bridge-summary.json"
    if ssh -i "$ssh_key_private" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=6 \
      -o TCPKeepAlive=yes \
      "$runner_ssh_user@$runner_public_ip" \
      "test -f $(printf '%q' "$remote_existing_bridge_summary_candidate")"; then
      bridge_summary_reuse_remote_path="$remote_existing_bridge_summary_candidate"
      remote_args+=("--existing-bridge-summary-path" "$remote_existing_bridge_summary_candidate")
    else
      log "no existing bridge summary found on runner; deploy bootstrap will run in resume mode"
    fi
  fi
  if [[ -n "$sp1_requestor_key_file" ]]; then
    remote_args+=(--sp1-requestor-key-file ".ci/secrets/sp1-requestor.key")
  fi
  if [[ -n "$aws_dr_region" ]]; then
    remote_args+=("--aws-dr-region" "$aws_dr_region")
  fi
  if [[ "$with_shared_services" == "true" ]]; then
    log "waiting for shared services connectivity from runner"
    wait_for_shared_connectivity_from_runner \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$shared_postgres_endpoint" \
      "$shared_postgres_port" \
      "$shared_kafka_bootstrap_brokers"

    local shared_postgres_dsn shared_kafka_brokers
    log "assembling shared service remote args"
    shared_postgres_dsn="postgres://${shared_postgres_user}:${shared_postgres_password}@${shared_postgres_endpoint}:${shared_postgres_port}/${shared_postgres_db}?sslmode=require"
    shared_kafka_brokers="$shared_kafka_bootstrap_brokers"
    remote_args+=(
      "--shared-postgres-dsn" "$shared_postgres_dsn"
      "--shared-kafka-brokers" "$shared_kafka_brokers"
      "--shared-ipfs-api-url" "$shared_ipfs_api_url"
      "--shared-ecs-cluster-arn" "$shared_ecs_cluster_arn"
      "--shared-proof-requestor-service-name" "$shared_proof_requestor_service_name"
      "--shared-proof-funder-service-name" "$shared_proof_funder_service_name"
    )
    log "shared service remote args assembled"
  fi
  if [[ "$relayer_runtime_mode" == "distributed" ]]; then
    [[ -n "$operator_private_ips_csv" ]] || die "distributed relayer runtime requires operator private host list"
    log "distributed relayer runtime enabled; forwarding operator fleet runtime args"
    if [[ "$relayer_runtime_mode_forwarded" != "true" ]]; then
      remote_args+=("--relayer-runtime-mode" "$relayer_runtime_mode")
    fi
    remote_args+=(
      "--relayer-runtime-operator-hosts" "$operator_private_ips_csv"
      "--relayer-runtime-operator-ssh-user" "$runner_ssh_user"
      "--relayer-runtime-operator-ssh-key-file" ".ci/secrets/operator-fleet-ssh.key"
    )
  fi
  if forwarded_arg_value "--runtime-mode" "${e2e_args[@]}" >/dev/null 2>&1; then
    die "withdraw coordinator mock runtime is forbidden in live e2e (do not pass --runtime-mode)"
  fi
  if forwarded_arg_value "--withdraw-coordinator-runtime-mode" "${e2e_args[@]}" >/dev/null 2>&1; then
    die "withdraw coordinator mock runtime is forbidden in live e2e (do not pass --withdraw-coordinator-runtime-mode)"
  fi
  if [[ -n "$bridge_summary_reuse_remote_path" ]] && forwarded_arg_value "--existing-bridge-summary-path" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --existing-bridge-summary-path with wrapper-managed reuse path"
  fi

  [[ "$DISTRIBUTED_SP1_DEPOSIT_OWALLET_IVK_HEX" =~ ^0x[0-9a-f]{128}$ ]] || \
    die "distributed dkg completion report produced invalid owallet key derivation output"
  [[ "$DISTRIBUTED_SP1_WITHDRAW_OWALLET_OVK_HEX" =~ ^0x[0-9a-f]{64}$ ]] || \
    die "distributed dkg completion report produced invalid owallet key derivation output"

  local forwarded_sp1_deposit_owallet_ivk_hex=""
  local forwarded_sp1_withdraw_owallet_ovk_hex=""
  local forwarded_sp1_witness_recipient_ua=""
  local forwarded_sp1_witness_recipient_ufvk=""
  forwarded_sp1_deposit_owallet_ivk_hex="$(forwarded_arg_value "--sp1-deposit-owallet-ivk-hex" "${e2e_args[@]}" || true)"
  forwarded_sp1_withdraw_owallet_ovk_hex="$(forwarded_arg_value "--sp1-withdraw-owallet-ovk-hex" "${e2e_args[@]}" || true)"
  forwarded_sp1_witness_recipient_ua="$(forwarded_arg_value "--sp1-witness-recipient-ua" "${e2e_args[@]}" || true)"
  forwarded_sp1_witness_recipient_ufvk="$(forwarded_arg_value "--sp1-witness-recipient-ufvk" "${e2e_args[@]}" || true)"

  if [[ -n "$forwarded_sp1_deposit_owallet_ivk_hex" ]]; then
    local normalized_forwarded_sp1_deposit_owallet_ivk_hex
    normalized_forwarded_sp1_deposit_owallet_ivk_hex="$(normalize_hex_prefixed_value "$forwarded_sp1_deposit_owallet_ivk_hex" || true)"
    if [[ ! "$normalized_forwarded_sp1_deposit_owallet_ivk_hex" =~ ^0x[0-9a-f]{128}$ ]]; then
      log "warning: ignoring invalid forwarded --sp1-deposit-owallet-ivk-hex; using distributed dkg ufvk-derived value"
    elif [[ "$normalized_forwarded_sp1_deposit_owallet_ivk_hex" != "$DISTRIBUTED_SP1_DEPOSIT_OWALLET_IVK_HEX" ]]; then
      log "warning: overriding forwarded --sp1-deposit-owallet-ivk-hex with distributed dkg ufvk-derived value"
    fi
  fi

  if [[ -n "$forwarded_sp1_withdraw_owallet_ovk_hex" ]]; then
    local normalized_forwarded_sp1_withdraw_owallet_ovk_hex
    normalized_forwarded_sp1_withdraw_owallet_ovk_hex="$(normalize_hex_prefixed_value "$forwarded_sp1_withdraw_owallet_ovk_hex" || true)"
    if [[ ! "$normalized_forwarded_sp1_withdraw_owallet_ovk_hex" =~ ^0x[0-9a-f]{64}$ ]]; then
      log "warning: ignoring invalid forwarded --sp1-withdraw-owallet-ovk-hex; using distributed dkg ufvk-derived value"
    elif [[ "$normalized_forwarded_sp1_withdraw_owallet_ovk_hex" != "$DISTRIBUTED_SP1_WITHDRAW_OWALLET_OVK_HEX" ]]; then
      log "warning: overriding forwarded --sp1-withdraw-owallet-ovk-hex with distributed dkg ufvk-derived value"
    fi
  fi
  if [[ -n "$forwarded_sp1_witness_recipient_ua" ]]; then
    if [[ "$forwarded_sp1_witness_recipient_ua" != "$DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA" ]]; then
      log "warning: overriding forwarded --sp1-witness-recipient-ua with distributed dkg completion juno_shielded_address"
    fi
  fi
  if [[ -n "$forwarded_sp1_witness_recipient_ufvk" ]]; then
    if [[ "$forwarded_sp1_witness_recipient_ufvk" != "$DISTRIBUTED_COMPLETION_UFVK" ]]; then
      log "warning: overriding forwarded --sp1-witness-recipient-ufvk with distributed dkg completion ufvk"
    fi
  fi

  log "using distributed dkg ufvk-derived owallet key material for sp1 guest witness inputs"
  remote_args+=(
    "--sp1-deposit-owallet-ivk-hex" "$DISTRIBUTED_SP1_DEPOSIT_OWALLET_IVK_HEX"
    "--sp1-withdraw-owallet-ovk-hex" "$DISTRIBUTED_SP1_WITHDRAW_OWALLET_OVK_HEX"
    "--sp1-witness-recipient-ua" "$DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA"
    "--sp1-witness-recipient-ufvk" "$DISTRIBUTED_COMPLETION_UFVK"
  )

  local -a sanitized_e2e_args=()
  local e2e_idx=0
  while (( e2e_idx < ${#e2e_args[@]} )); do
    case "${e2e_args[$e2e_idx]}" in
      --sp1-deposit-owallet-ivk-hex|--sp1-withdraw-owallet-ovk-hex|--sp1-witness-recipient-ua|--sp1-witness-recipient-ufvk|--existing-bridge-summary-path)
        (( e2e_idx + 1 < ${#e2e_args[@]} )) || die "forwarded argument missing value: ${e2e_args[$e2e_idx]}"
        e2e_idx=$((e2e_idx + 2))
        ;;
      *)
        sanitized_e2e_args+=("${e2e_args[$e2e_idx]}")
        e2e_idx=$((e2e_idx + 1))
        ;;
    esac
  done

  remote_args+=("${sanitized_e2e_args[@]}")
  if ! forwarded_arg_value "--sp1-input-s3-bucket" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "defaulting --sp1-input-s3-bucket to terraform dkg bucket output"
    remote_args+=("--sp1-input-s3-bucket" "$dkg_s3_bucket")
  fi
  if forwarded_arg_value "--sp1-witness-juno-scan-url" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-juno-scan-url with stack-derived witness tunnel endpoint"
  fi
  if forwarded_arg_value "--sp1-witness-juno-rpc-url" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-juno-rpc-url with stack-derived witness tunnel endpoint"
  fi
  if forwarded_arg_value "--sp1-witness-juno-scan-urls" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-juno-scan-urls with stack-derived witness tunnel endpoint pool"
  fi
  if forwarded_arg_value "--sp1-witness-juno-rpc-urls" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-juno-rpc-urls with stack-derived witness tunnel endpoint pool"
  fi
  if forwarded_arg_value "--sp1-witness-operator-labels" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-operator-labels with stack-derived witness operator labels"
  fi
  if forwarded_arg_value "--sp1-witness-quorum-threshold" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --sp1-witness-quorum-threshold with stack-derived witness quorum threshold"
  fi
  if forwarded_arg_value "--withdraw-coordinator-tss-url" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --withdraw-coordinator-tss-url with stack-derived witness tunnel endpoint"
  fi
  if forwarded_arg_value "--withdraw-coordinator-tss-server-ca-file" "${e2e_args[@]}" >/dev/null 2>&1; then
    log "overriding forwarded --withdraw-coordinator-tss-server-ca-file with stack-derived witness CA"
  fi
  remote_args+=(
    "--sp1-witness-juno-scan-url" "$witness_juno_scan_url"
    "--sp1-witness-juno-rpc-url" "$witness_juno_rpc_url"
    "--sp1-witness-juno-scan-urls" "$witness_juno_scan_urls_csv"
    "--sp1-witness-juno-rpc-urls" "$witness_juno_rpc_urls_csv"
    "--sp1-witness-operator-labels" "$witness_operator_labels_csv"
    "--sp1-witness-quorum-threshold" "$witness_quorum_threshold"
    "--withdraw-coordinator-tss-url" "$witness_tss_url"
    "--withdraw-coordinator-tss-server-ca-file" ".ci/secrets/witness-tss-ca.pem"
  )

  log "assembling remote e2e arguments"
  local remote_joined_args
  if ! remote_joined_args="$(shell_join "${remote_args[@]}")"; then
    die "failed to build remote command line"
  fi
  [[ -n "$remote_joined_args" ]] || die "remote command line is empty"
  log "remote e2e arguments assembled"

  local remote_run_script
  if ! remote_run_script=$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export PATH="\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$HOME/.local/bin:\$PATH"
export JUNO_DKG_NETWORK_MODE="vpc-private"
if [[ -f .ci/secrets/juno-funder.key ]]; then
  export JUNO_FUNDER_PRIVATE_KEY_HEX="\$(tr -d '\r\n' < .ci/secrets/juno-funder.key)"
fi
if [[ -f .ci/secrets/juno-funder.seed.txt ]]; then
  export JUNO_FUNDER_SEED_PHRASE="\$(cat .ci/secrets/juno-funder.seed.txt)"
fi
if [[ -f .ci/secrets/juno-funder.ua ]]; then
  export JUNO_FUNDER_SOURCE_ADDRESS="\$(tr -d '\r\n' < .ci/secrets/juno-funder.ua)"
fi
export JUNO_RPC_USER="\$(tr -d '\r\n' < .ci/secrets/juno-rpc-user.txt)"
export JUNO_RPC_PASS="\$(tr -d '\r\n' < .ci/secrets/juno-rpc-pass.txt)"
# Live e2e queues target TLS-enabled Kafka brokers in both managed and forwarded shared modes.
export JUNO_QUEUE_KAFKA_TLS="true"
if [[ -f .ci/secrets/juno-scan-bearer.txt ]]; then
  export JUNO_SCAN_BEARER_TOKEN="\$(tr -d '\r\n' < .ci/secrets/juno-scan-bearer.txt)"
fi
[[ -n "\${JUNO_RPC_USER:-}" ]] || { echo "JUNO_RPC_USER is required for withdraw coordinator full mode" >&2; exit 1; }
[[ -n "\${JUNO_RPC_PASS:-}" ]] || { echo "JUNO_RPC_PASS is required for withdraw coordinator full mode" >&2; exit 1; }
export AWS_REGION="${aws_region}"
export AWS_DEFAULT_REGION="${aws_region}"
if [[ -n "${aws_dr_region}" ]]; then
  export AWS_DR_REGION="${aws_dr_region}"
fi
export RELAYER_RUNTIME_MODE="${relayer_runtime_mode}"
export RELAYER_RUNTIME_OPERATOR_HOSTS="${operator_private_ips_csv}"
export RELAYER_RUNTIME_OPERATOR_SSH_USER="${runner_ssh_user}"
export RELAYER_RUNTIME_OPERATOR_SSH_KEY_FILE=".ci/secrets/operator-fleet-ssh.key"
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
  export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
fi
if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
fi
if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
  export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"
fi
if ! command -v psql >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql-client
fi
mkdir -p "$remote_workdir/reports"

operator_ssh_key=".ci/secrets/operator-fleet-ssh.key"
operator_ssh_user="${runner_ssh_user}"
operator_private_ips=($witness_tunnel_private_ip_joined)
witness_tunnel_scan_base_port="${witness_tunnel_scan_base_port}"
witness_tunnel_rpc_base_port="${witness_tunnel_rpc_base_port}"
witness_tunnel_tss_base_port="${witness_tunnel_tss_base_port}"
witness_tunnel_quorum="${witness_quorum_threshold}"
declare -a witness_tunnel_pids=()
declare -a witness_tunnel_ready_labels=()

cleanup_witness_tunnel() {
  set +e
  local witness_tunnel_pid
  for witness_tunnel_pid in "\${witness_tunnel_pids[@]}"; do
    kill "\$witness_tunnel_pid" >/dev/null 2>&1 || true
  done
  for witness_tunnel_pid in "\${witness_tunnel_pids[@]}"; do
    wait "\$witness_tunnel_pid" >/dev/null 2>&1 || true
  done
}
trap cleanup_witness_tunnel EXIT

for ((op_idx = 0; op_idx < \${#operator_private_ips[@]}; op_idx++)); do
  operator_ssh_host="\${operator_private_ips[\$op_idx]}"
  witness_operator_label="op\$((op_idx + 1))@\${operator_ssh_host}"
  witness_tunnel_scan_port=\$((witness_tunnel_scan_base_port + op_idx))
  witness_tunnel_rpc_port=\$((witness_tunnel_rpc_base_port + op_idx))
  witness_tunnel_tss_port=\$((witness_tunnel_tss_base_port + op_idx))
  tunnel_log="$remote_workdir/reports/witness-tunnel-op\$((op_idx + 1)).log"

  ssh \
    -i "\$operator_ssh_key" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    -N \
    -L "127.0.0.1:\${witness_tunnel_scan_port}:127.0.0.1:8080" \
    -L "127.0.0.1:\${witness_tunnel_rpc_port}:127.0.0.1:18232" \
    -L "127.0.0.1:\${witness_tunnel_tss_port}:127.0.0.1:9443" \
    "\$operator_ssh_user@\$operator_ssh_host" \
    >"\$tunnel_log" 2>&1 &
  witness_tunnel_pid=\$!
  witness_tunnel_pids+=("\$witness_tunnel_pid")

  witness_tunnel_ready="false"
  for attempt in \$(seq 1 20); do
    if ! kill -0 "\$witness_tunnel_pid" >/dev/null 2>&1; then
      break
    fi
    if timeout 2 bash -lc "</dev/tcp/127.0.0.1/\$witness_tunnel_scan_port" >/dev/null 2>&1 \
      && timeout 2 bash -lc "</dev/tcp/127.0.0.1/\$witness_tunnel_rpc_port" >/dev/null 2>&1 \
      && timeout 2 bash -lc "</dev/tcp/127.0.0.1/\$witness_tunnel_tss_port" >/dev/null 2>&1; then
      witness_tunnel_ready="true"
      break
    fi
    sleep 1
  done

  if [[ "\$witness_tunnel_ready" == "true" ]]; then
    witness_tunnel_ready_labels+=("\$witness_operator_label")
    echo "witness tunnel ready for operator=\$witness_operator_label scan_port=\$witness_tunnel_scan_port rpc_port=\$witness_tunnel_rpc_port tss_port=\$witness_tunnel_tss_port"
  else
    echo "witness tunnel readiness failed for operator=\$witness_operator_label scan_port=\$witness_tunnel_scan_port rpc_port=\$witness_tunnel_rpc_port tss_port=\$witness_tunnel_tss_port" >&2
  fi
done

if (( \${#witness_tunnel_ready_labels[@]} < witness_tunnel_quorum )); then
  echo "insufficient witness tunnels ready for quorum: ready=\${#witness_tunnel_ready_labels[@]} threshold=\$witness_tunnel_quorum" >&2
  for tunnel_log in "$remote_workdir"/reports/witness-tunnel-op*.log; do
    [[ -f "\$tunnel_log" ]] || continue
    echo "--- witness tunnel log tail: \$tunnel_log ---" >&2
    tail -n 80 "\$tunnel_log" >&2 || true
  done
  exit 1
fi

./deploy/operators/dkg/e2e/run-testnet-e2e.sh $remote_joined_args
EOF
); then
    die "failed to render remote run script"
  fi
  log "remote run script ready"

  log "running live e2e on remote host $runner_public_ip"
  local remote_run_status=0
  set +e
  ssh -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip" \
    "bash -lc $(printf '%q' "$remote_run_script")"
  remote_run_status=$?
  set -e

  log "collecting artifacts"
  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip:$remote_workdir/reports" \
    "$artifacts_dir/" || true

  sanitize_dkg_summary_file "$artifacts_dir/reports/dkg-summary.json"
  sanitize_dkg_summary_file "$artifacts_dir/dkg-summary-distributed.json"

  local summary_path
  summary_path="$artifacts_dir/reports/testnet-e2e-summary.json"
  if [[ -f "$summary_path" ]]; then
    local juno_tx_hash
    local juno_tx_hash_source
    local juno_tx_hash_expected_source="withdraw_coordinator.payout_state"
    juno_tx_hash="$(jq -r '.juno.tx_hash? // .bridge.report.juno.proof_of_execution.tx_hash? // ""' "$summary_path" 2>/dev/null || true)"
    juno_tx_hash_source="$(jq -r '.juno.tx_hash_source? // .bridge.report.juno.proof_of_execution.source? // ""' "$summary_path" 2>/dev/null || true)"
    if [[ -n "$juno_tx_hash" ]]; then
      if [[ "$juno_tx_hash_source" != "$juno_tx_hash_expected_source" ]]; then
        log "juno_tx_hash=$juno_tx_hash source=$juno_tx_hash_source expected_source=$juno_tx_hash_expected_source"
      else
        log "juno_tx_hash=$juno_tx_hash source=$juno_tx_hash_source"
      fi
    else
      log "juno_tx_hash=unavailable"
    fi
    log "summary=$summary_path"
    printf '%s\n' "$summary_path"
  else
    log "summary file not found locally after artifact collection"
  fi

  if (( remote_run_status != 0 )); then
    if [[ "$keep_infra" == "true" ]]; then
      cleanup_enabled="false"
      log "keep-infra enabled after failure; leaving resources up"
    fi
    die "remote live e2e run failed (status=$remote_run_status)"
  fi

  if [[ "$keep_infra" == "true" ]]; then
    cleanup_enabled="false"
    log "keep-infra enabled; leaving resources up"
  fi
}

command_preflight() {
  shift || true

  local status_json=""
  local -a run_args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --status-json)
        [[ $# -ge 2 ]] || die "missing value for --status-json"
        status_json="$2"
        shift 2
        ;;
      *)
        run_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ -z "$status_json" ]]; then
    status_json="$REPO_ROOT/tmp/aws-live-e2e/preflight-status.json"
  fi
  ensure_dir "$(dirname "$status_json")"
  local preflight_log
  preflight_log="$(mktemp "${TMPDIR:-/tmp}/aws-live-e2e-preflight.XXXXXX")"

  local run_status=0
  set +e
  "$SCRIPT_DIR/run-testnet-e2e-aws.sh" run \
    --preflight-only \
    --status-json "$status_json" \
    "${run_args[@]}" 2>&1 | tee "$preflight_log"
  run_status="${PIPESTATUS[0]}"
  set -e

  if (( run_status != 0 )); then
    local classification_json
    classification_json="$(classify_failure_signature "$preflight_log")"
    print_failure_classification_hint "$classification_json"
    write_status_json \
      "$status_json" \
      "preflight" \
      "failed" \
      "preflight checks failed" \
      "" \
      "$preflight_log" \
      "$classification_json"
    die "preflight failed"
  fi

  write_status_json \
    "$status_json" \
    "preflight" \
    "passed" \
    "preflight checks passed" \
    "" \
    "$preflight_log" \
    "null"
  log "preflight passed status_json=$status_json"
  printf '%s\n' "$status_json"
}

command_canary() {
  shift || true

  local status_json=""
  local -a wrapper_args=()
  local -a e2e_args=()
  local parse_forwarded="false"
  while [[ $# -gt 0 ]]; do
    if [[ "$parse_forwarded" == "true" ]]; then
      e2e_args+=("$1")
      shift
      continue
    fi
    case "$1" in
      --status-json)
        [[ $# -ge 2 ]] || die "missing value for --status-json"
        status_json="$2"
        shift 2
        ;;
      --)
        parse_forwarded="true"
        shift
        ;;
      *)
        wrapper_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ -z "$status_json" ]]; then
    status_json="$REPO_ROOT/tmp/aws-live-e2e/canary-status.json"
  fi
  ensure_dir "$(dirname "$status_json")"
  local canary_log
  canary_log="$(mktemp "${TMPDIR:-/tmp}/aws-live-e2e-canary.XXXXXX")"

  local reuse_bridge_summary_path
  reuse_bridge_summary_path="$(forwarded_arg_value "--reuse-bridge-summary-path" "${wrapper_args[@]}" || true)"
  [[ -n "$reuse_bridge_summary_path" ]] || \
    die "canary requires --reuse-bridge-summary-path (resume economics forbid redeploy)"
  [[ -f "$reuse_bridge_summary_path" ]] || \
    die "canary reuse bridge summary file not found: $reuse_bridge_summary_path"

  if ! array_has_value "--keep-infra" "${wrapper_args[@]}"; then
    wrapper_args+=("--keep-infra")
  fi
  if ! array_has_value "--skip-distributed-dkg" "${wrapper_args[@]}"; then
    wrapper_args+=("--skip-distributed-dkg")
  fi

  local -a canary_e2e_args=()
  local e2e_idx=0
  while (( e2e_idx < ${#e2e_args[@]} )); do
    case "${e2e_args[$e2e_idx]}" in
      --stop-after-stage)
        (( e2e_idx + 1 < ${#e2e_args[@]} )) || die "forwarded argument missing value: --stop-after-stage"
        e2e_idx=$((e2e_idx + 2))
        ;;
      *)
        canary_e2e_args+=("${e2e_args[$e2e_idx]}")
        e2e_idx=$((e2e_idx + 1))
        ;;
    esac
  done
  canary_e2e_args+=("--stop-after-stage" "checkpoint_validated")

  local run_status=0
  set +e
  "$SCRIPT_DIR/run-testnet-e2e-aws.sh" run \
    "${wrapper_args[@]}" \
    -- "${canary_e2e_args[@]}" 2>&1 | tee "$canary_log"
  run_status="${PIPESTATUS[0]}"
  set -e

  if (( run_status != 0 )); then
    local classification_json
    classification_json="$(classify_failure_signature "$canary_log")"
    print_failure_classification_hint "$classification_json"
    write_status_json \
      "$status_json" \
      "canary" \
      "failed" \
      "canary run failed" \
      "" \
      "$canary_log" \
      "$classification_json"
    die "canary failed"
  fi

  local summary_path
  summary_path="$(extract_summary_path_from_log "$canary_log")"
  [[ -n "$summary_path" ]] || die "canary succeeded but summary path could not be resolved from log"
  [[ -f "$summary_path" ]] || die "canary summary file not found: $summary_path"
  if ! validate_canary_summary "$summary_path"; then
    write_status_json \
      "$status_json" \
      "canary" \
      "failed" \
      "canary acceptance criteria failed" \
      "$summary_path" \
      "$canary_log" \
      "null"
    die "canary acceptance criteria failed"
  fi

  write_status_json \
    "$status_json" \
    "canary" \
    "passed" \
    "canary completed at checkpoint_validated" \
    "$summary_path" \
    "$canary_log" \
    "null"
  log "canary passed status_json=$status_json summary=$summary_path"
  printf '%s\n' "$status_json"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    run) command_run "$@" ;;
    preflight) command_preflight "$@" ;;
    canary) command_canary "$@" ;;
    cleanup) command_cleanup "$@" ;;
    -h|--help|"")
      usage
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
