#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-shared-services-ssm.sh --shared-manifest <path> [--queue-inspect-bin <path>] [--remote-runtime-env <path>] [--dry-run]

Checks:
  - Resolves a healthy shared proof-role instance from shared_roles.proof.asg
  - Rejects protected op2 instances before any SSM command
  - Runs canary-shared-services.sh inside the shared VPC over SSM

Output:
  JSON summary from the remote shared-services canary
EOF
}

shared_manifest=""
queue_inspect_bin=""
remote_runtime_env="/etc/intents-juno/proof-requestor.env"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest)
      shared_manifest="$2"
      shift 2
      ;;
    --queue-inspect-bin)
      queue_inspect_bin="$2"
      shift 2
      ;;
    --remote-runtime-env)
      remote_runtime_env="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -n "$remote_runtime_env" ]] || die "--remote-runtime-env must not be empty"

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

aws_profile="$(production_json_required "$shared_manifest" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
aws_region="$(production_json_required "$shared_manifest" '.shared_services.aws_region | select(type == "string" and length > 0)')"
shared_proof_role_asg="$(production_json_required "$shared_manifest" '.shared_roles.proof.asg | select(type == "string" and length > 0)')" \
  || die "shared manifest is missing shared_roles.proof.asg"
environment="$(production_json_required "$shared_manifest" '.environment | select(type == "string" and length > 0)')"

if [[ -n "$queue_inspect_bin" ]]; then
  [[ -x "$queue_inspect_bin" ]] || die "queue inspect binary must exist and be executable: $queue_inspect_bin"
fi

if [[ "$dry_run" == "true" ]]; then
  jq -n \
    --arg version "1" \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg environment "$environment" \
    --arg shared_manifest "$shared_manifest" \
    --arg proof_asg "$shared_proof_role_asg" \
    '{
      version: $version,
      generated_at: $generated_at,
      environment: $environment,
      shared_manifest: $shared_manifest,
      target_asg: $proof_asg,
      ready_for_deploy: false,
      checks: {
        ssm: {status: "skipped", detail: "dry run"},
        shared_canary: {status: "skipped", detail: "dry run"}
      }
    }'
  exit 0
fi

have_cmd aws || die "required command not found: aws"

protected_instance_id() {
  case "$1" in
    i-0a886419721b81020|i-033cc3a2d107255d3|i-00d9725a22f0608ea) return 0 ;;
    *) return 1 ;;
  esac
}

protected_instance_name() {
  case "$1" in
    pool2|nn|nn2) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_shared_proof_instance_id() {
  local asg_json ec2_json instance_id instance_name
  local candidate_ids=()

  asg_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$shared_proof_role_asg" \
    --output json)"
  while IFS= read -r instance_id; do
    [[ -n "$instance_id" ]] || continue
    candidate_ids+=("$instance_id")
  done < <(jq -r '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy") | .InstanceId] | .[]' <<<"$asg_json")

  ((${#candidate_ids[@]} > 0)) || die "shared proof asg $shared_proof_role_asg has no healthy in-service instances"

  for instance_id in "${candidate_ids[@]}"; do
    if protected_instance_id "$instance_id"; then
      die "protected instance id selected by shared proof asg $shared_proof_role_asg: $instance_id"
    fi
  done

  ec2_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
    --instance-ids "${candidate_ids[@]}" \
    --output json)"

  while IFS=$'\t' read -r instance_id instance_name; do
    [[ -n "$instance_id" ]] || continue
    if protected_instance_name "$instance_name"; then
      die "protected instance name selected by shared proof asg $shared_proof_role_asg: $instance_name ($instance_id)"
    fi
  done < <(jq -r '.Reservations[].Instances[]? | [.InstanceId, ((.Tags // [])[]? | select(.Key == "Name") | .Value) // ""] | @tsv' <<<"$ec2_json")

  instance_id="$(jq -r '[.Reservations[].Instances[]? | select(.State.Name == "running") | .InstanceId][0] // empty' <<<"$ec2_json")"
  [[ -n "$instance_id" ]] || die "shared proof asg $shared_proof_role_asg has no running healthy instances"
  printf '%s\n' "$instance_id"
}

cleanup_remote_stage() {
  production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "sudo rm -rf '$remote_stage_dir'" >/dev/null 2>&1 || true
}

stage_remote_file() {
  local source_path="$1"
  local destination_path="$2"
  local mode="$3"
  if ! production_ssm_stage_file "$aws_profile" "$aws_region" "$instance_id" "$source_path" "$destination_path" "$mode"; then
    cleanup_remote_stage
    die "failed to stage file over ssm: $source_path"
  fi
}

instance_id="$(resolve_shared_proof_instance_id)"
remote_stage_dir="/tmp/intents-juno-shared-canary-$(production_safe_slug "$environment")-$(date +%s)-$$"
remote_queue_inspect_bin=""

production_ssm_run_shell_command \
  "$aws_profile" "$aws_region" "$instance_id" \
  "sudo rm -rf '$remote_stage_dir' && sudo install -d -m 0755 '$remote_stage_dir/deploy/production' '$remote_stage_dir/deploy/operators/dkg' '$remote_stage_dir/bin'" >/dev/null \
  || die "failed to create remote shared canary stage dir over ssm: $remote_stage_dir"

stage_remote_file "$SCRIPT_DIR/canary-shared-services.sh" "$remote_stage_dir/deploy/production/canary-shared-services.sh" 0755
stage_remote_file "$SCRIPT_DIR/lib.sh" "$remote_stage_dir/deploy/production/lib.sh" 0644
stage_remote_file "$REPO_ROOT/deploy/operators/dkg/common.sh" "$remote_stage_dir/deploy/operators/dkg/common.sh" 0644
stage_remote_file "$shared_manifest" "$remote_stage_dir/shared-manifest.json" 0640

if [[ -n "$queue_inspect_bin" ]]; then
  remote_queue_inspect_bin="$remote_stage_dir/bin/queue-inspect"
  stage_remote_file "$queue_inspect_bin" "$remote_queue_inspect_bin" 0755
fi

printf -v remote_stage_dir_q '%q' "$remote_stage_dir"
printf -v remote_manifest_q '%q' "$remote_stage_dir/shared-manifest.json"
printf -v remote_canary_q '%q' "$remote_stage_dir/deploy/production/canary-shared-services.sh"
printf -v remote_runtime_env_q '%q' "$remote_runtime_env"
printf -v remote_queue_inspect_bin_q '%q' "$remote_queue_inspect_bin"

queue_env_block=""
if [[ -n "$remote_queue_inspect_bin" ]]; then
  queue_env_block="$(cat <<EOF
if [[ ! -f $remote_runtime_env_q ]]; then
  echo "remote runtime env not found: $remote_runtime_env" >&2
  exit 1
fi
set -a
source $remote_runtime_env_q
set +a
export PRODUCTION_CANARY_QUEUE_INSPECT_BIN=$remote_queue_inspect_bin_q
export PRODUCTION_CANARY_QUEUE_INSPECT_POSTGRES_DSN_ENV=POSTGRES_DSN
EOF
)"
fi

remote_command="$(cat <<EOF
set -euo pipefail
cleanup() {
  sudo rm -rf $remote_stage_dir_q
}
trap cleanup EXIT
export HOME="\${HOME:-/root}"
export PRODUCTION_CANARY_AWS_USE_INSTANCE_PROFILE=true
$queue_env_block
bash $remote_canary_q --shared-manifest $remote_manifest_q
EOF
)"

if ! canary_json="$(production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "$remote_command")"; then
  cleanup_remote_stage
  die "shared services canary failed over ssm for asg $shared_proof_role_asg instance $instance_id"
fi

printf '%s\n' "$canary_json"
