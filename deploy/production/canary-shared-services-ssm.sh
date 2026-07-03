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
  canary-shared-services-ssm.sh --shared-manifest <path> [--queue-inspect-bin <path> | --queue-inspect-release-tag <tag> [--github-repo <repo>]] [--queue-inspect-postgres-dsn-secret-arn <arn> | --remote-runtime-env <path>] [--dry-run]

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
queue_inspect_bin_provided="false"
queue_inspect_release_tag=""
queue_inspect_release_tag_provided="false"
github_repo="juno-intents/intents-juno"
github_repo_provided="false"
queue_inspect_postgres_dsn_secret_arn=""
queue_inspect_postgres_dsn_secret_arn_provided="false"
remote_runtime_env="/etc/intents-juno/proof-requestor.env"
remote_runtime_env_provided="false"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest)
      shared_manifest="$2"
      shift 2
      ;;
    --queue-inspect-bin)
      queue_inspect_bin="$2"
      queue_inspect_bin_provided="true"
      shift 2
      ;;
    --queue-inspect-release-tag)
      queue_inspect_release_tag="$2"
      queue_inspect_release_tag_provided="true"
      shift 2
      ;;
    --github-repo)
      github_repo="$2"
      github_repo_provided="true"
      shift 2
      ;;
    --queue-inspect-postgres-dsn-secret-arn)
      queue_inspect_postgres_dsn_secret_arn="$2"
      queue_inspect_postgres_dsn_secret_arn_provided="true"
      shift 2
      ;;
    --remote-runtime-env)
      remote_runtime_env="$2"
      remote_runtime_env_provided="true"
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
if [[ "$queue_inspect_bin_provided" == "true" && "$queue_inspect_release_tag_provided" == "true" ]]; then
  die "--queue-inspect-bin and --queue-inspect-release-tag are mutually exclusive"
fi
if [[ "$queue_inspect_bin_provided" == "true" && -z "$queue_inspect_bin" ]]; then
  die "--queue-inspect-bin must not be empty"
fi
if [[ "$queue_inspect_release_tag_provided" == "true" && -z "$queue_inspect_release_tag" ]]; then
  die "--queue-inspect-release-tag must not be empty"
fi
if [[ "$github_repo_provided" == "true" && "$queue_inspect_release_tag_provided" != "true" ]]; then
  die "--github-repo requires --queue-inspect-release-tag"
fi
if [[ "$github_repo_provided" == "true" && -z "$github_repo" ]]; then
  die "--github-repo must not be empty"
fi
if [[ "$queue_inspect_release_tag_provided" == "true" ]]; then
  [[ "$github_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
    || die "--github-repo must use owner/name syntax with safe characters"
  [[ "$queue_inspect_release_tag" =~ ^app-binaries-v[0-9]{4}\.[0-9]{2}\.[0-9]{2}-r[0-9]+-(testnet|mainnet)$ ]] \
    || die "--queue-inspect-release-tag must be a pinned app-binaries release ending in -testnet or -mainnet"
fi
if [[ "$queue_inspect_postgres_dsn_secret_arn_provided" == "true" && "$remote_runtime_env_provided" == "true" ]]; then
  die "--queue-inspect-postgres-dsn-secret-arn and --remote-runtime-env are mutually exclusive"
fi
if [[ "$queue_inspect_postgres_dsn_secret_arn_provided" == "true" && "$queue_inspect_bin_provided" != "true" && "$queue_inspect_release_tag_provided" != "true" ]]; then
  die "--queue-inspect-postgres-dsn-secret-arn requires queue inspection"
fi
if [[ "$queue_inspect_postgres_dsn_secret_arn_provided" == "true" && -z "$queue_inspect_postgres_dsn_secret_arn" ]]; then
  die "--queue-inspect-postgres-dsn-secret-arn must not be empty"
fi
if [[ "$queue_inspect_postgres_dsn_secret_arn_provided" == "true" ]]; then
  [[ "$queue_inspect_postgres_dsn_secret_arn" =~ ^arn:aws[a-zA-Z-]*:secretsmanager:[A-Za-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$ ]] \
    || die "--queue-inspect-postgres-dsn-secret-arn must be a Secrets Manager secret ARN"
fi

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
remote_queue_inspect_asset=""
remote_queue_inspect_checksum=""
queue_inspect_asset_url=""
queue_inspect_checksum_url=""

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
elif [[ -n "$queue_inspect_release_tag" ]]; then
  remote_queue_inspect_bin="$remote_stage_dir/bin/queue-inspect"
  remote_queue_inspect_asset="$remote_stage_dir/bin/queue-inspect_linux_amd64"
  remote_queue_inspect_checksum="$remote_stage_dir/bin/queue-inspect_linux_amd64.sha256"
  queue_inspect_asset_url="https://github.com/${github_repo}/releases/download/${queue_inspect_release_tag}/queue-inspect_linux_amd64"
  queue_inspect_checksum_url="https://github.com/${github_repo}/releases/download/${queue_inspect_release_tag}/queue-inspect_linux_amd64.sha256"
fi

printf -v remote_stage_dir_q '%q' "$remote_stage_dir"
printf -v remote_manifest_q '%q' "$remote_stage_dir/shared-manifest.json"
printf -v remote_canary_q '%q' "$remote_stage_dir/deploy/production/canary-shared-services.sh"
printf -v aws_region_q '%q' "$aws_region"
printf -v remote_runtime_env_q '%q' "$remote_runtime_env"
printf -v remote_queue_inspect_bin_q '%q' "$remote_queue_inspect_bin"
printf -v remote_queue_inspect_asset_q '%q' "$remote_queue_inspect_asset"
printf -v remote_queue_inspect_checksum_q '%q' "$remote_queue_inspect_checksum"
printf -v queue_inspect_asset_url_q '%q' "$queue_inspect_asset_url"
printf -v queue_inspect_checksum_url_q '%q' "$queue_inspect_checksum_url"
printf -v queue_inspect_postgres_dsn_secret_arn_q '%q' "$queue_inspect_postgres_dsn_secret_arn"

queue_release_download_block=""
if [[ -n "$queue_inspect_release_tag" ]]; then
  queue_release_download_block="$(cat <<EOF
for cmd in curl sha256sum awk install; do
  command -v "\$cmd" >/dev/null 2>&1 || {
    echo "required command not found for queue-inspect release download: \$cmd" >&2
    exit 1
  }
done
curl -fsSL $queue_inspect_asset_url_q -o $remote_queue_inspect_asset_q
curl -fsSL $queue_inspect_checksum_url_q -o $remote_queue_inspect_checksum_q
queue_inspect_expected="\$(awk 'NF {print \$1; exit}' $remote_queue_inspect_checksum_q)"
if [[ ! "\$queue_inspect_expected" =~ ^[0-9a-fA-F]{64}\$ ]]; then
  echo "invalid queue-inspect checksum in release asset" >&2
  exit 1
fi
printf '%s  %s\n' "\$queue_inspect_expected" $remote_queue_inspect_asset_q | sha256sum -c - >/dev/null
install -m 0755 $remote_queue_inspect_asset_q $remote_queue_inspect_bin_q
[[ -x $remote_queue_inspect_bin_q ]] || {
  echo "downloaded queue-inspect is not executable" >&2
  exit 1
}
EOF
)"
fi

queue_env_block=""
if [[ -n "$remote_queue_inspect_bin" ]]; then
  if [[ -n "$queue_inspect_postgres_dsn_secret_arn" ]]; then
    queue_env_block="$(cat <<EOF
command -v aws >/dev/null 2>&1 || {
  echo "required command not found for queue-inspect postgres dsn secret: aws" >&2
  exit 1
}
POSTGRES_DSN="\$(AWS_PAGER="" aws --region $aws_region_q secretsmanager get-secret-value --secret-id $queue_inspect_postgres_dsn_secret_arn_q --query SecretString --output text)"
if [[ -z "\$POSTGRES_DSN" || "\$POSTGRES_DSN" == "None" ]]; then
  echo "queue-inspect postgres dsn secret is empty" >&2
  exit 1
fi
export POSTGRES_DSN
export PRODUCTION_CANARY_QUEUE_INSPECT_BIN=$remote_queue_inspect_bin_q
export PRODUCTION_CANARY_QUEUE_INSPECT_POSTGRES_DSN_ENV=POSTGRES_DSN
EOF
)"
  else
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
fi

remote_command="$(cat <<EOF
set -euo pipefail
cleanup() {
  sudo rm -rf $remote_stage_dir_q
}
trap cleanup EXIT
export HOME="\${HOME:-/root}"
export PRODUCTION_CANARY_AWS_USE_INSTANCE_PROFILE=true
$queue_release_download_block
$queue_env_block
bash $remote_canary_q --shared-manifest $remote_manifest_q
EOF
)"

if ! canary_json="$(production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "$remote_command")"; then
  cleanup_remote_stage
  die "shared services canary failed over ssm for asg $shared_proof_role_asg instance $instance_id"
fi

printf '%s\n' "$canary_json"
