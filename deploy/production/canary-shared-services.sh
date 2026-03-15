#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-shared-services.sh --shared-manifest <path> [--dry-run]

Checks:
  - AWS auth for shared-services verification
  - Postgres reachability plus optional Aurora cluster health
  - Kafka auth mode plus broker TCP reachability and optional MSK cluster health
  - IPFS API reachability plus optional target-group health
  - Artifact bucket reachability, versioning, and optional object lock

Output:
  JSON summary to stdout suitable for gating deployment
EOF
}

shared_manifest=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest)
      shared_manifest="$2"
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

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  for cmd in pg_isready nc curl; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

aws_profile="$(production_json_optional "$shared_manifest" '.shared_services.aws_profile')"
aws_region="$(production_json_optional "$shared_manifest" '.shared_services.aws_region')"
postgres_endpoint="$(production_json_required "$shared_manifest" '.shared_services.postgres.endpoint | select(type == "string" and length > 0)')"
postgres_cluster_arn="$(production_json_optional "$shared_manifest" '.shared_services.postgres.cluster_arn | select(type == "string" and length > 0)')"
postgres_port="$(production_json_required "$shared_manifest" '.shared_services.postgres.port')"
kafka_brokers="$(production_json_required "$shared_manifest" '.shared_services.kafka.bootstrap_brokers | select(type == "string" and length > 0)')"
kafka_cluster_arn="$(production_json_optional "$shared_manifest" '.shared_services.kafka.cluster_arn | select(type == "string" and length > 0)')"
kafka_auth_mode="$(production_json_required "$shared_manifest" '.shared_services.kafka.auth.mode | select(type == "string" and length > 0)')"
ipfs_api_url="$(production_json_required "$shared_manifest" '.shared_services.ipfs.api_url | select(type == "string" and length > 0)')"
ipfs_target_group_arn="$(production_json_optional "$shared_manifest" '.shared_services.ipfs.target_group_arn | select(type == "string" and length > 0)')"
checkpoint_blob_bucket="$(production_json_optional "$shared_manifest" '.shared_services.artifacts.checkpoint_blob_bucket | select(type == "string" and length > 0)')"
artifacts_object_lock_required="$(production_json_optional "$shared_manifest" '.shared_services.artifacts.object_lock_required')"
environment="$(production_json_required "$shared_manifest" '.environment | select(type == "string" and length > 0)')"
ipfs_api_url="${ipfs_api_url%/}"
if [[ "$artifacts_object_lock_required" != "true" ]]; then
  artifacts_object_lock_required="false"
fi

aws_auth_status="passed"
aws_auth_detail="verified"
aws_args=(aws)
if [[ -n "$aws_profile" ]]; then
  aws_args+=(--profile "$aws_profile")
fi
if [[ -n "$aws_region" ]]; then
  aws_args+=(--region "$aws_region")
fi

postgres_status="passed"
kafka_status="passed"
ipfs_status="passed"
artifacts_status="skipped"
postgres_detail="reachable"
kafka_detail="all brokers reachable"
ipfs_detail="api reachable"
artifacts_detail="no artifact bucket configured"

if [[ "$dry_run" == "true" ]]; then
  aws_auth_status="skipped"
  aws_auth_detail="dry run"
  postgres_status="skipped"
  kafka_status="skipped"
  ipfs_status="skipped"
  artifacts_status="skipped"
  postgres_detail="dry run"
  kafka_detail="dry run"
  ipfs_detail="dry run"
  artifacts_detail="dry run"
else
  if [[ "$kafka_auth_mode" == "aws-msk-iam" ]]; then
    kafka_detail="all brokers reachable with aws-msk-iam"
  elif [[ "$environment" == "preview" && "$kafka_auth_mode" == "none" ]]; then
    kafka_detail="all brokers reachable with preview kafka transport"
  else
    kafka_status="failed"
    kafka_detail="shared manifest kafka.auth.mode must be aws-msk-iam (or none for preview)"
  fi

  if ! pg_isready -h "$postgres_endpoint" -p "$postgres_port" >/dev/null 2>&1; then
    postgres_status="failed"
    postgres_detail="pg_isready failed"
  fi

  IFS=',' read -r -a broker_array <<<"$kafka_brokers"
  for broker in "${broker_array[@]}"; do
    broker="$(trim "$broker")"
    [[ -n "$broker" ]] || continue
    broker_host="${broker%:*}"
    broker_port="${broker##*:}"
    if ! nc -z "$broker_host" "$broker_port" >/dev/null 2>&1; then
      kafka_status="failed"
      kafka_detail="broker unreachable: $broker"
      break
    fi
  done

  if ! curl -fsS -X POST "${ipfs_api_url}/api/v0/version" >/dev/null 2>&1; then
    ipfs_status="failed"
    ipfs_detail="ipfs api unreachable"
  fi

  if [[ "$kafka_auth_mode" == "aws-msk-iam" || -n "$postgres_cluster_arn" || -n "$kafka_cluster_arn" || -n "$ipfs_target_group_arn" || -n "$checkpoint_blob_bucket" ]]; then
    have_cmd aws || die "required command not found: aws"
    if [[ -z "$aws_profile" || -z "$aws_region" ]]; then
      aws_auth_status="failed"
      aws_auth_detail="shared manifest is missing shared_services.aws_profile or shared_services.aws_region"
    elif ! AWS_PAGER="" "${aws_args[@]}" sts get-caller-identity >/dev/null 2>&1; then
      aws_auth_status="failed"
      aws_auth_detail="aws sts get-caller-identity failed"
    fi
  else
    aws_auth_status="skipped"
    aws_auth_detail="no aws-backed checks configured"
  fi

  if [[ "$aws_auth_status" == "passed" && -n "$postgres_cluster_arn" ]]; then
    postgres_cluster_json="$(AWS_PAGER="" "${aws_args[@]}" rds describe-db-clusters --db-cluster-identifier "$postgres_cluster_arn" --output json 2>/dev/null || true)"
    postgres_cluster_state="$(jq -r '.DBClusters[0].Status // empty' <<<"$postgres_cluster_json")"
    postgres_cluster_azs="$(jq -r '(.DBClusters[0].AvailabilityZones // []) | length' <<<"$postgres_cluster_json")"
    if [[ "$postgres_cluster_state" != "available" ]]; then
      postgres_status="failed"
      postgres_detail="aurora cluster is not available"
    elif [[ "$postgres_cluster_azs" -lt 2 ]]; then
      postgres_status="failed"
      postgres_detail="aurora cluster does not span at least two availability zones"
    fi
  fi

  if [[ "$aws_auth_status" == "passed" && "$kafka_status" == "passed" && -n "$kafka_cluster_arn" ]]; then
    kafka_cluster_json="$(AWS_PAGER="" "${aws_args[@]}" kafka describe-cluster-v2 --cluster-arn "$kafka_cluster_arn" --output json 2>/dev/null || true)"
    kafka_cluster_state="$(jq -r '.ClusterInfo.State // empty' <<<"$kafka_cluster_json")"
    kafka_cluster_subnets="$(jq -r '(.ClusterInfo.Provisioned.BrokerNodeGroupInfo.ClientSubnets // []) | length' <<<"$kafka_cluster_json")"
    if [[ "$kafka_cluster_state" != "ACTIVE" ]]; then
      kafka_status="failed"
      kafka_detail="msk cluster is not active"
    elif [[ "$kafka_cluster_subnets" -lt 2 ]]; then
      kafka_status="failed"
      kafka_detail="msk cluster does not span at least two subnets"
    fi
  fi

  if [[ "$aws_auth_status" == "passed" && -n "$ipfs_target_group_arn" ]]; then
    ipfs_target_json="$(AWS_PAGER="" "${aws_args[@]}" elbv2 describe-target-health --target-group-arn "$ipfs_target_group_arn" --output json 2>/dev/null || true)"
    ipfs_healthy_targets="$(jq -r '[.TargetHealthDescriptions[]? | select(.TargetHealth.State == "healthy")] | length' <<<"$ipfs_target_json")"
    if [[ "$ipfs_healthy_targets" -lt 2 ]]; then
      ipfs_status="failed"
      ipfs_detail="ipfs target group has fewer than two healthy targets"
    fi
  fi

  if [[ -n "$checkpoint_blob_bucket" ]]; then
    artifacts_status="passed"
    artifacts_detail="bucket versioning verified"
    if [[ "$aws_auth_status" != "passed" ]]; then
      artifacts_status="failed"
      artifacts_detail="artifact bucket could not be verified because aws auth failed"
    elif ! AWS_PAGER="" "${aws_args[@]}" s3api head-bucket --bucket "$checkpoint_blob_bucket" >/dev/null 2>&1; then
      artifacts_status="failed"
      artifacts_detail="artifact bucket is unreachable"
    else
      bucket_versioning_status="$(AWS_PAGER="" "${aws_args[@]}" s3api get-bucket-versioning --bucket "$checkpoint_blob_bucket" --query Status --output text 2>/dev/null || true)"
      if [[ "$bucket_versioning_status" != "Enabled" ]]; then
        artifacts_status="failed"
        artifacts_detail="artifact bucket versioning is not enabled"
      elif [[ "$artifacts_object_lock_required" == "true" ]]; then
        object_lock_status="$(AWS_PAGER="" "${aws_args[@]}" s3api get-object-lock-configuration --bucket "$checkpoint_blob_bucket" --query ObjectLockConfiguration.ObjectLockEnabled --output text 2>/dev/null || true)"
        if [[ "$object_lock_status" != "Enabled" ]]; then
          artifacts_status="failed"
          artifacts_detail="artifact bucket object lock is not enabled"
        else
          artifacts_detail="bucket versioning and object lock verified"
        fi
      fi
    fi
  fi
fi

ready_for_deploy="true"
for status in "$aws_auth_status" "$postgres_status" "$kafka_status" "$ipfs_status" "$artifacts_status"; do
  if [[ "$status" != "passed" && "$status" != "skipped" ]]; then
    ready_for_deploy="false"
  fi
done
if [[ "$dry_run" == "true" ]]; then
  ready_for_deploy="false"
fi

jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg manifest "$shared_manifest" \
  --arg aws_auth_status "$aws_auth_status" \
  --arg aws_auth_detail "$aws_auth_detail" \
  --arg postgres_status "$postgres_status" \
  --arg postgres_detail "$postgres_detail" \
  --arg kafka_status "$kafka_status" \
  --arg kafka_detail "$kafka_detail" \
  --arg ipfs_status "$ipfs_status" \
  --arg ipfs_detail "$ipfs_detail" \
  --arg artifacts_status "$artifacts_status" \
  --arg artifacts_detail "$artifacts_detail" \
  --argjson ready_for_deploy "$ready_for_deploy" \
  '{
    version: $version,
    generated_at: $generated_at,
    shared_manifest: $manifest,
    ready_for_deploy: $ready_for_deploy,
    checks: {
      aws_auth: {
        status: $aws_auth_status,
        detail: $aws_auth_detail
      },
      postgres: {
        status: $postgres_status,
        detail: $postgres_detail
      },
      kafka: {
        status: $kafka_status,
        detail: $kafka_detail
      },
      ipfs: {
        status: $ipfs_status,
        detail: $ipfs_detail
      },
      artifacts: {
        status: $artifacts_status,
        detail: $artifacts_detail
      }
    }
  }'
