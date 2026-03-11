#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
source "$REPO_ROOT/deploy/production/tests/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

main() {
  local main_tf variables_tf password_block key_rotation failover min_healthy_count max_healthy_count rollback_count
  main_tf="$(cat "$SCRIPT_DIR/main.tf")"
  variables_tf="$(cat "$SCRIPT_DIR/variables.tf")"
  password_block="$(awk '
    /variable "shared_postgres_password" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/variables.tf")"
  shared_ecs_desired_count_block="$(awk '
    /variable "shared_ecs_desired_count" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/variables.tf")"
  key_rotation="$(cat "$REPO_ROOT/deploy/shared/runbooks/proof-key-rotation.md")"
  failover="$(cat "$REPO_ROOT/deploy/shared/runbooks/proof-requestor-failover.md")"

  assert_contains "$main_tf" 'check "distinct_proof_secret_arns"' "distinct proof secret ARN guard"
  assert_contains "$main_tf" 'check "proof_service_image_ecr_scope"' "explicit ECR image repository scope guard"
  assert_contains "$main_tf" 'shared_proof_service_image_ecr_repository_arn must be set when shared_proof_service_image points at an explicit ECR repository.' "explicit ECR image scope message"

  assert_not_contains "$main_tf" 'AmazonECSTaskExecutionRolePolicy' "managed ECS execution policy removed"
  assert_contains "$main_tf" 'sid = "AllowECRAuthorizationToken"' "execution role keeps required ECR auth token call"
  assert_contains "$main_tf" 'sid = "AllowProofRequestorImagePull"' "requestor execution role scopes image pull"
  assert_contains "$main_tf" 'sid = "AllowProofFunderImagePull"' "funder execution role scopes image pull"
  assert_contains "$main_tf" 'resources = [local.shared_proof_service_ecr_repository_arn]' "ECR image pull scope uses configured repository ARN"
  assert_contains "$main_tf" 'sid = "AllowProofRequestorLogWrite"' "requestor log write scope present"
  assert_contains "$main_tf" 'sid = "AllowProofFunderLogWrite"' "funder log write scope present"
  assert_contains "$main_tf" 'trimsuffix(aws_cloudwatch_log_group.proof_requestor.arn, ":*")' "requestor log group scope is explicit"
  assert_contains "$main_tf" 'trimsuffix(aws_cloudwatch_log_group.proof_funder.arn, ":*")' "funder log group scope is explicit"
  assert_contains "$main_tf" 'resources = [var.shared_sp1_requestor_secret_arn]' "requestor secret scope uses only requestor ARN"
  assert_contains "$main_tf" 'resources = [var.shared_sp1_funder_secret_arn]' "funder secret scope uses only funder ARN"

  assert_contains "$main_tf" 'description = "MSK broker mesh"' "MSK self-ingress rule exists"
  assert_contains "$main_tf" 'protocol    = "tcp"' "MSK self-ingress stays on TCP"
  assert_contains "$main_tf" 'from_port   = 9092' "MSK self-ingress lower port bound"
  assert_contains "$main_tf" 'to_port     = 9094' "MSK self-ingress upper port bound"
  assert_contains "$main_tf" 'min.insync.replicas = 2' "MSK durability policy"

  assert_contains "$main_tf" 'skip_final_snapshot       = false' "Aurora final snapshot required"
  assert_contains "$main_tf" 'final_snapshot_identifier = local.aurora_final_snapshot_identifier' "Aurora final snapshot identifier wired"
  assert_contains "$main_tf" 'deletion_protection       = true' "Aurora deletion protection enabled"

  min_healthy_count="$(grep -c 'deployment_minimum_healthy_percent = 100' "$SCRIPT_DIR/main.tf")"
  max_healthy_count="$(grep -c 'deployment_maximum_percent         = 200' "$SCRIPT_DIR/main.tf")"
  rollback_count="$(grep -c 'rollback = true' "$SCRIPT_DIR/main.tf")"
  assert_eq "$min_healthy_count" "2" "both proof services keep minimum healthy percent at 100"
  assert_eq "$max_healthy_count" "2" "both proof services keep maximum percent at 200"
  assert_eq "$rollback_count" "2" "both proof services keep rollback enabled"

  assert_contains "$main_tf" 'health_check_type         = "ELB"' "IPFS ASG uses ELB health"
  assert_contains "$main_tf" 'shared_ipfs_min_size must be at least 2 to avoid a single-node IPFS deployment.' "IPFS redundancy precondition"

  assert_not_contains "$password_block" 'default' "shared postgres password has no default"
  assert_contains "$variables_tf" 'variable "shared_proof_service_image_ecr_repository_arn"' "explicit proof-service ECR repository ARN input"
  assert_contains "$shared_ecs_desired_count_block" 'default     = 0' "shared proof services stay idle until runtime rollout"

  assert_contains "$key_rotation" 'configured proof-services ECR repository' "rotation runbook documents scoped repository access"
  assert_contains "$key_rotation" 'deployment_maximum_percent = 200' "rotation runbook documents overlapping rollout"
  assert_contains "$failover" 'at least two healthy targets' "failover runbook documents IPFS redundancy"
  assert_contains "$failover" 'ELB health checks' "failover runbook documents ELB-backed readiness"

  printf 'package_a_snapshot_test: PASS\n'
}

main "$@"
