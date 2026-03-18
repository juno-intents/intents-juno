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
  local main_tf variables_tf outputs_tf password_block key_rotation failover min_healthy_count max_healthy_count rollback_count
  main_tf="$(cat "$SCRIPT_DIR/main.tf")"
  variables_tf="$(cat "$SCRIPT_DIR/variables.tf")"
  outputs_tf="$(cat "$SCRIPT_DIR/outputs.tf")"
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
  assert_contains "$main_tf" 'check "shared_ecs_private_subnets_when_no_public_ip"' "shared ecs subnet/public-ip compatibility guard"
  assert_contains "$main_tf" 'shared_proof_service_image_ecr_repository_arn must be set when shared_proof_service_image points at an explicit ECR repository.' "explicit ECR image scope message"
  assert_contains "$main_tf" 'shared proof services require private shared_subnet_ids when shared_ecs_assign_public_ip=false.' "production-shared fails closed on public shared subnets without public IPs"
  assert_contains "$main_tf" 'shared_kafka_cluster_arn                    = coalesce(aws_msk_cluster.shared.arn, "")' "production-shared guards the shared kafka cluster arn when Terraform has not populated it yet"
  assert_contains "$main_tf" 'shared_kafka_topic_arn_prefix                = replace(local.shared_kafka_cluster_arn, ":cluster/", ":topic/")' "production-shared derives kafka topic arns from the guarded cluster arn"
  assert_contains "$main_tf" 'shared_kafka_group_arn_prefix                = replace(local.shared_kafka_cluster_arn, ":cluster/", ":group/")' "production-shared derives kafka group arns from the guarded cluster arn"

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
  assert_contains "$main_tf" 'resource "aws_secretsmanager_secret" "shared_postgres_dsn"' "production-shared provisions a dedicated postgres dsn secret"
  assert_contains "$main_tf" 'resources = [aws_secretsmanager_secret.shared_postgres_dsn.arn]' "execution roles can read only the shared postgres dsn secret"
  assert_contains "$variables_tf" 'variable "shared_sp1_requestor_address"' "production-shared exposes shared proof requestor address input"
  assert_contains "$variables_tf" 'alarm_actions must include at least one CloudWatch action ARN.' "production-shared requires alarm actions"
  assert_contains "$outputs_tf" 'output "shared_sp1_requestor_address"' "production-shared exports shared proof requestor address"
  assert_contains "$outputs_tf" 'output "shared_sp1_rpc_url"' "production-shared exports shared sp1 rpc url"
  assert_contains "$variables_tf" 'At least two private subnet IDs in distinct AZs for Aurora, MSK, ECS, and the IPFS NLB.' "production-shared documents private shared subnet requirement"
  assert_contains "$variables_tf" $'variable "shared_msk_broker_instance_type" {\n  description = "MSK broker instance type."\n  type        = string\n  default     = "kafka.m5.large"' "production-shared defaults MSK to an IAM-ready broker class"
  assert_contains "$variables_tf" 'variable "shared_base_chain_id"' "production-shared exposes base chain id input"
  assert_contains "$variables_tf" 'variable "shared_deposit_image_id"' "production-shared exposes deposit image id input"
  assert_contains "$variables_tf" 'variable "shared_withdraw_image_id"' "production-shared exposes withdraw image id input"
  assert_contains "$main_tf" 'local.shared_proof_requestor_command' "production-shared requestor task uses generated command"
  assert_contains "$main_tf" '"--sp1-requestor-address", local.shared_sp1_requestor_address' "production-shared requestor command includes requestor address"
  assert_contains "$main_tf" '"--chain-id", tostring(var.shared_base_chain_id)' "production-shared requestor command includes chain id"
  assert_contains "$main_tf" '"--postgres-dsn-env", "POSTGRES_DSN"' "production-shared requestor command resolves DSN from secret-backed env"
  assert_not_contains "$main_tf" '"--postgres-dsn", local.shared_postgres_dsn' "production-shared does not expose Postgres DSN in ECS command lines"
  assert_contains "$main_tf" '"--queue-brokers", local.shared_kafka_bootstrap_brokers' "production-shared proof tasks use IAM kafka brokers"
  assert_contains "$main_tf" 'local.shared_proof_funder_command' "production-shared funder task uses generated command"
  assert_contains "$main_tf" 'name      = "POSTGRES_DSN"' "production-shared injects Postgres DSN as an ECS secret"
  assert_contains "$main_tf" 'valueFrom = aws_secretsmanager_secret.shared_postgres_dsn.arn' "production-shared ECS DSN secret comes from dedicated secret ARN"
  assert_contains "$main_tf" '"--min-balance-wei", tostring(local.shared_sp1_required_credit_buffer)' "production-shared funder command includes min balance"
  assert_contains "$main_tf" '"--critical-balance-wei", tostring(local.shared_sp1_projected_with_overhead)' "production-shared funder command includes critical balance"
  assert_contains "$main_tf" 'name  = "JUNO_QUEUE_KAFKA_AUTH_MODE"' "production-shared proof task env includes kafka auth mode"
  assert_contains "$main_tf" 'value = "aws-msk-iam"' "production-shared proof task env enforces aws-msk-iam"
  assert_contains "$main_tf" 'name  = "JUNO_QUEUE_KAFKA_AWS_REGION"' "production-shared proof task env includes kafka aws region"
  assert_contains "$main_tf" 'value = var.aws_region' "production-shared proof task env propagates aws region"
  assert_contains "$main_tf" 'connectivity_info {' "production-shared configures explicit MSK broker connectivity"
  assert_contains "$main_tf" 'vpc_connectivity {' "production-shared enables explicit VPC connectivity settings for MSK"
  assert_contains "$main_tf" 'client_authentication {' "production-shared renders VPC connectivity auth settings"
  assert_contains "$main_tf" 'sasl {' "production-shared renders VPC connectivity SASL settings"
  assert_contains "$main_tf" 'iam = true' "production-shared enables IAM auth on VPC-connected brokers"
  assert_contains "$main_tf" 'name  = "SP1_NETWORK_RPC_URL"' "production-shared proof task env includes SP1 rpc url"
  assert_contains "$main_tf" 'name  = "SP1_DEPOSIT_PROGRAM_URL"' "production-shared proof task env includes deposit program url"
  assert_contains "$main_tf" 'name  = "SP1_WITHDRAW_PROGRAM_URL"' "production-shared proof task env includes withdraw program url"
  assert_contains "$main_tf" 'shared_sp1_requestor_address must be set when shared_ecs_desired_count > 0' "production-shared blocks active proof services without requestor address"
  assert_contains "$main_tf" 'task_role_arn            = aws_iam_role.proof_requestor_task.arn' "requestor task definition uses dedicated runtime role"
  assert_contains "$main_tf" 'task_role_arn            = aws_iam_role.proof_funder_task.arn' "funder task definition uses dedicated runtime role"
  assert_contains "$main_tf" 'sid = "AllowMSKConnect"' "proof runtime task roles can connect to MSK"
  assert_contains "$main_tf" 'sid = "AllowReadProofRequestsTopic"' "requestor task role can read proof request topic"
  assert_contains "$main_tf" 'sid = "AllowWriteProofResultsTopic"' "requestor task role can write fulfillment topic"
  assert_contains "$main_tf" 'sid = "AllowWriteProofFailuresTopic"' "requestor task role can write failure topic"
  assert_contains "$main_tf" 'sid = "AllowReadProofRequestorGroup"' "requestor task role can use its consumer group"
  assert_contains "$main_tf" 'sid = "AllowWriteOpsAlertsTopic"' "funder task role can emit ops alerts"

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
