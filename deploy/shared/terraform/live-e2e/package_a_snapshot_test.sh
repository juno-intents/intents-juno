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
  local main_tf variables_tf
  main_tf="$(cat "$SCRIPT_DIR/main.tf")"
  variables_tf="$(cat "$SCRIPT_DIR/variables.tf")"

  assert_contains "$variables_tf" 'variable "shared_sp1_funder_secret_arn"' "live-e2e exposes distinct proof funder secret input"
  assert_contains "$variables_tf" 'variable "shared_sp1_requestor_address"' "live-e2e exposes shared proof requestor address input"
  assert_contains "$variables_tf" 'variable "shared_base_chain_id"' "live-e2e exposes base chain id input for proof request IDs"
  assert_contains "$variables_tf" 'variable "shared_deposit_image_id"' "live-e2e exposes deposit image id input"
  assert_contains "$variables_tf" 'variable "shared_withdraw_image_id"' "live-e2e exposes withdraw image id input"
  assert_contains "$variables_tf" $'variable "shared_ecs_desired_count" {\n  description = "Desired task count for each shared proof service ECS service (proof-requestor and proof-funder)."\n  type        = number\n  default     = 1' "live-e2e enables proof services by default"
  assert_contains "$variables_tf" 'If empty, the first two private subnets in distinct AZs in the selected VPC are used.' "live-e2e documents private shared subnet auto-selection"
  assert_contains "$main_tf" $'allowed_checkpoint_signer_kms_key_arns = sort(distinct(concat(\n    [aws_kms_key.dkg.arn],' "live-e2e auto-includes the managed dkg kms key in checkpoint signer allowlists"

  assert_contains "$main_tf" '"/usr/local/bin/proof-requestor"' "live-e2e requestor still launches proof-requestor binary"
  assert_contains "$main_tf" '"--postgres-dsn"' "live-e2e requestor command includes postgres dsn"
  assert_contains "$main_tf" '"--owner"' "live-e2e requestor command includes owner"
  assert_contains "$main_tf" '"--sp1-requestor-address"' "live-e2e requestor command includes requestor address"
  assert_contains "$main_tf" '"--sp1-requestor-key-secret-arn"' "live-e2e requestor command includes requestor key reference"
  assert_contains "$main_tf" '"--chain-id"' "live-e2e requestor command includes chain id"
  assert_contains "$main_tf" '"--queue-brokers"' "live-e2e requestor command includes kafka brokers"
  assert_contains "$main_tf" '"--sp1-bin"' "live-e2e requestor command includes prover adapter binary"
  assert_contains "$main_tf" 'name      = "PROOF_REQUESTOR_KEY"' "live-e2e requestor task keeps requestor secret name"

  assert_contains "$main_tf" '"/usr/local/bin/proof-funder"' "live-e2e funder still launches proof-funder binary"
  assert_contains "$main_tf" '"--owner-id"' "live-e2e funder command includes owner id"
  assert_contains "$main_tf" '"--min-balance-wei"' "live-e2e funder command includes minimum balance threshold"
  assert_contains "$main_tf" '"--critical-balance-wei"' "live-e2e funder command includes critical balance threshold"
  assert_contains "$main_tf" 'name      = "PROOF_FUNDER_KEY"' "live-e2e funder task keeps funder secret name"
  assert_contains "$main_tf" 'valueFrom = local.shared_sp1_funder_secret_arn' "live-e2e funder task uses funder secret ARN"

  assert_contains "$main_tf" 'name  = "SP1_NETWORK_RPC_URL"' "live-e2e proof task env includes SP1 rpc url"
  assert_contains "$main_tf" 'name  = "SP1_DEPOSIT_PROGRAM_URL"' "live-e2e proof task env includes deposit program url"
  assert_contains "$main_tf" 'name  = "SP1_WITHDRAW_PROGRAM_URL"' "live-e2e proof task env includes withdraw program url"
  assert_contains "$main_tf" 'name  = "SP1_DEPOSIT_PROGRAM_VKEY"' "live-e2e proof task env includes deposit vkey"
  assert_contains "$main_tf" 'name  = "SP1_WITHDRAW_PROGRAM_VKEY"' "live-e2e proof task env includes withdraw vkey"

  assert_contains "$variables_tf" 'Required when provision_shared_services is true' "live-e2e documents explicit proof image requirement"
  assert_contains "$main_tf" 'shared_proof_service_image must be set when provision_shared_services=true.' "live-e2e fails closed without explicit proof image"
  assert_contains "$main_tf" 'shared_proof_service_image         = trimspace(var.shared_proof_service_image)' "live-e2e uses explicit proof image input directly"
  assert_not_contains "$main_tf" 'repository_url}:latest' "live-e2e no longer defaults proof services to empty terraform-managed latest tag"
  assert_contains "$main_tf" '!local.shared_proof_runtime_enabled || local.shared_sp1_requestor_address != ""' "live-e2e gates active proof services behind runtime contract"
  assert_contains "$main_tf" 'shared_sp1_requestor_address must be set when shared_ecs_desired_count > 0' "live-e2e blocks active proof services without requestor address"
  assert_contains "$main_tf" 'private_subnets_by_az' "live-e2e derives shared subnets from private subnets only"
  assert_contains "$main_tf" 'if !s.map_public_ip_on_launch' "live-e2e filters public subnets out of shared subnet auto-selection"
  assert_contains "$main_tf" 'check "shared_ecs_private_subnets_when_no_public_ip"' "live-e2e guards shared ECS subnet/public-ip compatibility"
  assert_contains "$main_tf" 'shared proof services require private shared_subnet_ids when shared_ecs_assign_public_ip=false.' "live-e2e fails closed on public shared subnets without public IPs"

  printf 'live_e2e package_a_snapshot_test: PASS\n'
}

main "$@"
