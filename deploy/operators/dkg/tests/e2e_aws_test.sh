#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: unexpected=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

test_remote_prepare_script_waits_for_cloud_init_and_retries_apt() {
  # shellcheck source=../e2e/run-testnet-e2e-aws.sh
  source "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

  local script_text
  script_text="$(build_remote_prepare_script deadbeef)"

  assert_contains "$script_text" "cloud-init status --wait" "cloud-init wait"
  assert_contains "$script_text" "for attempt in \$(seq 1 30)" "apt retry loop"
  assert_contains "$script_text" "run_apt_with_retry update -y" "apt update command"
  assert_contains "$script_text" "run_apt_with_retry install -y build-essential" "apt install command"
  assert_contains "$script_text" "for attempt in \$(seq 1 3)" "generic retry loop"
  assert_contains "$script_text" "rustup toolchain install 1.91.1 --profile minimal" "rust toolchain pin install"
  assert_contains "$script_text" "rustup default 1.91.1" "rust toolchain pin default"
  assert_contains "$script_text" "boundless_cli_target_version=\"1.2.0\"" "boundless target version pin"
  assert_contains "$script_text" "boundless_ref_tag=\"v1.2.1\"" "boundless git tag fallback pin"
  assert_contains "$script_text" "boundless_release_branch=\"release-1.2\"" "boundless release branch fallback pin"
  assert_contains "$script_text" "boundless-cli already installed at target version; skipping reinstall" "boundless install skip log"
  assert_contains "$script_text" "if run_with_retry cargo +1.91.1 install boundless-cli --version \"\$boundless_cli_target_version\" --locked --force; then" "boundless crates install attempt"
  assert_contains "$script_text" "boundless-cli \$boundless_cli_target_version is unavailable on crates.io; falling back to git tag \$boundless_ref_tag" "boundless crates fallback log"
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 install boundless-cli --git https://github.com/boundless-xyz/boundless --tag \"\$boundless_ref_tag\" --locked --force" "boundless git fallback install command"
  assert_contains "$script_text" "boundless-cli \$boundless_cli_target_version install from git tag failed; falling back to branch \$boundless_release_branch with parser workaround" "boundless release branch fallback log"
  assert_contains "$script_text" "git clone --depth 1 --branch \"\$boundless_release_branch\" https://github.com/boundless-xyz/boundless \"\$boundless_source_dir\"" "boundless release branch clone"
  assert_contains "$script_text" "perl -0pi -e" "boundless parser workaround patch command"
  assert_contains "$script_text" "__BOUNDLESS_DUMMY__ {{ __BOUNDLESS_DUMMY_VALUE__ }}" "boundless parser workaround uses escaped format braces"
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 install --path \"\$boundless_source_dir/crates/boundless-cli\" --locked --force" "boundless branch path install command"
  assert_contains "$script_text" "installing rzup for risc0 toolchain" "rzup install log"
  assert_contains "$script_text" "run_with_retry rzup install" "rzup install command"
  assert_contains "$script_text" "command -v r0vm" "r0vm presence check"
  assert_contains "$script_text" "r0vm --version" "r0vm version check"
  assert_contains "$script_text" "boundless --version" "boundless version check"
  assert_not_contains "$script_text" "boundless-market-0.14.1" "legacy boundless crate pin removed"
}

test_runner_shared_probe_script_supports_managed_endpoints() {
  # shellcheck source=../e2e/run-testnet-e2e-aws.sh
  source "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

  local script_text
  script_text="$(
    build_runner_shared_probe_script \
      "juno-live-e2e.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com" \
      "5432" \
      "b-1.juno-live-e2e.kafka.us-east-1.amazonaws.com:9094,b-2.juno-live-e2e.kafka.us-east-1.amazonaws.com:9094"
  )"

  assert_contains "$script_text" "timeout 2 bash -lc '</dev/tcp/juno-live-e2e.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com/5432'" "aurora readiness check"
  assert_contains "$script_text" "IFS=',' read -r -a broker_list <<<" "broker split"
  assert_contains "$script_text" "for broker in \"\${broker_list[@]}\"; do" "broker iteration"
  assert_contains "$script_text" "timeout 2 bash -lc \"</dev/tcp/\${broker_host}/\${broker_port}\"" "broker tcp checks"
  assert_not_contains "$script_text" "intents-shared-postgres" "no docker postgres container bootstrap"
  assert_not_contains "$script_text" "intents-shared-kafka" "no docker kafka container bootstrap"
}

test_remote_operator_prepare_script_boots_full_stack_services() {
  # shellcheck source=../e2e/run-testnet-e2e-aws.sh
  source "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

  local script_text
  script_text="$(build_remote_operator_prepare_script deadbeef)"

  assert_contains "$script_text" "required_services=(" "operator prep defines required services"
  assert_contains "$script_text" "junocashd.service" "operator prep requires junocashd"
  assert_contains "$script_text" "juno-scan.service" "operator prep requires juno-scan"
  assert_contains "$script_text" "checkpoint-signer.service" "operator prep requires checkpoint signer"
  assert_contains "$script_text" "checkpoint-aggregator.service" "operator prep requires checkpoint aggregator"
  assert_contains "$script_text" "tss-host.service" "operator prep requires tss-host"
  assert_contains "$script_text" "systemctl cat \"\$svc\"" "operator prep validates service units exist"
  assert_contains "$script_text" "systemctl enable \"\${required_services[@]}\"" "operator prep enables full stack services"
  assert_contains "$script_text" "systemctl restart \"\${required_services[@]}\"" "operator prep restarts full stack services"
  assert_contains "$script_text" "systemctl is-active --quiet \"\$svc\"" "operator prep verifies services are active"
  assert_contains "$script_text" "operator host is missing required stack service unit" "operator prep fails when stack service unit is missing"
}

test_live_e2e_terraform_supports_operator_instances() {
  local main_tf variables_tf outputs_tf
  main_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/main.tf")"
  variables_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/variables.tf")"
  outputs_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/outputs.tf")"

  assert_contains "$variables_tf" "variable \"operator_instance_count\"" "operator instance count variable"
  assert_contains "$variables_tf" "variable \"operator_instance_type\"" "operator instance type variable"
  assert_contains "$variables_tf" "variable \"runner_ami_id\"" "runner ami variable"
  assert_contains "$variables_tf" "variable \"operator_ami_id\"" "operator ami variable"
  assert_contains "$variables_tf" "variable \"shared_ami_id\"" "shared ami variable"
  assert_contains "$variables_tf" "variable \"operator_root_volume_size_gb\"" "operator root volume variable"
  assert_contains "$variables_tf" "variable \"operator_base_port\"" "operator base port variable"
  assert_contains "$variables_tf" "variable \"runner_associate_public_ip_address\"" "runner public ip toggle variable"
  assert_contains "$variables_tf" "variable \"operator_associate_public_ip_address\"" "operator public ip toggle variable"
  assert_contains "$variables_tf" "variable \"shared_ecs_assign_public_ip\"" "shared ecs public ip toggle variable"
  assert_contains "$variables_tf" "variable \"shared_subnet_ids\"" "shared subnet override variable"
  assert_contains "$variables_tf" "variable \"dkg_s3_key_prefix\"" "dkg s3 prefix variable"
  assert_contains "$variables_tf" "variable \"provision_shared_services\"" "shared services toggle variable"

  assert_contains "$main_tf" "resource \"aws_security_group\" \"operator\"" "operator security group resource"
  assert_contains "$main_tf" "resource \"aws_instance\" \"operator\"" "operator instance resource"
  assert_contains "$main_tf" "resource \"aws_kms_key\" \"dkg\"" "dkg kms key resource"
  assert_contains "$main_tf" "resource \"aws_s3_bucket\" \"dkg_keypackages\"" "dkg s3 bucket resource"
  assert_contains "$main_tf" "resource \"aws_iam_instance_profile\" \"live_e2e\"" "managed instance profile resource"
  assert_contains "$main_tf" "resource \"aws_rds_cluster\" \"shared\"" "aurora shared cluster resource"
  assert_contains "$main_tf" "resource \"aws_msk_cluster\" \"shared\"" "msk shared cluster resource"
  assert_contains "$main_tf" "resource \"aws_ecs_cluster\" \"shared\"" "ecs shared cluster resource"
  assert_contains "$main_tf" "resource \"aws_ecr_repository\" \"proof_services\"" "proof services ecr repository resource"
  assert_contains "$main_tf" "resource \"aws_ecs_service\" \"proof_requestor\"" "ecs proof requestor service resource"
  assert_contains "$main_tf" "resource \"aws_ecs_service\" \"proof_funder\"" "ecs proof funder service resource"
  assert_contains "$main_tf" "client_broker = \"TLS\"" "msk tls-only client transport"
  assert_not_contains "$main_tf" "TLS_PLAINTEXT" "msk plaintext transport disabled"
  assert_not_contains "$main_tf" "unauthenticated = true" "msk unauthenticated mode disabled"
  assert_not_contains "$main_tf" "map-public-ip-on-launch" "no hard public-subnet lookup dependency"
  assert_not_contains "$main_tf" "public.ecr.aws/docker/library/busybox:1.36.1" "busybox placeholder image removed"
  assert_contains "$main_tf" "resource \"aws_autoscaling_group\" \"ipfs\"" "ipfs asg resource"
  assert_contains "$main_tf" "resource \"aws_lb\" \"ipfs\"" "ipfs nlb resource"
  assert_contains "$main_tf" "count = var.operator_instance_count" "operator instance count wiring"
  assert_contains "$main_tf" "from_port       = var.operator_base_port" "operator grpc ingress start"
  assert_contains "$main_tf" "to_port         = var.operator_base_port + var.operator_instance_count - 1" "operator grpc ingress range"
  assert_contains "$main_tf" "ami                    = local.operator_ami_id" "operator ami wiring"

  assert_contains "$outputs_tf" "output \"operator_instance_ids\"" "operator ids output"
  assert_contains "$outputs_tf" "output \"operator_public_ips\"" "operator public ip output"
  assert_contains "$outputs_tf" "output \"operator_private_ips\"" "operator private ip output"
  assert_contains "$outputs_tf" "output \"dkg_kms_key_arn\"" "dkg kms output"
  assert_contains "$outputs_tf" "output \"dkg_s3_bucket\"" "dkg s3 bucket output"
  assert_contains "$outputs_tf" "output \"dkg_s3_key_prefix\"" "dkg s3 prefix output"
  assert_contains "$outputs_tf" "output \"shared_postgres_endpoint\"" "aurora endpoint output"
  assert_contains "$outputs_tf" "output \"shared_kafka_bootstrap_brokers\"" "msk brokers output"
  assert_contains "$outputs_tf" "output \"shared_ecs_cluster_arn\"" "ecs cluster output"
  assert_contains "$outputs_tf" "output \"shared_proof_funder_service_name\"" "ecs proof funder output"
  assert_contains "$outputs_tf" "output \"shared_proof_services_ecr_repository_url\"" "proof services ecr repository output"
  assert_contains "$outputs_tf" "output \"shared_ipfs_api_url\"" "ipfs api output"
  assert_not_contains "$outputs_tf" "output \"shared_public_ip\"" "legacy shared host output removed"
  assert_not_contains "$outputs_tf" "output \"shared_private_ip\"" "legacy shared host private ip output removed"
}

test_synced_junocashd_ami_runbook_exists() {
  local runbook_text
  runbook_text="$(cat "$REPO_ROOT/deploy/shared/runbooks/create-synced-junocashd-ami.sh")"

  assert_contains "$runbook_text" "create-synced-junocashd-ami.sh create" "ami runbook usage"
  assert_contains "$runbook_text" "--instance-id" "ami runbook instance id option"
  assert_contains "$runbook_text" "--aws-region" "ami runbook aws region option"
  assert_contains "$runbook_text" "ec2 create-image" "ami runbook create-image call"
  assert_contains "$runbook_text" "ec2 wait image-available" "ami runbook wait for image availability"
}

test_aws_wrapper_uses_ssh_keepalive_options() {
  local wrapper_script
  local keepalive_count
  wrapper_script="$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

  keepalive_count="$(grep -o 'ServerAliveInterval=30' "$wrapper_script" | wc -l | tr -d ' ')"
  if (( keepalive_count < 6 )); then
    printf 'assert_keepalive_count failed: expected at least 6, got=%s\n' "$keepalive_count" >&2
    exit 1
  fi

  local keepalive_max_count
  keepalive_max_count="$(grep -o 'ServerAliveCountMax=6' "$wrapper_script" | wc -l | tr -d ' ')"
  if (( keepalive_max_count < 6 )); then
    printf 'assert_keepalive_max_count failed: expected at least 6, got=%s\n' "$keepalive_max_count" >&2
    exit 1
  fi
}

test_aws_wrapper_supports_operator_fleet_and_distributed_dkg() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "--operator-instance-count" "operator instance count option"
  assert_contains "$wrapper_script_text" "--operator-instance-type" "operator instance type option"
  assert_contains "$wrapper_script_text" "--runner-ami-id" "runner ami option"
  assert_contains "$wrapper_script_text" "--operator-ami-id" "operator ami option"
  assert_contains "$wrapper_script_text" "--shared-ami-id" "shared ami option"
  assert_contains "$wrapper_script_text" "--runner-associate-public-ip-address" "runner public ip override option"
  assert_contains "$wrapper_script_text" "--operator-associate-public-ip-address" "operator public ip override option"
  assert_contains "$wrapper_script_text" "--shared-ecs-assign-public-ip" "shared ecs public ip override option"
  assert_contains "$wrapper_script_text" "--dkg-s3-key-prefix" "dkg s3 prefix option"
  assert_contains "$wrapper_script_text" "--operator-root-volume-gb" "operator root volume option"
  assert_contains "$wrapper_script_text" "operator_instance_count" "terraform operator count wiring"
  assert_contains "$wrapper_script_text" "operator_instance_type" "terraform operator type wiring"
  assert_contains "$wrapper_script_text" "runner_ami_id" "terraform runner ami wiring"
  assert_contains "$wrapper_script_text" "operator_ami_id" "terraform operator ami wiring"
  assert_contains "$wrapper_script_text" "shared_ami_id" "terraform shared ami wiring"
  assert_contains "$wrapper_script_text" "dkg_s3_key_prefix" "terraform dkg s3 prefix wiring"
  assert_contains "$wrapper_script_text" "operator_root_volume_size_gb" "terraform operator root volume wiring"
  assert_contains "$wrapper_script_text" "shared_postgres_password" "terraform shared postgres password wiring"
  assert_contains "$wrapper_script_text" "shared_boundless_requestor_secret_arn" "terraform boundless requestor secret arn wiring"
  assert_not_contains "$wrapper_script_text" "shared_boundless_requestor_private_key" "terraform boundless requestor private key tfvars wiring removed"
  assert_contains "$wrapper_script_text" "dkg_kms_key_arn" "terraform dkg kms output usage"
  assert_contains "$wrapper_script_text" "dkg_s3_bucket" "terraform dkg bucket output usage"
  assert_contains "$wrapper_script_text" "operator-export-kms.sh export" "operator kms export invocation"
  assert_contains "$wrapper_script_text" "remote_prepare_operator_host" "remote operator host preparation hook"
  assert_contains "$wrapper_script_text" "run_distributed_dkg_backup_restore" "distributed dkg orchestration hook"
  assert_contains "$wrapper_script_text" "--dkg-summary-path" "external dkg summary forwarding"
  assert_contains "$wrapper_script_text" "-json operator_public_ips" "terraform operator public ips output retrieval"
  assert_contains "$wrapper_script_text" "-json operator_private_ips" "terraform operator private ips output retrieval"
  assert_not_contains "$wrapper_script_text" "--argjson runner_associate_public_ip_address \"true\"" "runner public ip no longer hardcoded true"
  assert_not_contains "$wrapper_script_text" "--argjson operator_associate_public_ip_address \"true\"" "operator public ip no longer hardcoded true"
  assert_not_contains "$wrapper_script_text" "--argjson shared_ecs_assign_public_ip \"true\"" "shared ecs public ip no longer hardcoded true"
}

test_aws_wrapper_collects_artifacts_after_remote_failures() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "local remote_run_status=0" "remote run status capture"
  assert_contains "$wrapper_script_text" "set +e" "remote run temporary errexit disable"
  assert_contains "$wrapper_script_text" "remote_run_status=$?" "remote run exit capture"
  assert_contains "$wrapper_script_text" "log \"collecting artifacts\"" "artifact collection after remote run"
  assert_contains "$wrapper_script_text" '$remote_workdir/reports' "report artifacts collected"
  assert_not_contains "$wrapper_script_text" '$runner_ssh_user@$runner_public_ip:$remote_workdir/dkg' "raw dkg directory artifact collection removed"
  assert_not_contains "$wrapper_script_text" '$runner_ssh_user@$runner_public_ip:$remote_workdir/dkg-distributed' "raw distributed dkg directory artifact collection removed"
  assert_contains "$wrapper_script_text" "log \"juno_tx_hash=\$juno_tx_hash source=\$juno_tx_hash_source\"" "juno tx hash log when available"
  assert_contains "$wrapper_script_text" "log \"juno_tx_hash=unavailable\"" "juno tx hash unavailable log"
  assert_contains "$wrapper_script_text" ".bridge.report.juno.proof_of_execution.tx_hash?" "wrapper checks canonical juno proof path"
  assert_contains "$wrapper_script_text" ".juno.tx_hash_source? // .bridge.report.juno.proof_of_execution.source?" "wrapper checks canonical juno proof source path"
  assert_not_contains "$wrapper_script_text" ".bridge.report.transactions.finalize_withdraw?" "wrapper no longer accepts base finalize withdraw as juno hash fallback"
  assert_contains "$wrapper_script_text" "keep-infra enabled after failure; leaving resources up" "keep-infra failure retention log"
  assert_contains "$wrapper_script_text" "cleanup_enabled=\"false\"" "keep-infra disables cleanup on failure"
  assert_contains "$wrapper_script_text" 'remote live e2e run failed (status=$remote_run_status)' "remote failure reported after artifact collection"
}

test_aws_wrapper_wires_shared_services_into_remote_e2e() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "--without-shared-services" "shared services toggle option"
  assert_contains "$wrapper_script_text" "shared_postgres_password=\"\$(openssl rand -hex 16)\"" "shared postgres password generation"
  assert_contains "$wrapper_script_text" "provision_shared_services" "terraform shared services flag"
  assert_contains "$wrapper_script_text" "shared_postgres_dsn=\"postgres://" "shared postgres dsn assembly"
  assert_contains "$wrapper_script_text" "sslmode=require" "shared postgres uses tls mode for aurora"
  assert_contains "$wrapper_script_text" "shared_kafka_brokers=\"\$shared_kafka_bootstrap_brokers\"" "shared kafka brokers assembly"
  assert_contains "$wrapper_script_text" "-raw shared_ipfs_api_url" "shared ipfs api output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_postgres_endpoint" "shared postgres endpoint output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_kafka_bootstrap_brokers" "shared kafka bootstrap output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_ecs_cluster_arn" "shared ecs cluster output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_proof_requestor_service_name" "shared proof requestor output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_proof_funder_service_name" "shared proof funder output retrieval"
  assert_contains "$wrapper_script_text" "-raw shared_proof_services_ecr_repository_url" "proof services ecr repository output retrieval"
  assert_contains "$wrapper_script_text" "docker buildx build --platform linux/amd64" "proof services image build invocation"
  assert_contains "$wrapper_script_text" "aws ecr get-login-password" "proof services ecr login"
  assert_contains "$wrapper_script_text" "aws ecs update-service" "proof services ecs rollout"
  assert_not_contains "$wrapper_script_text" "-raw shared_public_ip" "no shared host public ip output retrieval"
  assert_not_contains "$wrapper_script_text" "remote_prepare_shared_host" "no shared host preparation hook"
  assert_not_contains "$wrapper_script_text" "shared services reported ready despite ssh exit status" "no shared host bootstrap fallback"
  assert_not_contains "$wrapper_script_text" "shared connectivity reported ready despite ssh exit status" "no ssh fallback for managed shared stack"
  assert_contains "$wrapper_script_text" "wait_for_shared_connectivity_from_runner" "runner-to-shared readiness gate"
  assert_contains "$wrapper_script_text" "shared service remote args assembled" "shared args assembly logging"
  assert_contains "$wrapper_script_text" "assembling remote e2e arguments" "remote args assembly logging"
  assert_contains "$wrapper_script_text" "failed to build remote command line" "remote args assembly error message"
  assert_contains "$wrapper_script_text" "\"--shared-postgres-dsn\" \"\$shared_postgres_dsn\"" "remote shared postgres arg"
  assert_contains "$wrapper_script_text" "\"--shared-kafka-brokers\" \"\$shared_kafka_brokers\"" "remote shared kafka arg"
  assert_contains "$wrapper_script_text" "\"--shared-ipfs-api-url\" \"\$shared_ipfs_api_url\"" "remote shared ipfs arg"
  assert_contains "$wrapper_script_text" "\"--shared-ecs-cluster-arn\" \"\$shared_ecs_cluster_arn\"" "remote shared ecs cluster arg"
  assert_contains "$wrapper_script_text" "\"--shared-proof-requestor-service-name\" \"\$shared_proof_requestor_service_name\"" "remote shared proof requestor arg"
  assert_contains "$wrapper_script_text" "\"--shared-proof-funder-service-name\" \"\$shared_proof_funder_service_name\"" "remote shared proof funder arg"
  assert_contains "$wrapper_script_text" "operator-fleet-ssh.key" "aws wrapper stages operator ssh key on runner for witness tunnel"
  assert_contains "$wrapper_script_text" "--boundless-witness-juno-scan-url\" \"\$witness_juno_scan_url\"" "aws wrapper forwards stack-derived witness scan endpoint"
  assert_contains "$wrapper_script_text" "--boundless-witness-juno-rpc-url\" \"\$witness_juno_rpc_url\"" "aws wrapper forwards stack-derived witness rpc endpoint"
  assert_contains "$wrapper_script_text" "overriding forwarded --boundless-witness-juno-scan-url with stack-derived witness tunnel endpoint" "aws wrapper overrides external witness scan endpoint"
  assert_contains "$wrapper_script_text" "overriding forwarded --boundless-witness-juno-rpc-url with stack-derived witness tunnel endpoint" "aws wrapper overrides external witness rpc endpoint"
  assert_contains "$wrapper_script_text" "-L \"127.0.0.1:\${witness_tunnel_scan_port}:127.0.0.1:8080\"" "aws wrapper opens runner-local tunnel to operator juno-scan"
  assert_contains "$wrapper_script_text" "-L \"127.0.0.1:\${witness_tunnel_rpc_port}:127.0.0.1:18232\"" "aws wrapper opens runner-local tunnel to operator junocashd rpc"
  assert_not_contains "$wrapper_script_text" "--boundless-deposit-witness-txid" "aws wrapper no longer forwards external deposit txid"
  assert_not_contains "$wrapper_script_text" "--boundless-withdraw-witness-txid" "aws wrapper no longer forwards external withdraw txid"
}

test_local_e2e_supports_shared_infra_validation() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "--shared-postgres-dsn" "shared postgres option"
  assert_contains "$e2e_script_text" "--shared-kafka-brokers" "shared kafka option"
  assert_contains "$e2e_script_text" "--shared-ipfs-api-url" "shared ipfs api option"
  assert_contains "$e2e_script_text" "--shared-ecs-cluster-arn" "shared ecs cluster option"
  assert_contains "$e2e_script_text" "--shared-proof-requestor-service-name" "shared proof requestor service option"
  assert_contains "$e2e_script_text" "--shared-proof-funder-service-name" "shared proof funder service option"
  assert_contains "$e2e_script_text" "--shared-postgres-dsn is required (centralized proof-requestor/proof-funder topology)" "shared postgres required message"
  assert_contains "$e2e_script_text" "--shared-kafka-brokers is required (centralized proof-requestor/proof-funder topology)" "shared kafka required message"
  assert_contains "$e2e_script_text" "--shared-ipfs-api-url is required (operator checkpoint package pin/fetch verification)" "shared ipfs required message"
  assert_contains "$e2e_script_text" "go run ./cmd/shared-infra-e2e" "shared infra command invocation"
  assert_contains "$e2e_script_text" "--checkpoint-ipfs-api-url \"\$shared_ipfs_api_url\"" "shared infra ipfs checkpoint package verification wiring"
  assert_contains "$e2e_script_text" "--checkpoint-min-persisted-at \"\$checkpoint_started_at\"" "shared checkpoint validation is run-bound"
  assert_contains "$e2e_script_text" "go run ./cmd/checkpoint-aggregator" "checkpoint aggregator startup in local e2e"
  assert_contains "$e2e_script_text" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "checkpoint signer private key env wiring"
  assert_contains "$e2e_script_text" "while IFS= read -r operator_key_file;" "checkpoint signers derived from dkg summary operator keys"
  assert_contains "$e2e_script_text" "aws ecs register-task-definition" "proof services ecs task definition rollout"
  assert_contains "$e2e_script_text" "aws ecs update-service" "proof services ecs service update"
  assert_contains "$e2e_script_text" "aws ecs wait services-stable" "proof services ecs stability wait"
  assert_contains "$e2e_script_text" "--boundless-proof-submission-mode" "bridge forwards proof submission mode"
  assert_contains "$e2e_script_text" "\"--boundless-proof-submission-mode\" \"\$boundless_proof_submission_mode\"" "bridge uses centralized proof submission mode value"
  assert_contains "$e2e_script_text" "\"--boundless-proof-request-topic\" \"\$proof_request_topic\"" "bridge forwards proof request topic"
  assert_contains "$e2e_script_text" "\"--boundless-proof-result-topic\" \"\$proof_result_topic\"" "bridge forwards proof result topic"
  assert_contains "$e2e_script_text" "\"--boundless-proof-failure-topic\" \"\$proof_failure_topic\"" "bridge forwards proof failure topic"
  assert_contains "$e2e_script_text" "\"--boundless-proof-consumer-group\" \"\$proof_bridge_consumer_group\"" "bridge forwards proof consumer group"
  assert_not_contains "$e2e_script_text" "go run ./cmd/proof-requestor" "proof-requestor no longer runs ad hoc on runner"
  assert_not_contains "$e2e_script_text" "go run ./cmd/proof-funder" "proof-funder no longer runs ad hoc on runner"
  assert_not_contains "$e2e_script_text" "\"--boundless-requestor-key-file\" \"\$boundless_requestor_key_file\"" "bridge no longer submits directly with requestor key"
  assert_not_contains "$e2e_script_text" "run_with_rpc_retry 4 3 \"bridge-e2e\"" "bridge e2e should not be re-invoked on transient rpc wrapper retries"
  assert_contains "$e2e_script_text" "go run ./cmd/bridge-e2e \"\${bridge_args[@]}\"" "bridge e2e direct invocation"
  assert_contains "$e2e_script_text" "--boundless-input-mode" "boundless input mode option"
  assert_contains "$e2e_script_text" "local boundless_input_mode=\"guest-witness-v1\"" "boundless input mode default"
  assert_contains "$e2e_script_text" "\"--boundless-input-mode\" \"\$boundless_input_mode\"" "boundless input mode bridge forwarding"
  assert_contains "$e2e_script_text" "--boundless-deposit-owallet-ivk-hex" "boundless deposit ivk option"
  assert_contains "$e2e_script_text" "--boundless-withdraw-owallet-ovk-hex" "boundless withdraw ovk option"
  assert_contains "$e2e_script_text" "--boundless-witness-wallet-id" "witness wallet id override option"
  assert_contains "$e2e_script_text" "--boundless-witness-metadata-timeout-seconds" "witness metadata timeout option"
  assert_contains "$e2e_script_text" "generate-juno-witness-metadata.sh" "run-generated witness metadata command"
  assert_contains "$e2e_script_text" "generated-witness-metadata.json" "run-generated witness metadata output"
  assert_contains "$e2e_script_text" "compute-bridge-withdrawal-id.sh run" "bridge withdrawal id derived during run"
  assert_contains "$e2e_script_text" "go run ./cmd/juno-witness-extract deposit" "deposit witness extraction command"
  assert_contains "$e2e_script_text" "go run ./cmd/juno-witness-extract withdraw" "withdraw witness extraction command"
  assert_contains "$e2e_script_text" "JUNO_FUNDER_PRIVATE_KEY_HEX is required for run-generated witness metadata" "run-generated witness requires juno funder key env"
  assert_contains "$e2e_script_text" "--boundless-deposit-witness-item-file" "boundless deposit witness option"
  assert_contains "$e2e_script_text" "--boundless-withdraw-witness-item-file" "boundless withdraw witness option"
  assert_not_contains "$e2e_script_text" "--boundless-deposit-witness-wallet-id" "manual witness wallet id flag removed"
  assert_not_contains "$e2e_script_text" "--boundless-deposit-witness-txid" "manual deposit txid flag removed"
  assert_not_contains "$e2e_script_text" "--boundless-withdraw-witness-wallet-id" "manual withdraw wallet id flag removed"
  assert_not_contains "$e2e_script_text" "--boundless-withdraw-witness-txid" "manual withdraw txid flag removed"
  assert_not_contains "$e2e_script_text" "--boundless-withdraw-witness-withdrawal-id-hex" "manual withdraw id flag removed"
  assert_not_contains "$e2e_script_text" "--boundless-withdraw-witness-recipient-raw-address-hex" "manual recipient raw address flag removed"
  assert_contains "$e2e_script_text" "--bridge-deposit-checkpoint-height" "bridge deposit checkpoint height option"
  assert_contains "$e2e_script_text" "--bridge-deposit-checkpoint-block-hash" "bridge deposit checkpoint block hash option"
  assert_contains "$e2e_script_text" "--bridge-withdraw-checkpoint-height" "bridge withdraw checkpoint height option"
  assert_contains "$e2e_script_text" "--bridge-withdraw-checkpoint-block-hash" "bridge withdraw checkpoint block hash option"
  assert_contains "$e2e_script_text" "\"--deposit-checkpoint-height\" \"\$bridge_deposit_checkpoint_height\"" "bridge forwards deposit checkpoint height"
  assert_contains "$e2e_script_text" "\"--deposit-checkpoint-block-hash\" \"\$bridge_deposit_checkpoint_block_hash\"" "bridge forwards deposit checkpoint block hash"
  assert_contains "$e2e_script_text" "\"--withdraw-checkpoint-height\" \"\$bridge_withdraw_checkpoint_height\"" "bridge forwards withdraw checkpoint height"
  assert_contains "$e2e_script_text" "\"--withdraw-checkpoint-block-hash\" \"\$bridge_withdraw_checkpoint_block_hash\"" "bridge forwards withdraw checkpoint block hash"
  assert_contains "$e2e_script_text" ".anchor_block_hash // empty" "witness extraction includes anchor block hash wiring"
  assert_contains "$e2e_script_text" "juno_rpc_json_call" "juno rpc helper function exists"
  assert_contains "$e2e_script_text" "juno_rebroadcast_tx" "juno rebroadcast helper function exists"
  assert_contains "$e2e_script_text" "getrawtransaction" "juno rebroadcast fetches raw transaction"
  assert_contains "$e2e_script_text" "sendrawtransaction" "juno rebroadcast submits raw transaction"
  assert_contains "$e2e_script_text" "bridge_juno_execution_tx_hash=\"\$generated_withdraw_txid\"" "bridge auto-resolves canonical juno execution tx hash from generated withdraw txid"
  assert_contains "$e2e_script_text" "canonical juno execution tx hash is required" "bridge fails fast when canonical juno execution tx hash cannot be resolved"
  assert_contains "$e2e_script_text" "\"--juno-execution-tx-hash\" \"\$bridge_juno_execution_tx_hash\"" "bridge forwards canonical juno execution tx hash"
  assert_not_contains "$e2e_script_text" "--boundless-guest-witness-manifest" "legacy guest witness manifest option removed"
  assert_contains "$e2e_script_text" "boundless_input_mode == \"guest-witness-v1\"" "guest witness mode validation"
  assert_contains "$e2e_script_text" "guest_witness_auto_generate" "guest witness auto generate summary wiring"
  assert_not_contains "$e2e_script_text" "boundless_guest_witness_manifest" "guest witness manifest variable removed"
  assert_contains "$e2e_script_text" "--boundless-market-address" "boundless market option"
  assert_contains "$e2e_script_text" "--boundless-verifier-router-address" "boundless verifier router option"
  assert_contains "$e2e_script_text" "--boundless-set-verifier-address" "boundless set verifier option"
  assert_contains "$e2e_script_text" "\"--boundless-market-address\" \"\$boundless_market_address\"" "boundless market bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-verifier-router-address\" \"\$boundless_verifier_router_address\"" "boundless verifier router bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-set-verifier-address\" \"\$boundless_set_verifier_address\"" "boundless set verifier bridge forwarding"
  assert_contains "$e2e_script_text" "log \"juno_tx_hash=\$juno_tx_hash source=\$juno_tx_hash_source\"" "juno tx hash log when present"
  assert_contains "$e2e_script_text" "log \"juno_tx_hash=unavailable\"" "juno tx hash unavailable log"
  assert_contains "$e2e_script_text" ".juno.proof_of_execution.tx_hash?" "bridge summary checks canonical juno proof path"
  assert_contains "$e2e_script_text" "input.juno_execution_tx_hash" "bridge summary enforces canonical juno proof source"
  assert_not_contains "$e2e_script_text" ".transactions.finalize_withdraw?" "bridge summary does not accept base finalize withdraw fallback"
  assert_contains "$e2e_script_text" "bridge summary missing juno proof-of-execution tx hash" "bridge summary fails when proof hash missing"
  assert_contains "$e2e_script_text" "bridge summary juno proof source mismatch" "bridge summary fails on unexpected juno proof source"
  assert_contains "$e2e_script_text" "--arg juno_tx_hash \"\$juno_tx_hash\"" "summary receives juno tx hash"
  assert_contains "$e2e_script_text" "--arg juno_tx_hash_source \"\$juno_tx_hash_source\"" "summary receives juno tx hash source"
  assert_contains "$e2e_script_text" "tx_hash_source: (if \$juno_tx_hash_source == \"\" then null else \$juno_tx_hash_source end)" "summary stores juno tx hash source"
  assert_contains "$e2e_script_text" "tx_hash: (if \$juno_tx_hash == \"\" then null else \$juno_tx_hash end)" "summary stores juno tx hash"
  assert_contains "$e2e_script_text" "dkg_report_public_json" "summary builds redacted dkg report payload"
  assert_contains "$e2e_script_text" "operator_key_file" "summary redaction touches operator key path field"
  assert_contains "$e2e_script_text" "backup_package" "summary redaction touches backup package path field"
  assert_contains "$e2e_script_text" "shared_infra" "shared infra summary section"
  assert_contains "$e2e_script_text" "proof_topics" "shared summary includes proof topics"
  assert_contains "$e2e_script_text" "proof_services" "shared summary includes proof service metadata"
}

test_e2e_workflows_exclude_sensitive_artifact_paths() {
  local aws_workflow_text local_workflow_text
  aws_workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy-aws.yml")"
  local_workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy.yml")"

  assert_contains "$aws_workflow_text" '${{ runner.temp }}/aws-live-e2e/artifacts' "aws workflow uploads artifact directory"
  assert_not_contains "$aws_workflow_text" '${{ runner.temp }}/aws-live-e2e/infra' "aws workflow no longer uploads terraform infra dir"
  assert_contains "$local_workflow_text" '${{ runner.temp }}/testnet-e2e/reports' "local workflow uploads reports"
  assert_not_contains "$local_workflow_text" '${{ runner.temp }}/testnet-e2e/dkg' "local workflow no longer uploads raw dkg directory"
}

test_local_e2e_supports_external_dkg_summary_path() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "--dkg-summary-path" "external dkg summary option"
  assert_contains "$e2e_script_text" "dkg_summary_path" "external dkg summary variable"
  assert_contains "$e2e_script_text" "if [[ -n \"\$dkg_summary_path\" ]]; then" "external dkg summary conditional"
  assert_contains "$e2e_script_text" "deploy/operators/dkg/e2e/run-dkg-backup-restore.sh run" "local dkg fallback path retained"
}

test_local_e2e_uses_operator_deployer_key() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "bridge_deployer_key_file=\"\$(jq -r '.operators[0].operator_key_file // empty' \"\$dkg_summary\")\"" "bridge deployer key derived from first operator"
  assert_contains "$e2e_script_text" "\"--deployer-key-file\" \"\$bridge_deployer_key_file\"" "bridge deployer key forwarded"
  assert_contains "$e2e_script_text" "\"--operator-signer-bin\" \"\$bridge_operator_signer_bin\"" "bridge operator signer binary forwarded"
  assert_contains "$e2e_script_text" "bridge_args+=(\"--operator-address\" \"\$operator_id\")" "bridge operator address forwarded from dkg summary"
  assert_contains "$e2e_script_text" "bridge_args+=(\"--operator-signer-endpoint\" \"\$operator_endpoint\")" "bridge operator signer endpoint forwarded from dkg summary"
  assert_contains "$e2e_script_text" ".operators[] | [.operator_id, (.endpoint // .grpc_endpoint // \"\")] | @tsv" "operator endpoints sourced from dkg summary"
  assert_not_contains "$e2e_script_text" "bridge_args+=(\"--operator-key-file\"" "bridge operator key-file signing removed"
  assert_not_contains "$e2e_script_text" "\"--deployer-key-file\" \"\$base_funder_key_file\"" "bridge deployer no longer reuses funder key"
}

test_local_e2e_cast_send_handles_already_known_nonce_race() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "[[ \"\$lowered\" == *\"already known\"* ]]" "cast send already-known nonce race handling"
}

test_local_e2e_tops_up_bridge_deployer_balance() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "bridge_deployer_required_wei=\$((base_operator_fund_wei * 10))" "bridge deployer required balance baseline multiplier"
  assert_contains "$e2e_script_text" "bridge_deployer_min_wei=" "bridge deployer absolute minimum floor"
  assert_contains "$e2e_script_text" "if (( bridge_deployer_required_wei < bridge_deployer_min_wei )); then" "bridge deployer top-up floor check"
  assert_contains "$e2e_script_text" "bridge_deployer_required_wei=\"\$bridge_deployer_min_wei\"" "bridge deployer floor assignment"
  assert_contains "$e2e_script_text" "ensure_recipient_min_balance()" "min-balance funding helper"
  assert_contains "$e2e_script_text" "\$label balance below target" "bridge deployer top-up log"
  assert_contains "$e2e_script_text" "\"bridge deployer\"" "bridge deployer label passed to helper"
  assert_contains "$e2e_script_text" "failed to fund bridge deployer" "bridge deployer top-up hard failure"
}

test_local_e2e_uses_managed_nonce_for_funding() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "funding_sender_address=\"\$(cast wallet address --private-key \"\$base_key\")\"" "funding sender address derivation"
  assert_contains "$e2e_script_text" "nonce_has_advanced()" "nonce advancement helper"
  assert_contains "$e2e_script_text" "cast_send_with_nonce_retry()" "nonce-aware cast send helper"
  assert_contains "$e2e_script_text" "force_replace_stuck_nonce()" "stuck nonce replacement helper"
  assert_contains "$e2e_script_text" "cast send nonce race detected but sender nonce not advanced" "nonce race guarded by sender nonce advancement"
  assert_contains "$e2e_script_text" "--gas-limit 21000 \\" "funding sends pin transfer gas limit"
  assert_contains "$e2e_script_text" "--gas-price \"\$gas_price_wei\" \\" "nonce retries bump gas price"
  assert_contains "$e2e_script_text" "submitted stuck nonce replacement tx nonce=" "stuck nonce replacement log"
  assert_contains "$e2e_script_text" "replacement_prices_wei=(" "stuck nonce replacement gas ladder"
  assert_contains "$e2e_script_text" "nonce=\"\$(cast nonce --rpc-url \"\$rpc_url\" --block pending \"\$sender\" 2>/dev/null || true)\"" "nonce resolved per-send from pending state"
  assert_contains "$e2e_script_text" "--async \\" "async cast send to avoid receipt wait stalls"
  assert_contains "$e2e_script_text" "ensure_recipient_min_balance \"\$base_rpc_url\" \"\$base_key\" \"\$funding_sender_address\" \"\$operator\" \"\$base_operator_fund_wei\" \"operator pre-fund\"" "operator prefund uses min-balance helper"
}

test_non_aws_workflow_wires_shared_ipfs_for_local_e2e() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy.yml")"

  assert_contains "$workflow_text" "Start Shared Infra (Postgres + Kafka + IPFS)" "non-aws workflow shared infra step includes ipfs"
  assert_contains "$workflow_text" "docker rm -f intents-shared-postgres intents-shared-kafka intents-shared-ipfs" "non-aws workflow removes stale ipfs container"
  assert_contains "$workflow_text" "--name intents-shared-ipfs" "non-aws workflow starts shared ipfs container"
  assert_contains "$workflow_text" "ipfs/kubo:v0.32.1" "non-aws workflow pins shared ipfs image"
  assert_contains "$workflow_text" "E2E_SHARED_IPFS_API_URL=http://127.0.0.1:5001" "non-aws workflow exports shared ipfs api url"
  assert_contains "$workflow_text" "boundless_deposit_owallet_ivk_hex" "non-aws workflow exposes deposit ivk input"
  assert_contains "$workflow_text" "boundless_withdraw_owallet_ovk_hex" "non-aws workflow exposes withdraw ovk input"
  assert_contains "$workflow_text" "boundless_witness_juno_scan_url" "non-aws workflow exposes juno-scan witness input"
  assert_contains "$workflow_text" "boundless_witness_juno_rpc_url" "non-aws workflow exposes junocashd witness input"
  assert_not_contains "$workflow_text" "boundless_witness_config_json" "non-aws workflow no longer uses witness config blob"
  assert_not_contains "$workflow_text" "--boundless-deposit-witness-wallet-id" "non-aws workflow no longer forwards external witness wallet ids"
  assert_not_contains "$workflow_text" "--boundless-deposit-witness-txid" "non-aws workflow no longer forwards external witness txids"
  assert_not_contains "$workflow_text" "--boundless-withdraw-witness-txid" "non-aws workflow no longer forwards external withdraw txids"
  assert_not_contains "$workflow_text" "go run ./cmd/checkpoint-aggregator" "non-aws workflow no longer starts synthetic checkpoint aggregator"
  assert_not_contains "$workflow_text" "go run ./cmd/checkpoint-signer" "non-aws workflow no longer starts synthetic checkpoint signer"
  assert_contains "$workflow_text" "--shared-ipfs-api-url \"\$E2E_SHARED_IPFS_API_URL\"" "non-aws workflow forwards shared ipfs api url to local e2e script"
}

test_aws_workflow_dispatch_input_count_within_limit() {
  local workflow
  workflow="$REPO_ROOT/.github/workflows/e2e-testnet-deploy-aws.yml"

  local count
  count="$(awk '
    /workflow_dispatch:/ { in_dispatch=1; next }
    in_dispatch && /inputs:/ { in_inputs=1; next }
    in_dispatch && in_inputs && /^[^[:space:]]/ { in_inputs=0; in_dispatch=0 }
    in_inputs && /^      [a-zA-Z0-9_]+:$/ { count++ }
    END { print count+0 }
  ' "$workflow")"

  if (( count > 25 )); then
    printf 'workflow_dispatch input count exceeds github limit: got=%s max=25\n' "$count" >&2
    exit 1
  fi
}

test_operator_stack_ami_release_workflow_exists() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/release-operator-stack-ami.yml")"

  assert_contains "$workflow_text" "name: release-operator-stack-ami" "operator stack ami workflow name"
  assert_contains "$workflow_text" "aws_region:" "operator stack ami workflow region input"
  assert_contains "$workflow_text" "release_tag:" "operator stack ami workflow release tag input"
  assert_contains "$workflow_text" "build-operator-stack-ami.sh create" "operator stack ami workflow invokes runbook"
  assert_contains "$workflow_text" "operator-ami-manifest.json" "operator stack ami workflow publishes manifest"
  assert_contains "$workflow_text" "gh release" "operator stack ami workflow creates/updates release"
}

test_operator_stack_ami_runbook_builds_full_stack_and_records_blockstamp() {
  local runbook_text
  runbook_text="$(cat "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh")"

  assert_contains "$runbook_text" "junocashd.service" "runbook installs junocashd service"
  assert_contains "$runbook_text" "juno-scan.service" "runbook installs juno-scan service"
  assert_contains "$runbook_text" "checkpoint-signer.service" "runbook installs checkpoint signer service"
  assert_contains "$runbook_text" "checkpoint-aggregator.service" "runbook installs checkpoint aggregator service"
  assert_contains "$runbook_text" "tss-host.service" "runbook installs tss-host service"
  assert_contains "$runbook_text" "getblockchaininfo" "runbook checks junocashd sync status"
  assert_contains "$runbook_text" "getbestblockhash" "runbook records synced blockstamp hash"
  assert_contains "$runbook_text" "create-image" "runbook creates ami"
  assert_contains "$runbook_text" "operator-ami-manifest.json" "runbook writes operator ami manifest"
}

test_aws_e2e_workflow_resolves_operator_ami_from_release_when_unset() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy-aws.yml")"

  assert_contains "$workflow_text" "Resolve Operator AMI" "aws e2e workflow has operator ami resolve step"
  assert_contains "$workflow_text" "gh release download" "aws e2e workflow downloads operator ami manifest from release"
  assert_contains "$workflow_text" "operator-ami-manifest.json" "aws e2e workflow references operator ami manifest"
  assert_contains "$workflow_text" "operator-stack-ami-latest" "aws e2e workflow resolves latest operator stack ami release tag"
  assert_contains "$workflow_text" "--operator-ami-id" "aws e2e workflow forwards resolved operator ami id"
  assert_contains "$workflow_text" "boundless_deposit_owallet_ivk_hex" "aws workflow exposes deposit ivk input"
  assert_contains "$workflow_text" "boundless_withdraw_owallet_ovk_hex" "aws workflow exposes withdraw ovk input"
  assert_not_contains "$workflow_text" "boundless_witness_config_json" "aws workflow no longer uses witness config blob"
  assert_not_contains "$workflow_text" "--boundless-witness-juno-scan-url" "aws workflow does not pass external witness scan endpoint"
  assert_not_contains "$workflow_text" "--boundless-witness-juno-rpc-url" "aws workflow does not pass external witness rpc endpoint"
  assert_not_contains "$workflow_text" "--boundless-deposit-witness-txid" "aws workflow no longer forwards external deposit txid"
  assert_not_contains "$workflow_text" "--boundless-withdraw-witness-txid" "aws workflow no longer forwards external withdraw txid"
}

main() {
  test_remote_prepare_script_waits_for_cloud_init_and_retries_apt
  test_runner_shared_probe_script_supports_managed_endpoints
  test_remote_operator_prepare_script_boots_full_stack_services
  test_live_e2e_terraform_supports_operator_instances
  test_synced_junocashd_ami_runbook_exists
  test_aws_wrapper_uses_ssh_keepalive_options
  test_aws_wrapper_supports_operator_fleet_and_distributed_dkg
  test_aws_wrapper_collects_artifacts_after_remote_failures
  test_aws_wrapper_wires_shared_services_into_remote_e2e
  test_local_e2e_supports_shared_infra_validation
  test_e2e_workflows_exclude_sensitive_artifact_paths
  test_local_e2e_supports_external_dkg_summary_path
  test_local_e2e_uses_operator_deployer_key
  test_local_e2e_cast_send_handles_already_known_nonce_race
  test_local_e2e_tops_up_bridge_deployer_balance
  test_local_e2e_uses_managed_nonce_for_funding
  test_non_aws_workflow_wires_shared_ipfs_for_local_e2e
  test_aws_workflow_dispatch_input_count_within_limit
  test_operator_stack_ami_release_workflow_exists
  test_operator_stack_ami_runbook_builds_full_stack_and_records_blockstamp
  test_aws_e2e_workflow_resolves_operator_ami_from_release_when_unset
}

main "$@"
