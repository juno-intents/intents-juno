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

assert_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"

  if [[ "$haystack" != *"$first"* ]]; then
    printf 'assert_order failed: %s: first missing=%q\n' "$msg" "$first" >&2
    exit 1
  fi
  if [[ "$haystack" != *"$second"* ]]; then
    printf 'assert_order failed: %s: second missing=%q\n' "$msg" "$second" >&2
    exit 1
  fi

  local after_first
  after_first="${haystack#*"$first"}"
  if [[ "$after_first" != *"$second"* ]]; then
    printf 'assert_order failed: %s: expected %q before %q\n' "$msg" "$first" "$second" >&2
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
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 build --release --manifest-path zk/sp1_prover_adapter/cli/Cargo.toml" "sp1 adapter release build command"
  assert_contains "$script_text" "install -m 0755 zk/target/release/sp1-prover-adapter \"\$HOME/.local/bin/sp1-prover-adapter\"" "sp1 adapter binary install command"
  assert_contains "$script_text" "ln -sf \"\$HOME/.local/bin/sp1-prover-adapter\" \"\$HOME/.local/bin/sp1\"" "sp1 adapter compatibility symlink"
  assert_contains "$script_text" "cargo --version" "cargo version check"
  assert_contains "$script_text" "rustc --version" "rustc version check"
  assert_contains "$script_text" "git rev-parse --verify --quiet deadbeef^{commit}" "runner prepare checks requested commit availability before checkout"
  assert_contains "$script_text" "falling back to origin/main" "runner prepare falls back to origin/main when requested commit is unavailable"
  assert_contains "$script_text" "git checkout origin/main" "runner prepare fallback checks out origin/main"
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
  assert_contains "$script_text" "startup_services=(" "operator prep separates boot-critical startup services"
  assert_not_contains "$script_text" "startup_services=("$'\n'"  junocashd.service"$'\n'"  juno-scan.service"$'\n'"  checkpoint-signer.service" "operator prep defers checkpoint services until shared config is provisioned"
  assert_contains "$script_text" "systemctl cat \"\$svc\"" "operator prep validates service units exist"
  assert_contains "$script_text" "git rev-parse --verify --quiet deadbeef^{commit}" "operator prepare checks requested commit availability before checkout"
  assert_contains "$script_text" "falling back to origin/main" "operator prepare falls back to origin/main when requested commit is unavailable"
  assert_contains "$script_text" "git checkout origin/main" "operator prepare fallback checks out origin/main when commit is missing"
  assert_contains "$script_text" "sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno" "operator prep normalizes stack config dir permissions for ubuntu services"
  assert_contains "$script_text" "required_stack_access_files=(" "operator prep defines required stack access files"
  assert_contains "$script_text" "/etc/intents-juno/junocashd.conf" "operator prep requires junocashd config file"
  assert_contains "$script_text" "/etc/intents-juno/operator-stack.env" "operator prep requires operator stack env file"
  assert_contains "$script_text" "/etc/intents-juno/checkpoint-signer.key" "operator prep requires checkpoint signer key file"
  assert_contains "$script_text" "optional_stack_access_files=(" "operator prep defines optional stack access files"
  assert_contains "$script_text" "/etc/intents-juno/operator-stack-hydrator.env" "operator prep supports hydrator env file access normalization"
  assert_contains "$script_text" "/etc/intents-juno/operator-stack-config.json" "operator prep supports missing stack config json on older AMIs"
  assert_contains "$script_text" "for stack_file in \"\${required_stack_access_files[@]}\"; do" "operator prep validates required stack files exist"
  assert_contains "$script_text" "operator host missing required stack config file" "operator prep fails with clear error when required stack file missing"
  assert_contains "$script_text" "for stack_file in \"\${stack_access_files[@]}\"; do" "operator prep iterates stack files for access normalization"
  assert_contains "$script_text" "if [[ -f \"\$stack_file\" ]]; then" "operator prep skips optional stack files when absent"
  assert_contains "$script_text" "sudo chgrp ubuntu \"\$stack_file\"" "operator prep normalizes stack file group ownership"
  assert_contains "$script_text" "sudo chmod 0640 \"\$stack_file\"" "operator prep normalizes stack file read permissions for ubuntu services"
  assert_contains "$script_text" "checkpoint_runtime_wrappers=(" "operator prep defines checkpoint wrapper retrofit list"
  assert_contains "$script_text" "/usr/local/bin/intents-juno-checkpoint-signer.sh" "operator prep retrofits checkpoint-signer wrapper env export behavior"
  assert_contains "$script_text" "/usr/local/bin/intents-juno-checkpoint-aggregator.sh" "operator prep retrofits checkpoint-aggregator wrapper env export behavior"
  assert_contains "$script_text" "grep -q \"source /etc/intents-juno/operator-stack.env\" \"\$checkpoint_wrapper\"" "operator prep detects wrappers sourcing stack env"
  assert_contains "$script_text" "grep -q '^set -a$' \"\$checkpoint_wrapper\"" "operator prep skips wrappers already exporting stack env"
  assert_contains "$script_text" "sudo perl -0pi -e 's/# shellcheck disable=SC1091\\nsource \\/etc\\/intents-juno\\/operator-stack\\.env/# shellcheck disable=SC1091\\nset -a\\nsource \\/etc\\/intents-juno\\/operator-stack.env\\nset +a/' \"\$checkpoint_wrapper\"" "operator prep injects set -a/set +a around stack env source for legacy wrappers"
  assert_contains "$script_text" "systemctl enable \"\${required_services[@]}\"" "operator prep enables full stack services"
  assert_contains "$script_text" "systemctl restart \"\${startup_services[@]}\"" "operator prep restarts boot-critical services"
  assert_contains "$script_text" "systemctl is-active --quiet \"\$svc\"" "operator prep verifies services are active"
  assert_contains "$script_text" "tss-host startup deferred until signer runtime artifacts are provisioned" "operator prep defers tss-host until signer artifacts exist"
  assert_contains "$script_text" "checkpoint-signer/checkpoint-aggregator startup deferred until shared checkpoint config is provisioned" "operator prep defers checkpoint services until shared config exists"
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
  local operator_runbook_text
  operator_runbook_text="$(cat "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh")"

  assert_contains "$runbook_text" "create-synced-junocashd-ami.sh create" "ami runbook usage"
  assert_contains "$runbook_text" "--instance-id" "ami runbook instance id option"
  assert_contains "$runbook_text" "--aws-region" "ami runbook aws region option"
  assert_contains "$runbook_text" "ec2 create-image" "ami runbook create-image call"
  assert_contains "$runbook_text" "ec2 wait image-available" "ami runbook wait for image availability"
  assert_contains "$operator_runbook_text" "cat > /tmp/intents-juno-checkpoint-signer.sh <<'EOF_SIGNER'" "operator runbook defines checkpoint-signer wrapper"
  assert_contains "$operator_runbook_text" "cat > /tmp/intents-juno-checkpoint-aggregator.sh <<'EOF_AGG'" "operator runbook defines checkpoint-aggregator wrapper"
  assert_contains "$operator_runbook_text" "# shellcheck disable=SC1091"$'\n'"set -a"$'\n'"source /etc/intents-juno/operator-stack.env"$'\n'"set +a" "operator runbook wrappers export sourced stack env vars to child processes"
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
  assert_contains "$wrapper_script_text" "--shared-proof-services-image" "shared proof services image override option"
  assert_contains "$wrapper_script_text" "--runner-associate-public-ip-address" "runner public ip override option"
  assert_contains "$wrapper_script_text" "--operator-associate-public-ip-address" "operator public ip override option"
  assert_contains "$wrapper_script_text" "--shared-ecs-assign-public-ip" "shared ecs public ip override option"
  assert_contains "$wrapper_script_text" "--dkg-s3-key-prefix" "dkg s3 prefix option"
  assert_contains "$wrapper_script_text" "--juno-funder-seed-file" "juno funder seed option"
  assert_contains "$wrapper_script_text" "--juno-funder-source-address-file" "juno funder source address option"
  assert_contains "$wrapper_script_text" "--operator-root-volume-gb" "operator root volume option"
  assert_contains "$wrapper_script_text" "one of --juno-funder-key-file, --juno-funder-seed-file, or --juno-funder-source-address-file is required" "juno funder source requirement"
  assert_contains "$wrapper_script_text" "export JUNO_FUNDER_SEED_PHRASE=\"\\\$(cat .ci/secrets/juno-funder.seed.txt)\"" "aws wrapper preserves multiline seed file content for downstream normalization"
  assert_not_contains "$wrapper_script_text" "export JUNO_FUNDER_SEED_PHRASE=\"\$(tr -d '\\r\\n' < .ci/secrets/juno-funder.seed.txt)\"" "aws wrapper no longer flattens wrapped seed file content"
  assert_contains "$wrapper_script_text" "workdir=\"\$(cd \"\$workdir\" && pwd)\"" "aws wrapper canonicalizes workdir path"
  assert_contains "$wrapper_script_text" "terraform_dir=\"\$(cd \"\$terraform_dir\" && pwd)\"" "aws wrapper canonicalizes terraform dir path"
  assert_contains "$wrapper_script_text" "operator_instance_count" "terraform operator count wiring"
  assert_contains "$wrapper_script_text" "operator_instance_type" "terraform operator type wiring"
  assert_contains "$wrapper_script_text" "runner_ami_id" "terraform runner ami wiring"
  assert_contains "$wrapper_script_text" "operator_ami_id" "terraform operator ami wiring"
  assert_contains "$wrapper_script_text" "shared_ami_id" "terraform shared ami wiring"
  assert_contains "$wrapper_script_text" "dkg_s3_key_prefix" "terraform dkg s3 prefix wiring"
  assert_contains "$wrapper_script_text" "operator_root_volume_size_gb" "terraform operator root volume wiring"
  assert_contains "$wrapper_script_text" "shared_postgres_password" "terraform shared postgres password wiring"
  assert_contains "$wrapper_script_text" "shared_sp1_requestor_secret_arn" "terraform sp1 requestor secret arn wiring"
  assert_not_contains "$wrapper_script_text" "shared_sp1_requestor_private_key" "terraform sp1 requestor private key tfvars wiring removed"
  assert_contains "$wrapper_script_text" "dkg_kms_key_arn" "terraform dkg kms output usage"
  assert_contains "$wrapper_script_text" "dkg_s3_bucket" "terraform dkg bucket output usage"
  assert_contains "$wrapper_script_text" "defaulting --sp1-input-s3-bucket to terraform dkg bucket output" "aws wrapper defaults sp1 input bucket to dkg output"
  assert_contains "$wrapper_script_text" "\"--sp1-input-s3-bucket\" \"\$dkg_s3_bucket\"" "aws wrapper forwards dkg bucket as sp1 input bucket fallback"
  assert_contains "$wrapper_script_text" "operator-export-kms.sh export" "operator kms export invocation"
  assert_contains "$wrapper_script_text" "remote_prepare_operator_host" "remote operator host preparation hook"
  assert_contains "$wrapper_script_text" "run_distributed_dkg_backup_restore" "distributed dkg orchestration hook"
  assert_contains "$wrapper_script_text" 'rm -f "\$age_backup" "\$backup_zip" "\$kms_receipt"' "distributed dkg clears stale backup artifacts for keep-infra reruns"
  assert_contains "$wrapper_script_text" '--out "\$age_backup" \' "distributed dkg backup-age output path wiring"
  assert_contains "$wrapper_script_text" '--out "\$age_backup" \
  --force' "distributed dkg backup-age overwrites prior backup output"
  assert_contains "$wrapper_script_text" "sudo rm -rf /var/lib/intents-juno/operator-runtime" "distributed dkg replaces preexisting operator-runtime directory before linking restored runtime"
  assert_contains "$wrapper_script_text" 'sudo ln -sfn "\$runtime_dir" /var/lib/intents-juno/operator-runtime' "distributed dkg links restored runtime at canonical operator-runtime path"
  assert_contains "$wrapper_script_text" 'run_with_retry "copying distributed bundle op${op_index} from runner" 3 5 \' "distributed dkg retries bundle fetch from runner"
  assert_contains "$wrapper_script_text" 'run_with_retry "copying distributed bundle op${op_index} to operator" 3 5 \' "distributed dkg retries bundle stage to operator"
  assert_contains "$wrapper_script_text" 'run_with_retry "starting operator daemon op${op_index}" 3 10 \' "distributed dkg wraps operator daemon startup with retry guard"
  assert_contains "$wrapper_script_text" 'ssh "${operator_ssh_opts[@]}" "$ssh_user@$op_private_ip" "bash -lc $(printf '\''%q'\'' "$start_operator_script")"' "distributed dkg retry executes operator daemon startup over runner-bastion/private-ip ssh"
  assert_contains "$wrapper_script_text" $'for ((idx = 0; idx < operator_count; idx++)); do\n    op_index=$((idx + 1))\n    op_public_ip="${operator_public_ips[$idx]}"\n    op_private_ip="${operator_private_ips[$idx]}"\n\n    local operator_work_root' "distributed dkg backup/restore loop rebinds per-operator private ip"
  assert_order "$wrapper_script_text" 'op_private_ip="${operator_private_ips[$idx]}"' 'running backup/restore verification on operator host op${op_index} via runner bastion ${runner_public_ip} -> ${op_private_ip} (public=${op_public_ip})' "distributed dkg backup/restore log uses private ip set in the same loop"
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
  assert_contains "$wrapper_script_text" "keep-infra enabled; cleanup trap disabled for all run phases" "keep-infra disables cleanup before pre-run failures"
  assert_contains "$wrapper_script_text" "keep-infra enabled after failure; leaving resources up" "keep-infra failure retention log"
  assert_contains "$wrapper_script_text" "cleanup_enabled=\"false\"" "keep-infra disables cleanup on failure"
  assert_contains "$wrapper_script_text" 'remote live e2e run failed (status=$remote_run_status)' "remote failure reported after artifact collection"
}

test_aws_wrapper_wires_shared_services_into_remote_e2e() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "--without-shared-services" "shared services toggle option"
  assert_contains "$wrapper_script_text" "requires forwarded shared args after '--':" "without-shared-services usage documents required forwarded shared args"
  assert_contains "$wrapper_script_text" "--shared-sp1-requestor-secret-arn <arn>" "shared services supports pre-existing primary sp1 secret arn override"
  assert_contains "$wrapper_script_text" "--shared-sp1-requestor-secret-arn-dr <arn>" "shared services supports pre-existing dr sp1 secret arn override"
  assert_contains "$wrapper_script_text" "--without-shared-services requires forwarded --shared-postgres-dsn, --shared-kafka-brokers, and --shared-ipfs-api-url after '--'" "without-shared-services mode validates required forwarded shared args up front"
  assert_contains "$wrapper_script_text" "--shared-sp1-requestor-secret-arn-dr requires --shared-sp1-requestor-secret-arn" "shared services validates primary secret arn when dr override is set"
  assert_contains "$wrapper_script_text" "--shared-sp1-requestor-secret-arn requires --shared-sp1-requestor-secret-arn-dr" "shared services validates dr secret arn when primary override is set"
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
  assert_contains "$wrapper_script_text" "reusing deployment_id from existing tfvars" "aws wrapper reuses deployment id for iterative reruns"
  assert_contains "$wrapper_script_text" "reusing dr deployment_id from existing tfvars" "aws wrapper reuses dr deployment id for iterative reruns"
  assert_contains "$wrapper_script_text" "sp1_requestor_secret_exists" "aws wrapper can verify preexisting sp1 requestor secret"
  assert_contains "$wrapper_script_text" "using provided sp1 requestor secret arn:" "aws wrapper accepts explicit primary sp1 requestor secret arn override"
  assert_contains "$wrapper_script_text" "using provided dr sp1 requestor secret arn:" "aws wrapper accepts explicit dr sp1 requestor secret arn override"
  assert_contains "$wrapper_script_text" "sp1_requestor_secret_created=\"false\"" "aws wrapper tracks whether primary sp1 requestor secret was created during run"
  assert_contains "$wrapper_script_text" "sp1_requestor_secret_dr_created=\"false\"" "aws wrapper tracks whether dr sp1 requestor secret was created during run"
  assert_contains "$wrapper_script_text" "local shared_proof_services_image_override=\"\"" "aws wrapper initializes shared proof services image override option"
  assert_contains "$wrapper_script_text" "if [[ \"\$sp1_requestor_secret_created\" == \"true\" ]]; then" "aws wrapper only schedules primary sp1 secret cleanup when created"
  assert_contains "$wrapper_script_text" "if [[ \"\$sp1_requestor_secret_dr_created\" == \"true\" ]]; then" "aws wrapper only schedules dr sp1 secret cleanup when created"
  assert_contains "$wrapper_script_text" "reusing sp1 requestor secret:" "aws wrapper reuses existing primary sp1 requestor secret"
  assert_contains "$wrapper_script_text" "reusing dr sp1 requestor secret:" "aws wrapper reuses existing dr sp1 requestor secret"
  assert_contains "$wrapper_script_text" "docker buildx build --platform linux/amd64" "proof services image build invocation"
  assert_contains "$wrapper_script_text" 'run_with_retry "shared proof services image buildx build/push" 3 15' "proof services image buildx path retries transient registry/build failures"
  assert_contains "$wrapper_script_text" "run_with_local_timeout 300 docker buildx build --platform linux/amd64" "proof services image buildx path uses a bounded local timeout to prevent indefinite buildx hangs"
  assert_contains "$wrapper_script_text" 'if [[ "$(uname -s)" == "Darwin" ]]; then' "proof services image path detects darwin hosts"
  assert_contains "$wrapper_script_text" "darwin host detected; using docker build + push path for shared proof services image" "proof services image path logs darwin fallback"
  assert_contains "$wrapper_script_text" '${E2E_AWS_FORCE_LEGACY_DOCKER_BUILD:-}' "proof services image path supports explicit legacy docker build override"
  assert_contains "$wrapper_script_text" "run_with_local_timeout 300 env DOCKER_BUILDKIT=0 docker build" "proof services image fallback path disables buildkit for docker build reliability on darwin hosts"
  assert_contains "$wrapper_script_text" "--provenance=false" "proof services buildx invocation disables provenance attestations for reliable push completion"
  assert_contains "$wrapper_script_text" "--sbom=false" "proof services buildx invocation disables sbom attestations for reliable push completion"
  assert_contains "$wrapper_script_text" "aws ecr describe-images" "proof services image flow checks whether commit tag already exists"
  assert_contains "$wrapper_script_text" "reusing existing shared proof services image tag:" "proof services image flow logs ecr tag reuse path"
  assert_contains "$wrapper_script_text" "SHARED_PROOF_SERVICES_IMAGE=\"\"" "proof services image reference global initialized"
  assert_contains "$wrapper_script_text" "SHARED_PROOF_SERVICES_IMAGE=\"\${repository_url}:\${image_tag}\"" "proof services image reference global assignment"
  assert_contains "$wrapper_script_text" "--shared-proof-services-image)" "aws wrapper parses shared proof services image override argument"
  assert_contains "$wrapper_script_text" "using provided shared proof services image override:" "aws wrapper logs shared proof services image override usage"
  assert_contains "$wrapper_script_text" "skipping shared proof services image build because override was provided" "aws wrapper skips docker image build when explicit image override is set"
  assert_contains "$wrapper_script_text" "shared_proof_service_image=\"\$shared_proof_services_image_override\"" "aws wrapper writes explicit shared proof services image override into terraform vars"
  assert_contains "$wrapper_script_text" "shared_proof_services_image=\"\$SHARED_PROOF_SERVICES_IMAGE\"" "proof services image build call reads explicit global output"
  assert_not_contains "$wrapper_script_text" 'shared_proof_services_image="$( build_and_push_shared_proof_services_image' "proof services image build no longer masks failure via command substitution"
  assert_contains "$wrapper_script_text" "aws ecr get-login-password" "proof services ecr login"
  assert_contains "$wrapper_script_text" "copy_remote_secret_file() {" "aws wrapper defines remote secret copy helper"
  assert_contains "$wrapper_script_text" "-o IdentitiesOnly=yes" "aws wrapper forces explicit ssh identity usage to avoid agent stalls"
  assert_contains "$wrapper_script_text" "run_with_local_timeout 45 scp \"\${ssh_opts[@]}\" \"\$local_file\" \"\$ssh_user@\$ssh_host:\$remote_file\"" "remote secret copy uses bounded scp timeout"
  assert_contains "$wrapper_script_text" "for attempt in \$(seq 1 6); do" "remote secret copy retries transient ssh/scp failures"
  assert_contains "$wrapper_script_text" "aws ecs update-service" "proof services ecs rollout"
  assert_not_contains "$wrapper_script_text" "-raw shared_public_ip" "no shared host public ip output retrieval"
  assert_not_contains "$wrapper_script_text" "remote_prepare_shared_host" "no shared host preparation hook"
  assert_not_contains "$wrapper_script_text" "shared services reported ready despite ssh exit status" "no shared host bootstrap fallback"
  assert_not_contains "$wrapper_script_text" "shared connectivity reported ready despite ssh exit status" "no ssh fallback for managed shared stack"
  assert_contains "$wrapper_script_text" "wait_for_shared_connectivity_from_runner" "runner-to-shared readiness gate"
  assert_contains "$wrapper_script_text" "if ssh \"\${ssh_opts[@]}\" \"\$ssh_user@\$ssh_host\" 'bash -s' <<<\"\$remote_script\"; then" "shared connectivity probe executes remote script via stdin for reliable ssh exit status"
  assert_contains "$wrapper_script_text" "tss-host restart deferred until hydrator config has been staged" "aws wrapper defers tss-host restart until hydrator input staging"
  assert_contains "$wrapper_script_text" "staging hydrator config and restarting operator stack services on op" "aws wrapper stages hydrator config per operator"
  assert_contains "$wrapper_script_text" "default_config_json_path=\"/etc/intents-juno/operator-stack-config.json\"" "aws wrapper stages hydrator json to operator stack config path"
  assert_contains "$wrapper_script_text" 'sudo install -m 0640 -o root -g ubuntu "\$tmp_env" "\$stack_env_file"' "aws wrapper preserves operator stack env readability for ubuntu services"
  assert_contains "$wrapper_script_text" 'sudo install -d -m 0750 -o root -g ubuntu "\$(dirname "\$config_json_path")"' "aws wrapper preserves config dir execute/read access for ubuntu services"
  assert_contains "$wrapper_script_text" 'sudo install -m 0640 -o root -g ubuntu "\$tmp_json" "\$config_json_path"' "aws wrapper preserves hydrated config readability for ubuntu services"
  assert_contains "$wrapper_script_text" 'configured_json_path="\$(sudo awk -F=' "aws wrapper reads root-owned hydrator env via sudo"
  assert_contains "$wrapper_script_text" 'staged hydrator config at \$config_json_path with TSS_SIGNER_RUNTIME_MODE=\$tss_signer_runtime_mode' "aws wrapper logs staged hydrator config and runtime mode"
  assert_contains "$wrapper_script_text" 'set_env "\$tmp_env" TSS_SIGNER_RUNTIME_MODE "\$tss_signer_runtime_mode"' "aws wrapper sets explicit tss signer runtime mode in operator stack env"
  assert_contains "$wrapper_script_text" "nitro signer artifacts or PCR expectations unavailable; forcing TSS_SIGNER_RUNTIME_MODE=host-process for e2e orchestration" "aws wrapper explicitly selects host-process mode when nitro prerequisites are unavailable"
  assert_contains "$wrapper_script_text" "operator stack hydration requires shared postgres dsn" "aws wrapper requires shared postgres config for hydrator flow"
  assert_contains "$wrapper_script_text" "operator stack hydration requires shared kafka brokers" "aws wrapper requires shared kafka config for hydrator flow"
  assert_contains "$wrapper_script_text" "operator stack hydration requires shared ipfs api url" "aws wrapper requires shared ipfs config for hydrator flow"
  assert_contains "$wrapper_script_text" "forwarded --shared-postgres-dsn must not be empty" "aws wrapper validates forwarded shared postgres dsn"
  assert_contains "$wrapper_script_text" "forwarded --shared-kafka-brokers must not be empty" "aws wrapper validates forwarded shared kafka brokers"
  assert_contains "$wrapper_script_text" "forwarded --shared-ipfs-api-url must not be empty" "aws wrapper validates forwarded shared ipfs api url"
  assert_contains "$wrapper_script_text" "sudo systemctl restart intents-juno-config-hydrator.service" "aws wrapper restarts config hydrator after staging input"
  assert_contains "$wrapper_script_text" 'sudo chgrp ubuntu "\$stack_env_file"' "aws wrapper restores stack env group readability after hydrator rewrite"
  assert_contains "$wrapper_script_text" 'sudo chmod 0640 "\$stack_env_file"' "aws wrapper restores stack env mode after hydrator rewrite"
  assert_contains "$wrapper_script_text" "sudo systemctl restart tss-host.service" "aws wrapper restarts tss-host after hydrator run"
  assert_contains "$wrapper_script_text" "checkpoint-signer/checkpoint-aggregator restart deferred until bridge config is staged by remote e2e" "aws wrapper defers checkpoint service restart until remote bridge staging"
  assert_order "$wrapper_script_text" "sudo systemctl restart intents-juno-config-hydrator.service" 'sudo chgrp ubuntu "\$stack_env_file"' "wrapper repairs env permissions after hydrator restart"
  assert_order "$wrapper_script_text" 'sudo chgrp ubuntu "\$stack_env_file"' "sudo systemctl restart tss-host.service" "wrapper repairs env permissions before restarting tss-host"
  assert_order "$wrapper_script_text" "sudo systemctl restart intents-juno-config-hydrator.service" "sudo systemctl restart tss-host.service" "hydrator restart should precede tss-host restart"
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
  assert_contains "$wrapper_script_text" "--sp1-witness-juno-scan-url\" \"\$witness_juno_scan_url\"" "aws wrapper forwards stack-derived witness scan endpoint"
  assert_contains "$wrapper_script_text" "--sp1-witness-juno-rpc-url\" \"\$witness_juno_rpc_url\"" "aws wrapper forwards stack-derived witness rpc endpoint"
  assert_contains "$wrapper_script_text" "--sp1-witness-juno-scan-urls\" \"\$witness_juno_scan_urls_csv\"" "aws wrapper forwards witness scan endpoint pool"
  assert_contains "$wrapper_script_text" "--sp1-witness-juno-rpc-urls\" \"\$witness_juno_rpc_urls_csv\"" "aws wrapper forwards witness rpc endpoint pool"
  assert_contains "$wrapper_script_text" "--sp1-witness-operator-labels\" \"\$witness_operator_labels_csv\"" "aws wrapper forwards witness operator labels"
  assert_contains "$wrapper_script_text" "--sp1-witness-quorum-threshold\" \"\$witness_quorum_threshold\"" "aws wrapper forwards witness quorum threshold"
  assert_contains "$wrapper_script_text" "--withdraw-coordinator-tss-url\" \"\$witness_tss_url\"" "aws wrapper forwards stack-derived tss endpoint"
  assert_contains "$wrapper_script_text" "--withdraw-coordinator-tss-server-ca-file\" \".ci/secrets/witness-tss-ca.pem\"" "aws wrapper forwards stack-derived tss ca file"
  assert_contains "$wrapper_script_text" "overriding forwarded --sp1-witness-juno-scan-url with stack-derived witness tunnel endpoint" "aws wrapper overrides external witness scan endpoint"
  assert_contains "$wrapper_script_text" "overriding forwarded --sp1-witness-juno-rpc-url with stack-derived witness tunnel endpoint" "aws wrapper overrides external witness rpc endpoint"
  assert_contains "$wrapper_script_text" "overriding forwarded --withdraw-coordinator-tss-url with stack-derived witness tunnel endpoint" "aws wrapper overrides external tss endpoint"
  assert_contains "$wrapper_script_text" "overriding forwarded --withdraw-coordinator-tss-server-ca-file with stack-derived witness CA" "aws wrapper overrides external tss ca file"
  assert_contains "$wrapper_script_text" "witness-tss-ca.pem" "aws wrapper stages tss ca on runner"
  assert_contains "$wrapper_script_text" 'witness_tss_ca_remote_source_candidates=(' "aws wrapper defines runner-local witness tss ca source candidate list"
  assert_contains "$wrapper_script_text" '$remote_repo/.ci/secrets/witness-tss-ca.pem' "aws wrapper reuses existing staged witness tss ca secret before operator proxy fetch"
  assert_contains "$wrapper_script_text" '$remote_workdir/dkg-distributed/operators/op1/runtime/bundle/tls/ca.pem' "aws wrapper prefers runner-local distributed dkg tss ca source"
  assert_contains "$wrapper_script_text" "using runner-local witness tss ca source path=" "aws wrapper logs runner-local tss ca source selection"
  assert_contains "$wrapper_script_text" "runner-local witness tss ca path missing; falling back to operator host fetch" "aws wrapper logs operator-host fallback when runner-local tss ca source is unavailable"
  assert_contains "$wrapper_script_text" "run_with_local_timeout()" "aws wrapper defines portable local timeout helper"
  assert_contains "$wrapper_script_text" "run_with_local_timeout 45 scp -i \"\$ssh_key_private\"" "aws wrapper bounds witness tss ca operator-host fallback scp with timeout helper"
  assert_contains "$wrapper_script_text" "witness_tss_urls+=(\"https://127.0.0.1:" "aws wrapper uses https for tss tunnel URLs"
  assert_contains "$wrapper_script_text" "for ((op_idx = 0; op_idx < \\\${#operator_private_ips[@]}; op_idx++)); do" "aws wrapper iterates operator fleet for witness tunnels"
  assert_contains "$wrapper_script_text" "witness-tunnel-op\\\$((op_idx + 1)).log" "aws wrapper escapes witness tunnel log label arithmetic during remote script render"
  assert_contains "$wrapper_script_text" "witness_tunnel_scan_port=\\\$((witness_tunnel_scan_base_port + op_idx))" "aws wrapper assigns scan tunnel ports per operator"
  assert_contains "$wrapper_script_text" "witness_tunnel_rpc_port=\\\$((witness_tunnel_rpc_base_port + op_idx))" "aws wrapper assigns rpc tunnel ports per operator"
  assert_contains "$wrapper_script_text" "witness_tunnel_tss_port=\\\$((witness_tunnel_tss_base_port + op_idx))" "aws wrapper assigns tss tunnel ports per operator"
  assert_contains "$wrapper_script_text" 'for witness_tunnel_pid in "\${witness_tunnel_pids[@]}"; do' "aws wrapper escapes witness tunnel pid loop vars during remote script render"
  assert_contains "$wrapper_script_text" 'witness_tunnel_pid=\$!' "aws wrapper escapes witness tunnel pid assignment during remote script render"
  assert_contains "$wrapper_script_text" 'for attempt in \$(seq 1 20); do' "aws wrapper escapes witness tunnel readiness loop command substitution during remote script render"
  assert_contains "$wrapper_script_text" "witness tunnel ready for operator=" "aws wrapper logs per-operator witness tunnel readiness"
  assert_contains "$wrapper_script_text" "insufficient witness tunnels ready for quorum" "aws wrapper fails fast when tunnel quorum is unavailable"
  assert_contains "$wrapper_script_text" "-L \"127.0.0.1:\\\${witness_tunnel_scan_port}:127.0.0.1:8080\"" "aws wrapper opens runner-local juno-scan tunnels per operator"
  assert_contains "$wrapper_script_text" "-L \"127.0.0.1:\\\${witness_tunnel_rpc_port}:127.0.0.1:18232\"" "aws wrapper opens runner-local junocashd rpc tunnels per operator"
  assert_contains "$wrapper_script_text" "-L \"127.0.0.1:\\\${witness_tunnel_tss_port}:127.0.0.1:9443\"" "aws wrapper opens runner-local tss-host tunnels per operator"
  assert_contains "$wrapper_script_text" "JUNO_RPC_USER is required for withdraw coordinator full mode" "aws wrapper remote run hard-fails when coordinator rpc auth is missing"
  assert_contains "$wrapper_script_text" "JUNO_RPC_PASS is required for withdraw coordinator full mode" "aws wrapper remote run hard-fails when coordinator rpc auth is missing"
  assert_contains "$wrapper_script_text" 'export JUNO_QUEUE_KAFKA_TLS="true"' "aws wrapper enforces kafka tls for live queue clients in remote run"
  assert_contains "$wrapper_script_text" "command -v psql" "aws wrapper ensures psql is available on remote runner"
  assert_contains "$wrapper_script_text" "withdraw coordinator mock runtime is forbidden in live e2e (do not pass --runtime-mode)" "aws wrapper rejects forwarded runtime-mode flag"
  assert_contains "$wrapper_script_text" "if [[ \"\${JUNO_DKG_ALLOW_INSECURE_NETWORK:-0}\" == \"1\" ]]; then" "aws wrapper allows explicit insecure dkg opt-in only"
  assert_contains "$wrapper_script_text" 'export JUNO_DKG_NETWORK_MODE="vpc-private"' "aws wrapper pins dkg network mode to private vpc transport"
  assert_not_contains "$wrapper_script_text" "--sp1-deposit-witness-txid" "aws wrapper no longer forwards external deposit txid"
  assert_not_contains "$wrapper_script_text" "--sp1-withdraw-witness-txid" "aws wrapper no longer forwards external withdraw txid"
}

test_aws_wrapper_supports_dr_readiness_and_distributed_relayer_runtime() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "--aws-dr-region" "aws wrapper dr region option"
  assert_contains "$wrapper_script_text" "--enable-aws-dr-readiness-checks" "aws wrapper dr readiness enable option"
  assert_contains "$wrapper_script_text" "--disable-aws-dr-readiness-checks" "aws wrapper dr readiness disable option"
  assert_contains "$wrapper_script_text" "--distributed-relayer-runtime" "aws wrapper distributed relayer runtime option"
  assert_contains "$wrapper_script_text" "--relayer-runtime-mode" "aws wrapper relayer runtime mode option"
  assert_contains "$wrapper_script_text" "validate_shared_services_dr_readiness()" "aws wrapper defines dr readiness validator"
  assert_contains "$wrapper_script_text" "run_optional_dr_readiness_probe()" "aws wrapper defines optional dr readiness probe helper"
  assert_contains "$wrapper_script_text" 'out="$(run_with_local_timeout 45 "$@" 2>&1)"' "aws wrapper bounds optional dr readiness probes with local timeout"
  assert_contains "$wrapper_script_text" "dr readiness probe failed (probe=\$probe_name attempt \$attempt/3); retrying in 5s" "aws wrapper retries transient optional dr readiness probe failures"
  assert_contains "$wrapper_script_text" "aws ec2 describe-availability-zones" "aws wrapper checks dr region az availability"
  assert_contains "$wrapper_script_text" "\"rds:DescribeDBEngineVersions\"" "aws wrapper names dr readiness rds probe"
  assert_contains "$wrapper_script_text" "aws rds describe-db-engine-versions" "aws wrapper checks dr region aurora api readiness"
  assert_contains "$wrapper_script_text" "--max-records 20" "aws wrapper uses valid rds max-records for readiness check"
  assert_contains "$wrapper_script_text" "\"kafka:ListClustersV2\"" "aws wrapper names dr readiness msk probe"
  assert_contains "$wrapper_script_text" "aws kafka list-clusters-v2" "aws wrapper checks dr region msk api readiness"
  assert_contains "$wrapper_script_text" "\"ecs:ListClusters\"" "aws wrapper names dr readiness ecs probe"
  assert_contains "$wrapper_script_text" "aws ecs list-clusters" "aws wrapper checks dr region ecs api readiness"
  assert_contains "$wrapper_script_text" "warning: skipping dr readiness probe due to IAM permission limits" "aws wrapper tolerates access denied in optional dr readiness probes"
  assert_contains "$wrapper_script_text" "--aws-dr-region is required when shared services are enabled" "aws wrapper requires dr region when shared services enabled"
  assert_contains "$wrapper_script_text" "--aws-dr-region must differ from --aws-region" "aws wrapper validates dr region differs from primary"
  assert_contains "$wrapper_script_text" "shared services are enabled; validating dr readiness" "aws wrapper logs dr readiness gate"
  assert_contains "$wrapper_script_text" "shared services require DR readiness checks; remove --disable-aws-dr-readiness-checks" "aws wrapper blocks disabling dr checks with shared services"
  assert_contains "$wrapper_script_text" "local aws_dr_region=\"\"" "aws wrapper tracks dr region run option"
  assert_contains "$wrapper_script_text" "local aws_dr_readiness_checks_enabled=\"true\"" "aws wrapper enables dr readiness checks by default"
  assert_contains "$wrapper_script_text" "local relayer_runtime_mode=\"distributed\"" "aws wrapper defaults relayer runtime mode to distributed"
  assert_contains "$wrapper_script_text" "local distributed_relayer_runtime_explicit=\"false\"" "aws wrapper tracks explicit distributed relayer toggle"
  assert_contains "$wrapper_script_text" "if [[ \"\$relayer_runtime_mode\" == \"distributed\" ]]; then" "aws wrapper conditionally enables distributed relayer runtime wiring"
  assert_contains "$wrapper_script_text" "\"--relayer-runtime-mode\" \"\$relayer_runtime_mode\"" "aws wrapper forwards relayer runtime mode to remote e2e"
  assert_contains "$wrapper_script_text" "\"--relayer-runtime-operator-hosts\" \"\$operator_private_ips_csv\"" "aws wrapper forwards relayer runtime operator hosts"
  assert_contains "$wrapper_script_text" "\"--relayer-runtime-operator-ssh-user\" \"\$runner_ssh_user\"" "aws wrapper forwards relayer runtime ssh user"
  assert_contains "$wrapper_script_text" "\"--relayer-runtime-operator-ssh-key-file\" \".ci/secrets/operator-fleet-ssh.key\"" "aws wrapper forwards relayer runtime ssh key path"
  assert_contains "$wrapper_script_text" "export RELAYER_RUNTIME_MODE=\"\${relayer_runtime_mode}\"" "aws wrapper exports relayer runtime mode env for remote e2e"
  assert_contains "$wrapper_script_text" "export RELAYER_RUNTIME_OPERATOR_HOSTS=\"\${operator_private_ips_csv}\"" "aws wrapper exports relayer runtime operator hosts env for remote e2e"
  assert_contains "$wrapper_script_text" "export RELAYER_RUNTIME_OPERATOR_SSH_USER=\"\${runner_ssh_user}\"" "aws wrapper exports relayer runtime ssh user env for remote e2e"
  assert_contains "$wrapper_script_text" "export RELAYER_RUNTIME_OPERATOR_SSH_KEY_FILE=\".ci/secrets/operator-fleet-ssh.key\"" "aws wrapper exports relayer runtime ssh key env for remote e2e"
}

test_aws_wrapper_provisions_and_cleans_dr_stack() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "ami_exists_in_region()" "aws wrapper defines regional ami existence helper"
  assert_contains "$wrapper_script_text" "resolve_dr_ami_id()" "aws wrapper defines dr ami resolver helper"
  assert_contains "$wrapper_script_text" "aws ec2 describe-images" "aws wrapper queries ec2 image api for dr ami validation"
  assert_contains "$wrapper_script_text" "--image-ids \"\$ami_id\"" "aws wrapper checks candidate ami id directly"
  assert_contains "$wrapper_script_text" "falling back to Terraform region default AMI" "aws wrapper logs dr ami fallback to region default"
  assert_contains "$wrapper_script_text" "local dr_tfvars_file=\"\"" "aws wrapper tracks dr tfvars path"
  assert_contains "$wrapper_script_text" "local dr_state_file=\"\"" "aws wrapper tracks dr state path"
  assert_contains "$wrapper_script_text" "local dr_deployment_id=\"\"" "aws wrapper tracks dr deployment id"
  assert_contains "$wrapper_script_text" "dr_tfvars_file=\"\$infra_dir/dr/terraform.tfvars.json\"" "aws wrapper writes dedicated dr tfvars file"
  assert_contains "$wrapper_script_text" "dr_state_file=\"\$infra_dir/dr/terraform.tfstate\"" "aws wrapper writes dedicated dr terraform state file"
  assert_contains "$wrapper_script_text" "dr_deployment_id=\"\${deployment_id}-dr\"" "aws wrapper uses dedicated dr deployment id"
  assert_contains "$wrapper_script_text" "dr_runner_ami_id=\"\$(resolve_dr_ami_id \"\$aws_profile\" \"\$aws_dr_region\" \"runner\" \"\$runner_ami_id\")\"" "aws wrapper resolves runner dr ami by region"
  assert_contains "$wrapper_script_text" "dr_operator_ami_id=\"\$(resolve_dr_ami_id \"\$aws_profile\" \"\$aws_dr_region\" \"operator\" \"\$operator_ami_id\")\"" "aws wrapper resolves operator dr ami by region"
  assert_contains "$wrapper_script_text" "dr_shared_ami_id=\"\$(resolve_dr_ami_id \"\$aws_profile\" \"\$aws_dr_region\" \"shared\" \"\$shared_ami_id\")\"" "aws wrapper resolves shared dr ami by region"
  assert_contains "$wrapper_script_text" "| .runner_ami_id = \$runner_ami_id" "aws wrapper writes dr runner ami override into dr tfvars"
  assert_contains "$wrapper_script_text" "| .operator_ami_id = \$operator_ami_id" "aws wrapper writes dr operator ami override into dr tfvars"
  assert_contains "$wrapper_script_text" "| .shared_ami_id = \$shared_ami_id" "aws wrapper writes dr shared ami override into dr tfvars"
  assert_contains "$wrapper_script_text" "terraform_apply_live_e2e \"\$terraform_dir\" \"\$dr_state_file\" \"\$dr_tfvars_file\" \"\$aws_profile\" \"\$aws_dr_region\"" "aws wrapper applies dr terraform stack"
  assert_contains "$wrapper_script_text" "cleanup_dr_state_file=\"\$dr_state_file\"" "aws wrapper registers dr state file for trap cleanup"
  assert_contains "$wrapper_script_text" "cleanup_dr_tfvars_file=\"\$dr_tfvars_file\"" "aws wrapper registers dr tfvars file for trap cleanup"
  assert_contains "$wrapper_script_text" "cleanup_dr_aws_region=\"\$aws_dr_region\"" "aws wrapper registers dr region for trap cleanup"
  assert_contains "$wrapper_script_text" "cleanup_dr_sp1_requestor_secret_arn=\"\$sp1_requestor_secret_arn_dr\"" "aws wrapper registers dr sp1 secret for trap cleanup"
  assert_contains "$wrapper_script_text" "terraform_destroy_live_e2e \"\$cleanup_terraform_dir\" \"\$cleanup_dr_state_file\" \"\$cleanup_dr_tfvars_file\" \"\$cleanup_aws_profile\" \"\$cleanup_dr_aws_region\"" "aws wrapper trap destroys dr terraform stack"
  assert_contains "$wrapper_script_text" "--aws-dr-region <region>             optional AWS DR region override" "aws wrapper cleanup command supports dr region override"
  assert_contains "$wrapper_script_text" "terraform_destroy_live_e2e \"\$terraform_dir\" \"\$dr_state_file\" \"\$dr_tfvars_file\" \"\$aws_profile\" \"\$dr_region_for_cleanup\"" "aws wrapper cleanup command destroys dr terraform stack"
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
  assert_contains "$e2e_script_text" "--relayer-runtime-mode <mode>" "relayer runtime mode option"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-hosts <csv>" "relayer runtime operator hosts option"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-ssh-user <user>" "relayer runtime ssh user option"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-ssh-key-file <path>" "relayer runtime ssh key option"
  assert_contains "$e2e_script_text" "--aws-dr-region <region>" "aws dr region passthrough option"
  assert_contains "$e2e_script_text" "--refund-after-expiry-window-seconds <n>" "refund-after-expiry test window option"
  assert_contains "$e2e_script_text" "--shared-postgres-dsn is required (centralized proof-requestor/proof-funder topology)" "shared postgres required message"
  assert_contains "$e2e_script_text" "--shared-kafka-brokers is required (centralized proof-requestor/proof-funder topology)" "shared kafka required message"
  assert_contains "$e2e_script_text" "--shared-ipfs-api-url is required (operator checkpoint package pin/fetch verification)" "shared ipfs required message"
  assert_contains "$e2e_script_text" "configure_remote_operator_checkpoint_services_for_bridge()" "distributed helper updates operator checkpoint services with deployed bridge address"
  assert_contains "$e2e_script_text" "updating operator checkpoint bridge config host=" "local e2e logs distributed checkpoint bridge hydration"
  assert_contains "$e2e_script_text" "--checkpoint-min-persisted-at \"\$checkpoint_started_at\"" "shared checkpoint validation is run-bound"
  assert_contains "$e2e_script_text" "go run ./cmd/shared-infra-e2e" "shared infra command invocation"
  assert_contains "$e2e_script_text" "--checkpoint-ipfs-api-url \"\$shared_ipfs_api_url\"" "shared infra ipfs checkpoint package verification wiring"
  assert_contains "$e2e_script_text" "operator-service checkpoint publication" "shared infra validation waits for operator-service checkpoint publication"
  assert_order "$e2e_script_text" "bridge summary missing deployed contracts.bridge address: \$bridge_summary" "go run ./cmd/shared-infra-e2e" "shared infra validation runs after bridge deploy summary is available"
  assert_contains "$e2e_script_text" ".coordinator_workdir // .coordinator.workdir // empty" "local e2e signer resolution supports sanitized coordinator workdir variants"
  assert_contains "$e2e_script_text" '"$workdir/dkg-distributed/coordinator/bin/dkg-admin"' "local e2e signer resolution prefers distributed dkg signer in workdir"
  assert_contains "$e2e_script_text" '"$workdir/dkg/coordinator/bin/dkg-admin"' "local e2e signer resolution falls back to legacy dkg signer in workdir"
  assert_contains "$e2e_script_text" 'bridge_operator_signer_bin="$(ensure_dkg_binary "dkg-admin" "$JUNO_DKG_VERSION_DEFAULT" "$workdir/bin")"' "local e2e signer resolution installs dkg-admin when workdir candidates are absent"
  assert_not_contains "$e2e_script_text" "go run ./cmd/checkpoint-aggregator" "synthetic checkpoint aggregator startup removed from local e2e"
  assert_not_contains "$e2e_script_text" "--queue-driver stdio" "synthetic stdio queue path removed from local e2e"
  assert_not_contains "$e2e_script_text" "checkpoint-signatures.fifo" "synthetic checkpoint fifo path removed from local e2e"
  assert_not_contains "$e2e_script_text" "\"\$bridge_operator_signer_bin\" sign-digest" "runner-side synthetic checkpoint signature loop removed"
  assert_not_contains "$e2e_script_text" "build_checkpoint_package_payload_file" "runner-side synthetic checkpoint package builder removed"
  assert_not_contains "$e2e_script_text" "checkpoint-package-deposit.json" "runner-side synthetic checkpoint deposit payload removed"
  assert_not_contains "$e2e_script_text" "checkpoint-package-withdraw.json" "runner-side synthetic checkpoint withdraw payload removed"
  assert_not_contains "$e2e_script_text" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "checkpoint signer private key env wiring removed"
  assert_not_contains "$e2e_script_text" "go run ./cmd/checkpoint-signer" "checkpoint signer process no longer spawned in local e2e"
  assert_contains "$e2e_script_text" "aws ecs register-task-definition" "proof services ecs task definition rollout"
  assert_contains "$e2e_script_text" "aws ecs update-service" "proof services ecs service update"
  assert_contains "$e2e_script_text" "aws ecs wait services-stable" "proof services ecs stability wait"
  assert_contains "$e2e_script_text" "--sp1-proof-submission-mode" "bridge forwards proof submission mode"
  assert_contains "$e2e_script_text" "\"--sp1-proof-submission-mode\" \"\$sp1_proof_submission_mode\"" "bridge uses centralized proof submission mode value"
  assert_contains "$e2e_script_text" "\"--sp1-proof-request-topic\" \"\$proof_request_topic\"" "bridge forwards proof request topic"
  assert_contains "$e2e_script_text" "\"--sp1-proof-result-topic\" \"\$proof_result_topic\"" "bridge forwards proof result topic"
  assert_contains "$e2e_script_text" "\"--sp1-proof-failure-topic\" \"\$proof_failure_topic\"" "bridge forwards proof failure topic"
  assert_contains "$e2e_script_text" "\"--sp1-proof-consumer-group\" \"\$proof_bridge_consumer_group\"" "bridge forwards proof consumer group"
  assert_not_contains "$e2e_script_text" "go run ./cmd/proof-requestor" "proof-requestor no longer runs ad hoc on runner"
  assert_not_contains "$e2e_script_text" "go run ./cmd/proof-funder" "proof-funder no longer runs ad hoc on runner"
  assert_not_contains "$e2e_script_text" "\"--sp1-requestor-key-file\" \"\$sp1_requestor_key_file\"" "bridge no longer submits directly with requestor key"
  assert_not_contains "$e2e_script_text" "run_with_rpc_retry 4 3 \"bridge-e2e\"" "bridge e2e should not be re-invoked on transient rpc wrapper retries"
  assert_not_contains "$e2e_script_text" "go run ./cmd/bridge-e2e \"\${bridge_args[@]}\"" "bridge e2e direct invocation removed for relayer service orchestration"
  assert_contains "$e2e_script_text" "\"--deploy-only\"" "bridge e2e deploy-only mode is used for contract bootstrap"
  assert_contains "$e2e_script_text" "go run ./cmd/base-relayer" "base relayer service startup in local e2e"
  assert_contains "$e2e_script_text" "go run ./cmd/deposit-relayer" "deposit-relayer service startup in local e2e"
  assert_contains "$e2e_script_text" "go run ./cmd/withdraw-coordinator" "withdraw-coordinator service startup in local e2e"
  assert_contains "$e2e_script_text" "local relayer_runtime_mode=\"runner\"" "local e2e tracks relayer runtime mode"
  assert_contains "$e2e_script_text" "local relayer_runtime_operator_hosts_csv=\"\"" "local e2e tracks relayer runtime host csv"
  assert_contains "$e2e_script_text" "local relayer_runtime_operator_ssh_user=\"\"" "local e2e tracks relayer runtime ssh user"
  assert_contains "$e2e_script_text" "local relayer_runtime_operator_ssh_key_file=\"\"" "local e2e tracks relayer runtime ssh key file"
  assert_contains "$e2e_script_text" "local aws_dr_region=\"\"" "local e2e records aws dr region passthrough"
  assert_contains "$e2e_script_text" "--relayer-runtime-mode must be runner or distributed" "local e2e validates relayer runtime mode"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-hosts is required when --relayer-runtime-mode=distributed" "distributed relayer runtime requires operator hosts"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-ssh-user is required when --relayer-runtime-mode=distributed" "distributed relayer runtime requires ssh user"
  assert_contains "$e2e_script_text" "--relayer-runtime-operator-ssh-key-file is required when --relayer-runtime-mode=distributed" "distributed relayer runtime requires ssh key"
  assert_contains "$e2e_script_text" "start_remote_relayer_service()" "distributed relayer runtime helper exists"
  assert_contains "$e2e_script_text" "stop_remote_relayer_service()" "distributed relayer runtime cleanup helper exists"
  assert_contains "$e2e_script_text" "distributed relayer runtime enabled; launching relayers on operator hosts" "distributed relayer runtime launch log"
  assert_contains "$e2e_script_text" "base-relayer host=" "distributed relayer runtime logs base-relayer host"
  assert_contains "$e2e_script_text" "deposit-relayer host=" "distributed relayer runtime logs deposit host"
  assert_contains "$e2e_script_text" "withdraw-coordinator host=" "distributed relayer runtime logs coordinator host"
  assert_contains "$e2e_script_text" "withdraw-finalizer host=" "distributed relayer runtime logs finalizer host"
  assert_contains "$e2e_script_text" "/usr/local/bin/base-relayer" "distributed relayer runtime uses operator-installed base relayer binary"
  assert_contains "$e2e_script_text" "/usr/local/bin/deposit-relayer" "distributed relayer runtime uses operator-installed deposit relayer binary"
  assert_contains "$e2e_script_text" "/usr/local/bin/withdraw-coordinator" "distributed relayer runtime uses operator-installed withdraw coordinator binary"
  assert_contains "$e2e_script_text" "/usr/local/bin/withdraw-finalizer" "distributed relayer runtime uses operator-installed withdraw finalizer binary"
  assert_not_contains "$e2e_script_text" "resolve_runner_relayer_host()" "distributed relayer runtime no longer depends on runner host discovery"
  assert_not_contains "$e2e_script_text" "--runtime-mode mock" "withdraw coordinator mock runtime removed from live e2e"
  assert_contains "$e2e_script_text" "--juno-rpc-url \"\$sp1_witness_juno_rpc_url\"" "withdraw coordinator uses witness-derived Juno RPC"
  assert_contains "$e2e_script_text" "--juno-wallet-id \"\$withdraw_coordinator_juno_wallet_id\"" "withdraw coordinator receives generated witness wallet id"
  assert_contains "$e2e_script_text" "--juno-change-address \"\$withdraw_coordinator_juno_change_address\"" "withdraw coordinator receives generated witness change address"
  assert_contains "$e2e_script_text" "--tss-url \"\$withdraw_coordinator_tss_url\"" "withdraw coordinator receives tunnelled tss endpoint"
  assert_contains "$e2e_script_text" "--base-chain-id \"\$base_chain_id\"" "withdraw coordinator receives base chain id"
  assert_contains "$e2e_script_text" "--bridge-address \"\$deployed_bridge_address\"" "withdraw coordinator receives deployed bridge address"
  assert_contains "$e2e_script_text" "--base-relayer-url \"\$base_relayer_url\"" "withdraw coordinator receives base-relayer url"
  assert_contains "$e2e_script_text" "--extend-signer-bin \"\$bridge_operator_signer_bin\"" "withdraw coordinator uses real extend signer binary"
  assert_contains "$e2e_script_text" "withdraw coordinator mock runtime is forbidden in live e2e" "live e2e aborts if mock runtime is requested"
  assert_contains "$e2e_script_text" "go run ./cmd/withdraw-finalizer" "withdraw-finalizer service startup in local e2e"
  assert_contains "$e2e_script_text" "go run ./cmd/queue-publish" "e2e publishes bridge queue events explicitly"
  assert_contains "$e2e_script_text" "go run ./cmd/deposit-event" "e2e derives deposit queue payload from witness bytes"
  assert_contains "$e2e_script_text" "go run ./cmd/withdraw-request" "e2e submits requestWithdraw and emits withdrawals.requested payload"
  assert_contains "$e2e_script_text" "--sp1-input-mode" "sp1 input mode option"
  assert_contains "$e2e_script_text" "local sp1_input_mode=\"guest-witness-v1\"" "sp1 input mode default"
  assert_contains "$e2e_script_text" "\"--sp1-input-mode\" \"\$sp1_input_mode\"" "sp1 input mode bridge forwarding"
  assert_contains "$e2e_script_text" "--sp1-deposit-owallet-ivk-hex" "sp1 deposit ivk option"
  assert_contains "$e2e_script_text" "--sp1-withdraw-owallet-ovk-hex" "sp1 withdraw ovk option"
  assert_contains "$e2e_script_text" "--sp1-witness-recipient-ua" "witness recipient UA override option"
  assert_contains "$e2e_script_text" "--sp1-witness-recipient-ufvk" "witness recipient UFVK override option"
  assert_contains "$e2e_script_text" "--sp1-witness-wallet-id" "witness wallet id override option"
  assert_contains "$e2e_script_text" "--sp1-witness-metadata-timeout-seconds" "witness metadata timeout option"
  assert_contains "$e2e_script_text" "--pre-upsert-scan-urls" "witness metadata pre-upserts wallet across quorum scan endpoints before tx submission"
  assert_contains "$e2e_script_text" "tr -cs '[:alnum:]_-' '_'" "witness fallback wallet ids sanitize operator labels to scan-safe characters"
  assert_not_contains "$e2e_script_text" "tr -cs '[:alnum:]_.-' '_'" "witness fallback wallet ids do not retain '.' from operator labels"
  assert_contains "$e2e_script_text" "--sp1-witness-juno-scan-urls" "witness scan endpoint pool option"
  assert_contains "$e2e_script_text" "--sp1-witness-juno-rpc-urls" "witness rpc endpoint pool option"
  assert_contains "$e2e_script_text" "--sp1-witness-operator-labels" "witness operator labels option"
  assert_contains "$e2e_script_text" "--sp1-witness-quorum-threshold" "witness quorum threshold option"
  assert_contains "$e2e_script_text" "--withdraw-coordinator-tss-url" "withdraw coordinator tss endpoint option"
  assert_contains "$e2e_script_text" "--withdraw-coordinator-tss-server-ca-file" "withdraw coordinator tss server ca option"
  assert_contains "$e2e_script_text" "witness_scan_healthcheck()" "witness scan health helper exists"
  assert_contains "$e2e_script_text" "witness_rpc_healthcheck()" "witness rpc health helper exists"
  assert_contains "$e2e_script_text" "witness_pair_healthcheck()" "witness endpoint pair health helper exists"
  assert_contains "$e2e_script_text" "witness_scan_upsert_wallet()" "witness wallet propagation helper exists"
  assert_contains "$e2e_script_text" "failed to build healthy witness endpoint pool with quorum" "witness flow enforces endpoint quorum health gate"
  assert_contains "$e2e_script_text" "failed to generate witness metadata from healthy witness endpoint pool" "witness metadata generation uses failover pool"
  assert_contains "$e2e_script_text" "witness quorum consistency mismatch across operators" "witness flow fails when operators disagree on witness bytes or anchors"
  assert_contains "$e2e_script_text" "failed to extract witness from quorum of operators" "witness flow enforces quorum extraction threshold"
  assert_contains "$e2e_script_text" "witness_extract_deadline_epoch" "witness extraction uses deadline-based retry window for operator index lag"
  assert_contains "$e2e_script_text" "waiting for note visibility on operator=" "witness extraction logs note indexing wait state per operator"
  assert_contains "$e2e_script_text" "generate-juno-witness-metadata.sh" "run-generated witness metadata command"
  assert_contains "$e2e_script_text" "generated-witness-metadata.json" "run-generated witness metadata output"
  assert_not_contains "$e2e_script_text" "compute-bridge-withdrawal-id.sh run" "withdraw witness ids are no longer precomputed from predicted bridge nonce"
  assert_contains "$e2e_script_text" "go run ./cmd/juno-witness-extract deposit" "deposit witness extraction command"
  assert_not_contains "$e2e_script_text" "go run ./cmd/juno-witness-extract withdraw" "withdraw witness extraction is no longer pre-generated from metadata txids"
  assert_contains "$e2e_script_text" '--recipient-ua "$sp1_witness_recipient_ua"' "witness generation forwards distributed DKG recipient UA"
  assert_contains "$e2e_script_text" '--recipient-ufvk "$sp1_witness_recipient_ufvk"' "witness generation forwards distributed DKG recipient UFVK"
  assert_contains "$e2e_script_text" "--sp1-witness-recipient-ua and --sp1-witness-recipient-ufvk are required for guest witness extraction mode" "guest witness flow requires distributed DKG recipient identity"
  assert_contains "$e2e_script_text" "one of JUNO_FUNDER_PRIVATE_KEY_HEX, JUNO_FUNDER_SEED_PHRASE, or JUNO_FUNDER_SOURCE_ADDRESS is required for run-generated witness metadata" "run-generated witness requires juno funder source env"
  assert_contains "$e2e_script_text" "--sp1-deposit-witness-item-file" "sp1 deposit witness option"
  assert_contains "$e2e_script_text" "--sp1-withdraw-witness-item-file" "sp1 withdraw witness option"
  assert_not_contains "$e2e_script_text" "--sp1-deposit-witness-wallet-id" "manual witness wallet id flag removed"
  assert_not_contains "$e2e_script_text" "--sp1-deposit-witness-txid" "manual deposit txid flag removed"
  assert_not_contains "$e2e_script_text" "--sp1-withdraw-witness-wallet-id" "manual withdraw wallet id flag removed"
  assert_not_contains "$e2e_script_text" "--sp1-withdraw-witness-txid" "manual withdraw txid flag removed"
  assert_not_contains "$e2e_script_text" "--sp1-withdraw-witness-withdrawal-id-hex" "manual withdraw id flag removed"
  assert_not_contains "$e2e_script_text" "--sp1-withdraw-witness-recipient-raw-address-hex" "manual recipient raw address flag removed"
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
  assert_contains "$e2e_script_text" 'getraw_params="$(jq -cn --arg txid "$txid" '\''[ $txid ]'\'')"' "juno rebroadcast uses single-arg getrawtransaction call"
  assert_not_contains "$e2e_script_text" '[ $txid, false ]' "juno rebroadcast does not use boolean getrawtransaction verbosity"
  assert_contains "$e2e_script_text" "sendrawtransaction" "juno rebroadcast submits raw transaction"
  assert_not_contains "$e2e_script_text" "bridge_juno_execution_tx_hash=\"\$generated_withdraw_txid\"" "bridge no longer uses pre-generated withdraw tx hash as canonical juno proof source"
  assert_not_contains "$e2e_script_text" "canonical juno execution tx hash is required" "pre-generated canonical juno proof hash gate removed"
  assert_not_contains "$e2e_script_text" "--sp1-guest-witness-manifest" "legacy guest witness manifest option removed"
  assert_contains "$e2e_script_text" "sp1_input_mode == \"guest-witness-v1\"" "guest witness mode validation"
  assert_contains "$e2e_script_text" "guest_witness_auto_generate" "guest witness auto generate summary wiring"
  assert_contains "$e2e_script_text" "endpoint_quorum_threshold: \$sp1_witness_quorum_threshold" "summary stores witness quorum threshold"
  assert_contains "$e2e_script_text" "endpoint_pool_size: \$witness_endpoint_pool_size" "summary stores witness pool size"
  assert_contains "$e2e_script_text" "endpoint_healthy_count: \$witness_endpoint_healthy_count" "summary stores healthy witness endpoint count"
  assert_contains "$e2e_script_text" "metadata_source_operator:" "summary stores witness metadata source operator"
  assert_contains "$e2e_script_text" "pool_operator_labels: \$witness_pool_operator_labels" "summary stores witness pool operators"
  assert_contains "$e2e_script_text" "healthy_operator_labels: \$witness_healthy_operator_labels" "summary stores healthy witness operators"
  assert_contains "$e2e_script_text" "quorum_operator_labels: \$witness_quorum_operator_labels" "summary stores quorum-validated witness operators"
  assert_contains "$e2e_script_text" "quorum_validated_count: \$witness_quorum_validated_count" "summary stores witness quorum validated count"
  assert_contains "$e2e_script_text" "quorum_validated: (\$witness_quorum_validated == \"true\")" "summary stores witness quorum validation flag"
  assert_not_contains "$e2e_script_text" "sp1_guest_witness_manifest" "guest witness manifest variable removed"
  assert_contains "$e2e_script_text" "--sp1-market-address" "sp1 market option"
  assert_contains "$e2e_script_text" "--sp1-verifier-router-address" "sp1 verifier router option"
  assert_contains "$e2e_script_text" "--sp1-set-verifier-address" "sp1 set verifier option"
  assert_contains "$e2e_script_text" "\"--sp1-market-address\" \"\$sp1_market_address\"" "sp1 market bridge forwarding"
  assert_contains "$e2e_script_text" "\"--sp1-verifier-router-address\" \"\$sp1_verifier_router_address\"" "sp1 verifier router bridge forwarding"
  assert_contains "$e2e_script_text" "\"--sp1-set-verifier-address\" \"\$sp1_set_verifier_address\"" "sp1 set verifier bridge forwarding"
  assert_contains "$e2e_script_text" "log \"juno_tx_hash=\$juno_tx_hash source=\$juno_tx_hash_source\"" "juno tx hash log when present"
  assert_contains "$e2e_script_text" "log \"juno_tx_hash=unavailable\"" "juno tx hash unavailable log"
  assert_contains "$e2e_script_text" "wait_for_withdrawal_payout_txid" "juno tx hash resolved from withdraw coordinator payout state"
  assert_contains "$e2e_script_text" "withdraw_coordinator.payout_state" "summary juno proof source reflects coordinator payout state"
  assert_not_contains "$e2e_script_text" ".transactions.finalize_withdraw?" "bridge summary does not accept base finalize withdraw fallback"
  assert_contains "$e2e_script_text" "withdraw coordinator payout state missing juno tx hash" "bridge summary fails when payout-state proof hash is missing"
  assert_contains "$e2e_script_text" "--arg juno_tx_hash \"\$juno_tx_hash\"" "summary receives juno tx hash"
  assert_contains "$e2e_script_text" "--arg juno_tx_hash_source \"\$juno_tx_hash_source\"" "summary receives juno tx hash source"
  assert_contains "$e2e_script_text" "tx_hash_source: (if \$juno_tx_hash_source == \"\" then null else \$juno_tx_hash_source end)" "summary stores juno tx hash source"
  assert_contains "$e2e_script_text" "tx_hash: (if \$juno_tx_hash == \"\" then null else \$juno_tx_hash end)" "summary stores juno tx hash"
  assert_contains "$e2e_script_text" "check_relayer_flow_invariants()" "run-scoped bridge invariant check helper exists"
  assert_contains "$e2e_script_text" "depositUsed(bytes32)" "run-scoped invariants validate depositUsed"
  assert_contains "$e2e_script_text" "getWithdrawal(bytes32)" "run-scoped invariants validate withdrawal state"
  assert_contains "$e2e_script_text" "--expiry-safety-margin \"30h\"" "withdraw coordinator is configured to force expiry extension coverage"
  assert_contains "$e2e_script_text" "run_withdraw_request_expiry" "run-scoped invariants track requested withdraw expiry"
  assert_contains "$e2e_script_text" "withdraw expiry did not increase after forced extension" "run-scoped invariants assert on-chain expiry extension"
  assert_contains "$e2e_script_text" "run_refund_after_expiry_scenario()" "live e2e defines refund-after-expiry chaos scenario helper"
  assert_contains "$e2e_script_text" "Bridge.setParams(uint96,uint96,uint64,uint64)" "refund-after-expiry scenario temporarily configures bridge refund window"
  assert_contains "$e2e_script_text" "refund-after-expiry scenario restoring Bridge.setParams(uint96,uint96,uint64,uint64)" "refund-after-expiry scenario restores original bridge params"
  assert_contains "$e2e_script_text" "refund(bytes32)" "refund-after-expiry scenario calls on-chain refund"
  assert_contains "$e2e_script_text" "withdrawal refund did not transition to refunded=true" "refund-after-expiry scenario asserts on-chain refunded state"
  assert_contains "$e2e_script_text" "refund_after_expiry_status" "refund-after-expiry scenario status tracked"
  assert_contains "$e2e_script_text" "refund_after_expiry_withdrawal_id" "refund-after-expiry scenario tracks withdrawal id"
  assert_contains "$e2e_script_text" "refund_after_expiry_refund_tx_hash" "refund-after-expiry scenario tracks refund tx hash"
  assert_contains "$e2e_script_text" "balance delta invariant failed" "run-scoped invariants validate fee/balance deltas"
  assert_contains "$e2e_script_text" "run_direct_cli_user_proof_scenario()" "live e2e defines direct-cli proof scenario helper"
  assert_contains "$e2e_script_text" "\"--sp1-proof-submission-mode\" \"\$direct_cli_proof_submission_mode\"" "direct-cli proof scenario forwards configured submission mode"
  assert_not_contains "$e2e_script_text" '(( ${#sp1_withdraw_witness_item_files[@]} > 0 )) || return 1' "direct-cli proof scenario does not require pre-generated withdraw witness files"
  assert_contains "$e2e_script_text" "direct-cli-user-proof-deploy-summary.json" "direct-cli proof scenario records deploy bootstrap summary"
  assert_not_contains "$e2e_script_text" 'direct_cli_bridge_deploy_args+=("--sp1-deposit-witness-item-file"' "direct-cli deploy bootstrap avoids manual deposit witness flags"
  assert_not_contains "$e2e_script_text" 'direct_cli_bridge_deploy_args+=("--sp1-withdraw-witness-item-file"' "direct-cli deploy bootstrap avoids manual withdraw witness flags"
  assert_not_contains "$e2e_script_text" $'--sp1-requestor-key-file" "$direct_cli_requestor_key_file"\n      "--sp1-deposit-owallet-ivk-hex" "$sp1_deposit_owallet_ivk_hex"' "direct-cli deploy bootstrap avoids partial manual guest witness inputs"
  assert_contains "$e2e_script_text" 'direct_cli_bridge_run_args+=("--sp1-deposit-owallet-ivk-hex" "$sp1_deposit_owallet_ivk_hex")' "direct-cli run phase injects deposit owallet ivk only with manual witness files"
  assert_contains "$e2e_script_text" 'direct_cli_bridge_run_args+=("--sp1-withdraw-owallet-ovk-hex" "$sp1_withdraw_owallet_ovk_hex")' "direct-cli run phase injects withdraw owallet ovk only with manual witness files"
  assert_contains "$e2e_script_text" "--existing-wjuno-address" "direct-cli proof scenario reuses deployed wjuno contract"
  assert_contains "$e2e_script_text" "--existing-operator-registry-address" "direct-cli proof scenario reuses deployed operator registry contract"
  assert_contains "$e2e_script_text" "--existing-fee-distributor-address" "direct-cli proof scenario reuses deployed fee distributor contract"
  assert_contains "$e2e_script_text" "--existing-bridge-address" "direct-cli proof scenario reuses deployed bridge contract"
  assert_not_contains "$e2e_script_text" 'direct_cli_bridge_deploy_nonce=$((direct_cli_deployer_nonce + 3))' "direct-cli proof scenario no longer predicts bridge address from nonce offset"
  assert_contains "$e2e_script_text" "direct-cli user proof scenario failed" "live e2e fails hard when direct-cli proof scenario fails"
  assert_contains "$e2e_script_text" "run_operator_down_threshold_scenario()" "live e2e defines operator-down threshold scenario helper"
  assert_contains "$e2e_script_text" "inject_operator_endpoint_failure()" "live e2e defines operator failure injection helper"
  assert_contains "$e2e_script_text" "lsof -tiTCP" "operator-down scenarios perform real listener/process disruption"
  assert_contains "$e2e_script_text" "threshold signer probe failed under operator-down scenario" "operator-down scenarios assert threshold signing still succeeds"
  assert_contains "$e2e_script_text" "--blob-driver s3" "live e2e uses durable s3 blob driver for withdraw services"
  assert_contains "$e2e_script_text" "--tss-server-ca-file \"\$withdraw_coordinator_tss_server_ca_file\"" "withdraw coordinator uses TLS server CA verification"
  assert_contains "$e2e_script_text" "--withdraw-witness-extractor-enabled" "withdraw finalizer enables runtime witness extraction"
  assert_contains "$e2e_script_text" "--juno-scan-wallet-id \"\$withdraw_coordinator_juno_wallet_id\"" "withdraw finalizer witness extractor uses runtime wallet id"
  assert_not_contains "$e2e_script_text" "--proof-witness-item-file \"\$withdraw_witness_file\"" "withdraw requests no longer inject pre-generated witness item bytes"
  assert_contains "$e2e_script_text" "dkg_report_public_json" "summary builds redacted dkg report payload"
  assert_contains "$e2e_script_text" "operator_key_file" "summary redaction touches operator key path field"
  assert_contains "$e2e_script_text" "backup_package" "summary redaction touches backup package path field"
  assert_contains "$e2e_script_text" "shared_infra" "shared infra summary section"
  assert_contains "$e2e_script_text" "proof_topics" "shared summary includes proof topics"
  assert_contains "$e2e_script_text" "proof_services" "shared summary includes proof service metadata"
  assert_contains "$e2e_script_text" "direct_cli_user_proof" "summary records direct-cli user proof scenario"
  assert_contains "$e2e_script_text" "expiry_extension" "summary records forced expiry extension scenario"
  assert_contains "$e2e_script_text" "refund_after_expiry" "summary records refund-after-expiry scenario"
  assert_contains "$e2e_script_text" "operator_down_1" "summary records one-operator-down scenario"
  assert_contains "$e2e_script_text" "operator_down_2" "summary records two-operator-down scenario"
  assert_contains "$e2e_script_text" "--arg aws_dr_region \"\$aws_dr_region\"" "summary receives aws dr region passthrough"
  assert_contains "$e2e_script_text" "dr_region: (if \$aws_dr_region == \"\" then null else \$aws_dr_region end)" "summary stores aws dr region passthrough"
}

test_e2e_workflows_exclude_sensitive_artifact_paths() {
  local aws_workflow_text local_workflow_text
  aws_workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy-aws.yml")"
  local_workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy.yml")"

  assert_contains "$aws_workflow_text" '${{ runner.temp }}/aws-live-e2e/artifacts' "aws workflow uploads artifact directory"
  assert_contains "$aws_workflow_text" "e2e-testnet-deploy-aws-resume-state" "aws workflow uploads canary resume-state artifact"
  assert_contains "$aws_workflow_text" '${{ runner.temp }}/aws-live-e2e/infra' "aws workflow includes terraform infra state in resume bundle"
  assert_contains "$aws_workflow_text" '${{ runner.temp }}/aws-live-e2e/ssh' "aws workflow includes ssh material in resume bundle for full_run handoff"
  assert_contains "$aws_workflow_text" "Download Canary Resume State" "aws workflow downloads canary resume bundle before full_run"
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
  assert_contains "$workflow_text" "sp1_deposit_owallet_ivk_hex" "non-aws workflow exposes deposit ivk input"
  assert_contains "$workflow_text" "sp1_withdraw_owallet_ovk_hex" "non-aws workflow exposes withdraw ovk input"
  assert_contains "$workflow_text" 'default: "https://rpc.mainnet.succinct.xyz"' "non-aws workflow defaults sp1 rpc to succinct mainnet network rpc"
  assert_not_contains "$workflow_text" 'default: "https://mainnet.base.org"' "non-aws workflow no longer defaults sp1 rpc to base chain endpoint"
  assert_contains "$workflow_text" "sp1_witness_juno_scan_url" "non-aws workflow exposes juno-scan witness input"
  assert_contains "$workflow_text" "sp1_witness_juno_rpc_url" "non-aws workflow exposes junocashd witness input"
  assert_not_contains "$workflow_text" "sp1_witness_config_json" "non-aws workflow no longer uses witness config blob"
  assert_not_contains "$workflow_text" "--sp1-deposit-witness-wallet-id" "non-aws workflow no longer forwards external witness wallet ids"
  assert_not_contains "$workflow_text" "--sp1-deposit-witness-txid" "non-aws workflow no longer forwards external witness txids"
  assert_not_contains "$workflow_text" "--sp1-withdraw-witness-txid" "non-aws workflow no longer forwards external withdraw txids"
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
  assert_contains "$workflow_text" 'ami_id="$(jq -r --arg region' "operator stack ami workflow derives ami id from manifest instead of log output"
  assert_not_contains "$workflow_text" 'ami_id="$(tr -d '\''\r\n'\'' < .ci/out/operator-ami-id.txt)"' "operator stack ami workflow no longer parses ami id from mixed log output file"
  assert_contains "$workflow_text" "Juno network: testnet" "operator stack ami workflow release notes explicitly state juno testnet scope"
  assert_contains "$workflow_text" "gh release" "operator stack ami workflow creates/updates release"
}

test_operator_stack_ami_release_workflow_supports_explicit_network_inputs() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/release-operator-stack-ami.yml")"

  assert_contains "$workflow_text" "aws_vpc_id:" "operator stack ami workflow exposes optional vpc input"
  assert_contains "$workflow_text" "aws_subnet_id:" "operator stack ami workflow exposes optional subnet input"
  assert_contains "$workflow_text" "source_ami_id:" "operator stack ami workflow exposes optional source ami override input"
  assert_contains "$workflow_text" "Resolve Builder Network" "operator stack ami workflow resolves builder network defaults when unset"
  assert_contains "$workflow_text" "Resolve Source AMI" "operator stack ami workflow resolves reusable source ami defaults when unset"
  assert_contains "$workflow_text" "--vpc-id" "operator stack ami workflow forwards resolved vpc id"
  assert_contains "$workflow_text" "--subnet-id" "operator stack ami workflow forwards resolved subnet id"
  assert_contains "$workflow_text" "--source-ami-id" "operator stack ami workflow forwards resolved source ami id when available"
}

test_long_running_aws_workflows_request_extended_oidc_session() {
  local ami_workflow_text aws_e2e_workflow_text
  ami_workflow_text="$(cat "$REPO_ROOT/.github/workflows/release-operator-stack-ami.yml")"
  aws_e2e_workflow_text="$(cat "$REPO_ROOT/.github/workflows/e2e-testnet-deploy-aws.yml")"

  assert_contains "$ami_workflow_text" "role-duration-seconds: 21600" "operator stack ami workflow requests extended oidc session duration"
  assert_contains "$aws_e2e_workflow_text" "role-duration-seconds: 21600" "aws e2e workflow requests extended oidc session duration"
}

test_bridge_guest_release_workflow_exists() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/release-bridge-guest-programs.yml")"

  assert_contains "$workflow_text" "name: release-bridge-guest-programs" "bridge guest release workflow name"
  assert_contains "$workflow_text" "release_tag:" "bridge guest release workflow release tag input"
  assert_contains "$workflow_text" 'export PATH="$HOME/.sp1/bin:$PATH"' "bridge guest release workflow adds sp1up install path to shell"
  assert_contains "$workflow_text" "sp1up" "bridge guest release workflow installs SP1 toolchain"
  assert_contains "$workflow_text" "cargo prove build -p deposit-guest -p withdraw-guest --output-directory ../.ci/out" "bridge guest release workflow builds deposit/withdraw guests"
  assert_contains "$workflow_text" "cargo prove vkey --elf" "bridge guest release workflow computes guest vkeys"
  assert_contains "$workflow_text" "gh release" "bridge guest release workflow creates/updates release"
}

test_operator_stack_ami_runbook_builds_full_stack_and_records_blockstamp() {
  local runbook_text
  runbook_text="$(cat "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh")"

  assert_contains "$runbook_text" 'go build -o "\$out_dir/base-relayer" ./cmd/base-relayer' "runbook builds base-relayer binary"
  assert_contains "$runbook_text" 'go build -o "\$out_dir/deposit-relayer" ./cmd/deposit-relayer' "runbook builds deposit-relayer binary"
  assert_contains "$runbook_text" 'go build -o "\$out_dir/withdraw-coordinator" ./cmd/withdraw-coordinator' "runbook builds withdraw-coordinator binary"
  assert_contains "$runbook_text" 'go build -o "\$out_dir/withdraw-finalizer" ./cmd/withdraw-finalizer' "runbook builds withdraw-finalizer binary"
  assert_contains "$runbook_text" 'sudo install -m 0755 "\$out_dir/base-relayer" /usr/local/bin/base-relayer' "runbook installs base-relayer binary"
  assert_contains "$runbook_text" 'sudo install -m 0755 "\$out_dir/deposit-relayer" /usr/local/bin/deposit-relayer' "runbook installs deposit-relayer binary"
  assert_contains "$runbook_text" 'sudo install -m 0755 "\$out_dir/withdraw-coordinator" /usr/local/bin/withdraw-coordinator' "runbook installs withdraw-coordinator binary"
  assert_contains "$runbook_text" 'sudo install -m 0755 "\$out_dir/withdraw-finalizer" /usr/local/bin/withdraw-finalizer' "runbook installs withdraw-finalizer binary"

  assert_contains "$runbook_text" "junocashd.service" "runbook installs junocashd service"
  assert_contains "$runbook_text" "juno-scan.service" "runbook installs juno-scan service"
  assert_contains "$runbook_text" "JUNO_SCAN_UA_HRP=jtest" "runbook defaults juno-scan UA HRP to testnet"
  assert_contains "$runbook_text" "JUNO_SCAN_CONFIRMATIONS=1" "runbook defaults juno-scan confirmation depth for live witness indexing"
  assert_contains "$runbook_text" '-ua-hrp "${JUNO_SCAN_UA_HRP:-jtest}"' "runbook passes juno-scan UA HRP from operator stack env"
  assert_contains "$runbook_text" '-confirmations "${JUNO_SCAN_CONFIRMATIONS:-1}"' "runbook passes juno-scan confirmation depth from operator stack env"
  assert_contains "$runbook_text" "checkpoint-signer.service" "runbook installs checkpoint signer service"
  assert_contains "$runbook_text" "checkpoint-aggregator.service" "runbook installs checkpoint aggregator service"
  assert_contains "$runbook_text" "intents-juno-config-hydrator.service" "runbook installs operator stack config hydrator service"
  assert_contains "$runbook_text" "/usr/local/bin/intents-juno-config-hydrator.sh" "runbook installs operator stack config hydrator script"
  assert_contains "$runbook_text" "OPERATOR_STACK_CONFIG_JSON_PATH=/etc/intents-juno/operator-stack-config.json" "runbook defaults hydrator json artifact path"
  assert_contains "$runbook_text" "OPERATOR_STACK_CONFIG_SECRET_ID=" "runbook exposes hydrator secrets manager source selector"
  assert_contains "$runbook_text" 'aws --region "$secret_region" secretsmanager get-secret-value' "runbook hydrator can pull config from secrets manager"
  assert_contains "$runbook_text" "install_aws_cli()" "runbook defines aws cli installer helper"
  assert_contains "$runbook_text" "awscli-exe-linux-x86_64.zip" "runbook installs aws cli from official amd64 bundle"
  assert_contains "$runbook_text" "awscli-exe-linux-aarch64.zip" "runbook installs aws cli from official arm64 bundle"
  assert_contains "$runbook_text" "run_with_retry install_aws_cli" "runbook invokes aws cli installer with retries"
  assert_not_contains "$runbook_text" "apt-get install -y ca-certificates curl jq tar git golang-go build-essential make openssl awscli" "runbook no longer relies on removed awscli apt package"
  assert_contains "$runbook_text" "Before=checkpoint-signer.service checkpoint-aggregator.service tss-host.service deposit-relayer.service withdraw-coordinator.service withdraw-finalizer.service" "runbook orders config hydrator before dependent services"
  assert_contains "$runbook_text" "After=junocashd.service intents-juno-config-hydrator.service" "runbook wires checkpoint signer ordering behind config hydrator"
  assert_contains "$runbook_text" "After=network-online.target intents-juno-config-hydrator.service" "runbook wires tss-host ordering behind config hydrator"
  assert_contains "$runbook_text" "After=base-relayer.service intents-juno-config-hydrator.service" "runbook wires relayer ordering behind config hydrator"
  assert_contains "$runbook_text" "sudo systemctl enable intents-juno-config-hydrator.service" "runbook enables config hydrator at boot"
  assert_contains "$runbook_text" "base-relayer.service" "runbook installs base-relayer service"
  assert_contains "$runbook_text" "deposit-relayer.service" "runbook installs deposit-relayer service"
  assert_contains "$runbook_text" "withdraw-coordinator.service" "runbook installs withdraw-coordinator service"
  assert_contains "$runbook_text" "withdraw-finalizer.service" "runbook installs withdraw-finalizer service"
  assert_contains "$runbook_text" "CHECKPOINT_POSTGRES_DSN=" "runbook records checkpoint postgres dsn placeholder in operator stack env"
  assert_contains "$runbook_text" "CHECKPOINT_KAFKA_BROKERS=" "runbook records checkpoint kafka brokers placeholder in operator stack env"
  assert_contains "$runbook_text" "CHECKPOINT_BLOB_BUCKET=" "runbook records checkpoint blob bucket placeholder in operator stack env"
  assert_contains "$runbook_text" "CHECKPOINT_IPFS_API_URL=" "runbook records checkpoint ipfs api placeholder in operator stack env"
  assert_contains "$runbook_text" "sudo chown ubuntu:ubuntu /etc/intents-juno/junocashd.conf" "runbook makes junocashd.conf readable by service user"
  assert_contains "$runbook_text" "sudo chown ubuntu:ubuntu /etc/intents-juno/operator-stack.env" "runbook makes operator stack env readable by service user"
  assert_contains "$runbook_text" "sudo chown ubuntu:ubuntu /etc/intents-juno/checkpoint-signer.key" "runbook grants checkpoint key access to ubuntu services"
  assert_contains "$runbook_text" "sudo chmod 0600 /etc/intents-juno/checkpoint-signer.key" "runbook enforces checkpoint key file permissions after keygen"
  assert_contains "$runbook_text" "BASE_RELAYER_PRIVATE_KEYS=" "runbook records base relayer signer key placeholder in operator stack env"
  assert_contains "$runbook_text" "BASE_RELAYER_AUTH_TOKEN=" "runbook records base relayer auth token placeholder in operator stack env"
  assert_contains "$runbook_text" "DEPOSIT_IMAGE_ID=" "runbook records deposit relayer image id placeholder in operator stack env"
  assert_contains "$runbook_text" "WITHDRAW_IMAGE_ID=" "runbook records withdraw finalizer image id placeholder in operator stack env"
  assert_contains "$runbook_text" "WITHDRAW_BLOB_BUCKET=" "runbook records withdraw blob bucket placeholder in operator stack env"
  assert_contains "$runbook_text" "WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=" "runbook records withdraw coordinator tss ca path placeholder in operator stack env"
  assert_contains "$runbook_text" "JUNO_QUEUE_KAFKA_TLS=true" "runbook defaults kafka clients to tls"
  assert_contains "$runbook_text" "sslmode=require" "runbook enforces tls postgres dsn mode"
  assert_contains "$runbook_text" "--proof-driver queue" "runbook configures relayer proof clients to queue mode"
  assert_contains "$runbook_text" "--queue-driver kafka" "runbook configures checkpoint services to use kafka queueing"
  assert_contains "$runbook_text" "--store-driver postgres" "runbook configures checkpoint aggregator to use postgres store"
  assert_contains "$runbook_text" "--blob-driver s3" "runbook configures checkpoint aggregator to use s3 blob store"
  assert_contains "$runbook_text" "--ipfs-enabled=true" "runbook enables checkpoint ipfs pinning"
  assert_not_contains "$runbook_text" "--queue-driver stdio" "runbook removes stdio checkpoint queue mode"
  assert_not_contains "$runbook_text" "--store-driver memory" "runbook removes memory checkpoint store mode"
  assert_not_contains "$runbook_text" "--blob-driver memory" "runbook removes memory checkpoint blob mode"
  assert_not_contains "$runbook_text" "--ipfs-enabled=false" "runbook removes disabled checkpoint ipfs mode"
  assert_contains "$runbook_text" "wait_for_service_active()" "runbook defines a helper that waits for service activation before declaring bootstrap success"
  assert_contains "$runbook_text" "service failed to become active" "runbook emits service readiness diagnostics before failing bootstrap"
  assert_contains "$runbook_text" "bootstrap failed at line" "runbook emits line-aware bootstrap error diagnostics"
  assert_contains "$runbook_text" "headers > 0 && blocks + 1 >= headers" "runbook requires observed headers before accepting sync completion"
  assert_contains "$runbook_text" "tss-host.service" "runbook installs tss-host service"
  assert_contains "$runbook_text" "--signer-bin /usr/local/bin/tss-signer" "runbook configures tss-host to use real tss-signer binary"
  assert_contains "$runbook_text" "--signer-arg --ufvk-file" "runbook forwards ufvk signer arg"
  assert_contains "$runbook_text" "--signer-arg --spendauth-signer-bin" "runbook forwards spendauth signer arg"
  assert_contains "$runbook_text" "--signer-arg /usr/local/bin/intents-juno-spendauth-signer.sh" "runbook routes tss spendauth signing through mode-aware wrapper"
  assert_contains "$runbook_text" "TSS_TLS_CERT_FILE=" "runbook records tss tls cert path in operator stack env"
  assert_contains "$runbook_text" "TSS_TLS_KEY_FILE=" "runbook records tss tls key path in operator stack env"
  assert_contains "$runbook_text" 'local tss_signer_runtime_mode="nitro-enclave"' "runbook defaults tss signer runtime mode to nitro enclave"
  assert_contains "$runbook_text" "TSS_SIGNER_RUNTIME_MODE=__BOOTSTRAP_TSS_SIGNER_RUNTIME_MODE__" "runbook wires selected tss signer runtime mode into operator stack env"
  assert_contains "$runbook_text" 'script="${script//\\\$/\$}"' "runbook unescapes deferred shell variables in quoted bootstrap template"
  assert_contains "$runbook_text" "--tss-signer-runtime-mode <mode>" "runbook exposes tss signer runtime mode option"
  assert_contains "$runbook_text" "--tss-signer-runtime-mode must be nitro-enclave or host-process" "runbook validates tss signer runtime mode option values"
  assert_contains "$runbook_text" "TSS_NITRO_ENCLAVE_EIF_FILE=" "runbook records nitro enclave image artifact path"
  assert_contains "$runbook_text" "TSS_NITRO_SPENDAUTH_SIGNER_BIN=" "runbook records nitro spendauth signer bridge binary path"
  assert_contains "$runbook_text" "TSS_NITRO_ATTESTATION_FILE=" "runbook records nitro attestation evidence file path"
  assert_contains "$runbook_text" "TSS_NITRO_EXPECTED_PCR0=" "runbook records nitro pcr0 expectation placeholder"
  assert_contains "$runbook_text" "TSS_NITRO_EXPECTED_PCR1=" "runbook records nitro pcr1 expectation placeholder"
  assert_contains "$runbook_text" "TSS_NITRO_EXPECTED_PCR2=" "runbook records nitro pcr2 expectation placeholder"
  assert_contains "$runbook_text" 'required_key "TSS_NITRO_EXPECTED_PCR0 when TSS_SIGNER_RUNTIME_MODE=nitro-enclave"' "runbook hydrator requires pcr0 when nitro mode is enabled"
  assert_contains "$runbook_text" 'required_key "TSS_NITRO_EXPECTED_PCR1 when TSS_SIGNER_RUNTIME_MODE=nitro-enclave"' "runbook hydrator requires pcr1 when nitro mode is enabled"
  assert_contains "$runbook_text" 'required_key "TSS_NITRO_EXPECTED_PCR2 when TSS_SIGNER_RUNTIME_MODE=nitro-enclave"' "runbook hydrator requires pcr2 when nitro mode is enabled"
  assert_contains "$runbook_text" 'install -m 0640 -o root -g ubuntu "$tmp_env" "$stack_env_file"' "runbook hydrator preserves operator stack env readability for ubuntu services"
  assert_contains "$runbook_text" "requires TSS_NITRO_EXPECTED_PCR0 as 96 hex chars" "runbook hydrator validates pcr0 format"
  assert_contains "$runbook_text" "requires TSS_NITRO_EXPECTED_PCR1 as 96 hex chars" "runbook hydrator validates pcr1 format"
  assert_contains "$runbook_text" "requires TSS_NITRO_EXPECTED_PCR2 as 96 hex chars" "runbook hydrator validates pcr2 format"
  assert_contains "$runbook_text" "TSS_NITRO_ATTESTATION_MAX_AGE_SECONDS=300" "runbook defaults nitro attestation freshness window"
  assert_contains "$runbook_text" "requires CHECKPOINT_POSTGRES_DSN to include sslmode=require (or verify-ca/verify-full)" "runbook hydrator enforces postgres tls mode for checkpoint services"
  assert_contains "$runbook_text" "requires JUNO_QUEUE_KAFKA_TLS=true for kafka TLS transport" "runbook hydrator enforces kafka tls mode"
  assert_contains "$runbook_text" "--tls-cert-file \"\${TSS_TLS_CERT_FILE}\"" "runbook configures tss-host tls cert"
  assert_contains "$runbook_text" "--tls-key-file \"\${TSS_TLS_KEY_FILE}\"" "runbook configures tss-host tls key"
  assert_not_contains "$runbook_text" "--insecure-http" "runbook removes insecure tss-host http mode"
  assert_contains "$runbook_text" "TSS_SIGNER_UFVK_FILE=" "runbook records ufvk runtime artifact path"
  assert_contains "$runbook_text" "TSS_SPENDAUTH_SIGNER_BIN=" "runbook records spendauth signer runtime artifact path"
  assert_contains "$runbook_text" "tss-host nitro mode requires TSS_NITRO_ENCLAVE_EIF_FILE" "runbook validates nitro enclave image artifact before tss-host startup"
  assert_contains "$runbook_text" "tss-host host-process mode requires TSS_SPENDAUTH_SIGNER_BIN" "runbook validates host fallback signer binary when host mode is selected"
  assert_contains "$runbook_text" "unsupported TSS_SIGNER_RUNTIME_MODE" "runbook rejects unknown tss signer runtime mode"
  assert_contains "$runbook_text" "tss-host nitro attestation pcr0 mismatch" "runbook validates nitro attestation pcr0"
  assert_not_contains "$runbook_text" '--signer-arg "${TSS_SPENDAUTH_SIGNER_BIN}"' "runbook no longer binds tss-host directly to host spendauth signer"
  assert_not_contains "$runbook_text" "--signer-bin /bin/true" "runbook no longer configures noop tss signer"
  assert_not_contains "$runbook_text" "--runtime-mode mock" "runbook excludes withdraw coordinator mock runtime mode"
  assert_not_contains "$runbook_text" "--proof-driver mock" "runbook excludes mock proof driver settings"
  assert_not_contains "$runbook_text" "--tss-insecure-http" "runbook excludes insecure tss client mode"
  assert_not_contains "$runbook_text" "sslmode=disable" "runbook excludes insecure postgres tls disable mode"
  assert_contains "$runbook_text" "getblockchaininfo" "runbook checks junocashd sync status"
  assert_contains "$runbook_text" "getbestblockhash" "runbook records synced blockstamp hash"
  assert_contains "$runbook_text" "sudo grep '^JUNO_RPC_USER=' /etc/intents-juno/operator-stack.env" "runbook reads junocash rpc user via sudo for root-owned env file"
  assert_contains "$runbook_text" "sudo grep '^JUNO_RPC_PASS=' /etc/intents-juno/operator-stack.env" "runbook reads junocash rpc password via sudo for root-owned env file"
  assert_contains "$runbook_text" 'rpc_user: \$junocash_rpc_user' "runbook bootstrap metadata records junocash rpc username"
  assert_contains "$runbook_text" 'rpc_password: \$junocash_rpc_pass' "runbook bootstrap metadata records junocash rpc password"
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
  assert_contains "$workflow_text" "sp1_deposit_owallet_ivk_hex" "aws workflow exposes deposit ivk input"
  assert_contains "$workflow_text" "sp1_withdraw_owallet_ovk_hex" "aws workflow exposes withdraw ovk input"
  assert_contains "$workflow_text" 'default: "https://rpc.mainnet.succinct.xyz"' "aws workflow defaults sp1 rpc to succinct mainnet network rpc"
  assert_not_contains "$workflow_text" 'default: "https://mainnet.base.org"' "aws workflow no longer defaults sp1 rpc to base chain endpoint"
  assert_not_contains "$workflow_text" "sp1_witness_config_json" "aws workflow no longer uses witness config blob"
  assert_not_contains "$workflow_text" "--sp1-witness-juno-scan-url" "aws workflow does not pass external witness scan endpoint"
  assert_not_contains "$workflow_text" "--sp1-witness-juno-rpc-url" "aws workflow does not pass external witness rpc endpoint"
  assert_not_contains "$workflow_text" "--sp1-deposit-witness-txid" "aws workflow no longer forwards external deposit txid"
  assert_not_contains "$workflow_text" "--sp1-withdraw-witness-txid" "aws workflow no longer forwards external withdraw txid"
}

test_proof_services_dockerfile_limits_cargo_memory() {
  local dockerfile_text
  dockerfile_text="$(cat "$REPO_ROOT/deploy/shared/docker/proof-services.Dockerfile")"

  assert_contains "$dockerfile_text" "ENV CARGO_BUILD_JOBS=1" "proof services dockerfile serializes cargo builds for lower memory pressure"
  assert_contains "$dockerfile_text" "ENV CARGO_PROFILE_RELEASE_LTO=false" "proof services dockerfile disables release lto for lower linker memory use"
  assert_contains "$dockerfile_text" "ENV CARGO_PROFILE_RELEASE_DEBUG=0" "proof services dockerfile disables release debuginfo in cargo profile"
  assert_contains "$dockerfile_text" "ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16" "proof services dockerfile increases release codegen units to lower peak memory"
  assert_contains "$dockerfile_text" "ENV CARGO_PROFILE_RELEASE_STRIP=symbols" "proof services dockerfile strips release symbols to reduce build and artifact size"
  assert_contains "$dockerfile_text" "ENV RUSTFLAGS=\"-C debuginfo=0\"" "proof services dockerfile disables rust debuginfo to lower memory pressure"
  assert_contains "$dockerfile_text" "ln -sf /usr/local/bin/sp1-prover-adapter /usr/local/bin/sp1" "proof services dockerfile installs sp1 compatibility symlink"
}

test_root_dockerignore_excludes_local_bloat_from_build_context() {
  local dockerignore_text
  dockerignore_text="$(cat "$REPO_ROOT/.dockerignore")"

  assert_contains "$dockerignore_text" "tmp" "root dockerignore excludes local tmp workspace from image build context"
  assert_contains "$dockerignore_text" "**/.terraform" "root dockerignore excludes terraform provider cache dirs"
  assert_contains "$dockerignore_text" "**/*.tfstate" "root dockerignore excludes terraform state files"
  assert_contains "$dockerignore_text" "**/*.tfstate.*" "root dockerignore excludes terraform state backup/lock artifacts"
}

test_aws_wrapper_rechecks_ssh_before_remote_runner_prepare() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" 'run_with_retry "remote runner ssh readiness"' "aws wrapper retries ssh readiness before remote runner bootstrap"
  assert_contains "$wrapper_script_text" 'wait_for_ssh "$ssh_private_key" "$ssh_user" "$ssh_host"' "aws wrapper remote runner bootstrap explicitly rechecks ssh reachability"
  assert_contains "$wrapper_script_text" 'run_with_retry "remote operator host bootstrap"' "aws wrapper retries remote operator host bootstrap"
  assert_contains "$wrapper_script_text" "git clean -fd" "aws wrapper remote runner bootstrap clears untracked repo files before checkout"
}

test_aws_wrapper_reuses_iterative_ssh_keypair() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" 'if [[ -s "$ssh_key_private" && -s "$ssh_key_public" ]]; then' "aws wrapper reuses existing iterative ssh keypair when present"
  assert_contains "$wrapper_script_text" 'log "reusing existing ssh keypair from prior run: $ssh_key_private"' "aws wrapper logs ssh keypair reuse"
  assert_not_contains "$wrapper_script_text" 'rm -f "$ssh_key_private" "$ssh_key_public"' "aws wrapper no longer unconditionally deletes iterative ssh keypair"
}

test_aws_wrapper_auto_resolves_operator_stack_ami_when_unset() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "resolve_latest_operator_stack_ami()" "aws wrapper defines operator stack ami resolver"
  assert_contains "$wrapper_script_text" "Name=name,Values=intents-juno-operator-stack-*" "aws wrapper queries latest operator stack ami by naming convention"
  assert_contains "$wrapper_script_text" "defaulting --operator-ami-id to latest operator stack AMI" "aws wrapper logs auto-selected operator stack ami"
  assert_contains "$wrapper_script_text" "failed to resolve operator stack AMI; pass --operator-ami-id or build one via deploy/shared/runbooks/build-operator-stack-ami.sh" "aws wrapper hard-fails when no operator stack ami is available"
}

test_aws_wrapper_derives_owallet_keys_from_distributed_ufvk() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "derive_owallet_keys_from_ufvk()" "aws wrapper defines ufvk->owallet key derivation helper"
  assert_contains "$wrapper_script_text" "deploy/operators/dkg/e2e/ufvk-derive-keys/Cargo.toml" "aws wrapper uses tracked ufvk derivation helper manifest"
  assert_contains "$wrapper_script_text" "distributed dkg completion report produced invalid owallet key derivation output" "aws wrapper fails on malformed ufvk derivation output"
  assert_contains "$wrapper_script_text" "warning: overriding forwarded --sp1-deposit-owallet-ivk-hex with distributed dkg ufvk-derived value" "aws wrapper overrides stale forwarded deposit ivk with distributed dkg ufvk"
  assert_contains "$wrapper_script_text" "warning: overriding forwarded --sp1-withdraw-owallet-ovk-hex with distributed dkg ufvk-derived value" "aws wrapper overrides stale forwarded withdraw ovk with distributed dkg ufvk"
  assert_contains "$wrapper_script_text" "using distributed dkg ufvk-derived owallet key material for sp1 guest witness inputs" "aws wrapper always injects distributed dkg-derived owallet keys"
  assert_contains "$wrapper_script_text" "DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA" "aws wrapper captures distributed dkg completion shielded address"
  assert_contains "$wrapper_script_text" "distributed dkg completion report missing juno_shielded_address" "aws wrapper fails when distributed completion report omits shielded recipient"
  assert_contains "$wrapper_script_text" "\"--sp1-witness-recipient-ua\" \"\$DISTRIBUTED_SP1_WITNESS_RECIPIENT_UA\"" "aws wrapper forwards distributed DKG recipient UA to local e2e witness generation"
  assert_contains "$wrapper_script_text" "\"--sp1-witness-recipient-ufvk\" \"\$DISTRIBUTED_COMPLETION_UFVK\"" "aws wrapper forwards distributed DKG UFVK to local e2e witness generation"
  assert_contains "$wrapper_script_text" 'remote_args+=("${sanitized_e2e_args[@]}")' "aws wrapper strips forwarded owallet keys before appending forwarded args"
  assert_not_contains "$wrapper_script_text" "provided --sp1-deposit-owallet-ivk-hex does not match distributed dkg ufvk-derived value" "aws wrapper no longer fails on stale forwarded deposit ivk"
  assert_not_contains "$wrapper_script_text" "provided --sp1-withdraw-owallet-ovk-hex does not match distributed dkg ufvk-derived value" "aws wrapper no longer fails on stale forwarded withdraw ovk"
}

test_aws_wrapper_supports_proof_stage_resume_without_dkg_or_redeploy() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "--skip-distributed-dkg" "aws wrapper exposes skip distributed dkg resume flag"
  assert_contains "$wrapper_script_text" "--reuse-bridge-summary-path" "aws wrapper exposes existing bridge summary resume flag"
  assert_contains "$wrapper_script_text" 'local skip_distributed_dkg="false"' "aws wrapper initializes distributed dkg resume toggle"
  assert_contains "$wrapper_script_text" 'local reuse_bridge_summary_path=""' "aws wrapper initializes bridge summary reuse path"
  assert_contains "$wrapper_script_text" 'if [[ "$skip_distributed_dkg" == "true" ]]; then' "aws wrapper has skip distributed dkg branch"
  assert_contains "$wrapper_script_text" "skipping distributed dkg ceremony and backup/restore setup; reusing existing runner artifacts" "aws wrapper logs distributed dkg skip path"
  assert_contains "$wrapper_script_text" 'copy_remote_secret_file \' "aws wrapper copies reuse bridge summary file to runner secrets when configured"
  assert_contains "$wrapper_script_text" '"$remote_repo/.ci/secrets/reuse-bridge-summary.json"' "aws wrapper stages bridge summary reuse file in runner secrets dir"
  assert_contains "$wrapper_script_text" '"--existing-bridge-summary-path" ".ci/secrets/reuse-bridge-summary.json"' "aws wrapper forwards bridge summary reuse path to remote e2e script"
}

test_terraform_grants_ecs_task_execution_secret_access() {
  local tf_text
  tf_text="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/main.tf")"

  assert_contains "$tf_text" 'data "aws_iam_policy_document" "ecs_task_execution_secrets"' "terraform defines ecs task execution secret access policy"
  assert_contains "$tf_text" "secretsmanager:GetSecretValue" "terraform grants ecs task execution role secret value read access"
  assert_contains "$tf_text" "secretsmanager:DescribeSecret" "terraform grants ecs task execution role secret metadata read access"
  assert_contains "$tf_text" 'resource "aws_iam_role_policy" "ecs_task_execution_secrets"' "terraform attaches ecs task execution secret policy"
  assert_contains "$tf_text" "local.shared_sp1_requestor_secret_arn" "terraform scopes ecs task execution secret policy to configured requestor secret arn"
}

test_aws_wrapper_exposes_preflight_canary_and_status_json() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "run-testnet-e2e-aws.sh preflight" "aws wrapper usage includes preflight command"
  assert_contains "$wrapper_script_text" "run-testnet-e2e-aws.sh canary" "aws wrapper usage includes canary command"
  assert_contains "$wrapper_script_text" "--status-json <path>" "aws wrapper usage documents machine-readable status output"
  assert_contains "$wrapper_script_text" "--preflight-only" "aws wrapper run command supports internal preflight-only mode"
  assert_contains "$wrapper_script_text" "command_preflight()" "aws wrapper implements preflight command handler"
  assert_contains "$wrapper_script_text" "command_canary()" "aws wrapper implements canary command handler"
  assert_contains "$wrapper_script_text" "preflight) command_preflight" "aws wrapper main dispatch includes preflight command"
  assert_contains "$wrapper_script_text" "canary) command_canary" "aws wrapper main dispatch includes canary command"
}

test_aws_wrapper_preflight_runs_required_checks() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "run_preflight_aws_reachability_probes()" "aws wrapper defines preflight aws reachability probe helper"
  assert_contains "$wrapper_script_text" "run_preflight_script_tests()" "aws wrapper defines preflight script test runner"
  assert_contains "$wrapper_script_text" "validate_sp1_credit_guardrail_preflight()" "aws wrapper defines sp1 credit guardrail preflight helper"
  assert_contains "$wrapper_script_text" "run_with_local_timeout" "aws wrapper preflight uses bounded local timeout helpers"
  assert_contains "$wrapper_script_text" "run_with_local_timeout 90 env" "sp1 guardrail balance probe is timeout-bounded"
  assert_contains "$wrapper_script_text" "sp1 balance probe returned error" "aws wrapper preflight surfaces adapter-reported balance errors"
  assert_contains "$wrapper_script_text" "must be a Succinct prover network RPC" "aws wrapper preflight rejects base chain rpc endpoints for sp1"
  assert_not_contains "$wrapper_script_text" "(( balance_wei < required_buffer_wei ))" "aws wrapper preflight avoids shell integer overflow for guardrail comparison"
  assert_contains "$wrapper_script_text" 'python3 - "$balance_wei" "$required_buffer_wei"' "aws wrapper preflight uses big-int guardrail comparison"
  assert_contains "$wrapper_script_text" "preflight missing required forwarded argument after '--'" "aws wrapper preflight hard-fails on missing required forwarded args"
  assert_contains "$wrapper_script_text" 'run_preflight_aws_reachability_probes "$aws_profile" "$aws_region" "$with_shared_services"' "aws wrapper preflight executes aws identity/reachability probes"
  assert_contains "$wrapper_script_text" "run_preflight_script_tests" "aws wrapper preflight executes shell test suite before run"
  assert_contains "$wrapper_script_text" "write_status_json" "aws wrapper preflight writes machine-readable status json"
}

test_aws_wrapper_canary_forces_resume_checkpoint_stage_and_triage() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "canary requires --reuse-bridge-summary-path" "aws wrapper canary requires bridge summary reuse path"
  assert_contains "$wrapper_script_text" "if ! array_has_value \"--keep-infra\"" "aws wrapper canary forces keep-infra"
  assert_contains "$wrapper_script_text" "if ! array_has_value \"--skip-distributed-dkg\"" "aws wrapper canary forces distributed dkg skip"
  assert_contains "$wrapper_script_text" "canary_e2e_args+=(\"--stop-after-stage\" \"checkpoint_validated\")" "aws wrapper canary forces stop-after-stage checkpoint_validated"
  assert_contains "$wrapper_script_text" "validate_canary_summary()" "aws wrapper defines canary acceptance validation helper"
  assert_contains "$wrapper_script_text" "classify_failure_signature()" "aws wrapper defines failure signature classifier helper"
  assert_contains "$wrapper_script_text" "print_failure_classification_hint" "aws wrapper emits classified failure hints on failure"
  assert_contains "$wrapper_script_text" "failure-signatures.yaml" "aws wrapper uses tracked failure signature catalog"
}

test_aws_wrapper_uses_portable_mktemp_templates() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_not_contains "$wrapper_script_text" 'mktemp "${TMPDIR:-/tmp}/aws-live-e2e-preflight.XXXXXX.log"' "aws wrapper preflight mktemp template is portable on BSD/GNU"
  assert_not_contains "$wrapper_script_text" 'mktemp "${TMPDIR:-/tmp}/aws-live-e2e-canary.XXXXXX.log"' "aws wrapper canary mktemp template is portable on BSD/GNU"
  assert_contains "$wrapper_script_text" 'mktemp "${TMPDIR:-/tmp}/aws-live-e2e-preflight.XXXXXX"' "aws wrapper preflight mktemp template ends with XXXXXX"
  assert_contains "$wrapper_script_text" 'mktemp "${TMPDIR:-/tmp}/aws-live-e2e-canary.XXXXXX"' "aws wrapper canary mktemp template ends with XXXXXX"
}

test_aws_wrapper_timeout_fallback_kills_process_groups() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "if have_cmd python3; then" "aws wrapper timeout helper uses python3 fallback before perl alarm fallback"
  assert_contains "$wrapper_script_text" 'python3 - "$timeout_seconds" "$@" <<'\''PY'\''' "aws wrapper timeout helper forwards command args into python fallback"
  assert_contains "$wrapper_script_text" "proc = subprocess.Popen(command, preexec_fn=os.setsid)" "aws wrapper timeout helper isolates fallback command in its own process group"
  assert_contains "$wrapper_script_text" "os.killpg(proc.pid, signal.SIGTERM)" "aws wrapper timeout helper sends SIGTERM to full fallback process group on timeout"
  assert_contains "$wrapper_script_text" "os.killpg(proc.pid, signal.SIGKILL)" "aws wrapper timeout helper escalates to SIGKILL for stubborn fallback process groups"
  assert_contains "$wrapper_script_text" "sys.exit(124)" "aws wrapper timeout helper preserves timeout exit code semantics"
}

test_failure_signature_catalog_exists() {
  local signatures_path signatures_text
  signatures_path="$REPO_ROOT/deploy/operators/dkg/e2e/failure-signatures.yaml"
  [[ -f "$signatures_path" ]] || {
    printf 'failure signature catalog missing: %s\n' "$signatures_path" >&2
    exit 1
  }
  signatures_text="$(cat "$signatures_path")"
  assert_contains "$signatures_text" "\"signatures\"" "failure signature catalog defines signatures array"
  assert_contains "$signatures_text" "\"regex\"" "failure signature catalog entries include regex matcher"
  assert_contains "$signatures_text" "\"class\"" "failure signature catalog entries include failure class"
  assert_contains "$signatures_text" "\"owner\"" "failure signature catalog entries include owning script"
  assert_contains "$signatures_text" "\"suggested_immediate_action\"" "failure signature catalog entries include suggested immediate action"
  jq -e '.signatures | type == "array"' "$signatures_path" >/dev/null
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
  test_aws_wrapper_supports_dr_readiness_and_distributed_relayer_runtime
  test_aws_wrapper_provisions_and_cleans_dr_stack
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
  test_operator_stack_ami_release_workflow_supports_explicit_network_inputs
  test_long_running_aws_workflows_request_extended_oidc_session
  test_bridge_guest_release_workflow_exists
  test_operator_stack_ami_runbook_builds_full_stack_and_records_blockstamp
  test_aws_e2e_workflow_resolves_operator_ami_from_release_when_unset
  test_proof_services_dockerfile_limits_cargo_memory
  test_root_dockerignore_excludes_local_bloat_from_build_context
  test_aws_wrapper_rechecks_ssh_before_remote_runner_prepare
  test_aws_wrapper_reuses_iterative_ssh_keypair
  test_aws_wrapper_auto_resolves_operator_stack_ami_when_unset
  test_aws_wrapper_derives_owallet_keys_from_distributed_ufvk
  test_aws_wrapper_supports_proof_stage_resume_without_dkg_or_redeploy
  test_terraform_grants_ecs_task_execution_secret_access
  test_aws_wrapper_exposes_preflight_canary_and_status_json
  test_aws_wrapper_preflight_runs_required_checks
  test_aws_wrapper_canary_forces_resume_checkpoint_stage_and_triage
  test_aws_wrapper_uses_portable_mktemp_templates
  test_aws_wrapper_timeout_fallback_kills_process_groups
  test_failure_signature_catalog_exists
}

main "$@"
