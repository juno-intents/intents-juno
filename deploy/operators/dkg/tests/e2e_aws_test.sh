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
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 install --path \"\$boundless_source_dir/crates/boundless-cli\" --locked --force" "boundless branch path install command"
  assert_contains "$script_text" "installing rzup for risc0 toolchain" "rzup install log"
  assert_contains "$script_text" "run_with_retry rzup install" "rzup install command"
  assert_contains "$script_text" "command -v r0vm" "r0vm presence check"
  assert_contains "$script_text" "r0vm --version" "r0vm version check"
  assert_contains "$script_text" "boundless --version" "boundless version check"
  assert_not_contains "$script_text" "boundless-market-0.14.1" "legacy boundless crate pin removed"
}

test_remote_shared_prepare_script_waits_for_services() {
  # shellcheck source=../e2e/run-testnet-e2e-aws.sh
  source "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

  local script_text
  script_text="$(
    build_remote_shared_prepare_script \
      "10.0.0.10" \
      "postgres" \
      "pw" \
      "intents_e2e" \
      "5432" \
      "9092"
  )"

  assert_contains "$script_text" "cloud-init status --wait" "cloud-init wait"
  assert_contains "$script_text" "run_apt_with_retry install -y ca-certificates curl docker.io netcat-openbsd postgresql-client" "shared host dependencies"
  assert_contains "$script_text" "docker pull \"\$image\"" "docker pull retry"
  assert_contains "$script_text" "intents-shared-postgres" "postgres container configured"
  assert_contains "$script_text" "intents-shared-kafka" "kafka container configured"
  assert_contains "$script_text" "pg_isready -h 127.0.0.1 -p 5432 -U 'postgres' -d 'intents_e2e'" "postgres readiness check"
  assert_contains "$script_text" "timeout 2 bash -lc '</dev/tcp/127.0.0.1/9092'" "kafka readiness check"
}

test_live_e2e_terraform_supports_operator_instances() {
  local main_tf variables_tf outputs_tf
  main_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/main.tf")"
  variables_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/variables.tf")"
  outputs_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/outputs.tf")"

  assert_contains "$variables_tf" "variable \"operator_instance_count\"" "operator instance count variable"
  assert_contains "$variables_tf" "variable \"operator_instance_type\"" "operator instance type variable"
  assert_contains "$variables_tf" "variable \"operator_root_volume_size_gb\"" "operator root volume variable"
  assert_contains "$variables_tf" "variable \"operator_base_port\"" "operator base port variable"

  assert_contains "$main_tf" "resource \"aws_security_group\" \"operator\"" "operator security group resource"
  assert_contains "$main_tf" "resource \"aws_instance\" \"operator\"" "operator instance resource"
  assert_contains "$main_tf" "count = var.operator_instance_count" "operator instance count wiring"
  assert_contains "$main_tf" "from_port       = var.operator_base_port" "operator grpc ingress start"
  assert_contains "$main_tf" "to_port         = var.operator_base_port + var.operator_instance_count - 1" "operator grpc ingress range"

  assert_contains "$outputs_tf" "output \"operator_instance_ids\"" "operator ids output"
  assert_contains "$outputs_tf" "output \"operator_public_ips\"" "operator public ip output"
  assert_contains "$outputs_tf" "output \"operator_private_ips\"" "operator private ip output"
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
  assert_contains "$wrapper_script_text" "--operator-root-volume-gb" "operator root volume option"
  assert_contains "$wrapper_script_text" "operator_instance_count" "terraform operator count wiring"
  assert_contains "$wrapper_script_text" "operator_instance_type" "terraform operator type wiring"
  assert_contains "$wrapper_script_text" "operator_root_volume_size_gb" "terraform operator root volume wiring"
  assert_contains "$wrapper_script_text" "remote_prepare_operator_host" "remote operator host preparation hook"
  assert_contains "$wrapper_script_text" "run_distributed_dkg_backup_restore" "distributed dkg orchestration hook"
  assert_contains "$wrapper_script_text" "--dkg-summary-path" "external dkg summary forwarding"
  assert_contains "$wrapper_script_text" "-json operator_public_ips" "terraform operator public ips output retrieval"
  assert_contains "$wrapper_script_text" "-json operator_private_ips" "terraform operator private ips output retrieval"
}

test_aws_wrapper_collects_artifacts_after_remote_failures() {
  local wrapper_script_text
  wrapper_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh")"

  assert_contains "$wrapper_script_text" "local remote_run_status=0" "remote run status capture"
  assert_contains "$wrapper_script_text" "set +e" "remote run temporary errexit disable"
  assert_contains "$wrapper_script_text" "remote_run_status=$?" "remote run exit capture"
  assert_contains "$wrapper_script_text" "log \"collecting artifacts\"" "artifact collection after remote run"
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
  assert_contains "$wrapper_script_text" "shared_kafka_brokers=\"\${shared_private_ip}:\${shared_kafka_port}\"" "shared kafka brokers assembly"
  assert_contains "$wrapper_script_text" "-raw shared_public_ip" "shared public ip output retrieval"
  assert_contains "$wrapper_script_text" "remote_prepare_shared_host" "shared host preparation hook"
  assert_contains "$wrapper_script_text" "preparing shared services host (attempt " "shared host preparation retry logs"
  assert_contains "$wrapper_script_text" "shared services reported ready despite ssh exit status" "shared host fallback on nonzero ssh exit"
  assert_contains "$wrapper_script_text" "shared connectivity reported ready despite ssh exit status" "runner connectivity fallback on nonzero ssh exit"
  assert_contains "$wrapper_script_text" "wait_for_shared_connectivity_from_runner" "runner-to-shared readiness gate"
  assert_contains "$wrapper_script_text" "shared service remote args assembled" "shared args assembly logging"
  assert_contains "$wrapper_script_text" "assembling remote e2e arguments" "remote args assembly logging"
  assert_contains "$wrapper_script_text" "failed to build remote command line" "remote args assembly error message"
  assert_contains "$wrapper_script_text" "\"--shared-postgres-dsn\" \"\$shared_postgres_dsn\"" "remote shared postgres arg"
  assert_contains "$wrapper_script_text" "\"--shared-kafka-brokers\" \"\$shared_kafka_brokers\"" "remote shared kafka arg"
}

test_local_e2e_supports_shared_infra_validation() {
  local e2e_script_text
  e2e_script_text="$(cat "$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e.sh")"

  assert_contains "$e2e_script_text" "--shared-postgres-dsn" "shared postgres option"
  assert_contains "$e2e_script_text" "--shared-kafka-brokers" "shared kafka option"
  assert_contains "$e2e_script_text" "go run ./cmd/shared-infra-e2e" "shared infra command invocation"
  assert_not_contains "$e2e_script_text" "run_with_rpc_retry 4 3 \"bridge-e2e\"" "bridge e2e should not be re-invoked on transient rpc wrapper retries"
  assert_contains "$e2e_script_text" "go run ./cmd/bridge-e2e \"\${bridge_args[@]}\"" "bridge e2e direct invocation"
  assert_contains "$e2e_script_text" "--boundless-input-mode" "boundless input mode option"
  assert_contains "$e2e_script_text" "\"--boundless-input-mode\" \"private-input\"" "boundless input mode pinned to private-input"
  assert_contains "$e2e_script_text" "--boundless-market-address" "boundless market option"
  assert_contains "$e2e_script_text" "--boundless-verifier-router-address" "boundless verifier router option"
  assert_contains "$e2e_script_text" "--boundless-set-verifier-address" "boundless set verifier option"
  assert_contains "$e2e_script_text" "\"--boundless-market-address\" \"\$boundless_market_address\"" "boundless market bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-verifier-router-address\" \"\$boundless_verifier_router_address\"" "boundless verifier router bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-set-verifier-address\" \"\$boundless_set_verifier_address\"" "boundless set verifier bridge forwarding"
  assert_contains "$e2e_script_text" "shared_infra" "shared infra summary section"
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

main() {
  test_remote_prepare_script_waits_for_cloud_init_and_retries_apt
  test_remote_shared_prepare_script_waits_for_services
  test_live_e2e_terraform_supports_operator_instances
  test_aws_wrapper_uses_ssh_keepalive_options
  test_aws_wrapper_supports_operator_fleet_and_distributed_dkg
  test_aws_wrapper_collects_artifacts_after_remote_failures
  test_aws_wrapper_wires_shared_services_into_remote_e2e
  test_local_e2e_supports_shared_infra_validation
  test_local_e2e_supports_external_dkg_summary_path
  test_local_e2e_uses_operator_deployer_key
  test_local_e2e_cast_send_handles_already_known_nonce_race
  test_local_e2e_tops_up_bridge_deployer_balance
  test_local_e2e_uses_managed_nonce_for_funding
  test_aws_workflow_dispatch_input_count_within_limit
}

main "$@"
