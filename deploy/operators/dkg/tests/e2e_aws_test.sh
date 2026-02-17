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
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 install --locked --git https://github.com/boundless-xyz/boundless --branch release-1.2 --bin boundless --force" "boundless cli install command"
  assert_contains "$script_text" "run_with_retry cargo +1.91.1 install --locked cargo-risczero --version 3.0.5" "cargo-risczero toolchain pin"
  assert_contains "$script_text" "boundless --version" "boundless version check"
  assert_not_contains "$script_text" "boundless-market-0.14.1" "legacy boundless crate pin removed"
  assert_not_contains "$script_text" "__BOUNDLESS_DUMMY__" "legacy parser workaround removed"
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
  assert_contains "$e2e_script_text" "--boundless-input-mode" "boundless input mode option"
  assert_contains "$e2e_script_text" "\"--boundless-input-mode\" \"\$boundless_input_mode\"" "boundless input mode bridge forwarding"
  assert_contains "$e2e_script_text" "--boundless-market-address" "boundless market option"
  assert_contains "$e2e_script_text" "--boundless-verifier-router-address" "boundless verifier router option"
  assert_contains "$e2e_script_text" "--boundless-set-verifier-address" "boundless set verifier option"
  assert_contains "$e2e_script_text" "\"--boundless-market-address\" \"\$boundless_market_address\"" "boundless market bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-verifier-router-address\" \"\$boundless_verifier_router_address\"" "boundless verifier router bridge forwarding"
  assert_contains "$e2e_script_text" "\"--boundless-set-verifier-address\" \"\$boundless_set_verifier_address\"" "boundless set verifier bridge forwarding"
  assert_contains "$e2e_script_text" "shared_infra" "shared infra summary section"
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
  test_aws_wrapper_uses_ssh_keepalive_options
  test_aws_wrapper_collects_artifacts_after_remote_failures
  test_aws_wrapper_wires_shared_services_into_remote_e2e
  test_local_e2e_supports_shared_infra_validation
  test_aws_workflow_dispatch_input_count_within_limit
}

main "$@"
