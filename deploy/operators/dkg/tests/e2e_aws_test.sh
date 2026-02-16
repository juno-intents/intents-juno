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
  assert_contains "$script_text" "dump_boundless_failure_context()" "boundless install failure diagnostics helper"
  assert_contains "$script_text" "prepare_boundless_market_patch()" "boundless market patch helper"
  assert_contains "$script_text" "https://static.crates.io/crates/boundless-market/boundless-market-0.14.1.crate" "boundless market crate url"
  assert_contains "$script_text" "__BOUNDLESS_DUMMY__" "boundless parser workaround marker"
  assert_contains "$script_text" "perl -0pi -e" "boundless parser workaround patch command"
  assert_contains "$script_text" "boundless-market build.rs patched:" "boundless parser workaround patched path log"
  assert_contains "$script_text" "boundless-market build.rs patched" "boundless parser workaround log"
  assert_contains "$script_text" "prepare_boundless_market_patch" "boundless market patch invocation"
  assert_contains "$script_text" "run_with_retry cargo install --locked boundless-cli --version 0.14.1" "boundless cli install retry"
}

main() {
  test_remote_prepare_script_waits_for_cloud_init_and_retries_apt
}

main "$@"
