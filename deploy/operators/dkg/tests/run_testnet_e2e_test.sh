#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/../e2e/run-testnet-e2e.sh"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
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

test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop() {
  local script_text
  local helper_reference_count
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "assert_prefund_sender_budget()" "prefund budget helper function exists"
  assert_contains "$script_text" "insufficient base funder balance for operator/deployer pre-funding" "prefund insufficiency error message exists"
  helper_reference_count="$(grep -c 'assert_prefund_sender_budget' <<<"$script_text" | tr -d ' ')"
  if (( helper_reference_count < 2 )); then
    printf 'assert_count failed: prefund budget helper must be called (references=%s)\n' "$helper_reference_count" >&2
    exit 1
  fi
  assert_order "$script_text" \
    "assert_prefund_sender_budget" \
    "while IFS= read -r operator; do" \
    "prefund budget check runs before operator prefund loop"
}

main() {
  test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop
}

main "$@"
