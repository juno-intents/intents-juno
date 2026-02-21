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

test_base_balance_queries_retry_on_transient_rpc_failures() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "read_balance_wei_with_retry()" "cast balance retry helper exists"
  assert_contains "$script_text" "run_with_rpc_retry 6 3 \"cast balance\"" "cast balance reads use rpc retry wrapper"
  assert_contains "$script_text" "failed to read \$label from cast after retries" "recipient balance failure includes explicit retry context"
  assert_contains "$script_text" "base funder balance for pre-fund budget check" "prefund sender balance lookup label is explicit"
  assert_contains "$script_text" "balance=\"\$(read_balance_wei_with_retry \"\$rpc_url\" \"\$recipient\" \"\$label balance\")\"" "recipient prefund loop uses balance retry helper"
  assert_contains "$script_text" "funding_sender_balance_wei=\"\$(read_balance_wei_with_retry \"\$rpc_url\" \"\$funding_sender_address\" \"base funder balance for pre-fund budget check\")\"" "prefund budget check uses balance retry helper"
}

test_operator_signer_fallback_exists_for_bins_without_sign_digest() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "supports_sign_digest_subcommand()" "operator signer capability probe helper exists"
  assert_contains "$script_text" "write_e2e_operator_digest_signer()" "fallback signer shim writer exists"
  assert_contains "$script_text" "does not support sign-digest; using e2e signer shim" "fallback log message exists"
  assert_contains "$script_text" "bridge_operator_signer_bin=\"\$(write_e2e_operator_digest_signer \"\$dkg_summary\" \"\$workdir/bin\")\"" "fallback signer shim is wired into bridge signer selection"
  assert_contains "$script_text" "cast wallet sign --private-key" "fallback signer shim signs digests with operator keys"
  assert_contains "$script_text" 'if [[ "\$key_hex" =~ ^[0-9a-fA-F]{64}\$ ]]; then' "fallback signer shim accepts bare 64-hex private keys"
  assert_contains "$script_text" 'key_hex="0x\$key_hex"' "fallback signer shim normalizes bare keys to 0x-prefixed form"
  assert_contains "$script_text" "no operator signatures were produced" "fallback signer emits explicit no-signatures error"
}

main() {
  test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop
  test_base_balance_queries_retry_on_transient_rpc_failures
  test_operator_signer_fallback_exists_for_bins_without_sign_digest
}

main "$@"
