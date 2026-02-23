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
  assert_contains "$script_text" "cast wallet sign --no-hash --private-key" "fallback signer shim signs raw digests with operator keys"
  assert_contains "$script_text" 'if [[ "\$key_hex" =~ ^[0-9a-fA-F]{64}\$ ]]; then' "fallback signer shim accepts bare 64-hex private keys"
  assert_contains "$script_text" 'key_hex="0x\$key_hex"' "fallback signer shim normalizes bare keys to 0x-prefixed form"
  assert_contains "$script_text" "no operator signatures were produced" "fallback signer emits explicit no-signatures error"
}

test_witness_pool_uses_per_endpoint_timeout_slices() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "local witness_timeout_slice_seconds" "witness timeout slice variable exists"
  assert_contains "$script_text" "witness_timeout_slice_seconds=\$((boundless_witness_metadata_timeout_seconds / witness_endpoint_healthy_count))" "witness timeout slice divides total timeout by healthy endpoint count"
  assert_contains "$script_text" "(( witness_timeout_slice_seconds >= 300 )) || witness_timeout_slice_seconds=300" "witness timeout slice has a floor for endpoint churn resilience"
  assert_contains "$script_text" "if (( witness_timeout_slice_seconds > boundless_witness_metadata_timeout_seconds )); then" "witness timeout slice is capped by global metadata timeout"
  assert_contains "$script_text" "--timeout-seconds \"\$witness_timeout_slice_seconds\"" "witness metadata generation uses per-endpoint timeout slice"
  assert_contains "$script_text" "witness_extract_deadline_epoch=\$(( \$(date +%s) + witness_timeout_slice_seconds ))" "witness extraction wait loop uses per-endpoint timeout slice"
}

test_witness_generation_reuses_distributed_dkg_recipient_identity() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "--boundless-witness-recipient-ua" "run-testnet-e2e supports explicit witness recipient UA input"
  assert_contains "$script_text" "--boundless-witness-recipient-ufvk" "run-testnet-e2e supports explicit witness recipient UFVK input"
  assert_contains "$script_text" "--boundless-witness-recipient-ua and --boundless-witness-recipient-ufvk are required for guest witness extraction mode" "guest witness extraction enforces distributed DKG recipient identity inputs"
  assert_contains "$script_text" "--recipient-ua \"\$boundless_witness_recipient_ua\"" "witness metadata generator receives distributed DKG recipient UA"
  assert_contains "$script_text" "--recipient-ufvk \"\$boundless_witness_recipient_ufvk\"" "witness metadata generator receives distributed DKG UFVK"
  assert_contains "$script_text" "generated witness metadata recipient_ua mismatch" "run-testnet-e2e validates generated witness recipient against distributed DKG recipient"
  assert_contains "$script_text" "generated witness metadata ufvk mismatch against distributed DKG value" "run-testnet-e2e validates generated witness UFVK against distributed DKG UFVK"
}

test_witness_extraction_derives_action_indexes_from_tx_orchard_actions() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "witness_rpc_action_index_candidates()" "run-testnet-e2e defines witness action-index candidate derivation helper"
  assert_contains "$script_text" "method:\"getrawtransaction\"" "action-index candidate derivation uses getrawtransaction RPC"
  assert_contains "$script_text" ".result.orchard.actions" "action-index candidate derivation inspects orchard action list"
  assert_contains "$script_text" "--skip-action-index-lookup" "witness metadata generation skips pre-index action lookup to avoid long scan stalls"
  assert_contains "$script_text" "using action-index candidates for deposit extraction" "deposit extraction logs candidate action-index set"
  assert_contains "$script_text" "direct-cli withdraw extraction action-index candidates" "direct-cli withdraw extraction logs candidate action-index set"
  assert_contains "$script_text" 'witness_fingerprint="${generated_deposit_txid}|${deposit_witness_hex}|${deposit_final_root}"' "quorum witness fingerprint ignores anchor drift across scanners"
  assert_contains "$script_text" "witness quorum anchor divergence detected across operators (using first successful anchor)" "quorum checker reports anchor drift without hard-failing identical witness/root"
}

test_witness_generation_binds_memos_to_predicted_bridge_domain() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "predicted_witness_bridge_nonce" "run-testnet-e2e computes the deployer nonce for bridge-domain witness planning"
  assert_contains "$script_text" "predicted_witness_bridge_address" "run-testnet-e2e computes the predicted bridge address for witness memo domain separation"
  assert_contains "$script_text" "predicted_witness_withdrawal_id" "run-testnet-e2e computes predicted withdrawal id for witness memo binding"
  assert_contains "$script_text" "predicted_witness_withdraw_batch_id" "run-testnet-e2e computes predicted withdraw batch id for witness memo binding"
  assert_contains "$script_text" '--base-chain-id "$base_chain_id"' "run-testnet-e2e passes base chain id into witness metadata generation"
  assert_contains "$script_text" '--bridge-address "$predicted_witness_bridge_address"' "run-testnet-e2e passes predicted bridge address into witness metadata generation"
  assert_contains "$script_text" '--withdrawal-id-hex "$predicted_witness_withdrawal_id"' "run-testnet-e2e passes predicted withdrawal id into witness metadata generation"
  assert_contains "$script_text" '--withdraw-batch-id-hex "$predicted_witness_withdraw_batch_id"' "run-testnet-e2e passes predicted withdrawal batch id into witness metadata generation"
}

test_bridge_address_prediction_parses_cast_labeled_output() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "cast compute-address --nonce" "bridge address prediction uses cast compute-address"
  assert_contains "$script_text" "grep -Eo '0x[0-9a-fA-F]{40}'" "bridge address prediction extracts hex address from cast labeled output"
}

test_direct_cli_user_proof_uses_bridge_specific_witness_generation() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "direct-cli-generated-witness-metadata.json" "direct-cli scenario writes dedicated witness metadata"
  assert_contains "$script_text" 'direct_cli_generated_witness_wallet_id="$withdraw_coordinator_juno_wallet_id"' "direct-cli scenario reuses indexed witness wallet id to avoid cold-scan lag"
  assert_contains "$script_text" "direct_cli_generated_deposit_txid" "direct-cli scenario extracts deposit txid from dedicated metadata"
  assert_contains "$script_text" "direct_cli_generated_withdraw_txid" "direct-cli scenario extracts withdraw txid from dedicated metadata"
  assert_contains "$script_text" "direct-cli-deposit.witness.bin" "direct-cli scenario extracts a dedicated deposit witness item"
  assert_contains "$script_text" '--wallet-id "$direct_cli_generated_witness_wallet_id"' "direct-cli withdraw extraction uses dedicated direct-cli witness wallet id"
  assert_contains "$script_text" 'direct_cli_bridge_run_args+=("--boundless-deposit-witness-item-file" "$direct_cli_deposit_witness_file")' "direct-cli bridge run uses dedicated deposit witness"
  assert_contains "$script_text" 'direct_cli_bridge_run_args+=("--boundless-withdraw-witness-item-file" "$direct_cli_withdraw_witness_file")' "direct-cli bridge run uses dedicated withdraw witness"
  assert_contains "$script_text" '"--deposit-final-orchard-root" "$direct_cli_deposit_final_orchard_root"' "direct-cli bridge run overrides deposit orchard root from dedicated witness extraction"
  assert_contains "$script_text" '"--withdraw-final-orchard-root" "$direct_cli_withdraw_final_orchard_root"' "direct-cli bridge run overrides withdraw orchard root from dedicated witness extraction"
}

test_direct_cli_user_proof_uses_queue_submission_mode() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'direct_cli_proof_submission_mode="$boundless_proof_submission_mode"' "direct-cli user proof scenario reuses configured proof submission mode"
  assert_contains "$script_text" '"--boundless-proof-submission-mode" "$direct_cli_proof_submission_mode"' "direct-cli user proof scenario forwards explicit proof submission mode"
  assert_contains "$script_text" '"--boundless-proof-queue-brokers" "$shared_kafka_brokers"' "direct-cli user proof scenario forwards shared proof queue brokers"
  assert_contains "$script_text" '"--boundless-proof-request-topic" "$proof_request_topic"' "direct-cli user proof scenario forwards proof request topic"
  assert_contains "$script_text" '"--boundless-proof-result-topic" "$proof_result_topic"' "direct-cli user proof scenario forwards proof result topic"
  assert_contains "$script_text" '"--boundless-proof-failure-topic" "$proof_failure_topic"' "direct-cli user proof scenario forwards proof failure topic"
  assert_contains "$script_text" '[[ "$direct_cli_user_proof_submission_mode" == "$direct_cli_proof_submission_mode" ]] || return 1' "direct-cli user proof summary validates expected submission mode"
}

test_direct_cli_witness_extraction_retries_note_visibility() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "direct_cli_deposit_extract_deadline_epoch" "direct-cli deposit extraction has a retry deadline"
  assert_contains "$script_text" "direct-cli waiting for deposit note visibility" "direct-cli deposit extraction logs note-visibility wait state"
  assert_contains "$script_text" "direct_cli_deposit_extract_error_file" "direct-cli deposit extraction captures extraction errors for retry classification"
  assert_contains "$script_text" "direct_cli_withdraw_extract_deadline_epoch" "direct-cli withdraw extraction has a retry deadline"
  assert_contains "$script_text" "direct-cli waiting for withdraw note visibility" "direct-cli withdraw extraction logs note-visibility wait state"
  assert_contains "$script_text" "direct_cli_withdraw_extract_error_file" "direct-cli withdraw extraction captures extraction errors for retry classification"
  assert_contains "$script_text" "for direct_cli_action_candidate in 0 1 2 3; do" "direct-cli extraction appends default action-index candidates for resilience"
}

test_json_array_from_args_separates_jq_options_from_cli_flags() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'jq -n --args -- "$@" '\''$ARGS.positional'\''' "json_array_from_args passes args after jq option delimiter"
}

main() {
  test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop
  test_base_balance_queries_retry_on_transient_rpc_failures
  test_operator_signer_fallback_exists_for_bins_without_sign_digest
  test_witness_pool_uses_per_endpoint_timeout_slices
  test_witness_generation_reuses_distributed_dkg_recipient_identity
  test_witness_extraction_derives_action_indexes_from_tx_orchard_actions
  test_witness_generation_binds_memos_to_predicted_bridge_domain
  test_bridge_address_prediction_parses_cast_labeled_output
  test_direct_cli_user_proof_uses_bridge_specific_witness_generation
  test_direct_cli_user_proof_uses_queue_submission_mode
  test_direct_cli_witness_extraction_retries_note_visibility
  test_json_array_from_args_separates_jq_options_from_cli_flags
}

main "$@"
