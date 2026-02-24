#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN_SCRIPT="$SCRIPT_DIR/../e2e/generate-juno-witness-metadata.sh"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

test_decode_orchard_receiver_raw_hex() {
  local ua expected got
  ua="jtest1atrdjvswk9n4mn8555vq274ur27gvuk49p9dne85n0w9hxpz8vc68lhq2puh4tlky4jz9wv5p9av8tr7dcvtyjnstwl6dszjacw26yjd"
  expected="c7200129c0b3476308ae48681abce2178c2fb6299ef0150c9f7924eedb76ff3056dbc5d79edfdee0179c2d"

  got="$($GEN_SCRIPT decode-orchard-raw --address "$ua")"
  assert_eq "$got" "$expected" "decode-orchard-raw output"
}

test_decode_orchard_receiver_rejects_invalid_input() {
  local ua
  ua="jtest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
  if $GEN_SCRIPT decode-orchard-raw --address "$ua" >/dev/null 2>&1; then
    printf 'expected invalid unified address to fail decoding\n' >&2
    exit 1
  fi
}

test_script_supports_seed_phrase_funder_argument() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--funder-seed-phrase"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --funder-seed-phrase\n' >&2
    exit 1
  fi
}

test_script_supports_explicit_funder_source_address_argument() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--funder-source-address"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --funder-source-address\n' >&2
    exit 1
  fi
}

test_script_supports_pre_upsert_scan_urls_argument() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--pre-upsert-scan-urls"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --pre-upsert-scan-urls for quorum pre-registration\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"pre_upsert_scan_urls_csv"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to parse pre-upsert scan URL CSV input\n' >&2
    exit 1
  fi
}

test_script_supports_explicit_recipient_and_ufvk_inputs() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--recipient-ua"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --recipient-ua for distributed DKG recipient reuse\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"--recipient-ufvk"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --recipient-ufvk for distributed DKG witness wallet upsert\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"--recipient-ua and --recipient-ufvk must be provided together"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to require --recipient-ua/--recipient-ufvk together\n' >&2
    exit 1
  fi
}

test_seed_phrase_normalization_handles_wrapped_seed_files() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"normalize_mnemonic_seed_phrase"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to normalize wrapped seed phrase content\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'funder_seed_phrase="$(normalize_mnemonic_seed_phrase "$funder_seed_phrase")"'* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to normalize --funder-seed-phrase input before recovery/send logic\n' >&2
    exit 1
  fi
}

test_operation_status_poll_targets_specific_opid_and_fails_fast_when_missing() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *'"z_getoperationstatus"'* ]]; then
    printf 'expected juno_wait_operation_txid to poll z_getoperationstatus for the specific opid\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'--arg opid "$opid" '\''[[ $opid ]]'\'''* ]]; then
    printf 'expected juno_wait_operation_txid to call operation status/result with [[opid]] params\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"operation missing from wallet queue for too long"* ]]; then
    printf 'expected juno_wait_operation_txid to fail fast when opid disappears after node restart\n' >&2
    exit 1
  fi
}

test_witness_generation_serializes_orchard_spends() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"submit_and_confirm_witness_tx()"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define submit_and_confirm_witness_tx helper\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'deposit_txid="$(submit_and_confirm_witness_tx'* ]]; then
    printf 'expected deposit witness tx to use serialized send/wait helper\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'withdraw_txid="$(submit_and_confirm_witness_tx'* ]]; then
    printf 'expected withdraw witness tx to use serialized send/wait helper\n' >&2
    exit 1
  fi
}

test_witness_generation_requires_bridge_domain_memo_inputs() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--base-chain-id"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to require --base-chain-id for memo domain separation\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"--bridge-address"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to require --bridge-address for memo domain separation\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"--withdrawal-id-hex"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to require --withdrawal-id-hex for withdrawal memo binding\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"--withdraw-batch-id-hex"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to require --withdraw-batch-id-hex for withdrawal memo binding\n' >&2
    exit 1
  fi
}

test_witness_generation_submits_explicit_hex_memos() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"memo: \$memo_hex"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to include memo hex payload in z_sendmany outputs\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'deposit_txid="$(submit_and_confirm_witness_tx'*" \"\$deposit_memo_hex\""* ]]; then
    printf 'expected deposit witness tx submission to pass generated deposit memo hex\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'withdraw_txid="$(submit_and_confirm_witness_tx'*" \"\$withdraw_memo_hex\""* ]]; then
    printf 'expected withdraw witness tx submission to pass generated withdrawal memo hex\n' >&2
    exit 1
  fi
}

test_script_supports_skipping_preindex_action_lookup() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"--skip-action-index-lookup"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to support --skip-action-index-lookup for fast witness tx generation\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"skip_action_index_lookup"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to parse skip_action_index_lookup toggle\n' >&2
    exit 1
  fi
}

test_scan_note_lookup_uses_paginated_notes_api() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"/notes?limit=1000"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to query paginated juno-scan notes endpoint\n' >&2
    exit 1
  fi
  if [[ "$script_text" == *"spent=true&limit=1000"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh not to force spent=true filter on notes endpoint\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"next_cursor"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to handle juno-scan notes pagination cursor\n' >&2
    exit 1
  fi
}

test_scan_note_lookup_fails_fast_on_repeated_http_errors() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"scan_http_failures_consecutive"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to track consecutive scan HTTP failures during note lookup\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"juno-scan notes endpoint repeatedly failed"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to fail fast on repeated juno-scan note endpoint failures\n' >&2
    exit 1
  fi
}

test_rpc_calls_fail_fast_on_repeated_transport_errors() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"JUNO_RPC_TRANSPORT_FAILURES_MAX"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define a max consecutive RPC transport failure threshold\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to track consecutive RPC transport failures\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"juno rpc endpoint repeatedly unreachable"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to fail fast when the RPC endpoint is repeatedly unreachable\n' >&2
    exit 1
  fi
}

test_rpc_and_scan_curl_calls_set_explicit_timeouts() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *"JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define RPC curl connect timeout env override\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"JUNO_RPC_CURL_MAX_TIME_SECONDS"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define RPC curl max-time env override\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define scan curl connect timeout env override\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *"JUNO_SCAN_CURL_MAX_TIME_SECONDS"* ]]; then
    printf 'expected generate-juno-witness-metadata.sh to define scan curl max-time env override\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'--connect-timeout "$JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS"'* ]]; then
    printf 'expected RPC curl calls to enforce connect timeout\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'--max-time "$JUNO_RPC_CURL_MAX_TIME_SECONDS"'* ]]; then
    printf 'expected RPC curl calls to enforce max-time\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'--connect-timeout "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS"'* ]]; then
    printf 'expected scan curl calls to enforce connect timeout\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'--max-time "$JUNO_SCAN_CURL_MAX_TIME_SECONDS"'* ]]; then
    printf 'expected scan curl calls to enforce max-time\n' >&2
    exit 1
  fi
}

test_tx_confirmation_prefers_wallet_view_and_keeps_getraw_fallback() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *'"z_viewtransaction"'* ]]; then
    printf 'expected juno_wait_tx_confirmed to check z_viewtransaction first for wallet-aware confirmation status\n' >&2
    exit 1
  fi
  if [[ "$script_text" != *'params_json="$(jq -cn --arg txid "$txid" '\''[ $txid, 1 ]'\'')"'* ]]; then
    printf 'expected juno_wait_tx_confirmed to retain getrawtransaction fallback with numeric verbosity (1)\n' >&2
    exit 1
  fi
  if [[ "$script_text" == *'params_json="$(jq -cn --arg txid "$txid" '\''[ $txid, true ]'\'')"'* ]]; then
    printf 'expected juno_wait_tx_confirmed getrawtransaction fallback not to use boolean verbosity\n' >&2
    exit 1
  fi
}

main() {
  test_decode_orchard_receiver_raw_hex
  test_decode_orchard_receiver_rejects_invalid_input
  test_script_supports_seed_phrase_funder_argument
  test_script_supports_explicit_funder_source_address_argument
  test_script_supports_pre_upsert_scan_urls_argument
  test_script_supports_explicit_recipient_and_ufvk_inputs
  test_seed_phrase_normalization_handles_wrapped_seed_files
  test_operation_status_poll_targets_specific_opid_and_fails_fast_when_missing
  test_witness_generation_serializes_orchard_spends
  test_witness_generation_requires_bridge_domain_memo_inputs
  test_witness_generation_submits_explicit_hex_memos
  test_script_supports_skipping_preindex_action_lookup
  test_scan_note_lookup_uses_paginated_notes_api
  test_scan_note_lookup_fails_fast_on_repeated_http_errors
  test_rpc_calls_fail_fast_on_repeated_transport_errors
  test_rpc_and_scan_curl_calls_set_explicit_timeouts
  test_tx_confirmation_prefers_wallet_view_and_keeps_getraw_fallback
}

main "$@"
