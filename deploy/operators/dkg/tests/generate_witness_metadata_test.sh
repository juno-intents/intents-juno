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

test_operation_result_poll_uses_full_queue_query() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *'"z_getoperationresult" "[]"'* ]]; then
    printf 'expected juno_wait_operation_txid to query z_getoperationresult with [] and filter by opid\n' >&2
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

main() {
  test_decode_orchard_receiver_raw_hex
  test_decode_orchard_receiver_rejects_invalid_input
  test_script_supports_seed_phrase_funder_argument
  test_script_supports_explicit_funder_source_address_argument
  test_seed_phrase_normalization_handles_wrapped_seed_files
  test_operation_result_poll_uses_full_queue_query
  test_witness_generation_serializes_orchard_spends
  test_scan_note_lookup_uses_paginated_notes_api
  test_scan_note_lookup_fails_fast_on_repeated_http_errors
}

main "$@"
