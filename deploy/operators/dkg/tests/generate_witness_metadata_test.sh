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

test_operation_result_poll_uses_full_queue_query() {
  local script_text
  script_text="$(cat "$GEN_SCRIPT")"
  if [[ "$script_text" != *'"z_getoperationresult" "[]"'* ]]; then
    printf 'expected juno_wait_operation_txid to query z_getoperationresult with [] and filter by opid\n' >&2
    exit 1
  fi
}

main() {
  test_decode_orchard_receiver_raw_hex
  test_decode_orchard_receiver_rejects_invalid_input
  test_script_supports_seed_phrase_funder_argument
  test_operation_result_poll_uses_full_queue_query
}

main "$@"
