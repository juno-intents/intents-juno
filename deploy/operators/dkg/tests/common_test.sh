#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

test_normalize_eth_address() {
  local got
  got="$(normalize_eth_address "0x52908400098527886E0F7030069857D2E4169EE7")"
  assert_eq "$got" "0x52908400098527886e0f7030069857d2e4169ee7" "normalize_eth_address"

  if normalize_eth_address "0x1234" >/dev/null 2>&1; then
    printf 'expected invalid address to fail\n' >&2
    exit 1
  fi
}

test_parse_endpoint_host_port() {
  local host port
  read -r host port <<<"$(parse_endpoint_host_port "https://node.tailnet.ts.net:8443")"
  assert_eq "$host" "node.tailnet.ts.net" "endpoint host"
  assert_eq "$port" "8443" "endpoint port"

  if parse_endpoint_host_port "http://node.tailnet.ts.net:8443" >/dev/null 2>&1; then
    printf 'expected non-https endpoint to fail\n' >&2
    exit 1
  fi
  if parse_endpoint_host_port "https://node.tailnet.ts.net" >/dev/null 2>&1; then
    printf 'expected missing port endpoint to fail\n' >&2
    exit 1
  fi
}

test_safe_slug() {
  local got
  got="$(safe_slug "0xabc:def/ghi")"
  assert_eq "$got" "0xabc_def_ghi" "safe_slug"
}

test_build_export_s3_key() {
  local got

  got="$(build_export_s3_key "dkg/keypackages" "cer-123" "0xabc" "7")"
  assert_eq "$got" "dkg/keypackages/cer-123/operator_7_0xabc.json" "s3 key basic"

  got="$(build_export_s3_key "/dkg/keypackages/" "cer-123" "0xabc" "7")"
  assert_eq "$got" "dkg/keypackages/cer-123/operator_7_0xabc.json" "s3 key trims slashes"

  got="$(build_export_s3_key "" "cer-123" "0xabc" "7")"
  assert_eq "$got" "cer-123/operator_7_0xabc.json" "s3 key empty prefix"
}

main() {
  test_normalize_eth_address
  test_parse_endpoint_host_port
  test_safe_slug
  test_build_export_s3_key
}

main "$@"
