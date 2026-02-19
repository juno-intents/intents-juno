#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  compute-bridge-withdrawal-id.sh run [options]

Options:
  --base-chain-id <id>                    required Base chain id
  --bridge-address <addr>                 required bridge contract address
  --requester-address <addr>              required requester/deployer address
  --recipient-raw-address-hex <hex>       required recipient raw Orchard bytes (43 bytes hex)
  --amount-zat <n>                        withdraw amount in zatoshis (default: 10000)
  --withdraw-nonce <n>                    withdraw nonce used in hash preimage (default: 1)

Output:
  Prints the expected withdrawal id hex (0x...) to stdout.
EOF
}

command_run() {
  shift || true

  local base_chain_id=""
  local bridge_address=""
  local requester_address=""
  local recipient_raw_address_hex=""
  local amount_zat="10000"
  local withdraw_nonce="1"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --base-chain-id)
        [[ $# -ge 2 ]] || die "missing value for --base-chain-id"
        base_chain_id="$2"
        shift 2
        ;;
      --bridge-address)
        [[ $# -ge 2 ]] || die "missing value for --bridge-address"
        bridge_address="$2"
        shift 2
        ;;
      --requester-address)
        [[ $# -ge 2 ]] || die "missing value for --requester-address"
        requester_address="$2"
        shift 2
        ;;
      --recipient-raw-address-hex)
        [[ $# -ge 2 ]] || die "missing value for --recipient-raw-address-hex"
        recipient_raw_address_hex="$2"
        shift 2
        ;;
      --amount-zat)
        [[ $# -ge 2 ]] || die "missing value for --amount-zat"
        amount_zat="$2"
        shift 2
        ;;
      --withdraw-nonce)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-nonce"
        withdraw_nonce="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for run: $1"
        ;;
    esac
  done

  [[ "$base_chain_id" =~ ^[0-9]+$ ]] || die "--base-chain-id must be numeric"
  [[ "$amount_zat" =~ ^[0-9]+$ ]] || die "--amount-zat must be numeric"
  [[ "$withdraw_nonce" =~ ^[0-9]+$ ]] || die "--withdraw-nonce must be numeric"
  (( withdraw_nonce > 0 )) || die "--withdraw-nonce must be > 0"
  [[ -n "$bridge_address" ]] || die "--bridge-address is required"
  [[ -n "$requester_address" ]] || die "--requester-address is required"
  [[ -n "$recipient_raw_address_hex" ]] || die "--recipient-raw-address-hex is required"

  ensure_base_dependencies
  ensure_command cast

  local version_tag recipient_ua_hash payload
  version_tag="$(cast format-bytes32-string WJUNO_WITHDRAW_V1)"
  recipient_ua_hash="$(cast keccak "$recipient_raw_address_hex")"
  payload="$(
    cast abi-encode \
      "f(bytes32,uint256,address,uint256,address,uint256,bytes32)" \
      "$version_tag" \
      "$base_chain_id" \
      "$bridge_address" \
      "$withdraw_nonce" \
      "$requester_address" \
      "$amount_zat" \
      "$recipient_ua_hash"
  )"
  cast keccak "$payload"
}

main() {
  local cmd="${1:-run}"
  case "$cmd" in
    run) command_run "$@" ;;
    -h|--help|"")
      usage
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

main "$@"
