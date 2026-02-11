#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  tailscale.sh register [options]

Options:
  --port <1-65535>            gRPC port to advertise (default: 8443)
  --fee-recipient <0x...>     required fee recipient wallet address
  --output <path>             registration JSON output path (default: ./operator-registration.json)
  --key-path <path>           operator private key path (default: ~/.juno-dkg/operator/operator.key)
  --network <name>            metadata only: mainnet|testnet|regtest (default: mainnet)

This command:
  1) Ensures tailscale is installed and active (runs tailscale up if needed)
  2) Generates or reuses an operator ECDSA key
  3) Emits a registration JSON containing operator_id, fee_recipient, and grpc_endpoint
EOF
}

cmd="${1:-register}"
if [[ "$cmd" == "-h" || "$cmd" == "--help" ]]; then
  usage
  exit 0
fi
if [[ "$cmd" != "register" ]]; then
  usage
  die "unsupported command: $cmd"
fi
shift || true

port="8443"
fee_recipient=""
output_path="./operator-registration.json"
key_path="$JUNO_DKG_HOME_DEFAULT/operator/operator.key"
network="mainnet"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      [[ $# -ge 2 ]] || die "missing value for --port"
      port="$2"
      shift 2
      ;;
    --fee-recipient)
      [[ $# -ge 2 ]] || die "missing value for --fee-recipient"
      fee_recipient="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || die "missing value for --output"
      output_path="$2"
      shift 2
      ;;
    --key-path)
      [[ $# -ge 2 ]] || die "missing value for --key-path"
      key_path="$2"
      shift 2
      ;;
    --network)
      [[ $# -ge 2 ]] || die "missing value for --network"
      network="$(lower "$2")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
done

if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  die "invalid --port: $port"
fi

case "$network" in
  mainnet|testnet|regtest) ;;
  *) die "invalid --network: $network" ;;
esac

if [[ -z "$fee_recipient" ]]; then
  die "--fee-recipient is required"
fi
fee_recipient="$(normalize_eth_address "$fee_recipient")" || die "invalid fee recipient: $fee_recipient"

ensure_tailscale_active

bin_dir="$JUNO_DKG_HOME_DEFAULT/bin"
keygen_bin="$(ensure_operator_keygen_bin "$bin_dir")"

key_json="$("$keygen_bin" -private-key-path "$key_path" -fee-recipient "$fee_recipient")"
operator_id="$(printf '%s' "$key_json" | jq -r '.operator_id')"
private_key_created="$(printf '%s' "$key_json" | jq -r '.private_key_created')"

dns_name="$(tailscale_dns_name)"
grpc_endpoint="https://${dns_name}:${port}"

registration_json="$(jq -n \
  --arg created_at "$(timestamp_utc)" \
  --arg network "$network" \
  --arg operator_id "$operator_id" \
  --arg fee_recipient "$fee_recipient" \
  --arg grpc_endpoint "$grpc_endpoint" \
  --arg tailscale_dns_name "$dns_name" \
  --arg private_key_path "$key_path" \
  --arg private_key_created "$private_key_created" \
  '{
    registration_version: 1,
    created_at: $created_at,
    network: $network,
    operator_id: $operator_id,
    fee_recipient: $fee_recipient,
    grpc_endpoint: $grpc_endpoint,
    tailscale_dns_name: $tailscale_dns_name,
    private_key_path: $private_key_path,
    private_key_created: ($private_key_created == "true")
  }')"

if [[ "$output_path" == "-" ]]; then
  printf '%s\n' "$registration_json"
else
  ensure_dir "$(dirname "$output_path")"
  printf '%s\n' "$registration_json" >"$output_path"
  chmod 0644 "$output_path"
  log "wrote registration: $output_path"
fi

log "operator_id=$operator_id"
log "grpc_endpoint=$grpc_endpoint"
