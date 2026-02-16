#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  create-funder-wallets.sh create [options]

Options:
  --out-dir <path>            output directory (default: <repo>/tmp/funders)
  --base-key-file <path>      base funder private key file (default: <out-dir>/base-funder.key)
  --juno-key-file <path>      juno funder private key file (default: <out-dir>/juno-funder.key)
  --juno-wallet-dir <path>    juno testnet wallet directory (default: <out-dir>/juno-testnet-wallet)
  --juno-seed-file <path>     juno seed phrase file (default: <out-dir>/juno-funder.seed.txt)
  --report <path>             output json report (default: <out-dir>/funder-wallets.json)
  --force                     overwrite existing report

Notes:
  - Keys are secp256k1 private keys in hex (0x...).
  - The Base funder key is used directly by the e2e workflow.
  - The Juno funder key is saved for future Juno-chain funding steps.
  - A Juno testnet Orchard wallet/account/address and seed phrase are generated under out-dir.
EOF
}

pick_available_port() {
  local start_port="$1"
  local port="$start_port"
  while (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; do
    port=$((port + 1))
  done
  printf '%s\n' "$port"
}

command_create() {
  shift || true

  local out_dir="$REPO_ROOT/tmp/funders"
  local base_key_file=""
  local juno_key_file=""
  local juno_wallet_dir=""
  local juno_seed_file=""
  local report_path=""
  local force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir)
        [[ $# -ge 2 ]] || die "missing value for --out-dir"
        out_dir="$2"
        shift 2
        ;;
      --base-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-key-file"
        base_key_file="$2"
        shift 2
        ;;
      --juno-key-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-key-file"
        juno_key_file="$2"
        shift 2
        ;;
      --juno-wallet-dir)
        [[ $# -ge 2 ]] || die "missing value for --juno-wallet-dir"
        juno_wallet_dir="$2"
        shift 2
        ;;
      --juno-seed-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-seed-file"
        juno_seed_file="$2"
        shift 2
        ;;
      --report)
        [[ $# -ge 2 ]] || die "missing value for --report"
        report_path="$2"
        shift 2
        ;;
      --force)
        force="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for create: $1"
        ;;
    esac
  done

  if [[ -z "$base_key_file" ]]; then
    base_key_file="$out_dir/base-funder.key"
  fi
  if [[ -z "$juno_key_file" ]]; then
    juno_key_file="$out_dir/juno-funder.key"
  fi
  if [[ -z "$juno_wallet_dir" ]]; then
    juno_wallet_dir="$out_dir/juno-testnet-wallet"
  fi
  if [[ -z "$juno_seed_file" ]]; then
    juno_seed_file="$out_dir/juno-funder.seed.txt"
  fi
  if [[ -z "$report_path" ]]; then
    report_path="$out_dir/funder-wallets.json"
  fi

  ensure_base_dependencies
  ensure_command go
  ensure_command junocashd
  ensure_command junocash-cli
  ensure_dir "$out_dir"

  if [[ -f "$report_path" && "$force" != "true" ]]; then
    die "report already exists (use --force to overwrite): $report_path"
  fi

  local base_meta juno_meta
  base_meta="$out_dir/base-funder.meta.json"
  juno_meta="$out_dir/juno-funder.meta.json"
  local juno_rpc_user juno_rpc_pass juno_rpc_port juno_p2p_port juno_conf
  local juno_account_json juno_account_id juno_addr_json juno_orchard_address juno_receivers_json
  juno_rpc_user="juno_funder"
  juno_rpc_pass="juno_funder_$(date +%s)"
  juno_rpc_port="$(pick_available_port 28339)"
  juno_p2p_port="$(pick_available_port 28338)"
  juno_conf="$juno_wallet_dir/junocashd.conf"

  (
    cd "$REPO_ROOT"
    go run ./cmd/operator-keygen -private-key-path "$base_key_file" >"$base_meta"
    go run ./cmd/operator-keygen -private-key-path "$juno_key_file" >"$juno_meta"
  )

  if [[ -d "$juno_wallet_dir" ]]; then
    if [[ "$force" != "true" ]]; then
      die "juno wallet dir already exists (use --force to overwrite): $juno_wallet_dir"
    fi
    rm -rf "$juno_wallet_dir"
  fi
  ensure_dir "$juno_wallet_dir"

  cat >"$juno_conf" <<CONF
testnet=1
server=1
daemon=1
txindex=1
listen=0
discover=0
dnsseed=0
upnp=0
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=$juno_rpc_user
rpcpassword=$juno_rpc_pass
rpcport=$juno_rpc_port
port=$juno_p2p_port
CONF

  junocashd -datadir="$juno_wallet_dir" -testnet >/dev/null
  local i
  for ((i = 0; i < 60; i++)); do
    if junocash-cli \
      -datadir="$juno_wallet_dir" \
      -testnet \
      -rpcuser="$juno_rpc_user" \
      -rpcpassword="$juno_rpc_pass" \
      -rpcport="$juno_rpc_port" \
      getblockchaininfo >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  juno_account_json="$(
    junocash-cli \
      -datadir="$juno_wallet_dir" \
      -testnet \
      -rpcuser="$juno_rpc_user" \
      -rpcpassword="$juno_rpc_pass" \
      -rpcport="$juno_rpc_port" \
      z_getnewaccount
  )"
  juno_account_id="$(jq -r '.account' <<<"$juno_account_json")"
  [[ "$juno_account_id" =~ ^[0-9]+$ ]] || die "failed to create juno testnet account"

  juno_addr_json="$(
    junocash-cli \
      -datadir="$juno_wallet_dir" \
      -testnet \
      -rpcuser="$juno_rpc_user" \
      -rpcpassword="$juno_rpc_pass" \
      -rpcport="$juno_rpc_port" \
      z_getaddressforaccount "$juno_account_id"
  )"
  juno_orchard_address="$(jq -r '.address' <<<"$juno_addr_json")"
  [[ "$juno_orchard_address" == jtest1* ]] || die "unexpected orchard address format: $juno_orchard_address"

  juno_receivers_json="$(
    junocash-cli \
      -datadir="$juno_wallet_dir" \
      -testnet \
      -rpcuser="$juno_rpc_user" \
      -rpcpassword="$juno_rpc_pass" \
      -rpcport="$juno_rpc_port" \
      z_listunifiedreceivers "$juno_orchard_address"
  )"

  junocash-cli \
    -datadir="$juno_wallet_dir" \
    -testnet \
    -rpcuser="$juno_rpc_user" \
    -rpcpassword="$juno_rpc_pass" \
    -rpcport="$juno_rpc_port" \
    z_getseedphrase | tr -d '\r' | sed -e 's/^"//' -e 's/"$//' >"$juno_seed_file"

  junocash-cli \
    -datadir="$juno_wallet_dir" \
    -testnet \
    -rpcuser="$juno_rpc_user" \
    -rpcpassword="$juno_rpc_pass" \
    -rpcport="$juno_rpc_port" \
    stop >/dev/null || true

  chmod 0600 "$base_key_file" "$juno_key_file" "$juno_seed_file" || true

  local base_address juno_address
  base_address="$(jq -r '.operator_id' "$base_meta")"
  juno_address="$(jq -r '.operator_id' "$juno_meta")"

  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg base_key_file "$base_key_file" \
    --arg juno_key_file "$juno_key_file" \
    --arg base_address "$base_address" \
    --arg juno_address "$juno_address" \
    --arg juno_wallet_dir "$juno_wallet_dir" \
    --arg juno_seed_file "$juno_seed_file" \
    --argjson juno_account_id "$juno_account_id" \
    --arg juno_orchard_address "$juno_orchard_address" \
    --argjson juno_receivers "$juno_receivers_json" \
    --arg base_secret_name "BASE_FUNDER_PRIVATE_KEY_HEX" \
    --arg juno_secret_name "JUNO_FUNDER_PRIVATE_KEY_HEX" \
    --arg juno_seed_secret_name "JUNO_FUNDER_SEED_PHRASE" \
    '{
      generated_at: $generated_at,
      wallets: {
        base: {
          private_key_file: $base_key_file,
          address: $base_address
        },
        juno: {
          private_key_file: $juno_key_file,
          secp256k1_address_hint: $juno_address,
          testnet: {
            wallet_dir: $juno_wallet_dir,
            seed_phrase_file: $juno_seed_file,
            account_id: $juno_account_id,
            orchard_unified_address: $juno_orchard_address,
            receivers: $juno_receivers
          }
        }
      },
      github_secrets: {
        base_private_key_hex: $base_secret_name,
        juno_private_key_hex: $juno_secret_name,
        juno_seed_phrase: $juno_seed_secret_name
      }
    }' >"$report_path"

  chmod 0644 "$report_path" || true

  log "created funder wallet files"
  log "base_address=$base_address"
  log "juno_address_hint=$juno_address"
  log "juno_orchard_address=$juno_orchard_address"
  log "report=$report_path"
  printf '%s\n' "$report_path"
}

main() {
  local cmd="${1:-create}"
  case "$cmd" in
    create) command_create "$@" ;;
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
