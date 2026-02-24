#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

JUNO_RPC_TRANSPORT_FAILURES_MAX="${JUNO_RPC_TRANSPORT_FAILURES_MAX:-8}"
JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE=0
JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS="${JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS:-5}"
JUNO_RPC_CURL_MAX_TIME_SECONDS="${JUNO_RPC_CURL_MAX_TIME_SECONDS:-20}"
JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS="${JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS:-5}"
JUNO_SCAN_CURL_MAX_TIME_SECONDS="${JUNO_SCAN_CURL_MAX_TIME_SECONDS:-20}"

usage() {
  cat <<'USAGE'
Usage:
  generate-juno-witness-metadata.sh run [options]
  generate-juno-witness-metadata.sh decode-orchard-raw --address <ua>

Options:
  --juno-rpc-url <url>               required junocashd RPC URL
  --juno-rpc-user <user>             required junocashd RPC username
  --juno-rpc-pass <pass>             required junocashd RPC password
  --juno-scan-url <url>              required juno-scan URL
  --pre-upsert-scan-urls <csv>       optional comma-separated juno-scan URLs to pre-register wallet before tx send
  --juno-scan-bearer-token <token>   optional juno-scan bearer token
  --funder-private-key-hex <hex>     optional funder private key hex (32-byte); converted to testnet WIF
  --funder-wif <wif>                 optional funder WIF (used directly when provided)
  --funder-seed-phrase <seed>        optional 24-word seed phrase used to select/recover funded unified account
  --funder-source-address <address>  optional explicit funded source address already available on the RPC wallet
  --wallet-id <id>                   optional juno-scan wallet id (default: generated run id)
  --recipient-ua <address>           optional fixed recipient unified/shielded address (requires --recipient-ufvk)
  --recipient-ufvk <ufvk>            optional fixed recipient UFVK (requires --recipient-ua)
  --base-chain-id <id>               required Base chain id for witness memo domain separation
  --bridge-address <addr>            required bridge contract address for witness memo domain separation
  --base-recipient-address <addr>    required Base recipient address for deposit witness memo
  --withdrawal-id-hex <hex>          required bytes32 withdrawal id for withdrawal witness memo
  --withdraw-batch-id-hex <hex>      required bytes32 batch id for withdrawal witness memo
  --skip-action-index-lookup         skip pre-index action lookup in juno-scan and emit placeholder action indexes
  --deposit-amount-zat <n>           deposit witness tx amount in zatoshis (default: 100000)
  --withdraw-amount-zat <n>          withdraw witness tx amount in zatoshis (default: 10000)
  --timeout-seconds <n>              overall timeout seconds (default: 900)
  --output <path>                    output JSON path (default: stdout)

Output:
  JSON document with wallet_id, recipient_ua, recipient_raw_address_hex,
  deposit/withdraw txids, and action indexes.
USAGE
}

trim_txid() {
  local txid="$1"
  txid="$(trim "$txid")"
  txid="${txid#0x}"
  printf '%s' "$(lower "$txid")"
}

zat_to_decimal() {
  local zat="$1"
  [[ "$zat" =~ ^[0-9]+$ ]] || return 1
  local whole frac
  whole=$((zat / 100000000))
  frac=$((zat % 100000000))
  printf '%d.%08d' "$whole" "$frac"
}

normalize_hex_0x_address() {
  local raw="$1"
  raw="$(trim "$raw")"
  [[ "$raw" =~ ^0x[0-9a-fA-F]{40}$ ]] || return 1
  printf '%s' "$(lower "$raw")"
}

normalize_fixed_hex() {
  local raw="$1"
  local want_bytes="$2"
  raw="$(trim "$raw")"
  raw="${raw#0x}"
  raw="${raw#0X}"
  raw="$(lower "$raw")"
  local want_chars=$((want_bytes * 2))
  [[ "$raw" =~ ^[0-9a-f]+$ ]] || return 1
  [[ "${#raw}" -eq "$want_chars" ]] || return 1
  printf '%s' "$raw"
}

encode_deposit_memo_hex() {
  local base_chain_id="$1"
  local bridge_address="$2"
  local base_recipient_address="$3"
  local nonce="$4"
  local flags="${5:-0}"
  (
    cd "$REPO_ROOT"
    go run ./cmd/juno-memo deposit \
      --base-chain-id "$base_chain_id" \
      --bridge-address "$bridge_address" \
      --recipient "$base_recipient_address" \
      --nonce "$nonce" \
      --flags "$flags"
  )
}

encode_withdraw_memo_hex() {
  local base_chain_id="$1"
  local bridge_address="$2"
  local withdrawal_id_hex="$3"
  local batch_id_hex="$4"
  local flags="${5:-0}"
  (
    cd "$REPO_ROOT"
    go run ./cmd/juno-memo withdraw \
      --base-chain-id "$base_chain_id" \
      --bridge-address "$bridge_address" \
      --withdrawal-id "0x$withdrawal_id_hex" \
      --batch-id "0x$batch_id_hex" \
      --flags "$flags"
  )
}

normalize_mnemonic_seed_phrase() {
  local raw="$1"
  local line normalized

  while IFS= read -r line; do
    line="$(lower "$(trim "$line")")"
    line="$(printf '%s' "$line" | tr '\t' ' ' | tr -s ' ')"
    line="${line# }"
    line="${line% }"
    [[ -n "$line" ]] || continue
    if [[ "$line" =~ ^([a-z]+[[:space:]]+){23}[a-z]+$ ]]; then
      printf '%s' "$line"
      return 0
    fi
  done < <(printf '%s\n' "$raw")

  normalized="$(printf '%s' "$raw" | tr '\r\n\t' '   ' | tr -s ' ')"
  normalized="$(lower "$(trim "$normalized")")"
  if [[ "$normalized" =~ ^([a-z]+[[:space:]]+){23}[a-z]+$ ]]; then
    printf '%s' "$normalized"
    return 0
  fi

  die "failed to normalize mnemonic seed phrase to 24 words"
}

hex_to_testnet_wif() {
  local key_hex="$1"
  python3 - "$key_hex" <<'PY'
import hashlib
import sys

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

key_hex = sys.argv[1].strip().lower()
if key_hex.startswith('0x'):
    key_hex = key_hex[2:]
if len(key_hex) != 64:
    raise SystemExit('private key hex must be 32 bytes (64 hex chars)')
try:
    raw = bytes.fromhex(key_hex)
except ValueError as exc:
    raise SystemExit(f'invalid private key hex: {exc}')

# Testnet/regtest transparent WIF prefix + compressed marker.
payload = b'\xef' + raw + b'\x01'
checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
data = payload + checksum
num = int.from_bytes(data, 'big')
out = ''
while num > 0:
    num, rem = divmod(num, 58)
    out = alphabet[rem] + out
for b in data:
    if b == 0:
        out = '1' + out
    else:
        break
print(out)
PY
}

decode_orchard_receiver_raw_hex() {
  local addr="$1"
  python3 - "$addr" <<'PY'
import hashlib
import sys

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BECH32M_CONST = 0x2BC830A3
F4JUMBLE_MIN_LENGTH = 48
F4JUMBLE_MAX_LENGTH = 4194368
F4JUMBLE_LEFT_MAX = 64
PADDING_LENGTH = 16
ORCHARD_TYPECODE = 3
ORCHARD_RAW_LENGTH = 43


def polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        if top & 1:
            chk ^= 0x3B6A57B2
        if top & 2:
            chk ^= 0x26508E6D
        if top & 4:
            chk ^= 0x1EA119FA
        if top & 8:
            chk ^= 0x3D4233DD
        if top & 16:
            chk ^= 0x2A1462B3
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def convertbits(data, frombits, tobits, pad=False):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def xor_into(dst, src):
    for i in range(min(len(dst), len(src))):
        dst[i] ^= src[i]


def f4_h_round(left, right, i):
    personalization = b'UA_F4Jumble_H' + bytes([i, 0, 0])
    digest = hashlib.blake2b(bytes(right), digest_size=len(left), person=personalization).digest()
    xor_into(left, digest)


def f4_g_round(left, right, i):
    outbytes = 64
    chunk_count = (len(right) + outbytes - 1) // outbytes
    for j in range(chunk_count):
        personalization = b'UA_F4Jumble_G' + bytes([i, j & 0xFF, (j >> 8) & 0xFF])
        digest = hashlib.blake2b(bytes(left), digest_size=outbytes, person=personalization).digest()
        start = j * outbytes
        end = min(len(right), start + outbytes)
        for k in range(start, end):
            right[k] ^= digest[k - start]


def f4jumble_inv_mut(message):
    if not (F4JUMBLE_MIN_LENGTH <= len(message) <= F4JUMBLE_MAX_LENGTH):
        raise SystemExit('invalid f4jumble length')
    left_length = min(F4JUMBLE_LEFT_MAX, len(message) // 2)
    left = bytearray(message[:left_length])
    right = bytearray(message[left_length:])
    f4_h_round(left, right, 1)
    f4_g_round(left, right, 1)
    f4_h_round(left, right, 0)
    f4_g_round(left, right, 0)
    message[:left_length] = left
    message[left_length:] = right


def read_compact_size(payload, idx):
    if idx >= len(payload):
        raise SystemExit('tlv_invalid')
    first = payload[idx]
    idx += 1
    if first <= 252:
        return first, idx
    if first == 253:
        if idx + 2 > len(payload):
            raise SystemExit('tlv_invalid')
        return int.from_bytes(payload[idx:idx + 2], 'little'), idx + 2
    if first == 254:
        if idx + 4 > len(payload):
            raise SystemExit('tlv_invalid')
        return int.from_bytes(payload[idx:idx + 4], 'little'), idx + 4
    if idx + 8 > len(payload):
        raise SystemExit('tlv_invalid')
    return int.from_bytes(payload[idx:idx + 8], 'little'), idx + 8


address = sys.argv[1].strip()
if not address:
    raise SystemExit('empty bech32m address')
if any(ord(c) < 33 or ord(c) > 126 for c in address):
    raise SystemExit('invalid bech32m address characters')
if address.lower() != address and address.upper() != address:
    raise SystemExit('mixed-case bech32m address is invalid')
address = address.lower()
pos = address.rfind('1')
if pos <= 0 or pos + 7 > len(address):
    raise SystemExit('invalid bech32m separator/length')
hrp = address[:pos]
raw_data = address[pos + 1:]
if len(hrp) > PADDING_LENGTH:
    raise SystemExit('invalid hrp length')
try:
    data = [CHARSET.index(c) for c in raw_data]
except ValueError:
    raise SystemExit('invalid bech32m alphabet')
if polymod(hrp_expand(hrp) + data) != BECH32M_CONST:
    raise SystemExit('invalid bech32m checksum')
payload5 = data[:-6]
payload8 = convertbits(payload5, 5, 8, pad=False)
if payload8 is None:
    raise SystemExit('invalid bech32m payload conversion')

decoded = bytearray(payload8)
f4jumble_inv_mut(decoded)
if len(decoded) < PADDING_LENGTH:
    raise SystemExit('invalid zip316 payload length')
padding = decoded[-PADDING_LENGTH:]
if padding[:len(hrp)] != hrp.encode():
    raise SystemExit('invalid zip316 padding prefix')
if any(b != 0 for b in padding[len(hrp):]):
    raise SystemExit('invalid zip316 padding suffix')
tlv = bytes(decoded[:-PADDING_LENGTH])

idx = 0
orchard_raw = None
while idx < len(tlv):
    typecode, idx = read_compact_size(tlv, idx)
    value_len, idx = read_compact_size(tlv, idx)
    if idx + value_len > len(tlv):
        raise SystemExit('tlv_invalid')
    value = tlv[idx:idx + value_len]
    idx += value_len
    if typecode == ORCHARD_TYPECODE:
        orchard_raw = value
        break

if orchard_raw is None:
    raise SystemExit('orchard receiver missing from unified address')
if len(orchard_raw) != ORCHARD_RAW_LENGTH:
    raise SystemExit('decoded orchard receiver must be 43 bytes')
print(orchard_raw.hex())
PY
}

command_decode_orchard_raw() {
  shift || true
  local address=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --address)
        [[ $# -ge 2 ]] || die "missing value for --address"
        address="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for decode-orchard-raw: $1"
        ;;
    esac
  done

  [[ -n "$address" ]] || die "--address is required"
  decode_orchard_receiver_raw_hex "$address"
}

juno_rpc_json_call() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local method="$4"
  local params_json="$5"
  local payload resp
  local failures_max="$JUNO_RPC_TRANSPORT_FAILURES_MAX"
  if ! [[ "$failures_max" =~ ^[0-9]+$ ]] || (( failures_max < 1 )); then
    failures_max=8
  fi

  payload="$({
    jq -cn \
      --arg method "$method" \
      --argjson params "$params_json" \
      '{jsonrpc: "1.0", id: "witness-meta", method: $method, params: $params}'
  })"
  if ! resp="$(
    curl -fsS \
      --connect-timeout "$JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS" \
      --max-time "$JUNO_RPC_CURL_MAX_TIME_SECONDS" \
      --user "$rpc_user:$rpc_pass" \
      --header "content-type: application/json" \
      --data-binary "$payload" \
      "$rpc_url"
  )"; then
    JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE=$((JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE + 1))
    if (( JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE >= failures_max )); then
      die "juno rpc endpoint repeatedly unreachable url=$rpc_url consecutive_failures=$JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE"
    fi
    return 1
  fi
  JUNO_RPC_TRANSPORT_FAILURES_CONSECUTIVE=0
  printf '%s' "$resp"
}

juno_rpc_result() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local method="$4"
  local params_json="$5"
  local resp err

  resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "$method" "$params_json")"
  err="$(jq -r '.error.message // empty' <<<"$resp")"
  if [[ -n "$err" ]]; then
    printf '%s\n' "$err" >&2
    return 1
  fi
  jq -c '.result' <<<"$resp"
}

juno_rpc_result_allow_key_exists() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local method="$4"
  local params_json="$5"
  local resp err lowered

  resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "$method" "$params_json")"
  err="$(jq -r '.error.message // empty' <<<"$resp")"
  if [[ -z "$err" ]]; then
    jq -c '.result' <<<"$resp"
    return 0
  fi
  lowered="$(lower "$err")"
  if [[ "$lowered" == *"already have this key"* ]] || [[ "$lowered" == *"wallet already contains private key"* ]]; then
    jq -c '.result' <<<"$resp"
    return 0
  fi
  printf '%s\n' "$err" >&2
  return 1
}

juno_wait_operation_txid() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local opid="$4"
  local deadline_epoch="$5"
  local resp status txid err_msg now op_json op_list_params
  local op_missing_since_epoch op_missing_grace_seconds
  op_list_params="$(jq -cn --arg opid "$opid" '[[ $opid ]]')"
  op_missing_grace_seconds=120
  op_missing_since_epoch="$(date +%s)"

  while true; do
    now="$(date +%s)"
    if (( now >= deadline_epoch )); then
      die "timed out waiting for juno operation result opid=$opid"
    fi
    resp="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "z_getoperationstatus" "$op_list_params" || true)"
    if [[ -z "$resp" || "$resp" == "null" ]]; then
      if (( now - op_missing_since_epoch >= op_missing_grace_seconds )); then
        die "operation missing from wallet queue for too long opid=$opid"
      fi
      sleep 2
      continue
    fi
    if [[ "$(jq -r 'type' <<<"$resp")" != "array" ]]; then
      if (( now - op_missing_since_epoch >= op_missing_grace_seconds )); then
        die "operation missing from wallet queue for too long opid=$opid"
      fi
      sleep 2
      continue
    fi
    if [[ "$(jq -r 'length' <<<"$resp")" == "0" ]]; then
      if (( now - op_missing_since_epoch >= op_missing_grace_seconds )); then
        die "operation missing from wallet queue for too long opid=$opid"
      fi
      sleep 2
      continue
    fi
    op_missing_since_epoch="$now"
    op_json="$(jq -c '.[0] // empty' <<<"$resp" 2>/dev/null || true)"
    if [[ -z "$op_json" || "$op_json" == "null" ]]; then
      sleep 2
      continue
    fi
    status="$(jq -r '.status // empty' <<<"$op_json")"
    case "$status" in
      success)
        txid="$(jq -r '.result.txid // empty' <<<"$op_json")"
        [[ -n "$txid" ]] || die "operation succeeded without txid opid=$opid"
        trim_txid "$txid"
        return 0
        ;;
      failed)
        err_msg="$(jq -r '.error.message // "unknown error"' <<<"$op_json")"
        die "operation failed opid=$opid error=$err_msg"
        ;;
      *)
        sleep 2
        ;;
    esac
  done
}

submit_and_confirm_witness_tx() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local from_address="$4"
  local recipient_ua="$5"
  local amount_dec="$6"
  local deadline_epoch="$7"
  local memo_hex="$8"

  local opid txid
  opid="$({
    juno_rpc_result \
      "$rpc_url" \
      "$rpc_user" \
      "$rpc_pass" \
      "z_sendmany" \
      "$(jq -cn --arg from "$from_address" --arg to "$recipient_ua" --arg amt "$amount_dec" --arg memo_hex "$memo_hex" '[ $from, [ { address: $to, amount: ($amt | tonumber), memo: $memo_hex } ], 1 ]')" \
      | jq -r '.'
  })"
  [[ -n "$opid" && "$opid" != "null" ]] || die "failed to submit witness tx"

  txid="$(juno_wait_operation_txid "$rpc_url" "$rpc_user" "$rpc_pass" "$opid" "$deadline_epoch")"
  juno_wait_tx_confirmed "$rpc_url" "$rpc_user" "$rpc_pass" "$txid" "$deadline_epoch"
  printf '%s' "$txid"
}

juno_select_funded_unified_address() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local accounts_json account_id balance_json funded_zat candidate_ua

  accounts_json="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "z_listaccounts" '[]' || true)"
  if [[ -z "$accounts_json" || "$accounts_json" == "null" ]]; then
    return 1
  fi

  while IFS= read -r account_id; do
    [[ "$account_id" =~ ^[0-9]+$ ]] || continue
    balance_json="$({
      juno_rpc_result \
        "$rpc_url" \
        "$rpc_user" \
        "$rpc_pass" \
        "z_getbalanceforaccount" \
        "$(jq -cn --argjson account "$account_id" '[ $account, 1 ]')" || true
    })"
    funded_zat="$(jq -r '.pools // {} | to_entries | map((.value.valueZat // 0) | tonumber) | add // 0' <<<"${balance_json:-null}" 2>/dev/null || echo 0)"
    [[ "$funded_zat" =~ ^[0-9]+$ ]] || funded_zat=0
    if (( funded_zat > 0 )); then
      candidate_ua="$(jq -r --argjson account "$account_id" '.[] | select(.account == $account) | .addresses[0].ua // empty' <<<"$accounts_json")"
      if [[ -n "$candidate_ua" ]]; then
        printf '%s' "$candidate_ua"
        return 0
      fi
    fi
  done < <(jq -r '.[]?.account // empty' <<<"$accounts_json")

  return 1
}

juno_wallet_has_mnemonic_seed() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local resp err

  resp="$(juno_rpc_json_call "$rpc_url" "$rpc_user" "$rpc_pass" "z_getseedphrase" '[]' || true)"
  [[ -n "$resp" ]] || return 1
  err="$(jq -r '.error.message // empty' <<<"$resp" 2>/dev/null || true)"
  if [[ -z "$err" ]]; then
    return 0
  fi
  if [[ "$(lower "$err")" == *"does not have a mnemonic seed phrase"* ]]; then
    return 1
  fi
  return 0
}

juno_recover_wallet_from_seed_phrase() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local seed_phrase="$4"
  local chain_height birthday_height

  chain_height="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "getblockcount" '[]' | jq -r '.')"
  [[ "$chain_height" =~ ^[0-9]+$ ]] || chain_height=0
  if (( chain_height > 2000 )); then
    birthday_height=$((chain_height - 2000))
  else
    birthday_height=0
  fi

  juno_rpc_result \
    "$rpc_url" \
    "$rpc_user" \
    "$rpc_pass" \
    "z_recoverwallet" \
    "$(jq -cn --arg mnemonic "$seed_phrase" --argjson birthday "$birthday_height" '[ $mnemonic, $birthday ]')" >/dev/null
}

juno_wait_tx_confirmed() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid="$4"
  local deadline_epoch="$5"
  local params_json resp confirmations now

  params_json="$(jq -cn --arg txid "$txid" '[ $txid, 1 ]')"
  while true; do
    now="$(date +%s)"
    if (( now >= deadline_epoch )); then
      die "timed out waiting for juno tx confirmation txid=$txid"
    fi
    resp="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "getrawtransaction" "$params_json" || true)"
    confirmations="$(jq -r '.confirmations // 0' <<<"${resp:-null}" 2>/dev/null || echo 0)"
    if [[ "$confirmations" =~ ^[0-9]+$ ]] && (( confirmations >= 1 )); then
      return 0
    fi
    sleep 4
  done
}

scan_auth_header() {
  local bearer="$1"
  if [[ -n "$bearer" ]]; then
    printf '%s' "Authorization: Bearer $bearer"
  fi
}

scan_upsert_wallet() {
  local scan_url="$1"
  local bearer="$2"
  local wallet_id="$3"
  local ufvk="$4"
  local auth_header

  auth_header="$(scan_auth_header "$bearer")"
  if [[ -n "$auth_header" ]]; then
    curl -fsS \
      --connect-timeout "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS" \
      --max-time "$JUNO_SCAN_CURL_MAX_TIME_SECONDS" \
      --header "Content-Type: application/json" \
      --header "$auth_header" \
      --data "$(jq -cn --arg wallet_id "$wallet_id" --arg ufvk "$ufvk" '{wallet_id: $wallet_id, ufvk: $ufvk}')" \
      "${scan_url%/}/v1/wallets" >/dev/null
  else
    curl -fsS \
      --connect-timeout "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS" \
      --max-time "$JUNO_SCAN_CURL_MAX_TIME_SECONDS" \
      --header "Content-Type: application/json" \
      --data "$(jq -cn --arg wallet_id "$wallet_id" --arg ufvk "$ufvk" '{wallet_id: $wallet_id, ufvk: $ufvk}')" \
      "${scan_url%/}/v1/wallets" >/dev/null
  fi
}

scan_find_action_index() {
  local scan_url="$1"
  local bearer="$2"
  local wallet_id="$3"
  local txid="$4"
  local deadline_epoch="$5"
  local auth_header base_url url body action now next_cursor cursor encoded_cursor
  local scan_http_failures_consecutive=0
  local -A seen_cursors=()

  auth_header="$(scan_auth_header "$bearer")"
  base_url="${scan_url%/}/v1/wallets/${wallet_id}/notes?limit=1000"
  txid="$(trim_txid "$txid")"

  while true; do
    now="$(date +%s)"
    if (( now >= deadline_epoch )); then
      die "timed out waiting for juno-scan note indexing wallet=$wallet_id txid=$txid"
    fi

    cursor=""
    seen_cursors=()
    while true; do
      url="$base_url"
      if [[ -n "$cursor" ]]; then
        encoded_cursor="$(jq -rn --arg value "$cursor" '$value|@uri')"
        url="${url}&cursor=${encoded_cursor}"
      fi

      if [[ -n "$auth_header" ]]; then
        body="$(
          curl -fsS \
            --connect-timeout "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS" \
            --max-time "$JUNO_SCAN_CURL_MAX_TIME_SECONDS" \
            --header "$auth_header" \
            "$url" || true
        )"
      else
        body="$(
          curl -fsS \
            --connect-timeout "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS" \
            --max-time "$JUNO_SCAN_CURL_MAX_TIME_SECONDS" \
            "$url" || true
        )"
      fi
      if [[ -z "$body" ]]; then
        scan_http_failures_consecutive=$((scan_http_failures_consecutive + 1))
        if (( scan_http_failures_consecutive >= 6 )); then
          die "juno-scan notes endpoint repeatedly failed wallet=$wallet_id txid=$txid"
        fi
        break
      fi
      if ! jq -e '.notes | type == "array"' >/dev/null 2>&1 <<<"$body"; then
        scan_http_failures_consecutive=$((scan_http_failures_consecutive + 1))
        if (( scan_http_failures_consecutive >= 6 )); then
          die "juno-scan notes endpoint repeatedly failed wallet=$wallet_id txid=$txid"
        fi
        break
      fi
      scan_http_failures_consecutive=0

      action="$({
        jq -r \
          --arg txid "$txid" \
          '
            .notes
            | map(select((.txid // "" | ascii_downcase) == $txid and (.position != null)))
            | (if length > 0 then .[0].action_index else empty end)
          ' <<<"$body" 2>/dev/null || true
      })"
      if [[ "$action" =~ ^[0-9]+$ ]]; then
        printf '%s' "$action"
        return 0
      fi

      next_cursor="$(jq -r '.next_cursor // empty' <<<"$body" 2>/dev/null || true)"
      next_cursor="$(trim "$next_cursor")"
      [[ -n "$next_cursor" ]] || break
      if [[ -n "${seen_cursors[$next_cursor]+x}" ]]; then
        break
      fi
      seen_cursors["$next_cursor"]=1
      cursor="$next_cursor"
    done
    sleep 4
  done
}

command_run() {
  shift || true

  local juno_rpc_url=""
  local juno_rpc_user=""
  local juno_rpc_pass=""
  local juno_scan_url=""
  local pre_upsert_scan_urls_csv=""
  local juno_scan_bearer_token=""
  local funder_wif=""
  local funder_private_key_hex=""
  local funder_seed_phrase=""
  local funder_source_address=""
  local wallet_id=""
  local recipient_ua=""
  local recipient_ufvk=""
  local base_chain_id=""
  local bridge_address=""
  local base_recipient_address=""
  local withdrawal_id_hex=""
  local withdraw_batch_id_hex=""
  local skip_action_index_lookup="false"
  local deposit_amount_zat="100000"
  local withdraw_amount_zat="10000"
  local timeout_seconds="900"
  local output_path="-"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --juno-rpc-url)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-url"
        juno_rpc_url="$2"
        shift 2
        ;;
      --juno-rpc-user)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-user"
        juno_rpc_user="$2"
        shift 2
        ;;
      --juno-rpc-pass)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-pass"
        juno_rpc_pass="$2"
        shift 2
        ;;
      --juno-scan-url)
        [[ $# -ge 2 ]] || die "missing value for --juno-scan-url"
        juno_scan_url="$2"
        shift 2
        ;;
      --pre-upsert-scan-urls)
        [[ $# -ge 2 ]] || die "missing value for --pre-upsert-scan-urls"
        pre_upsert_scan_urls_csv="$2"
        shift 2
        ;;
      --juno-scan-bearer-token)
        [[ $# -ge 2 ]] || die "missing value for --juno-scan-bearer-token"
        juno_scan_bearer_token="$2"
        shift 2
        ;;
      --funder-wif)
        [[ $# -ge 2 ]] || die "missing value for --funder-wif"
        funder_wif="$2"
        shift 2
        ;;
      --funder-private-key-hex)
        [[ $# -ge 2 ]] || die "missing value for --funder-private-key-hex"
        funder_private_key_hex="$2"
        shift 2
        ;;
      --funder-seed-phrase)
        [[ $# -ge 2 ]] || die "missing value for --funder-seed-phrase"
        funder_seed_phrase="$2"
        shift 2
        ;;
      --funder-source-address)
        [[ $# -ge 2 ]] || die "missing value for --funder-source-address"
        funder_source_address="$2"
        shift 2
        ;;
      --wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --wallet-id"
        wallet_id="$2"
        shift 2
        ;;
      --recipient-ua)
        [[ $# -ge 2 ]] || die "missing value for --recipient-ua"
        recipient_ua="$2"
        shift 2
        ;;
      --recipient-ufvk)
        [[ $# -ge 2 ]] || die "missing value for --recipient-ufvk"
        recipient_ufvk="$2"
        shift 2
        ;;
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
      --base-recipient-address)
        [[ $# -ge 2 ]] || die "missing value for --base-recipient-address"
        base_recipient_address="$2"
        shift 2
        ;;
      --withdrawal-id-hex)
        [[ $# -ge 2 ]] || die "missing value for --withdrawal-id-hex"
        withdrawal_id_hex="$2"
        shift 2
        ;;
      --withdraw-batch-id-hex)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-batch-id-hex"
        withdraw_batch_id_hex="$2"
        shift 2
        ;;
      --skip-action-index-lookup)
        skip_action_index_lookup="true"
        shift
        ;;
      --deposit-amount-zat)
        [[ $# -ge 2 ]] || die "missing value for --deposit-amount-zat"
        deposit_amount_zat="$2"
        shift 2
        ;;
      --withdraw-amount-zat)
        [[ $# -ge 2 ]] || die "missing value for --withdraw-amount-zat"
        withdraw_amount_zat="$2"
        shift 2
        ;;
      --timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --timeout-seconds"
        timeout_seconds="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output_path="$2"
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

  [[ -n "$juno_rpc_url" ]] || die "--juno-rpc-url is required"
  [[ -n "$juno_rpc_user" ]] || die "--juno-rpc-user is required"
  [[ -n "$juno_rpc_pass" ]] || die "--juno-rpc-pass is required"
  [[ -n "$juno_scan_url" ]] || die "--juno-scan-url is required"
  [[ -n "$base_chain_id" ]] || die "--base-chain-id is required"
  [[ -n "$bridge_address" ]] || die "--bridge-address is required"
  [[ -n "$base_recipient_address" ]] || die "--base-recipient-address is required"
  [[ -n "$withdrawal_id_hex" ]] || die "--withdrawal-id-hex is required"
  [[ -n "$withdraw_batch_id_hex" ]] || die "--withdraw-batch-id-hex is required"
  if [[ -z "$funder_wif" && -z "$funder_private_key_hex" && -z "$funder_seed_phrase" && -z "$funder_source_address" ]]; then
    die "one of --funder-wif, --funder-private-key-hex, --funder-seed-phrase, or --funder-source-address is required"
  fi
  funder_source_address="$(trim "$funder_source_address")"
  recipient_ua="$(trim "$recipient_ua")"
  recipient_ufvk="$(trim "$recipient_ufvk")"
  if [[ -n "$recipient_ua" || -n "$recipient_ufvk" ]]; then
    [[ -n "$recipient_ua" && -n "$recipient_ufvk" ]] || \
      die "--recipient-ua and --recipient-ufvk must be provided together"
  fi
  if [[ -n "$funder_seed_phrase" ]]; then
    funder_seed_phrase="$(normalize_mnemonic_seed_phrase "$funder_seed_phrase")"
  fi
  [[ "$base_chain_id" =~ ^[0-9]+$ ]] || die "--base-chain-id must be numeric"
  (( base_chain_id > 0 )) || die "--base-chain-id must be > 0"
  (( base_chain_id <= 4294967295 )) || die "--base-chain-id must fit uint32"
  [[ "$deposit_amount_zat" =~ ^[0-9]+$ ]] || die "--deposit-amount-zat must be numeric"
  [[ "$withdraw_amount_zat" =~ ^[0-9]+$ ]] || die "--withdraw-amount-zat must be numeric"
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "--timeout-seconds must be numeric"
  bridge_address="$(normalize_hex_0x_address "$bridge_address" || true)"
  [[ -n "$bridge_address" ]] || die "--bridge-address must be a 20-byte hex address"
  base_recipient_address="$(normalize_hex_0x_address "$base_recipient_address" || true)"
  [[ -n "$base_recipient_address" ]] || die "--base-recipient-address must be a 20-byte hex address"
  withdrawal_id_hex="$(normalize_fixed_hex "$withdrawal_id_hex" 32 || true)"
  [[ -n "$withdrawal_id_hex" ]] || die "--withdrawal-id-hex must be 32-byte hex"
  withdraw_batch_id_hex="$(normalize_fixed_hex "$withdraw_batch_id_hex" 32 || true)"
  [[ -n "$withdraw_batch_id_hex" ]] || die "--withdraw-batch-id-hex must be 32-byte hex"
  (( timeout_seconds > 0 )) || die "--timeout-seconds must be > 0"

  ensure_base_dependencies
  ensure_command jq
  ensure_command curl
  ensure_command go
  ensure_command python3
  [[ "$JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || die "JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS must be numeric"
  [[ "$JUNO_RPC_CURL_MAX_TIME_SECONDS" =~ ^[0-9]+$ ]] || die "JUNO_RPC_CURL_MAX_TIME_SECONDS must be numeric"
  [[ "$JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || die "JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS must be numeric"
  [[ "$JUNO_SCAN_CURL_MAX_TIME_SECONDS" =~ ^[0-9]+$ ]] || die "JUNO_SCAN_CURL_MAX_TIME_SECONDS must be numeric"
  (( JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS > 0 )) || die "JUNO_RPC_CURL_CONNECT_TIMEOUT_SECONDS must be > 0"
  (( JUNO_RPC_CURL_MAX_TIME_SECONDS > 0 )) || die "JUNO_RPC_CURL_MAX_TIME_SECONDS must be > 0"
  (( JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS > 0 )) || die "JUNO_SCAN_CURL_CONNECT_TIMEOUT_SECONDS must be > 0"
  (( JUNO_SCAN_CURL_MAX_TIME_SECONDS > 0 )) || die "JUNO_SCAN_CURL_MAX_TIME_SECONDS must be > 0"

  if [[ -z "$wallet_id" ]]; then
    wallet_id="testnet-e2e-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
  fi

  local deadline_epoch now
  now="$(date +%s)"
  deadline_epoch=$((now + timeout_seconds))

  local account_json account_id address_json ufvk receivers_json recipient_orchard_receiver recipient_raw_address_hex
  if [[ -z "$recipient_ua" ]]; then
    account_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_getnewaccount" '[]')"
    account_id="$(jq -r '.account // empty' <<<"$account_json")"
    [[ "$account_id" =~ ^[0-9]+$ ]] || die "failed to create juno account"

    address_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_getaddressforaccount" "$(jq -cn --argjson account "$account_id" '[ $account ]')")"
    recipient_ua="$(jq -r '.address // empty' <<<"$address_json")"
    [[ -n "$recipient_ua" ]] || die "failed to derive recipient unified address"

    ufvk="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_exportviewingkey" "$(jq -cn --arg ua "$recipient_ua" '[ $ua ]')" | jq -r '.')"
    [[ -n "$ufvk" && "$ufvk" != "null" ]] || die "failed to export viewing key for recipient unified address"
  else
    ufvk="$recipient_ufvk"
  fi

  receivers_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_listunifiedreceivers" "$(jq -cn --arg ua "$recipient_ua" '[ $ua ]')")"
  recipient_orchard_receiver="$(jq -r '.orchard // empty' <<<"$receivers_json")"
  [[ -n "$recipient_orchard_receiver" ]] || die "failed to resolve orchard receiver from recipient unified address"
  recipient_raw_address_hex="$(decode_orchard_receiver_raw_hex "$recipient_orchard_receiver")"
  [[ ${#recipient_raw_address_hex} -eq 86 ]] || die "decoded recipient raw orchard address must be 43 bytes"

  local -a pre_upsert_scan_urls=()
  local -a pre_upsert_scan_urls_raw=()
  local -A pre_upsert_scan_urls_seen=()
  local pre_upsert_scan_url scan_url_entry
  pre_upsert_scan_urls+=("$juno_scan_url")
  pre_upsert_scan_urls_seen["$juno_scan_url"]=1
  if [[ -n "$pre_upsert_scan_urls_csv" ]]; then
    IFS=',' read -r -a pre_upsert_scan_urls_raw <<<"$pre_upsert_scan_urls_csv"
    for scan_url_entry in "${pre_upsert_scan_urls_raw[@]}"; do
      scan_url_entry="$(trim "$scan_url_entry")"
      [[ -n "$scan_url_entry" ]] || continue
      if [[ -z "${pre_upsert_scan_urls_seen[$scan_url_entry]+x}" ]]; then
        pre_upsert_scan_urls+=("$scan_url_entry")
        pre_upsert_scan_urls_seen["$scan_url_entry"]=1
      fi
    done
  fi
  for pre_upsert_scan_url in "${pre_upsert_scan_urls[@]}"; do
    if ! scan_upsert_wallet "$pre_upsert_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$ufvk"; then
      if [[ "$pre_upsert_scan_url" == "$juno_scan_url" ]]; then
        die "failed to upsert witness wallet on primary juno-scan endpoint: $pre_upsert_scan_url"
      fi
      log "witness wallet pre-upsert failed on scan endpoint: $pre_upsert_scan_url (continuing)"
    fi
  done

  local funder_from_address="" funder_taddr="" funder_source_kind=""
  if [[ -n "$funder_source_address" ]]; then
    funder_source_kind="explicit_source_address"
    funder_from_address="$funder_source_address"
  elif [[ -n "$funder_seed_phrase" ]]; then
    funder_source_kind="seed_phrase_unified_account"
    funder_from_address="$(juno_select_funded_unified_address "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" || true)"
    if [[ -z "$funder_from_address" ]]; then
      if ! juno_wallet_has_mnemonic_seed "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass"; then
        juno_recover_wallet_from_seed_phrase "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$funder_seed_phrase"
      fi
      funder_from_address="$(juno_select_funded_unified_address "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" || true)"
    fi
    [[ -n "$funder_from_address" ]] || die "failed to resolve funded unified account for --funder-seed-phrase"
  else
    if [[ -n "$funder_private_key_hex" ]]; then
      funder_wif="$(hex_to_testnet_wif "$funder_private_key_hex")"
    fi
    [[ -n "$funder_wif" ]] || die "failed to resolve funder WIF"
    funder_source_kind="transparent_wif"

    local import_params import_result listaddresses_json
    import_params="$(jq -cn --arg wif "$funder_wif" '[ $wif, "", false ]')"
    import_result="$({
      juno_rpc_result_allow_key_exists "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "importprivkey" "$import_params" || true
    })"
    funder_taddr="$(jq -r 'if type == "string" then . else empty end' <<<"${import_result:-null}")"

    if [[ -z "$funder_taddr" ]]; then
      listaddresses_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "listaddresses" '[]' || true)"
      funder_taddr="$({
        jq -r '
          .[]
          | select(.source == "imported")
          | .transparent.addresses[]?
        ' <<<"${listaddresses_json:-[]}" | head -n 1
      })"
    fi
    [[ -n "$funder_taddr" ]] || die "failed to derive funder transparent address from imported private key"
    funder_from_address="$funder_taddr"
  fi

  local deposit_amount_dec withdraw_amount_dec
  deposit_amount_dec="$(zat_to_decimal "$deposit_amount_zat")"
  withdraw_amount_dec="$(zat_to_decimal "$withdraw_amount_zat")"

  local deposit_memo_hex withdraw_memo_hex
  deposit_memo_hex="$(encode_deposit_memo_hex "$base_chain_id" "$bridge_address" "$base_recipient_address" "1" "0")"
  deposit_memo_hex="$(normalize_fixed_hex "$deposit_memo_hex" 512 || true)"
  [[ -n "$deposit_memo_hex" ]] || die "failed to encode deposit witness memo"
  withdraw_memo_hex="$(encode_withdraw_memo_hex "$base_chain_id" "$bridge_address" "$withdrawal_id_hex" "$withdraw_batch_id_hex" "0")"
  withdraw_memo_hex="$(normalize_fixed_hex "$withdraw_memo_hex" 512 || true)"
  [[ -n "$withdraw_memo_hex" ]] || die "failed to encode withdraw witness memo"

  local deposit_txid withdraw_txid
  deposit_txid="$(submit_and_confirm_witness_tx "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$funder_from_address" "$recipient_ua" "$deposit_amount_dec" "$deadline_epoch" "$deposit_memo_hex")"
  withdraw_txid="$(submit_and_confirm_witness_tx "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$funder_from_address" "$recipient_ua" "$withdraw_amount_dec" "$deadline_epoch" "$withdraw_memo_hex")"

  local deposit_action_index withdraw_action_index
  if [[ "$skip_action_index_lookup" == "true" ]]; then
    # Action index is derived later from tx Orchard actions during witness extraction.
    deposit_action_index="0"
    withdraw_action_index="0"
  else
    deposit_action_index="$(scan_find_action_index "$juno_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$deposit_txid" "$deadline_epoch")"
    withdraw_action_index="$(scan_find_action_index "$juno_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$withdraw_txid" "$deadline_epoch")"
  fi

  local out_json
  out_json="$({
    jq -n \
      --arg generated_at "$(timestamp_utc)" \
      --arg wallet_id "$wallet_id" \
      --arg recipient_ua "$recipient_ua" \
      --arg recipient_orchard_receiver "$recipient_orchard_receiver" \
      --arg recipient_raw_address_hex "$recipient_raw_address_hex" \
      --arg ufvk "$ufvk" \
      --arg funder_taddr "$funder_taddr" \
      --arg funder_source_address "$funder_from_address" \
      --arg funder_source_kind "$funder_source_kind" \
      --arg deposit_txid "$deposit_txid" \
      --arg withdraw_txid "$withdraw_txid" \
      --argjson deposit_action_index "$deposit_action_index" \
      --argjson withdraw_action_index "$withdraw_action_index" \
      --argjson deposit_amount_zat "$deposit_amount_zat" \
      --argjson withdraw_amount_zat "$withdraw_amount_zat" \
      --arg action_index_lookup_mode "$skip_action_index_lookup" \
      '{
        generated_at: $generated_at,
        wallet_id: $wallet_id,
        recipient_ua: $recipient_ua,
        recipient_orchard_receiver: $recipient_orchard_receiver,
        recipient_raw_address_hex: $recipient_raw_address_hex,
        ufvk: $ufvk,
        funder_taddr: $funder_taddr,
        funder_source_address: $funder_source_address,
        funder_source_kind: $funder_source_kind,
        deposit_amount_zat: $deposit_amount_zat,
        withdraw_amount_zat: $withdraw_amount_zat,
        deposit_txid: $deposit_txid,
        deposit_action_index: $deposit_action_index,
        withdraw_txid: $withdraw_txid,
        withdraw_action_index: $withdraw_action_index,
        action_index_lookup_skipped: ($action_index_lookup_mode == "true")
      }'
  })"

  if [[ "$output_path" == "-" ]]; then
    printf '%s\n' "$out_json"
  else
    ensure_dir "$(dirname "$output_path")"
    printf '%s\n' "$out_json" >"$output_path"
    printf '%s\n' "$output_path"
  fi
}

main() {
  local cmd="${1:-run}"
  case "$cmd" in
    run) command_run "$@" ;;
    decode-orchard-raw) command_decode_orchard_raw "$@" ;;
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
