#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

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
  --juno-scan-bearer-token <token>   optional juno-scan bearer token
  --funder-private-key-hex <hex>     optional funder private key hex (32-byte); converted to testnet WIF
  --funder-wif <wif>                 optional funder WIF (used directly when provided)
  --wallet-id <id>                   optional juno-scan wallet id (default: generated run id)
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
  local payload

  payload="$({
    jq -cn \
      --arg method "$method" \
      --argjson params "$params_json" \
      '{jsonrpc: "1.0", id: "witness-meta", method: $method, params: $params}'
  })"
  curl -fsS \
    --user "$rpc_user:$rpc_pass" \
    --header "content-type: application/json" \
    --data-binary "$payload" \
    "$rpc_url"
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
  local resp status txid err_msg now params_json

  params_json="$(jq -cn --arg opid "$opid" '[ $opid ]')"
  while true; do
    now="$(date +%s)"
    if (( now >= deadline_epoch )); then
      die "timed out waiting for juno operation result opid=$opid"
    fi
    resp="$(juno_rpc_result "$rpc_url" "$rpc_user" "$rpc_pass" "z_getoperationresult" "$params_json" || true)"
    if [[ -z "$resp" || "$resp" == "null" ]]; then
      sleep 2
      continue
    fi
    if [[ "$(jq -r 'type' <<<"$resp")" != "array" ]]; then
      sleep 2
      continue
    fi
    if [[ "$(jq -r 'length' <<<"$resp")" == "0" ]]; then
      sleep 2
      continue
    fi
    status="$(jq -r '.[0].status // empty' <<<"$resp")"
    case "$status" in
      success)
        txid="$(jq -r '.[0].result.txid // empty' <<<"$resp")"
        [[ -n "$txid" ]] || die "operation succeeded without txid opid=$opid"
        trim_txid "$txid"
        return 0
        ;;
      failed)
        err_msg="$(jq -r '.[0].error.message // "unknown error"' <<<"$resp")"
        die "operation failed opid=$opid error=$err_msg"
        ;;
      *)
        sleep 2
        ;;
    esac
  done
}

juno_wait_tx_confirmed() {
  local rpc_url="$1"
  local rpc_user="$2"
  local rpc_pass="$3"
  local txid="$4"
  local deadline_epoch="$5"
  local params_json resp confirmations now

  params_json="$(jq -cn --arg txid "$txid" '[ $txid, true ]')"
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
      --header "Content-Type: application/json" \
      --header "$auth_header" \
      --data "$(jq -cn --arg wallet_id "$wallet_id" --arg ufvk "$ufvk" '{wallet_id: $wallet_id, ufvk: $ufvk}')" \
      "${scan_url%/}/v1/wallets" >/dev/null
  else
    curl -fsS \
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
  local auth_header url body action now

  auth_header="$(scan_auth_header "$bearer")"
  url="${scan_url%/}/v1/wallets/${wallet_id}/notes?spent=true&limit=1000"
  txid="$(trim_txid "$txid")"

  while true; do
    now="$(date +%s)"
    if (( now >= deadline_epoch )); then
      die "timed out waiting for juno-scan note indexing wallet=$wallet_id txid=$txid"
    fi

    if [[ -n "$auth_header" ]]; then
      body="$(curl -fsS --header "$auth_header" "$url" || true)"
    else
      body="$(curl -fsS "$url" || true)"
    fi
    if [[ -z "$body" ]]; then
      sleep 4
      continue
    fi

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
    sleep 4
  done
}

command_run() {
  shift || true

  local juno_rpc_url=""
  local juno_rpc_user=""
  local juno_rpc_pass=""
  local juno_scan_url=""
  local juno_scan_bearer_token=""
  local funder_wif=""
  local funder_private_key_hex=""
  local wallet_id=""
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
      --wallet-id)
        [[ $# -ge 2 ]] || die "missing value for --wallet-id"
        wallet_id="$2"
        shift 2
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
  if [[ -z "$funder_wif" && -z "$funder_private_key_hex" ]]; then
    die "one of --funder-wif or --funder-private-key-hex is required"
  fi
  [[ "$deposit_amount_zat" =~ ^[0-9]+$ ]] || die "--deposit-amount-zat must be numeric"
  [[ "$withdraw_amount_zat" =~ ^[0-9]+$ ]] || die "--withdraw-amount-zat must be numeric"
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "--timeout-seconds must be numeric"
  (( timeout_seconds > 0 )) || die "--timeout-seconds must be > 0"

  ensure_base_dependencies
  ensure_command jq
  ensure_command curl
  ensure_command python3

  if [[ -n "$funder_private_key_hex" ]]; then
    funder_wif="$(hex_to_testnet_wif "$funder_private_key_hex")"
  fi
  [[ -n "$funder_wif" ]] || die "failed to resolve funder WIF"

  if [[ -z "$wallet_id" ]]; then
    wallet_id="testnet-e2e-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
  fi

  local deadline_epoch now
  now="$(date +%s)"
  deadline_epoch=$((now + timeout_seconds))

  local account_json account_id address_json recipient_ua ufvk receivers_json recipient_orchard_receiver recipient_raw_address_hex
  account_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_getnewaccount" '[]')"
  account_id="$(jq -r '.account // empty' <<<"$account_json")"
  [[ "$account_id" =~ ^[0-9]+$ ]] || die "failed to create juno account"

  address_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_getaddressforaccount" "$(jq -cn --argjson account "$account_id" '[ $account ]')")"
  recipient_ua="$(jq -r '.address // empty' <<<"$address_json")"
  [[ -n "$recipient_ua" ]] || die "failed to derive recipient unified address"

  ufvk="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_exportviewingkey" "$(jq -cn --arg ua "$recipient_ua" '[ $ua ]')" | jq -r '.')"
  [[ -n "$ufvk" && "$ufvk" != "null" ]] || die "failed to export viewing key for recipient unified address"

  receivers_json="$(juno_rpc_result "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "z_listunifiedreceivers" "$(jq -cn --arg ua "$recipient_ua" '[ $ua ]')")"
  recipient_orchard_receiver="$(jq -r '.orchard // empty' <<<"$receivers_json")"
  [[ -n "$recipient_orchard_receiver" ]] || die "failed to resolve orchard receiver from recipient unified address"
  recipient_raw_address_hex="$(decode_orchard_receiver_raw_hex "$recipient_orchard_receiver")"
  [[ ${#recipient_raw_address_hex} -eq 86 ]] || die "decoded recipient raw orchard address must be 43 bytes"

  scan_upsert_wallet "$juno_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$ufvk"

  local import_params import_result funder_taddr listaddresses_json
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

  local deposit_amount_dec withdraw_amount_dec
  deposit_amount_dec="$(zat_to_decimal "$deposit_amount_zat")"
  withdraw_amount_dec="$(zat_to_decimal "$withdraw_amount_zat")"

  local deposit_opid withdraw_opid
  deposit_opid="$({
    juno_rpc_result \
      "$juno_rpc_url" \
      "$juno_rpc_user" \
      "$juno_rpc_pass" \
      "z_sendmany" \
      "$(jq -cn --arg from "$funder_taddr" --arg to "$recipient_ua" --arg amt "$deposit_amount_dec" '[ $from, [ { address: $to, amount: ($amt | tonumber) } ], 1, 0 ]')" \
      | jq -r '.'
  })"
  [[ -n "$deposit_opid" && "$deposit_opid" != "null" ]] || die "failed to submit deposit witness tx"

  withdraw_opid="$({
    juno_rpc_result \
      "$juno_rpc_url" \
      "$juno_rpc_user" \
      "$juno_rpc_pass" \
      "z_sendmany" \
      "$(jq -cn --arg from "$funder_taddr" --arg to "$recipient_ua" --arg amt "$withdraw_amount_dec" '[ $from, [ { address: $to, amount: ($amt | tonumber) } ], 1, 0 ]')" \
      | jq -r '.'
  })"
  [[ -n "$withdraw_opid" && "$withdraw_opid" != "null" ]] || die "failed to submit withdraw witness tx"

  local deposit_txid withdraw_txid
  deposit_txid="$(juno_wait_operation_txid "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$deposit_opid" "$deadline_epoch")"
  withdraw_txid="$(juno_wait_operation_txid "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$withdraw_opid" "$deadline_epoch")"

  juno_wait_tx_confirmed "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$deposit_txid" "$deadline_epoch"
  juno_wait_tx_confirmed "$juno_rpc_url" "$juno_rpc_user" "$juno_rpc_pass" "$withdraw_txid" "$deadline_epoch"

  local deposit_action_index withdraw_action_index
  deposit_action_index="$(scan_find_action_index "$juno_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$deposit_txid" "$deadline_epoch")"
  withdraw_action_index="$(scan_find_action_index "$juno_scan_url" "$juno_scan_bearer_token" "$wallet_id" "$withdraw_txid" "$deadline_epoch")"

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
      --arg deposit_txid "$deposit_txid" \
      --arg withdraw_txid "$withdraw_txid" \
      --argjson deposit_action_index "$deposit_action_index" \
      --argjson withdraw_action_index "$withdraw_action_index" \
      --argjson deposit_amount_zat "$deposit_amount_zat" \
      --argjson withdraw_amount_zat "$withdraw_amount_zat" \
      '{
        generated_at: $generated_at,
        wallet_id: $wallet_id,
        recipient_ua: $recipient_ua,
        recipient_orchard_receiver: $recipient_orchard_receiver,
        recipient_raw_address_hex: $recipient_raw_address_hex,
        ufvk: $ufvk,
        funder_taddr: $funder_taddr,
        deposit_amount_zat: $deposit_amount_zat,
        withdraw_amount_zat: $withdraw_amount_zat,
        deposit_txid: $deposit_txid,
        deposit_action_index: $deposit_action_index,
        withdraw_txid: $withdraw_txid,
        withdraw_action_index: $withdraw_action_index
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
