#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run-operator-local-canary.sh --operator-id ID
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

operator_id=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-id)
      operator_id="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$operator_id" ]] || die "--operator-id is required"
[[ -f /etc/intents-juno/operator-stack.env ]] || die "missing /etc/intents-juno/operator-stack.env"

# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env

services=(
  checkpoint-signer
  checkpoint-aggregator
  dkg-admin-serve
  tss-host
  base-relayer
  deposit-relayer
  withdraw-coordinator
  withdraw-finalizer
  base-event-scanner
)

input_status="passed"
input_detail="runtime material refs present"
relayer_funding_status="skipped"
relayer_funding_detail="host-local flow does not resolve relayer keys on the runner"
withdraw_config_status="passed"
withdraw_config_detail="operator env is staged correctly"
txsign_runtime_status="passed"
txsign_runtime_detail="juno-txsign supports sign-digest"
systemd_status="passed"
systemd_detail="all operator services active"
junocashd_sync_status="passed"
junocashd_sync_detail="junocashd is caught up enough"
deposit_relayer_ready_status="passed"
deposit_relayer_ready_detail="deposit-relayer /readyz passed"
kms_export_status="skipped"
kms_export_detail="no checkpoint blob bucket configured"
scan_catchup_status="passed"
scan_catchup_detail="juno-scan is caught up enough"

extend_signer_bin="${WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN:-}"
if [[ "${WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT:-}" != "1000000" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000"
elif [[ "${WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET:-}" != "240" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240"
elif [[ "${CHECKPOINT_SIGNER_DRIVER:-}" != "aws-kms" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing CHECKPOINT_SIGNER_DRIVER=aws-kms"
elif [[ -n "${CHECKPOINT_SIGNER_PRIVATE_KEY:-}" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env must not contain CHECKPOINT_SIGNER_PRIVATE_KEY"
elif [[ "${WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN:-}" != "6h" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h"
elif [[ "${WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION:-}" != "12h" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h"
elif [[ -n "${WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS:-}" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env must not contain WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS"
elif [[ -z "${WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS:-}" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS"
elif [[ -z "$extend_signer_bin" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env is missing WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN"
elif [[ ! -x "$extend_signer_bin" ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="withdraw extend signer is not executable: $extend_signer_bin"
elif [[ ! "${JUNO_TXSIGN_SIGNER_KEYS:-}" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
  withdraw_config_status="failed"
  withdraw_config_detail="operator env must contain exactly one operator-scoped JUNO_TXSIGN_SIGNER_KEYS entry"
fi

if [[ "$withdraw_config_status" == "passed" ]]; then
  txsign_help="$("$extend_signer_bin" --help 2>&1 || true)"
  if [[ "$txsign_help" != *"sign-digest"* ]]; then
    txsign_runtime_status="failed"
    txsign_runtime_detail="juno-txsign help does not list sign-digest"
  elif [[ "$txsign_help" != *"--operator-endpoint"* ]]; then
    txsign_runtime_status="failed"
    txsign_runtime_detail="juno-txsign help does not list --operator-endpoint"
  else
    txsign_probe="$("$extend_signer_bin" sign-digest --digest 0x1111111111111111111111111111111111111111111111111111111111111111 --json 2>/dev/null || true)"
    signature_count="$(jq -r '.data.signatures | length // 0' <<<"$txsign_probe" 2>/dev/null || printf '0')"
    threshold="${CHECKPOINT_THRESHOLD:-0}"
    if ! [[ "$threshold" =~ ^[0-9]+$ ]] || (( signature_count < threshold )); then
      txsign_runtime_status="failed"
      txsign_runtime_detail="sign-digest returned fewer signatures than checkpoint threshold"
    fi
  fi
fi

if [[ -n "${CHECKPOINT_BLOB_BUCKET:-}" ]]; then
  if [[ -f /var/lib/intents-juno/operator-runtime/exports/kms-export-receipt.json ]]; then
    kms_export_status="passed"
    kms_export_detail="runtime export receipt is present"
  else
    kms_export_status="failed"
    kms_export_detail="runtime export receipt is missing"
  fi
fi

for svc in "${services[@]}"; do
  if ! systemctl is-active --quiet "$svc"; then
    systemd_status="failed"
    systemd_detail="service is not active: $svc"
    break
  fi
done

if ! deposit_ready_response="$(curl -fsS "http://127.0.0.1:${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz" 2>/dev/null || true)"; then
  deposit_relayer_ready_status="failed"
  deposit_relayer_ready_detail="deposit-relayer readiness probe failed"
elif [[ -z "$deposit_ready_response" ]]; then
  deposit_relayer_ready_status="failed"
  deposit_relayer_ready_detail="deposit-relayer readiness probe returned empty output"
fi

juno_info="$(
  /usr/local/bin/junocash-cli -testnet -rpcconnect=127.0.0.1 -rpcport=18232 \
    -rpcuser="${JUNO_RPC_USER}" -rpcpassword="${JUNO_RPC_PASS}" \
    getblockchaininfo 2>/dev/null || true
)"
if [[ -z "$juno_info" ]]; then
  junocashd_sync_status="failed"
  junocashd_sync_detail="junocashd getblockchaininfo failed"
else
  initial_block_download_complete="$(jq -r '.initial_block_download_complete // false' <<<"$juno_info" 2>/dev/null || printf 'false')"
  verification_progress="$(jq -r '.verificationprogress // 0' <<<"$juno_info" 2>/dev/null || printf '0')"
  if [[ "$initial_block_download_complete" != "true" && "$verification_progress" != "1" ]]; then
    junocashd_sync_status="failed"
    junocashd_sync_detail="junocashd is still catching up"
  fi
fi

scan_health="$(curl -fsS http://127.0.0.1:8080/v1/health 2>/dev/null || true)"
local_tip="$(
  /usr/local/bin/junocash-cli -testnet -rpcconnect=127.0.0.1 -rpcport=18232 \
    -rpcuser="${JUNO_RPC_USER}" -rpcpassword="${JUNO_RPC_PASS}" \
    getblockcount 2>/dev/null || true
)"
if [[ -z "$scan_health" || -z "$local_tip" ]]; then
  scan_catchup_status="failed"
  scan_catchup_detail="juno-scan catch-up probe failed"
else
  scanned_height="$(jq -r '.scanned_height // 0' <<<"$scan_health" 2>/dev/null || printf '0')"
  local_tip="${local_tip//[[:space:]]/}"
  if ! [[ "$scanned_height" =~ ^[0-9]+$ && "$local_tip" =~ ^[0-9]+$ ]]; then
    scan_catchup_status="failed"
    scan_catchup_detail="juno-scan catch-up probe returned non-numeric heights"
  else
    lag_blocks=$(( local_tip - scanned_height ))
    if (( lag_blocks < 0 )); then
      lag_blocks=0
    fi
    if (( lag_blocks > 1 )); then
      scan_catchup_status="failed"
      scan_catchup_detail="juno-scan is ${lag_blocks} block(s) behind the local tip"
    else
      scan_catchup_detail="juno-scan is within 1 block(s) of local tip ${local_tip}"
    fi
  fi
fi

ready_for_deploy="true"
for status in \
  "$input_status" \
  "$withdraw_config_status" \
  "$txsign_runtime_status" \
  "$systemd_status" \
  "$junocashd_sync_status" \
  "$deposit_relayer_ready_status" \
  "$kms_export_status" \
  "$scan_catchup_status"
do
  case "$status" in
    passed|skipped) ;;
    *)
      ready_for_deploy="false"
      break
      ;;
  esac
done

jq -n \
  --arg operator_id "$operator_id" \
  --argjson ready_for_deploy "$ready_for_deploy" \
  --arg input_status "$input_status" \
  --arg input_detail "$input_detail" \
  --arg relayer_funding_status "$relayer_funding_status" \
  --arg relayer_funding_detail "$relayer_funding_detail" \
  --arg withdraw_config_status "$withdraw_config_status" \
  --arg withdraw_config_detail "$withdraw_config_detail" \
  --arg txsign_runtime_status "$txsign_runtime_status" \
  --arg txsign_runtime_detail "$txsign_runtime_detail" \
  --arg systemd_status "$systemd_status" \
  --arg systemd_detail "$systemd_detail" \
  --arg junocashd_sync_status "$junocashd_sync_status" \
  --arg junocashd_sync_detail "$junocashd_sync_detail" \
  --arg deposit_relayer_ready_status "$deposit_relayer_ready_status" \
  --arg deposit_relayer_ready_detail "$deposit_relayer_ready_detail" \
  --arg kms_export_status "$kms_export_status" \
  --arg kms_export_detail "$kms_export_detail" \
  --arg scan_catchup_status "$scan_catchup_status" \
  --arg scan_catchup_detail "$scan_catchup_detail" \
  '{
    operator_id: $operator_id,
    ready_for_deploy: $ready_for_deploy,
    checks: {
      inputs: {status: $input_status, detail: $input_detail},
      relayer_funding: {status: $relayer_funding_status, detail: $relayer_funding_detail},
      withdraw_config: {status: $withdraw_config_status, detail: $withdraw_config_detail},
      txsign_runtime: {status: $txsign_runtime_status, detail: $txsign_runtime_detail},
      systemd: {status: $systemd_status, detail: $systemd_detail},
      junocashd_sync: {status: $junocashd_sync_status, detail: $junocashd_sync_detail},
      deposit_relayer_ready: {status: $deposit_relayer_ready_status, detail: $deposit_relayer_ready_detail},
      kms_export: {status: $kms_export_status, detail: $kms_export_detail},
      scan_catchup: {status: $scan_catchup_status, detail: $scan_catchup_detail}
    }
  }'
