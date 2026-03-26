#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-operator-boot.sh --operator-deploy <path> [--dry-run]

Checks:
  - Required handoff inputs exist locally
  - Base relayer funding clears the deploy minimum
  - Remote withdraw env points at a configured extend signer and includes signer keys
  - Remote extend signer supports sign-digest and returns enough signatures for checkpoint quorum
  - Remote KMS export receipt exists when checkpoint blob export is configured
  - Remote operator services are active over strict-host-key SSH
  - Local juno-scan is caught up enough for deposit witness refreshes

Output:
  JSON summary to stdout suitable for rollout gating
EOF
}

operator_deploy=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy)
      operator_deploy="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$operator_deploy" ]] || die "--operator-deploy is required"
[[ -f "$operator_deploy" ]] || die "operator deploy manifest not found: $operator_deploy"
for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
using_runtime_material_ref="false"
if production_operator_uses_runtime_material_ref "$operator_deploy"; then
  using_runtime_material_ref="true"
fi
if [[ "$using_runtime_material_ref" == "true" ]]; then
  have_cmd aws || die "required command not found: aws"
elif [[ "$dry_run" != "true" ]]; then
  have_cmd cast || die "required command not found: cast"
  have_cmd ssh || die "required command not found: ssh"
fi

manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
operator_id="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
operator_user="$(production_json_required "$operator_deploy" '.operator_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$operator_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
aws_profile="$(production_json_optional "$operator_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
if [[ "$using_runtime_material_ref" == "true" ]]; then
  [[ -n "$aws_profile" ]] || die "operator deploy manifest is missing aws_profile for runtime_material_ref rollout"
  [[ -n "$aws_region" ]] || die "operator deploy manifest is missing aws_region for runtime_material_ref rollout"
fi
if [[ "$using_runtime_material_ref" == "true" ]]; then
  [[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'bucket')" ]] || die "operator deploy manifest is missing runtime_material_ref.bucket"
  [[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'key')" ]] || die "operator deploy manifest is missing runtime_material_ref.key"
  [[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'region')" ]] || die "operator deploy manifest is missing runtime_material_ref.region"
  [[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'kms_key_id')" ]] || die "operator deploy manifest is missing runtime_material_ref.kms_key_id"
  [[ -n "$(production_json_required "$operator_deploy" '.runtime_config_secret_id | select(type == "string" and length > 0)')" ]] || die "operator deploy manifest is missing runtime_config_secret_id"
fi

[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
if [[ "$using_runtime_material_ref" == "true" ]]; then
  if [[ "$dry_run" == "true" ]]; then
    jq -n \
      --arg operator_id "$operator_id" \
      '{
        operator_id: $operator_id,
        ready_for_deploy: false,
        checks: {
          inputs: {status: "skipped", detail: "dry run"},
          relayer_funding: {status: "skipped", detail: "dry run"},
          withdraw_config: {status: "skipped", detail: "dry run"},
          txsign_runtime: {status: "skipped", detail: "dry run"},
          systemd: {status: "skipped", detail: "dry run"},
          junocashd_sync: {status: "skipped", detail: "dry run"},
          deposit_relayer_ready: {status: "skipped", detail: "dry run"},
          kms_export: {status: "skipped", detail: "dry run"},
          scan_catchup: {status: "skipped", detail: "dry run"}
        }
      }'
    exit 0
  fi

  instance_id="$(production_resolve_instance_id_from_host "$aws_profile" "$aws_region" "$operator_host")"
  remote_stage_dir="/tmp/intents-juno-canary-$(production_safe_slug "$operator_id")"
  production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "sudo rm -rf '$remote_stage_dir' && sudo install -d -m 0755 '$remote_stage_dir'" >/dev/null \
    || die "failed to create remote canary stage dir over ssm: $remote_stage_dir"
  production_ssm_stage_file \
    "$aws_profile" "$aws_region" "$instance_id" \
    "$SCRIPT_DIR/run-operator-local-canary.sh" \
    "$remote_stage_dir/run-operator-local-canary.sh" \
    0755
  canary_json="$(production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "set -euo pipefail; cleanup(){ sudo rm -rf '$remote_stage_dir'; }; trap cleanup EXIT; sudo bash '$remote_stage_dir/run-operator-local-canary.sh' --operator-id '$operator_id'")" \
    || die "runtime canary failed over ssm for operator $operator_id"
  printf '%s\n' "$canary_json"
  exit 0
fi

dkg_backup_zip="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.dkg_backup_zip | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"
[[ -f "$dkg_backup_zip" ]] || die "dkg backup zip not found: $dkg_backup_zip"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"

input_status="passed"
input_detail="handoff inputs present"
relayer_funding_status="passed"
relayer_funding_detail="base relayer balance meets minimum"
withdraw_config_status="passed"
withdraw_config_detail="remote withdraw env is staged correctly"
txsign_runtime_status="passed"
txsign_runtime_detail="remote juno-txsign supports sign-digest"
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
junocashd_sync_poll_attempts="${PRODUCTION_OPERATOR_JUNO_SYNC_POLL_ATTEMPTS:-360}"
[[ "$junocashd_sync_poll_attempts" =~ ^[1-9][0-9]*$ ]] || die "PRODUCTION_OPERATOR_JUNO_SYNC_POLL_ATTEMPTS must be a positive integer"
junocashd_sync_poll_interval_seconds="${PRODUCTION_OPERATOR_JUNO_SYNC_POLL_INTERVAL_SECONDS:-10}"
[[ "$junocashd_sync_poll_interval_seconds" =~ ^[0-9]+$ ]] || die "PRODUCTION_OPERATOR_JUNO_SYNC_POLL_INTERVAL_SECONDS must be a non-negative integer"
scan_catchup_lag_blocks="${PRODUCTION_OPERATOR_SCAN_CATCHUP_LAG_BLOCKS:-1}"
[[ "$scan_catchup_lag_blocks" =~ ^[0-9]+$ ]] || die "PRODUCTION_OPERATOR_SCAN_CATCHUP_LAG_BLOCKS must be a non-negative integer"
scan_catchup_poll_attempts="${PRODUCTION_OPERATOR_SCAN_CATCHUP_POLL_ATTEMPTS:-180}"
[[ "$scan_catchup_poll_attempts" =~ ^[1-9][0-9]*$ ]] || die "PRODUCTION_OPERATOR_SCAN_CATCHUP_POLL_ATTEMPTS must be a positive integer"
scan_catchup_poll_interval_seconds="${PRODUCTION_OPERATOR_SCAN_CATCHUP_POLL_INTERVAL_SECONDS:-5}"
[[ "$scan_catchup_poll_interval_seconds" =~ ^[0-9]+$ ]] || die "PRODUCTION_OPERATOR_SCAN_CATCHUP_POLL_INTERVAL_SECONDS must be a non-negative integer"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi
base_rpc_url="$(production_json_required "$shared_manifest_path" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
checkpoint_threshold="$(jq -r '.checkpoint.threshold // empty' "$shared_manifest_path")"
production_is_positive_integer "$checkpoint_threshold" || die "shared manifest is missing positive checkpoint.threshold: $shared_manifest_path"
checkpoint_blob_bucket="$(production_json_optional "$operator_deploy" '.checkpoint_blob_bucket | select(type == "string" and length > 0)')"
if [[ -z "$checkpoint_blob_bucket" ]]; then
  checkpoint_blob_bucket="$(production_json_optional "$shared_manifest_path" '.shared_services.artifacts.checkpoint_blob_bucket | select(type == "string" and length > 0)')"
fi
checkpoint_signer_driver="$(production_json_optional "$operator_deploy" '.checkpoint_signer_driver')"
if [[ -z "$checkpoint_signer_driver" ]]; then
  checkpoint_signer_driver="aws-kms"
fi
minimum_base_relayer_balance_wei="$(production_required_min_base_relayer_balance_wei)"
tmp_dir="$(mktemp -d)"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

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

SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)

if [[ "$dry_run" == "true" ]]; then
  input_status="skipped"
  input_detail="dry run"
  relayer_funding_status="skipped"
  relayer_funding_detail="dry run"
  withdraw_config_status="skipped"
  withdraw_config_detail="dry run"
  txsign_runtime_status="skipped"
  txsign_runtime_detail="dry run"
  kms_export_status="skipped"
  kms_export_detail="dry run"
  systemd_status="skipped"
  systemd_detail="dry run"
  deposit_relayer_ready_status="skipped"
  deposit_relayer_ready_detail="dry run"
else
  production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_secret_env"

  set +e
  relayer_snapshot="$(production_base_relayer_balance_snapshot "$resolved_secret_env" "$base_rpc_url" 2>&1)"
  relayer_snapshot_status=$?
  set -e
  if [[ $relayer_snapshot_status -ne 0 ]]; then
    relayer_funding_status="failed"
    relayer_funding_detail="$(tail -n 1 <<<"$relayer_snapshot")"
    withdraw_config_status="blocked"
    withdraw_config_detail="blocked by relayer funding failure"
    txsign_runtime_status="blocked"
    txsign_runtime_detail="blocked by relayer funding failure"
    kms_export_status="blocked"
    kms_export_detail="blocked by relayer funding failure"
    systemd_status="blocked"
    systemd_detail="blocked by relayer funding failure"
    deposit_relayer_ready_status="blocked"
    deposit_relayer_ready_detail="blocked by relayer funding failure"
  else
    relayer_summary=""
    relayer_count=0
    while read -r relayer_address relayer_balance_wei; do
      [[ -n "${relayer_address:-}" ]] || continue
      relayer_count=$((relayer_count + 1))
      if [[ -n "$relayer_summary" ]]; then
        relayer_summary+=", "
      fi
      relayer_summary+="$relayer_address=$relayer_balance_wei"
      if (( relayer_balance_wei < minimum_base_relayer_balance_wei )); then
        relayer_funding_status="failed"
        relayer_funding_detail="base relayer $relayer_address balance $relayer_balance_wei wei is below minimum $minimum_base_relayer_balance_wei wei"
        withdraw_config_status="blocked"
        withdraw_config_detail="blocked by relayer funding failure"
        txsign_runtime_status="blocked"
        txsign_runtime_detail="blocked by relayer funding failure"
        kms_export_status="blocked"
        kms_export_detail="blocked by relayer funding failure"
        systemd_status="blocked"
        systemd_detail="blocked by relayer funding failure"
        deposit_relayer_ready_status="blocked"
        deposit_relayer_ready_detail="blocked by relayer funding failure"
        break
      fi
    done <<<"$relayer_snapshot"

    if (( relayer_count == 0 )); then
      relayer_funding_status="failed"
      relayer_funding_detail="no base relayer signer addresses resolved from BASE_RELAYER_PRIVATE_KEYS"
      withdraw_config_status="blocked"
      withdraw_config_detail="blocked by relayer funding failure"
      txsign_runtime_status="blocked"
      txsign_runtime_detail="blocked by relayer funding failure"
      kms_export_status="blocked"
      kms_export_detail="blocked by relayer funding failure"
      systemd_status="blocked"
      systemd_detail="blocked by relayer funding failure"
      deposit_relayer_ready_status="blocked"
      deposit_relayer_ready_detail="blocked by relayer funding failure"
    elif [[ "$relayer_funding_status" == "passed" ]]; then
      relayer_funding_detail="base relayer balances meet minimum $minimum_base_relayer_balance_wei wei: $relayer_summary"
      ssh_target="${operator_user}@${operator_host}"
      extend_signer_bin=""

      if ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240"
      elif [[ "$checkpoint_signer_driver" == "aws-kms" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^CHECKPOINT_SIGNER_DRIVER=aws-kms$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing CHECKPOINT_SIGNER_DRIVER=aws-kms"
      elif [[ "$checkpoint_signer_driver" == "aws-kms" ]] && ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY=' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env must not contain CHECKPOINT_SIGNER_PRIVATE_KEY"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h"
      else
        extend_signer_bin="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo awk -F= '/^WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/{print substr(\$0, index(\$0, \"=\") + 1); exit}' /etc/intents-juno/operator-stack.env" 2>/dev/null || true)"
        if [[ -z "$extend_signer_bin" ]]; then
          withdraw_config_status="failed"
          withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN"
        elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo test -x '$extend_signer_bin'" 2>/dev/null; then
          withdraw_config_status="failed"
          withdraw_config_detail="remote withdraw extend signer is not executable: $extend_signer_bin"
        fi
      fi
      if [[ "$withdraw_config_status" == "passed" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -qE '^JUNO_TXSIGN_SIGNER_KEYS=0x[0-9a-fA-F]{64}\$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env must contain exactly one operator-scoped JUNO_TXSIGN_SIGNER_KEYS entry"
      fi

      if [[ "$withdraw_config_status" == "passed" ]]; then
        txsign_help="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'set -euo pipefail; set -a; source /etc/intents-juno/operator-stack.env; set +a; $extend_signer_bin --help'" 2>/dev/null || true)"
        if [[ "$txsign_help" != *"sign-digest"* ]]; then
          txsign_runtime_status="failed"
          txsign_runtime_detail="remote extend signer is missing sign-digest support: $extend_signer_bin"
        else
          extend_signer_probe="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'set -euo pipefail; set -a; source /etc/intents-juno/operator-stack.env; set +a; $extend_signer_bin sign-digest --digest 0x1111111111111111111111111111111111111111111111111111111111111111 --json'" 2>/dev/null || true)"
          probe_status="$(jq -r '.status // empty' <<<"$extend_signer_probe" 2>/dev/null || true)"
          probe_sig_count="$(jq -r '
            if (.data.signatures // null) != null then
              (.data.signatures | length)
            elif ((.data.signature // "") | length) > 0 then
              1
            else
              0
            end
          ' <<<"$extend_signer_probe" 2>/dev/null || true)"
          if [[ "$probe_status" != "ok" ]]; then
            txsign_runtime_status="failed"
            txsign_runtime_detail="remote extend signer probe failed: ${probe_status:-invalid response}"
          elif ! [[ "$probe_sig_count" =~ ^[0-9]+$ ]]; then
            txsign_runtime_status="failed"
            txsign_runtime_detail="remote extend signer probe returned invalid signature count"
          elif (( probe_sig_count < 1 )); then
            txsign_runtime_status="failed"
            txsign_runtime_detail="remote extend signer returned $probe_sig_count signatures; need at least 1 operator-scoped signature"
          else
            txsign_runtime_detail="remote extend signer returned $probe_sig_count operator-scoped signature(s)"
          fi
        fi
      else
        txsign_runtime_status="blocked"
        txsign_runtime_detail="blocked by withdraw env validation failure"
      fi

      if [[ "$withdraw_config_status" == "passed" && "$txsign_runtime_status" == "passed" ]]; then
        if [[ -n "$checkpoint_blob_bucket" && "$checkpoint_signer_driver" == "aws-kms" ]]; then
          if ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo test -e $runtime_dir/exports/kms-export-receipt.json" 2>/dev/null; then
            kms_export_status="failed"
            kms_export_detail="remote kms export receipt is missing: $runtime_dir/exports/kms-export-receipt.json"
          else
            kms_export_status="passed"
            kms_export_detail="remote kms export receipt present"
          fi
        else
          kms_export_status="failed"
          kms_export_detail="checkpoint signer kms export requires checkpoint_blob_bucket for aws-kms mode"
        fi
      else
        kms_export_status="blocked"
        kms_export_detail="blocked by withdraw config validation failure"
      fi

      if [[ "$withdraw_config_status" == "passed" && "$txsign_runtime_status" == "passed" && ( "$kms_export_status" == "passed" || "$kms_export_status" == "skipped" ) ]]; then
        for svc in "${services[@]}"; do
          svc_status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
          if [[ "$svc_status" != "active" ]]; then
            systemd_status="failed"
            systemd_detail="service inactive: $svc"
            break
          fi
        done
      else
        systemd_status="blocked"
        if [[ "$kms_export_status" != "passed" && "$kms_export_status" != "skipped" ]]; then
          systemd_detail="blocked by kms export validation failure"
        else
          systemd_detail="blocked by withdraw config validation failure"
        fi
      fi

      if [[ "$systemd_status" == "passed" ]]; then
        junocashd_sync_status="failed"
        for ((sync_attempt=1; sync_attempt<=junocashd_sync_poll_attempts; sync_attempt++)); do
          blockchain_info="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'set -euo pipefail; set -a; source /etc/intents-juno/operator-stack.env; set +a; /usr/local/bin/junocash-cli -testnet -rpcconnect=127.0.0.1 -rpcport=18232 -rpcuser=\"\$JUNO_RPC_USER\" -rpcpassword=\"\$JUNO_RPC_PASS\" getblockchaininfo'" 2>/dev/null || true)"
          node_blocks="$(jq -r '.blocks // empty' <<<"$blockchain_info" 2>/dev/null || true)"
          node_headers="$(jq -r '.headers // empty' <<<"$blockchain_info" 2>/dev/null || true)"
          node_progress="$(jq -r '.verificationprogress // empty' <<<"$blockchain_info" 2>/dev/null || true)"
          node_ibd_complete="$(jq -r '.initial_block_download_complete // empty' <<<"$blockchain_info" 2>/dev/null || true)"

          if ! [[ "$node_blocks" =~ ^[0-9]+$ ]] || ! [[ "$node_headers" =~ ^[0-9]+$ ]]; then
            junocashd_sync_detail="junocashd getblockchaininfo did not report numeric blocks/headers on $operator_host"
          elif [[ "$node_ibd_complete" == "true" ]]; then
            junocashd_sync_status="passed"
            junocashd_sync_detail="junocashd blocks $node_blocks reached headers $node_headers on $operator_host"
            break
          elif awk -v p="${node_progress:-0}" 'BEGIN { exit (p >= 0.999 ? 0 : 1) }' && (( node_headers > 0 && node_blocks + 1 >= node_headers )); then
            junocashd_sync_status="passed"
            junocashd_sync_detail="junocashd blocks $node_blocks reached headers $node_headers on $operator_host"
            break
          else
            junocashd_sync_detail="junocashd blocks $node_blocks remain behind headers $node_headers on $operator_host"
          fi

          if (( sync_attempt < junocashd_sync_poll_attempts )); then
            sleep "$junocashd_sync_poll_interval_seconds"
          fi
        done

        if [[ "$junocashd_sync_status" != "passed" ]]; then
          scan_catchup_status="blocked"
          scan_catchup_detail="blocked by junocashd sync failure"
          deposit_relayer_ready_status="blocked"
          deposit_relayer_ready_detail="blocked by junocashd sync failure"
        else
          scan_catchup_status="failed"
          for ((scan_attempt=1; scan_attempt<=scan_catchup_poll_attempts; scan_attempt++)); do
            scan_status_response="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo curl -fsS http://127.0.0.1:8080/v1/health" 2>/dev/null || true)"
            scan_tip_height="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'set -euo pipefail; set -a; source /etc/intents-juno/operator-stack.env; set +a; /usr/local/bin/junocash-cli -testnet -rpcconnect=127.0.0.1 -rpcport=18232 -rpcuser=\"\$JUNO_RPC_USER\" -rpcpassword=\"\$JUNO_RPC_PASS\" getblockcount'" 2>/dev/null || true)"
            scan_tip_height="$(tr -d '[:space:]' <<<"$scan_tip_height")"
            scan_tip_valid="false"
            if [[ "$scan_tip_height" =~ ^[0-9]+$ ]]; then
              scan_tip_valid="true"
            fi
            scan_scanned_height="$(jq -r '.scanned_height // empty' <<<"$scan_status_response" 2>/dev/null || true)"
            if [[ "$scan_status_response" != *'"status":"ok"'* && "$scan_status_response" != *'"status": "ok"'* ]]; then
              scan_catchup_detail="juno-scan health check failed on $operator_host"
            elif ! [[ "$scan_scanned_height" =~ ^[0-9]+$ ]]; then
              scan_catchup_detail="juno-scan health did not report a numeric scanned_height on $operator_host"
            elif [[ "$scan_tip_valid" != "true" ]]; then
              scan_catchup_detail="junocashd getblockcount did not return a numeric tip on $operator_host"
            elif (( scan_scanned_height + scan_catchup_lag_blocks < scan_tip_height )); then
              scan_catchup_detail="juno-scan scanned_height $scan_scanned_height is behind local tip $scan_tip_height by more than $scan_catchup_lag_blocks block(s)"
            else
              scan_catchup_status="passed"
              scan_catchup_detail="juno-scan scanned_height $scan_scanned_height is within $scan_catchup_lag_blocks block(s) of local tip $scan_tip_height"
              break
            fi

            if (( scan_attempt < scan_catchup_poll_attempts )); then
              sleep "$scan_catchup_poll_interval_seconds"
            fi
          done

          if [[ "$scan_catchup_status" != "passed" ]]; then
            deposit_relayer_ready_status="blocked"
            deposit_relayer_ready_detail="blocked by juno-scan catch-up failure"
          fi

          if [[ "$scan_catchup_status" == "passed" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'source /etc/intents-juno/operator-stack.env && curl -fsS http://127.0.0.1:\${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz >/dev/null'" 2>/dev/null; then
            deposit_relayer_ready_status="failed"
            deposit_relayer_ready_detail="deposit-relayer /readyz failed"
          fi
        fi
      else
        junocashd_sync_status="blocked"
        junocashd_sync_detail="blocked by service validation failure"
        scan_catchup_status="blocked"
        scan_catchup_detail="blocked by service validation failure"
        deposit_relayer_ready_status="blocked"
        deposit_relayer_ready_detail="blocked by service validation failure"
      fi
    fi
  fi
fi

ready_for_deploy="true"
for status in "$input_status" "$relayer_funding_status" "$withdraw_config_status" "$txsign_runtime_status" "$kms_export_status" "$systemd_status" "$junocashd_sync_status" "$scan_catchup_status" "$deposit_relayer_ready_status"; do
  if [[ "$status" != "passed" && "$status" != "skipped" ]]; then
    ready_for_deploy="false"
  fi
done
if [[ "$dry_run" == "true" ]]; then
  ready_for_deploy="false"
fi

jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg operator_id "$operator_id" \
  --arg operator_host "$operator_host" \
  --arg runtime_dir "$runtime_dir" \
  --arg input_status "$input_status" \
  --arg input_detail "$input_detail" \
  --arg relayer_funding_status "$relayer_funding_status" \
  --arg relayer_funding_detail "$relayer_funding_detail" \
  --arg withdraw_config_status "$withdraw_config_status" \
  --arg withdraw_config_detail "$withdraw_config_detail" \
  --arg txsign_runtime_status "$txsign_runtime_status" \
  --arg txsign_runtime_detail "$txsign_runtime_detail" \
  --arg kms_export_status "$kms_export_status" \
  --arg kms_export_detail "$kms_export_detail" \
  --arg systemd_status "$systemd_status" \
  --arg systemd_detail "$systemd_detail" \
  --arg junocashd_sync_status "$junocashd_sync_status" \
  --arg junocashd_sync_detail "$junocashd_sync_detail" \
  --arg scan_catchup_status "$scan_catchup_status" \
  --arg scan_catchup_detail "$scan_catchup_detail" \
  --arg deposit_relayer_ready_status "$deposit_relayer_ready_status" \
  --arg deposit_relayer_ready_detail "$deposit_relayer_ready_detail" \
  --argjson ready_for_deploy "$ready_for_deploy" \
  '{
    version: $version,
    generated_at: $generated_at,
    operator_id: $operator_id,
    operator_host: $operator_host,
    runtime_dir: $runtime_dir,
    ready_for_deploy: $ready_for_deploy,
    checks: {
      inputs: {
        status: $input_status,
        detail: $input_detail
      },
      relayer_funding: {
        status: $relayer_funding_status,
        detail: $relayer_funding_detail
      },
      withdraw_config: {
        status: $withdraw_config_status,
        detail: $withdraw_config_detail
      },
      txsign_runtime: {
        status: $txsign_runtime_status,
        detail: $txsign_runtime_detail
      },
      kms_export: {
        status: $kms_export_status,
        detail: $kms_export_detail
      },
      junocashd_sync: {
        status: $junocashd_sync_status,
        detail: $junocashd_sync_detail
      },
      scan_catchup: {
        status: $scan_catchup_status,
        detail: $scan_catchup_detail
      },
      systemd: {
        status: $systemd_status,
        detail: $systemd_detail
      },
      deposit_relayer_ready: {
        status: $deposit_relayer_ready_status,
        detail: $deposit_relayer_ready_detail
      }
    }
  }'
