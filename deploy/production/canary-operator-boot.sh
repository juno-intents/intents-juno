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
  - Remote withdraw env points at juno-txsign and includes signer keys
  - Remote juno-txsign runtime supports sign-digest
  - Remote KMS export receipt exists when checkpoint blob export is configured
  - Remote operator services are active over strict-host-key SSH

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
if [[ "$dry_run" != "true" ]]; then
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
dkg_backup_zip="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.dkg_backup_zip | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"

[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
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
deposit_relayer_ready_status="passed"
deposit_relayer_ready_detail="deposit-relayer /readyz passed"
kms_export_status="skipped"
kms_export_detail="no checkpoint blob bucket configured"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi
base_rpc_url="$(production_json_required "$shared_manifest_path" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
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

      if ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000"
      elif [[ "$checkpoint_signer_driver" == "aws-kms" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^CHECKPOINT_SIGNER_DRIVER=aws-kms$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing CHECKPOINT_SIGNER_DRIVER=aws-kms"
      elif [[ "$checkpoint_signer_driver" == "aws-kms" ]] && ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY=' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env must not contain CHECKPOINT_SIGNER_PRIVATE_KEY"
      elif [[ "$checkpoint_signer_driver" == "local-env" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^CHECKPOINT_SIGNER_DRIVER=local-env$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing CHECKPOINT_SIGNER_DRIVER=local-env"
      elif [[ "$checkpoint_signer_driver" == "local-env" ]] && ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -qE '^CHECKPOINT_SIGNER_PRIVATE_KEY=0x[0-9a-fA-F]{64}$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env must contain an operator-scoped CHECKPOINT_SIGNER_PRIVATE_KEY"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is missing WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -q '^WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=$runtime_dir/bin/juno-txsign$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env is not pointing withdraw coordinator at $runtime_dir/bin/juno-txsign"
      elif ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo grep -qE '^JUNO_TXSIGN_SIGNER_KEYS=0x[0-9a-fA-F]{64}$' /etc/intents-juno/operator-stack.env" 2>/dev/null; then
        withdraw_config_status="failed"
        withdraw_config_detail="remote operator env must contain exactly one operator-scoped JUNO_TXSIGN_SIGNER_KEYS entry"
      fi

      if [[ "$withdraw_config_status" == "passed" ]]; then
        txsign_help="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo $runtime_dir/bin/juno-txsign --help" 2>/dev/null || true)"
        if [[ "$txsign_help" != *"sign-digest"* ]]; then
          txsign_runtime_status="failed"
          txsign_runtime_detail="remote juno-txsign is missing sign-digest support"
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
        elif [[ "$checkpoint_signer_driver" == "local-env" ]]; then
          kms_export_status="skipped"
          kms_export_detail="preview local checkpoint signer mode does not export to kms"
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
        if ! ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo bash -lc 'source /etc/intents-juno/operator-stack.env && curl -fsS http://127.0.0.1:\${DEPOSIT_RELAYER_HEALTH_PORT:-18303}/readyz >/dev/null'" 2>/dev/null; then
          deposit_relayer_ready_status="failed"
          deposit_relayer_ready_detail="deposit-relayer /readyz failed"
        fi
      else
        deposit_relayer_ready_status="blocked"
        deposit_relayer_ready_detail="blocked by service validation failure"
      fi
    fi
  fi
fi

ready_for_deploy="true"
for status in "$input_status" "$relayer_funding_status" "$withdraw_config_status" "$txsign_runtime_status" "$kms_export_status" "$systemd_status" "$deposit_relayer_ready_status"; do
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
