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
  have_cmd ssh || die "required command not found: ssh"
fi

manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
operator_id="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
operator_user="$(production_json_required "$operator_deploy" '.operator_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$operator_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
dkg_backup_zip="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.dkg_backup_zip | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"

[[ -f "$dkg_backup_zip" ]] || die "dkg backup zip not found: $dkg_backup_zip"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"

input_status="passed"
input_detail="handoff inputs present"
systemd_status="passed"
systemd_detail="all operator services active"

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
  systemd_status="skipped"
  systemd_detail="dry run"
else
  ssh_target="${operator_user}@${operator_host}"
  for svc in "${services[@]}"; do
    svc_status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
    if [[ "$svc_status" != "active" ]]; then
      systemd_status="failed"
      systemd_detail="service inactive: $svc"
      break
    fi
  done
fi

ready_for_deploy="true"
for status in "$input_status" "$systemd_status"; do
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
  --arg systemd_status "$systemd_status" \
  --arg systemd_detail "$systemd_detail" \
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
      systemd: {
        status: $systemd_status,
        detail: $systemd_detail
      }
    }
  }'
