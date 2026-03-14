#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-app-host.sh --app-deploy <path> [--dry-run]

Checks:
  - Required handoff inputs exist locally
  - Remote bridge-api/backoffice services are active over strict-host-key SSH
  - Public bridge-api and backoffice HTTP probes succeed

Output:
  JSON summary to stdout suitable for tester handoff
EOF
}

app_deploy=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-deploy)
      app_deploy="$2"
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

[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy manifest not found: $app_deploy"
for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  for cmd in ssh curl cast; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
[[ "$environment" == "alpha" ]] && allow_local_resolvers="true"
shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"
app_host="$(production_json_required "$app_deploy" '.app_host | select(type == "string" and length > 0)')"
app_user="$(production_json_required "$app_deploy" '.app_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$app_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
aws_profile="$(production_json_optional "$app_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$app_deploy" '.aws_region')"
public_scheme="$(production_json_required "$app_deploy" '.public_scheme | select(type == "string" and length > 0)')"
bridge_probe_url="$(production_json_required "$app_deploy" '.services.bridge_api.public_url | select(type == "string" and length > 0)')"
backoffice_probe_url="$(production_json_required "$app_deploy" '.services.backoffice.public_url | select(type == "string" and length > 0)')"
base_rpc_url="$(production_json_required "$shared_manifest_path" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
bridge_address="$(production_json_required "$shared_manifest_path" '.contracts.bridge | select(type == "string" and length > 0)')"

[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"
[[ "$public_scheme" == "https" ]] || die "app deploy manifest must use public_scheme=https"
[[ "$bridge_probe_url" == https://* ]] || die "bridge probe url must use https: $bridge_probe_url"
[[ "$backoffice_probe_url" == https://* ]] || die "backoffice probe url must use https: $backoffice_probe_url"

input_status="passed"
input_detail="handoff inputs present"
systemd_status="passed"
systemd_detail="bridge-api and backoffice active"
bridge_ready_status="passed"
bridge_ready_detail="bridge-api /readyz passed"
bridge_config_status="passed"
bridge_config_detail="bridge-api /v1/config passed"
bridge_frontend_status="passed"
bridge_frontend_detail="bridge frontend HTML served"
backoffice_ready_status="passed"
backoffice_ready_detail="backoffice /readyz passed"
backoffice_ui_status="passed"
backoffice_ui_detail="backoffice HTML served"
backoffice_settings_status="passed"
backoffice_settings_detail="backoffice runtime settings API passed"
min_deposit_admin_status="passed"
min_deposit_admin_detail="configured signer matches on-chain minDepositAdmin"

SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
tmp_dir="$(mktemp -d)"
resolved_env="$tmp_dir/app-secrets.resolved.env"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ "$dry_run" == "true" ]]; then
  input_status="skipped"
  input_detail="dry run"
  systemd_status="skipped"
  systemd_detail="dry run"
  bridge_ready_status="skipped"
  bridge_ready_detail="dry run"
  bridge_config_status="skipped"
  bridge_config_detail="dry run"
  bridge_frontend_status="skipped"
  bridge_frontend_detail="dry run"
  backoffice_ready_status="skipped"
  backoffice_ready_detail="dry run"
  backoffice_ui_status="skipped"
  backoffice_ui_detail="dry run"
  backoffice_settings_status="skipped"
  backoffice_settings_detail="dry run"
  min_deposit_admin_status="skipped"
  min_deposit_admin_detail="dry run"
else
  production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
  ssh_target="${app_user}@${app_host}"
  for svc in bridge-api backoffice; do
    svc_status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
    if [[ "$svc_status" != "active" ]]; then
      systemd_status="failed"
      systemd_detail="service inactive: $svc"
      break
    fi
  done

  if ! curl -fsS "${bridge_probe_url}/readyz" >/dev/null; then
    bridge_ready_status="failed"
    bridge_ready_detail="bridge-api /readyz failed"
  fi

  bridge_config_json="$(curl -fsS "${bridge_probe_url}/v1/config" 2>/dev/null || true)"
  if [[ -z "$bridge_config_json" ]] \
    || ! jq -e '.bridgeAddress | select(type == "string" and length > 0)' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.oWalletUA | select(type == "string" and length > 0)' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.minDepositAmount | select(type == "string" and test("^[0-9]+$"))' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.depositMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$bridge_config_json"; then
    bridge_config_status="failed"
    bridge_config_detail="bridge-api /v1/config missing bridgeAddress, oWalletUA, minDepositAmount, or depositMinConfirmations"
  fi

  bridge_html="$(curl -fsS "${bridge_probe_url}/" 2>/dev/null || true)"
  if [[ "$bridge_html" != *"<html"* && "$bridge_html" != *"<!doctype html"* ]]; then
    bridge_frontend_status="failed"
    bridge_frontend_detail="bridge frontend did not return HTML"
  fi

  if ! curl -fsS "${backoffice_probe_url}/readyz" >/dev/null; then
    backoffice_ready_status="failed"
    backoffice_ready_detail="backoffice /readyz failed"
  fi

  backoffice_html="$(curl -fsS "${backoffice_probe_url}/" 2>/dev/null || true)"
  if [[ "$backoffice_html" != *"JUNO BACKOFFICE"* ]]; then
    backoffice_ui_status="failed"
    backoffice_ui_detail="backoffice UI did not return expected marker"
  fi

  auth_secret="$(production_env_first_value "$resolved_env" BACKOFFICE_AUTH_SECRET APP_BACKOFFICE_AUTH_SECRET || true)"
  min_deposit_admin_private_key="$(production_env_first_value "$resolved_env" MIN_DEPOSIT_ADMIN_PRIVATE_KEY APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY || true)"
  if [[ -z "$min_deposit_admin_private_key" ]]; then
    min_deposit_admin_status="failed"
    min_deposit_admin_detail="secret contract is missing MIN_DEPOSIT_ADMIN_PRIVATE_KEY or APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY"
  else
    signer_address="$(cast wallet address --private-key "$min_deposit_admin_private_key" | tr -d '[:space:]')"
    onchain_min_deposit_admin="$(cast call --rpc-url "$base_rpc_url" "$bridge_address" "minDepositAdmin()(address)" 2>/dev/null | tr -d '[:space:]')"
    if [[ "${signer_address,,}" != "${onchain_min_deposit_admin,,}" ]]; then
      min_deposit_admin_status="failed"
      min_deposit_admin_detail="configured signer ${signer_address} does not match on-chain minDepositAdmin ${onchain_min_deposit_admin}"
    fi
  fi

  if [[ "$backoffice_ready_status" == "passed" && -n "${auth_secret:-}" ]]; then
    backoffice_settings_json="$(curl -fsS -H "Authorization: Bearer ${auth_secret}" "${backoffice_probe_url}/api/settings/runtime" 2>/dev/null || true)"
    if [[ -z "$backoffice_settings_json" ]] \
      || ! jq -e '.data.minDepositAmount | select(type == "string" and test("^[0-9]+$"))' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.minDepositAdmin | select(type == "string" and length > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.depositMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.withdrawPlannerMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.withdrawBatchConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json"; then
      backoffice_settings_status="failed"
      backoffice_settings_detail="backoffice runtime settings API missing minDeposit or confirmation fields"
    fi
  elif [[ -z "${auth_secret:-}" ]]; then
    backoffice_settings_status="failed"
    backoffice_settings_detail="secret contract is missing BACKOFFICE_AUTH_SECRET or APP_BACKOFFICE_AUTH_SECRET"
  else
    backoffice_settings_status="blocked"
    backoffice_settings_detail="blocked by backoffice readiness failure"
  fi
fi

ready_for_test="true"
for status in \
  "$input_status" \
  "$systemd_status" \
  "$bridge_ready_status" \
  "$bridge_config_status" \
  "$bridge_frontend_status" \
  "$backoffice_ready_status" \
  "$backoffice_ui_status" \
  "$backoffice_settings_status" \
  "$min_deposit_admin_status"; do
  if [[ "$status" != "passed" && "$status" != "skipped" ]]; then
    ready_for_test="false"
  fi
done
if [[ "$dry_run" == "true" ]]; then
  ready_for_test="false"
fi

jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg app_host "$app_host" \
  --arg runtime_dir "$runtime_dir" \
  --arg bridge_probe_url "$bridge_probe_url" \
  --arg backoffice_probe_url "$backoffice_probe_url" \
  --arg input_status "$input_status" \
  --arg input_detail "$input_detail" \
  --arg systemd_status "$systemd_status" \
  --arg systemd_detail "$systemd_detail" \
  --arg bridge_ready_status "$bridge_ready_status" \
  --arg bridge_ready_detail "$bridge_ready_detail" \
  --arg bridge_config_status "$bridge_config_status" \
  --arg bridge_config_detail "$bridge_config_detail" \
  --arg bridge_frontend_status "$bridge_frontend_status" \
  --arg bridge_frontend_detail "$bridge_frontend_detail" \
  --arg backoffice_ready_status "$backoffice_ready_status" \
  --arg backoffice_ready_detail "$backoffice_ready_detail" \
  --arg backoffice_ui_status "$backoffice_ui_status" \
  --arg backoffice_ui_detail "$backoffice_ui_detail" \
  --arg backoffice_settings_status "$backoffice_settings_status" \
  --arg backoffice_settings_detail "$backoffice_settings_detail" \
  --arg min_deposit_admin_status "$min_deposit_admin_status" \
  --arg min_deposit_admin_detail "$min_deposit_admin_detail" \
  --argjson ready_for_test "$ready_for_test" \
  '{
    version: $version,
    generated_at: $generated_at,
    app_host: $app_host,
    runtime_dir: $runtime_dir,
    bridge_probe_url: $bridge_probe_url,
    backoffice_probe_url: $backoffice_probe_url,
    ready_for_test: $ready_for_test,
    checks: {
      inputs: {
        status: $input_status,
        detail: $input_detail
      },
      systemd: {
        status: $systemd_status,
        detail: $systemd_detail
      },
      bridge_ready: {
        status: $bridge_ready_status,
        detail: $bridge_ready_detail
      },
      bridge_config: {
        status: $bridge_config_status,
        detail: $bridge_config_detail
      },
      bridge_frontend: {
        status: $bridge_frontend_status,
        detail: $bridge_frontend_detail
      },
      backoffice_ready: {
        status: $backoffice_ready_status,
        detail: $backoffice_ready_detail
      },
      backoffice_ui: {
        status: $backoffice_ui_status,
        detail: $backoffice_ui_detail
      },
      backoffice_settings: {
        status: $backoffice_settings_status,
        detail: $backoffice_settings_detail
      },
      min_deposit_admin: {
        status: $min_deposit_admin_status,
        detail: $min_deposit_admin_detail
      }
    }
  }'
