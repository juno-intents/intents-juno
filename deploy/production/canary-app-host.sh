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
  for cmd in ssh curl; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"
app_host="$(production_json_required "$app_deploy" '.app_host | select(type == "string" and length > 0)')"
app_user="$(production_json_required "$app_deploy" '.app_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$app_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
bridge_probe_url="$(production_json_required "$app_deploy" '.services.bridge_api.public_url | select(type == "string" and length > 0)')"
backoffice_probe_url="$(production_json_required "$app_deploy" '.services.backoffice.public_url | select(type == "string" and length > 0)')"

[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"

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

SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)

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
else
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
  if [[ -z "$bridge_config_json" ]] || ! jq -e '.bridgeAddress | select(type == "string" and length > 0)' >/dev/null <<<"$bridge_config_json" || ! jq -e '.oWalletUA | select(type == "string" and length > 0)' >/dev/null <<<"$bridge_config_json"; then
    bridge_config_status="failed"
    bridge_config_detail="bridge-api /v1/config missing bridgeAddress or oWalletUA"
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
fi

ready_for_test="true"
for status in \
  "$input_status" \
  "$systemd_status" \
  "$bridge_ready_status" \
  "$bridge_config_status" \
  "$bridge_frontend_status" \
  "$backoffice_ready_status" \
  "$backoffice_ui_status"; do
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
      }
    }
  }'
