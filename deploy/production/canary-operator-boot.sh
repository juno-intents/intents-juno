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
  - Required runtime material refs exist in the operator handoff
  - Host-local operator runtime canary passes over SSM

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

production_operator_uses_runtime_material_ref "$operator_deploy" \
  || die "operator deploy manifest must set runtime_material_ref.mode=s3-kms-zip"

operator_id="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
aws_profile="$(production_json_required "$operator_deploy" '.aws_profile | select(type == "string" and length > 0)')"
aws_region="$(production_json_required "$operator_deploy" '.aws_region | select(type == "string" and length > 0)')"

[[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'bucket')" ]] || die "operator deploy manifest is missing runtime_material_ref.bucket"
[[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'key')" ]] || die "operator deploy manifest is missing runtime_material_ref.key"
[[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'region')" ]] || die "operator deploy manifest is missing runtime_material_ref.region"
[[ -n "$(production_runtime_material_ref_field "$operator_deploy" 'kms_key_id')" ]] || die "operator deploy manifest is missing runtime_material_ref.kms_key_id"
[[ -n "$(production_json_required "$operator_deploy" '.runtime_config_secret_id | select(type == "string" and length > 0)')" ]] || die "operator deploy manifest is missing runtime_config_secret_id"

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

have_cmd aws || die "required command not found: aws"

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

canary_json="$(
  production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "sudo bash -lc 'set -euo pipefail; cleanup(){ rm -rf \"$remote_stage_dir\"; }; trap cleanup EXIT; bash \"$remote_stage_dir/run-operator-local-canary.sh\" --operator-id \"$operator_id\"'"
)" || die "runtime canary failed over ssm for operator $operator_id"

printf '%s\n' "$canary_json"
