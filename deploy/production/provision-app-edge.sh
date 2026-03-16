#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  provision-app-edge.sh --app-deploy PATH [--dry-run]

Creates or updates the CloudFront/WAF front door for an app host handoff.
EOF
}

app_deploy=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy manifest not found: $app_deploy"

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  for cmd in terraform; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

edge_enabled="$(production_json_optional "$app_deploy" '.edge.enabled')"
if [[ "$edge_enabled" != "true" ]]; then
  log "app edge disabled; skipping"
  exit 0
fi

manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
aws_profile="$(production_json_optional "$app_deploy" '.aws_profile')"
aws_region="$(production_json_required "$app_deploy" '.aws_region | select(type == "string" and length > 0)')"
zone_id="$(production_json_required "$app_deploy" '.dns.zone_id | select(type == "string" and length > 0)')"
bridge_record_name="$(production_json_required "$app_deploy" '.services.bridge_api.record_name | select(type == "string" and length > 0)')"
backoffice_record_name="$(production_json_required "$app_deploy" '.services.backoffice.record_name | select(type == "string" and length > 0)')"
origin_record_name="$(production_json_required "$app_deploy" '.edge.origin_record_name | select(type == "string" and length > 0)')"
origin_endpoint="$(production_json_required "$app_deploy" '.edge.origin_endpoint | select(type == "string" and length > 0)')"
origin_http_port="$(production_json_required "$app_deploy" '.edge.origin_http_port')"
rate_limit="$(production_json_required "$app_deploy" '.edge.rate_limit')"
state_path="$(production_json_required "$app_deploy" '.edge.state_path | select(type == "string" and length > 0)')"
security_group_id="$(production_json_optional "$app_deploy" '.security_group_id')"
enable_shield_advanced="$(production_json_optional "$app_deploy" '.edge.enable_shield_advanced')"

state_path="$(production_abs_path "$manifest_dir" "$state_path")"
mkdir -p "$(dirname "$state_path")"

[[ "$origin_http_port" =~ ^[0-9]+$ ]] || die "edge.origin_http_port must be numeric"
[[ "$rate_limit" =~ ^[0-9]+$ ]] || die "edge.rate_limit must be numeric"
if [[ "$enable_shield_advanced" != "true" ]]; then
  enable_shield_advanced="false"
fi

work_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

cp -R "$REPO_ROOT/deploy/shared/terraform/app-edge/." "$work_dir/"

cat >"$work_dir/terraform.tfvars.json" <<EOF
{
  "aws_region": $(jq -Rn --arg v "$aws_region" '$v'),
  "deployment_id": $(jq -Rn --arg v "$environment" '$v'),
  "zone_id": $(jq -Rn --arg v "$zone_id" '$v'),
  "bridge_record_name": $(jq -Rn --arg v "$bridge_record_name" '$v'),
  "backoffice_record_name": $(jq -Rn --arg v "$backoffice_record_name" '$v'),
  "origin_record_name": $(jq -Rn --arg v "$origin_record_name" '$v'),
  "origin_endpoint": $(jq -Rn --arg v "$origin_endpoint" '$v'),
  "origin_http_port": $origin_http_port,
  "security_group_id": $(jq -Rn --arg v "$security_group_id" '$v'),
  "rate_limit": $rate_limit,
  "enable_shield_advanced": $enable_shield_advanced
}
EOF

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would provision app edge for $bridge_record_name and $backoffice_record_name"
  exit 0
fi

TF_IN_AUTOMATION=1 \
AWS_PROFILE="${aws_profile:-}" \
terraform -chdir="$work_dir" init -input=false >/dev/null
TF_IN_AUTOMATION=1 \
AWS_PROFILE="${aws_profile:-}" \
terraform -chdir="$work_dir" apply -input=false -auto-approve -state="$state_path" -var-file="$work_dir/terraform.tfvars.json" >/dev/null

log "app edge provisioned: $bridge_record_name, $backoffice_record_name"
