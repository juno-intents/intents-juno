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

Creates or updates the CloudFront/WAF front door for a role-backed app handoff.
EOF
}

app_edge_resource_slug() {
  local deployment_id="$1"
  local resource_slug

  resource_slug="juno-app-edge-${deployment_id}"
  resource_slug="${resource_slug//_/-}"
  resource_slug="$(printf '%s' "$resource_slug" | tr '[:upper:]' '[:lower:]')"
  resource_slug="${resource_slug#-}"
  resource_slug="${resource_slug%-}"
  printf '%s\n' "$resource_slug"
}

app_edge_state_has_resource() {
  local work_dir="$1"
  local state_path="$2"
  local aws_profile="$3"
  local resource_address="$4"

  TF_IN_AUTOMATION=1 \
  AWS_PROFILE="${aws_profile:-}" \
  terraform -chdir="$work_dir" state list -state="$state_path" 2>/dev/null \
    | grep -Fxq "$resource_address"
}

app_edge_import_existing_waf() {
  local work_dir="$1"
  local state_path="$2"
  local aws_profile="$3"
  local deployment_id="$4"
  local waf_name existing_waf id name

  app_edge_state_has_resource "$work_dir" "$state_path" "$aws_profile" "aws_wafv2_web_acl.app" && return 0
  have_cmd aws || return 0

  waf_name="$(app_edge_resource_slug "$deployment_id")-waf"
  existing_waf="$(
    AWS_PAGER="" \
    AWS_PROFILE="${aws_profile:-}" \
    aws --region us-east-1 wafv2 list-web-acls --scope CLOUDFRONT --output json \
      | jq -r --arg name "$waf_name" '
          .WebACLs[]?
          | select(.Name == $name)
          | [.Id, .Name]
          | @tsv
        ' \
      | head -n1
  )"
  [[ -n "$existing_waf" ]] || return 0

  id="${existing_waf%%$'\t'*}"
  name="${existing_waf#*$'\t'}"
  log "importing existing app edge WAF into state: $name"
  TF_IN_AUTOMATION=1 \
  AWS_PROFILE="${aws_profile:-}" \
  terraform -chdir="$work_dir" import -input=false -state="$state_path" -var-file="$work_dir/terraform.tfvars.json" \
    aws_wafv2_web_acl.app "$id/$name/CLOUDFRONT" >/dev/null
}

app_edge_import_existing_distribution() {
  local work_dir="$1"
  local state_path="$2"
  local aws_profile="$3"
  local bridge_record_name="$4"
  local distribution_id

  app_edge_state_has_resource "$work_dir" "$state_path" "$aws_profile" "aws_cloudfront_distribution.bridge" && return 0
  have_cmd aws || return 0

  distribution_id="$(
    AWS_PAGER="" \
    AWS_PROFILE="${aws_profile:-}" \
    aws cloudfront list-distributions --output json \
      | jq -r --arg bridge_record_name "$bridge_record_name" '
          .DistributionList.Items[]?
          | select((.Aliases.Items // []) | index($bridge_record_name))
          | .Id
        ' \
      | head -n1
  )"
  [[ -n "$distribution_id" ]] || return 0

  log "importing existing app edge distribution into state: $distribution_id"
  TF_IN_AUTOMATION=1 \
  AWS_PROFILE="${aws_profile:-}" \
  terraform -chdir="$work_dir" import -input=false -state="$state_path" -var-file="$work_dir/terraform.tfvars.json" \
    aws_cloudfront_distribution.bridge "$distribution_id" >/dev/null
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
origin_record_name="$(production_json_required "$app_deploy" '.edge.origin_record_name | select(type == "string" and length > 0)')"
public_lb_dns_name="$(production_json_required "$app_deploy" '.edge.public_lb_dns_name | select(type == "string" and length > 0)')"
origin_http_port="$(production_json_required "$app_deploy" '.edge.origin_http_port')"
rate_limit="$(production_json_required "$app_deploy" '.edge.rate_limit')"
if ! jq -e '.edge.alarm_actions | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)' "$app_deploy" >/dev/null 2>&1; then
  die "edge.alarm_actions must be a non-empty array"
fi
alarm_actions_json="$(jq -c '.edge.alarm_actions' "$app_deploy")"
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
  "origin_record_name": $(jq -Rn --arg v "$origin_record_name" '$v'),
  "public_lb_dns_name": $(jq -Rn --arg v "$public_lb_dns_name" '$v'),
  "origin_http_port": $origin_http_port,
  "security_group_id": $(jq -Rn --arg v "$security_group_id" '$v'),
  "rate_limit": $rate_limit,
  "alarm_actions": $alarm_actions_json,
  "enable_shield_advanced": $enable_shield_advanced
}
EOF

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would provision app edge for $bridge_record_name"
  exit 0
fi

TF_IN_AUTOMATION=1 \
AWS_PROFILE="${aws_profile:-}" \
terraform -chdir="$work_dir" init -input=false >/dev/null
app_edge_import_existing_waf "$work_dir" "$state_path" "${aws_profile:-}" "$environment"
app_edge_import_existing_distribution "$work_dir" "$state_path" "${aws_profile:-}" "$bridge_record_name"
TF_IN_AUTOMATION=1 \
AWS_PROFILE="${aws_profile:-}" \
terraform -chdir="$work_dir" apply -input=false -auto-approve -state="$state_path" -var-file="$work_dir/terraform.tfvars.json" >/dev/null

log "app edge provisioned: $bridge_record_name"
