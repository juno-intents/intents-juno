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
  destroy-preview-role-runtime.sh [options]

Options:
  --inventory PATH            Role-runtime preview inventory JSON (required)
  --current-output-root DIR   Current preview output root used to discover app handoffs
  --skip-missing-edge-state   Skip app-edge destroy when no edge state can be discovered
EOF
}

inventory=""
current_output_root=""
skip_missing_edge_state="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --current-output-root) current_output_root="$2"; shift 2 ;;
    --skip-missing-edge-state) skip_missing_edge_state="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
for cmd in jq terraform aws; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
shared_terraform_dir_rel="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
shared_terraform_dir="$(production_abs_path "$REPO_ROOT" "$shared_terraform_dir_rel")"
app_terraform_dir_rel="$(production_json_required "$inventory" '.app_role.terraform_dir | select(type == "string" and length > 0)')"
app_terraform_dir="$(production_abs_path "$REPO_ROOT" "$app_terraform_dir_rel")"
aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
backend_account_id="$(production_json_optional "$inventory" '.shared_services.account_id')"
if [[ -z "$backend_account_id" ]]; then
  backend_account_id="$(production_json_optional "$inventory" '.app_role.account_id')"
fi

if [[ -z "$current_output_root" ]]; then
  current_output_root="$inventory_dir/production-output"
fi
current_output_root="$(production_abs_path "$(pwd)" "$current_output_root")"
destroy_work_dir="$(dirname "$current_output_root")/$env_slug"
mkdir -p "$destroy_work_dir"

shared_var_file="$destroy_work_dir/shared-terraform.auto.tfvars.json"
app_var_file="$destroy_work_dir/app-terraform.auto.tfvars.json"
production_write_shared_terraform_override_tfvars "$inventory" "$shared_var_file"
production_write_app_terraform_override_tfvars "$inventory" "$app_var_file"

mapfile -t shared_backend_lines < <(production_bootstrap_terraform_backend "$aws_profile" "$aws_region" "$env_slug" "$shared_terraform_dir" "$backend_account_id")
shared_bucket="${shared_backend_lines[0]}"
shared_table="${shared_backend_lines[1]}"
shared_key="${shared_backend_lines[2]}"
mapfile -t app_backend_lines < <(production_bootstrap_terraform_backend "$aws_profile" "$aws_region" "$env_slug" "$app_terraform_dir" "$backend_account_id")
app_bucket="${app_backend_lines[0]}"
app_table="${app_backend_lines[1]}"
app_key="${app_backend_lines[2]}"

app_deploy_path=""
for candidate in \
  "$current_output_root/$env_slug/app/app-deploy.json" \
  "$inventory_dir/production-output/$env_slug/app/app-deploy.json" \
  "$inventory_dir/app/app-deploy.json"; do
  if [[ -f "$candidate" ]]; then
    app_deploy_path="$candidate"
    break
  fi
done

resolve_edge_state_path() {
  local app_deploy="$1"
  local rel
  rel="$(production_json_required "$app_deploy" '.edge.state_path | select(type == "string" and length > 0)')"
  for candidate in \
    "$(production_abs_path "$(dirname "$app_deploy")" "$rel")" \
    "$(production_abs_path "$inventory_dir" "$rel")" \
    "$(production_abs_path "$(dirname "$current_output_root")" "$rel")"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

destroy_app_edge() {
  local app_deploy="$1"
  local edge_state_path edge_public_lb_dns_name edge_var_file bridge_record_name origin_record_name zone_id
  local origin_http_port security_group_id rate_limit enable_shield_advanced alarm_actions_json

  edge_state_path="$(resolve_edge_state_path "$app_deploy" || true)"
  if [[ -z "$edge_state_path" ]]; then
    [[ "$skip_missing_edge_state" == "true" ]] && return 0
    die "failed to resolve the current preview app-edge state path"
  fi

  edge_public_lb_dns_name="$(jq -r '.edge.public_lb_dns_name // .edge.origin_endpoint // empty' "$app_deploy")"
  [[ -n "$edge_public_lb_dns_name" ]] || die "app deploy manifest is missing edge.public_lb_dns_name or edge.origin_endpoint"
  bridge_record_name="$(production_json_required "$app_deploy" '.services.bridge_api.record_name | select(type == "string" and length > 0)')"
  origin_record_name="$(production_json_required "$app_deploy" '.edge.origin_record_name | select(type == "string" and length > 0)')"
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  origin_http_port="$(production_json_required "$app_deploy" '.edge.origin_http_port')"
  security_group_id="$(jq -r '.app_role.public_lb.security_group_id // .app_role.security_group_id // empty' "$inventory")"
  rate_limit="$(production_json_required "$app_deploy" '.edge.rate_limit')"
  enable_shield_advanced="$(jq -r '.edge.enable_shield_advanced // false' "$app_deploy")"
  alarm_actions_json="$(jq -c '.shared_services.alarm_actions' "$inventory")"

  edge_var_file="$destroy_work_dir/edge-terraform.auto.tfvars.json"
  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$env_slug" \
    --arg zone_id "$zone_id" \
    --arg bridge_record_name "$bridge_record_name" \
    --arg origin_record_name "$origin_record_name" \
    --arg public_lb_dns_name "$edge_public_lb_dns_name" \
    --arg security_group_id "$security_group_id" \
    --argjson origin_http_port "$origin_http_port" \
    --argjson rate_limit "$rate_limit" \
    --argjson alarm_actions "$alarm_actions_json" \
    --arg enable_shield_advanced "$enable_shield_advanced" '
      {
        aws_region: $aws_region,
        deployment_id: $deployment_id,
        zone_id: $zone_id,
        bridge_record_name: $bridge_record_name,
        origin_record_name: $origin_record_name,
        public_lb_dns_name: $public_lb_dns_name,
        origin_http_port: $origin_http_port,
        rate_limit: $rate_limit,
        alarm_actions: $alarm_actions,
        enable_shield_advanced: ($enable_shield_advanced == "true")
      }
      + (if $security_group_id == "" then {} else { security_group_id: $security_group_id } end)
    ' >"$edge_var_file"

  (
    cd "$REPO_ROOT/deploy/shared/terraform/app-edge"
    terraform init -input=false >/dev/null
    terraform destroy -auto-approve -input=false -state="$edge_state_path" -var-file="$edge_var_file"
  )
}

if [[ -n "$app_deploy_path" ]]; then
  destroy_app_edge "$app_deploy_path"
elif [[ "$skip_missing_edge_state" != "true" ]]; then
  die "failed to discover the current preview app-deploy manifest needed for app-edge destroy"
fi

(
  cd "$app_terraform_dir"
  terraform init -input=false -reconfigure \
    -backend-config="bucket=$app_bucket" \
    -backend-config="dynamodb_table=$app_table" \
    -backend-config="key=$app_key" \
    -backend-config="region=$aws_region" >/dev/null
  terraform destroy -auto-approve -input=false -var-file="$app_var_file"
)

(
  cd "$shared_terraform_dir"
  terraform init -input=false -reconfigure \
    -backend-config="bucket=$shared_bucket" \
    -backend-config="dynamodb_table=$shared_table" \
    -backend-config="key=$shared_key" \
    -backend-config="region=$aws_region" >/dev/null
  terraform destroy -auto-approve -input=false -var-file="$shared_var_file"
)
