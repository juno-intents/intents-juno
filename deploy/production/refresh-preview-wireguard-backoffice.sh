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
  refresh-preview-wireguard-backoffice.sh [options]

Options:
  --inventory PATH        Resolved preview inventory JSON (required)
  --bridge-summary PATH   Bridge summary JSON for shared manifest rendering (required)
  --dkg-summary PATH      DKG summary JSON for shared manifest rendering (required)
  --dkg-completion PATH   Optional DKG completion JSON
  --app-deploy PATH       Preview app deploy handoff with app role outputs (required)
  --shared-manifest PATH  Shared manifest JSON to update in place (required)
  --operator-deploy PATH  One rendered preview operator deploy handoff used as a VPC resolver (required)
  --output-dir DIR        Output directory for refreshed inventory and terraform evidence (required)
EOF
}

inventory=""
bridge_summary=""
dkg_summary=""
dkg_completion=""
app_deploy=""
shared_manifest=""
operator_deploy=""
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --bridge-summary) bridge_summary="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --dkg-completion) dkg_completion="$2"; shift 2 ;;
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --shared-manifest) shared_manifest="$2"; shift 2 ;;
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$bridge_summary" ]] || die "--bridge-summary is required"
[[ -f "$bridge_summary" ]] || die "bridge summary not found: $bridge_summary"
[[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
if [[ -n "$dkg_completion" ]]; then
  [[ -f "$dkg_completion" ]] || die "dkg completion not found: $dkg_completion"
fi
[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy handoff not found: $app_deploy"
[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -n "$operator_deploy" ]] || die "--operator-deploy is required"
[[ -f "$operator_deploy" ]] || die "operator deploy handoff not found: $operator_deploy"
[[ -n "$output_dir" ]] || die "--output-dir is required"

for cmd in jq aws ssh terraform; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

output_dir="$(production_abs_path "$(pwd)" "$output_dir")"
mkdir -p "$output_dir"

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
backend_account_id="$(production_json_optional "$inventory" '.shared_services.account_id')"
if [[ -z "$backend_account_id" ]]; then
  backend_account_id="$(production_json_optional "$inventory" '.app_role.account_id')"
fi
shared_terraform_dir_rel="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
shared_terraform_dir="$(production_abs_path "$REPO_ROOT" "$shared_terraform_dir_rel")"
[[ -d "$shared_terraform_dir" ]] || die "shared terraform dir not found: $shared_terraform_dir"

internal_lb_dns_name="$(production_json_required "$app_deploy" '.app_role.internal_lb.dns_name | select(type == "string" and length > 0)')"
app_security_group_id="$(production_json_optional "$app_deploy" '.app_role.app_security_group_id')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
known_hosts_file="$(production_abs_path "$(dirname "$operator_deploy")" "$(production_json_required "$operator_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"

resolved_ips_text="$(
  ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10 \
    "ubuntu@$operator_host" \
    "getent ahostsv4 '$internal_lb_dns_name' | awk '{print \$1}' | sort -u"
)"
resolved_ips_json="$(printf '%s\n' "$resolved_ips_text" | jq -Rsc 'split("\n") | map(select(length > 0)) | unique')"
[[ "$(jq -r 'length' <<<"$resolved_ips_json")" -gt 0 ]] || die "failed to resolve any internal backoffice endpoint ips for $internal_lb_dns_name"
primary_ip="$(jq -r '.[0]' <<<"$resolved_ips_json")"

refreshed_inventory="$output_dir/inventory.wireguard-backoffice-refreshed.json"
tmp_inventory="$(mktemp)"
trap 'rm -f "$tmp_inventory"' EXIT
jq \
  --arg primary_ip "$primary_ip" \
  --argjson resolved_ips "$resolved_ips_json" '
    .wireguard_role = ((.wireguard_role // {}) + {
      backoffice_private_endpoint: $primary_ip,
      backoffice_private_endpoint_ips: $resolved_ips
    })
    | if (.shared_roles.wireguard? | type) == "object" then
        .shared_roles.wireguard.backoffice_private_endpoint = $primary_ip
        | .shared_roles.wireguard.backoffice_private_endpoint_ips = $resolved_ips
      else
        .
      end
    | if (.shared_services.wireguard? | type) == "object" then
        .shared_services.wireguard.backoffice_private_endpoint = $primary_ip
        | .shared_services.wireguard.backoffice_private_endpoint_ips = $resolved_ips
      else
        .
      end
  ' "$inventory" >"$tmp_inventory"
if [[ -n "$app_security_group_id" ]]; then
  jq --arg app_security_group_id "$app_security_group_id" '.app_role.app_security_group_id = $app_security_group_id' "$tmp_inventory" >"${tmp_inventory}.next"
  mv "${tmp_inventory}.next" "$tmp_inventory"
fi
  mv "$tmp_inventory" "$refreshed_inventory"

  if [[ -n "$backend_account_id" ]]; then
    bucket_name="$(production_terraform_backend_bucket_name "$backend_account_id" "$aws_region")"
    table_name="$(production_terraform_backend_table_name "$backend_account_id" "$aws_region")"
    state_key="$(production_terraform_backend_state_key "$env_slug" "$shared_terraform_dir")"
  else
    readarray -t backend_parts < <(production_bootstrap_terraform_backend "$aws_profile" "$aws_region" "$env_slug" "$shared_terraform_dir")
    bucket_name="${backend_parts[0]}"
    table_name="${backend_parts[1]}"
    state_key="${backend_parts[2]}"
  fi
  tfvars_file="$output_dir/shared-wireguard-backoffice.tfvars.json"
  production_write_shared_terraform_override_tfvars "$refreshed_inventory" "$tfvars_file"

  (
    cd "$shared_terraform_dir"
    terraform init \
      -reconfigure \
      -backend-config="bucket=$bucket_name" \
      -backend-config="dynamodb_table=$table_name" \
      -backend-config="key=$state_key" \
      -backend-config="region=$aws_region" >/dev/null
    if [[ -s "$tfvars_file" ]]; then
      terraform apply -auto-approve -input=false -var-file="$tfvars_file" >/dev/null
    else
      terraform apply -auto-approve -input=false >/dev/null
    fi
    terraform output -json >"$output_dir/shared-terraform-output.json"
  )

production_render_shared_manifest \
  "$refreshed_inventory" \
  "$bridge_summary" \
  "$dkg_summary" \
  "$output_dir/shared-terraform-output.json" \
  "$shared_manifest" \
  "$inventory_dir" \
  "$dkg_completion"

jq -n \
  --arg ready "true" \
  --arg inventory_path "$refreshed_inventory" \
  --arg shared_manifest "$shared_manifest" \
  --arg shared_terraform_output "$output_dir/shared-terraform-output.json" \
  --arg app_internal_lb_dns_name "$internal_lb_dns_name" \
  --arg operator_deploy "$operator_deploy" \
  --argjson backoffice_private_endpoint_ips "$resolved_ips_json" '
    {
      ready_for_deploy: ($ready == "true"),
      inventory_path: $inventory_path,
      shared_manifest: $shared_manifest,
      shared_terraform_output: $shared_terraform_output,
      app_internal_lb_dns_name: $app_internal_lb_dns_name,
      operator_deploy: $operator_deploy,
      backoffice_private_endpoint_ips: $backoffice_private_endpoint_ips
    }
  '
