#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  connect-operator-private-network.sh [options]

Options:
  --inventory PATH            Deployment inventory JSON (required)
  --operator-id ID           Operator id to connect (required unless --operator-index is set)
  --operator-index N         Operator array index to connect (required unless --operator-id is set)
  --output-inventory PATH    Output inventory JSON (required)
  --receipt PATH             Optional receipt JSON path
  --shared-profile NAME      Optional shared AWS profile override
  --shared-region REGION     Optional shared AWS region override
  --shared-vpc-id ID         Optional shared VPC id override
  --operator-profile NAME    Optional operator AWS profile override
  --operator-region REGION   Optional operator AWS region override
  --operator-vpc-id ID       Optional operator VPC id override
EOF
}

inventory=""
operator_id=""
operator_index=""
output_inventory=""
receipt_path=""
shared_profile=""
shared_region=""
shared_vpc_id=""
operator_profile=""
operator_region=""
operator_vpc_id=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --operator-id) operator_id="$2"; shift 2 ;;
    --operator-index) operator_index="$2"; shift 2 ;;
    --output-inventory) output_inventory="$2"; shift 2 ;;
    --receipt) receipt_path="$2"; shift 2 ;;
    --shared-profile) shared_profile="$2"; shift 2 ;;
    --shared-region) shared_region="$2"; shift 2 ;;
    --shared-vpc-id) shared_vpc_id="$2"; shift 2 ;;
    --operator-profile) operator_profile="$2"; shift 2 ;;
    --operator-region) operator_region="$2"; shift 2 ;;
    --operator-vpc-id) operator_vpc_id="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$output_inventory" ]] || die "--output-inventory is required"
if [[ -z "$operator_id" && -z "$operator_index" ]]; then
  die "--operator-id or --operator-index is required"
fi

have_cmd jq || die "required command not found: jq"
have_cmd aws || die "required command not found: aws"

if [[ -z "$operator_index" ]]; then
  operator_index="$(jq -er --arg operator_id "$operator_id" '
    .operators
    | to_entries[]
    | select(.value.operator_id == $operator_id)
    | .key
  ' "$inventory")"
fi
operator_json="$(jq -c ".operators[$operator_index]" "$inventory")"
[[ -n "$operator_json" && "$operator_json" != "null" ]] || die "operator entry not found for index $operator_index"
if [[ -z "$operator_id" ]]; then
  operator_id="$(jq -r '.operator_id' <<<"$operator_json")"
fi

shared_profile="${shared_profile:-$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')}"
shared_region="${shared_region:-$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')}"
shared_vpc_id="${shared_vpc_id:-$(production_json_required "$inventory" '(.app_role.vpc_id // .app_host.vpc_id) | select(type == "string" and length > 0)')}"
operator_profile="${operator_profile:-$(jq -r '.aws_profile // empty' <<<"$operator_json")}"
operator_region="${operator_region:-$(jq -r '.aws_region // empty' <<<"$operator_json")}"
[[ -n "$operator_profile" ]] || die "operator aws profile is required"
[[ -n "$operator_region" ]] || die "operator aws region is required"

aws_text() {
  local profile="$1"
  local region="$2"
  shift 2
  AWS_PAGER="" aws --profile "$profile" --region "$region" "$@" --output text
}

aws_json() {
  local profile="$1"
  local region="$2"
  shift 2
  AWS_PAGER="" aws --profile "$profile" --region "$region" "$@" --output json
}

discover_default_vpc_id() {
  local profile="$1"
  local region="$2"
  local vpc_id
  vpc_id="$(aws_text "$profile" "$region" ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId')"
  [[ -n "$vpc_id" && "$vpc_id" != "None" ]] || die "no default VPC found in $region for profile $profile"
  printf '%s\n' "$vpc_id"
}

discover_vpc_cidr() {
  local profile="$1"
  local region="$2"
  local vpc_id="$3"
  local cidr
  cidr="$(aws_text "$profile" "$region" ec2 describe-vpcs --vpc-ids "$vpc_id" --query 'Vpcs[0].CidrBlock')"
  [[ -n "$cidr" && "$cidr" != "None" ]] || die "unable to resolve CIDR for VPC $vpc_id in $region"
  printf '%s\n' "$cidr"
}

discover_subnet_ids() {
  local profile="$1"
  local region="$2"
  local vpc_id="$3"
  local output
  output="$(aws_text "$profile" "$region" ec2 describe-subnets --filters Name=vpc-id,Values="$vpc_id" Name=default-for-az,Values=true --query 'Subnets[].SubnetId' || true)"
  if [[ -z "$output" || "$output" == "None" ]]; then
    output="$(aws_text "$profile" "$region" ec2 describe-subnets --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[].SubnetId')"
  fi
  [[ -n "$output" && "$output" != "None" ]] || die "unable to resolve subnet ids for VPC $vpc_id in $region"
  tr '\t' '\n' <<<"$output" | sed '/^$/d'
}

discover_route_table_ids() {
  local profile="$1"
  local region="$2"
  local vpc_id="$3"
  local output
  output="$(aws_text "$profile" "$region" ec2 describe-route-tables --filters Name=vpc-id,Values="$vpc_id" --query 'RouteTables[].RouteTableId')"
  [[ -n "$output" && "$output" != "None" ]] || die "unable to resolve route tables for VPC $vpc_id in $region"
  tr '\t' '\n' <<<"$output" | sed '/^$/d'
}

find_existing_peering_id() {
  local requester_profile="$1"
  local requester_region="$2"
  local requester_vpc_id="$3"
  local accepter_vpc_id="$4"
  local pcx
  pcx="$(aws_text "$requester_profile" "$requester_region" ec2 describe-vpc-peering-connections \
    --filters \
      Name=requester-vpc-info.vpc-id,Values="$requester_vpc_id" \
      Name=accepter-vpc-info.vpc-id,Values="$accepter_vpc_id" \
      Name=status-code,Values=initiating-request,pending-acceptance,provisioning,active \
    --query 'VpcPeeringConnections[0].VpcPeeringConnectionId' || true)"
  if [[ -n "$pcx" && "$pcx" != "None" ]]; then
    printf '%s\n' "$pcx"
    return 0
  fi
  pcx="$(aws_text "$requester_profile" "$requester_region" ec2 describe-vpc-peering-connections \
    --filters \
      Name=requester-vpc-info.vpc-id,Values="$accepter_vpc_id" \
      Name=accepter-vpc-info.vpc-id,Values="$requester_vpc_id" \
      Name=status-code,Values=initiating-request,pending-acceptance,provisioning,active \
    --query 'VpcPeeringConnections[0].VpcPeeringConnectionId' || true)"
  if [[ -n "$pcx" && "$pcx" != "None" ]]; then
    printf '%s\n' "$pcx"
  fi
}

wait_for_peering_active() {
  local profile="$1"
  local region="$2"
  local pcx_id="$3"
  local status=""
  local attempt
  for attempt in $(seq 1 30); do
    status="$(aws_text "$profile" "$region" ec2 describe-vpc-peering-connections --vpc-peering-connection-ids "$pcx_id" --query 'VpcPeeringConnections[0].Status.Code')"
    if [[ "$status" == "active" ]]; then
      return 0
    fi
    sleep 2
  done
  die "vpc peering connection $pcx_id did not become active (last status: ${status:-unknown})"
}

ensure_route() {
  local profile="$1"
  local region="$2"
  local route_table_id="$3"
  local destination_cidr="$4"
  local pcx_id="$5"
  if ! AWS_PAGER="" aws --profile "$profile" --region "$region" ec2 create-route \
    --route-table-id "$route_table_id" \
    --destination-cidr-block "$destination_cidr" \
    --vpc-peering-connection-id "$pcx_id" >/dev/null 2>&1; then
    AWS_PAGER="" aws --profile "$profile" --region "$region" ec2 replace-route \
      --route-table-id "$route_table_id" \
      --destination-cidr-block "$destination_cidr" \
      --vpc-peering-connection-id "$pcx_id" >/dev/null
  fi
}

shared_account_id="$(AWS_PAGER="" aws --profile "$shared_profile" --region "$shared_region" sts get-caller-identity --query 'Account' --output text)"
operator_account_id="$(AWS_PAGER="" aws --profile "$operator_profile" --region "$operator_region" sts get-caller-identity --query 'Account' --output text)"

operator_vpc_id="${operator_vpc_id:-$(jq -r '.private_network.vpc_id // empty' <<<"$operator_json")}"
if [[ -z "$operator_vpc_id" ]]; then
  operator_vpc_id="$(discover_default_vpc_id "$operator_profile" "$operator_region")"
fi

shared_vpc_cidr="$(discover_vpc_cidr "$shared_profile" "$shared_region" "$shared_vpc_id")"
operator_vpc_cidr="$(discover_vpc_cidr "$operator_profile" "$operator_region" "$operator_vpc_id")"

tmp_dir="$(mktemp -d)"
operator_subnet_ids_file="$tmp_dir/operator-subnet-ids.txt"
operator_route_tables_file="$tmp_dir/operator-route-tables.txt"
shared_route_tables_file="$tmp_dir/shared-route-tables.txt"
receipt_json_file="$tmp_dir/receipt.json"
patched_inventory="$tmp_dir/inventory.json"

discover_subnet_ids "$operator_profile" "$operator_region" "$operator_vpc_id" >"$operator_subnet_ids_file"
discover_route_table_ids "$operator_profile" "$operator_region" "$operator_vpc_id" >"$operator_route_tables_file"
discover_route_table_ids "$shared_profile" "$shared_region" "$shared_vpc_id" >"$shared_route_tables_file"

pcx_id="$(find_existing_peering_id "$operator_profile" "$operator_region" "$operator_vpc_id" "$shared_vpc_id" || true)"
if [[ -z "$pcx_id" ]]; then
  pcx_id="$(AWS_PAGER="" aws --profile "$operator_profile" --region "$operator_region" ec2 create-vpc-peering-connection \
    --vpc-id "$operator_vpc_id" \
    --peer-vpc-id "$shared_vpc_id" \
    --peer-owner-id "$shared_account_id" \
    --peer-region "$shared_region" \
    --query 'VpcPeeringConnection.VpcPeeringConnectionId' \
    --output text)"
  AWS_PAGER="" aws --profile "$shared_profile" --region "$shared_region" ec2 accept-vpc-peering-connection \
    --vpc-peering-connection-id "$pcx_id" >/dev/null
fi

AWS_PAGER="" aws --profile "$operator_profile" --region "$operator_region" ec2 modify-vpc-peering-connection-options \
  --vpc-peering-connection-id "$pcx_id" \
  --requester-peering-connection-options AllowDnsResolutionFromRemoteVpc=true >/dev/null
AWS_PAGER="" aws --profile "$shared_profile" --region "$shared_region" ec2 modify-vpc-peering-connection-options \
  --vpc-peering-connection-id "$pcx_id" \
  --accepter-peering-connection-options AllowDnsResolutionFromRemoteVpc=true >/dev/null

wait_for_peering_active "$operator_profile" "$operator_region" "$pcx_id"

while IFS= read -r route_table_id; do
  [[ -n "$route_table_id" ]] || continue
  ensure_route "$operator_profile" "$operator_region" "$route_table_id" "$shared_vpc_cidr" "$pcx_id"
done <"$operator_route_tables_file"

while IFS= read -r route_table_id; do
  [[ -n "$route_table_id" ]] || continue
  ensure_route "$shared_profile" "$shared_region" "$route_table_id" "$operator_vpc_cidr" "$pcx_id"
done <"$shared_route_tables_file"

jq -n \
  --arg operator_profile "$operator_profile" \
  --arg operator_region "$operator_region" \
  --arg operator_account_id "$operator_account_id" \
  --arg operator_vpc_id "$operator_vpc_id" \
  --arg operator_vpc_cidr "$operator_vpc_cidr" \
  --argjson operator_subnet_ids "$(jq -R -s 'split("\n") | map(select(length > 0))' "$operator_subnet_ids_file")" \
  --argjson operator_route_table_ids "$(jq -R -s 'split("\n") | map(select(length > 0))' "$operator_route_tables_file")" \
  --arg shared_profile "$shared_profile" \
  --arg shared_region "$shared_region" \
  --arg shared_account_id "$shared_account_id" \
  --arg shared_vpc_id "$shared_vpc_id" \
  --arg shared_vpc_cidr "$shared_vpc_cidr" \
  --argjson shared_route_table_ids "$(jq -R -s 'split("\n") | map(select(length > 0))' "$shared_route_tables_file")" \
  --arg vpc_peering_connection_id "$pcx_id" \
  '{
    operator_profile: $operator_profile,
    operator_region: $operator_region,
    operator_account_id: $operator_account_id,
    operator_vpc_id: $operator_vpc_id,
    operator_vpc_cidr: $operator_vpc_cidr,
    operator_subnet_ids: $operator_subnet_ids,
    operator_route_table_ids: $operator_route_table_ids,
    shared_profile: $shared_profile,
    shared_region: $shared_region,
    shared_account_id: $shared_account_id,
    shared_vpc_id: $shared_vpc_id,
    shared_vpc_cidr: $shared_vpc_cidr,
    shared_route_table_ids: $shared_route_table_ids,
    vpc_peering_connection_id: $vpc_peering_connection_id
  }' >"$receipt_json_file"

jq --argjson operator_index "$operator_index" --slurpfile receipt "$receipt_json_file" '
  .operators[$operator_index].account_id = ($receipt[0].operator_account_id)
  | .operators[$operator_index].private_network = {
      vpc_id: $receipt[0].operator_vpc_id,
      vpc_cidr: $receipt[0].operator_vpc_cidr,
      subnet_ids: $receipt[0].operator_subnet_ids,
      route_table_ids: $receipt[0].operator_route_table_ids,
      vpc_peering_connection_id: $receipt[0].vpc_peering_connection_id,
      shared_vpc_id: $receipt[0].shared_vpc_id,
      shared_vpc_cidr: $receipt[0].shared_vpc_cidr,
      shared_route_table_ids: $receipt[0].shared_route_table_ids
    }
' "$inventory" >"$patched_inventory"

mv "$patched_inventory" "$output_inventory"
if [[ -n "$receipt_path" ]]; then
  cp "$receipt_json_file" "$receipt_path"
fi

log "connected operator $operator_id private network $operator_vpc_id ($operator_region) to shared vpc $shared_vpc_id ($shared_region) via $pcx_id"
