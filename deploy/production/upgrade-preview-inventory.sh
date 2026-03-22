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
  upgrade-preview-inventory.sh [options]

Options:
  --inventory PATH                               Preview deployment inventory JSON (required)
  --output PATH                                  Upgraded role-runtime inventory JSON (required)
  --legacy-state PATH                            Optional legacy terraform state JSON
  --app-runtime-ami-release-tag TAG              Optional app runtime AMI release tag to pin
  --shared-proof-services-image-release-tag TAG  Optional shared proof image release tag to pin
  --wireguard-role-ami-release-tag TAG           Optional wireguard role AMI release tag to pin
  --aws-profile PROFILE                          Override AWS profile from inventory
  --aws-region REGION                            Override AWS region from inventory
EOF
}

inventory=""
output=""
legacy_state=""
app_runtime_ami_release_tag=""
shared_proof_services_image_release_tag=""
wireguard_role_ami_release_tag=""
aws_profile_override=""
aws_region_override=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --legacy-state) legacy_state="$2"; shift 2 ;;
    --app-runtime-ami-release-tag) app_runtime_ami_release_tag="$2"; shift 2 ;;
    --shared-proof-services-image-release-tag) shared_proof_services_image_release_tag="$2"; shift 2 ;;
    --wireguard-role-ami-release-tag) wireguard_role_ami_release_tag="$2"; shift 2 ;;
    --aws-profile) aws_profile_override="$2"; shift 2 ;;
    --aws-region) aws_region_override="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$output" ]] || die "--output is required"
have_cmd jq || die "required command not found: jq"

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
inventory_abs="$(cd "$(dirname "$inventory")" && pwd)/$(basename "$inventory")"
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

find_legacy_state() {
  local inventory_file="$1"
  local inventory_root="$2"
  local supplied="$3"
  local state_path legacy_tf_dir env_slug aws_profile aws_region tf_bin bucket table key

  if [[ -n "$supplied" ]]; then
    [[ -f "$supplied" ]] || die "legacy state not found: $supplied"
    printf '%s\n' "$supplied"
    return 0
  fi

  for state_path in \
    "$inventory_root/terraform.tfstate" \
    "$inventory_root/edge-state/$(production_json_required "$inventory_file" '.environment').tfstate"; do
    if [[ -f "$state_path" ]]; then
      printf '%s\n' "$state_path"
      return 0
    fi
  done

  legacy_tf_dir="$(production_json_optional "$inventory_file" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  if [[ -n "$legacy_tf_dir" ]]; then
    legacy_tf_dir="$(production_abs_path "$inventory_root" "$legacy_tf_dir")"
    if [[ -f "$legacy_tf_dir/terraform.tfstate" ]]; then
      printf '%s\n' "$legacy_tf_dir/terraform.tfstate"
      return 0
    fi

    if [[ -d "$legacy_tf_dir" ]] && have_cmd terraform && have_cmd aws; then
      env_slug="$(production_json_required "$inventory_file" '.environment | select(type == "string" and length > 0)')"
      aws_profile="$aws_profile_override"
      if [[ -z "$aws_profile" ]]; then
        aws_profile="$(production_json_required "$inventory_file" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
      fi
      aws_region="$aws_region_override"
      if [[ -z "$aws_region" ]]; then
        aws_region="$(production_json_required "$inventory_file" '.shared_services.aws_region | select(type == "string" and length > 0)')"
      fi
      mapfile -t backend_lines < <(production_bootstrap_terraform_backend "$aws_profile" "$aws_region" "$env_slug" "$legacy_tf_dir")
      bucket="${backend_lines[0]}"
      table="${backend_lines[1]}"
      key="${backend_lines[2]}"
      (
        cd "$legacy_tf_dir"
        terraform init -input=false -reconfigure \
          -backend-config="bucket=$bucket" \
          -backend-config="dynamodb_table=$table" \
          -backend-config="key=$key" \
          -backend-config="region=$aws_region" >/dev/null
        terraform state pull >"$tmp_dir/legacy-state.json"
      )
      printf '%s\n' "$tmp_dir/legacy-state.json"
      return 0
    fi
  fi

  return 1
}

legacy_instance_json_for_ip() {
  local aws_profile="$1"
  local aws_region="$2"
  local public_ip="$3"
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
    --filters "Name=ip-address,Values=$public_ip" \
    --output json
}

resolve_cert_arn() {
  local aws_profile="$1"
  local aws_region="$2"
  local domain_name="$3"
  local certificates_json

  certificates_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" acm list-certificates \
    --certificate-statuses ISSUED \
    --includes keyTypes=RSA_2048,EC_prime256v1 \
    --output json)"
  jq -r --arg domain_name "$domain_name" '
    .CertificateSummaryList[]
    | select((.DomainName // "") == $domain_name)
    | .CertificateArn
    | select(type == "string" and length > 0)
  ' <<<"$certificates_json" | head -n 1
}

inventory_aws_profile() {
  local inventory_file="$1"
  if [[ -n "$aws_profile_override" ]]; then
    printf '%s\n' "$aws_profile_override"
    return 0
  fi

  production_json_optional "$inventory_file" '.shared_services.aws_profile | select(type == "string" and length > 0)'
}

inventory_aws_region() {
  local inventory_file="$1"
  if [[ -n "$aws_region_override" ]]; then
    printf '%s\n' "$aws_region_override"
    return 0
  fi

  production_json_optional "$inventory_file" '.shared_services.aws_region | select(type == "string" and length > 0)'
}

resolve_preview_app_instance_profile_name() {
  local inventory_file="$1"
  local aws_profile="$2"
  local aws_region="$3"
  local instance_profile_name app_host app_instance_json

  instance_profile_name="$(production_json_optional "$inventory_file" '.app_role.app_instance_profile_name | select(type == "string" and length > 0)')"
  if [[ -n "$instance_profile_name" ]]; then
    printf '%s\n' "$instance_profile_name"
    return 0
  fi

  app_host="$(production_json_optional "$inventory_file" '.app_role.host // .app_host.host | select(type == "string" and length > 0)')"
  if [[ -z "$app_host" || -z "$aws_profile" || -z "$aws_region" ]]; then
    return 1
  fi
  if ! have_cmd aws; then
    return 1
  fi

  app_instance_json="$(legacy_instance_json_for_ip "$aws_profile" "$aws_region" "$app_host")"
  instance_profile_name="$(
    jq -r '
      .Reservations[0].Instances[0].IamInstanceProfile.Arn // empty
      | if type == "string" and length > 0 then split("/")[-1] else "" end
    ' <<<"$app_instance_json"
  )"
  [[ -n "$instance_profile_name" ]] || return 1
  printf '%s\n' "$instance_profile_name"
}

resolve_preview_shared_terraform_dir() {
  local configured_dir="$1"
  local app_instance_profile_name="${2:-}"

  if [[ "$app_instance_profile_name" == *"live-e2e"* ]]; then
    printf 'deploy/shared/terraform/live-e2e\n'
    return 0
  fi

  if [[ "$configured_dir" == *"live-e2e"* ]]; then
    printf 'deploy/shared/terraform/live-e2e\n'
    return 0
  fi

  if [[ "$configured_dir" == *"production-shared"* ]]; then
    printf 'deploy/shared/terraform/production-shared\n'
    return 0
  fi

  if [[ "$configured_dir" == deploy/shared/terraform/* ]]; then
    printf '%s\n' "$configured_dir"
    return 0
  fi

  printf 'deploy/shared/terraform/production-shared\n'
}

find_live_e2e_state_file() {
  local inventory_file="$1"
  local inventory_root="$2"
  local discovered_state_file="$3"
  local configured_dir candidate

  for candidate in \
    "$discovered_state_file" \
    "$inventory_root/legacy-live-e2e.tfstate.json" \
    "$inventory_root/legacy-live-e2e.tfstate" \
    "$inventory_root/terraform/live-e2e/terraform.tfstate.localbak" \
    "$inventory_root/terraform/live-e2e/terraform.tfstate" \
    "$inventory_root/terraform/live-e2e/terraform.tfstate.backup" \
    "$inventory_root/terraform/live-e2e/terraform.tfstate.backup.localbak"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  configured_dir="$(production_json_optional "$inventory_file" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  if [[ "$configured_dir" == *"live-e2e"* ]]; then
    configured_dir="$(production_abs_path "$inventory_root" "$configured_dir")"
    for candidate in \
      "$configured_dir/terraform.tfstate.localbak" \
      "$configured_dir/terraform.tfstate" \
      "$configured_dir/terraform.tfstate.backup" \
      "$configured_dir/terraform.tfstate.backup.localbak"; do
      if [[ -f "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
  fi

  return 1
}

live_e2e_deployment_id_from_instance_profile() {
  local app_instance_profile_name="${1:-}"

  if [[ "$app_instance_profile_name" == juno-live-e2e-*-instance-profile ]]; then
    local deployment_id="${app_instance_profile_name#juno-live-e2e-}"
    deployment_id="${deployment_id%-instance-profile}"
    printf '%s\n' "$deployment_id"
  fi
}

live_e2e_deployment_id_from_state() {
  local state_file="$1"
  local app_instance_profile_name="${2:-}"
  local deployment_id

  deployment_id="$(
    jq -r '
      [
        .outputs.effective_instance_profile.value // empty,
        (
          (.resources // [])[]
          | select(.type == "aws_key_pair" and .name == "runner")
          | .instances[0].attributes.tags.Deployment // empty
        ),
        (
          (.resources // [])[]
          | select(.type == "aws_security_group" and .name == "runner")
          | .instances[0].attributes.tags.Deployment // empty
        )
      ]
      | map(select(type == "string" and length > 0))
      | .[0] // empty
    ' "$state_file"
  )"
  deployment_id="$(live_e2e_deployment_id_from_instance_profile "$deployment_id")"
  if [[ -z "$deployment_id" ]]; then
    deployment_id="$(live_e2e_deployment_id_from_instance_profile "$app_instance_profile_name")"
  fi
  printf '%s\n' "$deployment_id"
}

live_e2e_operator_asg_name() {
  local deployment_id="${1:-}"
  local operator_index="${2:-}"
  if [[ -n "$deployment_id" && -n "$operator_index" ]]; then
    printf 'juno-live-e2e-%s-operator-%s\n' "$deployment_id" "$operator_index"
  fi
}

resolve_operator_launch_template_json_for_asg() {
  local aws_profile="$1"
  local aws_region="$2"
  local operator_asg="$3"
  local asg_json lt_id lt_version

  [[ -n "$operator_asg" ]] || return 0
  asg_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$operator_asg" \
    --output json 2>/dev/null || true)"
  [[ -n "$asg_json" ]] || return 0

  lt_id="$(jq -r '.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId // .AutoScalingGroups[0].MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.LaunchTemplateId // empty' <<<"$asg_json")"
  lt_version="$(jq -r '.AutoScalingGroups[0].LaunchTemplate.Version // .AutoScalingGroups[0].MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.Version // empty' <<<"$asg_json")"
  if [[ -n "$lt_id" ]]; then
    jq -cn --arg id "$lt_id" --arg version "$lt_version" '{id: $id, version: $version}'
  fi
}

resolve_launch_template_image_id() {
  local aws_profile="$1"
  local aws_region="$2"
  local launch_template_id="$3"
  local launch_template_version="$4"
  local lt_json

  [[ -n "$launch_template_id" ]] || return 0
  if [[ -z "$launch_template_version" ]]; then
    launch_template_version='$Latest'
  fi

  lt_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-launch-template-versions \
    --launch-template-id "$launch_template_id" \
    --versions "$launch_template_version" \
    --output json 2>/dev/null || true)"
  [[ -n "$lt_json" ]] || return 0
  jq -r '.LaunchTemplateVersions[0].LaunchTemplateData.ImageId // empty' <<<"$lt_json"
}

live_e2e_allowed_ssh_cidr_from_state() {
  local state_file="$1"
  jq -r '
    [
      (.resources // [])[]
      | select(.type == "aws_security_group" and .name == "runner")
      | .instances[0].attributes.ingress[]?
      | select((.from_port // 0) == 22 and (.to_port // 0) == 22 and (.protocol // "") == "tcp")
      | .cidr_blocks[]?
      | select(type == "string" and length > 0)
    ][0] // empty
  ' "$state_file"
}

live_e2e_ssh_public_key_from_state() {
  local state_file="$1"
  jq -r '
    [
      (.resources // [])[]
      | select(.type == "aws_key_pair" and .name == "runner")
      | .instances[0].attributes.public_key
      | select(type == "string" and length > 0)
    ][0] // empty
  ' "$state_file"
}

normalize_preview_app_role_certificates() {
  local inventory_file="$1"
  local output_file="$2"
  local aws_profile aws_region public_subdomain bridge_public_dns_label backoffice_dns_label
  local bridge_cert_arn origin_cert_arn backoffice_cert_arn

  if ! jq -e '
    ((.app_host? | type == "object") or (.app_role? | type == "object"))
    and (.shared_services.public_subdomain? | type == "string" and length > 0)
  ' "$inventory_file" >/dev/null 2>&1; then
    cp "$inventory_file" "$output_file"
    return 0
  fi

  have_cmd aws || die "required command not found: aws"

  aws_profile="$(inventory_aws_profile "$inventory_file")"
  [[ -n "$aws_profile" ]] || die "preview inventory is missing shared_services.aws_profile"
  aws_region="$(inventory_aws_region "$inventory_file")"
  [[ -n "$aws_region" ]] || die "preview inventory is missing shared_services.aws_region"

  public_subdomain="$(production_json_required "$inventory_file" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  bridge_public_dns_label="$(
    production_json_optional "$inventory_file" '
      .app_role.bridge_public_dns_label // .app_host.bridge_public_dns_label
      | select(type == "string" and length > 0)
    '
  )"
  [[ -n "$bridge_public_dns_label" ]] || die "preview inventory is missing app_role.bridge_public_dns_label"
  backoffice_dns_label="$(
    production_json_optional "$inventory_file" '
      .app_role.backoffice_dns_label // .app_host.backoffice_dns_label // .app_host.ops_public_dns_label
      | select(type == "string" and length > 0)
    '
  )"
  [[ -n "$backoffice_dns_label" ]] || die "preview inventory is missing app_role.backoffice_dns_label"

  bridge_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "${bridge_public_dns_label}.${public_subdomain}")"
  [[ -n "$bridge_cert_arn" ]] || die "failed to resolve bridge ACM certificate for ${bridge_public_dns_label}.${public_subdomain}"
  origin_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "origin.${public_subdomain}")"
  [[ -n "$origin_cert_arn" ]] || die "failed to resolve CloudFront origin ACM certificate for origin.${public_subdomain}"
  backoffice_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "${backoffice_dns_label}.${public_subdomain}")"
  [[ -n "$backoffice_cert_arn" ]] || die "failed to resolve backoffice ACM certificate for ${backoffice_dns_label}.${public_subdomain}"

  jq \
    --arg bridge_public_dns_label "$bridge_public_dns_label" \
    --arg backoffice_dns_label "$backoffice_dns_label" \
    --arg bridge_cert_arn "$bridge_cert_arn" \
    --arg origin_cert_arn "$origin_cert_arn" \
    --arg backoffice_cert_arn "$backoffice_cert_arn" \
    '
      .app_role = (.app_role // {})
      | .app_role.bridge_public_dns_label = $bridge_public_dns_label
      | .app_role.backoffice_dns_label = $backoffice_dns_label
      | .app_role.public_bridge_certificate_arn = $origin_cert_arn
      | .app_role.public_bridge_additional_certificate_arns = [$bridge_cert_arn]
      | .app_role.internal_backoffice_certificate_arn = $backoffice_cert_arn
    ' "$inventory_file" >"$output_file"
}

state_file="$(find_legacy_state "$inventory_abs" "$inventory_dir" "$legacy_state" || true)"
aws_profile="$(inventory_aws_profile "$inventory_abs")"
aws_region="$(inventory_aws_region "$inventory_abs")"
configured_shared_terraform_dir="$(production_json_optional "$inventory_abs" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
app_instance_profile_name="$(resolve_preview_app_instance_profile_name "$inventory_abs" "$aws_profile" "$aws_region" || true)"
shared_terraform_dir_rel="$(resolve_preview_shared_terraform_dir "$configured_shared_terraform_dir" "$app_instance_profile_name")"

upgraded_inventory="$inventory_abs"
operator_ami_id=""
if ! production_inventory_has_v2_roles "$inventory_abs"; then
  [[ -n "$state_file" ]] || die "legacy preview inventory requires a discoverable terraform state"
  have_cmd aws || die "required command not found: aws"

  [[ -n "$aws_profile" ]] || die "preview inventory is missing shared_services.aws_profile"
  [[ -n "$aws_region" ]] || die "preview inventory is missing shared_services.aws_region"

  state_json="$(cat "$state_file")"
  vpc_id="$(jq -r '
    [
      (.resources // [])[]
      | select(.type == "aws_vpc" and .name == "selected")
      | .instances[]?
      | .attributes.id
      | select(type == "string" and length > 0)
    ][0] // empty
  ' <<<"$state_json")"
  [[ -n "$vpc_id" ]] || die "failed to resolve vpc id from legacy terraform state"

  public_subnets_json="$(jq -c '
    [
      (.resources // [])[]
      | select(.type == "aws_subnet")
      | .instances[]?
      | .attributes
      | select((.map_public_ip_on_launch // false) == true)
      | {id, cidr_block, availability_zone}
    ]
    | sort_by(.availability_zone, .id)
  ' <<<"$state_json")"
  private_subnets_json="$(jq -c '
    [
      (.resources // [])[]
      | select(.type == "aws_subnet")
      | .instances[]?
      | .attributes
      | select((.map_public_ip_on_launch // false) == false)
      | {id, cidr_block, availability_zone}
    ]
    | sort_by(.availability_zone, .id)
  ' <<<"$state_json")"
  [[ "$(jq -r 'length' <<<"$public_subnets_json")" -ge 2 ]] || die "legacy preview state must expose at least two public subnets"
  [[ "$(jq -r 'length' <<<"$private_subnets_json")" -ge 2 ]] || die "legacy preview state must expose at least two private subnets"

  app_host_public_ip="$(production_json_required "$inventory_abs" '.app_host.host | select(type == "string" and length > 0)')"
  app_host_private_ip="$(production_json_required "$inventory_abs" '.app_host.private_endpoint | select(type == "string" and length > 0)')"
  app_instance_json="$(legacy_instance_json_for_ip "$aws_profile" "$aws_region" "$app_host_public_ip")"
  app_instance_profile_name="$(
    jq -r '
      .Reservations[0].Instances[0].IamInstanceProfile.Arn // empty
      | if type == "string" and length > 0 then split("/")[-1] else "" end
    ' <<<"$app_instance_json"
  )"
  if [[ -z "$app_instance_profile_name" ]]; then
    app_instance_profile_name="$(jq -r '.outputs.effective_instance_profile.value // empty' <<<"$state_json")"
  fi
  [[ -n "$app_instance_profile_name" ]] || die "failed to resolve the app instance profile name"
  shared_terraform_dir_rel="$(resolve_preview_shared_terraform_dir "$configured_shared_terraform_dir" "$app_instance_profile_name")"

  public_subnet_ids_json="$(jq -c '[.[].id]' <<<"$public_subnets_json")"
  private_subnet_ids_json="$(jq -c '[.[].id]' <<<"$private_subnets_json")"
  wireguard_source_cidrs_json="$(jq -c '[.[].cidr_block]' <<<"$public_subnets_json")"
  wireguard_public_subnet_id="$(jq -r '.[0].id' <<<"$public_subnets_json")"
  wireguard_public_subnet_ids_json="$public_subnet_ids_json"
  wireguard_backoffice_private_endpoint_ips_json="$(jq -cn --arg app_host_private_ip "$app_host_private_ip" '[$app_host_private_ip]')"
  bridge_public_dns_label="$(production_json_required "$inventory_abs" '.app_host.bridge_public_dns_label | select(type == "string" and length > 0)')"
  backoffice_dns_label="$(jq -r '.app_host.backoffice_dns_label // .app_host.ops_public_dns_label // empty' "$inventory_abs")"
  [[ -n "$backoffice_dns_label" ]] || die "legacy preview inventory is missing app_host.backoffice_dns_label or app_host.ops_public_dns_label"
  public_subdomain="$(production_json_required "$inventory_abs" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  bridge_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "${bridge_public_dns_label}.${public_subdomain}")"
  [[ -n "$bridge_cert_arn" ]] || die "failed to resolve bridge ACM certificate for ${bridge_public_dns_label}.${public_subdomain}"
  origin_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "origin.${public_subdomain}")"
  [[ -n "$origin_cert_arn" ]] || die "failed to resolve CloudFront origin ACM certificate for origin.${public_subdomain}"
  backoffice_cert_arn="$(resolve_cert_arn "$aws_profile" "$aws_region" "${backoffice_dns_label}.${public_subdomain}")"
  [[ -n "$backoffice_cert_arn" ]] || die "failed to resolve backoffice ACM certificate for ${backoffice_dns_label}.${public_subdomain}"

  live_e2e_deployment_id="$(live_e2e_deployment_id_from_state "$state_file" "$app_instance_profile_name")"

  operator_roles_json="$(
    jq -cn '{}'
  )"
  operator_ami_id=""
  while IFS=$'\t' read -r operator_host operator_index; do
    [[ -n "$operator_host" ]] || continue
    operator_instance_json="$(legacy_instance_json_for_ip "$aws_profile" "$aws_region" "$operator_host")"
    operator_asg="$(
      jq -r '
        [
          .Reservations[0].Instances[0].Tags[]?
          | select(.Key == "aws:autoscaling:groupName")
          | .Value
        ][0] // empty
      ' <<<"$operator_instance_json"
    )"
    if [[ -z "$operator_asg" && "$shared_terraform_dir_rel" == "deploy/shared/terraform/live-e2e" ]]; then
      operator_asg="$(live_e2e_operator_asg_name "$live_e2e_deployment_id" "$operator_index")"
    fi
    operator_lt_id="$(jq -r '.Reservations[0].Instances[0].LaunchTemplate.LaunchTemplateId // empty' <<<"$operator_instance_json")"
    operator_lt_version="$(jq -r '.Reservations[0].Instances[0].LaunchTemplate.Version // empty' <<<"$operator_instance_json")"
    if [[ -n "$operator_asg" && -z "$operator_lt_id" ]]; then
      operator_lt_json="$(resolve_operator_launch_template_json_for_asg "$aws_profile" "$aws_region" "$operator_asg")"
      operator_lt_id="$(jq -r '.id // empty' <<<"$operator_lt_json")"
      operator_lt_version="$(jq -r '.version // empty' <<<"$operator_lt_json")"
    fi
    if [[ -z "$operator_ami_id" && -n "$operator_lt_id" ]]; then
      candidate_operator_ami_id="$(resolve_launch_template_image_id "$aws_profile" "$aws_region" "$operator_lt_id" "$operator_lt_version")"
      if [[ -n "$candidate_operator_ami_id" ]]; then
        operator_ami_id="$candidate_operator_ami_id"
      fi
    fi
    operator_roles_json="$(
      jq -cn \
        --argjson current "$operator_roles_json" \
        --arg operator_host "$operator_host" \
        --arg operator_asg "$operator_asg" \
        --arg operator_lt_id "$operator_lt_id" \
        --arg operator_lt_version "$operator_lt_version" '
          $current
          + {
              ($operator_host): {
                asg: $operator_asg,
                launch_template: (
                  if $operator_lt_id == "" then null else {
                    id: $operator_lt_id,
                    version: $operator_lt_version
                  } end
                )
              }
            }
        '
    )"
  done < <(jq -r '.operators[] | [(.operator_host // empty), ((.index // "") | tostring)] | @tsv' "$inventory_abs")

  wireguard_network_cidr="$(jq -r '.outputs.shared_wireguard_network_cidr.value // "10.66.0.0/24"' <<<"$state_json")"
  wireguard_listen_port="$(jq -r '.outputs.shared_wireguard_listen_port.value // 51820' <<<"$state_json")"
  wireguard_endpoint_host="$(jq -r '.outputs.shared_wireguard_endpoint_host.value // empty' <<<"$state_json")"
  wireguard_client_config_secret_arn="$(jq -r '.outputs.shared_wireguard_client_config_secret_arn.value // empty' <<<"$state_json")"

  upgraded_inventory="$tmp_dir/inventory.upgraded.json"
  jq \
    --arg vpc_id "$vpc_id" \
    --arg app_instance_profile_name "$app_instance_profile_name" \
    --arg bridge_cert_arn "$bridge_cert_arn" \
    --arg origin_cert_arn "$origin_cert_arn" \
    --arg backoffice_cert_arn "$backoffice_cert_arn" \
    --arg bridge_public_dns_label "$bridge_public_dns_label" \
    --arg backoffice_dns_label "$backoffice_dns_label" \
    --arg shared_terraform_dir_rel "$shared_terraform_dir_rel" \
    --arg aws_profile "$aws_profile" \
    --arg aws_region "$aws_region" \
    --argjson public_subnet_ids "$public_subnet_ids_json" \
    --argjson private_subnet_ids "$private_subnet_ids_json" \
    --arg wireguard_public_subnet_id "$wireguard_public_subnet_id" \
    --argjson wireguard_public_subnet_ids "$wireguard_public_subnet_ids_json" \
    --argjson wireguard_source_cidrs "$wireguard_source_cidrs_json" \
    --argjson wireguard_backoffice_private_endpoint_ips "$wireguard_backoffice_private_endpoint_ips_json" \
    --arg wireguard_network_cidr "$wireguard_network_cidr" \
    --arg wireguard_listen_port "$wireguard_listen_port" \
    --arg wireguard_endpoint_host "$wireguard_endpoint_host" \
    --arg wireguard_client_config_secret_arn "$wireguard_client_config_secret_arn" \
    --argjson operator_roles "$operator_roles_json" \
    '
      .version = "2"
      | .shared_services.terraform_dir = $shared_terraform_dir_rel
      | .app_role = (.app_role // {})
      | .app_role.host = (.app_host.host // "")
      | .app_role.user = (.app_host.user // "ubuntu")
      | .app_role.runtime_dir = (.app_host.runtime_dir // "/var/lib/intents-juno/app-runtime")
      | .app_role.terraform_dir = "deploy/shared/terraform/app-runtime"
      | .app_role.public_endpoint = (.app_host.public_endpoint // .app_host.host // "")
      | .app_role.private_endpoint = (.app_host.private_endpoint // "")
      | .app_role.vpc_id = $vpc_id
      | .app_role.public_subnet_ids = $public_subnet_ids
      | .app_role.private_subnet_ids = $private_subnet_ids
      | .app_role.app_instance_profile_name = $app_instance_profile_name
      | .app_role.aws_profile = (.app_host.aws_profile // $aws_profile)
      | .app_role.aws_region = (.app_host.aws_region // $aws_region)
      | .app_role.account_id = (.app_host.account_id // "")
      | .app_role.security_group_id = (.app_host.security_group_id // "")
      | .app_role.known_hosts_file = (.app_host.known_hosts_file // "")
      | .app_role.secret_contract_file = (.app_host.secret_contract_file // "")
      | .app_role.bridge_public_dns_label = (.app_host.bridge_public_dns_label // $bridge_public_dns_label)
      | .app_role.backoffice_dns_label = (.app_host.backoffice_dns_label // .app_host.ops_public_dns_label // $backoffice_dns_label)
      | .app_role.public_scheme = (.app_host.public_scheme // "https")
      | .app_role.public_bridge_certificate_arn = $origin_cert_arn
      | .app_role.public_bridge_additional_certificate_arns = [$bridge_cert_arn]
      | .app_role.internal_backoffice_certificate_arn = $backoffice_cert_arn
      | .app_role.bridge_api_listen = (.app_host.bridge_api_listen // "127.0.0.1:8082")
      | .app_role.backoffice_listen = (.app_host.backoffice_listen // "127.0.0.1:8090")
      | .app_role.juno_rpc_url = (.app_host.juno_rpc_url // "")
      | .app_role.service_urls = (.app_host.service_urls // [])
      | .app_role.operator_endpoints = (.app_host.operator_endpoints // [])
      | .app_role.publish_public_dns = false
      | .shared_roles = (.shared_roles // {})
      | .shared_roles.proof = (.shared_roles.proof // {})
      | if (.shared_roles.proof.rpc_url // "") == "" then
          .shared_roles.proof.rpc_url = "https://rpc.mainnet.succinct.xyz"
        else .
        end
      | .wireguard_role = (.wireguard_role // .shared_roles.wireguard // {})
      | .wireguard_role.public_subnet_id = $wireguard_public_subnet_id
      | .wireguard_role.public_subnet_ids = $wireguard_public_subnet_ids
      | .wireguard_role.listen_port = ($wireguard_listen_port | tonumber)
      | .wireguard_role.network_cidr = $wireguard_network_cidr
      | .wireguard_role.source_cidrs = $wireguard_source_cidrs
      | .wireguard_role.backoffice_hostname = ((.app_host.backoffice_dns_label // .app_host.ops_public_dns_label // $backoffice_dns_label) + "." + .shared_services.public_subdomain)
      | .wireguard_role.backoffice_private_endpoint = (.app_host.private_endpoint // "")
      | .wireguard_role.backoffice_private_endpoint_ips = $wireguard_backoffice_private_endpoint_ips
      | .wireguard_role.client_config_secret_arn = (if $wireguard_client_config_secret_arn == "" then (.wireguard_role.client_config_secret_arn // "") else $wireguard_client_config_secret_arn end)
      | .wireguard_role.endpoint_host = (if $wireguard_endpoint_host == "" then (.wireguard_role.endpoint_host // "") else $wireguard_endpoint_host end)
      | .wireguard_role.peer_roster_secret_arns = (.wireguard_role.peer_roster_secret_arns // [])
      | .wireguard_role.server_key_secret_arn = (.wireguard_role.server_key_secret_arn // "")
      | .wireguard_role.publish_public_dns = false
      | .shared_roles.wireguard = .wireguard_role
      | .operators = [
          .operators[]
          | . + {
              public_endpoint: (.public_endpoint // .operator_host),
              asg: (
                if (.asg // "") != "" then .asg
                else ($operator_roles[.operator_host].asg // "")
                end
              ),
              launch_template: (
                if (.launch_template // null) != null then .launch_template
                else ($operator_roles[.operator_host].launch_template // null)
                end
              )
            }
        ]
    ' "$inventory_abs" >"$upgraded_inventory"
fi

live_e2e_state_file=""
live_e2e_deployment_id=""
live_e2e_allowed_ssh_cidr=""
live_e2e_ssh_public_key=""
if [[ "$shared_terraform_dir_rel" == "deploy/shared/terraform/live-e2e" ]]; then
  live_e2e_state_file="$(find_live_e2e_state_file "$inventory_abs" "$inventory_dir" "$state_file" || true)"
  if [[ -n "$live_e2e_state_file" ]]; then
    live_e2e_deployment_id="$(live_e2e_deployment_id_from_state "$live_e2e_state_file" "$app_instance_profile_name")"
    live_e2e_allowed_ssh_cidr="$(live_e2e_allowed_ssh_cidr_from_state "$live_e2e_state_file")"
    live_e2e_ssh_public_key="$(live_e2e_ssh_public_key_from_state "$live_e2e_state_file")"
  else
    live_e2e_deployment_id="$(live_e2e_deployment_id_from_instance_profile "$app_instance_profile_name")"
  fi
fi

normalized_shared_terraform_inventory="$tmp_dir/inventory.shared-terraform-dir.json"
jq \
  --arg shared_terraform_dir_rel "$shared_terraform_dir_rel" \
  --arg live_e2e_deployment_id "$live_e2e_deployment_id" \
  --arg live_e2e_allowed_ssh_cidr "$live_e2e_allowed_ssh_cidr" \
  --arg live_e2e_ssh_public_key "$live_e2e_ssh_public_key" \
  --arg operator_ami_id "$operator_ami_id" \
  '
    .shared_services = (.shared_services // {})
    | .shared_services.terraform_dir = $shared_terraform_dir_rel
    | if $shared_terraform_dir_rel == "deploy/shared/terraform/live-e2e" then
        .shared_services.live_e2e = (
          (.shared_services.live_e2e // {})
          + (if $live_e2e_deployment_id == "" then {} else {deployment_id: $live_e2e_deployment_id} end)
          + (if $live_e2e_allowed_ssh_cidr == "" then {} else {allowed_ssh_cidr: $live_e2e_allowed_ssh_cidr} end)
          + (if $live_e2e_ssh_public_key == "" then {} else {ssh_public_key: $live_e2e_ssh_public_key} end)
          + (if $operator_ami_id == "" then {} else {operator_ami_id: $operator_ami_id} end)
        )
      else .
      end
  ' "$upgraded_inventory" >"$normalized_shared_terraform_inventory"
upgraded_inventory="$normalized_shared_terraform_inventory"

normalized_inventory="$tmp_dir/inventory.normalized.json"
normalize_preview_app_role_certificates "$upgraded_inventory" "$normalized_inventory"
upgraded_inventory="$normalized_inventory"

jq \
  --arg app_runtime_ami_release_tag "$app_runtime_ami_release_tag" \
  --arg shared_proof_services_image_release_tag "$shared_proof_services_image_release_tag" \
  --arg wireguard_role_ami_release_tag "$wireguard_role_ami_release_tag" '
    if $app_runtime_ami_release_tag != "" then
      .app_role.ami_release_tag = $app_runtime_ami_release_tag
    else . end
    | if $shared_proof_services_image_release_tag != "" then
        .shared_roles.proof.image_release_tag = $shared_proof_services_image_release_tag
      else . end
    | if $wireguard_role_ami_release_tag != "" then
        .shared_roles.wireguard.ami_release_tag = $wireguard_role_ami_release_tag
        | .wireguard_role.ami_release_tag = $wireguard_role_ami_release_tag
      else . end
  ' "$upgraded_inventory" >"$output"
