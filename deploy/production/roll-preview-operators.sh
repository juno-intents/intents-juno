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
  roll-preview-operators.sh [options]

Options:
  --inventory PATH                   Resolved preview inventory JSON (required)
  --shared-manifest PATH             Shared manifest JSON from the rebuilt preview (required)
  --dkg-summary PATH                 DKG summary JSON used to render operator handoffs (required)
  --operator-stack-ami-release-tag   Pinned operator stack AMI release tag (required)
  --output-dir DIR                   Output directory for rendered handoffs and evidence (required)
  --github-repo REPO                 GitHub repo for release downloads (default: juno-intents/intents-juno)
EOF
}

inventory=""
shared_manifest=""
dkg_summary=""
operator_stack_ami_release_tag=""
output_dir=""
github_repo="juno-intents/intents-juno"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --shared-manifest) shared_manifest="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --operator-stack-ami-release-tag) operator_stack_ami_release_tag="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --github-repo) github_repo="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
[[ -n "$operator_stack_ami_release_tag" ]] || die "--operator-stack-ami-release-tag is required"
[[ -n "$output_dir" ]] || die "--output-dir is required"

for cmd in jq aws gh ssh-keyscan; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

deploy_operator_bin="${PRODUCTION_DEPLOY_OPERATOR_BIN:-$SCRIPT_DIR/deploy-operator.sh}"
canary_operator_boot_bin="${PRODUCTION_CANARY_OPERATOR_BOOT_BIN:-$SCRIPT_DIR/canary-operator-boot.sh}"
[[ -x "$deploy_operator_bin" ]] || have_cmd "$deploy_operator_bin" || die "required command not found: $deploy_operator_bin"
[[ -x "$canary_operator_boot_bin" ]] || have_cmd "$canary_operator_boot_bin" || die "required command not found: $canary_operator_boot_bin"

mkdir -p "$output_dir"
output_dir="$(production_abs_path "$(pwd)" "$output_dir")"
release_tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$release_tmp_dir"
}
trap cleanup EXIT

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
working_inventory="$output_dir/inventory.operators-rolled.json"
cp "$inventory" "$working_inventory"

aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"

gh release download "$operator_stack_ami_release_tag" \
  --repo "$github_repo" \
  --pattern "operator-ami-manifest.json" \
  --pattern "operator-ami-manifest.json.sha256" \
  --dir "$release_tmp_dir" \
  --clobber
(
  cd "$release_tmp_dir"
  checksum_target="$(awk 'NR == 1 {print $2}' operator-ami-manifest.json.sha256)"
  if [[ -n "$checksum_target" && "$checksum_target" != "operator-ami-manifest.json" ]]; then
    mkdir -p "$(dirname "$checksum_target")"
    cp operator-ami-manifest.json "$checksum_target"
  fi
  sha256sum -c operator-ami-manifest.json.sha256 >/dev/null
)
operator_stack_ami_id="$(jq -r --arg region "$aws_region" '.regions[$region].ami_id // empty' "$release_tmp_dir/operator-ami-manifest.json")"
[[ -n "$operator_stack_ami_id" ]] || die "operator ami manifest is missing a region entry for $aws_region"

update_inventory_operator() {
  local inventory_file="$1"
  local operator_id="$2"
  local operator_host="$3"
  local public_endpoint="$4"
  local launch_template_id="$5"
  local launch_template_version="$6"
  local known_hosts_file="$7"
  local tmp

  tmp="$(mktemp)"
  jq \
    --arg operator_id "$operator_id" \
    --arg operator_host "$operator_host" \
    --arg public_endpoint "$public_endpoint" \
    --arg launch_template_id "$launch_template_id" \
    --arg launch_template_version "$launch_template_version" \
    --arg known_hosts_file "$known_hosts_file" '
      .operators = [
        .operators[]
        | if .operator_id == $operator_id then
            .operator_host = $operator_host
            | .public_endpoint = $public_endpoint
            | .known_hosts_file = $known_hosts_file
            | .launch_template = (
                (.launch_template // {})
                + {
                    id: $launch_template_id,
                    version: $launch_template_version
                  }
              )
          else
            .
          end
      ]
    ' "$inventory_file" >"$tmp"
  mv "$tmp" "$inventory_file"
}

operator_results_json='[]'
while IFS= read -r operator_json; do
  operator_id="$(jq -r '.operator_id | select(type == "string" and length > 0)' <<<"$operator_json")"
  operator_asg="$(jq -r '.asg | select(type == "string" and length > 0)' <<<"$operator_json")"
  launch_template_id="$(jq -r '.launch_template.id | select(type == "string" and length > 0)' <<<"$operator_json")"
  launch_template_version="$(jq -r '.launch_template.version | select(type == "string" and length > 0)' <<<"$operator_json")"

  lt_response="$(
    AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 create-launch-template-version \
      --launch-template-id "$launch_template_id" \
      --source-version "$launch_template_version" \
      --launch-template-data "{\"ImageId\":\"$operator_stack_ami_id\"}" \
      --output json
  )"
  new_launch_template_version="$(jq -r '.LaunchTemplateVersion.VersionNumber' <<<"$lt_response")"
  [[ -n "$new_launch_template_version" ]] || die "failed to resolve the new launch template version for operator $operator_id"

  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling update-auto-scaling-group \
    --auto-scaling-group-name "$operator_asg" \
    --launch-template "LaunchTemplateId=$launch_template_id,Version=$new_launch_template_version" >/dev/null

  refresh_id="$(
    AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling start-instance-refresh \
      --auto-scaling-group-name "$operator_asg" \
      --preferences '{"MinHealthyPercentage":100}' \
      --output json \
      | jq -r '.InstanceRefreshId // empty'
  )"
  [[ -n "$refresh_id" ]] || die "failed to start the instance refresh for operator $operator_id"

  refresh_status=""
  for _ in $(seq 1 60); do
    refresh_status="$(
      AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling describe-instance-refreshes \
        --auto-scaling-group-name "$operator_asg" \
        --instance-refresh-ids "$refresh_id" \
        --output json \
        | jq -r '.InstanceRefreshes[0].Status // empty'
    )"
    case "$refresh_status" in
      Successful) break ;;
      Failed|Cancelled) die "instance refresh failed for operator $operator_id: $refresh_status" ;;
      *) sleep 5 ;;
    esac
  done
  [[ "$refresh_status" == "Successful" ]] || die "instance refresh did not complete successfully for operator $operator_id"

  asg_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$operator_asg" \
    --output json)"
  instance_id="$(jq -r '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy")][0].InstanceId // empty' <<<"$asg_json")"
  [[ -n "$instance_id" ]] || die "operator $operator_id asg $operator_asg did not expose a healthy instance id"

  instance_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
    --instance-ids "$instance_id" \
    --output json)"
  operator_host="$(jq -r '.Reservations[0].Instances[0].PublicIpAddress // empty' <<<"$instance_json")"
  operator_private_ip="$(jq -r '.Reservations[0].Instances[0].PrivateIpAddress // empty' <<<"$instance_json")"
  [[ -n "$operator_host" ]] || die "failed to resolve operator $operator_id public ip after the instance refresh"

  operator_handoff_dir="$output_dir/operators/$operator_id"
  mkdir -p "$operator_handoff_dir"
  known_hosts_file="$operator_handoff_dir/known_hosts"
  ssh-keyscan -H "$operator_host" >"$known_hosts_file"

  update_inventory_operator \
    "$working_inventory" \
    "$operator_id" \
    "$operator_host" \
    "$operator_host" \
    "$launch_template_id" \
    "$new_launch_template_version" \
    "$known_hosts_file"

  operator_results_json="$(
    jq -cn \
      --argjson current "$operator_results_json" \
      --arg operator_id "$operator_id" \
      --arg operator_asg "$operator_asg" \
      --arg refresh_id "$refresh_id" \
      --arg instance_id "$instance_id" \
      --arg operator_host "$operator_host" \
      --arg operator_private_ip "$operator_private_ip" \
      --argjson launch_template_version "$new_launch_template_version" '
        $current + [{
          operator_id: $operator_id,
          asg: $operator_asg,
          refresh_id: $refresh_id,
          instance_id: $instance_id,
          operator_host: $operator_host,
          operator_private_ip: $operator_private_ip,
          launch_template_version: $launch_template_version
        }]
      '
  )"
done < <(jq -c '.operators[]' "$working_inventory")

production_render_operator_handoffs "$working_inventory" "$shared_manifest" "$dkg_summary" "$output_dir" "$inventory_dir"

ready_for_deploy="true"
while IFS= read -r operator_deploy; do
  "$deploy_operator_bin" --operator-deploy "$operator_deploy"
  canary_output="${operator_deploy%/*}/boot-canary.json"
  "$canary_operator_boot_bin" --operator-deploy "$operator_deploy" >"$canary_output"
  if [[ "$(jq -r '.ready_for_deploy // "false"' "$canary_output")" != "true" ]]; then
    ready_for_deploy="false"
  fi
done < <(find "$output_dir/operators" -name operator-deploy.json | sort)

jq -n \
  --arg operator_stack_ami_release_tag "$operator_stack_ami_release_tag" \
  --arg operator_stack_ami_id "$operator_stack_ami_id" \
  --arg inventory_path "$working_inventory" \
  --argjson operators "$operator_results_json" \
  --arg ready_for_deploy "$ready_for_deploy" '
    {
      ready_for_deploy: ($ready_for_deploy == "true"),
      operator_stack_ami_release_tag: $operator_stack_ami_release_tag,
      operator_stack_ami_id: $operator_stack_ami_id,
      inventory_path: $inventory_path,
      operators: $operators
    }
  '
