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
instance_refresh_poll_attempts="${PRODUCTION_PREVIEW_OPERATOR_INSTANCE_REFRESH_POLL_ATTEMPTS:-360}"
instance_refresh_poll_interval_seconds="${PRODUCTION_PREVIEW_OPERATOR_INSTANCE_REFRESH_POLL_INTERVAL_SECONDS:-5}"

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
shared_kafka_cluster_arn="$(jq -r '.shared_services.kafka.cluster_arn // empty' "$shared_manifest")"
shared_kafka_topic_arn_prefix=""
shared_kafka_group_arn_prefix=""
if [[ -n "$shared_kafka_cluster_arn" ]]; then
  shared_kafka_topic_arn_prefix="${shared_kafka_cluster_arn/:cluster\//:topic/}"
  shared_kafka_group_arn_prefix="${shared_kafka_cluster_arn/:cluster\//:group/}"
fi

declare -A shared_kafka_policy_roles=()

ensure_preview_shared_kafka_role_policy() {
  local instance_profile_arn="$1"
  local instance_profile_name role_name policy_document

  [[ -n "$shared_kafka_cluster_arn" ]] || return 0
  [[ -n "$instance_profile_arn" ]] || die "operator instance profile arn is required to update kafka access"

  instance_profile_name="${instance_profile_arn##*/}"
  [[ -n "$instance_profile_name" ]] || die "failed to derive instance profile name from arn: $instance_profile_arn"
  if [[ -n "${shared_kafka_policy_roles[$instance_profile_name]:-}" ]]; then
    return 0
  fi

  role_name="$(
    AWS_PAGER="" aws --profile "$aws_profile" iam get-instance-profile \
      --instance-profile-name "$instance_profile_name" \
      --output json \
      | jq -r '.InstanceProfile.Roles[0].RoleName // empty'
  )"
  [[ -n "$role_name" ]] || die "instance profile $instance_profile_name is missing a role binding"

  policy_document="$(
    jq -cn \
      --arg cluster_arn "$shared_kafka_cluster_arn" \
      --arg topic_arn "${shared_kafka_topic_arn_prefix}/*" \
      --arg group_arn "${shared_kafka_group_arn_prefix}/*" '
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "AllowSharedMSKConnect",
              Effect: "Allow",
              Action: [
                "kafka-cluster:Connect",
                "kafka-cluster:DescribeCluster",
                "kafka-cluster:DescribeClusterDynamicConfiguration"
              ],
              Resource: [$cluster_arn]
            },
            {
              Sid: "AllowSharedMSKTopicAccess",
              Effect: "Allow",
              Action: [
                "kafka-cluster:CreateTopic",
                "kafka-cluster:DescribeTopic",
                "kafka-cluster:DescribeTopicDynamicConfiguration",
                "kafka-cluster:AlterTopic",
                "kafka-cluster:ReadData",
                "kafka-cluster:WriteData",
                "kafka-cluster:WriteDataIdempotently"
              ],
              Resource: [$topic_arn]
            },
            {
              Sid: "AllowSharedMSKGroupAccess",
              Effect: "Allow",
              Action: [
                "kafka-cluster:AlterGroup",
                "kafka-cluster:DescribeGroup"
              ],
              Resource: [$group_arn]
            }
          ]
        }
      '
  )"

  AWS_PAGER="" aws --profile "$aws_profile" iam put-role-policy \
    --role-name "$role_name" \
    --policy-name "preview-shared-kafka-access" \
    --policy-document "$policy_document" >/dev/null

  shared_kafka_policy_roles[$instance_profile_name]="$role_name"
}

update_inventory_operator() {
  local inventory_file="$1"
  local operator_id="$2"
  local operator_asg="$3"
  local operator_host="$4"
  local public_endpoint="$5"
  local private_endpoint="$6"
  local launch_template_id="$7"
  local launch_template_version="$8"
  local known_hosts_file="$9"
  local tmp

  tmp="$(mktemp)"
  jq \
    --arg operator_id "$operator_id" \
    --arg operator_asg "$operator_asg" \
    --arg operator_host "$operator_host" \
    --arg public_endpoint "$public_endpoint" \
    --arg private_endpoint "$private_endpoint" \
    --arg launch_template_id "$launch_template_id" \
    --arg launch_template_version "$launch_template_version" \
    --arg known_hosts_file "$known_hosts_file" '
      .operators = [
        .operators[]
        | if .operator_id == $operator_id then
            .asg = $operator_asg
            | .operator_host = $operator_host
            | .public_endpoint = $public_endpoint
            | .private_endpoint = (if $private_endpoint == "" then null else $private_endpoint end)
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

describe_operator_instance_json() {
  local operator_public_ip="$1"
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
    --filters "Name=ip-address,Values=$operator_public_ip" \
    --output json
}

describe_operator_asg_json() {
  local operator_asg="$1"
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$operator_asg" \
    --output json
}

extract_operator_asg_name_from_asg_json() {
  local operator_asg_json="$1"
  jq -r '.AutoScalingGroups[0].AutoScalingGroupName // empty' <<<"$operator_asg_json"
}

extract_operator_asg_from_instance_json() {
  local operator_instance_json="$1"
  jq -r '.Reservations[0].Instances[0].Tags[]? | select(.Key == "aws:autoscaling:groupName") | .Value' <<<"$operator_instance_json" | head -n 1
}

extract_launch_template_id_from_asg_json() {
  local operator_asg_json="$1"
  jq -r '.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId // empty' <<<"$operator_asg_json"
}

extract_launch_template_version_from_asg_json() {
  local operator_asg_json="$1"
  jq -r '.AutoScalingGroups[0].LaunchTemplate.Version // empty' <<<"$operator_asg_json"
}

extract_launch_template_id_from_instance_json() {
  local operator_instance_json="$1"
  jq -r '.Reservations[0].Instances[0].LaunchTemplate.LaunchTemplateId // empty' <<<"$operator_instance_json"
}

extract_launch_template_version_from_instance_json() {
  local operator_instance_json="$1"
  jq -r '.Reservations[0].Instances[0].LaunchTemplate.Version // empty' <<<"$operator_instance_json"
}

create_operator_launch_template_version() {
  local launch_template_id="$1"
  local launch_template_version="$2"
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 create-launch-template-version \
    --launch-template-id "$launch_template_id" \
    --source-version "$launch_template_version" \
    --launch-template-data "{\"ImageId\":\"$operator_stack_ami_id\"}" \
    --output json
}

operator_results_json='[]'
while IFS= read -r operator_json; do
  operator_id="$(jq -r '.operator_id | select(type == "string" and length > 0)' <<<"$operator_json")"
  operator_asg="$(jq -r '.asg // empty' <<<"$operator_json")"
  launch_template_id="$(jq -r '.launch_template.id // empty' <<<"$operator_json")"
  launch_template_version="$(jq -r '.launch_template.version // empty' <<<"$operator_json")"
  operator_public_ip="$(jq -r '.public_endpoint // .operator_host // empty' <<<"$operator_json")"

  if [[ -z "$operator_asg" || -z "$launch_template_id" || -z "$launch_template_version" ]]; then
    if [[ -n "$operator_asg" ]]; then
      operator_asg_json="$(describe_operator_asg_json "$operator_asg")"
      if [[ -z "$launch_template_id" ]]; then
        launch_template_id="$(extract_launch_template_id_from_asg_json "$operator_asg_json")"
      fi
      if [[ -z "$launch_template_version" ]]; then
        launch_template_version="$(extract_launch_template_version_from_asg_json "$operator_asg_json")"
      fi
      operator_asg="$(extract_operator_asg_name_from_asg_json "$operator_asg_json")"
    fi
    if [[ -z "$operator_asg" || -z "$launch_template_id" || -z "$launch_template_version" ]]; then
      [[ -n "$operator_public_ip" ]] || die "operator $operator_id is missing public_endpoint/operator_host required for rollout metadata discovery"
      operator_instance_json="$(describe_operator_instance_json "$operator_public_ip")"
    fi
    if [[ -z "$operator_asg" ]]; then
      operator_asg="$(extract_operator_asg_from_instance_json "$operator_instance_json")"
    fi
    if [[ -z "$launch_template_id" ]]; then
      launch_template_id="$(extract_launch_template_id_from_instance_json "$operator_instance_json")"
    fi
    if [[ -z "$launch_template_version" ]]; then
      launch_template_version="$(extract_launch_template_version_from_instance_json "$operator_instance_json")"
    fi
  fi
  [[ -n "$operator_asg" ]] || die "operator $operator_id is missing an autoscaling group name"
  [[ -n "$launch_template_id" ]] || die "operator $operator_id is missing a launch template id"
  [[ -n "$launch_template_version" ]] || die "operator $operator_id is missing a launch template version"

  lt_error_file="$(mktemp)"
  if ! lt_response="$(create_operator_launch_template_version "$launch_template_id" "$launch_template_version" 2>"$lt_error_file")"; then
    lt_error="$(cat "$lt_error_file")"
    rm -f "$lt_error_file"
    refreshed_operator_asg=""
    refreshed_launch_template_id=""
    refreshed_launch_template_version=""

    if [[ -n "$operator_asg" ]]; then
      operator_asg_json="$(describe_operator_asg_json "$operator_asg")"
      refreshed_operator_asg="$(extract_operator_asg_name_from_asg_json "$operator_asg_json")"
      refreshed_launch_template_id="$(extract_launch_template_id_from_asg_json "$operator_asg_json")"
      refreshed_launch_template_version="$(extract_launch_template_version_from_asg_json "$operator_asg_json")"
    fi

    if [[ -z "$refreshed_operator_asg" || -z "$refreshed_launch_template_id" || -z "$refreshed_launch_template_version" ]]; then
      [[ -n "$operator_public_ip" ]] || die "operator $operator_id launch template rollout failed without a public endpoint for metadata rediscovery: $lt_error"
      operator_instance_json="$(describe_operator_instance_json "$operator_public_ip")"
      if [[ -z "$refreshed_operator_asg" ]]; then
        refreshed_operator_asg="$(extract_operator_asg_from_instance_json "$operator_instance_json")"
      fi
      if [[ -z "$refreshed_launch_template_id" ]]; then
        refreshed_launch_template_id="$(extract_launch_template_id_from_instance_json "$operator_instance_json")"
      fi
      if [[ -z "$refreshed_launch_template_version" ]]; then
        refreshed_launch_template_version="$(extract_launch_template_version_from_instance_json "$operator_instance_json")"
      fi
    fi

    [[ -n "$refreshed_operator_asg" ]] || die "operator $operator_id metadata rediscovery returned an empty autoscaling group after launch template failure: $lt_error"
    [[ -n "$refreshed_launch_template_id" ]] || die "operator $operator_id metadata rediscovery returned an empty launch template id after launch template failure: $lt_error"
    [[ -n "$refreshed_launch_template_version" ]] || die "operator $operator_id metadata rediscovery returned an empty launch template version after launch template failure: $lt_error"

    if [[ "$refreshed_operator_asg" == "$operator_asg" && "$refreshed_launch_template_id" == "$launch_template_id" && "$refreshed_launch_template_version" == "$launch_template_version" ]]; then
      die "operator $operator_id launch template rollout failed and rediscovery did not find newer metadata: $lt_error"
    fi

    operator_asg="$refreshed_operator_asg"
    launch_template_id="$refreshed_launch_template_id"
    launch_template_version="$refreshed_launch_template_version"

    lt_response="$(create_operator_launch_template_version "$launch_template_id" "$launch_template_version")" \
      || die "operator $operator_id launch template rollout still failed after rediscovery from $operator_public_ip"
  else
    rm -f "$lt_error_file"
  fi
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
  for _ in $(seq 1 "$instance_refresh_poll_attempts"); do
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
      *) sleep "$instance_refresh_poll_interval_seconds" ;;
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
  instance_profile_arn="$(jq -r '.Reservations[0].Instances[0].IamInstanceProfile.Arn // empty' <<<"$instance_json")"
  [[ -n "$operator_host" ]] || die "failed to resolve operator $operator_id public ip after the instance refresh"
  ensure_preview_shared_kafka_role_policy "$instance_profile_arn"

  operator_handoff_dir="$output_dir/operators/$operator_id"
  mkdir -p "$operator_handoff_dir"
  known_hosts_file="$operator_handoff_dir/known_hosts"
  ssh-keyscan -T 10 -H "$operator_host" >"$known_hosts_file"

  update_inventory_operator \
    "$working_inventory" \
    "$operator_id" \
    "$operator_asg" \
    "$operator_host" \
    "$operator_host" \
    "$operator_private_ip" \
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
mapfile -t operator_deploys < <(find "$output_dir/operators" -name operator-deploy.json | sort)
for operator_deploy in "${operator_deploys[@]}"; do
  "$deploy_operator_bin" --operator-deploy "$operator_deploy" </dev/null
  canary_output="${operator_deploy%/*}/boot-canary.json"
  "$canary_operator_boot_bin" --operator-deploy "$operator_deploy" </dev/null >"$canary_output"
  if [[ "$(jq -r '.ready_for_deploy // "false"' "$canary_output")" != "true" ]]; then
    ready_for_deploy="false"
  fi
done

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
