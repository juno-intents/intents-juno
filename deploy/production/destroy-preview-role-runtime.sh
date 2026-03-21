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
cloudfront_poll_interval_seconds="${PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_INTERVAL_SECONDS:-10}"
cloudfront_poll_attempts="${PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_ATTEMPTS:-120}"
app_asg_poll_interval_seconds="${PRODUCTION_PREVIEW_APP_ASG_POLL_INTERVAL_SECONDS:-5}"
app_asg_poll_attempts="${PRODUCTION_PREVIEW_APP_ASG_POLL_ATTEMPTS:-120}"
shared_cleanup_poll_interval_seconds="${PRODUCTION_PREVIEW_SHARED_CLEANUP_POLL_INTERVAL_SECONDS:-5}"
shared_cleanup_poll_attempts="${PRODUCTION_PREVIEW_SHARED_CLEANUP_POLL_ATTEMPTS:-60}"

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
production_maybe_use_public_sts_endpoint "$aws_region"
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

shared_name_prefix="$(production_json_optional "$inventory" '.shared_services.name_prefix')"
if [[ -z "$shared_name_prefix" ]]; then
  shared_name_prefix="intents-juno-shared"
fi
shared_resource_name="${shared_name_prefix}-${env_slug}"
shared_resource_slug="$(production_safe_slug "$shared_resource_name")"
shared_postgres_cluster_id="${shared_resource_name}-shared-aurora"
shared_postgres_backup_vault_name="${shared_resource_name}-shared-postgres"
shared_postgres_dr_region="$(production_json_optional "$inventory" '.shared_services.postgres_dr_region')"
if [[ -z "$shared_postgres_dr_region" ]]; then
  shared_postgres_dr_region="$(production_json_optional "$inventory" '.shared_postgres_dr_region')"
fi
if [[ -z "$shared_postgres_dr_region" ]]; then
  shared_postgres_dr_region="us-west-2"
fi
shared_postgres_backup_vault_dr_name="${shared_resource_name}-shared-postgres-dr"
shared_cloudtrail_bucket_name="${shared_resource_slug}-trail"
shared_cloudtrail_trail_name="${shared_resource_slug}-trail"

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

cloudfront_distribution_id_from_state() {
  local edge_state_path="$1"
  terraform state show -no-color -state="$edge_state_path" aws_cloudfront_distribution.bridge 2>/dev/null \
    | awk -F' = ' '/^[[:space:]]*id[[:space:]]*=/ { gsub(/"/, "", $2); print $2; exit }'
}

cloudfront_sleep() {
  if [[ "$cloudfront_poll_interval_seconds" =~ ^[0-9]+$ ]] && [[ "$cloudfront_poll_interval_seconds" -gt 0 ]]; then
    sleep "$cloudfront_poll_interval_seconds"
  fi
}

cloudfront_wait_disabled() {
  local distribution_id="$1"
  local attempt output status enabled

  for ((attempt = 1; attempt <= cloudfront_poll_attempts; attempt++)); do
    output="$(aws cloudfront get-distribution \
      --profile "$aws_profile" \
      --id "$distribution_id" \
      --output json)"
    status="$(jq -r '.Distribution.Status' <<<"$output")"
    enabled="$(jq -r '.Distribution.DistributionConfig.Enabled' <<<"$output")"
    if [[ "$status" == "Deployed" && "$enabled" == "false" ]]; then
      return 0
    fi
    cloudfront_sleep
  done

  die "timed out waiting for cloudfront distribution $distribution_id to disable"
}

cloudfront_wait_deleted() {
  local distribution_id="$1"
  local attempt output

  for ((attempt = 1; attempt <= cloudfront_poll_attempts; attempt++)); do
    if output="$(aws cloudfront get-distribution \
      --profile "$aws_profile" \
      --id "$distribution_id" \
      --output json 2>&1)"; then
      cloudfront_sleep
      continue
    fi

    if [[ "$output" == *"NoSuchDistribution"* ]]; then
      return 0
    fi

    die "failed to query cloudfront distribution $distribution_id deletion status: $output"
  done

  die "timed out waiting for cloudfront distribution $distribution_id to delete"
}

destroy_edge_cloudfront_distribution() {
  local edge_state_path="$1"
  local distribution_id config_json enabled etag config_file

  distribution_id="$(cloudfront_distribution_id_from_state "$edge_state_path" || true)"
  [[ -n "$distribution_id" ]] || return 0

  if ! config_json="$(aws cloudfront get-distribution-config \
    --profile "$aws_profile" \
    --id "$distribution_id" \
    --output json 2>&1)"; then
    [[ "$config_json" == *"NoSuchDistribution"* ]] && return 0
    die "failed to read cloudfront distribution $distribution_id config: $config_json"
  fi

  enabled="$(jq -r '.DistributionConfig.Enabled' <<<"$config_json")"
  if [[ "$enabled" == "true" ]]; then
    etag="$(jq -r '.ETag' <<<"$config_json")"
    config_file="$(mktemp)"
    jq '.DistributionConfig.Enabled = false | .DistributionConfig' <<<"$config_json" >"$config_file"
    aws cloudfront update-distribution \
      --profile "$aws_profile" \
      --id "$distribution_id" \
      --if-match "$etag" \
      --distribution-config "file://$config_file" \
      >/dev/null
    rm -f "$config_file"
    cloudfront_wait_disabled "$distribution_id"
  fi

  if ! config_json="$(aws cloudfront get-distribution-config \
    --profile "$aws_profile" \
    --id "$distribution_id" \
    --output json 2>&1)"; then
    [[ "$config_json" == *"NoSuchDistribution"* ]] && return 0
    die "failed to reload cloudfront distribution $distribution_id config before delete: $config_json"
  fi

  etag="$(jq -r '.ETag' <<<"$config_json")"
  aws cloudfront delete-distribution \
    --profile "$aws_profile" \
    --id "$distribution_id" \
    --if-match "$etag" \
    >/dev/null
  cloudfront_wait_deleted "$distribution_id"
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
    destroy_edge_cloudfront_distribution "$edge_state_path"
    terraform destroy -auto-approve -input=false -state="$edge_state_path" -var-file="$edge_var_file"
  )
}

app_asg_sleep() {
  if [[ "$app_asg_poll_interval_seconds" =~ ^[0-9]+$ ]] && [[ "$app_asg_poll_interval_seconds" -gt 0 ]]; then
    sleep "$app_asg_poll_interval_seconds"
  fi
}

shared_cleanup_sleep() {
  if [[ "$shared_cleanup_poll_interval_seconds" =~ ^[0-9]+$ ]] && [[ "$shared_cleanup_poll_interval_seconds" -gt 0 ]]; then
    sleep "$shared_cleanup_poll_interval_seconds"
  fi
}

app_runtime_output_json() {
  terraform output -json
}

app_runtime_asg_name_from_outputs() {
  local output_json="$1"
  jq -r '.app_role.value.asg // .app_role_asg_name.value // empty' <<<"$output_json"
}

discover_app_runtime_security_group_id() {
  local security_group_id

  security_group_id="$(aws ec2 describe-security-groups \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --filters "Name=group-name,Values=juno-app-runtime-${env_slug}-app" \
    --query 'SecurityGroups[].GroupId' \
    --output text 2>/dev/null || true)"
  security_group_id="${security_group_id//$'\r'/}"
  security_group_id="${security_group_id//None/}"
  printf '%s\n' "$security_group_id"
}

app_runtime_security_group_id_from_outputs() {
  local output_json="$1"
  local security_group_id

  security_group_id="$(jq -r '.app_security_group_id.value // empty' <<<"$output_json")"
  if [[ -z "$security_group_id" ]]; then
    security_group_id="$(discover_app_runtime_security_group_id)"
  fi
  printf '%s\n' "$security_group_id"
}

app_runtime_asg_instance_ids() {
  local asg_name="$1"
  local ids

  ids="$(aws autoscaling describe-auto-scaling-groups \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --auto-scaling-group-names "$asg_name" \
    --query 'AutoScalingGroups[0].Instances[].InstanceId' \
    --output text 2>/dev/null || true)"
  ids="${ids//$'\r'/}"
  ids="${ids//None/}"
  printf '%s\n' "$ids"
}

wait_for_app_runtime_asg_empty() {
  local asg_name="$1"
  local attempt ids

  for ((attempt = 1; attempt <= app_asg_poll_attempts; attempt++)); do
    ids="$(app_runtime_asg_instance_ids "$asg_name")"
    if [[ -z "${ids//[[:space:]]/}" ]]; then
      return 0
    fi
    app_asg_sleep
  done

  die "timed out waiting for app runtime asg $asg_name instances to terminate"
}

revoke_app_runtime_security_group_references() {
  local output_json="$1"
  local app_security_group_id group_ids_text rule_ids_text group_id
  local -a group_ids=()
  local -a rule_ids=()

  app_security_group_id="$(app_runtime_security_group_id_from_outputs "$output_json")"
  [[ -n "$app_security_group_id" ]] || return 0

  group_ids_text="$(aws ec2 describe-security-groups \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --filters "Name=ip-permission.group-id,Values=$app_security_group_id" \
    --query 'SecurityGroups[].GroupId' \
    --output text 2>/dev/null || true)"
  group_ids_text="${group_ids_text//$'\r'/}"
  group_ids_text="${group_ids_text//None/}"
  if [[ -z "${group_ids_text//[[:space:]]/}" ]]; then
    return 0
  fi

  # shellcheck disable=SC2206
  group_ids=( $group_ids_text )
  for group_id in "${group_ids[@]}"; do
    rule_ids_text="$(aws ec2 describe-security-group-rules \
      --profile "$aws_profile" \
      --region "$aws_region" \
      --filters "Name=group-id,Values=$group_id" \
      --query "SecurityGroupRules[?IsEgress==\`false\` && ReferencedGroupInfo.GroupId==\`$app_security_group_id\`].SecurityGroupRuleId" \
      --output text 2>/dev/null || true)"
    rule_ids_text="${rule_ids_text//$'\r'/}"
    rule_ids_text="${rule_ids_text//None/}"
    if [[ -z "${rule_ids_text//[[:space:]]/}" ]]; then
      continue
    fi

    # shellcheck disable=SC2206
    rule_ids=( $rule_ids_text )
    if [[ ${#rule_ids[@]} -eq 0 ]]; then
      continue
    fi

    aws ec2 revoke-security-group-ingress \
      --profile "$aws_profile" \
      --region "$aws_region" \
      --group-id "$group_id" \
      --security-group-rule-ids "${rule_ids[@]}" >/dev/null
  done
}

drain_app_runtime_asg() {
  local output_json="$1"
  local asg_name ids_text
  local -a instance_ids=()

  asg_name="$(app_runtime_asg_name_from_outputs "$output_json")"
  [[ -n "$asg_name" ]] || return 0

  aws autoscaling update-auto-scaling-group \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --auto-scaling-group-name "$asg_name" \
    --min-size 0 \
    --max-size 0 \
    --desired-capacity 0 >/dev/null

  ids_text="$(app_runtime_asg_instance_ids "$asg_name")"
  if [[ -z "${ids_text//[[:space:]]/}" ]]; then
    return 0
  fi

  # shellcheck disable=SC2206
  instance_ids=( $ids_text )
  if [[ ${#instance_ids[@]} -eq 0 ]]; then
    return 0
  fi

  aws ec2 terminate-instances \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --instance-ids "${instance_ids[@]}" >/dev/null
  aws ec2 wait instance-terminated \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --instance-ids "${instance_ids[@]}"
  wait_for_app_runtime_asg_empty "$asg_name"
}

shared_postgres_cluster_json() {
  aws rds describe-db-clusters \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --db-cluster-identifier "$shared_postgres_cluster_id" \
    --output json 2>/dev/null || true
}

disable_shared_postgres_deletion_protection() {
  local cluster_json deletion_protection status attempt

  cluster_json="$(shared_postgres_cluster_json)"
  [[ -n "$cluster_json" ]] || return 0
  status="$(jq -r '.DBClusters[0].Status // empty' <<<"$cluster_json")"
  [[ -n "$status" ]] || return 0
  [[ "$status" == "deleting" ]] && return 0
  deletion_protection="$(jq -r '.DBClusters[0].DeletionProtection // false' <<<"$cluster_json")"
  [[ "$deletion_protection" == "true" ]] || return 0

  aws rds modify-db-cluster \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --db-cluster-identifier "$shared_postgres_cluster_id" \
    --no-deletion-protection \
    --apply-immediately >/dev/null

  for ((attempt = 1; attempt <= shared_cleanup_poll_attempts; attempt++)); do
    cluster_json="$(shared_postgres_cluster_json)"
    [[ -n "$cluster_json" ]] || return 0
    status="$(jq -r '.DBClusters[0].Status // empty' <<<"$cluster_json")"
    deletion_protection="$(jq -r '.DBClusters[0].DeletionProtection // false' <<<"$cluster_json")"
    if [[ -z "$status" || "$status" == "deleting" || "$deletion_protection" != "true" ]]; then
      return 0
    fi
    shared_cleanup_sleep
  done

  die "timed out waiting for shared aurora deletion protection to disable"
}

backup_vault_recovery_points_json() {
  local aws_region_override="$1"
  local backup_vault_name="$2"

  aws backup list-recovery-points-by-backup-vault \
    --profile "$aws_profile" \
    --region "$aws_region_override" \
    --backup-vault-name "$backup_vault_name" \
    --output json 2>/dev/null || true
}

purge_backup_vault_recovery_points() {
  local aws_region_override="$1"
  local backup_vault_name="$2"
  local recovery_points_json delete_json delete_file attempt
  local -a recovery_point_arns=()

  recovery_points_json="$(backup_vault_recovery_points_json "$aws_region_override" "$backup_vault_name")"
  [[ -n "$recovery_points_json" ]] || return 0
  mapfile -t recovery_point_arns < <(jq -r '.RecoveryPoints[]?.RecoveryPointArn // empty' <<<"$recovery_points_json")
  if [[ ${#recovery_point_arns[@]} -eq 0 ]]; then
    return 0
  fi

  for recovery_point_arn in "${recovery_point_arns[@]}"; do
    [[ -n "$recovery_point_arn" ]] || continue
    aws backup delete-recovery-point \
      --profile "$aws_profile" \
      --region "$aws_region_override" \
      --backup-vault-name "$backup_vault_name" \
      --recovery-point-arn "$recovery_point_arn" >/dev/null
  done

  for ((attempt = 1; attempt <= shared_cleanup_poll_attempts; attempt++)); do
    recovery_points_json="$(backup_vault_recovery_points_json "$aws_region_override" "$backup_vault_name")"
    [[ -n "$recovery_points_json" ]] || return 0
    delete_json="$(jq -c '[.RecoveryPoints[]?.RecoveryPointArn // empty] | map(select(length > 0))' <<<"$recovery_points_json")"
    if [[ "$delete_json" == "[]" ]]; then
      return 0
    fi
    shared_cleanup_sleep
  done

  die "timed out waiting for backup vault $backup_vault_name recovery points to delete"
}

stop_shared_cloudtrail_logging() {
  aws cloudtrail stop-logging \
    --profile "$aws_profile" \
    --region "$aws_region" \
    --name "$shared_cloudtrail_trail_name" >/dev/null 2>&1 || true
}

empty_shared_cloudtrail_bucket() {
  local versions_json delete_file objects_json batch_json object_count offset

  while true; do
    versions_json="$(aws s3api list-object-versions \
      --profile "$aws_profile" \
      --region "$aws_region" \
      --bucket "$shared_cloudtrail_bucket_name" \
      --output json 2>/dev/null || true)"
    [[ -n "$versions_json" ]] || return 0

    objects_json="$(jq -c '[.Versions[]?, .DeleteMarkers[]?] | map({Key, VersionId})' <<<"$versions_json")"
    object_count="$(jq -r 'length' <<<"$objects_json")"
    if [[ "$object_count" == "0" ]]; then
      return 0
    fi

    for ((offset = 0; offset < object_count; offset += 1000)); do
      batch_json="$(jq -c --argjson offset "$offset" --argjson limit 1000 '{Objects: (.[ $offset : ($offset + $limit) ]), Quiet: true}' <<<"$objects_json")"
      delete_file="$(mktemp)"
      printf '%s\n' "$batch_json" >"$delete_file"
      aws s3api delete-objects \
        --profile "$aws_profile" \
        --region "$aws_region" \
        --bucket "$shared_cloudtrail_bucket_name" \
        --delete "file://$delete_file" >/dev/null
      rm -f "$delete_file"
    done
  done
}

prepare_shared_runtime_destroy() {
  disable_shared_postgres_deletion_protection
  purge_backup_vault_recovery_points "$aws_region" "$shared_postgres_backup_vault_name"
  purge_backup_vault_recovery_points "$shared_postgres_dr_region" "$shared_postgres_backup_vault_dr_name"
  stop_shared_cloudtrail_logging
  empty_shared_cloudtrail_bucket
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
  app_runtime_outputs="$(app_runtime_output_json)"
  drain_app_runtime_asg "$app_runtime_outputs"
  revoke_app_runtime_security_group_references "$app_runtime_outputs"
  terraform destroy -auto-approve -input=false -var-file="$app_var_file"
)

(
  cd "$shared_terraform_dir"
  prepare_shared_runtime_destroy
  terraform init -input=false -reconfigure \
    -backend-config="bucket=$shared_bucket" \
    -backend-config="dynamodb_table=$shared_table" \
    -backend-config="key=$shared_key" \
    -backend-config="region=$aws_region" >/dev/null
  terraform destroy -auto-approve -input=false -var-file="$shared_var_file"
)
