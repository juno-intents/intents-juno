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
  rebuild-preview-role-runtime.sh [options]

Options:
  --inventory PATH                             Preview inventory JSON (required)
  --current-output-root DIR                    Current preview output root used for destroy/handoff discovery
  --dkg-summary PATH                           DKG summary JSON (required)
  --dkg-completion PATH                        Optional DKG completion JSON
  --bridge-deploy-binary PATH                  Released bridge-deploy binary (required unless reusing bridge)
  --deployer-key-file PATH                     Bridge deployer key file
  --funder-key-file PATH                       Bridge deploy ephemeral funder key
  --ephemeral-funding-amount-wei AMOUNT        Bridge deploy ephemeral funding amount
  --existing-bridge-summary PATH               Optional bridge summary reuse path
  --app-runtime-ami-release-tag TAG            Pinned app runtime AMI release tag (required)
  --shared-proof-services-image-release-tag TAG Pinned shared proof image release tag (required)
  --wireguard-role-ami-release-tag TAG         Pinned wireguard role AMI release tag (required)
  --operator-stack-ami-release-tag TAG         Pinned operator stack AMI release tag (required)
  --shared-infra-e2e-binary PATH               Released shared-infra-e2e binary (required)
  --github-repo REPO                           GitHub repo for release resolution (default: juno-intents/intents-juno)
  --output-dir DIR                             Output directory (default: ./preview-reset-output)
EOF
}

find_latest_clean_preview_bridge_summary() {
  local current_output_root="$1"
  local env_slug="$2"
  local preview_output_root candidate

  preview_output_root="$current_output_root/$env_slug"
  [[ -d "$preview_output_root" ]] || return 0

  candidate="$(
    find "$preview_output_root" -maxdepth 2 -type f -path '*/clean-preview-r*/bridge-summary.json' \
      | LC_ALL=C sort -V \
      | tail -n1
  )"
  [[ -n "$candidate" ]] || return 0
  printf '%s\n' "$candidate"
}

find_lowest_index_operator_deploy() {
  local operator_rollout_dir="$1"
  local operator_deploy_path operator_index
  local selected_path=""
  local selected_index=""

  while IFS= read -r operator_deploy_path; do
    operator_index="$(jq -r '.operator_index // empty' "$operator_deploy_path")"
    if [[ "$operator_index" =~ ^[0-9]+$ ]]; then
      if [[ -z "$selected_index" || "$operator_index" -lt "$selected_index" ]]; then
        selected_index="$operator_index"
        selected_path="$operator_deploy_path"
      fi
    fi
  done < <(find "$operator_rollout_dir" -name operator-deploy.json | sort)

  if [[ -n "$selected_path" ]]; then
    printf '%s\n' "$selected_path"
    return 0
  fi

  find "$operator_rollout_dir" -name operator-deploy.json | sort | head -n1
}

inventory=""
current_output_root_override=""
dkg_summary=""
dkg_completion=""
bridge_deploy_binary=""
deployer_key_file=""
funder_key_file=""
ephemeral_funding_amount_wei=""
existing_bridge_summary=""
app_runtime_ami_release_tag=""
shared_proof_services_image_release_tag=""
wireguard_role_ami_release_tag=""
operator_stack_ami_release_tag=""
shared_infra_e2e_binary=""
github_repo="juno-intents/intents-juno"
output_root="./preview-reset-output"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --current-output-root) current_output_root_override="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --dkg-completion) dkg_completion="$2"; shift 2 ;;
    --bridge-deploy-binary) bridge_deploy_binary="$2"; shift 2 ;;
    --deployer-key-file) deployer_key_file="$2"; shift 2 ;;
    --funder-key-file) funder_key_file="$2"; shift 2 ;;
    --ephemeral-funding-amount-wei) ephemeral_funding_amount_wei="$2"; shift 2 ;;
    --existing-bridge-summary) existing_bridge_summary="$2"; shift 2 ;;
    --app-runtime-ami-release-tag) app_runtime_ami_release_tag="$2"; shift 2 ;;
    --shared-proof-services-image-release-tag) shared_proof_services_image_release_tag="$2"; shift 2 ;;
    --wireguard-role-ami-release-tag) wireguard_role_ami_release_tag="$2"; shift 2 ;;
    --operator-stack-ami-release-tag) operator_stack_ami_release_tag="$2"; shift 2 ;;
    --shared-infra-e2e-binary) shared_infra_e2e_binary="$2"; shift 2 ;;
    --github-repo) github_repo="$2"; shift 2 ;;
    --output-dir) output_root="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

normalize_preview_inventory_local_paths() {
  local source_inventory="$1"
  local target_inventory="$2"
  local source_inventory_dir tmp_inventory

  source_inventory_dir="$(dirname "$(production_abs_path "$(pwd)" "$source_inventory")")"
  tmp_inventory="$(mktemp)"
  jq --arg source_inventory_dir "$source_inventory_dir" '
    def abs_source_path:
      if type == "string" and length > 0 then
        if startswith("/") then . else ($source_inventory_dir + "/" + .) end
      else .
      end;
    .dkg_tls_dir |= (if . == null then . else abs_source_path end)
    | if .app_role != null then
        .app_role.known_hosts_file |= (if . == null then . else abs_source_path end)
        | .app_role.secret_contract_file |= (if . == null then . else abs_source_path end)
      else .
      end
    | if .app_host != null then
        .app_host.known_hosts_file |= (if . == null then . else abs_source_path end)
        | .app_host.secret_contract_file |= (if . == null then . else abs_source_path end)
      else .
      end
    | .operators = (
        (.operators // [])
        | map(
            .known_hosts_file |= (if . == null then . else abs_source_path end)
            | .secret_contract_file |= (if . == null then . else abs_source_path end)
            | .dkg_backup_zip |= (if . == null then . else abs_source_path end)
          )
      )
  ' "$target_inventory" >"$tmp_inventory"
  mv "$tmp_inventory" "$target_inventory"
}

ssm_run_shell_command() {
  local aws_profile="$1"
  local aws_region="$2"
  local instance_id="$3"
  local command="$4"
  local send_json command_id invocation_json invocation_status stderr stdout parameters_json

  parameters_json="$(jq -cn --arg command "$command" '{commands: [$command]}')"

  send_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --parameters "$parameters_json" \
    --output json 2>/dev/null || true)"
  [[ -n "$send_json" ]] || return 1
  command_id="$(jq -r '.Command.CommandId // empty' <<<"$send_json")"
  [[ -n "$command_id" ]] || return 1

  for _ in $(seq 1 120); do
    invocation_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ssm get-command-invocation \
      --command-id "$command_id" \
      --instance-id "$instance_id" \
      --output json 2>/dev/null || true)"
    [[ -n "$invocation_json" ]] || {
      sleep 2
      continue
    }

    invocation_status="$(jq -r '.Status // empty' <<<"$invocation_json")"
    case "$invocation_status" in
      Success)
        stdout="$(jq -r '.StandardOutputContent // ""' <<<"$invocation_json")"
        printf '%s' "$stdout"
        return 0
        ;;
      Failed|Cancelled|TimedOut|Cancelling)
        stderr="$(jq -r '.StandardErrorContent // ""' <<<"$invocation_json")"
        stdout="$(jq -r '.StandardOutputContent // ""' <<<"$invocation_json")"
        [[ -n "$stderr" ]] && printf '%s\n' "$stderr" >&2
        [[ -n "$stdout" ]] && printf '%s\n' "$stdout" >&2
        return 1
        ;;
      Pending|InProgress|Delayed|"")
        sleep 2
        ;;
      *)
        sleep 2
        ;;
    esac
  done

  return 1
}

production_shell_quote() {
  local value="$1"
  jq -rn --arg value "$value" '$value | @sh'
}

run_shared_infra_e2e() {
  local app_deploy="$1"
  local shared_manifest="$2"
  local binary="$3"
  local postgres_dsn="$4"
  local required_topics="$5"
  local output_path="$6"
  local kafka_brokers ipfs_api_url checkpoint_operators checkpoint_threshold
  local kafka_tls kafka_auth_mode kafka_auth_region
  local shared_aws_profile shared_aws_region ipfs_api_auth_secret_arn ipfs_api_bearer_token
  local app_role_asg app_aws_profile app_aws_region asg_json instance_id
  local checkpoint_blob_bucket stage_key stage_uri presigned_url stdout_json
  local url_q pg_q kb_q topics_q ipfs_q operators_q threshold_q output_q remote_env_prefix remote_cmd

  kafka_brokers="$(jq -r '.shared_services.kafka.bootstrap_brokers' "$shared_manifest")"
  ipfs_api_url="$(jq -r '.shared_services.ipfs.api_url' "$shared_manifest")"
  shared_aws_profile="$(production_json_optional "$shared_manifest" '.shared_services.aws_profile')"
  shared_aws_region="$(production_json_optional "$shared_manifest" '.shared_services.aws_region')"
  ipfs_api_auth_secret_arn="$(production_json_optional "$shared_manifest" '.shared_services.ipfs.api_auth_secret_arn')"
  ipfs_api_bearer_token=""
  if [[ -n "$ipfs_api_auth_secret_arn" ]]; then
    ipfs_api_bearer_token="$(production_resolve_optional_aws_sm_secret "$ipfs_api_auth_secret_arn" "$shared_aws_profile" "$shared_aws_region")"
  fi
  checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
  checkpoint_threshold="$(jq -r '.checkpoint.threshold' "$shared_manifest")"
  kafka_tls="$(jq -r 'if (.shared_services.kafka.tls // false) then "true" else "false" end' "$shared_manifest")"
  kafka_auth_mode="$(jq -r '.shared_services.kafka.auth.mode // empty' "$shared_manifest")"
  kafka_auth_region="$(jq -r '.shared_services.kafka.auth.aws_region // empty' "$shared_manifest")"

  app_role_asg="$(jq -r '.app_role.asg // empty' "$app_deploy")"
  if [[ -n "$app_role_asg" ]]; then
    have_cmd aws || die "required command not found: aws"
    app_aws_profile="$(production_json_required "$app_deploy" '(.app_role.aws_profile // .aws_profile) | select(type == "string" and length > 0)')"
    app_aws_region="$(production_json_required "$app_deploy" '(.app_role.aws_region // .aws_region) | select(type == "string" and length > 0)')"
    if [[ -z "$kafka_auth_region" ]]; then
      kafka_auth_region="$app_aws_region"
    fi
    checkpoint_blob_bucket="$(production_json_required "$shared_manifest" '.shared_services.artifacts.checkpoint_blob_bucket | select(type == "string" and length > 0)')"
    asg_json="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$app_role_asg" \
      --output json)"
    instance_id="$(jq -r '.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy") | .InstanceId' <<<"$asg_json" | head -n1)"
    if [[ -z "$instance_id" ]]; then
      instance_id="$(jq -r '.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService") | .InstanceId' <<<"$asg_json" | head -n1)"
    fi
    [[ -n "$instance_id" ]] || die "app role asg $app_role_asg does not have any in-service instances for shared-infra-e2e"

    stage_key="tmp/shared-infra-e2e/$(date +%s)-$(basename "$binary")"
    stage_uri="s3://$checkpoint_blob_bucket/$stage_key"
    AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" s3 cp "$binary" "$stage_uri" >/dev/null
    presigned_url="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" s3 presign "$stage_uri" --expires-in 900)"
    [[ -n "$presigned_url" ]] || {
      AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" s3 rm "$stage_uri" >/dev/null 2>&1 || true
      die "failed to stage shared-infra-e2e binary for remote execution"
    }

    url_q="$(production_shell_quote "$presigned_url")"
    pg_q="$(production_shell_quote "$postgres_dsn")"
    kb_q="$(production_shell_quote "$kafka_brokers")"
    topics_q="$(production_shell_quote "$required_topics")"
    ipfs_q="$(production_shell_quote "$ipfs_api_url")"
    operators_q="$(production_shell_quote "$checkpoint_operators")"
    threshold_q="$(production_shell_quote "$checkpoint_threshold")"
    output_q="$(production_shell_quote "$output_path")"

    remote_env_prefix="JUNO_QUEUE_KAFKA_TLS=$(production_shell_quote "$kafka_tls") "
    if [[ -n "$kafka_auth_mode" ]]; then
      remote_env_prefix+="JUNO_QUEUE_KAFKA_AUTH_MODE=$(production_shell_quote "$kafka_auth_mode") "
    fi
    if [[ -n "$kafka_auth_region" ]]; then
      remote_env_prefix+="JUNO_QUEUE_KAFKA_AWS_REGION=$(production_shell_quote "$kafka_auth_region") "
      remote_env_prefix+="AWS_REGION=$(production_shell_quote "$kafka_auth_region") "
      remote_env_prefix+="AWS_DEFAULT_REGION=$(production_shell_quote "$kafka_auth_region") "
    fi
    if [[ -n "$ipfs_api_bearer_token" ]]; then
      remote_env_prefix+="CHECKPOINT_IPFS_API_BEARER_TOKEN=$(production_shell_quote "$ipfs_api_bearer_token") "
    fi

    remote_cmd="set -eu; rm -f /var/tmp/shared-infra-e2e; curl -fsSL $url_q -o /var/tmp/shared-infra-e2e; chmod 0755 /var/tmp/shared-infra-e2e; ${remote_env_prefix}/var/tmp/shared-infra-e2e --postgres-dsn $pg_q --kafka-brokers $kb_q --required-kafka-topics $topics_q --checkpoint-ipfs-api-url $ipfs_q --checkpoint-operators $operators_q --checkpoint-threshold $threshold_q --output $output_q; cat $output_q"
    if ! stdout_json="$(ssm_run_shell_command "$app_aws_profile" "$app_aws_region" "$instance_id" "$remote_cmd")"; then
      AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" s3 rm "$stage_uri" >/dev/null 2>&1 || true
      die "shared-infra-e2e failed on app role instance $instance_id"
    fi
    AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" s3 rm "$stage_uri" >/dev/null 2>&1 || true
    [[ -n "$stdout_json" ]] || die "shared-infra-e2e did not return any output from app role instance $instance_id"
    printf '%s\n' "$stdout_json" >"$output_path"
    return 0
  fi

  (
    export JUNO_QUEUE_KAFKA_TLS="$kafka_tls"
    if [[ -n "$kafka_auth_mode" ]]; then
      export JUNO_QUEUE_KAFKA_AUTH_MODE="$kafka_auth_mode"
    fi
    if [[ -n "$kafka_auth_region" ]]; then
      export JUNO_QUEUE_KAFKA_AWS_REGION="$kafka_auth_region"
      export AWS_REGION="$kafka_auth_region"
      export AWS_DEFAULT_REGION="$kafka_auth_region"
    fi
    if [[ -n "$ipfs_api_bearer_token" ]]; then
      export CHECKPOINT_IPFS_API_BEARER_TOKEN="$ipfs_api_bearer_token"
    fi
    production_run_release_binary "$binary" \
      --postgres-dsn "$postgres_dsn" \
      --kafka-brokers "$kafka_brokers" \
      --required-kafka-topics "$required_topics" \
      --checkpoint-ipfs-api-url "$ipfs_api_url" \
      --checkpoint-operators "$checkpoint_operators" \
      --checkpoint-threshold "$checkpoint_threshold" \
      --output "$output_path"
  )
}

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
[[ -n "$app_runtime_ami_release_tag" ]] || die "--app-runtime-ami-release-tag is required"
[[ -n "$shared_proof_services_image_release_tag" ]] || die "--shared-proof-services-image-release-tag is required"
[[ -n "$wireguard_role_ami_release_tag" ]] || die "--wireguard-role-ami-release-tag is required"
[[ -n "$operator_stack_ami_release_tag" ]] || die "--operator-stack-ami-release-tag is required"
[[ -n "$shared_infra_e2e_binary" ]] || die "--shared-infra-e2e-binary is required"
[[ -f "$shared_infra_e2e_binary" ]] || die "shared-infra-e2e binary not found: $shared_infra_e2e_binary"

if [[ -n "$funder_key_file" && -z "$ephemeral_funding_amount_wei" ]]; then
  # Match the established clean preview cycle floor: enough headroom for preview
  # contract deployment while staying within the reusable preview funder budget.
  ephemeral_funding_amount_wei="15000000000000000"
fi

upgrade_preview_inventory_bin="${PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN:-$SCRIPT_DIR/upgrade-preview-inventory.sh}"
destroy_preview_role_runtime_bin="${PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN:-$SCRIPT_DIR/destroy-preview-role-runtime.sh}"
resolve_role_runtime_release_inputs_bin="${PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN:-$SCRIPT_DIR/resolve-role-runtime-release-inputs.sh}"
deploy_coordinator_bin="${PRODUCTION_DEPLOY_COORDINATOR_BIN:-$SCRIPT_DIR/deploy-coordinator.sh}"
provision_app_edge_bin="${PRODUCTION_PROVISION_APP_EDGE_BIN:-$SCRIPT_DIR/provision-app-edge.sh}"
canary_shared_bin="${PRODUCTION_CANARY_SHARED_BIN:-$SCRIPT_DIR/canary-shared-services.sh}"
refresh_app_runtime_bin="${PRODUCTION_REFRESH_APP_RUNTIME_BIN:-$SCRIPT_DIR/refresh-app-runtime.sh}"
canary_app_bin="${PRODUCTION_CANARY_APP_BIN:-$SCRIPT_DIR/canary-app-host.sh}"
roll_preview_operators_bin="${PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN:-$SCRIPT_DIR/roll-preview-operators.sh}"
refresh_preview_app_backoffice_bin="${PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN:-$SCRIPT_DIR/refresh-preview-app-backoffice.sh}"
refresh_preview_wireguard_backoffice_bin="${PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN:-$SCRIPT_DIR/refresh-preview-wireguard-backoffice.sh}"

for cmd in \
  "$upgrade_preview_inventory_bin" \
  "$destroy_preview_role_runtime_bin" \
  "$resolve_role_runtime_release_inputs_bin" \
  "$deploy_coordinator_bin" \
  "$provision_app_edge_bin" \
  "$canary_shared_bin" \
  "$refresh_app_runtime_bin" \
  "$canary_app_bin" \
  "$roll_preview_operators_bin" \
  "$refresh_preview_app_backoffice_bin" \
  "$refresh_preview_wireguard_backoffice_bin"; do
  [[ -x "$cmd" ]] || have_cmd "$cmd" || die "required command not found: $cmd"
done

env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
output_dir="$output_root/$env_slug"
mkdir -p "$output_dir/canaries" "$output_dir/e2e"

upgraded_inventory="$output_dir/inventory.preview-runtime.json"
resolved_inventory="$output_dir/inventory.resolved.json"
if [[ -n "$current_output_root_override" ]]; then
  current_output_root="$(production_abs_path "$(pwd)" "$current_output_root_override")"
else
  current_output_root="$(dirname "$(production_abs_path "$(pwd)" "$inventory")")/production-output"
fi
current_shared_tf_output="$current_output_root/$env_slug/shared-terraform-output.json"

if [[ -z "$existing_bridge_summary" && -n "$funder_key_file" && "$env_slug" == "preview" ]]; then
  auto_existing_bridge_summary="$(find_latest_clean_preview_bridge_summary "$current_output_root" "$env_slug")"
  if [[ -n "$auto_existing_bridge_summary" ]]; then
    existing_bridge_summary="$auto_existing_bridge_summary"
  fi
fi

"$upgrade_preview_inventory_bin" \
  --inventory "$inventory" \
  --output "$upgraded_inventory" \
  --app-runtime-ami-release-tag "$app_runtime_ami_release_tag" \
  --shared-proof-services-image-release-tag "$shared_proof_services_image_release_tag" \
  --wireguard-role-ami-release-tag "$wireguard_role_ami_release_tag"

"$resolve_role_runtime_release_inputs_bin" \
  --inventory "$upgraded_inventory" \
  --output "$resolved_inventory" \
  --operator-stack-ami-release-tag "$operator_stack_ami_release_tag" \
  --github-repo "$github_repo"

if [[ -f "$current_shared_tf_output" ]]; then
  tmp_inventory="$(mktemp)"
  jq \
    --arg requestor_secret_arn "$(jq -r '.shared_proof_requestor_secret_arn.value // empty' "$current_shared_tf_output")" \
    --arg funder_secret_arn "$(jq -r '.shared_proof_funder_secret_arn.value // empty' "$current_shared_tf_output")" \
    --arg requestor_address "$(jq -r '.shared_sp1_requestor_address.value // empty' "$current_shared_tf_output")" \
    --arg rpc_url "$(jq -r '.shared_sp1_rpc_url.value // empty' "$current_shared_tf_output")" \
    '
      .shared_roles = (.shared_roles // {})
      | .shared_roles.proof = (.shared_roles.proof // {})
      | if (.shared_roles.proof.requestor_secret_arn // "") == "" and $requestor_secret_arn != "" then
          .shared_roles.proof.requestor_secret_arn = $requestor_secret_arn
        else .
        end
      | if (.shared_roles.proof.funder_secret_arn // "") == "" and $funder_secret_arn != "" then
          .shared_roles.proof.funder_secret_arn = $funder_secret_arn
        else .
        end
      | if (.shared_roles.proof.requestor_address // "") == "" and $requestor_address != "" then
          .shared_roles.proof.requestor_address = $requestor_address
        else .
        end
      | if (.shared_roles.proof.rpc_url // "") == "" and $rpc_url != "" then
          .shared_roles.proof.rpc_url = $rpc_url
        else .
        end
    ' "$resolved_inventory" >"$tmp_inventory"
  mv "$tmp_inventory" "$resolved_inventory"
fi

normalize_preview_inventory_local_paths "$inventory" "$resolved_inventory"

"$destroy_preview_role_runtime_bin" \
  --inventory "$resolved_inventory" \
  --current-output-root "$current_output_root" \
  --skip-missing-edge-state

coordinator_args=(
  "$deploy_coordinator_bin"
  --inventory "$resolved_inventory"
  --dkg-summary "$dkg_summary"
  --bridge-deploy-binary "$bridge_deploy_binary"
  --output-dir "$output_root"
  --github-repo "$github_repo"
)
if [[ -n "$dkg_completion" ]]; then
  coordinator_args+=(--dkg-completion "$dkg_completion")
fi
if [[ -n "$existing_bridge_summary" ]]; then
  coordinator_args+=(--existing-bridge-summary "$existing_bridge_summary")
fi
if [[ -n "$deployer_key_file" ]]; then
  coordinator_args+=(--deployer-key-file "$deployer_key_file")
fi
if [[ -n "$funder_key_file" ]]; then
  coordinator_args+=(--funder-key-file "$funder_key_file")
fi
if [[ -n "$ephemeral_funding_amount_wei" ]]; then
  coordinator_args+=(--ephemeral-funding-amount-wei "$ephemeral_funding_amount_wei")
fi
"${coordinator_args[@]}"

app_deploy="$output_root/$env_slug/app/app-deploy.json"
shared_manifest="$output_root/$env_slug/shared-manifest.json"
bridge_summary_path="$output_root/$env_slug/bridge-summary.json"
[[ -f "$app_deploy" ]] || die "rebuilt preview app deploy manifest not found: $app_deploy"
[[ -f "$shared_manifest" ]] || die "rebuilt preview shared manifest not found: $shared_manifest"
[[ -f "$bridge_summary_path" ]] || die "rebuilt preview bridge summary not found: $bridge_summary_path"

"$provision_app_edge_bin" --app-deploy "$app_deploy"
"$canary_shared_bin" --shared-manifest "$shared_manifest" >"$output_dir/canaries/shared-services.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/shared-services.json")" == "true" ]] || die "shared services canary failed"
app_runtime_refresh_path="$output_dir/app-runtime-refresh.json"
"$refresh_app_runtime_bin" \
  --shared-manifest "$shared_manifest" \
  --app-deploy "$app_deploy" \
  --output-dir "$output_dir/app-runtime" >"$app_runtime_refresh_path"
[[ "$(jq -r '.ready_for_deploy' "$app_runtime_refresh_path")" == "true" ]] || die "app runtime refresh failed"
"$canary_app_bin" --app-deploy "$app_deploy" >"$output_dir/canaries/app.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/app.json")" == "true" ]] || die "app canary failed"

resolved_env="$(mktemp)"
trap 'rm -f "$resolved_env"' EXIT
aws_profile="$(jq -r '.aws_profile // empty' "$app_deploy")"
aws_region="$(jq -r '.aws_region // empty' "$app_deploy")"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$env_slug"; then
  allow_local_resolvers="true"
fi
production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_deploy")" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
checkpoint_postgres_dsn="$(production_env_first_value "$resolved_env" CHECKPOINT_POSTGRES_DSN APP_POSTGRES_DSN)"
kafka_brokers="$(jq -r '.shared_services.kafka.bootstrap_brokers' "$shared_manifest")"
ipfs_api_url="$(jq -r '.shared_services.ipfs.api_url' "$shared_manifest")"
checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
checkpoint_threshold="$(jq -r '.checkpoint.threshold' "$shared_manifest")"
checkpoint_topics="$(jq -r '.checkpoint.signature_topic + "," + .checkpoint.package_topic' "$shared_manifest")"
operator_topics="deposits.event.v2,withdrawals.requested.v2"
required_topics="proof.requests.v1,proof.fulfillments.v1,proof.failures.v1,ops.alerts.v1,${checkpoint_topics},${operator_topics}"
"$roll_preview_operators_bin" \
  --inventory "$resolved_inventory" \
  --shared-manifest "$shared_manifest" \
  --dkg-summary "$dkg_summary" \
  --operator-stack-ami-release-tag "$operator_stack_ami_release_tag" \
  --output-dir "$output_dir/operator-rollout" \
  --github-repo "$github_repo" >"$output_dir/operator-rollout.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/operator-rollout.json")" == "true" ]] || die "operator rollout failed"

first_operator_deploy="$(find_lowest_index_operator_deploy "$output_dir/operator-rollout/operators")"
[[ -n "$first_operator_deploy" ]] || die "operator rollout did not render any operator deploy handoffs"
first_rolled_inventory="$output_dir/operator-rollout/inventory.operators-rolled.json"
[[ -f "$first_rolled_inventory" ]] || die "operator rollout did not render a rolled inventory"

run_shared_infra_e2e \
  "$app_deploy" \
  "$shared_manifest" \
  "$shared_infra_e2e_binary" \
  "$checkpoint_postgres_dsn" \
  "$required_topics" \
  "$output_dir/e2e/shared-infra-e2e.json"

wireguard_backoffice_refresh_path="$output_dir/wireguard-backoffice.json"
wireguard_backoffice_args=(
  "$refresh_preview_wireguard_backoffice_bin"
  --inventory "$resolved_inventory" \
  --bridge-summary "$bridge_summary_path" \
  --dkg-summary "$dkg_summary" \
  --app-deploy "$app_deploy" \
  --shared-manifest "$shared_manifest" \
  --operator-deploy "$first_operator_deploy" \
  --output-dir "$output_dir/wireguard-backoffice"
)
if [[ -n "$dkg_completion" ]]; then
  wireguard_backoffice_args+=(--dkg-completion "$dkg_completion")
fi
"${wireguard_backoffice_args[@]}" >"$wireguard_backoffice_refresh_path"
[[ "$(jq -r '.ready_for_deploy' "$wireguard_backoffice_refresh_path")" == "true" ]] || die "wireguard backoffice refresh failed"
"$canary_shared_bin" --shared-manifest "$shared_manifest" >"$output_dir/canaries/shared-services.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/shared-services.json")" == "true" ]] || die "shared services canary failed after wireguard backoffice refresh"

"$roll_preview_operators_bin" \
  --inventory "$first_rolled_inventory" \
  --shared-manifest "$shared_manifest" \
  --dkg-summary "$dkg_summary" \
  --operator-stack-ami-release-tag "$operator_stack_ami_release_tag" \
  --output-dir "$output_dir/operator-rollout-final" \
  --github-repo "$github_repo" >"$output_dir/operator-rollout-final.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/operator-rollout-final.json")" == "true" ]] || die "final operator rollout failed"

"$refresh_preview_app_backoffice_bin" \
  --rolled-inventory "$output_dir/operator-rollout-final/inventory.operators-rolled.json" \
  --shared-manifest "$shared_manifest" \
  --app-deploy "$app_deploy" \
  --output-dir "$output_dir/operator-rollout-final" >"$output_dir/app-backoffice-refresh.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/app-backoffice-refresh.json")" == "true" ]] || die "preview app backoffice refresh failed"
final_app_canary_path="$output_dir/canaries/app-post-final-rollout.json"
"$canary_app_bin" --app-deploy "$app_deploy" >"$final_app_canary_path"
[[ "$(jq -r '.ready_for_deploy' "$final_app_canary_path")" == "true" ]] || die "app canary failed after final operator rollout"

release_lock="$output_dir/role-runtime-release-lock.json"
jq -n \
  --arg workflow "reset-preview-role-runtime" \
  --arg inventory_path "$inventory" \
  --arg app_runtime_ami_release_tag "$app_runtime_ami_release_tag" \
  --arg shared_proof_services_image_release_tag "$shared_proof_services_image_release_tag" \
  --arg wireguard_role_ami_release_tag "$wireguard_role_ami_release_tag" \
  --arg operator_stack_ami_release_tag "$operator_stack_ami_release_tag" \
  --arg shared_manifest "$shared_manifest" \
  --arg app_deploy "$app_deploy" \
  --arg bridge_summary_path "$bridge_summary_path" \
  --arg operator_rollout_path "$output_dir/operator-rollout-final.json" \
  --arg app_runtime_refresh_path "$app_runtime_refresh_path" \
  --arg wireguard_backoffice_refresh_path "$wireguard_backoffice_refresh_path" \
  --arg app_backoffice_refresh_path "$output_dir/app-backoffice-refresh.json" \
  --arg app_post_rollout_canary_path "$final_app_canary_path" \
  --arg preview_completed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '
    {
      workflow: $workflow,
      inventory_path: $inventory_path,
      app_runtime_ami_release_tag: $app_runtime_ami_release_tag,
      shared_proof_services_image_release_tag: $shared_proof_services_image_release_tag,
      wireguard_role_ami_release_tag: $wireguard_role_ami_release_tag,
      operator_stack_ami_release_tag: $operator_stack_ami_release_tag,
      shared_manifest: $shared_manifest,
      app_deploy: $app_deploy,
      bridge_summary_path: $bridge_summary_path,
      operator_rollout_path: $operator_rollout_path,
      app_runtime_refresh_path: $app_runtime_refresh_path,
      wireguard_backoffice_refresh_path: $wireguard_backoffice_refresh_path,
      app_backoffice_refresh_path: $app_backoffice_refresh_path,
      app_post_rollout_canary_path: $app_post_rollout_canary_path,
      preview_completed_at: $preview_completed_at
    }
  ' >"$release_lock"
