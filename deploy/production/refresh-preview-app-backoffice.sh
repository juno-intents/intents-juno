#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

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

  for _ in $(seq 1 20); do
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
        [[ -n "$stderr" ]] && printf '%s\n' "$stderr" >&2
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

usage() {
  cat <<'EOF'
Usage:
  refresh-preview-app-backoffice.sh [options]

Options:
  --rolled-inventory PATH   Preview inventory JSON after operator rollout (required)
  --shared-manifest PATH    Shared manifest JSON from the rebuilt preview (required)
  --app-deploy PATH         Existing preview app deploy handoff (required)
  --output-dir DIR          Output directory that already contains operator handoffs (required)
EOF
}

rolled_inventory=""
shared_manifest=""
app_deploy=""
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rolled-inventory) rolled_inventory="$2"; shift 2 ;;
    --shared-manifest) shared_manifest="$2"; shift 2 ;;
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$rolled_inventory" ]] || die "--rolled-inventory is required"
[[ -f "$rolled_inventory" ]] || die "rolled inventory not found: $rolled_inventory"
[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy handoff not found: $app_deploy"
[[ -n "$output_dir" ]] || die "--output-dir is required"

for cmd in jq cast; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

app_deploy="$(production_abs_path "$(pwd)" "$app_deploy")"
output_dir="$(production_abs_path "$(pwd)" "$output_dir")"
mkdir -p "$output_dir/app"

patched_app_deploy="$output_dir/app/app-deploy.json"
backoffice_env="$output_dir/app/backoffice.env"
tmp_dir="$(mktemp -d)"
patched_app_deploy_tmp="$tmp_dir/app-deploy.json"
resolved_env="$tmp_dir/app-secrets.resolved.env"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

operator_endpoints_json="$(
  production_default_operator_endpoints_json "$rolled_inventory" "$shared_manifest"
)"
[[ "$(jq -r 'length' <<<"$operator_endpoints_json")" -gt 0 ]] || die "rolled inventory did not produce any operator endpoints"

jq \
  --argjson operator_endpoints "$operator_endpoints_json" \
  '.operator_endpoints = $operator_endpoints' \
  "$app_deploy" >"$patched_app_deploy_tmp"
mv "$patched_app_deploy_tmp" "$patched_app_deploy"

environment="$(production_json_required "$patched_app_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi

app_secret_contract="$(production_json_required "$patched_app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')"
app_aws_profile="$(production_json_optional "$patched_app_deploy" '.aws_profile')"
app_aws_region="$(production_json_optional "$patched_app_deploy" '.aws_region')"
production_resolve_secret_contract "$app_secret_contract" "$allow_local_resolvers" "$app_aws_profile" "$app_aws_region" "$resolved_env"
production_render_backoffice_env "$shared_manifest" "$patched_app_deploy" "$resolved_env" "$backoffice_env"

app_role_asg="$(jq -r '.app_role.asg // empty' "$patched_app_deploy")"
app_host="$(jq -r '.app_host // empty' "$patched_app_deploy")"
app_user="$(jq -r '.app_user // "ubuntu"' "$patched_app_deploy")"
app_target_mode="host"
app_targets_json='[]'
wait_for_local_app_runtime_cmd='ready=""; for _ in $(seq 1 60); do if systemctl is-active --quiet bridge-api.service backoffice.service && curl -fsS http://127.0.0.1:8090/readyz >/dev/null; then ready=yes; break; fi; sleep 5; done; [ "${ready:-}" = "yes" ]'
wait_for_backoffice_ready_cmd='ready=""; for _ in $(seq 1 60); do if curl -fsS http://127.0.0.1:8090/readyz >/dev/null; then ready=yes; break; fi; sleep 5; done; [ "${ready:-}" = "yes" ]'

if [[ -n "$app_role_asg" ]]; then
  have_cmd aws || die "required command not found: aws"
  have_cmd base64 || die "required command not found: base64"
  [[ -n "$app_aws_profile" ]] || die "app aws profile is required for app role refresh"
  [[ -n "$app_aws_region" ]] || die "app aws region is required for app role refresh"

  app_target_mode="asg"
  asg_json="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$app_role_asg" \
    --output json)"
  app_targets_json="$(jq -c '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy") | .InstanceId]' <<<"$asg_json")"
  [[ "$(jq -r 'length' <<<"$app_targets_json")" -gt 0 ]] || die "app role asg $app_role_asg does not have any healthy in-service instances"

  backoffice_env_b64="$(base64 <"$backoffice_env" | tr -d '\n')"
  while IFS= read -r instance_id; do
    remote_cmd="$wait_for_local_app_runtime_cmd && tmp_file=\$(mktemp) && printf '%s' '$backoffice_env_b64' | base64 -d >\"\$tmp_file\" && sudo install -m 0600 \"\$tmp_file\" /etc/intents-juno/backoffice.env && rm -f \"\$tmp_file\" && sudo systemctl restart backoffice.service && $wait_for_backoffice_ready_cmd"
    ssm_run_shell_command "$app_aws_profile" "$app_aws_region" "$instance_id" "$remote_cmd" >/dev/null || die "failed to refresh backoffice on app instance $instance_id"
  done < <(jq -r '.[]' <<<"$app_targets_json")
else
  have_cmd ssh || die "required command not found: ssh"
  have_cmd scp || die "required command not found: scp"
  [[ -n "$app_host" ]] || die "app host is required when app role asg is not present"
  known_hosts_file="$(production_json_required "$patched_app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')"
  known_hosts_file="$(production_abs_path "$(dirname "$patched_app_deploy")" "$known_hosts_file")"
  [[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"

  SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
  SCP_OPTS=("${SSH_OPTS[@]}")
  ssh_target="${app_user}@${app_host}"
  remote_stage="/tmp/intents-juno-preview-backoffice.env"

  scp "${SCP_OPTS[@]}" "$backoffice_env" "$ssh_target:$remote_stage"
  ssh "${SSH_OPTS[@]}" "$ssh_target" \
    "$wait_for_local_app_runtime_cmd && sudo install -m 0600 '$remote_stage' /etc/intents-juno/backoffice.env && sudo systemctl restart backoffice.service && $wait_for_backoffice_ready_cmd"
  app_targets_json="$(jq -cn --arg app_host "$app_host" '[$app_host]')"
fi

if [[ "$patched_app_deploy" != "$app_deploy" ]]; then
  cp "$patched_app_deploy" "$app_deploy"
fi

jq -n \
  --arg ready "true" \
  --arg app_deploy "$app_deploy" \
  --arg backoffice_env "$backoffice_env" \
  --arg app_host "$app_host" \
  --arg app_target_mode "$app_target_mode" \
  --arg app_role_asg "$app_role_asg" \
  --argjson app_targets "$app_targets_json" \
  --argjson operator_endpoints "$operator_endpoints_json" '
    {
      ready_for_deploy: ($ready == "true"),
      app_deploy: $app_deploy,
      backoffice_env: $backoffice_env,
      app_host: $app_host,
      app_target_mode: $app_target_mode,
      app_role_asg: (if $app_role_asg == "" then null else $app_role_asg end),
      app_targets: $app_targets,
      operator_endpoints: $operator_endpoints
    }
  '
