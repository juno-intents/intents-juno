#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-app-host.sh --app-deploy <path> [--dry-run]

Checks:
  - Required handoff inputs exist locally
  - Remote bridge-api/backoffice services are active over strict-host-key SSH
  - Public bridge-api and backoffice HTTP probes succeed

Output:
  JSON summary to stdout suitable for tester handoff
EOF
}

app_deploy=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-deploy)
      app_deploy="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy manifest not found: $app_deploy"
for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi
shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
known_hosts_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')")"
secret_contract_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"
app_role_json="$(production_json_optional "$app_deploy" '.app_role')"
app_role_asg=""
app_public_lb_target_group_arn=""
app_internal_lb_target_group_arn=""
app_role_mode="false"
if [[ -n "$app_role_json" ]] && [[ "$(jq -r 'length' <<<"$app_role_json")" != "0" ]]; then
  app_host="$(jq -r '.host // empty' <<<"$app_role_json")"
  app_user="$(jq -r '.user // "ubuntu"' <<<"$app_role_json")"
  runtime_dir="$(jq -r '.runtime_dir // "/var/lib/intents-juno/app-runtime"' <<<"$app_role_json")"
  app_role_asg="$(jq -r '.asg // empty' <<<"$app_role_json")"
  app_public_lb_target_group_arn="$(jq -r '.public_lb.target_group_arn // empty' <<<"$app_role_json")"
  app_internal_lb_target_group_arn="$(jq -r '.internal_lb.target_group_arn // empty' <<<"$app_role_json")"
  if [[ -n "$app_role_asg" && -n "$app_public_lb_target_group_arn" && -n "$app_internal_lb_target_group_arn" ]]; then
    app_role_mode="true"
  fi
else
  app_host="$(production_json_required "$app_deploy" '.app_host | select(type == "string" and length > 0)')"
  app_user="$(production_json_required "$app_deploy" '.app_user | select(type == "string" and length > 0)')"
  runtime_dir="$(production_json_required "$app_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
fi
aws_profile="$(production_json_optional "$app_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$app_deploy" '.aws_region')"
public_scheme="$(production_json_required "$app_deploy" '.public_scheme | select(type == "string" and length > 0)')"
bridge_probe_url="$(production_json_required "$app_deploy" '.services.bridge_api.public_url | select(type == "string" and length > 0)')"
backoffice_public_url="$(production_json_optional "$app_deploy" '.services.backoffice.public_url | select(type == "string" and length > 0)')"
backoffice_internal_url="$(production_json_required "$app_deploy" '.services.backoffice.internal_url | select(type == "string" and length > 0)')"
backoffice_access_mode="$(production_json_required "$app_deploy" '.services.backoffice.access.mode | select(type == "string" and length > 0)')"
backoffice_probe_url="$backoffice_public_url"
backoffice_probe_transport="direct"
if [[ "$backoffice_access_mode" == "wireguard" ]]; then
  backoffice_probe_url="$backoffice_internal_url"
  if [[ "$app_role_mode" == "true" ]]; then
    backoffice_probe_transport="ssm-local"
  else
    backoffice_probe_transport="ssh-local"
  fi
fi
base_rpc_url="$(production_json_required "$shared_manifest_path" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
base_chain_id="$(production_json_required "$shared_manifest_path" '.contracts.base_chain_id')"
bridge_address="$(production_json_required "$shared_manifest_path" '.contracts.bridge | select(type == "string" and length > 0)')"
wjuno_address="$(production_json_optional "$shared_manifest_path" '.contracts.wjuno')"
shared_ecs_cluster_arn="$(production_json_optional "$shared_manifest_path" '.shared_services.ecs.cluster_arn')"
shared_proof_requestor_service_name="$(production_json_optional "$shared_manifest_path" '.shared_services.ecs.proof_requestor_service_name')"
shared_proof_funder_service_name="$(production_json_optional "$shared_manifest_path" '.shared_services.ecs.proof_funder_service_name')"
shared_proof_role_asg="$(production_json_optional "$shared_manifest_path" '.shared_roles.proof.asg')"

[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"
if [[ "$app_role_mode" != "true" ]]; then
  [[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"
fi
[[ "$public_scheme" == "https" ]] || die "app deploy manifest must use public_scheme=https"
[[ "$bridge_probe_url" == https://* ]] || die "bridge probe url must use https: $bridge_probe_url"
if [[ "$dry_run" != "true" ]]; then
  for cmd in curl cast aws; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  if [[ "$app_role_mode" != "true" ]]; then
    have_cmd ssh || die "required command not found: ssh"
  fi
fi
case "$backoffice_probe_transport" in
  direct)
    [[ -n "$backoffice_probe_url" ]] || die "backoffice probe url is required when directly accessible"
    [[ "$backoffice_probe_url" == https://* ]] || die "backoffice probe url must use https when directly accessible: $backoffice_probe_url"
    ;;
  ssh-local)
    [[ "$backoffice_probe_url" == http://127.0.0.1:* ]] || die "wireguard backoffice probes must use host-local http via ssh: $backoffice_probe_url"
    ;;
  ssm-local)
    [[ "$backoffice_probe_url" == http://127.0.0.1:* ]] || die "wireguard backoffice probes must use host-local http via ssm: $backoffice_probe_url"
    ;;
  *)
    die "unsupported backoffice probe transport: $backoffice_probe_transport"
    ;;
esac

aws_args=()
[[ -n "$aws_profile" ]] && aws_args+=(--profile "$aws_profile")
[[ -n "$aws_region" ]] && aws_args+=(--region "$aws_region")

input_status="passed"
input_detail="handoff inputs present"
systemd_status="passed"
systemd_detail="bridge-api and backoffice active"
app_capacity_status="skipped"
app_capacity_detail="legacy host runtime"
public_bridge_lb_status="skipped"
public_bridge_lb_detail="legacy host runtime"
internal_backoffice_lb_status="skipped"
internal_backoffice_lb_detail="legacy host runtime"
bridge_ready_status="passed"
bridge_ready_detail="bridge-api /readyz passed"
bridge_config_status="passed"
bridge_config_detail="bridge-api /v1/config passed"
deposit_memo_status="passed"
deposit_memo_detail="bridge-api /v1/deposit-memo passed"
bridge_frontend_status="passed"
bridge_frontend_detail="bridge frontend HTML served"
backoffice_ready_status="passed"
backoffice_ready_detail="backoffice /readyz passed"
backoffice_ui_status="passed"
backoffice_ui_detail="backoffice HTML served"
backoffice_settings_status="passed"
backoffice_settings_detail="backoffice runtime settings API passed"
shared_proof_runtime_status="skipped"
shared_proof_runtime_detail="disabled"
backoffice_funds_status="skipped"
backoffice_funds_detail="disabled"
min_deposit_admin_status="passed"
min_deposit_admin_detail="configured signer matches on-chain minDepositAdmin"
shared_proof_services_status="passed"
shared_proof_services_detail="shared proof ECS services active"
http_retry_max_attempts="${PRODUCTION_CANARY_HTTP_MAX_ATTEMPTS:-20}"
http_retry_sleep_seconds="${PRODUCTION_CANARY_HTTP_RETRY_SLEEP_SECONDS:-3}"
require_funds_check="${PRODUCTION_CANARY_REQUIRE_FUNDS_CHECK:-false}"
deposit_probe_base_recipient="0x1111111111111111111111111111111111111111"

SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
tmp_dir="$(mktemp -d)"
resolved_env="$tmp_dir/app-secrets.resolved.env"
app_ssm_instance_id=""
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

authoritative_resolve_target() {
  local url="$1"
  local host_port host port ip

  [[ "$url" == https://* ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1

  host_port="${url#https://}"
  host_port="${host_port%%/*}"
  host="${host_port%%:*}"
  port="${host_port##*:}"
  if [[ "$host" == "$port" ]]; then
    port=443
  fi

  ip="$(dig @1.1.1.1 +short "$host" | awk 'NF { print; exit }')"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  printf '%s:%s:%s\n' "$host" "$port" "$ip"
}

http_get_with_retry() {
  local url="$1"
  local label="$2"
  shift 2
  local response_file error_file resolve_target
  local curl_status attempt
  local -a curl_argv

  resolve_target="$(authoritative_resolve_target "$url" || true)"

  response_file="$(mktemp)"
  error_file="$(mktemp)"
  for ((attempt = 1; attempt <= http_retry_max_attempts; attempt++)); do
    : >"$response_file"
    : >"$error_file"
    curl_argv=(curl -fsS)
    if [[ -n "$resolve_target" ]]; then
      curl_argv+=(--resolve "$resolve_target")
    fi
    if (($# > 0)); then
      curl_argv+=("$@")
    fi
    curl_argv+=("$url")
    set +e
    "${curl_argv[@]}" >"$response_file" 2>"$error_file"
    curl_status=$?
    set -e

    if (( curl_status == 0 )); then
      cat "$response_file"
      rm -f "$response_file"
      rm -f "$error_file"
      return 0
    fi

    if (( attempt < http_retry_max_attempts )); then
      sleep "$http_retry_sleep_seconds"
    fi
  done

  if [[ -s "$response_file" ]]; then
    cat "$response_file" >&2
  fi
  if [[ -s "$error_file" ]]; then
    cat "$error_file" >&2
  fi
  printf 'http probe failed label=%s url=%s\n' "$label" "$url" >&2
  rm -f "$response_file"
  rm -f "$error_file"
  return 1
}

ssh_http_get_with_retry() {
  local url="$1"
  local label="$2"
  shift 2
  local response_file error_file
  local ssh_status attempt remote_cmd
  local -a remote_argv=(curl -fsS)

  response_file="$(mktemp)"
  error_file="$(mktemp)"
  for ((attempt = 1; attempt <= http_retry_max_attempts; attempt++)); do
    : >"$response_file"
    : >"$error_file"
    remote_argv=(curl -fsS)
    if (($# > 0)); then
      remote_argv+=("$@")
    fi
    remote_argv+=("$url")
    printf -v remote_cmd '%q ' "${remote_argv[@]}"
    set +e
    ssh "${SSH_OPTS[@]}" "$ssh_target" "$remote_cmd" >"$response_file" 2>"$error_file"
    ssh_status=$?
    set -e

    if (( ssh_status == 0 )); then
      cat "$response_file"
      rm -f "$response_file"
      rm -f "$error_file"
      return 0
    fi

    if (( attempt < http_retry_max_attempts )); then
      sleep "$http_retry_sleep_seconds"
    fi
  done

  if [[ -s "$response_file" ]]; then
    cat "$response_file" >&2
  fi
  if [[ -s "$error_file" ]]; then
    cat "$error_file" >&2
  fi
  printf 'remote http probe failed label=%s url=%s\n' "$label" "$url" >&2
  rm -f "$response_file"
  rm -f "$error_file"
  return 1
}

ssm_run_shell_command() {
  local instance_id="$1"
  local command="$2"
  local send_json command_id invocation_json invocation_status stderr stdout parameters_json

  parameters_json="$(jq -cn --arg command "$command" '{commands: [$command]}')"

  send_json="$(AWS_PAGER="" aws "${aws_args[@]}" ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --parameters "$parameters_json" \
    --output json 2>/dev/null || true)"
  [[ -n "$send_json" ]] || return 1
  command_id="$(jq -r '.Command.CommandId // empty' <<<"$send_json")"
  [[ -n "$command_id" ]] || return 1

  invocation_json="$(AWS_PAGER="" aws "${aws_args[@]}" ssm get-command-invocation \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --output json 2>/dev/null || true)"
  [[ -n "$invocation_json" ]] || return 1
  invocation_status="$(jq -r '.Status // empty' <<<"$invocation_json")"
  stdout="$(jq -r '.StandardOutputContent // ""' <<<"$invocation_json")"
  stderr="$(jq -r '.StandardErrorContent // ""' <<<"$invocation_json")"
  if [[ "$invocation_status" != "Success" ]]; then
    [[ -n "$stderr" ]] && printf '%s\n' "$stderr" >&2
    return 1
  fi
  printf '%s' "$stdout"
}

ssm_http_get_with_retry() {
  local url="$1"
  local label="$2"
  shift 2
  local response_file error_file
  local ssm_status attempt remote_cmd
  local -a remote_argv=(curl -fsS)

  [[ -n "$app_ssm_instance_id" ]] || return 1

  response_file="$(mktemp)"
  error_file="$(mktemp)"
  for ((attempt = 1; attempt <= http_retry_max_attempts; attempt++)); do
    : >"$response_file"
    : >"$error_file"
    remote_argv=(curl -fsS)
    if (($# > 0)); then
      remote_argv+=("$@")
    fi
    remote_argv+=("$url")
    printf -v remote_cmd '%q ' "${remote_argv[@]}"
    set +e
    ssm_run_shell_command "$app_ssm_instance_id" "$remote_cmd" >"$response_file" 2>"$error_file"
    ssm_status=$?
    set -e

    if (( ssm_status == 0 )); then
      cat "$response_file"
      rm -f "$response_file"
      rm -f "$error_file"
      return 0
    fi

    if (( attempt < http_retry_max_attempts )); then
      sleep "$http_retry_sleep_seconds"
    fi
  done

  if [[ -s "$response_file" ]]; then
    cat "$response_file" >&2
  fi
  if [[ -s "$error_file" ]]; then
    cat "$error_file" >&2
  fi
  printf 'ssm http probe failed label=%s url=%s\n' "$label" "$url" >&2
  rm -f "$response_file"
  rm -f "$error_file"
  return 1
}

check_asg_capacity() {
  local asg_name="$1"
  local min_healthy="$2"
  local asg_json

  asg_json="$(AWS_PAGER="" aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$asg_name" --output json 2>/dev/null || true)"
  if [[ -z "$asg_json" ]] \
    || ! jq -e --argjson min_healthy "$min_healthy" '
      (.AutoScalingGroups | length) == 1
      and ((.AutoScalingGroups[0].DesiredCapacity // 0) >= $min_healthy)
      and ([.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy")] | length) >= $min_healthy
    ' >/dev/null <<<"$asg_json"; then
    return 1
  fi
  printf '%s' "$asg_json"
}

check_target_group_health() {
  local target_group_arn="$1"
  local min_healthy="$2"
  local target_health_json

  target_health_json="$(AWS_PAGER="" aws "${aws_args[@]}" elbv2 describe-target-health \
    --target-group-arn "$target_group_arn" --output json 2>/dev/null || true)"
  if [[ -z "$target_health_json" ]] \
    || ! jq -e --argjson min_healthy "$min_healthy" '
      ([.TargetHealthDescriptions[]? | select(.TargetHealth.State == "healthy")] | length) >= $min_healthy
    ' >/dev/null <<<"$target_health_json"; then
    return 1
  fi
}

backoffice_http_get_with_retry() {
  case "$backoffice_probe_transport" in
    ssh-local)
      ssh_http_get_with_retry "$@"
      ;;
    ssm-local)
      ssm_http_get_with_retry "$@"
      ;;
    *)
      http_get_with_retry "$@"
      ;;
  esac
}

if [[ "$dry_run" == "true" ]]; then
  input_status="skipped"
  input_detail="dry run"
  systemd_status="skipped"
  systemd_detail="dry run"
  app_capacity_status="skipped"
  app_capacity_detail="dry run"
  public_bridge_lb_status="skipped"
  public_bridge_lb_detail="dry run"
  internal_backoffice_lb_status="skipped"
  internal_backoffice_lb_detail="dry run"
  bridge_ready_status="skipped"
  bridge_ready_detail="dry run"
  bridge_config_status="skipped"
  bridge_config_detail="dry run"
  deposit_memo_status="skipped"
  deposit_memo_detail="dry run"
  bridge_frontend_status="skipped"
  bridge_frontend_detail="dry run"
  backoffice_ready_status="skipped"
  backoffice_ready_detail="dry run"
  backoffice_ui_status="skipped"
  backoffice_ui_detail="dry run"
  backoffice_settings_status="skipped"
  backoffice_settings_detail="dry run"
  shared_proof_runtime_status="skipped"
  shared_proof_runtime_detail="dry run"
  backoffice_funds_status="skipped"
  backoffice_funds_detail="dry run"
  min_deposit_admin_status="skipped"
  min_deposit_admin_detail="dry run"
  shared_proof_services_status="skipped"
  shared_proof_services_detail="dry run"
else
  production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
  if [[ "$app_role_mode" == "true" ]]; then
    [[ -n "$aws_region" ]] || die "app deploy manifest is missing aws_region"
    app_asg_json="$(check_asg_capacity "$app_role_asg" 2 || true)"
    if [[ -z "$app_asg_json" ]]; then
      app_capacity_status="failed"
      app_capacity_detail="app role asg does not have two healthy in-service instances"
    else
      app_capacity_status="passed"
      app_capacity_detail="app role asg healthy"
      app_ssm_instance_id="$(jq -r '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService" and .HealthStatus == "Healthy")][0].InstanceId // empty' <<<"$app_asg_json")"
    fi

    if ! check_target_group_health "$app_public_lb_target_group_arn" 2; then
      public_bridge_lb_status="failed"
      public_bridge_lb_detail="public bridge target group does not have two healthy targets"
    else
      public_bridge_lb_status="passed"
      public_bridge_lb_detail="public bridge target group healthy"
    fi

    if ! check_target_group_health "$app_internal_lb_target_group_arn" 2; then
      internal_backoffice_lb_status="failed"
      internal_backoffice_lb_detail="internal backoffice target group does not have two healthy targets"
    else
      internal_backoffice_lb_status="passed"
      internal_backoffice_lb_detail="internal backoffice target group healthy"
    fi

    if [[ -z "$app_ssm_instance_id" ]]; then
      systemd_status="failed"
      systemd_detail="app role asg does not expose a healthy instance id for ssm checks"
    else
      for svc in bridge-api backoffice; do
        svc_status="$(ssm_run_shell_command "$app_ssm_instance_id" "sudo systemctl is-active $svc" 2>/dev/null | tr -d '[:space:]' || echo "inactive")"
        if [[ "$svc_status" != "active" ]]; then
          systemd_status="failed"
          systemd_detail="service inactive: $svc"
          break
        fi
      done
    fi
  else
    ssh_target="${app_user}@${app_host}"
    for svc in bridge-api backoffice; do
      svc_status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
      if [[ "$svc_status" != "active" ]]; then
        systemd_status="failed"
        systemd_detail="service inactive: $svc"
        break
      fi
    done
  fi

  if ! http_get_with_retry "${bridge_probe_url}/readyz" "bridge readyz" >/dev/null; then
    bridge_ready_status="failed"
    bridge_ready_detail="bridge-api /readyz failed"
  fi

  bridge_config_json="$(http_get_with_retry "${bridge_probe_url}/v1/config" "bridge config" || true)"
  if [[ -z "$bridge_config_json" ]] \
    || ! jq -e --arg bridge_address "${bridge_address,,}" --argjson base_chain_id "$base_chain_id" --arg wjuno_address "${wjuno_address,,}" '
      (.bridgeAddress | type == "string" and ascii_downcase == $bridge_address)
      and (.baseChainId == $base_chain_id)
      and (
        ($wjuno_address == "")
        or (.wjunoAddress | type == "string" and ascii_downcase == $wjuno_address)
      )
    ' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.oWalletUA | select(type == "string" and length > 0)' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.minDepositAmount | select(type == "string" and test("^[0-9]+$"))' >/dev/null <<<"$bridge_config_json" \
    || ! jq -e '.depositMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$bridge_config_json"; then
    bridge_config_status="failed"
    bridge_config_detail="bridge-api /v1/config missing or mismatched baseChainId, bridgeAddress, wjunoAddress, oWalletUA, minDepositAmount, or depositMinConfirmations"
  fi

  deposit_memo_json="$(
    http_get_with_retry \
      "${bridge_probe_url}/v1/deposit-memo?baseRecipient=${deposit_probe_base_recipient}" \
      "bridge deposit memo" || true
  )"
  if [[ -z "$deposit_memo_json" ]] \
    || ! jq -e --arg recipient "${deposit_probe_base_recipient,,}" '
      (.baseRecipient | ascii_downcase) == $recipient
      and (.nonce | type == "string" and test("^[0-9]+$"))
      and (.memoHex | type == "string" and test("^[0-9a-fA-F]{1024}$"))
    ' >/dev/null <<<"$deposit_memo_json"; then
    deposit_memo_status="failed"
    deposit_memo_detail="bridge-api /v1/deposit-memo missing baseRecipient, nonce, or memoHex"
  fi

  bridge_html="$(http_get_with_retry "${bridge_probe_url}/" "bridge frontend html" || true)"
  if [[ "$bridge_html" != *"<html"* && "$bridge_html" != *"<!doctype html"* ]]; then
    bridge_frontend_status="failed"
    bridge_frontend_detail="bridge frontend did not return HTML"
  fi

  if ! backoffice_http_get_with_retry "${backoffice_probe_url}/readyz" "backoffice readyz" >/dev/null; then
    backoffice_ready_status="failed"
    backoffice_ready_detail="backoffice /readyz failed"
  fi

  backoffice_html="$(backoffice_http_get_with_retry "${backoffice_probe_url}/" "backoffice html" || true)"
  if [[ "$backoffice_html" != *"JUNO BACKOFFICE"* ]]; then
    backoffice_ui_status="failed"
    backoffice_ui_detail="backoffice UI did not return expected marker"
  fi

  shared_proof_requestor_address="$(production_json_optional "$shared_manifest_path" '.shared_services.proof.requestor_address')"
  shared_proof_rpc_url="$(production_json_optional "$shared_manifest_path" '.shared_services.proof.rpc_url')"
  if [[ "$require_funds_check" == "true" ]]; then
    shared_proof_runtime_status="passed"
    shared_proof_runtime_detail="shared manifest carries proof requestor runtime metadata"
    if [[ -z "$shared_proof_requestor_address" || -z "$shared_proof_rpc_url" ]]; then
      shared_proof_runtime_status="failed"
      shared_proof_runtime_detail="shared manifest is missing proof.requestor_address or proof.rpc_url"
    fi
  fi

  auth_secret="$(production_env_first_value "$resolved_env" BACKOFFICE_AUTH_SECRET APP_BACKOFFICE_AUTH_SECRET || true)"
  min_deposit_admin_private_key="$(production_env_first_value "$resolved_env" MIN_DEPOSIT_ADMIN_PRIVATE_KEY APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY || true)"
  if [[ -z "$min_deposit_admin_private_key" ]]; then
    min_deposit_admin_status="failed"
    min_deposit_admin_detail="secret contract is missing MIN_DEPOSIT_ADMIN_PRIVATE_KEY or APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY"
  else
    signer_address="$(cast wallet address --private-key "$min_deposit_admin_private_key" | tr -d '[:space:]')"
    onchain_min_deposit_admin="$(cast call --rpc-url "$base_rpc_url" "$bridge_address" "minDepositAdmin()(address)" 2>/dev/null | tr -d '[:space:]')"
    if [[ "${signer_address,,}" != "${onchain_min_deposit_admin,,}" ]]; then
      min_deposit_admin_status="failed"
      min_deposit_admin_detail="configured signer ${signer_address} does not match on-chain minDepositAdmin ${onchain_min_deposit_admin}"
    fi
  fi

  if [[ "$backoffice_ready_status" == "passed" && -n "${auth_secret:-}" ]]; then
    backoffice_settings_json="$(
      backoffice_http_get_with_retry \
        "${backoffice_probe_url}/api/settings/runtime" \
        "backoffice settings api" \
        -H "Authorization: Bearer ${auth_secret}" || true
    )"
    if [[ -z "$backoffice_settings_json" ]] \
      || ! jq -e '.data.minDepositAmount | select(type == "string" and test("^[0-9]+$"))' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.minDepositAdmin | select(type == "string" and length > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.depositMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.withdrawPlannerMinConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json" \
      || ! jq -e '.data.withdrawBatchConfirmations | select(type == "number" and . > 0)' >/dev/null <<<"$backoffice_settings_json"; then
      backoffice_settings_status="failed"
      backoffice_settings_detail="backoffice runtime settings API missing minDeposit or confirmation fields"
    fi
  elif [[ -z "${auth_secret:-}" ]]; then
    backoffice_settings_status="failed"
    backoffice_settings_detail="secret contract is missing BACKOFFICE_AUTH_SECRET or APP_BACKOFFICE_AUTH_SECRET"
  else
    backoffice_settings_status="blocked"
    backoffice_settings_detail="blocked by backoffice readiness failure"
  fi

  if [[ "$require_funds_check" == "true" ]]; then
    backoffice_funds_status="passed"
    backoffice_funds_detail="backoffice funds API reports prover and MPC wallet runtime balances"
    if [[ "$backoffice_ready_status" == "passed" && -n "${auth_secret:-}" ]]; then
      backoffice_funds_json="$(
        backoffice_http_get_with_retry \
          "${backoffice_probe_url}/api/funds" \
          "backoffice funds api" \
          -H "Authorization: Bearer ${auth_secret}" || true
      )"
      if [[ -z "$backoffice_funds_json" ]] \
        || ! jq -e '.operators | select(type == "array" and length > 0)' >/dev/null <<<"$backoffice_funds_json" \
        || ! jq -e '.mpcWallet.address | select(type == "string" and length > 0)' >/dev/null <<<"$backoffice_funds_json" \
        || ! jq -e '.prover.network | select(type == "string" and length > 0)' >/dev/null <<<"$backoffice_funds_json" \
        || ! jq -e '.prover.address | select(type == "string" and length > 0)' >/dev/null <<<"$backoffice_funds_json"; then
        backoffice_funds_status="failed"
        backoffice_funds_detail="backoffice funds API missing prover or MPC wallet fields"
      elif ! jq -e '
        (.prover.error // "") == ""
        and (
          if .prover.network == "succinct" then
            ((.prover.creditsRaw // .prover.creditsFormatted // "") | type == "string" and length > 0)
          else
            ((.prover.balanceWei // .prover.balanceEth // "") | type == "string" and length > 0)
          end
        )
        and (.mpcWallet.error // "") == ""
        and ((.mpcWallet.total // .mpcWallet.balance // "") | type == "string" and length > 0)
      ' >/dev/null <<<"$backoffice_funds_json"; then
        backoffice_funds_status="failed"
        backoffice_funds_detail="backoffice funds API reports prover or MPC wallet runtime error"
      elif [[ -n "$shared_proof_requestor_address" ]] \
        && ! jq -e --arg requestor "${shared_proof_requestor_address,,}" '
          .prover.address | type == "string" and ascii_downcase == $requestor
        ' >/dev/null <<<"$backoffice_funds_json"; then
        backoffice_funds_status="failed"
        backoffice_funds_detail="backoffice funds prover address does not match shared manifest proof.requestor_address"
      fi
    elif [[ -z "${auth_secret:-}" ]]; then
      backoffice_funds_status="failed"
      backoffice_funds_detail="secret contract is missing BACKOFFICE_AUTH_SECRET or APP_BACKOFFICE_AUTH_SECRET"
    else
      backoffice_funds_status="blocked"
      backoffice_funds_detail="blocked by backoffice readiness failure"
    fi
  fi

  if [[ -n "$shared_proof_role_asg" ]]; then
    [[ -n "$aws_region" ]] || die "app deploy manifest is missing aws_region"
    if ! proof_role_asg_json="$(check_asg_capacity "$shared_proof_role_asg" 2 || true)" || [[ -z "$proof_role_asg_json" ]]; then
      shared_proof_services_status="failed"
      shared_proof_services_detail="shared proof role asg does not have two healthy in-service instances"
    else
      shared_proof_services_detail="shared proof role asg healthy"
    fi
  elif [[ -z "$shared_ecs_cluster_arn" || -z "$shared_proof_requestor_service_name" || -z "$shared_proof_funder_service_name" ]]; then
    shared_proof_services_status="failed"
    shared_proof_services_detail="shared manifest is missing proof role or ECS proof service metadata"
  else
    [[ -n "$aws_region" ]] || die "app deploy manifest is missing aws_region"
    aws_args=()
    [[ -n "$aws_profile" ]] && aws_args+=(--profile "$aws_profile")
    aws_args+=(--region "$aws_region")
    ecs_services_json="$(AWS_PAGER="" aws "${aws_args[@]}" ecs describe-services \
      --cluster "$shared_ecs_cluster_arn" \
      --services "$shared_proof_requestor_service_name" "$shared_proof_funder_service_name" 2>/dev/null || true)"
    if [[ -z "$ecs_services_json" ]] \
      || ! jq -e '
        .services | length == 2
        and all(.[]; (.desiredCount // 0) >= 1 and (.runningCount // 0) >= 1)
      ' >/dev/null <<<"$ecs_services_json"; then
      shared_proof_services_status="failed"
      shared_proof_services_detail="shared proof ECS services do not have desiredCount/runningCount >= 1"
    fi
  fi
fi

ready_for_test="true"
for status in \
  "$input_status" \
  "$systemd_status" \
  "$app_capacity_status" \
  "$public_bridge_lb_status" \
  "$internal_backoffice_lb_status" \
  "$bridge_ready_status" \
  "$bridge_config_status" \
  "$deposit_memo_status" \
  "$bridge_frontend_status" \
  "$backoffice_ready_status" \
  "$backoffice_ui_status" \
  "$backoffice_settings_status" \
  "$shared_proof_runtime_status" \
  "$backoffice_funds_status" \
  "$min_deposit_admin_status" \
  "$shared_proof_services_status"; do
  if [[ "$status" != "passed" && "$status" != "skipped" ]]; then
    ready_for_test="false"
  fi
done
if [[ "$dry_run" == "true" ]]; then
  ready_for_test="false"
fi

jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg app_host "$app_host" \
  --arg runtime_dir "$runtime_dir" \
  --arg bridge_probe_url "$bridge_probe_url" \
  --arg backoffice_probe_url "$backoffice_probe_url" \
  --arg input_status "$input_status" \
  --arg input_detail "$input_detail" \
  --arg systemd_status "$systemd_status" \
  --arg systemd_detail "$systemd_detail" \
  --arg app_capacity_status "$app_capacity_status" \
  --arg app_capacity_detail "$app_capacity_detail" \
  --arg public_bridge_lb_status "$public_bridge_lb_status" \
  --arg public_bridge_lb_detail "$public_bridge_lb_detail" \
  --arg internal_backoffice_lb_status "$internal_backoffice_lb_status" \
  --arg internal_backoffice_lb_detail "$internal_backoffice_lb_detail" \
  --arg bridge_ready_status "$bridge_ready_status" \
  --arg bridge_ready_detail "$bridge_ready_detail" \
  --arg bridge_config_status "$bridge_config_status" \
  --arg bridge_config_detail "$bridge_config_detail" \
  --arg deposit_memo_status "$deposit_memo_status" \
  --arg deposit_memo_detail "$deposit_memo_detail" \
  --arg bridge_frontend_status "$bridge_frontend_status" \
  --arg bridge_frontend_detail "$bridge_frontend_detail" \
  --arg backoffice_ready_status "$backoffice_ready_status" \
  --arg backoffice_ready_detail "$backoffice_ready_detail" \
  --arg backoffice_ui_status "$backoffice_ui_status" \
  --arg backoffice_ui_detail "$backoffice_ui_detail" \
  --arg backoffice_settings_status "$backoffice_settings_status" \
  --arg backoffice_settings_detail "$backoffice_settings_detail" \
  --arg shared_proof_runtime_status "$shared_proof_runtime_status" \
  --arg shared_proof_runtime_detail "$shared_proof_runtime_detail" \
  --arg backoffice_funds_status "$backoffice_funds_status" \
  --arg backoffice_funds_detail "$backoffice_funds_detail" \
  --arg min_deposit_admin_status "$min_deposit_admin_status" \
  --arg min_deposit_admin_detail "$min_deposit_admin_detail" \
  --arg shared_proof_services_status "$shared_proof_services_status" \
  --arg shared_proof_services_detail "$shared_proof_services_detail" \
  --argjson ready_for_test "$ready_for_test" \
  '{
    version: $version,
    generated_at: $generated_at,
    app_host: $app_host,
    runtime_dir: $runtime_dir,
    bridge_probe_url: $bridge_probe_url,
    backoffice_probe_url: $backoffice_probe_url,
    ready_for_test: $ready_for_test,
    checks: {
      inputs: {
        status: $input_status,
        detail: $input_detail
      },
      systemd: {
        status: $systemd_status,
        detail: $systemd_detail
      },
      app_capacity: {
        status: $app_capacity_status,
        detail: $app_capacity_detail
      },
      public_bridge_lb: {
        status: $public_bridge_lb_status,
        detail: $public_bridge_lb_detail
      },
      internal_backoffice_lb: {
        status: $internal_backoffice_lb_status,
        detail: $internal_backoffice_lb_detail
      },
      bridge_ready: {
        status: $bridge_ready_status,
        detail: $bridge_ready_detail
      },
      bridge_config: {
        status: $bridge_config_status,
        detail: $bridge_config_detail
      },
      deposit_memo: {
        status: $deposit_memo_status,
        detail: $deposit_memo_detail
      },
      bridge_frontend: {
        status: $bridge_frontend_status,
        detail: $bridge_frontend_detail
      },
      backoffice_ready: {
        status: $backoffice_ready_status,
        detail: $backoffice_ready_detail
      },
      backoffice_ui: {
        status: $backoffice_ui_status,
        detail: $backoffice_ui_detail
      },
      backoffice_settings: {
        status: $backoffice_settings_status,
        detail: $backoffice_settings_detail
      },
      shared_proof_runtime: {
        status: $shared_proof_runtime_status,
        detail: $shared_proof_runtime_detail
      },
      backoffice_funds: {
        status: $backoffice_funds_status,
        detail: $backoffice_funds_detail
      },
      min_deposit_admin: {
        status: $min_deposit_admin_status,
        detail: $min_deposit_admin_detail
      },
      shared_proof_services: {
        status: $shared_proof_services_status,
        detail: $shared_proof_services_detail
      }
    }
  }'
