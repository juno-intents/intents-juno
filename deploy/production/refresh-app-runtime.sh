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

  for _ in $(seq 1 30); do
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

live_e2e_deployment_id_from_app_deploy() {
  local app_deploy="$1"
  local deployment_id app_instance_profile_name

  deployment_id="$(production_json_optional "$app_deploy" '.shared_services.live_e2e.deployment_id')"
  if [[ -n "$deployment_id" ]]; then
    printf '%s\n' "$deployment_id"
    return 0
  fi

  app_instance_profile_name="$(jq -r '.app_role.app_instance_profile_name // empty' "$app_deploy")"
  if [[ "$app_instance_profile_name" == juno-live-e2e-*-instance-profile ]]; then
    deployment_id="${app_instance_profile_name#juno-live-e2e-}"
    deployment_id="${deployment_id%-instance-profile}"
  fi

  printf '%s\n' "$deployment_id"
}

security_group_id_by_name() {
  local aws_profile="$1"
  local aws_region="$2"
  local group_name="$3"
  local group_id

  group_id="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-security-groups \
    --filters "Name=group-name,Values=$group_name" \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null || true)"
  group_id="${group_id//$'\r'/}"
  group_id="${group_id//None/}"
  printf '%s\n' "$group_id"
}

ensure_security_group_ingress_rule() {
  local aws_profile="$1"
  local aws_region="$2"
  local group_id="$3"
  local from_port="$4"
  local to_port="$5"
  local source_group_id="$6"
  local description="$7"

  [[ -n "$group_id" && -n "$source_group_id" ]] || return 0

  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 authorize-security-group-ingress \
    --group-id "$group_id" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":$from_port,\"ToPort\":$to_port,\"UserIdGroupPairs\":[{\"GroupId\":\"$source_group_id\",\"Description\":\"$description\"}]}]" \
    >/dev/null 2>&1 || true
}

ensure_live_e2e_app_runtime_ingress() {
  local shared_manifest="$1"
  local app_deploy="$2"
  local aws_profile="$3"
  local aws_region="$4"
  local app_security_group_id deployment_id shared_resource_name
  local shared_security_group_id ipfs_security_group_id operator_security_group_id
  local shared_postgres_port shared_kafka_port shared_ipfs_api_port operator_grpc_min_port operator_grpc_max_port juno_rpc_port

  app_security_group_id="$(jq -r '.app_role.app_security_group_id // empty' "$app_deploy")"
  [[ -n "$app_security_group_id" ]] || return 0

  deployment_id="$(live_e2e_deployment_id_from_app_deploy "$app_deploy")"
  [[ -n "$deployment_id" ]] || return 0

  shared_resource_name="juno-live-e2e-${deployment_id}"
  shared_security_group_id="$(security_group_id_by_name "$aws_profile" "$aws_region" "${shared_resource_name}-shared-sg")"
  ipfs_security_group_id="$(security_group_id_by_name "$aws_profile" "$aws_region" "${shared_resource_name}-ipfs-sg")"
  operator_security_group_id="$(security_group_id_by_name "$aws_profile" "$aws_region" "${shared_resource_name}-operator-sg")"

  [[ -n "$shared_security_group_id" ]] || die "live-e2e shared security group not found: ${shared_resource_name}-shared-sg"
  [[ -n "$ipfs_security_group_id" ]] || die "live-e2e ipfs security group not found: ${shared_resource_name}-ipfs-sg"
  [[ -n "$operator_security_group_id" ]] || die "live-e2e operator security group not found: ${shared_resource_name}-operator-sg"

  shared_postgres_port="$(jq -r '.shared_services.postgres.port // 5432' "$shared_manifest")"
  shared_kafka_port="$(jq -r '(.shared_services.kafka.bootstrap_brokers // "" | split(",") | map(select(length > 0)) | .[0] // "") | capture(":(?<port>[0-9]+)$").port // "9098"' "$shared_manifest")"
  shared_ipfs_api_port="$(jq -r '(.shared_services.ipfs.api_url // "") | capture(":(?<port>[0-9]+)(/|$)").port // "5001"' "$shared_manifest")"
  operator_grpc_min_port="$(jq -r '[.operator_endpoints[]? | capture(":(?<port>[0-9]+)$").port | tonumber] | min // empty' "$app_deploy")"
  operator_grpc_max_port="$(jq -r '[.operator_endpoints[]? | capture(":(?<port>[0-9]+)$").port | tonumber] | max // empty' "$app_deploy")"
  juno_rpc_port="$(jq -r '(.juno_rpc_url // "") | capture(":(?<port>[0-9]+)(/|$)").port // "18232"' "$app_deploy")"

  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$shared_security_group_id" "$shared_postgres_port" "$shared_postgres_port" "$app_security_group_id" "Postgres from app runtime"
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$shared_security_group_id" "$shared_kafka_port" "$shared_kafka_port" "$app_security_group_id" "Kafka from app runtime"
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$ipfs_security_group_id" "$shared_ipfs_api_port" "$shared_ipfs_api_port" "$app_security_group_id" "IPFS API from app runtime"

  if [[ -n "$operator_grpc_min_port" && -n "$operator_grpc_max_port" ]]; then
    ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$operator_security_group_id" "$operator_grpc_min_port" "$operator_grpc_max_port" "$app_security_group_id" "Operator gRPC from app runtime"
  fi
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$operator_security_group_id" "$juno_rpc_port" "$juno_rpc_port" "$app_security_group_id" "Juno RPC from app runtime"
}

usage() {
  cat <<'EOF'
Usage:
  refresh-app-runtime.sh [options]

Options:
  --shared-manifest PATH    Shared manifest JSON for the deployment (required)
  --app-deploy PATH         App deploy handoff JSON for the deployment (required)
  --output-dir DIR          Output directory for rendered runtime artifacts (required)
  --dry-run                 Render local artifacts but skip remote mutations
EOF
}

shared_manifest=""
app_deploy=""
output_dir=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest) shared_manifest="$2"; shift 2 ;;
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy handoff not found: $app_deploy"
[[ -n "$output_dir" ]] || die "--output-dir is required"

for cmd in jq base64 tar cast; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

output_dir="$(production_abs_path "$(pwd)" "$output_dir")"
mkdir -p "$output_dir" "$output_dir/nginx" "$output_dir/systemd" "$output_dir/bin"

tmp_dir="$(mktemp -d)"
resolved_env="$tmp_dir/app-secrets.resolved.env"
bundle_dir="$tmp_dir/bundle"
bundle_tar="$tmp_dir/app-runtime-bootstrap.tgz"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi

secret_contract_file="$(production_json_required "$app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')"
app_aws_profile="$(production_json_optional "$app_deploy" '.aws_profile')"
app_aws_region="$(production_json_optional "$app_deploy" '.aws_region')"
production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$app_aws_profile" "$app_aws_region" "$resolved_env"

bridge_env="$output_dir/bridge-api.env"
backoffice_env="$output_dir/backoffice.env"
production_render_bridge_api_env "$shared_manifest" "$app_deploy" "$resolved_env" "$bridge_env"
production_render_backoffice_env "$shared_manifest" "$app_deploy" "$resolved_env" "$backoffice_env"

bridge_hostname="$(production_json_required "$app_deploy" '.services.bridge_api.record_name | select(type == "string" and length > 0)')"
backoffice_hostname="$(production_json_optional "$shared_manifest" '.wireguard_role.backoffice_hostname // .shared_roles.wireguard.backoffice_hostname')"
[[ -n "$backoffice_hostname" ]] || die "shared manifest is missing wireguard_role.backoffice_hostname"

bridge_wrapper="$output_dir/bin/bridge-api-wrapper"
cat >"$bridge_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set -a
source /etc/intents-juno/bridge-api.env
set +a

args=(
  --listen "${BRIDGE_API_LISTEN_ADDR}"
  --postgres-dsn "${BRIDGE_API_POSTGRES_DSN}"
  --base-rpc-url "${BRIDGE_API_BASE_RPC_URL}"
  --base-chain-id "${BRIDGE_API_BASE_CHAIN_ID}"
  --bridge-address "${BRIDGE_API_BRIDGE_ADDRESS}"
  --owallet-ua "${BRIDGE_API_OWALLET_UA}"
  --withdrawal-expiry-window-seconds "${BRIDGE_API_WITHDRAWAL_EXPIRY_WINDOW_SECONDS}"
  --min-deposit-amount "${BRIDGE_API_MIN_DEPOSIT_AMOUNT}"
  --deposit-min-confirmations "${BRIDGE_API_DEPOSIT_MIN_CONFIRMATIONS}"
  --withdraw-planner-min-confirmations "${BRIDGE_API_WITHDRAW_PLANNER_MIN_CONFIRMATIONS}"
  --withdraw-batch-confirmations "${BRIDGE_API_WITHDRAW_BATCH_CONFIRMATIONS}"
  --min-withdraw-amount "${BRIDGE_API_MIN_WITHDRAW_AMOUNT}"
  --fee-bps "${BRIDGE_API_FEE_BPS}"
)

if [[ -n "${BRIDGE_API_WJUNO_ADDRESS:-}" ]]; then
  args+=(--wjuno-address "${BRIDGE_API_WJUNO_ADDRESS}")
fi

exec /usr/local/bin/bridge-api "${args[@]}"
EOF
chmod +x "$bridge_wrapper"

backoffice_wrapper="$output_dir/bin/backoffice-wrapper"
cat >"$backoffice_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set -a
source /etc/intents-juno/backoffice.env
set +a

args=(
  --listen "${BACKOFFICE_LISTEN_ADDR}"
  --postgres-dsn-env BACKOFFICE_POSTGRES_DSN
  --base-rpc-url "${BACKOFFICE_BASE_RPC_URL}"
  --auth-secret "${BACKOFFICE_AUTH_SECRET}"
  --bridge-address "${BACKOFFICE_BRIDGE_ADDRESS}"
  --wjuno-address "${BACKOFFICE_WJUNO_ADDRESS}"
  --operator-registry-address "${BACKOFFICE_OPERATOR_REGISTRY_ADDRESS}"
  --operator-addresses "${BACKOFFICE_OPERATOR_ADDRESSES}"
  --base-relayer-signer-addresses "${BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES}"
  --base-relayer-gas-min-wei "${BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI}"
  --service-urls "${BACKOFFICE_SERVICE_URLS}"
  --kafka-brokers "${BACKOFFICE_KAFKA_BROKERS}"
  --ipfs-api-url "${BACKOFFICE_IPFS_API_URL}"
  --deposit-min-confirmations "${BACKOFFICE_DEPOSIT_MIN_CONFIRMATIONS}"
  --withdraw-planner-min-confirmations "${BACKOFFICE_WITHDRAW_PLANNER_MIN_CONFIRMATIONS}"
  --withdraw-batch-confirmations "${BACKOFFICE_WITHDRAW_BATCH_CONFIRMATIONS}"
  --min-deposit-admin-key-env MIN_DEPOSIT_ADMIN_PRIVATE_KEY
)

if [[ -n "${BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS:-}" ]]; then
  args+=(--fee-distributor-address "${BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS}")
fi
if [[ -n "${BACKOFFICE_OWALLET_UA:-}" ]]; then
  args+=(--owallet-ua "${BACKOFFICE_OWALLET_UA}")
fi
if [[ -n "${BACKOFFICE_SP1_REQUESTOR_ADDRESS:-}" ]]; then
  args+=(--sp1-requestor-address "${BACKOFFICE_SP1_REQUESTOR_ADDRESS}")
fi
if [[ -n "${BACKOFFICE_SP1_RPC_URL:-}" ]]; then
  args+=(--sp1-rpc-url "${BACKOFFICE_SP1_RPC_URL}")
fi
if [[ -n "${BACKOFFICE_OPERATOR_ENDPOINTS:-}" ]]; then
  args+=(--operator-endpoints "${BACKOFFICE_OPERATOR_ENDPOINTS}")
fi
if [[ -n "${BACKOFFICE_JUNO_RPC_URLS:-}" ]]; then
  args+=(--juno-rpc-urls "${BACKOFFICE_JUNO_RPC_URLS}")
fi
if [[ -n "${BACKOFFICE_JUNO_RPC_URL:-}" ]]; then
  args+=(--juno-rpc-url "${BACKOFFICE_JUNO_RPC_URL}")
fi
if [[ -n "${BACKOFFICE_JUNO_RPC_USER:-}" ]]; then
  args+=(--juno-rpc-user "${BACKOFFICE_JUNO_RPC_USER}")
fi
if [[ -n "${BACKOFFICE_JUNO_RPC_PASS:-}" ]]; then
  args+=(--juno-rpc-pass "${BACKOFFICE_JUNO_RPC_PASS}")
fi
if [[ -n "${BACKOFFICE_IPFS_API_BEARER_TOKEN:-}" ]]; then
  args+=(--ipfs-api-bearer-token-env BACKOFFICE_IPFS_API_BEARER_TOKEN)
fi

exec /usr/local/bin/backoffice "${args[@]}"
EOF
chmod +x "$backoffice_wrapper"

bridge_unit="$output_dir/systemd/bridge-api.service"
cat >"$bridge_unit" <<'EOF'
[Unit]
Description=Juno bridge-api
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bridge-api-wrapper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

backoffice_unit="$output_dir/systemd/backoffice.service"
cat >"$backoffice_unit" <<'EOF'
[Unit]
Description=Juno backoffice
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backoffice-wrapper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

nginx_config="$output_dir/nginx/app.conf"
cat >"$nginx_config" <<EOF
map_hash_bucket_size 128;

map \$host \$intents_upstream {
  default http://127.0.0.1:8082;
  ${bridge_hostname} http://127.0.0.1:8082;
  ${backoffice_hostname} http://127.0.0.1:8090;
}

server {
  listen 80 default_server;
  server_name _;
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl default_server;
  server_name ${bridge_hostname} ${backoffice_hostname} _;

  ssl_certificate /etc/nginx/intents-juno/server.crt;
  ssl_certificate_key /etc/nginx/intents-juno/server.key;

  location = /healthz {
    add_header Content-Type text/plain;
    return 200 "ok\n";
  }

  location / {
    proxy_pass \$intents_upstream;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
EOF

mkdir -p "$bundle_dir/systemd" "$bundle_dir/nginx"
cp "$bridge_env" "$bundle_dir/bridge-api.env"
cp "$backoffice_env" "$bundle_dir/backoffice.env"
cp "$bridge_wrapper" "$bundle_dir/bridge-api-wrapper"
cp "$backoffice_wrapper" "$bundle_dir/backoffice-wrapper"
cp "$bridge_unit" "$bundle_dir/systemd/bridge-api.service"
cp "$backoffice_unit" "$bundle_dir/systemd/backoffice.service"
cp "$nginx_config" "$bundle_dir/nginx/app.conf"

install_script="$output_dir/install.sh"
cat >"$install_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -d -m 0755 /etc/intents-juno /etc/nginx/intents-juno /etc/nginx/sites-available /etc/nginx/sites-enabled
install -m 0600 "$script_dir/bridge-api.env" /etc/intents-juno/bridge-api.env
install -m 0600 "$script_dir/backoffice.env" /etc/intents-juno/backoffice.env
install -m 0755 "$script_dir/bridge-api-wrapper" /usr/local/bin/bridge-api-wrapper
install -m 0755 "$script_dir/backoffice-wrapper" /usr/local/bin/backoffice-wrapper
install -m 0644 "$script_dir/systemd/bridge-api.service" /etc/systemd/system/bridge-api.service
install -m 0644 "$script_dir/systemd/backoffice.service" /etc/systemd/system/backoffice.service
install -m 0644 "$script_dir/nginx/app.conf" /etc/nginx/sites-available/intents-juno-app.conf
ln -sfn /etc/nginx/sites-available/intents-juno-app.conf /etc/nginx/sites-enabled/intents-juno-app.conf
rm -f /etc/nginx/sites-enabled/default

if [[ ! -s /etc/nginx/intents-juno/server.key || ! -s /etc/nginx/intents-juno/server.crt ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=intents-juno-app" \
    -keyout /etc/nginx/intents-juno/server.key \
    -out /etc/nginx/intents-juno/server.crt >/dev/null 2>&1
  chmod 0600 /etc/nginx/intents-juno/server.key
  chmod 0644 /etc/nginx/intents-juno/server.crt
fi

nginx -t
systemctl daemon-reload
systemctl enable bridge-api.service backoffice.service nginx.service >/dev/null
systemctl restart bridge-api.service
systemctl restart backoffice.service
systemctl restart nginx.service

for _ in $(seq 1 60); do
  if systemctl is-active --quiet bridge-api.service backoffice.service nginx.service \
    && curl -ksfS https://127.0.0.1/healthz >/dev/null; then
    exit 0
  fi
  sleep 5
done

printf 'app runtime services failed readiness checks\n' >&2
exit 1
EOF
chmod +x "$install_script"
cp "$install_script" "$bundle_dir/install.sh"

COPYFILE_DISABLE=1 tar -czf "$bundle_tar" -C "$bundle_dir" .
bundle_b64="$(base64 <"$bundle_tar" | tr -d '\n')"

app_role_asg="$(jq -r '.app_role.asg // empty' "$app_deploy")"
app_host="$(jq -r '.app_host // empty' "$app_deploy")"
app_user="$(jq -r '.app_user // "ubuntu"' "$app_deploy")"
app_target_mode="host"
app_targets_json='[]'

if [[ "$dry_run" == "true" ]]; then
  if [[ -n "$app_role_asg" ]]; then
    app_target_mode="asg"
  fi
else
  if [[ -n "$app_role_asg" ]]; then
    have_cmd aws || die "required command not found: aws"
    [[ -n "$app_aws_profile" ]] || die "app aws profile is required for app role refresh"
    [[ -n "$app_aws_region" ]] || die "app aws region is required for app role refresh"

    app_target_mode="asg"
    ensure_live_e2e_app_runtime_ingress "$shared_manifest" "$app_deploy" "$app_aws_profile" "$app_aws_region"
    asg_json="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$app_role_asg" \
      --output json)"
    app_targets_json="$(jq -c '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService") | .InstanceId]' <<<"$asg_json")"
    [[ "$(jq -r 'length' <<<"$app_targets_json")" -gt 0 ]] || die "app role asg $app_role_asg does not have any in-service instances"

    while IFS= read -r instance_id; do
      remote_cmd="tmp_dir=\$(mktemp -d) && archive_path=\$tmp_dir/app-runtime-bootstrap.tgz && printf '%s' '$bundle_b64' | base64 -d >\"\$archive_path\" && tar -xzf \"\$archive_path\" -C \"\$tmp_dir\" && sudo bash \"\$tmp_dir/install.sh\" && rm -rf \"\$tmp_dir\""
      ssm_run_shell_command "$app_aws_profile" "$app_aws_region" "$instance_id" "$remote_cmd" >/dev/null || die "failed to refresh app runtime on app instance $instance_id"
    done < <(jq -r '.[]' <<<"$app_targets_json")
  else
    have_cmd ssh || die "required command not found: ssh"
    have_cmd scp || die "required command not found: scp"
    [[ -n "$app_host" ]] || die "app host is required when app role asg is not present"
    known_hosts_file="$(production_json_required "$app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')"
    known_hosts_file="$(production_abs_path "$(dirname "$app_deploy")" "$known_hosts_file")"
    [[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"

    app_targets_json="$(jq -cn --arg app_host "$app_host" '[$app_host]')"
    remote_stage="/tmp/intents-juno-app-runtime-bootstrap.tgz"
    SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
    SCP_OPTS=("${SSH_OPTS[@]}")
    ssh_target="${app_user}@${app_host}"

    scp "${SCP_OPTS[@]}" "$bundle_tar" "$ssh_target:$remote_stage"
    ssh "${SSH_OPTS[@]}" "$ssh_target" \
      "tmp_dir=\$(mktemp -d) && tar -xzf '$remote_stage' -C \"\$tmp_dir\" && sudo bash \"\$tmp_dir/install.sh\" && rm -rf \"\$tmp_dir\" '$remote_stage'"
  fi
fi

jq -n \
  --arg ready "true" \
  --arg dry_run "$dry_run" \
  --arg shared_manifest "$shared_manifest" \
  --arg app_deploy "$app_deploy" \
  --arg bridge_env "$bridge_env" \
  --arg backoffice_env "$backoffice_env" \
  --arg bridge_wrapper "$bridge_wrapper" \
  --arg backoffice_wrapper "$backoffice_wrapper" \
  --arg install_script "$install_script" \
  --arg nginx_config "$nginx_config" \
  --arg app_target_mode "$app_target_mode" \
  --arg app_role_asg "$app_role_asg" \
  --arg app_host "$app_host" \
  --arg bridge_hostname "$bridge_hostname" \
  --arg backoffice_hostname "$backoffice_hostname" \
  --argjson app_targets "$app_targets_json" '
    {
      ready_for_deploy: ($ready == "true"),
      dry_run: ($dry_run == "true"),
      shared_manifest: $shared_manifest,
      app_deploy: $app_deploy,
      bridge_env: $bridge_env,
      backoffice_env: $backoffice_env,
      bridge_wrapper: $bridge_wrapper,
      backoffice_wrapper: $backoffice_wrapper,
      install_script: $install_script,
      nginx_config: $nginx_config,
      bridge_hostname: $bridge_hostname,
      backoffice_hostname: $backoffice_hostname,
      app_target_mode: $app_target_mode,
      app_role_asg: (if $app_role_asg == "" then null else $app_role_asg end),
      app_host: (if $app_host == "" then null else $app_host end),
      app_targets: $app_targets
    }
  '
