#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

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
  local shared_postgres_port shared_kafka_port shared_ipfs_api_port operator_grpc_min_port operator_grpc_max_port juno_rpc_port juno_scan_port

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
  juno_scan_port="$(jq -r '(.juno_scan_url // "") | capture(":(?<port>[0-9]+)(/|$)").port // "8080"' "$app_deploy")"

  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$shared_security_group_id" "$shared_postgres_port" "$shared_postgres_port" "$app_security_group_id" "Postgres from app runtime"
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$shared_security_group_id" "$shared_kafka_port" "$shared_kafka_port" "$app_security_group_id" "Kafka from app runtime"
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$ipfs_security_group_id" "$shared_ipfs_api_port" "$shared_ipfs_api_port" "$app_security_group_id" "IPFS API from app runtime"

  if [[ -n "$operator_grpc_min_port" && -n "$operator_grpc_max_port" ]]; then
    ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$operator_security_group_id" "$operator_grpc_min_port" "$operator_grpc_max_port" "$app_security_group_id" "Operator gRPC from app runtime"
  fi
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$operator_security_group_id" "$juno_rpc_port" "$juno_rpc_port" "$app_security_group_id" "Juno RPC from app runtime"
  ensure_security_group_ingress_rule "$aws_profile" "$aws_region" "$operator_security_group_id" "$juno_scan_port" "$juno_scan_port" "$app_security_group_id" "Juno scan from app runtime"
}

render_app_runtime_bootstrap_user_data() {
  local bundle_b64="$1"
  local output_file="$2"

  cat >"$output_file" <<EOF
#!/usr/bin/env bash
set -euo pipefail

tmp_dir="\$(mktemp -d)"
cleanup() {
  rm -rf "\$tmp_dir"
}
trap cleanup EXIT

archive_path="\$tmp_dir/app-runtime-bootstrap.tgz"
cat <<'APP_RUNTIME_BUNDLE_EOF' | base64 -d >"\$archive_path"
$bundle_b64
APP_RUNTIME_BUNDLE_EOF
tar -xzf "\$archive_path" -C "\$tmp_dir"
bash "\$tmp_dir/install.sh"
EOF
}

usage() {
  cat <<'EOF'
Usage:
  refresh-app-runtime.sh [options]

Options:
  --shared-manifest PATH    Shared manifest JSON for the deployment (required)
  --app-deploy PATH         App deploy handoff JSON for the deployment (required)
  --app-binaries-release-tag TAG
                           Optional published app-binaries release tag to stage
                           bridge-api/backoffice binaries into the refresh bundle
  --github-repo REPO        GitHub repo for release asset downloads
                           (default: juno-intents/intents-juno)
  --output-dir DIR          Output directory for rendered runtime artifacts (required)
  --dry-run                 Render local artifacts but skip remote mutations
EOF
}

shared_manifest=""
app_deploy=""
app_binaries_release_tag=""
github_repo="juno-intents/intents-juno"
output_dir=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest) shared_manifest="$2"; shift 2 ;;
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --app-binaries-release-tag) app_binaries_release_tag="$2"; shift 2 ;;
    --github-repo) github_repo="$2"; shift 2 ;;
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

for cmd in jq base64 tar cast aws; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ -n "$app_binaries_release_tag" ]]; then
  for cmd in gh sha256sum; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

output_dir="$(production_abs_path "$(pwd)" "$output_dir")"
mkdir -p "$output_dir" "$output_dir/nginx" "$output_dir/systemd" "$output_dir/bin"
if [[ -n "$app_binaries_release_tag" ]]; then
  mkdir -p "$output_dir/app-binaries"
fi

tmp_dir="$(mktemp -d)"
bundle_dir="$tmp_dir/bundle"
bundle_tar="$tmp_dir/app-runtime-bootstrap.tgz"
empty_env="$tmp_dir/app-runtime.empty.env"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
: >"$empty_env"

app_aws_profile="$(production_json_required "$app_deploy" '.aws_profile | select(type == "string" and length > 0)')"
app_aws_region="$(production_json_required "$app_deploy" '.aws_region | select(type == "string" and length > 0)')"
runtime_config_secret_id="$(production_json_required "$app_deploy" '.runtime_config_secret_id | select(type == "string" and length > 0)')"
runtime_config_secret_region="$(production_json_optional "$app_deploy" '.runtime_config_secret_region')"
if [[ -z "$runtime_config_secret_region" ]]; then
  runtime_config_secret_region="$app_aws_region"
fi

bridge_env="$output_dir/bridge-api.env"
backoffice_env="$output_dir/backoffice.env"
production_render_bridge_api_env "$shared_manifest" "$app_deploy" "$empty_env" "$bridge_env"
production_render_backoffice_env "$shared_manifest" "$app_deploy" "$empty_env" "$backoffice_env"

bridge_hostname="$(production_json_required "$app_deploy" '.services.bridge_api.record_name | select(type == "string" and length > 0)')"
backoffice_access_mode="$(production_json_required "$app_deploy" '.services.backoffice.access.mode | select(type == "string" and length > 0)')"
backoffice_hostname="$(jq -r '
  if (.services.backoffice.record_name // "") != "" then
    .services.backoffice.record_name
  else
    (try ((.services.backoffice.public_url // "") | capture("^https?://(?<host>[^/:]+)").host) catch "")
  end
' "$app_deploy")"
if [[ -z "$backoffice_hostname" ]]; then
  backoffice_hostname="$(production_json_optional "$shared_manifest" '.wireguard_role.backoffice_hostname // .shared_roles.wireguard.backoffice_hostname')"
fi
[[ -n "$backoffice_hostname" ]] || die "app deploy is missing services.backoffice.record_name or services.backoffice.public_url"

if [[ -n "$app_binaries_release_tag" ]]; then
  gh release download "$app_binaries_release_tag" \
    --repo "$github_repo" \
    --pattern "bridge-api_linux_amd64" \
    --pattern "bridge-api_linux_amd64.sha256" \
    --pattern "backoffice_linux_amd64" \
    --pattern "backoffice_linux_amd64.sha256" \
    --dir "$output_dir/app-binaries" \
    --clobber
  (
    cd "$output_dir/app-binaries"
    sha256sum -c bridge-api_linux_amd64.sha256 >/dev/null
    sha256sum -c backoffice_linux_amd64.sha256 >/dev/null
  )
fi

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
if [[ -n "${BACKOFFICE_JUNO_SCAN_URL:-}" ]]; then
  args+=(--juno-scan-url "${BACKOFFICE_JUNO_SCAN_URL}")
fi
if [[ -n "${BACKOFFICE_JUNO_SCAN_WALLET_ID:-}" ]]; then
  args+=(--juno-scan-wallet-id "${BACKOFFICE_JUNO_SCAN_WALLET_ID}")
fi
if [[ -n "${BACKOFFICE_JUNO_SCAN_BEARER_TOKEN:-}" ]]; then
  args+=(--juno-scan-bearer-token-env BACKOFFICE_JUNO_SCAN_BEARER_TOKEN)
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

cloudflared_wrapper=""
cloudflared_unit=""
if [[ "$backoffice_access_mode" == "cloudflare-access" ]]; then
  cloudflared_wrapper="$output_dir/bin/cloudflared-backoffice-wrapper"
  cat >"$cloudflared_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set -a
source /etc/intents-juno/backoffice.env
set +a

[[ -n "${BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN:-}" ]] || {
  printf 'missing BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN\n' >&2
  exit 1
}

exec /usr/local/bin/cloudflared tunnel --no-autoupdate run --token "${BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN}"
EOF
  chmod +x "$cloudflared_wrapper"

  cloudflared_unit="$output_dir/systemd/cloudflared-backoffice.service"
  cat >"$cloudflared_unit" <<'EOF'
[Unit]
Description=Juno backoffice Cloudflare Tunnel
After=network-online.target backoffice.service
Wants=network-online.target backoffice.service

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared-backoffice-wrapper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

app_hydrator_env="$output_dir/app-runtime-hydrator.env"
cat >"$app_hydrator_env" <<EOF
APP_RUNTIME_CONFIG_SECRET_ID=$runtime_config_secret_id
APP_RUNTIME_CONFIG_SECRET_REGION=$runtime_config_secret_region
EOF

app_hydrator_script="$output_dir/bin/app-config-hydrator.sh"
cat >"$app_hydrator_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

hydrator_env_file="/etc/intents-juno/app-runtime-hydrator.env"
bridge_env_file="/etc/intents-juno/bridge-api.env"
backoffice_env_file="/etc/intents-juno/backoffice.env"

log() {
  printf 'app-config-hydrator: %s\n' "$*" >&2
}

die() {
  log "$*"
  exit 1
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    { print }
    END {
      if (updated == 0) {
        print key "=" value
      }
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

json_first_string() {
  local json="$1"
  shift
  jq -r --argjson keys "$(printf '%s\n' "$@" | jq -R . | jq -s .)" '
    first(
      $keys[]
      | . as $key
      | $json[$key]
      | select(type == "string" and length > 0)
    ) // empty
  ' --argjson json "$json" 'null' 2>/dev/null
}

[[ -f "$hydrator_env_file" ]] || die "missing $hydrator_env_file"
[[ -f "$bridge_env_file" ]] || die "missing $bridge_env_file"
[[ -f "$backoffice_env_file" ]] || die "missing $backoffice_env_file"
command -v aws >/dev/null 2>&1 || die "aws CLI is required on the host"
command -v jq >/dev/null 2>&1 || die "jq is required on the host"

# shellcheck disable=SC1091
source "$hydrator_env_file"
[[ -n "${APP_RUNTIME_CONFIG_SECRET_ID:-}" ]] || die "APP_RUNTIME_CONFIG_SECRET_ID is required"
[[ -n "${APP_RUNTIME_CONFIG_SECRET_REGION:-}" ]] || die "APP_RUNTIME_CONFIG_SECRET_REGION is required"

secret_string="$(AWS_PAGER="" aws --region "$APP_RUNTIME_CONFIG_SECRET_REGION" secretsmanager get-secret-value \
  --secret-id "$APP_RUNTIME_CONFIG_SECRET_ID" \
  --query SecretString \
  --output text)"
[[ -n "$secret_string" && "$secret_string" != "None" ]] || die "secret payload is empty for $APP_RUNTIME_CONFIG_SECRET_ID"
secret_json="$(jq -c . <<<"$secret_string")" || die "secret payload is not valid JSON"

bridge_postgres_dsn="$(jq -r '.BRIDGE_API_POSTGRES_DSN // .APP_POSTGRES_DSN // .CHECKPOINT_POSTGRES_DSN // empty' <<<"$secret_json")"
backoffice_postgres_dsn="$(jq -r '.BACKOFFICE_POSTGRES_DSN // .APP_POSTGRES_DSN // .CHECKPOINT_POSTGRES_DSN // empty' <<<"$secret_json")"
backoffice_auth_secret="$(jq -r '.BACKOFFICE_AUTH_SECRET // .APP_BACKOFFICE_AUTH_SECRET // empty' <<<"$secret_json")"
backoffice_ipfs_api_bearer_token="$(jq -r '.BACKOFFICE_IPFS_API_BEARER_TOKEN // .IPFS_API_BEARER_TOKEN // empty' <<<"$secret_json")"
backoffice_juno_scan_bearer_token="$(jq -r '.BACKOFFICE_JUNO_SCAN_BEARER_TOKEN // .JUNO_SCAN_BEARER_TOKEN // empty' <<<"$secret_json")"
backoffice_juno_rpc_user="$(jq -r '.BACKOFFICE_JUNO_RPC_USER // .APP_JUNO_RPC_USER // .JUNO_RPC_USER // empty' <<<"$secret_json")"
backoffice_juno_rpc_pass="$(jq -r '.BACKOFFICE_JUNO_RPC_PASS // .APP_JUNO_RPC_PASS // .JUNO_RPC_PASS // empty' <<<"$secret_json")"
min_deposit_admin_private_key="$(jq -r '.MIN_DEPOSIT_ADMIN_PRIVATE_KEY // .APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY // empty' <<<"$secret_json")"
backoffice_cloudflare_tunnel_token="$(jq -r '.BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN // .CLOUDFLARE_TUNNEL_TOKEN // empty' <<<"$secret_json")"

[[ -n "$bridge_postgres_dsn" ]] || die "runtime secret is missing bridge postgres dsn"
[[ -n "$backoffice_postgres_dsn" ]] || die "runtime secret is missing backoffice postgres dsn"
[[ -n "$backoffice_auth_secret" ]] || die "runtime secret is missing backoffice auth secret"
[[ -n "$backoffice_juno_rpc_user" ]] || die "runtime secret is missing juno rpc user"
[[ -n "$backoffice_juno_rpc_pass" ]] || die "runtime secret is missing juno rpc pass"
[[ -n "$min_deposit_admin_private_key" ]] || die "runtime secret is missing min deposit admin private key"

set_env_value "$bridge_env_file" BRIDGE_API_POSTGRES_DSN "$bridge_postgres_dsn"
set_env_value "$backoffice_env_file" BACKOFFICE_POSTGRES_DSN "$backoffice_postgres_dsn"
set_env_value "$backoffice_env_file" BACKOFFICE_AUTH_SECRET "$backoffice_auth_secret"
set_env_value "$backoffice_env_file" BACKOFFICE_JUNO_RPC_USER "$backoffice_juno_rpc_user"
set_env_value "$backoffice_env_file" BACKOFFICE_JUNO_RPC_PASS "$backoffice_juno_rpc_pass"
set_env_value "$backoffice_env_file" MIN_DEPOSIT_ADMIN_PRIVATE_KEY "$min_deposit_admin_private_key"
if [[ -n "$backoffice_ipfs_api_bearer_token" ]]; then
  set_env_value "$backoffice_env_file" BACKOFFICE_IPFS_API_BEARER_TOKEN "$backoffice_ipfs_api_bearer_token"
fi
if [[ -n "$backoffice_juno_scan_bearer_token" ]]; then
  set_env_value "$backoffice_env_file" BACKOFFICE_JUNO_SCAN_BEARER_TOKEN "$backoffice_juno_scan_bearer_token"
fi
if [[ -n "$backoffice_cloudflare_tunnel_token" ]]; then
  set_env_value "$backoffice_env_file" BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN "$backoffice_cloudflare_tunnel_token"
fi

chmod 0600 "$bridge_env_file" "$backoffice_env_file"
log "hydrated app runtime env"
EOF
chmod +x "$app_hydrator_script"

bridge_unit="$output_dir/systemd/bridge-api.service"
cat >"$bridge_unit" <<'EOF'
[Unit]
Description=Juno bridge-api
After=network-online.target intents-juno-app-config-hydrator.service
Wants=network-online.target intents-juno-app-config-hydrator.service

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
After=network-online.target intents-juno-app-config-hydrator.service
Wants=network-online.target intents-juno-app-config-hydrator.service

[Service]
Type=simple
ExecStart=/usr/local/bin/backoffice-wrapper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

app_hydrator_unit="$output_dir/systemd/intents-juno-app-config-hydrator.service"
cat >"$app_hydrator_unit" <<'EOF'
[Unit]
Description=Intents Juno App config hydrator
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/intents-juno/app-runtime-hydrator.env
ExecStart=/usr/local/bin/intents-juno-app-config-hydrator.sh

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
cp "$app_hydrator_env" "$bundle_dir/app-runtime-hydrator.env"
cp "$app_hydrator_script" "$bundle_dir/app-config-hydrator.sh"
cp "$bridge_unit" "$bundle_dir/systemd/bridge-api.service"
cp "$backoffice_unit" "$bundle_dir/systemd/backoffice.service"
cp "$app_hydrator_unit" "$bundle_dir/systemd/intents-juno-app-config-hydrator.service"
cp "$nginx_config" "$bundle_dir/nginx/app.conf"
if [[ -n "$cloudflared_wrapper" && -n "$cloudflared_unit" ]]; then
  cp "$cloudflared_wrapper" "$bundle_dir/cloudflared-backoffice-wrapper"
  cp "$cloudflared_unit" "$bundle_dir/systemd/cloudflared-backoffice.service"
fi
if [[ -n "$app_binaries_release_tag" ]]; then
  mkdir -p "$bundle_dir/app-binaries"
  cp "$output_dir/app-binaries/bridge-api_linux_amd64" "$bundle_dir/app-binaries/bridge-api_linux_amd64"
  cp "$output_dir/app-binaries/backoffice_linux_amd64" "$bundle_dir/app-binaries/backoffice_linux_amd64"
fi

install_script="$output_dir/install.sh"
cat >"$install_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -d -m 0755 /etc/intents-juno /etc/nginx/intents-juno /etc/nginx/sites-available /etc/nginx/sites-enabled

if ! command -v jq >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y jq
fi

if ! command -v aws >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl unzip
  aws_tmp_dir="$(mktemp -d)"
  cleanup_aws_tmp_dir() {
    rm -rf "$aws_tmp_dir"
  }
  trap cleanup_aws_tmp_dir EXIT
  arch="$(uname -m)"
  case "$arch" in
    x86_64) aws_cli_zip_url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" ;;
    aarch64|arm64) aws_cli_zip_url="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" ;;
    *) printf 'unsupported architecture for awscli install: %s\n' "$arch" >&2; exit 1 ;;
  esac
  curl -fsSL "$aws_cli_zip_url" -o "$aws_tmp_dir/awscliv2.zip"
  unzip -q "$aws_tmp_dir/awscliv2.zip" -d "$aws_tmp_dir"
  "$aws_tmp_dir/aws/install" --update
  trap - EXIT
  rm -rf "$aws_tmp_dir"
fi

if [[ -d "$script_dir/app-binaries" ]]; then
  install -m 0755 "$script_dir/app-binaries/bridge-api_linux_amd64" /usr/local/bin/bridge-api
  install -m 0755 "$script_dir/app-binaries/backoffice_linux_amd64" /usr/local/bin/backoffice
fi

install -m 0600 "$script_dir/bridge-api.env" /etc/intents-juno/bridge-api.env
install -m 0600 "$script_dir/backoffice.env" /etc/intents-juno/backoffice.env
install -m 0600 "$script_dir/app-runtime-hydrator.env" /etc/intents-juno/app-runtime-hydrator.env
install -m 0755 "$script_dir/app-config-hydrator.sh" /usr/local/bin/intents-juno-app-config-hydrator.sh
install -m 0755 "$script_dir/bridge-api-wrapper" /usr/local/bin/bridge-api-wrapper
install -m 0755 "$script_dir/backoffice-wrapper" /usr/local/bin/backoffice-wrapper
install -m 0644 "$script_dir/systemd/intents-juno-app-config-hydrator.service" /etc/systemd/system/intents-juno-app-config-hydrator.service
install -m 0644 "$script_dir/systemd/bridge-api.service" /etc/systemd/system/bridge-api.service
install -m 0644 "$script_dir/systemd/backoffice.service" /etc/systemd/system/backoffice.service
if [[ -f "$script_dir/cloudflared-backoffice-wrapper" && -f "$script_dir/systemd/cloudflared-backoffice.service" ]]; then
  install -m 0755 "$script_dir/cloudflared-backoffice-wrapper" /usr/local/bin/cloudflared-backoffice-wrapper
  install -m 0644 "$script_dir/systemd/cloudflared-backoffice.service" /etc/systemd/system/cloudflared-backoffice.service
else
  rm -f /usr/local/bin/cloudflared-backoffice-wrapper /etc/systemd/system/cloudflared-backoffice.service
  systemctl disable --now cloudflared-backoffice.service >/dev/null 2>&1 || true
fi
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

systemctl daemon-reload
services=(
  intents-juno-app-config-hydrator.service
  bridge-api.service
  backoffice.service
  nginx.service
)
if [[ -f /etc/systemd/system/cloudflared-backoffice.service ]]; then
  services+=(cloudflared-backoffice.service)
fi
systemctl enable "${services[@]}" >/dev/null
systemctl restart intents-juno-app-config-hydrator.service
systemctl restart bridge-api.service
systemctl restart backoffice.service
nginx -t
systemctl restart nginx.service
if [[ -f /etc/systemd/system/cloudflared-backoffice.service ]]; then
  systemctl restart cloudflared-backoffice.service
fi

for _ in $(seq 1 60); do
  ready_services=(
    bridge-api.service
    backoffice.service
    nginx.service
    intents-juno-app-config-hydrator.service
  )
  if [[ -f /etc/systemd/system/cloudflared-backoffice.service ]]; then
    ready_services+=(cloudflared-backoffice.service)
  fi
  if systemctl is-active --quiet "${ready_services[@]}" && curl -ksfS https://127.0.0.1/healthz >/dev/null; then
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
app_host="$(jq -r '.app_role.host // .app_host // empty' "$app_deploy")"
app_target_mode="host"
app_targets_json='[]'
app_launch_template_id=""
app_launch_template_version=""

if [[ "$dry_run" != "true" ]]; then
  if [[ -n "$app_role_asg" ]]; then
    app_target_mode="asg"
    ensure_live_e2e_app_runtime_ingress "$shared_manifest" "$app_deploy" "$app_aws_profile" "$app_aws_region"
    asg_json="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$app_role_asg" \
      --output json)"
    app_launch_template_id="$(jq -r '.AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId // empty' <<<"$asg_json")"
    [[ -n "$app_launch_template_id" ]] || die "app role asg $app_role_asg did not return a launch template id"
    app_launch_template_source_version="$(jq -r '.AutoScalingGroups[0].LaunchTemplate.Version // empty' <<<"$asg_json")"
    [[ -n "$app_launch_template_source_version" ]] || die "app role asg $app_role_asg did not return a launch template version"
    bootstrap_user_data="$tmp_dir/app-launch-template-user-data.sh"
    render_app_runtime_bootstrap_user_data "$bundle_b64" "$bootstrap_user_data"
    launch_template_data_json="$(jq -cn --arg user_data "$(base64 <"$bootstrap_user_data" | tr -d '\n')" '{UserData: $user_data}')"
    launch_template_create_json="$(AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" ec2 create-launch-template-version \
      --launch-template-id "$app_launch_template_id" \
      --source-version "$app_launch_template_source_version" \
      --launch-template-data "$launch_template_data_json" \
      --output json)"
    app_launch_template_version="$(jq -r '.LaunchTemplateVersion.VersionNumber // empty' <<<"$launch_template_create_json")"
    [[ -n "$app_launch_template_version" && "$app_launch_template_version" != "null" ]] || die "failed to create a new launch template version for app role asg $app_role_asg"
    AWS_PAGER="" aws --profile "$app_aws_profile" --region "$app_aws_region" autoscaling update-auto-scaling-group \
      --auto-scaling-group-name "$app_role_asg" \
      --launch-template "LaunchTemplateId=$app_launch_template_id,Version=$app_launch_template_version" \
      >/dev/null
    app_deploy_tmp="$tmp_dir/app-deploy.json"
    jq \
      --arg lt_id "$app_launch_template_id" \
      --arg lt_version "$app_launch_template_version" \
      '
      if (.app_role? | type) == "object" then
        .app_role.launch_template = {id: $lt_id, version: $lt_version}
      else
        .
      end
      ' "$app_deploy" >"$app_deploy_tmp"
    mv "$app_deploy_tmp" "$app_deploy"
    app_targets_json="$(jq -c '[.AutoScalingGroups[0].Instances[]? | select(.LifecycleState == "InService") | .InstanceId]' <<<"$asg_json")"
    [[ "$(jq -r 'length' <<<"$app_targets_json")" -gt 0 ]] || die "app role asg $app_role_asg does not have any in-service instances"
  else
    [[ -n "$app_host" ]] || die "app deploy must define app_role.asg or app_host"
    app_targets_json="$(jq -cn --arg instance_id "$(production_resolve_instance_id_from_host "$app_aws_profile" "$app_aws_region" "$app_host")" '[ $instance_id ]')"
  fi

  while IFS= read -r instance_id; do
    [[ -n "$instance_id" ]] || continue
    remote_stage_dir="/tmp/intents-juno-app-runtime-$(production_safe_slug "$instance_id")"
    production_ssm_run_shell_command \
      "$app_aws_profile" "$app_aws_region" "$instance_id" \
      "sudo rm -rf '$remote_stage_dir' && sudo install -d -m 0755 '$remote_stage_dir'" >/dev/null \
      || die "failed to create app runtime stage dir over ssm: $remote_stage_dir"
    production_ssm_stage_file \
      "$app_aws_profile" "$app_aws_region" "$instance_id" \
      "$bundle_tar" \
      "$remote_stage_dir/app-runtime-bootstrap.tgz" \
      0640
    production_ssm_run_shell_command \
      "$app_aws_profile" "$app_aws_region" "$instance_id" \
      "set -euo pipefail; cleanup(){ sudo rm -rf '$remote_stage_dir'; }; trap cleanup EXIT; sudo tar -xzf '$remote_stage_dir/app-runtime-bootstrap.tgz' -C '$remote_stage_dir'; sudo bash '$remote_stage_dir/install.sh'" >/dev/null \
      || die "failed to refresh app runtime on instance $instance_id"
  done < <(jq -r '.[]' <<<"$app_targets_json")
elif [[ -n "$app_role_asg" ]]; then
  app_target_mode="asg"
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
  --arg app_launch_template_id "$app_launch_template_id" \
  --arg app_launch_template_version "$app_launch_template_version" \
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
      launch_template_id: (if $app_launch_template_id == "" then null else $app_launch_template_id end),
      launch_template_version: (if $app_launch_template_version == "" then null else $app_launch_template_version end),
      app_host: (if $app_host == "" then null else $app_host end),
      app_targets: $app_targets
    }
  '
