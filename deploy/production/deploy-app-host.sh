#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  deploy-app-host.sh --app-deploy PATH --release-tag TAG [options]

Options:
  --app-deploy PATH           App deploy manifest (required)
  --release-tag TAG           GitHub release tag containing bridge-api/backoffice assets (required)
  --repo OWNER/REPO           GitHub repo for the release (default: juno-intents/intents-juno)
  --known-hosts PATH          Override known_hosts path from manifest
  --secret-contract-file PATH Override app secret contract path from manifest
  --dry-run                   Validate and print actions without mutating remote state
EOF
}

app_deploy=""
release_tag=""
repo="juno-intents/intents-juno"
known_hosts_override=""
secret_contract_override=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-deploy) app_deploy="$2"; shift 2 ;;
    --release-tag) release_tag="$2"; shift 2 ;;
    --repo) repo="$2"; shift 2 ;;
    --known-hosts) known_hosts_override="$2"; shift 2 ;;
    --secret-contract-file) secret_contract_override="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$app_deploy" ]] || die "--app-deploy is required"
[[ -f "$app_deploy" ]] || die "app deploy manifest not found: $app_deploy"
[[ -n "$release_tag" ]] || die "--release-tag is required"

for cmd in jq gh sha256sum ssh scp; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  have_cmd aws || die "required command not found: aws"
fi

manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$app_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"

known_hosts_file="$known_hosts_override"
if [[ -z "$known_hosts_file" ]]; then
  known_hosts_file="$(production_json_required "$app_deploy" '.known_hosts_file | select(type == "string" and length > 0)')"
fi
known_hosts_file="$(production_abs_path "$manifest_dir" "$known_hosts_file")"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"

secret_contract_file="$secret_contract_override"
if [[ -z "$secret_contract_file" ]]; then
  secret_contract_file="$(production_json_required "$app_deploy" '.secret_contract_file | select(type == "string" and length > 0)')"
fi
secret_contract_file="$(production_abs_path "$manifest_dir" "$secret_contract_file")"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"

environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
[[ "$environment" == "alpha" ]] && allow_local_resolvers="true"

app_host="$(production_json_required "$app_deploy" '.app_host | select(type == "string" and length > 0)')"
app_user="$(production_json_required "$app_deploy" '.app_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$app_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
public_endpoint="$(production_json_required "$app_deploy" '.public_endpoint | select(type == "string" and length > 0)')"
aws_profile="$(production_json_optional "$app_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$app_deploy" '.aws_region')"
security_group_id="$(production_json_optional "$app_deploy" '.security_group_id')"
public_scheme="$(production_json_required "$app_deploy" '.public_scheme | select(type == "string" and length > 0)')"
dns_mode="$(production_json_optional "$app_deploy" '.dns.mode')"
zone_id="$(production_json_optional "$app_deploy" '.dns.zone_id')"
ttl_seconds="$(production_json_optional "$app_deploy" '.dns.ttl_seconds')"
acme_account_email="${ACME_ACCOUNT_EMAIL:-ops@thejunowallet.com}"

bridge_record_name="$(production_json_required "$app_deploy" '.services.bridge_api.record_name | select(type == "string" and length > 0)')"
bridge_listen_addr="$(production_json_required "$app_deploy" '.services.bridge_api.listen_addr | select(type == "string" and length > 0)')"
backoffice_record_name="$(production_json_required "$app_deploy" '.services.backoffice.record_name | select(type == "string" and length > 0)')"
backoffice_listen_addr="$(production_json_required "$app_deploy" '.services.backoffice.listen_addr | select(type == "string" and length > 0)')"
shared_kafka_brokers="$(production_json_required "$shared_manifest_path" '.shared_services.kafka.bootstrap_brokers | select(type == "string" and length > 0)')"
shared_ipfs_api_url="$(production_json_required "$shared_manifest_path" '.shared_services.ipfs.api_url | select(type == "string" and length > 0)')"
checkpoint_signature_topic="$(production_json_required "$shared_manifest_path" '.checkpoint.signature_topic | select(type == "string" and length > 0)')"
checkpoint_package_topic="$(production_json_required "$shared_manifest_path" '.checkpoint.package_topic | select(type == "string" and length > 0)')"
checkpoint_threshold="$(production_json_required "$shared_manifest_path" '.checkpoint.threshold')"
checkpoint_operators_csv="$(jq -r '.checkpoint.operators | map(select(type == "string" and length > 0)) | join(",")' "$shared_manifest_path")"

bridge_port="$(production_port_from_listen_addr "$bridge_listen_addr")"
backoffice_port="$(production_port_from_listen_addr "$backoffice_listen_addr")"
[[ "$public_scheme" == "https" ]] || die "app deploy manifest must use public_scheme=https"
production_require_loopback_listen_addr "$bridge_listen_addr" "services.bridge_api.listen_addr"
production_require_loopback_listen_addr "$backoffice_listen_addr" "services.backoffice.listen_addr"
[[ "$checkpoint_threshold" =~ ^[0-9]+$ ]] || die "shared manifest checkpoint.threshold must be numeric"
[[ -n "$checkpoint_operators_csv" ]] || die "shared manifest checkpoint.operators must not be empty"
ssh_target="${app_user}@${app_host}"
SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)

tmp_dir="$(mktemp -d)"
download_dir="$tmp_dir/release"
resolved_env="$tmp_dir/app-secrets.resolved.env"
bridge_env="$tmp_dir/bridge-api.env"
backoffice_env="$tmp_dir/backoffice.env"
mkdir -p "$download_dir"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

download_release_asset() {
  local asset_name="$1"
  gh release download "$release_tag" --repo "$repo" --pattern "$asset_name" --dir "$download_dir"
  gh release download "$release_tag" --repo "$repo" --pattern "${asset_name}.sha256" --dir "$download_dir"
  (
    cd "$download_dir"
    sha256sum -c "${asset_name}.sha256"
  )
}

ensure_security_group_ingress() {
  local port="$1"
  [[ -n "$security_group_id" && -n "$aws_region" ]] || return 0

  local -a aws_args=(aws)
  [[ -n "$aws_profile" ]] && aws_args+=(--profile "$aws_profile")
  aws_args+=(--region "$aws_region")

  local output status
  set +e
  output="$(AWS_PAGER="" "${aws_args[@]}" ec2 authorize-security-group-ingress \
    --group-id "$security_group_id" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":${port},\"ToPort\":${port},\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\",\"Description\":\"intents-juno app\"}]}]" 2>&1)"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    return 0
  fi
  if [[ "$output" == *"InvalidPermission.Duplicate"* || "$output" == *"already exists"* ]]; then
    return 0
  fi
  printf '%s\n' "$output" >&2
  die "failed to authorize security group ingress on port $port"
}

production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
production_render_bridge_api_env "$shared_manifest_path" "$app_deploy" "$resolved_env" "$bridge_env"
production_render_backoffice_env "$shared_manifest_path" "$app_deploy" "$resolved_env" "$backoffice_env"
shared_postgres_dsn="$(production_env_first_value "$bridge_env" BRIDGE_API_POSTGRES_DSN CHECKPOINT_POSTGRES_DSN || true)"
[[ -n "$shared_postgres_dsn" ]] || die "rendered bridge-api env is missing postgres dsn for shared infra validation"
required_kafka_topics_csv="$(
  printf '%s\n' \
    "$checkpoint_signature_topic" \
    "$checkpoint_package_topic" \
    "proof.requests.v1" \
    "proof.fulfillments.v1" \
    "proof.failures.v1" \
    "deposits.event.v1" \
    "withdrawals.requested.v1" \
    "ops.alerts.v1" \
    | awk 'NF && !seen[$0]++' \
    | paste -sd, -
)"
kafka_tls_enabled="$(production_json_optional "$shared_manifest_path" '.shared_services.kafka.tls')"
if [[ "$kafka_tls_enabled" != "true" ]]; then
  kafka_tls_enabled="false"
fi

download_release_asset "bridge-api_linux_amd64"
download_release_asset "backoffice_linux_amd64"
download_release_asset "shared-infra-e2e_linux_amd64"

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would deploy bridge-api and backoffice to $ssh_target from release $release_tag"
  exit 0
fi

if [[ "$public_scheme" == "https" ]]; then
  ensure_security_group_ingress 80
  ensure_security_group_ingress 443
else
  ensure_security_group_ingress "$bridge_port"
  ensure_security_group_ingress "$backoffice_port"
fi

if [[ "$dns_mode" == "public-zone" && -n "$zone_id" && -n "$ttl_seconds" ]]; then
  production_publish_dns_record "$aws_profile" "$aws_region" "$zone_id" "$bridge_record_name" "$ttl_seconds" "$public_endpoint"
  production_publish_dns_record "$aws_profile" "$aws_region" "$zone_id" "$backoffice_record_name" "$ttl_seconds" "$public_endpoint"
fi

remote_stage_dir="/tmp/intents-juno-app-deploy"
ssh "${SSH_OPTS[@]}" "$ssh_target" "rm -rf '$remote_stage_dir' && mkdir -p '$remote_stage_dir'"
scp "${SSH_OPTS[@]}" \
  "$download_dir/bridge-api_linux_amd64" \
  "$download_dir/backoffice_linux_amd64" \
  "$download_dir/shared-infra-e2e_linux_amd64" \
  "$bridge_env" \
  "$backoffice_env" \
  "$shared_manifest_path" \
  "$app_deploy" \
  "$ssh_target:$remote_stage_dir/"

ssh "${SSH_OPTS[@]}" "$ssh_target" "bash -s" <<EOF
set -euo pipefail
remote_stage_dir="$remote_stage_dir"
runtime_dir="$runtime_dir"
bridge_api_wrapper="/usr/local/bin/intents-juno-bridge-api.sh"
backoffice_wrapper="/usr/local/bin/intents-juno-backoffice.sh"
shared_infra_e2e_bin="\$runtime_dir/bin/shared-infra-e2e"
shared_infra_report="\$runtime_dir/shared-infra-e2e.json"
bridge_api_env="/etc/intents-juno/bridge-api.env"
backoffice_env="/etc/intents-juno/backoffice.env"
public_scheme="$public_scheme"
acme_account_email="$acme_account_email"
bridge_record_name="$bridge_record_name"
backoffice_record_name="$backoffice_record_name"
shared_postgres_dsn="$shared_postgres_dsn"
shared_kafka_brokers="$shared_kafka_brokers"
shared_required_kafka_topics="$required_kafka_topics_csv"
shared_ipfs_api_url="$shared_ipfs_api_url"
shared_checkpoint_operators="$checkpoint_operators_csv"
shared_checkpoint_threshold="$checkpoint_threshold"
kafka_tls_enabled="$kafka_tls_enabled"

if ! id -u intents-juno >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir /var/lib/intents-juno --shell /usr/sbin/nologin intents-juno
fi

sudo install -d -m 0755 -o intents-juno -g intents-juno "\$runtime_dir"
sudo install -d -m 0755 -o intents-juno -g intents-juno "\$runtime_dir/bin"
sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno
sudo install -m 0755 "\$remote_stage_dir/bridge-api_linux_amd64" "\$runtime_dir/bin/bridge-api"
sudo install -m 0755 "\$remote_stage_dir/backoffice_linux_amd64" "\$runtime_dir/bin/backoffice"
sudo install -m 0755 "\$remote_stage_dir/shared-infra-e2e_linux_amd64" "\$shared_infra_e2e_bin"
sudo install -m 0640 -o root -g intents-juno "\$remote_stage_dir/bridge-api.env" "\$bridge_api_env"
sudo install -m 0640 -o root -g intents-juno "\$remote_stage_dir/backoffice.env" "\$backoffice_env"

sudo -u intents-juno env \
  JUNO_QUEUE_KAFKA_TLS="\$kafka_tls_enabled" \
  "\$shared_infra_e2e_bin" \
    --postgres-dsn "\$shared_postgres_dsn" \
    --kafka-brokers "\$shared_kafka_brokers" \
    --required-kafka-topics "\$shared_required_kafka_topics" \
    --checkpoint-ipfs-api-url "\$shared_ipfs_api_url" \
    --checkpoint-operators "\$shared_checkpoint_operators" \
    --checkpoint-threshold "\$shared_checkpoint_threshold" \
    --output "\$shared_infra_report"

bridge_wrapper_tmp="\$(mktemp)"
cat >"\$bridge_wrapper_tmp" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
args=(
  --listen "\$BRIDGE_API_LISTEN_ADDR"
  --postgres-dsn "\$BRIDGE_API_POSTGRES_DSN"
  --base-chain-id "\$BRIDGE_API_BASE_CHAIN_ID"
  --bridge-address "\$BRIDGE_API_BRIDGE_ADDRESS"
  --owallet-ua "\$BRIDGE_API_OWALLET_UA"
  --refund-window-seconds "\$BRIDGE_API_REFUND_WINDOW_SECONDS"
  --min-deposit-amount "\$BRIDGE_API_MIN_DEPOSIT_AMOUNT"
  --min-withdraw-amount "\$BRIDGE_API_MIN_WITHDRAW_AMOUNT"
  --fee-bps "\$BRIDGE_API_FEE_BPS"
)
if [[ -n "\${BRIDGE_API_WJUNO_ADDRESS:-}" ]]; then
  args+=(--wjuno-address "\$BRIDGE_API_WJUNO_ADDRESS")
fi
exec __RUNTIME_DIR__/bin/bridge-api "\${args[@]}"
WRAP
sed -i.bak "s|__RUNTIME_DIR__|$runtime_dir|g" "\$bridge_wrapper_tmp"
rm -f "\$bridge_wrapper_tmp.bak"
sudo install -m 0755 "\$bridge_wrapper_tmp" "\$bridge_api_wrapper"
rm -f "\$bridge_wrapper_tmp"

backoffice_wrapper_tmp="\$(mktemp)"
cat >"\$backoffice_wrapper_tmp" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
args=(
  --listen "\$BACKOFFICE_LISTEN_ADDR"
  --postgres-dsn "\$BACKOFFICE_POSTGRES_DSN"
  --base-rpc-url "\$BACKOFFICE_BASE_RPC_URL"
  --auth-secret "\$BACKOFFICE_AUTH_SECRET"
  --bridge-address "\$BACKOFFICE_BRIDGE_ADDRESS"
  --wjuno-address "\$BACKOFFICE_WJUNO_ADDRESS"
  --operator-registry-address "\$BACKOFFICE_OPERATOR_REGISTRY_ADDRESS"
  --operator-addresses "\$BACKOFFICE_OPERATOR_ADDRESSES"
  --kafka-brokers "\$BACKOFFICE_KAFKA_BROKERS"
  --ipfs-api-url "\$BACKOFFICE_IPFS_API_URL"
)
if [[ -n "\${BACKOFFICE_JUNO_RPC_URL:-}" ]]; then
  args+=(--juno-rpc-url "\$BACKOFFICE_JUNO_RPC_URL")
fi
if [[ -n "\${BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS:-}" ]]; then
  args+=(--fee-distributor-address "\$BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS")
fi
if [[ -n "\${BACKOFFICE_JUNO_RPC_USER:-}" ]]; then
  args+=(--juno-rpc-user "\$BACKOFFICE_JUNO_RPC_USER")
fi
if [[ -n "\${BACKOFFICE_JUNO_RPC_PASS:-}" ]]; then
  args+=(--juno-rpc-pass "\$BACKOFFICE_JUNO_RPC_PASS")
fi
if [[ -n "\${BACKOFFICE_SERVICE_URLS:-}" ]]; then
  args+=(--service-urls "\$BACKOFFICE_SERVICE_URLS")
fi
if [[ -n "\${BACKOFFICE_OPERATOR_ENDPOINTS:-}" ]]; then
  args+=(--operator-endpoints "\$BACKOFFICE_OPERATOR_ENDPOINTS")
fi
exec __RUNTIME_DIR__/bin/backoffice "\${args[@]}"
WRAP
sed -i.bak "s|__RUNTIME_DIR__|$runtime_dir|g" "\$backoffice_wrapper_tmp"
rm -f "\$backoffice_wrapper_tmp.bak"
sudo install -m 0755 "\$backoffice_wrapper_tmp" "\$backoffice_wrapper"
rm -f "\$backoffice_wrapper_tmp"

bridge_unit_tmp="\$(mktemp)"
cat >"\$bridge_unit_tmp" <<'UNIT'
[Unit]
Description=Intents Juno Bridge API
After=network-online.target
Wants=network-online.target

[Service]
User=intents-juno
Group=intents-juno
EnvironmentFile=/etc/intents-juno/bridge-api.env
ExecStart=/usr/local/bin/intents-juno-bridge-api.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo install -m 0644 "\$bridge_unit_tmp" /etc/systemd/system/bridge-api.service
rm -f "\$bridge_unit_tmp"

backoffice_unit_tmp="\$(mktemp)"
cat >"\$backoffice_unit_tmp" <<'UNIT'
[Unit]
Description=Intents Juno Backoffice
After=network-online.target
Wants=network-online.target

[Service]
User=intents-juno
Group=intents-juno
EnvironmentFile=/etc/intents-juno/backoffice.env
ExecStart=/usr/local/bin/intents-juno-backoffice.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo install -m 0644 "\$backoffice_unit_tmp" /etc/systemd/system/backoffice.service
rm -f "\$backoffice_unit_tmp"

if [[ "\$public_scheme" == "https" ]]; then
  if ! command -v caddy >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y caddy
  fi
  caddyfile_tmp="\$(mktemp)"
  cat >"\$caddyfile_tmp" <<CADDY
{
  email \$acme_account_email
}

\$bridge_record_name {
  encode zstd gzip
  reverse_proxy 127.0.0.1:$bridge_port
}

\$backoffice_record_name {
  encode zstd gzip
  reverse_proxy 127.0.0.1:$backoffice_port
}
CADDY
  sudo install -m 0644 "\$caddyfile_tmp" /etc/caddy/Caddyfile
  rm -f "\$caddyfile_tmp"
fi

sudo systemctl daemon-reload
sudo systemctl enable bridge-api backoffice >/dev/null
sudo systemctl restart bridge-api
sudo systemctl restart backoffice
if [[ "\$public_scheme" == "https" ]]; then
  sudo systemctl enable caddy >/dev/null
  sudo systemctl restart caddy
fi
sudo rm -rf "\$remote_stage_dir"
EOF

ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active bridge-api"
ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active backoffice"
if [[ "$public_scheme" == "https" ]]; then
  ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active caddy"
fi
