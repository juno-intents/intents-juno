#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_refresh_runtime_cloudflare_shared_manifest() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "contracts": {
    "base_rpc_url": "https://base-mainnet.example.invalid",
    "base_chain_id": 8453,
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "owallet_ua": "u1mainnetexample"
  },
  "shared_services": {
    "kafka": {
      "bootstrap_brokers": "b-1.mainnet.kafka:9098,b-2.mainnet.kafka:9098"
    },
    "ipfs": {
      "api_url": "http://shared-ipfs-mainnet.example.internal:5001"
    },
    "proof": {
      "requestor_address": "0x4444444444444444444444444444444444444444",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  }
}
JSON
}

write_refresh_runtime_cloudflare_app_deploy() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "3",
  "environment": "mainnet",
  "runtime_config_secret_id": "mainnet/app/runtime-config",
  "runtime_config_secret_region": "us-east-1",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "juno_rpc_url": "http://127.0.0.1:18232",
  "app_role": {
    "host": "203.0.113.21",
    "user": "ubuntu",
    "runtime_dir": "/var/lib/intents-juno/app-runtime"
  },
  "operator_addresses": [
    "0x1111111111111111111111111111111111111111"
  ],
  "service_urls": [
    "bridge-api=http://127.0.0.1:8082/readyz"
  ],
  "operator_endpoints": [
    "0x1111111111111111111111111111111111111111=10.0.0.12:18443"
  ],
  "services": {
    "bridge_api": {
      "listen_addr": "127.0.0.1:8082",
      "record_name": "bridge.junointents.com",
      "public_url": "https://bridge.junointents.com",
      "probe_url": "https://bridge.junointents.com",
      "internal_url": "http://127.0.0.1:8082",
      "withdrawal_expiry_window_seconds": 86400,
      "min_deposit_amount": 201005025,
      "min_withdraw_amount": 200000000,
      "fee_bps": 50
    },
    "backoffice": {
      "listen_addr": "127.0.0.1:8090",
      "public_url": "https://ops.junointents.com",
      "probe_url": "http://127.0.0.1:8090",
      "internal_url": "http://127.0.0.1:8090",
      "record_name": "ops.junointents.com",
      "access": {
        "mode": "cloudflare-access"
      }
    }
  }
}
JSON
}

write_fake_refresh_runtime_cloudflare_aws() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >>"$TEST_AWS_LOG"
exit 0
EOF
  chmod +x "$target"
}

write_fake_refresh_runtime_cloudflare_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
EOF
  chmod +x "$target"
}

test_refresh_app_runtime_renders_cloudflared_service_for_access_backoffice() {
  local tmp fake_bin aws_log shared_manifest app_deploy output_dir
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"
  shared_manifest="$tmp/shared-manifest.json"
  app_deploy="$tmp/app-deploy.json"
  output_dir="$tmp/output"

  mkdir -p "$fake_bin" "$output_dir"
  : >"$aws_log"

  write_refresh_runtime_cloudflare_shared_manifest "$shared_manifest"
  write_refresh_runtime_cloudflare_app_deploy "$app_deploy"
  write_fake_refresh_runtime_cloudflare_aws "$fake_bin/aws"
  write_fake_refresh_runtime_cloudflare_cast "$fake_bin/cast"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-app-runtime.sh" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --output-dir "$output_dir" \
        --dry-run >/dev/null
  )

  assert_file_exists "$output_dir/systemd/cloudflared-backoffice.service" "refresh renders a cloudflared systemd unit"
  assert_file_exists "$output_dir/bin/cloudflared-backoffice-wrapper" "refresh renders a cloudflared wrapper"
  assert_contains "$(cat "$output_dir/backoffice.env")" "BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN=" "refresh seeds a tunnel token placeholder into the backoffice env"
  assert_contains "$(cat "$output_dir/install.sh")" "cloudflared-backoffice.service" "refresh installs the cloudflared service when backoffice access uses cloudflare"
  assert_contains "$(cat "$output_dir/install.sh")" "systemctl restart cloudflared-backoffice.service" "refresh restarts cloudflared during install"
  rm -rf "$tmp"
}

main() {
  test_refresh_app_runtime_renders_cloudflared_service_for_access_backoffice
  printf 'refresh_app_runtime_cloudflare_test: PASS\n'
}

main "$@"
