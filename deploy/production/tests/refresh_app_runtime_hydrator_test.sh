#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_shared_manifest_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "contracts": {
    "base_rpc_url": "https://mainnet.base.org",
    "base_chain_id": 8453,
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "bridge_params": {
      "fee_bps": 50,
      "withdrawal_expiry_window_seconds": 86400,
      "min_deposit_amount": 200000000,
      "min_withdraw_amount": 200000000
    },
    "owallet_ua": "j1example"
  },
  "shared_services": {
    "kafka": {
      "bootstrap_brokers": "b-1.example:9098,b-2.example:9098"
    },
    "ipfs": {
      "api_url": "http://internal-ipfs.example:5001"
    },
    "proof": {
      "requestor_address": "0x4444444444444444444444444444444444444444",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  }
}
JSON
}

write_app_deploy_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "3",
  "environment": "mainnet",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "runtime_config_secret_id": "intents-juno-mainnet-app-runtime-config",
  "runtime_config_secret_region": "us-east-1",
  "public_endpoint": "juno-app-runtime-mainnet-bridge.example.elb.amazonaws.com",
  "operator_addresses": [
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ],
  "operator_endpoints": [
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=10.0.0.10:18443"
  ],
  "service_urls": [
    "bridge-api=http://127.0.0.1:8082/readyz"
  ],
  "app_role": {
    "host": "10.0.0.20",
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "account_id": "054422645452",
    "runtime_config_secret_id": "intents-juno-mainnet-app-runtime-config",
    "runtime_config_secret_region": "us-east-1",
    "bridge_public_dns_label": "bridge",
    "backoffice_dns_label": "ops",
    "public_scheme": "https",
    "bridge_api_listen": "127.0.0.1:8082",
    "backoffice_listen": "127.0.0.1:8090",
    "juno_rpc_url": "http://127.0.0.1:18232",
    "service_urls": [
      "bridge-api=http://127.0.0.1:8082/readyz"
    ],
    "operator_endpoints": [
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=10.0.0.10:18443"
    ],
    "edge_viewer_certificate_arn": "arn:aws:acm:us-east-1:054422645452:certificate/example"
  },
  "services": {
    "bridge_api": {
      "listen_addr": "127.0.0.1:8082",
      "record_name": "bridge.junointents.com",
      "public_url": "https://bridge.junointents.com",
      "probe_url": "https://bridge.junointents.com",
      "internal_url": "http://127.0.0.1:8082",
      "withdrawal_expiry_window_seconds": 86400,
      "min_deposit_amount": 200000000,
      "min_withdraw_amount": 200000000,
      "fee_bps": 50
    },
    "backoffice": {
      "listen_addr": "127.0.0.1:8090",
      "record_name": "ops.junointents.com",
      "public_url": "https://ops.junointents.com",
      "probe_url": "http://127.0.0.1:8090",
      "internal_url": "http://127.0.0.1:8090",
      "access": {
        "mode": "cloudflare-access",
        "source_cidrs": [],
        "publish_public_dns": false
      }
    }
  },
  "dns": {
    "mode": "external",
    "zone_name": "junointents.com",
    "ttl_seconds": 60
  },
  "edge": {
    "enabled": true,
    "state_path": "/tmp/mainnet.tfstate",
    "origin_record_name": "origin.junointents.com",
    "origin_http_port": 443,
    "rate_limit": 2000,
    "alarm_actions": [
      "arn:aws:sns:us-east-1:054422645452:intents-juno-mainnet-alerts"
    ],
    "enable_shield_advanced": false,
    "public_lb_dns_name": "juno-app-runtime-mainnet-bridge.example.elb.amazonaws.com",
    "public_lb_zone_id": "Z35SXDOTRQ7X7K",
    "viewer_certificate_arn": "arn:aws:acm:us-east-1:054422645452:certificate/example"
  }
}
JSON
}

write_fake_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
EOF
  chmod +x "$target"
}

write_fake_aws() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '{}\n'
EOF
  chmod +x "$target"
}

test_refresh_app_runtime_install_script_bootstraps_host_hydrator_dependencies() {
  local tmp fake_bin shared_manifest app_deploy output_dir
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  shared_manifest="$tmp/shared-manifest.json"
  app_deploy="$tmp/app-deploy.json"
  output_dir="$tmp/output"
  mkdir -p "$fake_bin" "$output_dir"

  write_shared_manifest_fixture "$shared_manifest"
  write_app_deploy_fixture "$app_deploy"
  write_fake_cast "$fake_bin/cast"
  write_fake_aws "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-app-runtime.sh" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --output-dir "$output_dir" \
        --dry-run >/dev/null
  )

  assert_contains "$(cat "$output_dir/install.sh")" 'apt-get install -y jq' "refresh bootstrap installs jq from apt when the host is missing it"
  assert_contains "$(cat "$output_dir/install.sh")" 'awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' "refresh bootstrap installs awscli from the official v2 bundle"

  rm -rf "$tmp"
}

main() {
  test_refresh_app_runtime_install_script_bootstraps_host_hydrator_dependencies
}

main "$@"
