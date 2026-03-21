#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if grep -Fq -- "$needle" <<<"$haystack"; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_refresh_runtime_shared_manifest_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid",
    "base_chain_id": 84532,
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "owallet_ua": "u1previewexample"
  },
  "shared_services": {
    "kafka": {
      "bootstrap_brokers": "b-1.preview.kafka:9098,b-2.preview.kafka:9098"
    },
    "ipfs": {
      "api_url": "http://preview-ipfs:5001"
    },
    "proof": {
      "requestor_address": "0x4444444444444444444444444444444444444444",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  },
  "shared_roles": {
    "wireguard": {
      "backoffice_hostname": "ops.preview.intents-testing.thejunowallet.com"
    }
  },
  "wireguard_role": {
    "backoffice_hostname": "ops.preview.intents-testing.thejunowallet.com"
  }
}
JSON
}

write_refresh_runtime_app_secret_contract() {
  local target="$1"
  cat >"$target" <<'EOF'
APP_POSTGRES_DSN=literal:postgres://preview
BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
}

write_refresh_runtime_operator_secret_contract() {
  local target="$1"
  local key="$2"
  cat >"$target" <<EOF
BASE_RELAYER_PRIVATE_KEYS=literal:$key
EOF
}

write_refresh_runtime_operator_handoff() {
  local output_root="$1"
  local operator_id="$2"
  local secret_contract="$3"
  mkdir -p "$output_root/operators/$operator_id"
  cat >"$output_root/operators/$operator_id/operator-deploy.json" <<JSON
{
  "environment": "preview",
  "secret_contract_file": "$secret_contract"
}
JSON
}

write_refresh_runtime_app_deploy_fixture() {
  local target="$1"
  local secret_contract="$2"
  cat >"$target" <<JSON
{
  "version": "2",
  "environment": "preview",
  "secret_contract_file": "$secret_contract",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "juno_rpc_url": "http://127.0.0.1:18232",
  "app_role": {
    "asg": "preview-app-asg"
  },
  "operator_addresses": [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222"
  ],
  "operator_endpoints": [
    "0x1111111111111111111111111111111111111111=10.0.0.12:18443",
    "0x2222222222222222222222222222222222222222=10.0.1.13:18444"
  ],
  "service_urls": [
    "bridge-api=http://127.0.0.1:8082/readyz"
  ],
  "services": {
    "bridge_api": {
      "listen_addr": "127.0.0.1:8082",
      "record_name": "bridge.preview.intents-testing.thejunowallet.com",
      "public_url": "https://bridge.preview.intents-testing.thejunowallet.com",
      "probe_url": "https://bridge.preview.intents-testing.thejunowallet.com",
      "internal_url": "http://127.0.0.1:8082",
      "withdrawal_expiry_window_seconds": 86400,
      "min_deposit_amount": 201005025,
      "min_withdraw_amount": 200000000,
      "fee_bps": 50
    },
    "backoffice": {
      "listen_addr": "127.0.0.1:8090",
      "internal_url": "http://127.0.0.1:8090",
      "access": {
        "mode": "wireguard"
      }
    }
  }
}
JSON
}

write_fake_refresh_runtime_aws() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >>"$TEST_AWS_LOG"
args=( "$@" )
if [[ "${args[0]:-}" == "--profile" ]]; then
  args=( "${args[@]:2}" )
fi
if [[ "${args[0]:-}" == "--region" ]]; then
  args=( "${args[@]:2}" )
fi
case "${args[*]}" in
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-app-asg --output json")
    printf '{"AutoScalingGroups":[{"Instances":[{"InstanceId":"i-app001","LifecycleState":"InService","HealthStatus":"Healthy"},{"InstanceId":"i-app002","LifecycleState":"InService","HealthStatus":"Unhealthy"},{"InstanceId":"i-app003","LifecycleState":"Terminating","HealthStatus":"Unhealthy"}]}]}\n'
    ;;
  ssm\ send-command\ --instance-ids\ i-app001\ --document-name\ AWS-RunShellScript\ --parameters\ *\ --output\ json)
    printf '{"Command":{"CommandId":"cmd-app001"}}\n'
    ;;
  ssm\ send-command\ --instance-ids\ i-app002\ --document-name\ AWS-RunShellScript\ --parameters\ *\ --output\ json)
    printf '{"Command":{"CommandId":"cmd-app002"}}\n'
    ;;
  "ssm get-command-invocation --command-id cmd-app001 --instance-id i-app001 --output json")
    printf '{"Status":"Success","StandardOutputContent":"","StandardErrorContent":""}\n'
    ;;
  "ssm get-command-invocation --command-id cmd-app002 --instance-id i-app002 --output json")
    printf '{"Status":"Success","StandardOutputContent":"","StandardErrorContent":""}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_refresh_runtime_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
EOF
  chmod +x "$target"
}

test_refresh_app_runtime_bootstraps_all_in_service_app_instances_via_ssm() {
  local tmp fake_bin aws_log shared_manifest app_deploy secret_contract output_dir operators_root
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"
  shared_manifest="$tmp/shared-manifest.json"
  output_dir="$tmp/output"
  operators_root="$tmp"
  mkdir -p "$fake_bin" "$tmp/app" "$output_dir"

  secret_contract="$tmp/app/app-secrets.env"
  app_deploy="$tmp/app/app-deploy.json"
  write_refresh_runtime_shared_manifest_fixture "$shared_manifest"
  write_refresh_runtime_app_secret_contract "$secret_contract"
  write_refresh_runtime_app_deploy_fixture "$app_deploy" "$secret_contract"
  write_refresh_runtime_operator_secret_contract "$tmp/op1-secrets.env" "0x1111111111111111111111111111111111111111111111111111111111111111"
  write_refresh_runtime_operator_secret_contract "$tmp/op2-secrets.env" "0x2222222222222222222222222222222222222222222222222222222222222222"
  write_refresh_runtime_operator_handoff "$operators_root" "0x1111111111111111111111111111111111111111" "$tmp/op1-secrets.env"
  write_refresh_runtime_operator_handoff "$operators_root" "0x2222222222222222222222222222222222222222" "$tmp/op2-secrets.env"
  write_fake_refresh_runtime_aws "$fake_bin/aws"
  write_fake_refresh_runtime_cast "$fake_bin/cast"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-app-runtime.sh" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --output-dir "$output_dir" >"$tmp/refresh-summary.json"
  )

  assert_contains "$(cat "$output_dir/bridge-api.env")" "BRIDGE_API_BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111" "refresh renders the bridge env"
  assert_contains "$(cat "$output_dir/backoffice.env")" "BACKOFFICE_AUTH_SECRET=backoffice-token" "refresh renders the backoffice env"
  assert_contains "$(cat "$output_dir/install.sh")" 'script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"' "refresh writes a self-locating install script for remote bundle extraction"
  assert_contains "$(cat "$output_dir/install.sh")" 'for _ in $(seq 1 60); do' "refresh allows slow app runtime startup during the remote readiness gate"
  assert_contains "$(cat "$output_dir/install.sh")" 'sleep 5' "refresh backs off between remote readiness checks so the app can finish booting"
  assert_contains "$(cat "$output_dir/install.sh")" 'systemctl is-active --quiet bridge-api.service backoffice.service nginx.service' "refresh treats supervised local services as the remote bootstrap success gate"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "map_hash_bucket_size 128;" "refresh sizes nginx host routing maps for long preview hostnames"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "bridge.preview.intents-testing.thejunowallet.com" "refresh renders bridge host routing into nginx config"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "ops.preview.intents-testing.thejunowallet.com" "refresh renders backoffice host routing into nginx config"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-app-asg" "refresh discovers app instances from the app role asg"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app001" "refresh bootstraps the first in-service app instance over ssm"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app002" "refresh bootstraps the second in-service app instance over ssm even before it is marked healthy"
  assert_not_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app003" "refresh skips terminating app instances"
  assert_eq "$(jq -r '.app_target_mode' "$tmp/refresh-summary.json")" "asg" "refresh summary reports app role mode"
  assert_eq "$(jq -r '.app_targets[0]' "$tmp/refresh-summary.json")" "i-app001" "refresh summary reports the first app instance id"
  assert_eq "$(jq -r '.app_targets[1]' "$tmp/refresh-summary.json")" "i-app002" "refresh summary reports the second app instance id"
  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/refresh-summary.json")" "true" "refresh summary reports success"

  rm -rf "$tmp"
}

main() {
  test_refresh_app_runtime_bootstraps_all_in_service_app_instances_via_ssm
}

main "$@"
