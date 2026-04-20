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

assert_line_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"
  local first_line second_line
  first_line="$(awk -v needle="$first" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  second_line="$(awk -v needle="$second" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'assert_line_order failed: %s\nfirst=%s (line %s)\nsecond=%s (line %s)\n' "$msg" "$first" "${first_line:-missing}" "$second" "${second_line:-missing}" >&2
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
  "runtime_config_secret_id": "intents-juno-mainnet-app-runtime-config",
  "runtime_config_secret_region": "us-east-1",
  "juno_rpc_url": "http://127.0.0.1:18232",
  "juno_scan_url": "http://10.0.0.12:8080",
  "juno_scan_wallet_id": "wallet-mainnet-f8379377446f",
  "app_role": {
    "asg": "preview-app-asg",
    "app_instance_profile_name": "juno-live-e2e-preview0316d-instance-profile",
    "app_security_group_id": "sg-approle1234567890"
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
  "launch_template": {
    "id": "lt-app1234567890",
    "version": "9"
  },
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
    printf '{"AutoScalingGroups":[{"LaunchTemplate":{"LaunchTemplateId":"lt-app1234567890","Version":"9"},"Instances":[{"InstanceId":"i-app001","LifecycleState":"InService","HealthStatus":"Healthy"},{"InstanceId":"i-app002","LifecycleState":"InService","HealthStatus":"Unhealthy"},{"InstanceId":"i-app003","LifecycleState":"Terminating","HealthStatus":"Unhealthy"}]}]}\n'
    ;;
  "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-shared-sg --query SecurityGroups[0].GroupId --output text")
    printf 'sg-shared1234567890\n'
    ;;
  "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-ipfs-sg --query SecurityGroups[0].GroupId --output text")
    printf 'sg-ipfs1234567890\n'
    ;;
  "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-operator-sg --query SecurityGroups[0].GroupId --output text")
    printf 'sg-operator1234567890\n'
    ;;
  ec2\ authorize-security-group-ingress\ --group-id\ sg-shared1234567890\ --ip-permissions\ * )
    printf '{}\n'
    ;;
  ec2\ authorize-security-group-ingress\ --group-id\ sg-ipfs1234567890\ --ip-permissions\ * )
    printf '{}\n'
    ;;
  ec2\ authorize-security-group-ingress\ --group-id\ sg-operator1234567890\ --ip-permissions\ * )
    printf '{}\n'
    ;;
  ec2\ create-launch-template-version\ --launch-template-id\ lt-app1234567890\ --source-version\ 9\ --launch-template-data\ *\ --output\ json)
    printf '{"LaunchTemplateVersion":{"VersionNumber":10}}\n'
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-app-asg --launch-template LaunchTemplateId=lt-app1234567890,Version=10")
    printf '{}\n'
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

write_fake_refresh_runtime_gh() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$TEST_AWS_LOG"

if [[ "${1:-}" == "release" && "${2:-}" == "view" ]]; then
  printf '%s\n' '{"assets":[{"name":"bridge-api_linux_amd64"},{"name":"bridge-api_linux_amd64.sha256"},{"name":"backoffice_linux_amd64"},{"name":"backoffice_linux_amd64.sha256"}]}'
  exit 0
fi

printf 'unexpected gh invocation\n' >&2
exit 1
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
  write_fake_refresh_runtime_gh "$fake_bin/gh"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-app-runtime.sh" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --app-binaries-release-tag app-binaries-v2026.04.07-r2-mainnet \
        --github-repo juno-intents/intents-juno \
        --output-dir "$output_dir" >"$tmp/refresh-summary.json"
  )

  assert_contains "$(cat "$output_dir/bridge-api.env")" "BRIDGE_API_BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111" "refresh renders the bridge env"
  assert_contains "$(cat "$output_dir/backoffice.env")" "BACKOFFICE_AUTH_SECRET=" "refresh renders the backoffice env placeholder for hydrated auth secrets"
  assert_contains "$(cat "$output_dir/backoffice.env")" "BACKOFFICE_JUNO_SCAN_URL=http://10.0.0.12:8080" "refresh renders the backoffice scan url"
  assert_contains "$(cat "$output_dir/backoffice.env")" "BACKOFFICE_JUNO_SCAN_WALLET_ID=wallet-mainnet-f8379377446f" "refresh renders the backoffice scan wallet id"
  assert_contains "$(cat "$output_dir/app-runtime-hydrator.env")" "APP_RUNTIME_CONFIG_SECRET_ID=intents-juno-mainnet-app-runtime-config" "refresh renders the runtime config secret id for host hydration"
  assert_contains "$(cat "$output_dir/app-runtime-hydrator.env")" "APP_RUNTIME_CONFIG_SECRET_REGION=us-east-1" "refresh renders the runtime config secret region for host hydration"
  assert_contains "$(cat "$output_dir/install.sh")" 'source "$script_dir/app-binaries-release.env"' "refresh installs app binaries from bundled release metadata when a release tag is pinned"
  assert_contains "$(cat "$output_dir/install.sh")" 'https://github.com/${APP_BINARIES_GITHUB_REPO}/releases/download/${APP_BINARIES_RELEASE_TAG}' "refresh downloads host binaries from the pinned github release tag"
  assert_contains "$(cat "$output_dir/install.sh")" 'sha256sum -c bridge-api_linux_amd64.sha256' "refresh verifies the bridge-api release checksum on-host before install"
  assert_contains "$(cat "$output_dir/install.sh")" 'sha256sum -c backoffice_linux_amd64.sha256' "refresh verifies the backoffice release checksum on-host before install"
  assert_contains "$(cat "$output_dir/install.sh")" 'install -m 0755 "$binaries_tmp_dir/bridge-api_linux_amd64" /usr/local/bin/bridge-api' "refresh installs the verified bridge-api release binary onto the host"
  assert_contains "$(cat "$output_dir/install.sh")" 'install -m 0755 "$binaries_tmp_dir/backoffice_linux_amd64" /usr/local/bin/backoffice' "refresh installs the verified backoffice release binary onto the host"
  assert_contains "$(cat "$output_dir/bin/backoffice-wrapper")" '--juno-scan-url "${BACKOFFICE_JUNO_SCAN_URL}"' "refresh passes the backoffice scan url to the backoffice wrapper"
  assert_contains "$(cat "$output_dir/bin/backoffice-wrapper")" '--juno-scan-wallet-id "${BACKOFFICE_JUNO_SCAN_WALLET_ID}"' "refresh passes the backoffice scan wallet id to the backoffice wrapper"
  assert_contains "$(cat "$output_dir/bin/backoffice-wrapper")" '--juno-scan-bearer-token-env BACKOFFICE_JUNO_SCAN_BEARER_TOKEN' "refresh passes the optional backoffice scan bearer token env to the backoffice wrapper"
  assert_contains "$(cat "$output_dir/app-binaries-release.env")" "APP_BINARIES_RELEASE_TAG=app-binaries-v2026.04.07-r2-mainnet" "refresh writes the pinned app-binaries release tag into the bundle metadata"
  assert_contains "$(cat "$output_dir/app-binaries-release.env")" "APP_BINARIES_GITHUB_REPO=juno-intents/intents-juno" "refresh writes the github repo into the bundle metadata"
  assert_contains "$(cat "$output_dir/install.sh")" 'script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"' "refresh writes a self-locating install script for remote bundle extraction"
  assert_contains "$(cat "$output_dir/install.sh")" 'for _ in $(seq 1 60); do' "refresh allows slow app runtime startup during the remote readiness gate"
  assert_contains "$(cat "$output_dir/install.sh")" 'sleep 5' "refresh backs off between remote readiness checks so the app can finish booting"
  assert_contains "$(cat "$output_dir/install.sh")" 'ready_services=(' "refresh builds the supervised local service set for the remote readiness gate"
  assert_contains "$(cat "$output_dir/install.sh")" 'intents-juno-app-config-hydrator.service' "refresh includes the config hydrator in the remote readiness gate"
  assert_contains "$(cat "$output_dir/install.sh")" 'systemctl is-active --quiet "${ready_services[@]}"' "refresh treats the rendered ready service set as the remote bootstrap success gate"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "map_hash_bucket_size 128;" "refresh sizes nginx host routing maps for long preview hostnames"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "bridge.preview.intents-testing.thejunowallet.com" "refresh renders bridge host routing into nginx config"
  assert_contains "$(cat "$output_dir/nginx/app.conf")" "ops.preview.intents-testing.thejunowallet.com" "refresh renders backoffice host routing into nginx config"
  assert_contains "$(cat "$aws_log")" "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-shared-sg" "refresh discovers the live-e2e shared security group"
  assert_contains "$(cat "$aws_log")" "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-ipfs-sg" "refresh discovers the live-e2e ipfs security group"
  assert_contains "$(cat "$aws_log")" "ec2 describe-security-groups --filters Name=group-name,Values=juno-live-e2e-preview0316d-operator-sg" "refresh discovers the live-e2e operator security group"
  assert_contains "$(cat "$aws_log")" "authorize-security-group-ingress --group-id sg-shared1234567890" "refresh restores preview app ingress to shared postgres and kafka"
  assert_contains "$(cat "$aws_log")" '"FromPort":5432' "refresh restores shared postgres ingress for the app security group"
  assert_contains "$(cat "$aws_log")" '"FromPort":9098' "refresh restores shared kafka ingress for the app security group"
  assert_contains "$(cat "$aws_log")" "authorize-security-group-ingress --group-id sg-ipfs1234567890" "refresh restores preview app ingress to shared ipfs"
  assert_contains "$(cat "$aws_log")" '"FromPort":5001' "refresh restores shared ipfs ingress for the app security group"
  assert_contains "$(cat "$aws_log")" "authorize-security-group-ingress --group-id sg-operator1234567890" "refresh restores preview app ingress to operator services"
  assert_contains "$(cat "$aws_log")" '"FromPort":18443' "refresh restores operator grpc ingress using the published operator endpoint ports"
  assert_contains "$(cat "$aws_log")" '"ToPort":18444' "refresh restores operator grpc ingress across the preview operator port range"
  assert_contains "$(cat "$aws_log")" '"FromPort":18232' "refresh restores operator juno rpc ingress for the app security group"
  assert_contains "$(cat "$aws_log")" '"FromPort":8080' "refresh restores operator juno scan ingress for the app security group"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-app-asg" "refresh discovers app instances from the app role asg"
  assert_contains "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-app1234567890 --source-version 9 --launch-template-data file://" "refresh publishes the rendered app runtime bundle into a temp launch template payload file"
  assert_contains "$(cat "$aws_log")" "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-app-asg --launch-template LaunchTemplateId=lt-app1234567890,Version=10" "refresh moves the app asg to the new bootstrap launch template version"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app001" "refresh bootstraps the first in-service app instance over ssm"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app002" "refresh bootstraps the second in-service app instance over ssm even before it is marked healthy"
  assert_not_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app003" "refresh skips terminating app instances"
  assert_contains "$(cat "$aws_log")" "gh release view app-binaries-v2026.04.07-r2-mainnet --repo juno-intents/intents-juno --json assets" "refresh verifies the pinned github release assets before rendering host-side downloads"
  assert_line_order "$(cat "$aws_log")" "authorize-security-group-ingress --group-id sg-shared1234567890" "ssm send-command --instance-ids i-app001" "refresh reopens shared ingress before restarting app services"
  assert_line_order "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-app1234567890 --source-version 9" "ssm send-command --instance-ids i-app001" "refresh updates the app launch template before touching the live instances"
  assert_eq "$(jq -r '.app_target_mode' "$tmp/refresh-summary.json")" "asg" "refresh summary reports app role mode"
  assert_eq "$(jq -r '.app_targets[0]' "$tmp/refresh-summary.json")" "i-app001" "refresh summary reports the first app instance id"
  assert_eq "$(jq -r '.app_targets[1]' "$tmp/refresh-summary.json")" "i-app002" "refresh summary reports the second app instance id"
  assert_eq "$(jq -r '.launch_template_id' "$tmp/refresh-summary.json")" "lt-app1234567890" "refresh summary reports the app launch template id"
  assert_eq "$(jq -r '.launch_template_version' "$tmp/refresh-summary.json")" "10" "refresh summary reports the new app launch template version"
  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/refresh-summary.json")" "true" "refresh summary reports success"

  rm -rf "$tmp"
}

main() {
  test_refresh_app_runtime_bootstraps_all_in_service_app_instances_via_ssm
}

main "$@"
