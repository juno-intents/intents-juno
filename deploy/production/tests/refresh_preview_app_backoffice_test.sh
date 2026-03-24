#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_refresh_shared_manifest_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid",
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "owallet_ua": "u1previewexample"
  },
  "operator_roster": [
    {
      "operator_id": "0x1111111111111111111111111111111111111111",
      "dkg_endpoint": "10.0.0.12:18443"
    },
    {
      "operator_id": "0x2222222222222222222222222222222222222222",
      "dkg_endpoint": "10.0.1.13:18444"
    }
  ],
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
  }
}
JSON
}

write_refresh_inventory_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "2",
  "environment": "preview",
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "operator_address": "0x1111111111111111111111111111111111111111",
      "private_endpoint": "10.0.0.12",
      "public_endpoint": "203.0.113.11",
      "operator_host": "203.0.113.11"
    },
    {
      "index": 2,
      "operator_id": "0x2222222222222222222222222222222222222222",
      "operator_address": "0x2222222222222222222222222222222222222222",
      "private_endpoint": "10.0.1.13",
      "public_endpoint": "203.0.113.12",
      "operator_host": "203.0.113.12"
    }
  ]
}
JSON
}

write_refresh_app_deploy_fixture() {
  local target="$1"
  local known_hosts="$2"
  local secret_contract="$3"
  cat >"$target" <<JSON
{
  "version": "2",
  "environment": "preview",
  "known_hosts_file": "$known_hosts",
  "secret_contract_file": "$secret_contract",
  "app_host": "203.0.113.50",
  "app_user": "ubuntu",
  "juno_rpc_url": "http://127.0.0.1:18232",
  "operator_addresses": [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222"
  ],
  "operator_endpoints": [
    "0x1111111111111111111111111111111111111111=203.0.113.11:18443",
    "0x2222222222222222222222222222222222222222=203.0.113.12:18444"
  ],
  "service_urls": [
    "bridge-api=http://127.0.0.1:8082/readyz"
  ],
  "services": {
    "backoffice": {
      "listen_addr": "127.0.0.1:8090"
    }
  }
}
JSON
}

write_refresh_app_role_deploy_fixture() {
  local target="$1"
  local secret_contract="$2"
  cat >"$target" <<JSON
{
  "version": "2",
  "environment": "preview",
  "secret_contract_file": "$secret_contract",
  "app_host": "203.0.113.50",
  "app_user": "ubuntu",
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
    "0x1111111111111111111111111111111111111111=203.0.113.11:18443",
    "0x2222222222222222222222222222222222222222=203.0.113.12:18444"
  ],
  "service_urls": [
    "bridge-api=http://127.0.0.1:8082/readyz"
  ],
  "services": {
    "backoffice": {
      "listen_addr": "127.0.0.1:8090"
    }
  }
}
JSON
}

write_refresh_app_secret_contract() {
  local target="$1"
  cat >"$target" <<'EOF'
APP_POSTGRES_DSN=literal:postgres://preview
BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
}

write_refresh_operator_handoff() {
  local output_dir="$1"
  local operator_id="$2"
  local secret_contract="$3"
  mkdir -p "$output_dir/operators/$operator_id"
  cat >"$output_dir/operators/$operator_id/operator-deploy.json" <<JSON
{
  "environment": "preview",
  "secret_contract_file": "$secret_contract"
}
JSON
}

write_refresh_operator_secret_contract() {
  local target="$1"
  local key="$2"
  cat >"$target" <<EOF
BASE_RELAYER_PRIVATE_KEYS=literal:$key
EOF
}

write_fake_refresh_ssh() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'ssh %s\n' "\$*" >>"$log_file"
exit 0
EOF
  chmod +x "$target"
}

write_fake_refresh_scp() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'scp %s\n' "\$*" >>"$log_file"
exit 0
EOF
  chmod +x "$target"
}

write_fake_refresh_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
EOF
  chmod +x "$target"
}

write_fake_refresh_aws() {
  local target="$1"
  local log_file="$2"
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
    printf '{"AutoScalingGroups":[{"Instances":[{"InstanceId":"i-app001","LifecycleState":"InService","HealthStatus":"Healthy"},{"InstanceId":"i-app002","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
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

test_refresh_preview_app_backoffice_renders_private_operator_endpoints_and_restarts_backoffice() {
  local tmp fake_bin ssh_log scp_log rolled_inventory shared_manifest app_deploy known_hosts secret_contract output_dir
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  ssh_log="$tmp/ssh.log"
  scp_log="$tmp/scp.log"
  rolled_inventory="$tmp/rolled-inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  output_dir="$tmp/output"
  mkdir -p "$fake_bin" "$output_dir/app"

  known_hosts="$output_dir/app/known_hosts"
  secret_contract="$output_dir/app/app-secrets.env"
  app_deploy="$output_dir/app/app-deploy.json"
  : >"$known_hosts"
  write_refresh_inventory_fixture "$rolled_inventory"
  write_refresh_shared_manifest_fixture "$shared_manifest"
  write_refresh_app_secret_contract "$secret_contract"
  write_refresh_app_deploy_fixture "$app_deploy" "$known_hosts" "$secret_contract"
  write_refresh_operator_secret_contract "$tmp/op1-secrets.env" "0x1111111111111111111111111111111111111111111111111111111111111111"
  write_refresh_operator_secret_contract "$tmp/op2-secrets.env" "0x2222222222222222222222222222222222222222222222222222222222222222"
  write_refresh_operator_handoff "$output_dir" "0x1111111111111111111111111111111111111111" "$tmp/op1-secrets.env"
  write_refresh_operator_handoff "$output_dir" "0x2222222222222222222222222222222222222222" "$tmp/op2-secrets.env"
  write_fake_refresh_ssh "$fake_bin/ssh" "$ssh_log"
  write_fake_refresh_scp "$fake_bin/scp" "$scp_log"
  write_fake_refresh_cast "$fake_bin/cast"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-preview-app-backoffice.sh" \
        --rolled-inventory "$rolled_inventory" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --output-dir "$output_dir" >"$tmp/refresh-summary.json"
  )

  assert_eq "$(jq -r '.operator_endpoints[0]' "$output_dir/app/app-deploy.json")" "0x1111111111111111111111111111111111111111=10.0.0.12:18443" "refresh writes first private operator endpoint"
  assert_eq "$(jq -r '.operator_endpoints[1]' "$output_dir/app/app-deploy.json")" "0x2222222222222222222222222222222222222222=10.0.1.13:18444" "refresh writes second private operator endpoint"
  assert_contains "$(cat "$output_dir/app/backoffice.env")" "BACKOFFICE_OPERATOR_ENDPOINTS=0x1111111111111111111111111111111111111111=10.0.0.12:18443,0x2222222222222222222222222222222222222222=10.0.1.13:18444" "refresh writes private operator probes into backoffice env"
  assert_contains "$(cat "$output_dir/app/backoffice.env")" "BACKOFFICE_JUNO_RPC_URLS=http://10.0.0.12:18232,http://10.0.1.13:18232" "refresh writes private operator rpc fallbacks into backoffice env"
  assert_contains "$(cat "$scp_log")" "/tmp/intents-juno-preview-backoffice.env" "refresh uploads the rendered backoffice env"
  assert_contains "$(cat "$ssh_log")" "systemctl is-active --quiet bridge-api.service backoffice.service" "refresh waits for the local app runtime services before rewriting backoffice env over ssh"
  assert_contains "$(cat "$ssh_log")" "systemctl restart backoffice.service" "refresh restarts backoffice after uploading env"
  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/refresh-summary.json")" "true" "refresh summary reports success"

  rm -rf "$tmp"
}

test_refresh_preview_app_backoffice_updates_all_app_role_instances_via_ssm() {
  local tmp fake_bin aws_log rolled_inventory shared_manifest app_deploy secret_contract output_dir
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"
  rolled_inventory="$tmp/rolled-inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  output_dir="$tmp/output"
  mkdir -p "$fake_bin" "$tmp/app" "$output_dir"

  secret_contract="$tmp/app/app-secrets.env"
  app_deploy="$tmp/app/app-deploy.json"
  write_refresh_inventory_fixture "$rolled_inventory"
  write_refresh_shared_manifest_fixture "$shared_manifest"
  write_refresh_app_secret_contract "$secret_contract"
  write_refresh_app_role_deploy_fixture "$app_deploy" "$secret_contract"
  write_refresh_operator_secret_contract "$tmp/op1-secrets.env" "0x1111111111111111111111111111111111111111111111111111111111111111"
  write_refresh_operator_secret_contract "$tmp/op2-secrets.env" "0x2222222222222222222222222222222222222222222222222222222222222222"
  write_refresh_operator_handoff "$output_dir" "0x1111111111111111111111111111111111111111" "$tmp/op1-secrets.env"
  write_refresh_operator_handoff "$output_dir" "0x2222222222222222222222222222222222222222" "$tmp/op2-secrets.env"
  write_fake_refresh_cast "$fake_bin/cast"
  write_fake_refresh_aws "$fake_bin/aws" "$aws_log"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/refresh-preview-app-backoffice.sh" \
        --rolled-inventory "$rolled_inventory" \
        --shared-manifest "$shared_manifest" \
        --app-deploy "$app_deploy" \
        --output-dir "$output_dir" >"$tmp/refresh-summary.json"
  )

  assert_contains "$(cat "$aws_log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-app-asg" "refresh discovers healthy app instances from the app role asg"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app001" "refresh pushes the backoffice env to the first app instance over ssm"
  assert_contains "$(cat "$aws_log")" "ssm send-command --instance-ids i-app002" "refresh pushes the backoffice env to the second app instance over ssm"
  assert_contains "$(cat "$aws_log")" "systemctl is-active --quiet bridge-api.service backoffice.service" "refresh waits for the local app runtime services before rewriting backoffice env over ssm"
  assert_contains "$(cat "$aws_log")" "systemctl restart backoffice.service" "refresh restarts the explicit backoffice service unit over ssm"
  assert_eq "$(jq -r '.app_target_mode' "$tmp/refresh-summary.json")" "asg" "refresh summary reports app role mode"
  assert_eq "$(jq -r '.app_role_asg' "$tmp/refresh-summary.json")" "preview-app-asg" "refresh summary reports the app role asg"
  assert_eq "$(jq -r '.app_targets[0]' "$tmp/refresh-summary.json")" "i-app001" "refresh summary reports the first app instance id"
  assert_eq "$(jq -r '.app_targets[1]' "$tmp/refresh-summary.json")" "i-app002" "refresh summary reports the second app instance id"

  rm -rf "$tmp"
}

main() {
  test_refresh_preview_app_backoffice_renders_private_operator_endpoints_and_restarts_backoffice
  test_refresh_preview_app_backoffice_updates_all_app_role_instances_via_ssm
}

main "$@"
