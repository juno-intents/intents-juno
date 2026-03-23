#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_rebuild_inventory_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "2",
  "environment": "preview",
  "dns": {
    "mode": "route53",
    "ttl_seconds": 60
  },
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "terraform_dir": "deploy/shared/terraform/production-shared",
    "route53_zone_id": "Z01169511CVMQJAD7T3TJ",
    "public_zone_name": "thejunowallet.com",
    "public_subdomain": "preview.intents-testing.thejunowallet.com",
    "alarm_actions": [
      "arn:aws:sns:us-east-1:021490342184:runs-on-AlertTopic-yKL5sNi9ij9K"
    ]
  }
}
JSON
}

write_fake_rebuild_passthrough() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$(basename "$target")" "\$*" >>"$log_file"
output=""
args=( "\$@" )
for ((i = 0; i < \${#args[@]}; i++)); do
  if [[ "\${args[i]}" == "--output" ]]; then
    output="\${args[i+1]}"
    break
  fi
done
if [[ -n "\$output" ]]; then
  cp "\${args[1]}" "\$output"
fi
exit 0
EOF
  chmod +x "$target"
}

write_fake_rebuild_deploy_coordinator() {
  local target="$1"
  local log_file="$2"
  local fixture_dir="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'deploy-coordinator %s\n' "\$*" >>"$log_file"
output_dir=""
args=( "\$@" )
for ((i = 0; i < \${#args[@]}; i++)); do
  if [[ "\${args[i]}" == "--output-dir" ]]; then
    output_dir="\${args[i+1]}"
    break
  fi
done
env_dir="\$output_dir/preview"
mkdir -p "\$env_dir/app"
cat >"\$env_dir/app/app-deploy.json" <<JSON
{
  "version": "2",
  "environment": "preview",
  "app_host": "203.0.113.50",
  "app_user": "ubuntu",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "known_hosts_file": "$fixture_dir/known_hosts",
  "secret_contract_file": "$fixture_dir/app-secrets.env",
  "operator_addresses": ["0x1111111111111111111111111111111111111111"],
  "operator_endpoints": ["0x1111111111111111111111111111111111111111=203.0.113.11:18443"],
  "service_urls": ["bridge-api=http://127.0.0.1:8082/readyz"],
  "app_role": {
    "asg": "juno-app-runtime-preview-asg",
    "aws_profile": "juno",
    "aws_region": "us-east-1"
  },
  "services": {
    "backoffice": {
      "listen_addr": "127.0.0.1:8090"
    }
  }
}
JSON
cat >"\$env_dir/shared-manifest.json" <<JSON
{
  "shared_services": {
    "kafka": {
      "bootstrap_brokers": "b-1.preview.kafka:9098",
      "tls": true,
      "auth": {
        "mode": "aws-msk-iam",
        "aws_region": "us-east-1"
      }
    },
    "ipfs": {
      "api_url": "http://preview-ipfs:5001",
      "api_auth_secret_arn": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-ipfs-api-token"
    },
    "artifacts": {
      "checkpoint_blob_bucket": "preview-checkpoint-blobs"
    },
    "proof": {
      "requestor_address": "0x4444444444444444444444444444444444444444",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  },
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example.invalid",
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "owallet_ua": "u1previewexample"
  },
  "checkpoint": {
    "operators": ["0x1111111111111111111111111111111111111111"],
    "threshold": 1,
    "signature_topic": "checkpoints.signatures.v1",
    "package_topic": "checkpoints.packages.v1"
  }
}
JSON
printf '{}' >"\$env_dir/bridge-summary.json"
exit 0
EOF
  chmod +x "$target"
}

write_fake_rebuild_canary() {
  local target="$1"
  local log_file="$2"
  local label="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '$label %s\n' "\$*" >>"$log_file"
printf '{"ready_for_deploy":true}\n'
EOF
  chmod +x "$target"
}

write_fake_rebuild_roll() {
  local target="$1"
  local log_file="$2"
  local fixture_dir="$3"
  local ready_file="${4:-}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'roll-preview-operators %s\n' "\$*" >>"$log_file"
output_dir=""
inventory=""
args=( "\$@" )
for ((i = 0; i < \${#args[@]}; i++)); do
  case "\${args[i]}" in
    --output-dir) output_dir="\${args[i+1]}" ;;
    --inventory) inventory="\${args[i+1]}" ;;
  esac
done
mkdir -p "\$output_dir/operators/0x1111111111111111111111111111111111111111"
cp "\$inventory" "\$output_dir/inventory.operators-rolled.json"
printf '{"environment":"preview","secret_contract_file":"$fixture_dir/operator-secrets.env"}' >"\$output_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
if [[ -n "$ready_file" ]]; then
  : >"$ready_file"
fi
printf '{"ready_for_deploy":true}\n'
EOF
  chmod +x "$target"
}

write_fake_rebuild_refresh() {
  local target="$1"
  local log_file="$2"
  local label="${3:-refresh-preview-app-backoffice}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '$label %s\n' "\$*" >>"$log_file"
printf '{"ready_for_deploy":true}\n'
EOF
  chmod +x "$target"
}

write_fake_rebuild_e2e() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'shared-infra-e2e %s\n' "\$*" >>"$log_file"
output=""
args=( "\$@" )
for ((i = 0; i < \${#args[@]}; i++)); do
  if [[ "\${args[i]}" == "--output" ]]; then
    output="\${args[i+1]}"
    break
  fi
done
printf '{"ok":true}\n' >"\$output"
EOF
  chmod +x "$target"
}

write_fake_rebuild_aws() {
  local target="$1"
  local log_file="$2"
  local commands_file="$3"
  local remote_stdout_file="$4"
  local ready_file="${5:-}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"

while [[ \$# -gt 0 ]]; do
  case "\$1" in
    autoscaling|s3|secretsmanager|ssm)
      service="\$1"
      shift
      break
      ;;
    *)
      shift
      ;;
  esac
done

case "\${service:-}" in
  autoscaling)
    subcommand="\$1"
    shift
    case "\$subcommand" in
      describe-auto-scaling-groups)
        cat <<'JSON'
{"AutoScalingGroups":[{"Instances":[{"InstanceId":"i-preview-app","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}
JSON
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  s3)
    subcommand="\$1"
    shift
    case "\$subcommand" in
      cp)
        printf 's3 cp %s %s\n' "\$1" "\$2" >>"$log_file"
        ;;
      presign)
        printf 'https://example.invalid/shared-infra-e2e?token=abc&x=1\n'
        ;;
      rm)
        printf 's3 rm %s\n' "\$1" >>"$log_file"
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  secretsmanager)
    subcommand="\$1"
    shift
    case "\$subcommand" in
      get-secret-value)
        printf 'preview-ipfs-bearer-token\n'
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  ssm)
    subcommand="\$1"
    shift
    case "\$subcommand" in
      send-command)
        if [[ -n "$ready_file" && ! -f "$ready_file" ]]; then
          printf 'shared-infra-e2e remote command ran before operator rollout\n' >&2
          exit 1
        fi
        parameters_json=""
        while [[ \$# -gt 0 ]]; do
          case "\$1" in
            --parameters)
              parameters_json="\$2"
              shift 2
              ;;
            *)
              shift
              ;;
          esac
        done
        printf '%s\n' "\$parameters_json" >"$commands_file"
        cat <<'JSON'
{"Command":{"CommandId":"cmd-preview-ssm"}}
JSON
        ;;
      get-command-invocation)
        jq -n --arg stdout "\$(cat "$remote_stdout_file")" '{
          Status: "Success",
          StandardOutputContent: \$stdout,
          StandardErrorContent: ""
        }'
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  *)
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

ensure_rebuild_fixture_files() {
  local fixture_dir="$1"
  mkdir -p "$fixture_dir"
  : >"$fixture_dir/known_hosts"
  cat >"$fixture_dir/app-secrets.env" <<'EOF'
APP_POSTGRES_DSN=literal:postgres://preview
BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cat >"$fixture_dir/operator-secrets.env" <<'EOF'
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
EOF
}

test_rebuild_preview_role_runtime_refreshes_backoffice_after_operator_rollout() {
  local tmp fake_bin inventory dkg_summary log_file refresh_log e2e_log output_root fixture_dir aws_log ssm_commands remote_stdout rollout_ready
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  inventory="$tmp/inventory.json"
  dkg_summary="$tmp/dkg-summary.json"
  log_file="$tmp/rebuild.log"
  refresh_log="$tmp/refresh.log"
  e2e_log="$tmp/e2e.log"
  output_root="$tmp/output"
  fixture_dir="$tmp/fixtures"
  aws_log="$tmp/aws.log"
  ssm_commands="$tmp/ssm-commands.json"
  remote_stdout="$tmp/remote-stdout.json"
  rollout_ready="$tmp/operator-rollout.ready"

  mkdir -p "$fake_bin"
  write_rebuild_inventory_fixture "$inventory"
  printf '{}' >"$dkg_summary"
  printf '{"ok":true}\n' >"$remote_stdout"
  ensure_rebuild_fixture_files "$fixture_dir"
  write_fake_rebuild_passthrough "$fake_bin/upgrade-preview-inventory.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/destroy-preview-role-runtime.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/resolve-role-runtime-release-inputs.sh" "$log_file"
  write_fake_rebuild_deploy_coordinator "$fake_bin/deploy-coordinator.sh" "$log_file" "$fixture_dir"
  write_fake_rebuild_canary "$fake_bin/provision-app-edge.sh" "$log_file" "provision-app-edge"
  write_fake_rebuild_canary "$fake_bin/canary-shared-services.sh" "$log_file" "canary-shared-services"
  write_fake_rebuild_canary "$fake_bin/canary-app-host.sh" "$log_file" "canary-app-host"
  write_fake_rebuild_roll "$fake_bin/roll-preview-operators.sh" "$log_file" "$fixture_dir" "$rollout_ready"
  write_fake_rebuild_refresh "$fake_bin/refresh-app-runtime.sh" "$log_file" "refresh-app-runtime"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-app-backoffice.sh" "$refresh_log"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-wireguard-backoffice.sh" "$log_file" "refresh-preview-wireguard-backoffice"
  write_fake_rebuild_e2e "$fake_bin/shared-infra-e2e" "$e2e_log"
  write_fake_rebuild_aws "$fake_bin/aws" "$aws_log" "$ssm_commands" "$remote_stdout" "$rollout_ready"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN="$fake_bin/upgrade-preview-inventory.sh" \
      PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN="$fake_bin/destroy-preview-role-runtime.sh" \
      PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN="$fake_bin/resolve-role-runtime-release-inputs.sh" \
      PRODUCTION_DEPLOY_COORDINATOR_BIN="$fake_bin/deploy-coordinator.sh" \
      PRODUCTION_PROVISION_APP_EDGE_BIN="$fake_bin/provision-app-edge.sh" \
      PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
      PRODUCTION_CANARY_APP_BIN="$fake_bin/canary-app-host.sh" \
      PRODUCTION_REFRESH_APP_RUNTIME_BIN="$fake_bin/refresh-app-runtime.sh" \
      PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN="$fake_bin/roll-preview-operators.sh" \
      PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN="$fake_bin/refresh-preview-app-backoffice.sh" \
      PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN="$fake_bin/refresh-preview-wireguard-backoffice.sh" \
      bash "$REPO_ROOT/deploy/production/rebuild-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --dkg-summary "$dkg_summary" \
        --bridge-deploy-binary /bin/true \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --shared-infra-e2e-binary "$fake_bin/shared-infra-e2e" \
        --output-dir "$output_root"
  )

  assert_contains "$(cat "$log_file")" "refresh-app-runtime --shared-manifest $output_root/preview/shared-manifest.json" "rebuild refreshes app runtime from the rebuilt shared manifest"
  assert_contains "$(cat "$log_file")" "--app-deploy $output_root/preview/app/app-deploy.json" "rebuild refreshes app runtime from the rebuilt app handoff"
  assert_contains "$(cat "$log_file")" "--output-dir $output_root/preview/app-runtime" "rebuild stores app runtime evidence in a dedicated directory"
  local refresh_line canary_line
  refresh_line="$(grep -n "refresh-app-runtime" "$log_file" | head -n1 | cut -d: -f1)"
  canary_line="$(grep -n "canary-app-host" "$log_file" | head -n1 | cut -d: -f1)"
  assert_eq "${refresh_line:+present}" "present" "rebuild runs app runtime refresh"
  assert_eq "${canary_line:+present}" "present" "rebuild runs app canary"
  if (( refresh_line >= canary_line )); then
    printf 'app runtime refresh must run before app canary\n' >&2
    exit 1
  fi
  local roll_count first_roll_line wireguard_refresh_line final_roll_line
  roll_count="$(grep -c '^roll-preview-operators ' "$log_file")"
  assert_eq "$roll_count" "2" "rebuild rolls operators before and after the wireguard backoffice refresh"
  first_roll_line="$(grep -nF -- "--output-dir $output_root/preview/operator-rollout --github-repo" "$log_file" | head -n1 | cut -d: -f1)"
  wireguard_refresh_line="$(grep -n 'refresh-preview-wireguard-backoffice' "$log_file" | head -n1 | cut -d: -f1)"
  final_roll_line="$(grep -nF -- "--output-dir $output_root/preview/operator-rollout-final --github-repo" "$log_file" | head -n1 | cut -d: -f1)"
  assert_eq "${first_roll_line:+present}" "present" "rebuild performs the initial operator rollout"
  assert_eq "${wireguard_refresh_line:+present}" "present" "rebuild refreshes wireguard backoffice routing"
  assert_eq "${final_roll_line:+present}" "present" "rebuild performs the final operator rollout"
  if (( first_roll_line >= wireguard_refresh_line )); then
    printf 'initial operator rollout must run before wireguard backoffice refresh\n' >&2
    exit 1
  fi
  if (( wireguard_refresh_line >= final_roll_line )); then
    printf 'final operator rollout must run after wireguard backoffice refresh\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$refresh_log")" "--rolled-inventory $output_root/preview/operator-rollout-final/inventory.operators-rolled.json" "rebuild refreshes backoffice from the final rolled inventory"
  assert_contains "$(cat "$refresh_log")" "--app-deploy $output_root/preview/app/app-deploy.json" "rebuild refreshes the live app handoff in place"
  assert_contains "$(cat "$refresh_log")" "--output-dir $output_root/preview/operator-rollout-final" "rebuild refresh stores app refresh evidence beside the final operator rollout evidence"
  assert_contains "$(cat "$log_file")" "refresh-preview-wireguard-backoffice --inventory $output_root/preview/inventory.resolved.json" "rebuild refreshes wireguard backoffice routing after operator rollout"
  assert_contains "$(cat "$log_file")" "--operator-deploy $output_root/preview/operator-rollout/operators/0x1111111111111111111111111111111111111111/operator-deploy.json" "rebuild uses a rendered operator handoff to resolve internal backoffice endpoints"
  assert_eq "$(jq -r '.wireguard_backoffice_refresh_path' "$output_root/preview/role-runtime-release-lock.json")" "$output_root/preview/wireguard-backoffice.json" "release lock records the wireguard backoffice refresh evidence"
  if [[ -s "$e2e_log" ]]; then
    printf 'shared-infra-e2e must execute remotely for preview app role rebuilds\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$aws_log")" "s3 cp $fake_bin/shared-infra-e2e s3://preview-checkpoint-blobs/tmp/shared-infra-e2e/" "rebuild stages the released shared-infra-e2e binary in the shared artifact bucket"
  assert_contains "$(cat "$ssm_commands")" "JUNO_QUEUE_KAFKA_TLS='true'" "rebuild enables kafka tls for remote shared infra validation"
  assert_contains "$(cat "$ssm_commands")" "JUNO_QUEUE_KAFKA_AUTH_MODE='aws-msk-iam'" "rebuild enables aws msk iam auth for remote shared infra validation"
  assert_contains "$(cat "$ssm_commands")" "JUNO_QUEUE_KAFKA_AWS_REGION='us-east-1'" "rebuild forwards the kafka auth region for remote shared infra validation"
  assert_contains "$(cat "$ssm_commands")" "CHECKPOINT_IPFS_API_BEARER_TOKEN='preview-ipfs-bearer-token'" "rebuild forwards the ipfs bearer token for remote shared infra validation"
  assert_contains "$(cat "$ssm_commands")" "deposits.event.v2" "rebuild ensures the deposit event topic exists before preview validation"
  assert_contains "$(cat "$ssm_commands")" "withdrawals.requested.v2" "rebuild ensures the withdraw request topic exists before preview validation"
  assert_eq "$(jq -r '.ok' "$output_root/preview/e2e/shared-infra-e2e.json")" "true" "rebuild records the remote shared infra validation output"
  assert_eq "$(jq -r '.app_runtime_refresh_path' "$output_root/preview/role-runtime-release-lock.json")" "$output_root/preview/app-runtime-refresh.json" "release lock records the app runtime refresh evidence"
  assert_eq "$(jq -r '.app_backoffice_refresh_path' "$output_root/preview/role-runtime-release-lock.json")" "$output_root/preview/app-backoffice-refresh.json" "release lock records the app backoffice refresh evidence"

  rm -rf "$tmp"
}

test_rebuild_preview_role_runtime_carries_forward_current_shared_proof_secrets() {
  local tmp fake_bin inventory dkg_summary log_file output_root fixture_dir current_output_root aws_log ssm_commands remote_stdout rollout_ready
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  inventory="$tmp/inventory.json"
  dkg_summary="$tmp/dkg-summary.json"
  log_file="$tmp/rebuild.log"
  output_root="$tmp/output"
  fixture_dir="$tmp/fixtures"
  current_output_root="$tmp/production-output/preview"
  aws_log="$tmp/aws.log"
  ssm_commands="$tmp/ssm-commands.json"
  remote_stdout="$tmp/remote-stdout.json"
  rollout_ready="$tmp/operator-rollout.ready"

  mkdir -p "$fake_bin" "$current_output_root"
  write_rebuild_inventory_fixture "$inventory"
  printf '{}' >"$dkg_summary"
  printf '{"ok":true}\n' >"$remote_stdout"
  ensure_rebuild_fixture_files "$fixture_dir"
  cat >"$current_output_root/shared-terraform-output.json" <<'JSON'
{
  "shared_proof_requestor_secret_arn": {
    "value": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-requestor"
  },
  "shared_proof_funder_secret_arn": {
    "value": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-funder"
  },
  "shared_sp1_requestor_address": {
    "value": "0x4444444444444444444444444444444444444444"
  },
  "shared_sp1_rpc_url": {
    "value": "https://rpc.mainnet.succinct.xyz"
  }
}
JSON
  write_fake_rebuild_passthrough "$fake_bin/upgrade-preview-inventory.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/destroy-preview-role-runtime.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/resolve-role-runtime-release-inputs.sh" "$log_file"
  write_fake_rebuild_deploy_coordinator "$fake_bin/deploy-coordinator.sh" "$log_file" "$fixture_dir"
  write_fake_rebuild_canary "$fake_bin/provision-app-edge.sh" "$log_file" "provision-app-edge"
  write_fake_rebuild_canary "$fake_bin/canary-shared-services.sh" "$log_file" "canary-shared-services"
  write_fake_rebuild_canary "$fake_bin/canary-app-host.sh" "$log_file" "canary-app-host"
  write_fake_rebuild_roll "$fake_bin/roll-preview-operators.sh" "$log_file" "$fixture_dir" "$rollout_ready"
  write_fake_rebuild_refresh "$fake_bin/refresh-app-runtime.sh" "$log_file" "refresh-app-runtime"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-app-backoffice.sh" "$log_file"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-wireguard-backoffice.sh" "$log_file" "refresh-preview-wireguard-backoffice"
  write_fake_rebuild_e2e "$fake_bin/shared-infra-e2e" "$log_file"
  write_fake_rebuild_aws "$fake_bin/aws" "$aws_log" "$ssm_commands" "$remote_stdout" "$rollout_ready"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN="$fake_bin/upgrade-preview-inventory.sh" \
      PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN="$fake_bin/destroy-preview-role-runtime.sh" \
      PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN="$fake_bin/resolve-role-runtime-release-inputs.sh" \
      PRODUCTION_DEPLOY_COORDINATOR_BIN="$fake_bin/deploy-coordinator.sh" \
      PRODUCTION_PROVISION_APP_EDGE_BIN="$fake_bin/provision-app-edge.sh" \
      PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
      PRODUCTION_CANARY_APP_BIN="$fake_bin/canary-app-host.sh" \
      PRODUCTION_REFRESH_APP_RUNTIME_BIN="$fake_bin/refresh-app-runtime.sh" \
      PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN="$fake_bin/roll-preview-operators.sh" \
      PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN="$fake_bin/refresh-preview-app-backoffice.sh" \
      PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN="$fake_bin/refresh-preview-wireguard-backoffice.sh" \
      bash "$REPO_ROOT/deploy/production/rebuild-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --dkg-summary "$dkg_summary" \
        --bridge-deploy-binary /bin/true \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --shared-infra-e2e-binary "$fake_bin/shared-infra-e2e" \
        --output-dir "$output_root"
  )

  assert_eq "$(jq -r '.shared_roles.proof.requestor_secret_arn' "$output_root/preview/inventory.resolved.json")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-requestor" "rebuild carries forward the current proof requestor secret arn before destroy"
  assert_eq "$(jq -r '.shared_roles.proof.funder_secret_arn' "$output_root/preview/inventory.resolved.json")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-funder" "rebuild carries forward the current proof funder secret arn before destroy"
  assert_eq "$(jq -r '.shared_roles.proof.requestor_address' "$output_root/preview/inventory.resolved.json")" "0x4444444444444444444444444444444444444444" "rebuild carries forward the current proof requestor address before destroy"
  rm -rf "$tmp"
}

test_rebuild_preview_role_runtime_defaults_ephemeral_bridge_funding_amount() {
  local tmp fake_bin inventory dkg_summary log_file output_root fixture_dir aws_log ssm_commands remote_stdout rollout_ready
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  inventory="$tmp/inventory.json"
  dkg_summary="$tmp/dkg-summary.json"
  log_file="$tmp/rebuild.log"
  output_root="$tmp/output"
  fixture_dir="$tmp/fixtures"
  aws_log="$tmp/aws.log"
  ssm_commands="$tmp/ssm-commands.json"
  remote_stdout="$tmp/remote-stdout.json"
  rollout_ready="$tmp/operator-rollout.ready"

  mkdir -p "$fake_bin"
  write_rebuild_inventory_fixture "$inventory"
  printf '{}' >"$dkg_summary"
  printf '{"ok":true}\n' >"$remote_stdout"
  ensure_rebuild_fixture_files "$fixture_dir"
  cat >"$tmp/funder.key" <<'EOF'
0x59c6995e998f97a5a0044966f09453883f4b8f3359aa4fcf3e4a76fb3f8d5c11
EOF
  write_fake_rebuild_passthrough "$fake_bin/upgrade-preview-inventory.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/destroy-preview-role-runtime.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/resolve-role-runtime-release-inputs.sh" "$log_file"
  write_fake_rebuild_deploy_coordinator "$fake_bin/deploy-coordinator.sh" "$log_file" "$fixture_dir"
  write_fake_rebuild_canary "$fake_bin/provision-app-edge.sh" "$log_file" "provision-app-edge"
  write_fake_rebuild_canary "$fake_bin/canary-shared-services.sh" "$log_file" "canary-shared-services"
  write_fake_rebuild_canary "$fake_bin/canary-app-host.sh" "$log_file" "canary-app-host"
  write_fake_rebuild_roll "$fake_bin/roll-preview-operators.sh" "$log_file" "$fixture_dir" "$rollout_ready"
  write_fake_rebuild_refresh "$fake_bin/refresh-app-runtime.sh" "$log_file" "refresh-app-runtime"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-app-backoffice.sh" "$log_file"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-wireguard-backoffice.sh" "$log_file" "refresh-preview-wireguard-backoffice"
  write_fake_rebuild_e2e "$fake_bin/shared-infra-e2e" "$log_file"
  write_fake_rebuild_aws "$fake_bin/aws" "$aws_log" "$ssm_commands" "$remote_stdout" "$rollout_ready"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN="$fake_bin/upgrade-preview-inventory.sh" \
      PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN="$fake_bin/destroy-preview-role-runtime.sh" \
      PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN="$fake_bin/resolve-role-runtime-release-inputs.sh" \
      PRODUCTION_DEPLOY_COORDINATOR_BIN="$fake_bin/deploy-coordinator.sh" \
      PRODUCTION_PROVISION_APP_EDGE_BIN="$fake_bin/provision-app-edge.sh" \
      PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
      PRODUCTION_CANARY_APP_BIN="$fake_bin/canary-app-host.sh" \
      PRODUCTION_REFRESH_APP_RUNTIME_BIN="$fake_bin/refresh-app-runtime.sh" \
      PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN="$fake_bin/roll-preview-operators.sh" \
      PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN="$fake_bin/refresh-preview-app-backoffice.sh" \
      PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN="$fake_bin/refresh-preview-wireguard-backoffice.sh" \
      bash "$REPO_ROOT/deploy/production/rebuild-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --dkg-summary "$dkg_summary" \
        --bridge-deploy-binary /bin/true \
        --funder-key-file "$tmp/funder.key" \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --shared-infra-e2e-binary "$fake_bin/shared-infra-e2e" \
        --output-dir "$output_root"
  )

  assert_contains "$(cat "$log_file")" "--funder-key-file $tmp/funder.key" "rebuild forwards funder mode into deploy coordinator"
  assert_contains "$(cat "$log_file")" "--ephemeral-funding-amount-wei 15000000000000000" "rebuild defaults the bridge ephemeral funding amount for preview funder mode"

  rm -rf "$tmp"
}

test_rebuild_preview_role_runtime_absolutizes_source_artifact_paths() {
  local tmp fake_bin inventory dkg_summary log_file output_root fixture_dir updated_inventory aws_log ssm_commands remote_stdout rollout_ready
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  inventory="$tmp/inventory.json"
  updated_inventory="$tmp/inventory.updated.json"
  dkg_summary="$tmp/dkg-summary.json"
  log_file="$tmp/rebuild.log"
  output_root="$tmp/output"
  fixture_dir="$tmp/fixtures"
  aws_log="$tmp/aws.log"
  ssm_commands="$tmp/ssm-commands.json"
  remote_stdout="$tmp/remote-stdout.json"
  rollout_ready="$tmp/operator-rollout.ready"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/operators/op1" "$tmp/dkg-tls"
  write_rebuild_inventory_fixture "$inventory"
  jq '
    .dkg_tls_dir = "dkg-tls"
    | .app_role = {
        known_hosts_file: "app/known_hosts",
        secret_contract_file: "app/app-secrets.env"
      }
    | .app_host = {
        known_hosts_file: "app/known_hosts",
        secret_contract_file: "app/app-secrets.env"
      }
    | .operators = [
        {
          operator_id: "0x1111111111111111111111111111111111111111",
          known_hosts_file: "operators/op1/known_hosts",
          dkg_backup_zip: "operators/op1/dkg-backup.zip",
          secret_contract_file: "operators/op1/operator-secrets.env"
        }
      ]
  ' "$inventory" >"$updated_inventory"
  mv "$updated_inventory" "$inventory"
  printf '{}' >"$dkg_summary"
  printf '{"ok":true}\n' >"$remote_stdout"
  ensure_rebuild_fixture_files "$fixture_dir"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$tmp/operators/op1/known_hosts"
  : >"$tmp/operators/op1/operator-secrets.env"
  : >"$tmp/operators/op1/dkg-backup.zip"
  write_fake_rebuild_passthrough "$fake_bin/upgrade-preview-inventory.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/destroy-preview-role-runtime.sh" "$log_file"
  write_fake_rebuild_passthrough "$fake_bin/resolve-role-runtime-release-inputs.sh" "$log_file"
  write_fake_rebuild_deploy_coordinator "$fake_bin/deploy-coordinator.sh" "$log_file" "$fixture_dir"
  write_fake_rebuild_canary "$fake_bin/provision-app-edge.sh" "$log_file" "provision-app-edge"
  write_fake_rebuild_canary "$fake_bin/canary-shared-services.sh" "$log_file" "canary-shared-services"
  write_fake_rebuild_canary "$fake_bin/canary-app-host.sh" "$log_file" "canary-app-host"
  write_fake_rebuild_roll "$fake_bin/roll-preview-operators.sh" "$log_file" "$fixture_dir" "$rollout_ready"
  write_fake_rebuild_refresh "$fake_bin/refresh-app-runtime.sh" "$log_file" "refresh-app-runtime"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-app-backoffice.sh" "$log_file"
  write_fake_rebuild_refresh "$fake_bin/refresh-preview-wireguard-backoffice.sh" "$log_file" "refresh-preview-wireguard-backoffice"
  write_fake_rebuild_e2e "$fake_bin/shared-infra-e2e" "$log_file"
  write_fake_rebuild_aws "$fake_bin/aws" "$aws_log" "$ssm_commands" "$remote_stdout" "$rollout_ready"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN="$fake_bin/upgrade-preview-inventory.sh" \
      PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN="$fake_bin/destroy-preview-role-runtime.sh" \
      PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN="$fake_bin/resolve-role-runtime-release-inputs.sh" \
      PRODUCTION_DEPLOY_COORDINATOR_BIN="$fake_bin/deploy-coordinator.sh" \
      PRODUCTION_PROVISION_APP_EDGE_BIN="$fake_bin/provision-app-edge.sh" \
      PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
      PRODUCTION_CANARY_APP_BIN="$fake_bin/canary-app-host.sh" \
      PRODUCTION_REFRESH_APP_RUNTIME_BIN="$fake_bin/refresh-app-runtime.sh" \
      PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN="$fake_bin/roll-preview-operators.sh" \
      PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN="$fake_bin/refresh-preview-app-backoffice.sh" \
      PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN="$fake_bin/refresh-preview-wireguard-backoffice.sh" \
      bash "$REPO_ROOT/deploy/production/rebuild-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --dkg-summary "$dkg_summary" \
        --bridge-deploy-binary /bin/true \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --shared-infra-e2e-binary "$fake_bin/shared-infra-e2e" \
        --output-dir "$output_root"
  )

  assert_eq "$(jq -r '.dkg_tls_dir' "$output_root/preview/inventory.resolved.json")" "$tmp/dkg-tls" "rebuild anchors dkg tls paths to the source inventory bundle"
  assert_eq "$(jq -r '.app_role.known_hosts_file' "$output_root/preview/inventory.resolved.json")" "$tmp/app/known_hosts" "rebuild anchors app known_hosts to the source inventory bundle"
  assert_eq "$(jq -r '.app_role.secret_contract_file' "$output_root/preview/inventory.resolved.json")" "$tmp/app/app-secrets.env" "rebuild anchors app secrets to the source inventory bundle"
  assert_eq "$(jq -r '.operators[0].known_hosts_file' "$output_root/preview/inventory.resolved.json")" "$tmp/operators/op1/known_hosts" "rebuild anchors operator known_hosts to the source inventory bundle"
  assert_eq "$(jq -r '.operators[0].secret_contract_file' "$output_root/preview/inventory.resolved.json")" "$tmp/operators/op1/operator-secrets.env" "rebuild anchors operator secrets to the source inventory bundle"
  assert_eq "$(jq -r '.operators[0].dkg_backup_zip' "$output_root/preview/inventory.resolved.json")" "$tmp/operators/op1/dkg-backup.zip" "rebuild anchors operator dkg backups to the source inventory bundle"

  rm -rf "$tmp"
}

main() {
  test_rebuild_preview_role_runtime_refreshes_backoffice_after_operator_rollout
  test_rebuild_preview_role_runtime_carries_forward_current_shared_proof_secrets
  test_rebuild_preview_role_runtime_defaults_ephemeral_bridge_funding_amount
  test_rebuild_preview_role_runtime_absolutizes_source_artifact_paths
}

main "$@"
