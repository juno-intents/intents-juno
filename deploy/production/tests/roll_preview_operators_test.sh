#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_roll_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh1 "$workdir/operators/op1/known_hosts" \
    --arg kh2 "$workdir/operators/op2/known_hosts" \
    --arg backup1 "$workdir/operators/op1/dkg-backup.zip" \
    --arg backup2 "$workdir/operators/op2/dkg-backup.zip" \
    --arg secrets1 "$workdir/operators/op1/operator-secrets.env" \
    --arg secrets2 "$workdir/operators/op2/operator-secrets.env" \
    '
      .environment = "preview"
      | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
      | .shared_services.route53_zone_id = "Z01169511CVMQJAD7T3TJ"
      | .operators = [
          {
            index: 1,
            operator_id: "0x1111111111111111111111111111111111111111",
            operator_address: "0x1111111111111111111111111111111111111111",
            checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/op1",
            operator_host: "44.201.3.134",
            operator_user: "ubuntu",
            runtime_dir: "/var/lib/intents-juno/operator-runtime",
            public_dns_label: "op1",
            public_endpoint: "44.201.3.134",
            aws_profile: "juno",
            aws_region: "us-east-1",
            account_id: "021490342184",
            asg: "preview-op1",
            launch_template: { id: "lt-op1", version: "3" },
            known_hosts_file: $kh1,
            dkg_backup_zip: $backup1,
            secret_contract_file: $secrets1
          },
          {
            index: 2,
            operator_id: "0x6666666666666666666666666666666666666666",
            operator_address: "0x6666666666666666666666666666666666666666",
            checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/op2",
            operator_host: "34.207.95.248",
            operator_user: "ubuntu",
            runtime_dir: "/var/lib/intents-juno/operator-runtime",
            public_dns_label: "op2",
            public_endpoint: "34.207.95.248",
            aws_profile: "juno",
            aws_region: "us-east-1",
            account_id: "021490342184",
            asg: "preview-op2",
            launch_template: { id: "lt-op2", version: "7" },
            known_hosts_file: $kh2,
            dkg_backup_zip: $backup2,
            secret_contract_file: $secrets2
          }
        ]
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_fake_operator_release_downloader() {
  local target="$1"
  local releases_dir="$2"
  local log_file="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "\$*" >>"$log_file"
tag=""
dir=""
patterns=()
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    release)
      shift
      ;;
    download)
      tag="\$2"
      shift 2
      ;;
    --repo)
      shift 2
      ;;
    --pattern)
      patterns+=("\$2")
      shift 2
      ;;
    --dir)
      dir="\$2"
      shift 2
      ;;
    --clobber)
      shift
      ;;
    *)
      printf 'unexpected gh arg: %s\n' "\$1" >&2
      exit 1
      ;;
  esac
done
mkdir -p "\$dir"
for pattern in "\${patterns[@]}"; do
  cp "$releases_dir/\$tag/\$pattern" "\$dir/\$pattern"
done
EOF
  chmod +x "$target"
}

write_fake_roll_preview_aws() {
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
  "ec2 create-launch-template-version --launch-template-id lt-op1 --source-version 3 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf '{"LaunchTemplateVersion":{"VersionNumber":4}}\n'
    ;;
  "ec2 create-launch-template-version --launch-template-id lt-op2 --source-version 7 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf '{"LaunchTemplateVersion":{"VersionNumber":8}}\n'
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op1 --launch-template LaunchTemplateId=lt-op1,Version=4")
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op2 --launch-template LaunchTemplateId=lt-op2,Version=8")
    ;;
  "autoscaling start-instance-refresh --auto-scaling-group-name preview-op1 --preferences {\"MinHealthyPercentage\":100} --output json")
    printf '{"InstanceRefreshId":"refresh-op1"}\n'
    ;;
  "autoscaling start-instance-refresh --auto-scaling-group-name preview-op2 --preferences {\"MinHealthyPercentage\":100} --output json")
    printf '{"InstanceRefreshId":"refresh-op2"}\n'
    ;;
  "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op1 --instance-refresh-ids refresh-op1 --output json")
    printf '{"InstanceRefreshes":[{"Status":"Successful"}]}\n'
    ;;
  "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op2 --instance-refresh-ids refresh-op2 --output json")
    printf '{"InstanceRefreshes":[{"Status":"Successful"}]}\n'
    ;;
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op1 --output json")
    printf '{"AutoScalingGroups":[{"DesiredCapacity":1,"Instances":[{"InstanceId":"i-op1","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op2 --output json")
    printf '{"AutoScalingGroups":[{"DesiredCapacity":1,"Instances":[{"InstanceId":"i-op2","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op1 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op1","PublicIpAddress":"44.201.10.10","PrivateIpAddress":"10.0.10.10"}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op2 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op2","PublicIpAddress":"34.207.20.20","PrivateIpAddress":"10.0.11.11"}]}]}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_deploy_operator_binary() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'deploy-operator %s\n' "\$*" >>"$log_file"
exit 0
EOF
  chmod +x "$target"
}

write_fake_operator_canary_binary() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'canary-operator %s\n' "\$*" >>"$log_file"
cat <<'JSON'
{"ready_for_deploy":true}
JSON
EOF
  chmod +x "$target"
}

write_shared_manifest_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "2",
  "environment": "preview",
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example",
    "base_chain_id": 84532,
    "bridge": "0x2222222222222222222222222222222222222222",
    "owallet_ua": "u1previewowalletaddress"
  },
  "checkpoint": {
    "threshold": 2,
      "operators": [
        "0x1111111111111111111111111111111111111111",
        "0x6666666666666666666666666666666666666666"
      ],
    "signature_topic": "checkpoint.signatures.v1",
    "package_topic": "checkpoint.packages.v1",
    "signer_ufvk": "uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
  },
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "artifacts": {
      "checkpoint_blob_bucket": "preview-checkpoint-blobs"
    }
  }
}
JSON
}

test_roll_preview_operators_refreshes_asgs_and_redeploys_handoffs() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  output_dir="$tmp/output"

  mkdir -p "$tmp/bin" "$tmp/operators/op1" "$tmp/operators/op2" "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
  : >"$tmp/operators/op1/known_hosts"
  : >"$tmp/operators/op2/known_hosts"
  cat >"$tmp/operators/op1/operator-secrets.env" <<'EOF'
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  cat >"$tmp/operators/op2/operator-secrets.env" <<'EOF'
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$tmp/operators/op1/operator-secrets.env"
  append_default_owallet_proof_keys "$tmp/operators/op2/operator-secrets.env"
  write_test_dkg_backup_zip "$tmp/operators/op1/dkg-backup.zip"
  write_test_dkg_backup_zip "$tmp/operators/op2/dkg-backup.zip"
  write_roll_inventory_fixture "$inventory" "$tmp"
  write_shared_manifest_fixture "$shared_manifest"

  cat >"$releases_dir/operator-stack-ami-v2026.03.20-testnet/operator-ami-manifest.json" <<'JSON'
{
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0operatorfresh123456"
    }
  }
}
JSON
  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
      sha256sum operator-ami-manifest.json > operator-ami-manifest.json.sha256
    )
  else
    (
      cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
      shasum -a 256 operator-ami-manifest.json | awk '{print $1 "  operator-ami-manifest.json"}' > operator-ami-manifest.json.sha256
    )
  fi

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<'EOF'
#!/usr/bin/env bash
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "$2"
EOF
  chmod +x "$tmp/bin/ssh-keyscan"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" PATH="$tmp/bin:$PATH" \
      PRODUCTION_DEPLOY_OPERATOR_BIN="$tmp/bin/deploy-operator.sh" \
      PRODUCTION_CANARY_OPERATOR_BOOT_BIN="$tmp/bin/canary-operator-boot.sh" \
      bash "$REPO_ROOT/deploy/production/roll-preview-operators.sh" \
        --inventory "$inventory" \
        --shared-manifest "$shared_manifest" \
        --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --output-dir "$output_dir" \
        --github-repo juno-intents/intents-juno >"$tmp/roll-summary.json"
  )

  assert_contains "$(cat "$gh_log")" "release download operator-stack-ami-v2026.03.20-testnet" "preview operator roll downloads the operator ami manifest"
  assert_contains "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-op1 --source-version 3" "preview operator roll creates a fresh launch template version"
  assert_contains "$(cat "$aws_log")" "autoscaling start-instance-refresh --auto-scaling-group-name preview-op2" "preview operator roll refreshes the second operator asg"
  assert_contains "$(cat "$deploy_log")" "--operator-deploy $output_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json" "preview operator roll redeploys the first operator"
  assert_contains "$(cat "$canary_log")" "--operator-deploy $output_dir/operators/0x6666666666666666666666666666666666666666/operator-deploy.json" "preview operator roll runs the second operator canary"
  assert_eq "$(jq -r '.operators[0].operator_host' "$output_dir/inventory.operators-rolled.json")" "44.201.10.10" "preview operator roll updates first operator host"
  assert_eq "$(jq -r '.operators[1].launch_template.version' "$output_dir/inventory.operators-rolled.json")" "8" "preview operator roll updates second launch template version"
  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/roll-summary.json")" "true" "preview operator roll reports success"

  rm -rf "$tmp"
}

main() {
  test_roll_preview_operators_refreshes_asgs_and_redeploys_handoffs
}

main "$@"
