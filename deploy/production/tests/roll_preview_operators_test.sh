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
  "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"44.201.3.134","LaunchTemplate":{"LaunchTemplateId":"lt-op1","Version":"3"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op1"}]}]}]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"34.207.95.248","LaunchTemplate":{"LaunchTemplateId":"lt-op2","Version":"7"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op2"}]}]}]}\n'
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
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op1","PublicIpAddress":"44.201.10.10","PrivateIpAddress":"10.0.10.10","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op2 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op2","PublicIpAddress":"34.207.20.20","PrivateIpAddress":"10.0.11.11","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "iam get-instance-profile --instance-profile-name juno-live-e2e-preview0316d-instance-profile --output json")
    printf '{"InstanceProfile":{"Roles":[{"RoleName":"juno-live-e2e-preview0316d-instance-role"}]}}\n'
    ;;
  "s3api get-bucket-encryption --bucket preview-checkpoint-blobs --output json")
    printf '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:021490342184:key/preview-checkpoint-blobs"}}]}}\n'
    ;;
  iam\ put-role-policy\ --role-name\ juno-live-e2e-preview0316d-instance-role\ --policy-name\ preview-shared-kafka-access\ --policy-document\ *)
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_roll_preview_aws_with_slow_refresh() {
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
  "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"44.201.3.134","LaunchTemplate":{"LaunchTemplateId":"lt-op1","Version":"3"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op1"}]}]}]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"34.207.95.248","LaunchTemplate":{"LaunchTemplateId":"lt-op2","Version":"7"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op2"}]}]}]}\n'
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
    refresh_count_file="${SLOW_REFRESH_COUNT_FILE:?missing SLOW_REFRESH_COUNT_FILE}"
    refresh_count=0
    if [[ -f "$refresh_count_file" ]]; then
      refresh_count="$(cat "$refresh_count_file")"
    fi
    refresh_count=$((refresh_count + 1))
    printf '%s\n' "$refresh_count" >"$refresh_count_file"
    if (( refresh_count < 61 )); then
      printf '{"InstanceRefreshes":[{"Status":"InProgress"}]}\n'
    else
      printf '{"InstanceRefreshes":[{"Status":"Successful"}]}\n'
    fi
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
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op1","PublicIpAddress":"44.201.10.10","PrivateIpAddress":"10.0.10.10","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op2 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op2","PublicIpAddress":"34.207.20.20","PrivateIpAddress":"10.0.11.11","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "iam get-instance-profile --instance-profile-name juno-live-e2e-preview0316d-instance-profile --output json")
    printf '{"InstanceProfile":{"Roles":[{"RoleName":"juno-live-e2e-preview0316d-instance-role"}]}}\n'
    ;;
  "s3api get-bucket-encryption --bucket preview-checkpoint-blobs --output json")
    printf '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:021490342184:key/preview-checkpoint-blobs"}}]}}\n'
    ;;
  iam\ put-role-policy\ --role-name\ juno-live-e2e-preview0316d-instance-role\ --policy-name\ preview-shared-kafka-access\ --policy-document\ *)
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_roll_preview_aws_with_existing_refresh() {
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
  "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"44.201.3.134","LaunchTemplate":{"LaunchTemplateId":"lt-op1","Version":"3"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op1"}]}]}]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"34.207.95.248","LaunchTemplate":{"LaunchTemplateId":"lt-op2","Version":"7"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op2"}]}]}]}\n'
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op1 --launch-template LaunchTemplateId=lt-op1,Version=4")
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op2 --launch-template LaunchTemplateId=lt-op2,Version=8")
    ;;
  "autoscaling start-instance-refresh --auto-scaling-group-name preview-op1 --preferences {\"MinHealthyPercentage\":100} --output json")
    printf '{"InstanceRefreshId":"refresh-op1"}\n'
    ;;
  "autoscaling start-instance-refresh --auto-scaling-group-name preview-op2 --preferences {\"MinHealthyPercentage\":100} --output json")
    printf 'An error occurred (InstanceRefreshInProgress) when calling the StartInstanceRefresh operation: An Instance Refresh is already in progress and blocks the execution of this Instance Refresh.\n' >&2
    exit 254
    ;;
  "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op1 --instance-refresh-ids refresh-op1 --output json")
    printf '{"InstanceRefreshes":[{"Status":"Successful"}]}\n'
    ;;
  "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op2 --output json")
    printf '{"InstanceRefreshes":[{"InstanceRefreshId":"refresh-op2-existing","Status":"InProgress","StartTime":"2026-03-24T15:11:45+00:00"}]}\n'
    ;;
  "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op2 --instance-refresh-ids refresh-op2-existing --output json")
    printf '{"InstanceRefreshes":[{"Status":"Successful"}]}\n'
    ;;
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op1 --output json")
    printf '{"AutoScalingGroups":[{"DesiredCapacity":1,"Instances":[{"InstanceId":"i-op1","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op2 --output json")
    printf '{"AutoScalingGroups":[{"DesiredCapacity":1,"Instances":[{"InstanceId":"i-op2","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op1 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op1","PublicIpAddress":"44.201.10.10","PrivateIpAddress":"10.0.10.10","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op2 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op2","PublicIpAddress":"34.207.20.20","PrivateIpAddress":"10.0.11.11","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "iam get-instance-profile --instance-profile-name juno-live-e2e-preview0316d-instance-profile --output json")
    printf '{"InstanceProfile":{"Roles":[{"RoleName":"juno-live-e2e-preview0316d-instance-role"}]}}\n'
    ;;
  "s3api get-bucket-encryption --bucket preview-checkpoint-blobs --output json")
    printf '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:021490342184:key/preview-checkpoint-blobs"}}]}}\n'
    ;;
  iam\ put-role-policy\ --role-name\ juno-live-e2e-preview0316d-instance-role\ --policy-name\ preview-shared-kafka-access\ --policy-document\ *)
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_roll_preview_aws_with_stale_launch_templates() {
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
  "ec2 create-launch-template-version --launch-template-id lt-stale-op1 --source-version 3 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf 'An error occurred (InvalidLaunchTemplateId.NotFound) when calling the CreateLaunchTemplateVersion operation: The specified launch template, with template ID lt-stale-op1, does not exist.\n' >&2
    exit 254
    ;;
  "ec2 create-launch-template-version --launch-template-id lt-stale-op2 --source-version 7 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf 'An error occurred (InvalidLaunchTemplateId.NotFound) when calling the CreateLaunchTemplateVersion operation: The specified launch template, with template ID lt-stale-op2, does not exist.\n' >&2
    exit 254
    ;;
  "ec2 create-launch-template-version --launch-template-id lt-live-op1 --source-version 11 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf '{"LaunchTemplateVersion":{"VersionNumber":12}}\n'
    ;;
  "ec2 create-launch-template-version --launch-template-id lt-live-op2 --source-version 13 --launch-template-data {\"ImageId\":\"ami-0operatorfresh123456\"} --output json")
    printf '{"LaunchTemplateVersion":{"VersionNumber":14}}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"44.201.3.134","LaunchTemplate":{"LaunchTemplateId":"lt-live-op1","Version":"11"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op1"}]}]}]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json")
    printf '{"Reservations":[{"Instances":[{"PublicIpAddress":"34.207.95.248","LaunchTemplate":{"LaunchTemplateId":"lt-live-op2","Version":"13"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op2"}]}]}]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=203.0.113.10 --output json")
    printf '{"Reservations":[]}\n'
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=203.0.113.11 --output json")
    printf '{"Reservations":[]}\n'
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op1 --launch-template LaunchTemplateId=lt-live-op1,Version=12")
    ;;
  "autoscaling update-auto-scaling-group --auto-scaling-group-name preview-op2 --launch-template LaunchTemplateId=lt-live-op2,Version=14")
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
    printf '{"AutoScalingGroups":[{"AutoScalingGroupName":"preview-op1","DesiredCapacity":1,"LaunchTemplate":{"LaunchTemplateId":"lt-live-op1","Version":"11"},"Instances":[{"InstanceId":"i-op1","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op2 --output json")
    printf '{"AutoScalingGroups":[{"AutoScalingGroupName":"preview-op2","DesiredCapacity":1,"LaunchTemplate":{"LaunchTemplateId":"lt-live-op2","Version":"13"},"Instances":[{"InstanceId":"i-op2","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op1 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op1","PublicIpAddress":"44.201.10.10","PrivateIpAddress":"10.0.10.10","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "ec2 describe-instances --instance-ids i-op2 --output json")
    printf '{"Reservations":[{"Instances":[{"InstanceId":"i-op2","PublicIpAddress":"34.207.20.20","PrivateIpAddress":"10.0.11.11","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}\n'
    ;;
  "iam get-instance-profile --instance-profile-name juno-live-e2e-preview0316d-instance-profile --output json")
    printf '{"InstanceProfile":{"Roles":[{"RoleName":"juno-live-e2e-preview0316d-instance-role"}]}}\n'
    ;;
  "s3api get-bucket-encryption --bucket preview-checkpoint-blobs --output json")
    printf '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:021490342184:key/preview-checkpoint-blobs"}}]}}\n'
    ;;
  iam\ put-role-policy\ --role-name\ juno-live-e2e-preview0316d-instance-role\ --policy-name\ preview-shared-kafka-access\ --policy-document\ *)
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

write_fake_deploy_operator_binary_consumes_stdin() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'deploy-operator %s\n' "\$*" >>"$log_file"
if IFS= read -r _; then
  :
fi
exit 0
EOF
  chmod +x "$target"
}

write_fake_deploy_operator_binary_emits_stdout() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'deploy-operator %s\n' "\$*" >>"$log_file"
cat <<'JSON'
{"receipt_version":"key_import_receipt_v1","operator_id":"0xnoise"}
JSON
cat <<'JSON'
{"ChangeInfo":{"Id":"/change/NOISE","Status":"PENDING"}}
JSON
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
    "kafka": {
      "cluster_arn": "arn:aws:kafka:us-east-1:021490342184:cluster/intents-juno-shared-preview-shared-msk/0d36d42f-e2ef-487d-88c9-8afe649ed844-13"
    },
    "artifacts": {
      "checkpoint_blob_bucket": "preview-checkpoint-blobs"
    }
  }
}
JSON
}

test_roll_preview_operators_refreshes_asgs_and_redeploys_handoffs() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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
  assert_contains "$(cat "$aws_log")" "iam put-role-policy --role-name juno-live-e2e-preview0316d-instance-role --policy-name preview-shared-kafka-access" "preview operator roll adds kafka access for the rebuilt shared cluster"
  assert_contains "$(cat "$aws_log")" "s3api get-bucket-encryption --bucket preview-checkpoint-blobs --output json" "preview operator roll resolves the checkpoint bucket kms key"
  assert_contains "$(cat "$ssh_keyscan_log")" "ssh-keyscan -T 10 -H 44.201.10.10" "preview operator roll bounds ssh-keyscan when collecting known hosts"
  assert_contains "$(cat "$deploy_log")" "--operator-deploy $output_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json" "preview operator roll redeploys the first operator"
  assert_contains "$(cat "$canary_log")" "--operator-deploy $output_dir/operators/0x6666666666666666666666666666666666666666/operator-deploy.json" "preview operator roll runs the second operator canary"
  assert_eq "$(jq -r '.operators[0].operator_host' "$output_dir/inventory.operators-rolled.json")" "44.201.10.10" "preview operator roll updates first operator host"
  assert_eq "$(jq -r '.operators[0].private_endpoint' "$output_dir/inventory.operators-rolled.json")" "10.0.10.10" "preview operator roll records first operator private endpoint"
  assert_eq "$(jq -r '.operators[1].launch_template.version' "$output_dir/inventory.operators-rolled.json")" "8" "preview operator roll updates second launch template version"
  assert_eq "$(jq -r '.checkpoint_blob_bucket' "$output_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json")" "preview-checkpoint-blobs" "preview operator handoff falls back to the shared checkpoint bucket"
  assert_eq "$(jq -r '.checkpoint_blob_sse_kms_key_id' "$output_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/preview-checkpoint-blobs" "preview operator handoff resolves the checkpoint bucket kms key"
  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/roll-summary.json")" "true" "preview operator roll reports success"

  rm -rf "$tmp"
}

test_roll_preview_operators_waits_for_slow_but_successful_instance_refreshes() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir refresh_count_file
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
  output_dir="$tmp/output"
  refresh_count_file="$tmp/refresh-count"

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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws_with_slow_refresh "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
EOF
  chmod +x "$tmp/bin/ssh-keyscan"

  (
    cd "$REPO_ROOT"
    TEST_AWS_LOG="$aws_log" \
      SLOW_REFRESH_COUNT_FILE="$refresh_count_file" \
      PATH="$tmp/bin:$PATH" \
      PRODUCTION_DEPLOY_OPERATOR_BIN="$tmp/bin/deploy-operator.sh" \
      PRODUCTION_CANARY_OPERATOR_BOOT_BIN="$tmp/bin/canary-operator-boot.sh" \
      PRODUCTION_PREVIEW_OPERATOR_INSTANCE_REFRESH_POLL_ATTEMPTS=61 \
      PRODUCTION_PREVIEW_OPERATOR_INSTANCE_REFRESH_POLL_INTERVAL_SECONDS=0 \
      bash "$REPO_ROOT/deploy/production/roll-preview-operators.sh" \
        --inventory "$inventory" \
        --shared-manifest "$shared_manifest" \
        --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
        --operator-stack-ami-release-tag operator-stack-ami-v2026.03.20-testnet \
        --output-dir "$output_dir" \
        --github-repo juno-intents/intents-juno >"$tmp/roll-summary.json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/roll-summary.json")" "true" "preview operator roll waits for a slow but successful refresh"
  assert_eq "$(cat "$refresh_count_file")" "61" "preview operator roll polls until the refresh eventually becomes successful"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op1 --instance-refresh-ids refresh-op1 --output json" "preview operator roll keeps polling the slow refresh"

  rm -rf "$tmp"
}

test_roll_preview_operators_reuses_existing_instance_refreshes() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws_with_existing_refresh "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/roll-summary.json")" "true" "preview operator roll reuses an in-progress refresh instead of failing"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op2 --output json" "preview operator roll queries the active refresh when aws rejects a second refresh start"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-instance-refreshes --auto-scaling-group-name preview-op2 --instance-refresh-ids refresh-op2-existing --output json" "preview operator roll waits on the existing refresh id"

  rm -rf "$tmp"
}

test_roll_preview_operators_discovers_missing_asg_and_launch_template_from_public_ip() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  jq '
    .operators[0].asg = ""
    | .operators[0].launch_template = null
    | .operators[1].asg = ""
    | .operators[1].launch_template = null
  ' "$inventory" >"$tmp/inventory.next"
  mv "$tmp/inventory.next" "$inventory"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  assert_contains "$(cat "$aws_log")" "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json" "preview operator roll rediscovers the first operator metadata from its public ip"
  assert_contains "$(cat "$aws_log")" "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json" "preview operator roll rediscovers the second operator metadata from its public ip"
  assert_contains "$(cat "$ssh_keyscan_log")" "ssh-keyscan -T 10 -H 44.201.10.10" "preview operator roll still bounds ssh-keyscan after metadata rediscovery"
  assert_eq "$(jq -r '.operators[0].asg' "$output_dir/inventory.operators-rolled.json")" "preview-op1" "preview operator roll persists the discovered first operator asg"
  assert_eq "$(jq -r '.operators[1].launch_template.id' "$output_dir/inventory.operators-rolled.json")" "lt-op2" "preview operator roll persists the discovered second operator launch template id"

  rm -rf "$tmp"
}

test_roll_preview_operators_recovers_from_stale_launch_template_ids() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  jq '
    .operators[0].launch_template = {id: "lt-stale-op1", version: "3"}
    | .operators[1].launch_template = {id: "lt-stale-op2", version: "7"}
  ' "$inventory" >"$tmp/inventory.next"
  mv "$tmp/inventory.next" "$inventory"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws_with_stale_launch_templates "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  assert_contains "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-stale-op1 --source-version 3" "preview operator roll attempts the persisted first launch template before rediscovery"
  assert_contains "$(cat "$aws_log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op1 --output json" "preview operator roll reads the first live asg when its persisted launch template is gone"
  assert_contains "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-live-op1 --source-version 11" "preview operator roll retries the first operator with the live launch template"
  assert_eq "$(jq -r '.operators[0].launch_template.id' "$output_dir/inventory.operators-rolled.json")" "lt-live-op1" "preview operator roll persists the refreshed first launch template id"
  assert_eq "$(jq -r '.operators[1].launch_template.version' "$output_dir/inventory.operators-rolled.json")" "14" "preview operator roll persists the refreshed second launch template version"

  rm -rf "$tmp"
}

test_roll_preview_operators_recovers_from_asg_when_public_ip_is_stale() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  jq '
    .operators[0].public_endpoint = "203.0.113.10"
    | .operators[0].operator_host = "203.0.113.10"
    | .operators[0].launch_template = {id: "lt-stale-op1", version: "3"}
    | .operators[1].public_endpoint = "203.0.113.11"
    | .operators[1].operator_host = "203.0.113.11"
    | .operators[1].launch_template = {id: "lt-stale-op2", version: "7"}
  ' "$inventory" >"$tmp/inventory.next"
  mv "$tmp/inventory.next" "$inventory"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws_with_stale_launch_templates "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  assert_contains "$(cat "$aws_log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names preview-op1 --output json" "preview operator roll reads the first live asg after a stale launch template failure"
  assert_contains "$(cat "$aws_log")" "ec2 create-launch-template-version --launch-template-id lt-live-op1 --source-version 11" "preview operator roll retries the first operator with the asg launch template"
  assert_eq "$(jq -r '.operators[0].launch_template.id' "$output_dir/inventory.operators-rolled.json")" "lt-live-op1" "preview operator roll persists the asg launch template id when the public ip is stale"

  rm -rf "$tmp"
}

test_roll_preview_operators_redeploys_all_handoffs_when_deploy_consumes_stdin() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary_consumes_stdin "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  deploy_count="$(grep -c '^deploy-operator ' "$deploy_log")"
  canary_count="$(grep -c '^canary-operator ' "$canary_log")"
  assert_eq "$deploy_count" "2" "preview operator roll redeploys every handoff even when deploy-operator consumes stdin"
  assert_eq "$canary_count" "2" "preview operator roll canaries every handoff even when deploy-operator consumes stdin"

  rm -rf "$tmp"
}

test_roll_preview_operators_keeps_summary_json_clean_when_deploy_logs_to_stdout() {
  local tmp inventory shared_manifest releases_dir gh_log aws_log deploy_log canary_log ssh_keyscan_log output_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  shared_manifest="$tmp/shared-manifest.json"
  releases_dir="$tmp/releases"
  gh_log="$tmp/gh.log"
  aws_log="$tmp/aws.log"
  deploy_log="$tmp/deploy.log"
  canary_log="$tmp/canary.log"
  ssh_keyscan_log="$tmp/ssh-keyscan.log"
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
  (
    cd "$releases_dir/operator-stack-ami-v2026.03.20-testnet"
    digest="$(shasum -a 256 operator-ami-manifest.json | awk '{print $1}')"
    printf '%s  .ci/out/operator-ami-manifest.json\n' "$digest" > operator-ami-manifest.json.sha256
  )

  write_fake_operator_release_downloader "$tmp/bin/gh" "$releases_dir" "$gh_log"
  write_fake_roll_preview_aws "$tmp/bin/aws" "$aws_log"
  write_fake_deploy_operator_binary_emits_stdout "$tmp/bin/deploy-operator.sh" "$deploy_log"
  write_fake_operator_canary_binary "$tmp/bin/canary-operator-boot.sh" "$canary_log"
  cat >"$tmp/bin/ssh-keyscan" <<EOF
#!/usr/bin/env bash
printf 'ssh-keyscan %s\n' "\$*" >>"$ssh_keyscan_log"
host="\${@: -1}"
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey\n' "\$host"
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

  assert_eq "$(jq -r '.ready_for_deploy' "$tmp/roll-summary.json")" "true" "preview operator roll keeps the final summary as a single json document when deploy logs to stdout"
  assert_eq "$(jq -r '.operators | length' "$tmp/roll-summary.json")" "2" "preview operator roll summary preserves operator results when deploy logs to stdout"

  rm -rf "$tmp"
}

main() {
  test_roll_preview_operators_refreshes_asgs_and_redeploys_handoffs
  test_roll_preview_operators_waits_for_slow_but_successful_instance_refreshes
  test_roll_preview_operators_reuses_existing_instance_refreshes
  test_roll_preview_operators_discovers_missing_asg_and_launch_template_from_public_ip
  test_roll_preview_operators_recovers_from_stale_launch_template_ids
  test_roll_preview_operators_recovers_from_asg_when_public_ip_is_stale
  test_roll_preview_operators_redeploys_all_handoffs_when_deploy_consumes_stdin
  test_roll_preview_operators_keeps_summary_json_clean_when_deploy_logs_to_stdout
}

main "$@"
