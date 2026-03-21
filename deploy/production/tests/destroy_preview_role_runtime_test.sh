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
  if [[ "$haystack" == *"$needle"* ]]; then
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
    printf 'assert_line_order failed: %s: first=%q second=%q first_line=%q second_line=%q\n' "$msg" "$first" "$second" "$first_line" "$second_line" >&2
    exit 1
  fi
}

write_fake_destroy_terraform() {
  local target="$1"
  local log_file="$2"
  local cloudfront_distribution_id="${3:-}"
  local app_security_group_id="${4-sg-049874c1a0e9a1c9d}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'terraform %s\n' "\$*" >>"$log_file"
printf 'terraform-cwd %s\n' "\$PWD" >>"$log_file"
printf 'terraform-env AWS_ENDPOINT_URL_STS=%s\n' "\${AWS_ENDPOINT_URL_STS:-}" >>"$log_file"
case "\${1:-}" in
  init|destroy)
    for arg in "\$@"; do
      if [[ "\$arg" == -var-file=* ]]; then
        printf 'terraform-var-file %s\n' "\${arg#-var-file=}" >>"$log_file"
      fi
      if [[ "\$arg" == -state=* ]]; then
        printf 'terraform-state %s\n' "\${arg#-state=}" >>"$log_file"
      fi
    done
    exit 0
    ;;
  output)
    if [[ "\${2:-}" == "-json" && "\$PWD" == *"/deploy/shared/terraform/app-runtime" ]]; then
      cat <<'JSON'
{
  "app_role": {
    "value": {
      "asg": "juno-app-runtime-preview-asg",
      "internal_lb": {
        "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/juno-app-runtime-preview-backoff/861c0d2977e0ad7b"
      },
      "public_lb": {
        "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/juno-app-runtime-preview-bridge/bf53abd559495064"
      }
    }
  }
$(if [[ -n "$app_security_group_id" ]]; then cat <<JSON
,
  "app_security_group_id": {
    "value": "$app_security_group_id"
  }
JSON
fi)
}
JSON
      exit 0
    fi
    ;;
  state)
    if [[ "\${2:-}" == show && -n "$cloudfront_distribution_id" && " \$* " == *" aws_cloudfront_distribution.bridge "* ]]; then
      cat <<STATE
# aws_cloudfront_distribution.bridge:
resource "aws_cloudfront_distribution" "bridge" {
    id = "$cloudfront_distribution_id"
}
STATE
      exit 0
    fi
    ;;
esac
printf 'unexpected terraform invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_destroy_aws() {
  local target="$1"
  local log_file="$2"
  local state_dir="${3:-}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"
args=( "\$@" )
if [[ "\${args[0]:-}" == "--profile" ]]; then
  args=( "\${args[@]:2}" )
fi
if [[ "\${args[0]:-}" == "--region" ]]; then
  args=( "\${args[@]:2}" )
fi
backup_vault_name=""
bucket_name=""
for ((i = 0; i < \${#args[@]}; i++)); do
  case "\${args[\$i]}" in
    --backup-vault-name)
      if (( i + 1 < \${#args[@]} )); then
        backup_vault_name="\${args[\$((i + 1))]}"
      fi
      ;;
    --bucket)
      if (( i + 1 < \${#args[@]} )); then
        bucket_name="\${args[\$((i + 1))]}"
      fi
      ;;
  esac
done
case "\${args[0]:-} \${args[1]:-}" in
  "sts get-caller-identity")
    if [[ " \$* " == *" --query Account "* && " \$* " == *" --output text "* ]]; then
      printf '021490342184\n'
    else
      printf '{"Account":"021490342184"}\n'
    fi
    ;;
  "s3api head-bucket")
    exit 255
    ;;
  "s3api create-bucket"|"s3api put-bucket-versioning"|"s3api put-bucket-encryption"|"s3api put-public-access-block")
    ;;
  "dynamodb describe-table")
    exit 255
    ;;
  "dynamodb create-table")
    printf '{"TableDescription":{"TableStatus":"ACTIVE"}}\n'
    ;;
  "cloudfront get-distribution-config")
    if [[ -n "$state_dir" && -f "$state_dir/distribution.deleted" ]]; then
      printf 'NoSuchDistribution\n' >&2
      exit 255
    fi
    if [[ -n "$state_dir" && -f "$state_dir/distribution.disabled" ]]; then
      printf '{"ETag":"E2","DistributionConfig":{"Enabled":false}}\n'
    else
      printf '{"ETag":"E1","DistributionConfig":{"Enabled":true}}\n'
    fi
    ;;
  "cloudfront update-distribution")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/distribution.disabled"
    fi
    ;;
  "cloudfront get-distribution")
    if [[ -n "$state_dir" && -f "$state_dir/distribution.deleted" ]]; then
      printf 'NoSuchDistribution\n' >&2
      exit 255
    fi
    if [[ -n "$state_dir" && -f "$state_dir/distribution.disabled" ]]; then
      printf '{"Distribution":{"Status":"Deployed","DistributionConfig":{"Enabled":false}}}\n'
    else
      printf '{"Distribution":{"Status":"Deployed","DistributionConfig":{"Enabled":true}}}\n'
    fi
    ;;
  "cloudfront delete-distribution")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/distribution.deleted"
    fi
    ;;
  "cloudtrail stop-logging")
    ;;
  "autoscaling update-auto-scaling-group")
    ;;
  "autoscaling describe-auto-scaling-groups")
    if [[ -n "$state_dir" && -f "$state_dir/app.instances.cleared" ]]; then
      printf '\n'
    else
      printf 'i-app-a\ti-app-b\n'
    fi
    ;;
  "ec2 terminate-instances")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/app.instances.terminating"
    fi
    ;;
  "ec2 wait")
    if [[ "\${args[2]:-}" == "instance-terminated" && -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/app.instances.cleared"
    fi
    ;;
  "ec2 describe-security-groups")
    if [[ " \$* " == *" Name=ip-permission.group-id,Values=sg-049874c1a0e9a1c9d "* ]]; then
      printf 'sg-09af876efa8c830fb\tsg-004e0c14829a3228a\n'
    elif [[ " \$* " == *" Name=group-name,Values=juno-app-runtime-preview-app "* ]]; then
      printf 'sg-049874c1a0e9a1c9d\n'
    else
      printf '\n'
    fi
    ;;
  "ec2 describe-security-group-rules")
    if [[ " \$* " == *" Name=group-id,Values=sg-09af876efa8c830fb "* ]]; then
      printf 'sgr-operator-preview-app\n'
    elif [[ " \$* " == *" Name=group-id,Values=sg-004e0c14829a3228a "* ]]; then
      printf 'sgr-shared-preview-app\n'
    else
      printf '\n'
    fi
    ;;
  "ec2 revoke-security-group-ingress")
    ;;
  "rds describe-db-clusters")
    if [[ -n "$state_dir" && -f "$state_dir/shared.cluster.deletion_protection.disabled" ]]; then
      printf '{"DBClusters":[{"DBClusterIdentifier":"intents-juno-shared-preview-shared-aurora","Status":"available","DeletionProtection":false}]}\n'
    else
      printf '{"DBClusters":[{"DBClusterIdentifier":"intents-juno-shared-preview-shared-aurora","Status":"available","DeletionProtection":true}]}\n'
    fi
    ;;
  "rds modify-db-cluster")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/shared.cluster.deletion_protection.disabled"
    fi
    printf '{"DBCluster":{"DBClusterIdentifier":"intents-juno-shared-preview-shared-aurora","DeletionProtection":false}}\n'
    ;;
  "backup list-recovery-points-by-backup-vault")
    if [[ -n "$state_dir" && -f "$state_dir/backup-vault.\$backup_vault_name.cleared" ]]; then
      printf '{"RecoveryPoints":[]}\n'
    else
      printf '{"RecoveryPoints":[{"RecoveryPointArn":"arn:aws:backup:us-east-1:021490342184:recovery-point:%s-rp-1"}]}\n' "\$backup_vault_name"
    fi
    ;;
  "backup delete-recovery-point")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/backup-vault.\$backup_vault_name.cleared"
    fi
    ;;
  "s3api list-object-versions")
    if [[ -n "$state_dir" && -f "$state_dir/bucket.\$bucket_name.cleared" ]]; then
      printf '{"Versions":[],"DeleteMarkers":[]}\n'
    else
      printf '{"Versions":[{"Key":"AWSLogs/021490342184/CloudTrail/us-east-1/2026/03/21/log-1.json.gz","VersionId":"version-1"}],"DeleteMarkers":[{"Key":"AWSLogs/021490342184/CloudTrail/us-east-1/2026/03/20/log-old.json.gz","VersionId":"delete-marker-1"}]}\n'
    fi
    ;;
  "s3api delete-objects")
    if [[ -n "$state_dir" ]]; then
      mkdir -p "$state_dir"
      : >"$state_dir/bucket.\$bucket_name.cleared"
    fi
    printf '{"Deleted":[]}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_destroy_inventory_fixture() {
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
  },
  "app_role": {
    "terraform_dir": "deploy/shared/terraform/app-runtime",
    "vpc_id": "vpc-0e9830a2e4abe7118",
    "public_subnet_ids": ["subnet-0cecac94dde54efca", "subnet-03d50beebb2734da8"],
    "private_subnet_ids": ["subnet-0afebf35409cafe82", "subnet-0dfe9dd62ddea943b"],
    "app_ami_id": "ami-0123456789abcdef0",
    "app_instance_profile_name": "juno-preview-app-role",
    "public_bridge_certificate_arn": "arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview",
    "internal_backoffice_certificate_arn": "arn:aws:acm:us-east-1:021490342184:certificate/ops-preview",
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "account_id": "021490342184",
    "bridge_public_dns_label": "bridge",
    "backoffice_dns_label": "ops",
    "public_scheme": "https",
    "bridge_api_listen": "127.0.0.1:8082",
    "backoffice_listen": "127.0.0.1:8090",
    "known_hosts_file": "app/known_hosts",
    "secret_contract_file": "app/app-secrets.env",
    "service_urls": ["bridge-api=http://127.0.0.1:8082/readyz"],
    "operator_endpoints": [],
    "publish_public_dns": false
  },
  "shared_postgres_password": "preview-postgres-password",
  "contracts": {
    "base_chain_id": 84532,
    "deposit_image_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "withdraw_image_id": "0x2222222222222222222222222222222222222222222222222222222222222222"
  },
  "shared_roles": {
    "proof": {
      "requestor_address": "0x1234567890abcdef1234567890abcdef12345678",
      "requestor_secret_arn": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-requestor",
      "funder_secret_arn": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-proof-funder",
      "rpc_url": "https://rpc.mainnet.succinct.xyz",
      "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
      "image_ecr_repository_arn": "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"
    }
  },
  "wireguard_role": {
    "ami_id": "ami-0wireguardcafebeef0",
    "public_subnet_ids": ["subnet-0cecac94dde54efca", "subnet-03d50beebb2734da8"],
    "listen_port": 51820,
    "network_cidr": "10.66.0.0/24",
    "source_cidrs": ["10.0.0.0/24", "10.0.1.0/24"],
    "backoffice_hostname": "ops.preview.intents-testing.thejunowallet.com",
    "backoffice_private_endpoint_ips": ["10.0.10.10", "10.0.11.10"]
  }
}
JSON
}

write_app_deploy_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "2",
  "environment": "preview",
  "edge": {
    "enabled": true,
    "state_path": "edge-state/preview.tfstate",
    "origin_record_name": "origin.preview.intents-testing.thejunowallet.com",
    "public_lb_dns_name": "preview-bridge-123456.us-east-1.elb.amazonaws.com",
    "public_lb_zone_id": "Z35SXDOTRQ7X7K",
    "origin_http_port": 443,
    "rate_limit": 2000,
    "alarm_actions": ["arn:aws:sns:us-east-1:021490342184:runs-on-AlertTopic-yKL5sNi9ij9K"],
    "enable_shield_advanced": false
  },
  "services": {
    "bridge_api": {
      "record_name": "bridge.preview.intents-testing.thejunowallet.com"
    }
  }
}
JSON
}

test_destroy_preview_role_runtime_tears_down_edge_then_app_then_shared() {
  local tmp inventory app_deploy fake_bin tf_log aws_log edge_state cloudfront_state_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  app_deploy="$tmp/production-output/preview/app/app-deploy.json"
  edge_state="$tmp/edge-state/preview.tfstate"
  fake_bin="$tmp/bin"
  tf_log="$tmp/combined.log"
  aws_log="$tmp/combined.log"
  cloudfront_state_dir="$tmp/cloudfront"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/production-output/preview/app" "$tmp/edge-state"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$edge_state"
  write_destroy_inventory_fixture "$inventory"
  write_app_deploy_fixture "$app_deploy"
  write_fake_destroy_terraform "$fake_bin/terraform" "$tf_log" "ENKATN26PZLPX"
  write_fake_destroy_aws "$fake_bin/aws" "$aws_log" "$cloudfront_state_dir"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
      PRODUCTION_TEST_STS_REGIONAL_IPS=10.0.11.214 \
      PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_INTERVAL_SECONDS=0 \
      PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_ATTEMPTS=2 \
      bash "$REPO_ROOT/deploy/production/destroy-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --current-output-root "$tmp/production-output"
  )

  assert_line_order "$(cat "$tf_log")" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-edge" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-runtime" "preview destroy tears down edge before app runtime"
  assert_line_order "$(cat "$tf_log")" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-runtime" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/production-shared" "preview destroy tears down app runtime before shared runtime"
  assert_contains "$(cat "$tf_log")" "terraform-state $edge_state" "preview destroy uses the discovered edge state file"
  assert_contains "$(cat "$tf_log")" "terraform-var-file $tmp/preview/shared-terraform.auto.tfvars.json" "preview destroy writes shared terraform destroy vars"
  assert_contains "$(cat "$tf_log")" "terraform-var-file $tmp/preview/app-terraform.auto.tfvars.json" "preview destroy writes app terraform destroy vars"
  assert_contains "$(cat "$tf_log")" "terraform-env AWS_ENDPOINT_URL_STS=https://sts.amazonaws.com" "preview destroy forces public sts when regional sts resolves private"
  assert_contains "$(cat "$aws_log")" "aws autoscaling update-auto-scaling-group --profile juno --region us-east-1 --auto-scaling-group-name juno-app-runtime-preview-asg --min-size 0 --max-size 0 --desired-capacity 0" "preview destroy scales app runtime asg to zero before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws ec2 terminate-instances --profile juno --region us-east-1 --instance-ids i-app-a i-app-b" "preview destroy terminates app runtime instances before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws ec2 wait instance-terminated --profile juno --region us-east-1 --instance-ids i-app-a i-app-b" "preview destroy waits for app runtime instances to terminate before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws ec2 revoke-security-group-ingress --profile juno --region us-east-1 --group-id sg-09af876efa8c830fb --security-group-rule-ids sgr-operator-preview-app" "preview destroy removes operator ingress rules that still reference the app runtime security group"
  assert_contains "$(cat "$aws_log")" "aws ec2 revoke-security-group-ingress --profile juno --region us-east-1 --group-id sg-004e0c14829a3228a --security-group-rule-ids sgr-shared-preview-app" "preview destroy removes shared ingress rules that still reference the app runtime security group"
  assert_contains "$(cat "$aws_log")" "aws rds modify-db-cluster --profile juno --region us-east-1 --db-cluster-identifier intents-juno-shared-preview-shared-aurora --no-deletion-protection --apply-immediately" "preview destroy disables shared aurora deletion protection before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws backup delete-recovery-point --profile juno --region us-east-1 --backup-vault-name intents-juno-shared-preview-shared-postgres" "preview destroy deletes recovery points from the primary backup vault before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws backup delete-recovery-point --profile juno --region us-west-2 --backup-vault-name intents-juno-shared-preview-shared-postgres-dr" "preview destroy deletes recovery points from the dr backup vault before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws s3api list-object-versions --profile juno --region us-east-1 --bucket intents-juno-shared-preview-trail --output json" "preview destroy inspects the cloudtrail bucket for versioned objects before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws s3api delete-objects --profile juno --region us-east-1 --bucket intents-juno-shared-preview-trail --delete file://" "preview destroy deletes versioned cloudtrail objects before terraform destroy"
  assert_line_order "$(cat "$aws_log")" "aws autoscaling update-auto-scaling-group --profile juno --region us-east-1 --auto-scaling-group-name juno-app-runtime-preview-asg --min-size 0 --max-size 0 --desired-capacity 0" "terraform destroy -auto-approve -input=false -var-file=$tmp/preview/app-terraform.auto.tfvars.json" "preview destroy drains the app runtime asg before terraform destroy"
  assert_line_order "$(cat "$aws_log")" "aws ec2 revoke-security-group-ingress --profile juno --region us-east-1 --group-id sg-09af876efa8c830fb --security-group-rule-ids sgr-operator-preview-app" "terraform destroy -auto-approve -input=false -var-file=$tmp/preview/app-terraform.auto.tfvars.json" "preview destroy removes operator references to the app runtime security group before terraform destroy"
  assert_line_order "$(cat "$aws_log")" "aws rds modify-db-cluster --profile juno --region us-east-1 --db-cluster-identifier intents-juno-shared-preview-shared-aurora --no-deletion-protection --apply-immediately" "terraform destroy -auto-approve -input=false -var-file=$tmp/preview/shared-terraform.auto.tfvars.json" "preview destroy disables aurora deletion protection before shared terraform destroy"
  assert_line_order "$(cat "$aws_log")" "aws backup delete-recovery-point --profile juno --region us-east-1 --backup-vault-name intents-juno-shared-preview-shared-postgres" "terraform destroy -auto-approve -input=false -var-file=$tmp/preview/shared-terraform.auto.tfvars.json" "preview destroy clears backup recovery points before shared terraform destroy"
  assert_line_order "$(cat "$aws_log")" "aws s3api delete-objects --profile juno --region us-east-1 --bucket intents-juno-shared-preview-trail --delete file://" "terraform destroy -auto-approve -input=false -var-file=$tmp/preview/shared-terraform.auto.tfvars.json" "preview destroy empties the cloudtrail bucket before shared terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws cloudfront update-distribution --profile juno --id ENKATN26PZLPX" "preview destroy disables the edge cloudfront distribution before terraform destroy"
  assert_contains "$(cat "$aws_log")" "aws cloudfront delete-distribution --profile juno --id ENKATN26PZLPX" "preview destroy deletes the edge cloudfront distribution before terraform destroy"
  if [[ -f "$aws_log" ]]; then
    assert_not_contains "$(cat "$aws_log")" "sts get-caller-identity" "preview destroy derives the terraform backend account id from inventory when available"
  fi

  rm -rf "$tmp"
}

test_destroy_preview_role_runtime_discovers_app_security_group_when_output_is_missing() {
  local tmp inventory app_deploy fake_bin combined_log edge_state cloudfront_state_dir
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  app_deploy="$tmp/production-output/preview/app/app-deploy.json"
  edge_state="$tmp/edge-state/preview.tfstate"
  fake_bin="$tmp/bin"
  combined_log="$tmp/combined.log"
  cloudfront_state_dir="$tmp/cloudfront"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/production-output/preview/app" "$tmp/edge-state"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$edge_state"
  write_destroy_inventory_fixture "$inventory"
  write_app_deploy_fixture "$app_deploy"
  write_fake_destroy_terraform "$fake_bin/terraform" "$combined_log" "ENKATN26PZLPX" ""
  write_fake_destroy_aws "$fake_bin/aws" "$combined_log" "$cloudfront_state_dir"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
      PRODUCTION_TEST_STS_REGIONAL_IPS=10.0.11.214 \
      PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_INTERVAL_SECONDS=0 \
      PRODUCTION_PREVIEW_EDGE_CLOUDFRONT_POLL_ATTEMPTS=2 \
      bash "$REPO_ROOT/deploy/production/destroy-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --current-output-root "$tmp/production-output"
  )

  assert_contains "$(cat "$combined_log")" "aws ec2 describe-security-groups --profile juno --region us-east-1 --filters Name=group-name,Values=juno-app-runtime-preview-app --query SecurityGroups[].GroupId --output text" "preview destroy falls back to live app security group discovery when terraform output omits the app sg id"
  assert_contains "$(cat "$combined_log")" "aws ec2 revoke-security-group-ingress --profile juno --region us-east-1 --group-id sg-09af876efa8c830fb --security-group-rule-ids sgr-operator-preview-app" "preview destroy still revokes operator ingress rules after app security group fallback discovery"

  rm -rf "$tmp"
}

main() {
  test_destroy_preview_role_runtime_tears_down_edge_then_app_then_shared
  test_destroy_preview_role_runtime_discovers_app_security_group_when_output_is_missing
}

main "$@"
