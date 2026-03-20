#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

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
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'terraform %s\n' "\$*" >>"$log_file"
printf 'terraform-cwd %s\n' "\$PWD" >>"$log_file"
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
esac
printf 'unexpected terraform invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_destroy_aws() {
  local target="$1"
  local log_file="$2"
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
  "shared_roles": {
    "proof": {
      "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
      "image_ecr_repository_arn": "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"
    }
  },
  "wireguard_role": {
    "ami_id": "ami-0wireguardcafebeef0",
    "public_subnet_ids": ["subnet-0cecac94dde54efca", "subnet-03d50beebb2734da8"],
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
  local tmp inventory app_deploy fake_bin tf_log aws_log edge_state
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  app_deploy="$tmp/production-output/preview/app/app-deploy.json"
  edge_state="$tmp/edge-state/preview.tfstate"
  fake_bin="$tmp/bin"
  tf_log="$tmp/terraform.log"
  aws_log="$tmp/aws.log"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/production-output/preview/app" "$tmp/edge-state"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$edge_state"
  write_destroy_inventory_fixture "$inventory"
  write_app_deploy_fixture "$app_deploy"
  write_fake_destroy_terraform "$fake_bin/terraform" "$tf_log"
  write_fake_destroy_aws "$fake_bin/aws" "$aws_log"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/destroy-preview-role-runtime.sh" \
        --inventory "$inventory" \
        --current-output-root "$tmp/production-output"
  )

  assert_line_order "$(cat "$tf_log")" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-edge" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-runtime" "preview destroy tears down edge before app runtime"
  assert_line_order "$(cat "$tf_log")" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/app-runtime" "terraform-cwd $REPO_ROOT/deploy/shared/terraform/production-shared" "preview destroy tears down app runtime before shared runtime"
  assert_contains "$(cat "$tf_log")" "terraform-state $edge_state" "preview destroy uses the discovered edge state file"
  assert_contains "$(cat "$tf_log")" "terraform-var-file $tmp/preview/shared-terraform.auto.tfvars.json" "preview destroy writes shared terraform destroy vars"
  assert_contains "$(cat "$tf_log")" "terraform-var-file $tmp/preview/app-terraform.auto.tfvars.json" "preview destroy writes app terraform destroy vars"

  rm -rf "$tmp"
}

main() {
  test_destroy_preview_role_runtime_tears_down_edge_then_app_then_shared
}

main "$@"
