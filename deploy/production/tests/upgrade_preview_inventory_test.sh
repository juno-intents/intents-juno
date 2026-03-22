#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_legacy_preview_inventory() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "1",
  "environment": "preview",
  "dns": {
    "mode": "route53",
    "ttl_seconds": 60
  },
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "terraform_dir": "./legacy-live-e2e",
    "route53_zone_id": "Z01169511CVMQJAD7T3TJ",
    "public_zone_name": "thejunowallet.com",
    "public_subdomain": "preview.intents-testing.thejunowallet.com",
    "alarm_actions": [
      "arn:aws:sns:us-east-1:021490342184:runs-on-AlertTopic-yKL5sNi9ij9K"
    ]
  },
  "app_host": {
    "host": "52.203.216.157",
    "user": "ubuntu",
    "runtime_dir": "/var/lib/intents-juno/app-runtime",
    "public_endpoint": "52.203.216.157",
    "private_endpoint": "10.0.1.163",
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "account_id": "021490342184",
    "security_group_id": "sg-0aefaaf60bf10b378",
    "known_hosts_file": "app/known_hosts",
    "secret_contract_file": "app/app-secrets.env",
    "bridge_public_dns_label": "bridge",
    "ops_public_dns_label": "ops",
    "public_scheme": "https",
    "bridge_api_listen": "127.0.0.1:8082",
    "backoffice_listen": "127.0.0.1:8090",
    "juno_rpc_url": "http://10.0.0.14:18232",
    "service_urls": [
      "bridge-api=http://127.0.0.1:8082/readyz"
    ],
    "operator_endpoints": []
  },
  "contracts": {
    "base_rpc_url": "https://base-sepolia.example",
    "base_chain_id": 84532,
    "deposit_image_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "withdraw_image_id": "0x2222222222222222222222222222222222222222222222222222222222222222"
  },
  "operators": [
    {
      "index": 1,
      "operator_id": "0xfdf833a121ada10a142ef88c17cbd5af01bce2eb",
      "operator_host": "44.201.3.134",
      "operator_user": "ubuntu",
      "runtime_dir": "/var/lib/intents-juno/operator-runtime",
      "public_dns_label": "op1",
      "known_hosts_file": "operators/op1/known_hosts",
      "dkg_backup_zip": "operators/op1/dkg-backup.zip",
      "secret_contract_file": "operators/op1/operator-secrets.env"
    },
    {
      "index": 2,
      "operator_id": "0x3b63d997dae3594efdc370ae7f45005aef9c47fb",
      "operator_host": "34.207.95.248",
      "operator_user": "ubuntu",
      "runtime_dir": "/var/lib/intents-juno/operator-runtime",
      "public_dns_label": "op2",
      "known_hosts_file": "operators/op2/known_hosts",
      "dkg_backup_zip": "operators/op2/dkg-backup.zip",
      "secret_contract_file": "operators/op2/operator-secrets.env"
    }
  ]
}
JSON
}

write_legacy_state_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": 4,
  "resources": [
    {
      "type": "aws_vpc",
      "name": "selected",
      "instances": [
        {
          "attributes": {
            "id": "vpc-0e9830a2e4abe7118"
          }
        }
      ]
    },
    {
      "type": "aws_subnet",
      "name": "selected",
      "instances": [
        {
          "attributes": {
            "id": "subnet-0cecac94dde54efca",
            "cidr_block": "10.0.0.0/24",
            "availability_zone": "us-east-1a",
            "map_public_ip_on_launch": true
          }
        },
        {
          "attributes": {
            "id": "subnet-03d50beebb2734da8",
            "cidr_block": "10.0.1.0/24",
            "availability_zone": "us-east-1b",
            "map_public_ip_on_launch": true
          }
        }
      ]
    },
    {
      "type": "aws_subnet",
      "name": "shared",
      "instances": [
        {
          "attributes": {
            "id": "subnet-0afebf35409cafe82",
            "cidr_block": "10.0.10.0/24",
            "availability_zone": "us-east-1a",
            "map_public_ip_on_launch": false
          }
        },
        {
          "attributes": {
            "id": "subnet-0dfe9dd62ddea943b",
            "cidr_block": "10.0.11.0/24",
            "availability_zone": "us-east-1b",
            "map_public_ip_on_launch": false
          }
        }
      ]
    }
  ],
  "outputs": {
    "effective_instance_profile": {
      "value": "juno-live-e2e-preview0316d-instance-profile"
    },
    "shared_wireguard_client_config_secret_arn": {
      "value": "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-wireguard-client-config"
    },
    "shared_wireguard_network_cidr": {
      "value": "10.66.0.0/24"
    },
    "shared_wireguard_listen_port": {
      "value": 51820
    },
    "shared_wireguard_endpoint_host": {
      "value": "preview-wireguard.example.internal"
    }
  }
}
JSON
}

write_fake_upgrade_preview_aws() {
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
  "ec2 describe-instances --filters Name=ip-address,Values=52.203.216.157 --output json")
    cat <<'JSON'
{"Reservations":[{"Instances":[{"PublicIpAddress":"52.203.216.157","PrivateIpAddress":"10.0.1.163","IamInstanceProfile":{"Arn":"arn:aws:iam::021490342184:instance-profile/juno-live-e2e-preview0316d-instance-profile"}}]}]}
JSON
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=44.201.3.134 --output json")
    cat <<'JSON'
{"Reservations":[{"Instances":[{"PublicIpAddress":"44.201.3.134","LaunchTemplate":{"LaunchTemplateId":"lt-op1","Version":"3"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op1"}]}]}]}
JSON
    ;;
  "ec2 describe-instances --filters Name=ip-address,Values=34.207.95.248 --output json")
    cat <<'JSON'
{"Reservations":[{"Instances":[{"PublicIpAddress":"34.207.95.248","LaunchTemplate":{"LaunchTemplateId":"lt-op2","Version":"7"},"Tags":[{"Key":"aws:autoscaling:groupName","Value":"preview-op2"}]}]}]}
JSON
    ;;
  "acm list-certificates --certificate-statuses ISSUED --includes keyTypes=RSA_2048,EC_prime256v1 --output json")
    cat <<'JSON'
{"CertificateSummaryList":[
  {"CertificateArn":"arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview","DomainName":"bridge.preview.intents-testing.thejunowallet.com"},
  {"CertificateArn":"arn:aws:acm:us-east-1:021490342184:certificate/origin-preview","DomainName":"origin.preview.intents-testing.thejunowallet.com"},
  {"CertificateArn":"arn:aws:acm:us-east-1:021490342184:certificate/ops-preview","DomainName":"ops.preview.intents-testing.thejunowallet.com"}
]}
JSON
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

test_upgrade_preview_inventory_translates_legacy_preview_inputs() {
  local tmp inventory state output fake_bin aws_log
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.json"
  state="$tmp/terraform.tfstate"
  output="$tmp/inventory.upgraded.json"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/operators/op1" "$tmp/operators/op2"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$tmp/operators/op1/known_hosts"
  : >"$tmp/operators/op1/dkg-backup.zip"
  : >"$tmp/operators/op1/operator-secrets.env"
  : >"$tmp/operators/op2/known_hosts"
  : >"$tmp/operators/op2/dkg-backup.zip"
  : >"$tmp/operators/op2/operator-secrets.env"
  mkdir -p "$tmp/legacy-live-e2e"

  write_legacy_preview_inventory "$inventory"
  write_legacy_state_fixture "$state"
  write_fake_upgrade_preview_aws "$fake_bin/aws" "$aws_log"

  (
    cd "$tmp"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/upgrade-preview-inventory.sh" \
        --inventory "$inventory" \
        --legacy-state "$state" \
        --output "$output" \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet
  )

  assert_eq "$(jq -r '.app_role.terraform_dir' "$output")" "deploy/shared/terraform/app-runtime" "legacy preview upgrade sets app runtime terraform dir"
  assert_eq "$(jq -r '.shared_services.terraform_dir' "$output")" "deploy/shared/terraform/production-shared" "legacy preview upgrade switches shared terraform dir"
  assert_eq "$(jq -r '.app_role.vpc_id' "$output")" "vpc-0e9830a2e4abe7118" "legacy preview upgrade copies vpc id"
  assert_eq "$(jq -r '.app_role.public_subnet_ids[1]' "$output")" "subnet-03d50beebb2734da8" "legacy preview upgrade copies public subnet ids"
  assert_eq "$(jq -r '.app_role.private_subnet_ids[1]' "$output")" "subnet-0dfe9dd62ddea943b" "legacy preview upgrade copies private subnet ids"
  assert_eq "$(jq -r '.app_role.app_instance_profile_name' "$output")" "juno-live-e2e-preview0316d-instance-profile" "legacy preview upgrade sets app instance profile"
  assert_eq "$(jq -r '.app_role.public_bridge_certificate_arn' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/origin-preview" "legacy preview upgrade resolves the CloudFront origin cert for the public bridge listener"
  assert_eq "$(jq -r '.app_role.public_bridge_additional_certificate_arns[0]' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview" "legacy preview upgrade preserves the bridge hostname cert as an additional listener certificate"
  assert_eq "$(jq -r '.app_role.internal_backoffice_certificate_arn' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/ops-preview" "legacy preview upgrade resolves internal backoffice cert"
  assert_eq "$(jq -r '.shared_roles.proof.image_release_tag' "$output")" "shared-proof-services-image-v2026.03.20-testnet" "legacy preview upgrade patches proof image release tag"
  assert_eq "$(jq -r '.wireguard_role.ami_release_tag' "$output")" "wireguard-role-ami-v2026.03.20-testnet" "legacy preview upgrade patches wireguard ami release tag"
  assert_eq "$(jq -r '.wireguard_role.source_cidrs[0]' "$output")" "10.0.0.0/24" "legacy preview upgrade maps wireguard source cidrs from public subnets"
  assert_eq "$(jq -r '.wireguard_role.backoffice_private_endpoint_ips[0]' "$output")" "10.0.1.163" "legacy preview upgrade preserves private backoffice endpoint"
  assert_eq "$(jq -r '.operators[0].asg' "$output")" "preview-op1" "legacy preview upgrade resolves first operator asg"
  assert_eq "$(jq -r '.operators[0].launch_template.id' "$output")" "lt-op1" "legacy preview upgrade resolves first operator launch template"
  assert_contains "$(cat "$aws_log")" "acm list-certificates" "legacy preview upgrade queries ACM certificates"

  rm -rf "$tmp"
}

test_upgrade_preview_inventory_normalizes_partial_v2_preview_inputs() {
  local tmp inventory output fake_bin aws_log
  tmp="$(mktemp -d)"
  inventory="$tmp/inventory.v2.json"
  output="$tmp/inventory.upgraded.json"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"

  mkdir -p "$fake_bin" "$tmp/app" "$tmp/operators/op1" "$tmp/operators/op2"
  : >"$tmp/app/known_hosts"
  : >"$tmp/app/app-secrets.env"
  : >"$tmp/operators/op1/known_hosts"
  : >"$tmp/operators/op1/dkg-backup.zip"
  : >"$tmp/operators/op1/operator-secrets.env"
  : >"$tmp/operators/op2/known_hosts"
  : >"$tmp/operators/op2/dkg-backup.zip"
  : >"$tmp/operators/op2/operator-secrets.env"

  write_legacy_preview_inventory "$inventory"
  jq '
    .version = "2"
    | .shared_services.terraform_dir = "deploy/shared/terraform/production-shared"
    | .app_role = {
        host: .app_host.host,
        user: .app_host.user,
        runtime_dir: .app_host.runtime_dir,
        public_endpoint: .app_host.public_endpoint,
        private_endpoint: .app_host.private_endpoint,
        aws_profile: .app_host.aws_profile,
        aws_region: .app_host.aws_region,
        account_id: .app_host.account_id,
        security_group_id: .app_host.security_group_id,
        known_hosts_file: .app_host.known_hosts_file,
        secret_contract_file: .app_host.secret_contract_file,
        bridge_public_dns_label: .app_host.bridge_public_dns_label,
        backoffice_dns_label: .app_host.ops_public_dns_label,
        public_scheme: .app_host.public_scheme,
        public_bridge_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview",
        public_bridge_additional_certificate_arns: [],
        internal_backoffice_certificate_arn: "",
        bridge_api_listen: .app_host.bridge_api_listen,
        backoffice_listen: .app_host.backoffice_listen,
        juno_rpc_url: .app_host.juno_rpc_url,
        service_urls: .app_host.service_urls,
        operator_endpoints: .app_host.operator_endpoints,
        publish_public_dns: false,
        app_instance_profile_name: "juno-live-e2e-preview0316d-instance-profile"
      }
    | .shared_roles = {
        proof: {
          rpc_url: "https://rpc.mainnet.succinct.xyz",
          image_release_tag: "shared-proof-services-image-v2026.03.20-testnet"
        },
        wireguard: {
          public_subnet_id: "subnet-0cecac94dde54efca",
          public_subnet_ids: ["subnet-0cecac94dde54efca", "subnet-03d50beebb2734da8"],
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          source_cidrs: ["10.0.0.0/24", "10.0.1.0/24"],
          backoffice_hostname: "ops.preview.intents-testing.thejunowallet.com",
          backoffice_private_endpoint: .app_host.private_endpoint,
          backoffice_private_endpoint_ips: [.app_host.private_endpoint],
          client_config_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-wireguard-client-config",
          endpoint_host: "preview-wireguard.example.internal",
          peer_roster_secret_arns: [],
          server_key_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:preview-wireguard-server-key",
          publish_public_dns: false,
          ami_release_tag: "wireguard-role-ami-v2026.03.20-testnet"
        }
      }
    | .wireguard_role = .shared_roles.wireguard
    | del(.app_host)
  ' "$inventory" >"$tmp/inventory.next"
  mv "$tmp/inventory.next" "$inventory"
  write_fake_upgrade_preview_aws "$fake_bin/aws" "$aws_log"

  (
    cd "$tmp"
    TEST_AWS_LOG="$aws_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/upgrade-preview-inventory.sh" \
        --inventory "$inventory" \
        --output "$output" \
        --app-runtime-ami-release-tag app-runtime-ami-v2026.03.20-testnet \
        --shared-proof-services-image-release-tag shared-proof-services-image-v2026.03.20-testnet \
        --wireguard-role-ami-release-tag wireguard-role-ami-v2026.03.20-testnet
  )

  assert_eq "$(jq -r '.app_role.public_bridge_certificate_arn' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/origin-preview" "partial v2 preview upgrade restores the origin listener certificate"
  assert_eq "$(jq -r '.app_role.public_bridge_additional_certificate_arns[0]' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview" "partial v2 preview upgrade preserves the bridge hostname certificate"
  assert_eq "$(jq -r '.app_role.internal_backoffice_certificate_arn' "$output")" "arn:aws:acm:us-east-1:021490342184:certificate/ops-preview" "partial v2 preview upgrade restores the backoffice certificate"
  assert_contains "$(cat "$aws_log")" "acm list-certificates" "partial v2 preview upgrade queries ACM certificates"

  rm -rf "$tmp"
}

main() {
  test_upgrade_preview_inventory_translates_legacy_preview_inputs
  test_upgrade_preview_inventory_normalizes_partial_v2_preview_inputs
}

main "$@"
