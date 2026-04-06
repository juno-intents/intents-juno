#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

write_bridge_public_hostname_inventory() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg app_host "203.0.113.21" \
    '
      .environment = "mainnet"
      | .dns.mode = "external"
      | .shared_services.route53_zone_id = null
      | .shared_services.public_zone_name = "junointents.com"
      | .shared_services.public_subdomain = "junointents.com"
      | .operators[0].known_hosts_file = null
      | .operators[0].dkg_backup_zip = null
      | .operators[0].secret_contract_file = null
      | .operators[0].runtime_material_ref = {
          mode: "s3-kms-zip",
          bucket: "mainnet-runtime-materials",
          key: "operators/op1/runtime-material.zip",
          region: "us-east-1",
          kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
        }
      | .operators[0].runtime_config_secret_id = "mainnet/op1/runtime-config"
      | .operators[0].runtime_config_secret_region = "us-east-1"
      | .operators[0].operator_address = "0x9999999999999999999999999999999999999999"
      | .app_host.known_hosts_file = null
      | .app_host.secret_contract_file = null
      | .app_host.host = $app_host
      | .app_host.public_endpoint = $app_host
      | .app_host.private_endpoint = "10.0.10.21"
      | .app_host.publish_public_dns = false
      | .app_role = {
          host: $app_host,
          user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/app-runtime",
          public_endpoint: $app_host,
          private_endpoint: "10.0.10.21",
          public_lb: {
            dns_name: "bridge-mainnet-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678"
          },
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          security_group_id: "sg-0123456789abcdef0",
          runtime_config_secret_id: "mainnet/app/runtime-config",
          runtime_config_secret_region: "us-east-1",
          bridge_public_hostname: "junointents.com",
          bridge_public_dns_label: null,
          backoffice_dns_label: "ops",
          backoffice_access: {
            mode: "cloudflare-access",
            public_hostname: "ops.junointents.com"
          },
          public_scheme: "https",
          bridge_api_listen: "127.0.0.1:8082",
          backoffice_listen: "127.0.0.1:8090",
          juno_rpc_url: "http://127.0.0.1:18232",
          service_urls: ["bridge-api=http://127.0.0.1:8082/readyz"],
          operator_endpoints: [],
          public_bridge_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/origin-mainnet",
          public_bridge_additional_certificate_arns: ["arn:aws:acm:us-east-1:021490342184:certificate/apex-mainnet"],
          internal_backoffice_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/backoffice-mainnet",
          publish_public_dns: false
        }
      | .shared_roles.proof = {
          requestor_address: "0x1234567890abcdef1234567890abcdef12345678",
          requestor_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-requestor",
          funder_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-funder",
          rpc_url: "https://rpc.mainnet.succinct.xyz",
          image_uri: "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          image_ecr_repository_arn: "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services",
          image_release_tag: "shared-proof-services-image-v1.2.3-mainnet"
        }
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_render_app_handoff_supports_apex_bridge_hostname() {
  local workdir shared_manifest app_manifest
  workdir="$(mktemp -d)"
  write_bridge_public_hostname_inventory "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"

  app_manifest="$workdir/output/app/app-deploy.json"
  assert_eq "$(jq -r '.services.bridge_api.record_name' "$app_manifest")" "junointents.com" "app manifest supports apex bridge hostname"
  assert_eq "$(jq -r '.services.bridge_api.public_url' "$app_manifest")" "https://junointents.com" "app manifest public url uses apex bridge hostname"
  assert_eq "$(jq -r '.edge.origin_record_name' "$app_manifest")" "origin.junointents.com" "edge origin record stays under public subdomain"

  rm -rf "$workdir"
}

main() {
  test_render_app_handoff_supports_apex_bridge_hostname
  printf 'bridge_public_hostname_test: PASS\n'
}

main "$@"
