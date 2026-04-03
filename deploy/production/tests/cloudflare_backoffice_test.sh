#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if grep -Fq -- "$needle" <<<"$haystack"; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_cloudflare_inventory_fixture() {
  local target="$1"
  jq '
    .environment = "mainnet"
    | .shared_services.public_zone_name = "junointents.com"
    | .shared_services.public_subdomain = "junointents.com"
    | .shared_services.route53_zone_id = ""
    | .dns.mode = "external"
    | .app_role.public_endpoint = "juno-app-runtime-mainnet-bridge.example.internal"
    | .app_role.public_lb = {
        dns_name: "juno-app-runtime-mainnet-bridge.example.internal",
        zone_id: "Z35SXDOTRQ7X7K",
        security_group_id: "sg-publicbridge012345678"
      }
    | .app_role.internal_lb = {
        dns_name: "internal-ops-mainnet.example.internal",
        zone_id: "Z2P70J7EXAMPLE",
        security_group_id: "sg-internalops012345678"
      }
    | .app_role.aws_profile = "juno"
    | .app_role.aws_region = "us-east-1"
    | .app_role.account_id = "021490342184"
    | .app_role.runtime_config_secret_id = "mainnet/app/runtime-config"
    | .app_role.runtime_config_secret_region = "us-east-1"
    | .app_role.bridge_public_dns_label = "bridge"
    | .app_role.backoffice_dns_label = "ops"
    | .app_role.backoffice_access = {
        mode: "cloudflare-access",
        public_hostname: "ops.junointents.com"
      }
    | .shared_roles.proof = {
        requestor_address: "0x1234567890abcdef1234567890abcdef12345678",
        requestor_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet-proof-requestor",
        funder_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet-proof-funder",
        rpc_url: "https://rpc.mainnet.succinct.xyz",
        image_release_tag: "shared-proof-services-image-v2026.04.03-r1-mainnet",
        image_uri: "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
        image_ecr_repository_arn: "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"
      }
    | .shared_postgres_password = "postgres"
    | .shared_services.alarm_actions = ["arn:aws:sns:us-east-1:021490342184:juno-mainnet-alerts"]
    | .contracts.juno_network = "mainnet"
    | .contracts.base_rpc_url = "https://base-mainnet.example.invalid"
    | .contracts.base_chain_id = 8453
    | .contracts.bridge_guest_release_tag = "bridge-guests-v2026.04.03-r1-mainnet"
    | .contracts.deposit_image_id = "0x00b37c192d199f4a6a6303f3af0040f10d240463ebcab0966c257c13a28939aa"
    | .contracts.withdraw_image_id = "0x00e979c5a86c06a7f936c3ed32c4c03f253d44a252e1b865e87a97a18e9ea0e8"
    | .app_role.app_ami_id = "ami-0432b4571770fa599"
    | .app_role.app_instance_profile_name = "juno-app-role"
    | .app_role.public_bridge_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/public-bridge"
    | .app_role.internal_backoffice_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/internal-backoffice"
    | .operators = [
        {
          index: 1,
          operator_id: "0x1111111111111111111111111111111111111111",
          operator_address: "0x9999999999999999999999999999999999999999",
          checkpoint_signer_driver: "aws-kms",
          checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555",
          runtime_material_ref: {
            mode: "s3-kms-zip",
            bucket: "mainnet-runtime-materials",
            key: "operators/op1/runtime-material.zip",
            region: "us-east-1",
            kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
          },
          runtime_config_secret_id: "mainnet/op1/runtime-config",
          runtime_config_secret_region: "us-east-1",
          aws_profile: "mainnet-op1",
          aws_region: "us-east-1",
          account_id: "021490342184",
          operator_host: "203.0.113.11",
          public_dns_label: "op1",
          asg: "juno-op1",
          launch_template: {
            id: "lt-0123456789abcdef0",
            version: "1"
          }
        }
      ]
    | del(.shared_services.wireguard)
    | del(.shared_roles.wireguard)
    | del(.wireguard_role)
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_cloudflare_shared_manifest_fixture() {
  local target="$1"
  cat >"$target" <<'JSON'
{
  "version": "3",
  "environment": "mainnet",
  "shared_services": {
    "kafka": {
      "bootstrap_brokers": "b-1.mainnet.kafka:9098,b-2.mainnet.kafka:9098"
    },
    "ipfs": {
      "api_url": "http://shared-ipfs-mainnet.example.internal:5001"
    },
    "proof": {
      "requestor_address": "0x1234567890abcdef1234567890abcdef12345678",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  },
  "contracts": {
    "base_rpc_url": "https://base-mainnet.example.invalid",
    "base_chain_id": 8453,
    "bridge": "0x1111111111111111111111111111111111111111",
    "wjuno": "0x2222222222222222222222222222222222222222",
    "operator_registry": "0x3333333333333333333333333333333333333333",
    "bridge_params": {
      "withdrawal_expiry_window_seconds": 86400,
      "min_deposit_amount": 201005025,
      "min_withdraw_amount": 200000000,
      "fee_bps": 50
    },
    "owallet_ua": "u1mainnetexample"
  },
  "shared_roles": {
    "proof": {
      "requestor_address": "0x1234567890abcdef1234567890abcdef12345678",
      "rpc_url": "https://rpc.mainnet.succinct.xyz"
    }
  },
  "operator_roster": [],
  "wireguard_role": {}
}
JSON
}

test_production_render_app_handoff_supports_cloudflare_backoffice_access() {
  local workdir inventory shared_manifest output_dir app_manifest
  workdir="$(mktemp -d)"
  inventory="$workdir/inventory.json"
  shared_manifest="$workdir/shared-manifest.json"
  output_dir="$workdir/output"

  write_cloudflare_inventory_fixture "$inventory"
  write_cloudflare_shared_manifest_fixture "$shared_manifest"
  mkdir -p "$output_dir"

  production_render_app_handoff "$inventory" "$shared_manifest" "$output_dir" "$workdir"

  app_manifest="$output_dir/app/app-deploy.json"
  assert_eq "$(jq -r '.services.backoffice.access.mode' "$app_manifest")" "cloudflare-access" "app handoff renders cloudflare backoffice mode"
  assert_eq "$(jq -r '.services.backoffice.public_url' "$app_manifest")" "https://ops.junointents.com" "app handoff renders the cloudflare backoffice url"
  assert_eq "$(jq -r '.services.backoffice.record_name' "$app_manifest")" "ops.junointents.com" "app handoff renders the cloudflare backoffice hostname"
  assert_eq "$(jq -r '.services.backoffice.probe_url' "$app_manifest")" "http://127.0.0.1:8090" "app handoff keeps local probe url for access-protected backoffice"
  assert_eq "$(jq -r '.wireguard_role == null or (.wireguard_role | length == 0)' "$app_manifest")" "true" "app handoff does not require a wireguard role"
  rm -rf "$workdir"
}

test_production_terraform_overrides_drop_wireguard_inputs_for_cloudflare_backoffice() {
  local workdir inventory shared_override app_override
  workdir="$(mktemp -d)"
  inventory="$workdir/inventory.json"
  shared_override="$workdir/shared.auto.tfvars.json"
  app_override="$workdir/app.auto.tfvars.json"

  write_cloudflare_inventory_fixture "$inventory"

  production_write_shared_terraform_override_tfvars "$inventory" "$shared_override"
  production_write_app_terraform_override_tfvars "$inventory" "$app_override"

  assert_eq "$(jq -r '.shared_wireguard_enabled // false' "$shared_override")" "false" "shared tfvars disable the shared wireguard role"
  assert_eq "$(jq -r 'has("shared_wireguard_role_ami_id")' "$shared_override")" "false" "shared tfvars omit the wireguard ami input"
  assert_eq "$(jq -r 'has("wireguard_cidr_blocks")' "$app_override")" "false" "app tfvars no longer require wireguard cidrs"
  assert_eq "$(jq -r '.deployment_id' "$app_override")" "mainnet" "app tfvars still render the deployment id"
  rm -rf "$workdir"
}

main() {
  test_production_render_app_handoff_supports_cloudflare_backoffice_access
  test_production_terraform_overrides_drop_wireguard_inputs_for_cloudflare_backoffice
  printf 'cloudflare_backoffice_test: PASS\n'
}

main "$@"
