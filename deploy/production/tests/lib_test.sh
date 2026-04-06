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
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh "$workdir/known_hosts" \
    --arg app_kh "$workdir/app-known_hosts" \
    --arg backup "$workdir/dkg-backup.zip" \
    --arg secrets "$workdir/operator-secrets.env" \
    --arg app_secrets "$workdir/app-secrets.env" \
    --arg operator_address "0x9999999999999999999999999999999999999999" \
    --arg app_host "203.0.113.21" \
    --arg app_public_endpoint "203.0.113.21" \
    --arg app_private_endpoint "10.0.10.21" \
    --arg wireguard_public_subnet_id "subnet-0abc1234def567890" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
      | .operators[0].operator_address = $operator_address
      | .operators[0].asg = "juno-op1"
      | .operators[0].launch_template = {"id":"lt-0123456789abcdef0","version":"1"}
      | .shared_postgres_password = "postgres"
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
      | .app_host.host = $app_host
      | .app_host.public_endpoint = $app_public_endpoint
      | .app_host.private_endpoint = $app_private_endpoint
      | .app_host.publish_public_dns = false
      | .app_role = {
          host: $app_host,
          user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/app-runtime",
          terraform_dir: "deploy/shared/terraform/app-runtime",
          public_endpoint: $app_public_endpoint,
          private_endpoint: $app_private_endpoint,
          vpc_id: "vpc-0123456789abcdef0",
          public_subnet_ids: ["subnet-0apppublica", "subnet-0apppublicb"],
          private_subnet_ids: ["subnet-0appprivatea", "subnet-0appprivateb"],
          asg: "juno-app",
          launch_template: { id: "lt-0appcafebabefeed0", version: "3" },
          app_ami_id: "ami-0123456789abcdef0",
          app_instance_profile_name: "juno-app-instance-profile",
          ami_release_tag: "app-runtime-ami-v1.2.3-testnet",
          public_bridge_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/origin-preview",
          public_bridge_additional_certificate_arns: ["arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview"],
          internal_backoffice_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/ops-preview",
          public_lb: {
            dns_name: "bridge-alpha-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678"
          },
          internal_lb: {
            dns_name: "internal-ops-alpha-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z2P70J7EXAMPLE",
            security_group_id: "sg-internalops012345678"
          },
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          app_security_group_id: "sg-0123456789abcdef0",
          security_group_id: "sg-0123456789abcdef0",
          known_hosts_file: $app_kh,
          secret_contract_file: $app_secrets,
          bridge_public_dns_label: "bridge",
          backoffice_dns_label: "ops",
          public_scheme: "https",
          bridge_api_listen: "127.0.0.1:8082",
          backoffice_listen: "127.0.0.1:8090",
          juno_rpc_url: "http://127.0.0.1:18232",
          service_urls: ["bridge-api=http://127.0.0.1:8082/readyz"],
          operator_endpoints: [],
          publish_public_dns: false
        }
      | .shared_services.wireguard.public_subnet_id = $wireguard_public_subnet_id
      | .shared_roles.proof = {
          requestor_address: "0x1234567890abcdef1234567890abcdef12345678",
          requestor_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-requestor",
          funder_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-funder",
          rpc_url: "https://rpc.mainnet.succinct.xyz",
          image_uri: "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          image_ecr_repository_arn: "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services",
          image_release_tag: "shared-proof-services-image-v1.2.3-testnet"
        }
      | .shared_roles.wireguard = {
          ami_id: "ami-0wireguardcafebeef0",
          public_subnet_id: $wireguard_public_subnet_id,
          public_subnet_ids: [$wireguard_public_subnet_id],
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          backoffice_hostname: "ops.alpha.intents-testing.thejunowallet.com",
          backoffice_private_endpoint: $app_private_endpoint,
          source_cidrs: ["10.0.2.50/32"],
          client_config_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config",
          endpoint_host: "198.51.100.25",
          publish_public_dns: false
        }
      | .wireguard_role = {
          ami_id: "ami-0wireguardcafebeef0",
          public_subnet_id: $wireguard_public_subnet_id,
          public_subnet_ids: [$wireguard_public_subnet_id],
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          backoffice_hostname: "ops.alpha.intents-testing.thejunowallet.com",
          backoffice_private_endpoint: $app_private_endpoint,
          source_cidrs: ["10.0.2.50/32"],
          client_config_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config",
          endpoint_host: "198.51.100.25",
          publish_public_dns: false
        }
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_live_e2e_tfvars_fixture() {
  local target="$1"
  cat >"$target" <<'EOF'
deployment_id = "preview0316d"
allowed_ssh_cidr = "92.98.132.70/32"
ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10"
operator_ami_id = "ami-0d130f29f8f555638"

allowed_checkpoint_signer_kms_key_arns = [
  "arn:aws:kms:us-east-1:021490342184:key/0aa20bf8-bf3c-43ca-9bfe-85d964a5c3b9",
  "arn:aws:kms:us-east-1:021490342184:key/e9ac19f2-8726-417f-9dfb-97ea3e5beb5e",
  "arn:aws:kms:us-east-1:021490342184:key/d493d944-7c7c-459c-b364-88c6b1089475",
]
EOF
}

test_write_shared_terraform_override_tfvars_writes_full_production_shared_tfvars() {
  local workdir override_file
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_postgres_password = "preview-postgres-password"
    | .app_role.private_subnet_ids = ["subnet-0afebf35409cafe82", "subnet-0dfe9dd62ddea943b"]
    | .wireguard_role.public_subnet_ids = ["subnet-0cecac94dde54efca", "subnet-03d50beebb2734da8"]
    | .wireguard_role.source_cidrs = ["10.0.0.0/24", "10.0.1.0/24"]
    | .wireguard_role.backoffice_private_endpoint_ips = ["10.0.10.21", "10.0.11.21"]
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/shared-terraform.auto.tfvars.json"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"

  assert_eq "$(jq -r '.aws_region' "$override_file")" "us-east-1" "production shared tfvars include aws region"
  assert_eq "$(jq -r '.deployment_id' "$override_file")" "preview" "production shared tfvars include deployment id"
  assert_eq "$(jq -r '.vpc_id' "$override_file")" "vpc-0123456789abcdef0" "production shared tfvars include vpc id"
  assert_eq "$(jq -r '.shared_subnet_ids[0]' "$override_file")" "subnet-0afebf35409cafe82" "production shared tfvars include private shared subnet ids"
  assert_eq "$(jq -r '.shared_postgres_password' "$override_file")" "preview-postgres-password" "production shared tfvars include postgres password"
  assert_eq "$(jq -r '.shared_sp1_requestor_secret_arn' "$override_file")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-requestor" "production shared tfvars include proof requestor secret arn"
  assert_eq "$(jq -r '.shared_sp1_funder_secret_arn' "$override_file")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-funder" "production shared tfvars include proof funder secret arn"
  assert_eq "$(jq -r '.shared_base_chain_id' "$override_file")" "84532" "production shared tfvars include base chain id"
  assert_eq "$(jq -r '.shared_deposit_image_id' "$override_file")" "0x000000000000000000000000000000000000000000000000000000000000aa01" "production shared tfvars include deposit guest id"
  assert_eq "$(jq -r '.shared_withdraw_image_id' "$override_file")" "0x000000000000000000000000000000000000000000000000000000000000aa02" "production shared tfvars include withdraw guest id"
  assert_eq "$(jq -r '.shared_wireguard_backoffice_private_endpoint_ips[1]' "$override_file")" "10.0.11.21" "production shared tfvars include wireguard private backoffice ips"
  assert_eq "$(jq -r '.shared_service_client_security_group_ids[0]' "$override_file")" "sg-0123456789abcdef0" "production shared tfvars allow the app runtime sg into shared postgres and msk"
  assert_eq "$(jq -r '.shared_ipfs_client_security_group_ids[0]' "$override_file")" "sg-0123456789abcdef0" "production shared tfvars allow the app runtime sg into shared ipfs"
  rm -rf "$workdir"
}

test_write_shared_terraform_override_tfvars_includes_operator_private_network_cidrs() {
  local workdir override_file
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "mainnet"
    | .shared_postgres_password = "mainnet-postgres-password"
    | .operators[0].private_network = {
        vpc_id: "vpc-op1west2",
        vpc_cidr: "10.80.0.0/16",
        subnet_ids: ["subnet-op1a", "subnet-op1b"],
        route_table_ids: ["rtb-op1a", "rtb-op1b"],
        vpc_peering_connection_id: "pcx-op1shared",
        shared_vpc_id: "vpc-0123456789abcdef0",
        shared_vpc_cidr: "10.64.0.0/16",
        shared_route_table_ids: ["rtb-shareda", "rtb-sharedb"]
      }
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/shared-terraform.auto.tfvars.json"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"

  assert_eq "$(jq -r '.shared_service_client_cidr_blocks[0]' "$override_file")" "10.80.0.0/16" "production shared tfvars allow operator VPC cidrs into shared postgres and msk"
  assert_eq "$(jq -r '.shared_ipfs_client_cidr_blocks[0]' "$override_file")" "10.80.0.0/16" "production shared tfvars allow operator VPC cidrs into shared ipfs"
  rm -rf "$workdir"
}

write_terraform_tfvars_fixture() {
  local terraform_dir="$1"
  mkdir -p "$terraform_dir"
  cat >"$terraform_dir/terraform.tfvars" <<'EOF'
shared_postgres_user = "postgres"
shared_postgres_password = "postgres"
shared_postgres_db = "intents_e2e"
shared_postgres_port = 5432
EOF
}

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  local first_balance_wei="${3:-1300000000000000}"
  local second_balance_wei="${4:-$first_balance_wei}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  case "\$4" in
    0x1111111111111111111111111111111111111111111111111111111111111111)
      printf '0xd68c28F414B210a6C519D05159014378A5b8Bc0F\n'
      ;;
    0x2222222222222222222222222222222222222222222222222222222222222222)
      printf '0x2222222222222222222222222222222222222222\n'
      ;;
    *)
      printf 'unexpected private key: %s\n' "\$4" >&2
      exit 1
      ;;
  esac
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  case "\${@: -1}" in
    0xd68c28F414B210a6C519D05159014378A5b8Bc0F)
      printf '%s\n' "$first_balance_wei"
      ;;
    0x2222222222222222222222222222222222222222)
      printf '%s\n' "$second_balance_wei"
      ;;
    *)
      printf 'unexpected balance address: %s\n' "\${@: -1}" >&2
      exit 1
      ;;
  esac
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_checkpoint_signer_kms_provisioner() {
  local target="$1"
  local log_file="$2"
  local provisioned_key_arn="${3:-arn:aws:kms:us-east-1:021490342184:key/provisioned}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'checkpoint-kms-provisioner %s\n' "\$*" >>"$log_file"
key_arn="$provisioned_key_arn"
alias_name=""
operator_address=""
reused=false
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --operator-address)
      operator_address="\$2"
      shift 2
      ;;
    --alias-name)
      alias_name="\$2"
      shift 2
      ;;
    --key-id)
      key_arn="\$2"
      reused=true
      shift 2
      ;;
    --operator-id|--aws-profile|--aws-region|--account-id|--private-key|--description)
      shift 2
      ;;
    *)
      printf 'unexpected checkpoint kms provisioner arg: %s\n' "\$1" >&2
      exit 1
      ;;
  esac
done
printf '{"keyId":"%s","keyArn":"%s","aliasName":"%s","operatorAddress":"%s","reused":%s}\n' \
  "\${key_arn##*/}" \
  "\$key_arn" \
  "\$alias_name" \
  "\$operator_address" \
  "\$reused"
EOF
  chmod +x "$target"
}

write_fake_aws_secret_reader() {
  local target="$1"
  local expected_secret_arn="$2"
  local secret_value="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=( "\$@" )
for ((i=0; i<\${#args[@]}; i++)); do
  if [[ "\${args[\$i]}" == "secretsmanager" && \$((i + 1)) -lt \${#args[@]} && "\${args[\$((i + 1))]}" == "get-secret-value" ]]; then
    secret_arn=""
    for ((j=0; j<\${#args[@]}; j++)); do
      if [[ "\${args[\$j]}" == "--secret-id" && \$((j + 1)) -lt \${#args[@]} ]]; then
        secret_arn="\${args[\$((j + 1))]}"
        break
      fi
    done
    [[ "\$secret_arn" == "$expected_secret_arn" ]] || {
      printf 'unexpected secret id: %s\n' "\$secret_arn" >&2
      exit 1
    }
    printf '%s\n' "$secret_value"
    exit 0
  fi
done
printf 'unexpected aws invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_aws_vpc_endpoint_describer() {
  local target="$1"
  shift
  local services_json='{"VpcEndpoints":[]}'
  local spec service state

  if [[ "$#" -gt 0 ]]; then
    services_json="$(
      for spec in "$@"; do
        service="${spec%%:*}"
        state="${spec#*:}"
        if [[ "$state" == "$spec" ]]; then
          state="available"
        fi
        jq -cn --arg service "$service" --arg state "$state" '{ServiceName: $service, State: $state}'
      done | jq -s '{VpcEndpoints: .}'
    )"
  fi

  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=( "\$@" )
while [[ \${#args[@]} -gt 0 ]]; do
  case "\${args[0]}" in
    --profile|--region)
      args=( "\${args[@]:2}" )
      ;;
    *)
      break
      ;;
  esac
done
case "\${args[0]:-} \${args[1]:-}" in
  "ec2 describe-vpc-endpoints")
    if [[ " \$* " == *" Name=state,Values="* ]]; then
      printf 'unexpected state filter: %s\n' "\$*" >&2
      exit 1
    fi
    printf '%s\n' '$services_json'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_aws_live_e2e_describer() {
  local target="$1"
  shift
  local services_json='{"VpcEndpoints":[]}'
  local kms_aliases_json='{}'
  local launch_templates_json='{}'
  local mode="vpc"
  local spec service state alias_name arn launch_template_spec image_id

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --kms)
        mode="kms"
        shift
        continue
        ;;
      --lt)
        mode="lt"
        shift
        continue
        ;;
    esac
    if [[ "$mode" == "vpc" ]]; then
      service="${1%%:*}"
      state="${1#*:}"
      if [[ "$state" == "$1" ]]; then
        state="available"
      fi
      services_json="$(
        {
          printf '%s\n' "$services_json" | jq -c '.VpcEndpoints[]?'
          jq -cn --arg service "$service" --arg state "$state" '{ServiceName: $service, State: $state}'
        } | jq -s '{VpcEndpoints: .}'
      )"
    elif [[ "$mode" == "kms" ]]; then
      alias_name="${1%%=*}"
      arn="${1#*=}"
      kms_aliases_json="$(
        jq -cn \
          --argjson current "$kms_aliases_json" \
          --arg alias_name "$alias_name" \
          --arg arn "$arn" \
          '$current + {($alias_name): $arn}'
      )"
    else
      launch_template_spec="${1%%=*}"
      image_id="${1#*=}"
      launch_templates_json="$(
        jq -cn \
          --argjson current "$launch_templates_json" \
          --arg launch_template_spec "$launch_template_spec" \
          --arg image_id "$image_id" \
          '$current + {($launch_template_spec): $image_id}'
      )"
    fi
    shift
  done

  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=( "\$@" )
while [[ \${#args[@]} -gt 0 ]]; do
  case "\${args[0]}" in
    --profile|--region)
      args=( "\${args[@]:2}" )
      ;;
    *)
      break
      ;;
  esac
done
case "\${args[0]:-} \${args[1]:-}" in
  "ec2 describe-vpc-endpoints")
    if [[ " \$* " == *" Name=state,Values="* ]]; then
      printf 'unexpected state filter: %s\n' "\$*" >&2
      exit 1
    fi
    printf '%s\n' '$services_json'
    ;;
  "kms describe-key")
    key_id=""
    idx=2
    while [[ \$idx -lt \${#args[@]} ]]; do
      case "\${args[\$idx]}" in
        --key-id)
          key_id="\${args[\$((idx + 1))]}"
          idx=\$((idx + 2))
          ;;
        *)
          idx=\$((idx + 1))
          ;;
      esac
    done
    arn="\$(jq -r --arg key_id "\$key_id" '.[\$key_id] // empty' <<<'$kms_aliases_json')"
    [[ -n "\$arn" ]] || {
      printf 'unexpected kms key id: %s\n' "\$key_id" >&2
      exit 1
    }
    printf '%s\n' "\$arn"
    ;;
  "ec2 describe-launch-template-versions")
    launch_template_id=""
    launch_template_version=""
    idx=2
    while [[ \$idx -lt \${#args[@]} ]]; do
      case "\${args[\$idx]}" in
        --launch-template-id)
          launch_template_id="\${args[\$((idx + 1))]}"
          idx=\$((idx + 2))
          ;;
        --versions)
          launch_template_version="\${args[\$((idx + 1))]}"
          idx=\$((idx + 2))
          ;;
        *)
          idx=\$((idx + 1))
          ;;
      esac
    done
    image_id="\$(jq -r --arg spec "\${launch_template_id}@\${launch_template_version}" '.[\$spec] // empty' <<<'$launch_templates_json')"
    [[ -n "\$image_id" ]] || {
      printf 'unexpected launch template lookup: %s@%s\n' "\$launch_template_id" "\$launch_template_version" >&2
      exit 1
    }
    jq -cn --arg image_id "\$image_id" '{LaunchTemplateVersions: [{LaunchTemplateData: {ImageId: \$image_id}}]}'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

write_fake_docker_runner() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "\$*" >>"$log_file"
args=( "\$@" )
idx=0
if [[ "\${args[0]:-}" == "run" ]]; then
  idx=1
fi
while [[ \$idx -lt \${#args[@]} ]]; do
  case "\${args[\$idx]}" in
    --rm)
      idx=\$((idx + 1))
      ;;
    --platform|--user|-v|-w)
      idx=\$((idx + 2))
      ;;
    *)
      printf 'image=%s\n' "\${args[\$idx]}" >>"$log_file"
      idx=\$((idx + 1))
      break
      ;;
  esac
done
"\${args[@]:\$idx}"
EOF
  chmod +x "$target"
}

setup_default_checkpoint_signer_kms_provisioner() {
  local workdir fake_bin fake_log
  workdir="$(mktemp -d)"
  fake_bin="$workdir/fake-checkpoint-kms-provisioner.sh"
  fake_log="$workdir/checkpoint-kms-provisioner.log"
  write_fake_checkpoint_signer_kms_provisioner "$fake_bin" "$fake_log"
  export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$fake_bin"
  export TEST_DEFAULT_CHECKPOINT_SIGNER_KMS_PROVISIONER_DIR="$workdir"
}

cleanup_default_checkpoint_signer_kms_provisioner() {
  if [[ -n "${TEST_DEFAULT_CHECKPOINT_SIGNER_KMS_PROVISIONER_DIR:-}" ]]; then
    rm -rf "$TEST_DEFAULT_CHECKPOINT_SIGNER_KMS_PROVISIONER_DIR"
    unset TEST_DEFAULT_CHECKPOINT_SIGNER_KMS_PROVISIONER_DIR
  fi
  unset PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN
}

test_render_operator_handoffs_preserves_dkg_tls_dir() {
  local workdir shared_manifest handoff_dir rendered_backup admin_config_path bundled_fingerprint shared_fingerprint
  workdir="$(mktemp -d)"
  write_test_dkg_tls_dir "$workdir/source-dkg-tls"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip" "$workdir/source-dkg-tls"
  write_test_dkg_tls_dir "$workdir/dkg-tls"
  rm -f "$workdir/dkg-tls/server.pem" "$workdir/dkg-tls/server.key"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >>"$workdir/operator-secrets.env" <<'EOF'
JUNO_RPC_BIND=literal:0.0.0.0
JUNO_RPC_ALLOW_IPS=literal:127.0.0.1,10.0.0.5
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_eq "$(jq -r '.dkg_tls_dir' "$handoff_dir/operator-deploy.json")" "$workdir/dkg-tls" "operator deploy preserves dkg tls dir"
  assert_eq "$(jq -r '.dkg_backup_zip' "$handoff_dir/operator-deploy.json")" "$handoff_dir/dkg-backup.zip" "operator deploy rewrites backup package into the handoff dir"
  assert_file_exists "$handoff_dir/dkg-backup.zip" "operator handoff renders a local backup package"
  shared_fingerprint="$(test_certificate_sha256_hex "$workdir/dkg-tls/coordinator-client.pem")"
  bundled_fingerprint="$(unzip -p "$handoff_dir/dkg-backup.zip" payload/tls/coordinator-client.pem | openssl x509 -inform PEM -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
  assert_eq "$bundled_fingerprint" "$shared_fingerprint" "rendered backup package uses the shared coordinator client cert"
  admin_config_path="$workdir/rendered-admin-config.json"
  unzip -p "$handoff_dir/dkg-backup.zip" payload/admin-config.json >"$admin_config_path"
  assert_eq "$(jq -r '.grpc.coordinator_client_cert_sha256' "$admin_config_path")" "$shared_fingerprint" "rendered backup admin-config matches the shared coordinator cert fingerprint"
  rm -rf "$workdir"
}

write_dkg_summary_with_operator_key() {
  local target="$1"
  local operator_key_file="$2"
  jq \
    --arg operator_key_file "$operator_key_file" \
    '
      .operators[0].operator_key_file = $operator_key_file
    ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$target"
}

test_resolve_secret_contract_allows_alpha_literals() {
  local workdir inventory resolved file_secret
  workdir="$(mktemp -d)"
  file_secret="$workdir/secret.txt"
  printf 'from-file' >"$file_secret"
  export TEST_ENV_SECRET="from-env"
  cat >"$workdir/operator-secrets.env" <<EOF
JUNO_RPC_USER=literal:testuser
JUNO_RPC_PASS=file:$file_secret
JUNO_SCAN_BEARER_TOKEN=env:TEST_ENV_SECRET
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  resolved="$workdir/resolved.env"
  production_resolve_secret_contract "$workdir/operator-secrets.env" "true" "" "" "$resolved"
  assert_contains "$(cat "$resolved")" "JUNO_RPC_USER=testuser" "literal resolver"
  assert_contains "$(cat "$resolved")" "JUNO_RPC_PASS=from-file" "file resolver"
  assert_contains "$(cat "$resolved")" "JUNO_SCAN_BEARER_TOKEN=from-env" "env resolver"
  rm -rf "$workdir"
}

test_resolve_secret_contract_rejects_literals_outside_alpha() {
  local workdir
  workdir="$(mktemp -d)"
  cat >"$workdir/operator-secrets.env" <<'EOF'
JUNO_RPC_USER=literal:testuser
EOF
  if (production_resolve_secret_contract "$workdir/operator-secrets.env" "false" "" "" "$workdir/resolved.env") >/dev/null 2>&1; then
    printf 'expected production_resolve_secret_contract to reject literal resolver outside alpha\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_and_handoffs() {
  local workdir inventory shared_manifest handoff_dir dkg_summary tf_json
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  printf 'secret' >"$workdir/secret.txt"
  cat >"$workdir/op1.key" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cat >"$workdir/op2.key" <<'EOF'
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  cat >"$workdir/op3.key" <<'EOF'
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >>"$workdir/operator-secrets.env" <<'EOF'
JUNO_RPC_BIND=literal:0.0.0.0
JUNO_RPC_ALLOW_IPS=literal:127.0.0.1,10.0.0.5
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
    | .operators[0].checkpoint_blob_sse_kms_key_id = "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  jq '
    .operators[0].operator_key_file = "op1.key"
    | .operators[1].operator_key_file = "op2.key"
    | .operators[2].operator_key_file = "op3.key"
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"
  tf_json="$workdir/terraform-output.json"
  jq '
    .shared_ecs_cluster_arn = {
      value: "arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared"
    }
    | .shared_proof_requestor_service_name = {
      value: "alpha-proof-requestor"
    }
    | .shared_proof_funder_service_name = {
      value: "alpha-proof-funder"
    }
    | .shared_proof_role = {
        value: {
          asg: "alpha-proof-role",
          launch_template: { id: "lt-proof0123456789abcdef", version: "7" },
          requestor_address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
          rpc_url: "https://rpc.role.mainnet.succinct.xyz"
        }
      }
    | .shared_wireguard_role = {
        value: {
          asg: "alpha-wireguard-role",
          launch_template: { id: "lt-wireguard0123456789ab", version: "11" },
          endpoint_host: "nlb-alpha-wireguard.example.internal",
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          source_cidrs: ["10.0.20.0/24", "10.0.21.0/24"],
          peer_roster_secret_arns: [
            "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-peer-ops-laptop",
            "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-peer-ops-phone"
          ],
          server_key_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key"
        }
      }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  assert_eq "$(jq -r '.contracts.juno_network' "$shared_manifest")" "testnet" "juno network"
  assert_eq "$(jq -r '.contracts.bridge' "$shared_manifest")" "0x2222222222222222222222222222222222222222" "bridge address"
  assert_eq "$(jq -r '.contracts.base_event_scanner_start_block' "$shared_manifest")" "12345" "base event scanner start block"
  assert_eq "$(jq -r '.contracts.bridge_params.fee_bps' "$shared_manifest")" "50" "bridge fee bps"
  assert_eq "$(jq -r '.contracts.bridge_params.relayer_tip_bps' "$shared_manifest")" "1000" "bridge relayer tip bps"
  assert_eq "$(jq -r '.contracts.bridge_params.withdrawal_expiry_window_seconds' "$shared_manifest")" "86400" "bridge withdrawal expiry window"
  assert_eq "$(jq -r '.contracts.bridge_params.max_expiry_extension_seconds' "$shared_manifest")" "43200" "bridge max expiry extension"
  assert_eq "$(jq -r '.contracts.bridge_params.min_deposit_amount' "$shared_manifest")" "201005025" "bridge min deposit amount"
  assert_eq "$(jq -r '.contracts.bridge_params.min_withdraw_amount' "$shared_manifest")" "200000000" "bridge min withdraw amount"
  assert_eq "$(jq -r '.version' "$shared_manifest")" "2" "shared manifest version"
  assert_eq "$(jq -r '.shared_roles.proof.requestor_address' "$shared_manifest")" "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" "shared roles proof requestor address"
  assert_eq "$(jq -r '.shared_roles.proof.rpc_url' "$shared_manifest")" "https://rpc.role.mainnet.succinct.xyz" "shared roles proof rpc url"
  assert_eq "$(jq -r '.shared_roles.wireguard.backoffice_private_endpoint' "$shared_manifest")" "10.0.10.21" "shared roles wireguard backoffice endpoint"
  assert_eq "$(jq -r '.wireguard_role.publish_public_dns' "$shared_manifest")" "false" "wireguard role suppresses public dns"
  assert_eq "$(jq -r '.shared_services.postgres.cluster_arn' "$shared_manifest")" "arn:aws:rds:us-east-1:021490342184:cluster:alpha-shared" "postgres cluster arn"
  assert_eq "$(jq -r '.shared_services.kafka.cluster_arn' "$shared_manifest")" "arn:aws:kafka:us-east-1:021490342184:cluster/alpha-shared/11111111-2222-3333-4444-555555555555-1" "kafka cluster arn"
  assert_eq "$(jq -r '.shared_services.ecs.cluster_arn' "$shared_manifest")" "arn:aws:ecs:us-east-1:021490342184:cluster/alpha-shared" "ecs cluster arn"
  assert_eq "$(jq -r '.shared_services.ecs.proof_requestor_service_name' "$shared_manifest")" "alpha-proof-requestor" "ecs proof requestor service name"
  assert_eq "$(jq -r '.shared_services.ecs.proof_funder_service_name' "$shared_manifest")" "alpha-proof-funder" "ecs proof funder service name"
  assert_eq "$(jq -r '.shared_services.ipfs.target_group_arn' "$shared_manifest")" "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/alpha-ipfs-api/1111111111111111" "ipfs target group arn"
  assert_eq "$(jq -r '.shared_roles.proof.asg' "$shared_manifest")" "alpha-proof-role" "proof role asg"
  assert_eq "$(jq -r '.shared_roles.proof.launch_template.id' "$shared_manifest")" "lt-proof0123456789abcdef" "proof role launch template"
  assert_eq "$(jq -r '.wireguard_role.asg' "$shared_manifest")" "alpha-wireguard-role" "wireguard role asg"
  assert_eq "$(jq -r '.wireguard_role.launch_template.id' "$shared_manifest")" "lt-wireguard0123456789ab" "wireguard role launch template"
  assert_eq "$(jq -r '.wireguard_role.source_cidrs[0]' "$shared_manifest")" "10.0.20.0/24" "wireguard source cidrs"
  assert_eq "$(jq -r '.shared_services.artifacts.checkpoint_blob_sse_kms_key_id' "$shared_manifest")" "arn:aws:kms:us-east-1:021490342184:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" "shared manifest checkpoint blob sse kms key id"
  assert_eq "$(jq -r '.checkpoint.threshold' "$shared_manifest")" "3" "checkpoint threshold"
  assert_contains "$(jq -cr '.secret_reference_names' "$shared_manifest")" "CHECKPOINT_POSTGRES_DSN" "secret keys"
  assert_eq "$(jq -r '.governance.timelock.address' "$shared_manifest")" "0x8888888888888888888888888888888888888888" "timelock address"
  assert_eq "$(jq -r '.governance.timelock.min_delay_seconds' "$shared_manifest")" "172800" "timelock delay"

  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$dkg_summary" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_file_exists "$handoff_dir/operator-deploy.json" "operator manifest"
  assert_file_exists "$handoff_dir/operator-secrets.env" "secret contract copy"
  assert_file_exists "$handoff_dir/known_hosts" "known_hosts copy"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "handoff injects the operator-scoped withdraw signer key"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "handoff preserves the full withdraw extend signer roster"
  assert_eq "$(jq -r '.operator_address' "$handoff_dir/operator-deploy.json")" "0x9999999999999999999999999999999999999999" "handoff operator address"
  assert_eq "$(jq -r '.checkpoint_signer_driver' "$handoff_dir/operator-deploy.json")" "aws-kms" "handoff signer driver"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$handoff_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "handoff signer kms key id"
  assert_eq "$(jq -r '.checkpoint_blob_bucket' "$handoff_dir/operator-deploy.json")" "alpha-op1-dkg-keypackages" "handoff checkpoint blob bucket"
  assert_eq "$(jq -r '.checkpoint_blob_prefix' "$handoff_dir/operator-deploy.json")" "operators/op1/checkpoint-packages" "handoff checkpoint blob prefix"
  assert_eq "$(jq -r '.checkpoint_blob_sse_kms_key_id' "$handoff_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff" "handoff checkpoint blob sse kms key id"
  assert_eq "$(jq -r '.version' "$handoff_dir/operator-deploy.json")" "2" "operator handoff version"
  assert_eq "$(jq -r '.operator_role.asg' "$handoff_dir/operator-deploy.json")" "juno-op1" "operator handoff asg"
  assert_eq "$(jq -r '.current_operator_id // ""' "$workdir/output/rollout-state.json")" "" "initial rollout state"
  assert_eq "$(jq -r '.operator_endpoints[0]' "$workdir/output/app/app-deploy.json")" "0x9999999999999999999999999999999999999999=203.0.113.11:18443" "app handoff derives operator endpoint probes"
  assert_eq "$(jq -r '.version' "$workdir/output/app/app-deploy.json")" "2" "app handoff version"
  assert_eq "$(jq -r '.services.backoffice.access.publish_public_dns' "$workdir/output/app/app-deploy.json")" "false" "app handoff suppresses public backoffice dns"
  assert_eq "$(jq -r '.services.backoffice.public_url // empty' "$workdir/output/app/app-deploy.json")" "" "app handoff omits backoffice public url"
  assert_eq "$(jq -r '.services.backoffice.record_name // empty' "$workdir/output/app/app-deploy.json")" "" "app handoff omits backoffice record name"
  rm -rf "$workdir"
}

test_render_shared_manifest_prefers_role_outputs_for_shared_proof_and_wireguard() {
  local workdir shared_manifest app_manifest tf_json
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  tf_json="$workdir/terraform-output.json"
  jq '
    .shared_ecs_cluster_arn = { value: "arn:aws:ecs:us-east-1:021490342184:cluster/legacy-shared" }
    | .shared_proof_requestor_service_name = { value: "legacy-proof-requestor" }
    | .shared_proof_funder_service_name = { value: "legacy-proof-funder" }
    | .shared_proof_role = {
        value: {
          asg: "alpha-proof-role",
          launch_template: { id: "lt-proof0123456789abcdef", version: "7" },
          requestor_address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
          rpc_url: "https://rpc.role.mainnet.succinct.xyz"
        }
      }
    | .shared_wireguard_role = {
        value: {
          asg: "alpha-wireguard-role",
          launch_template: { id: "lt-wireguard0123456789ab", version: "11" },
          endpoint_host: "nlb-alpha-wireguard.example.internal",
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          source_cidrs: ["10.0.20.0/24", "10.0.21.0/24"],
          peer_roster_secret_arns: [
            "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-peer-ops-laptop",
            "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-peer-ops-phone"
          ],
          server_key_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key"
        }
      }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  assert_eq "$(jq -r '.shared_roles.proof.asg' "$shared_manifest")" "alpha-proof-role" "shared manifest prefers proof role asg"
  assert_eq "$(jq -r '.shared_roles.proof.launch_template.id' "$shared_manifest")" "lt-proof0123456789abcdef" "shared manifest prefers proof role launch template"
  assert_eq "$(jq -r '.shared_roles.proof.requestor_address' "$shared_manifest")" "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" "shared manifest prefers proof role requestor"
  assert_eq "$(jq -r '.shared_services.ecs.cluster_arn' "$shared_manifest")" "arn:aws:ecs:us-east-1:021490342184:cluster/legacy-shared" "shared manifest retains ecs cluster arn"
  assert_eq "$(jq -r '.shared_services.ecs.proof_requestor_service_name' "$shared_manifest")" "legacy-proof-requestor" "shared manifest retains proof requestor service"
  assert_eq "$(jq -r '.shared_services.ecs.proof_funder_service_name' "$shared_manifest")" "legacy-proof-funder" "shared manifest retains proof funder service"
  assert_eq "$(jq -r '.wireguard_role.asg' "$shared_manifest")" "alpha-wireguard-role" "shared manifest prefers wireguard role asg"
  assert_eq "$(jq -r '.wireguard_role.server_key_secret_arn' "$shared_manifest")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key" "shared manifest includes wireguard server key secret"
  assert_eq "$(jq -r '.wireguard_role.endpoint_host' "$shared_manifest")" "nlb-alpha-wireguard.example.internal" "shared manifest prefers wireguard nlb endpoint"
  assert_eq "$(jq -r '.wireguard_role.source_cidrs[0]' "$shared_manifest")" "10.0.20.0/24" "shared manifest exposes wireguard source cidrs"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[0]' "$app_manifest")" "10.0.20.0/24" "app handoff uses wireguard role source cidr"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[1]' "$app_manifest")" "10.0.21.0/24" "app handoff uses all wireguard role source cidrs"
  rm -rf "$workdir"
}

test_render_operator_stack_env_prefers_operator_checkpoint_blob_storage() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
    | .operators[0].checkpoint_blob_sse_kms_key_id = "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "operator env prefers operator checkpoint bucket"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_PREFIX=operators/op1/checkpoint-packages" "operator env prefers operator checkpoint prefix"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_SSE_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff" "operator env prefers operator checkpoint blob sse kms key id"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_BUCKET=alpha-dkg-keypackages" "operator env does not fall back to shared checkpoint bucket when operator bucket is set"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_PREFIX=dkg/keypackages" "operator env does not fall back to shared checkpoint prefix when operator prefix is set"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_SSE_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" "operator env does not fall back to shared checkpoint blob sse kms key id when operator key is set"
  rm -rf "$workdir"
}

test_render_operator_stack_env_retargets_runtime_values_from_shared_manifest() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://operator:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
CHECKPOINT_BLOB_BUCKET=literal:stale-checkpoint-bucket
WITHDRAW_BLOB_BUCKET=literal:stale-withdraw-bucket
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://app:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
    | .operators[0].checkpoint_blob_sse_kms_key_id = "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "CHECKPOINT_POSTGRES_DSN=postgres://operator:pw@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents?sslmode=require" "operator env retargets postgres dsn to the shared manifest endpoint"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "operator env keeps the current deployment checkpoint bucket"
  assert_contains "$(cat "$output_env")" "WITHDRAW_BLOB_BUCKET=alpha-op1-dkg-keypackages" "operator env derives withdraw blob bucket from the current deployment artifact bucket"
  assert_not_contains "$(cat "$output_env")" "old-preview.cluster.example.internal" "operator env drops stale secret-contract postgres hosts"
  assert_not_contains "$(cat "$output_env")" "stale-withdraw-bucket" "operator env drops stale secret-contract withdraw buckets"
  rm -rf "$workdir"
}

test_render_operator_handoffs_refreshes_deployment_bound_secret_contracts() {
  local workdir shared_manifest handoff_dir rendered_secrets
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://operator:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
CHECKPOINT_BLOB_BUCKET=literal:stale-checkpoint-bucket
WITHDRAW_BLOB_BUCKET=literal:stale-withdraw-bucket
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_terraform_tfvars_fixture "$workdir/terraform"
  jq --arg terraform_dir "$workdir/terraform" '
    .shared_services.terraform_dir = $terraform_dir
    | .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
    | .operators[0].checkpoint_blob_sse_kms_key_id = "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  rendered_secrets="$handoff_dir/operator-secrets.env"

  assert_contains "$(cat "$rendered_secrets")" "CHECKPOINT_POSTGRES_DSN=literal:postgres://postgres:postgres@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents_e2e?sslmode=require" "operator handoff retargets postgres dsn to current deployment settings"
  assert_contains "$(cat "$rendered_secrets")" "CHECKPOINT_BLOB_BUCKET=literal:alpha-op1-dkg-keypackages" "operator handoff refreshes checkpoint blob bucket"
  assert_contains "$(cat "$rendered_secrets")" "WITHDRAW_BLOB_BUCKET=literal:alpha-op1-dkg-keypackages" "operator handoff refreshes withdraw blob bucket"
  assert_not_contains "$(cat "$rendered_secrets")" "old-preview.cluster.example.internal" "operator handoff drops stale postgres hosts"
  assert_not_contains "$(cat "$rendered_secrets")" "stale-withdraw-bucket" "operator handoff drops stale withdraw bucket"
  rm -rf "$workdir"
}

test_render_app_handoff_refreshes_deployment_bound_secret_contracts() {
  local workdir shared_manifest rendered_secrets
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
APP_POSTGRES_DSN=literal:postgres://app:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
CHECKPOINT_POSTGRES_DSN=literal:postgres://app:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_terraform_tfvars_fixture "$workdir/terraform"
  jq --arg terraform_dir "$workdir/terraform" '.shared_services.terraform_dir = $terraform_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  rendered_secrets="$workdir/output/app/app-secrets.env"

  assert_contains "$(cat "$rendered_secrets")" "APP_POSTGRES_DSN=literal:postgres://postgres:postgres@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents_e2e?sslmode=require" "app handoff refreshes app postgres dsn"
  assert_contains "$(cat "$rendered_secrets")" "CHECKPOINT_POSTGRES_DSN=literal:postgres://postgres:postgres@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents_e2e?sslmode=require" "app handoff refreshes fallback postgres dsn"
  assert_not_contains "$(cat "$rendered_secrets")" "old-preview.cluster.example.internal" "app handoff drops stale postgres hosts"
  rm -rf "$workdir"
}

test_render_shared_manifest_synthesizes_legacy_wireguard_peer_roster_from_client_config_secret() {
  local workdir shared_manifest tf_json
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  tf_json="$workdir/terraform-output.json"
  jq '
    .shared_proof_role = {
        value: {
          asg: "alpha-proof-role",
          launch_template: { id: "lt-proof0123456789abcdef", version: "7" },
          requestor_address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
          rpc_url: "https://rpc.role.mainnet.succinct.xyz"
        }
      }
    | .shared_wireguard_role = {
        value: {
          asg: "alpha-wireguard-role",
          launch_template: { id: "lt-wireguard0123456789ab", version: "11" },
          endpoint_host: "nlb-alpha-wireguard.example.internal",
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          source_cidrs: ["10.0.20.0/24", "10.0.21.0/24"],
          server_key_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key"
        }
      }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"

  assert_eq "$(jq -r '.wireguard_role.client_config_secret_arn' "$shared_manifest")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config" "shared manifest preserves legacy wireguard client config secret"
  assert_eq "$(jq -r '.wireguard_role.peer_roster_secret_arns[0]' "$shared_manifest")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config" "shared manifest synthesizes a legacy wireguard peer roster entry"
  assert_eq "$(jq -r '.wireguard_role.peer_config_secret_arns.preview_legacy' "$shared_manifest")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config" "shared manifest synthesizes a named legacy wireguard peer mapping"
  assert_eq "$(jq -r '.shared_roles.wireguard.peer_roster_secret_arns[0]' "$shared_manifest")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config" "shared roles wireguard keeps the synthesized legacy peer roster entry"

  rm -rf "$workdir"
}

test_render_shared_manifest_derives_base_event_scanner_start_block_from_transactions() {
  local workdir shared_manifest bridge_summary old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  bridge_summary="$workdir/bridge-summary.json"
  jq '
    del(.base_event_scanner_start_block)
    | .transactions = {
        set_fee_distributor: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        set_threshold: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        set_bridge_wjuno: "",
        set_bridge_fees: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" >"$bridge_summary"

  mkdir -p "$workdir/bin"
  cat >"$workdir/bin/cast" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
tx_hash="$2"
case "$tx_hash" in
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) printf '11111\n' ;;
  0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) printf '22222\n' ;;
  0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc) printf '33333\n' ;;
  *) printf 'unexpected tx hash: %s\n' "$tx_hash" >&2; exit 1 ;;
esac
EOF
  chmod +x "$workdir/bin/cast"

  shared_manifest="$workdir/shared-manifest.json"
  old_path="$PATH"
  PATH="$workdir/bin:$PATH"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$bridge_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  PATH="$old_path"

  assert_eq "$(jq -r '.contracts.base_event_scanner_start_block' "$shared_manifest")" "33333" "derived base event scanner start block"
  rm -rf "$workdir"
}

test_render_app_handoff_prefers_public_operator_endpoints_when_public_endpoints_are_present() {
  local workdir shared_manifest old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mkdir -p "$workdir/bin"
  cat >"$workdir/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '10.0.0.12\n'
EOF
  chmod +x "$workdir/bin/aws"

  shared_manifest="$workdir/shared-manifest.json"
  old_path="$PATH"
  PATH="$workdir/bin:$PATH"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  PATH="$old_path"

  assert_eq "$(jq -r '.operator_endpoints[0]' "$workdir/output/app/app-deploy.json")" "0x9999999999999999999999999999999999999999=203.0.113.11:18443" "app handoff keeps public operator endpoints when public endpoints are present"
  rm -rf "$workdir"
}

test_render_app_handoff_uses_dkg_operator_ports_when_present() {
  local workdir shared_manifest dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators += [
      {
        "index": 2,
        "operator_id": "0x6666666666666666666666666666666666666666",
        "operator_address": "0x8888888888888888888888888888888888888888",
        "checkpoint_signer_driver": "aws-kms",
        "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/66666666-2222-3333-4444-555555555555",
        "aws_profile": "juno",
        "aws_region": "us-east-1",
        "account_id": "021490342184",
        "operator_host": "203.0.113.12",
        "operator_user": "ubuntu",
        "runtime_dir": "/var/lib/intents-juno/operator-runtime",
        "public_dns_label": "op2",
        "public_endpoint": "203.0.113.12",
        "known_hosts_file": "'"$workdir"'/known_hosts",
        "dkg_backup_zip": "'"$workdir"'/dkg-backup.zip",
        "secret_contract_file": "'"$workdir"'/operator-secrets.env"
      },
      {
        "index": 3,
        "operator_id": "0x7777777777777777777777777777777777777777",
        "operator_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "checkpoint_signer_driver": "aws-kms",
        "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/77777777-2222-3333-4444-555555555555",
        "aws_profile": "juno",
        "aws_region": "us-east-1",
        "account_id": "021490342184",
        "operator_host": "203.0.113.13",
        "operator_user": "ubuntu",
        "runtime_dir": "/var/lib/intents-juno/operator-runtime",
        "public_dns_label": "op3",
        "public_endpoint": "203.0.113.13",
        "known_hosts_file": "'"$workdir"'/known_hosts",
        "dkg_backup_zip": "'"$workdir"'/dkg-backup.zip",
        "secret_contract_file": "'"$workdir"'/operator-secrets.env"
      }
    ]
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  jq '
    .operators[0].endpoint = "https://10.0.0.11:18443"
    | .operators[1].endpoint = "https://10.0.0.12:18444"
    | .operators[2].endpoint = "https://10.0.0.13:18445"
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"

  assert_eq "$(jq -r '.operator_endpoints[0]' "$workdir/output/app/app-deploy.json")" "0x9999999999999999999999999999999999999999=203.0.113.11:18443" "first operator endpoint port"
  assert_eq "$(jq -r '.operator_endpoints[1]' "$workdir/output/app/app-deploy.json")" "0x8888888888888888888888888888888888888888=203.0.113.12:18444" "second operator endpoint port"
  assert_eq "$(jq -r '.operator_endpoints[2]' "$workdir/output/app/app-deploy.json")" "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=203.0.113.13:18445" "third operator endpoint port"
  rm -rf "$workdir"
}

test_render_app_handoff_defaults_operator_ports_by_index_when_dkg_summary_lacks_endpoints() {
  local workdir shared_manifest dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators += [
      {
        "index": 2,
        "operator_id": "0x6666666666666666666666666666666666666666",
        "operator_address": "0x8888888888888888888888888888888888888888",
        "checkpoint_signer_driver": "aws-kms",
        "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/66666666-2222-3333-4444-555555555555",
        "aws_profile": "juno",
        "aws_region": "us-east-1",
        "account_id": "021490342184",
        "operator_host": "203.0.113.12",
        "operator_user": "ubuntu",
        "runtime_dir": "/var/lib/intents-juno/operator-runtime",
        "public_dns_label": "op2",
        "public_endpoint": "203.0.113.12",
        "known_hosts_file": "'"$workdir"'/known_hosts",
        "dkg_backup_zip": "'"$workdir"'/dkg-backup.zip",
        "secret_contract_file": "'"$workdir"'/operator-secrets.env"
      },
      {
        "index": 3,
        "operator_id": "0x7777777777777777777777777777777777777777",
        "operator_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "checkpoint_signer_driver": "aws-kms",
        "checkpoint_signer_kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/77777777-2222-3333-4444-555555555555",
        "aws_profile": "juno",
        "aws_region": "us-east-1",
        "account_id": "021490342184",
        "operator_host": "203.0.113.13",
        "operator_user": "ubuntu",
        "runtime_dir": "/var/lib/intents-juno/operator-runtime",
        "public_dns_label": "op3",
        "public_endpoint": "203.0.113.13",
        "known_hosts_file": "'"$workdir"'/known_hosts",
        "dkg_backup_zip": "'"$workdir"'/dkg-backup.zip",
        "secret_contract_file": "'"$workdir"'/operator-secrets.env"
      }
    ]
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  jq '
    .operators[0] |= del(.endpoint)
    | .operators[1] |= del(.endpoint)
    | .operators[2] |= del(.endpoint)
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"

  assert_eq "$(jq -r '.operator_roster[0].dkg_endpoint' "$shared_manifest")" "https://203.0.113.11:18443" "shared manifest defaults first operator dkg endpoint"
  assert_eq "$(jq -r '.operator_roster[1].dkg_endpoint' "$shared_manifest")" "https://203.0.113.12:18444" "shared manifest defaults second operator dkg endpoint"
  assert_eq "$(jq -r '.operator_roster[2].dkg_endpoint' "$shared_manifest")" "https://203.0.113.13:18445" "shared manifest defaults third operator dkg endpoint"
  assert_eq "$(jq -r '.operator_endpoints[0]' "$workdir/output/app/app-deploy.json")" "0x9999999999999999999999999999999999999999=203.0.113.11:18443" "app handoff defaults first operator endpoint port"
  assert_eq "$(jq -r '.operator_endpoints[1]' "$workdir/output/app/app-deploy.json")" "0x8888888888888888888888888888888888888888=203.0.113.12:18444" "app handoff defaults second operator endpoint port"
  assert_eq "$(jq -r '.operator_endpoints[2]' "$workdir/output/app/app-deploy.json")" "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=203.0.113.13:18445" "app handoff defaults third operator endpoint port"
  rm -rf "$workdir"
}

test_render_shared_manifest_prefers_inventory_owallet_ua() {
  local workdir shared_manifest bridge_summary_no_ua
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  printf 'JUNO_TXSIGN_SIGNER_KEYS=literal:%s\n' "$(test_default_operator_txsign_key)" >>"$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  bridge_summary_no_ua="$workdir/bridge-summary-no-ua.json"
  jq 'del(.owallet_ua)' "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" >"$bridge_summary_no_ua"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$bridge_summary_no_ua" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"

  assert_eq "$(jq -r '.contracts.owallet_ua' "$shared_manifest")" "u1alphaexample" "inventory owallet ua fallback"
  rm -rf "$workdir"
}

test_render_shared_manifest_prefers_dkg_owallet_ua_over_reused_bridge_summary() {
  local workdir shared_manifest bridge_summary dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.contracts.owallet_ua)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  bridge_summary="$workdir/bridge-summary.json"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" "$bridge_summary"
  dkg_summary="$workdir/dkg-summary.json"
  jq '.juno_shielded_address = "u1freshdkgsummary"' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$bridge_summary" \
    "$dkg_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"

  assert_eq "$(jq -r '.contracts.owallet_ua' "$shared_manifest")" "u1freshdkgsummary" "dkg owallet ua overrides reused bridge summary"
  rm -rf "$workdir"
}

test_render_shared_manifest_rejects_inventory_owallet_ua_mismatch_with_dkg() {
  local workdir shared_manifest dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  dkg_summary="$workdir/dkg-summary.json"
  jq '.juno_shielded_address = "u1freshdkgsummary"' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"
  shared_manifest="$workdir/shared-manifest.json"

  if (
    production_render_shared_manifest \
      "$workdir/inventory.json" \
      "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      "$dkg_summary" \
      "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      "$shared_manifest" \
      "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_shared_manifest to reject stale inventory owallet ua\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_rejects_mismatched_juno_network() {
  local workdir shared_manifest mainnet_dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mainnet_dkg_summary="$workdir/dkg-summary-mainnet.json"
  jq '.network = "mainnet"' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$mainnet_dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  if (
    production_render_shared_manifest \
      "$workdir/inventory.json" \
      "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      "$mainnet_dkg_summary" \
      "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      "$shared_manifest" \
      "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_shared_manifest to reject mismatched juno network\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_rejects_nonroutable_dkg_endpoints() {
  local workdir shared_manifest loopback_dkg_summary
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  loopback_dkg_summary="$workdir/dkg-summary.loopback.json"
  jq '
    .operators[0].endpoint = "https://127.0.0.1:18443"
    | .operators[1].endpoint = "https://127.0.0.1:18444"
    | .operators[2].endpoint = "https://localhost:18445"
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$loopback_dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  if (
    production_render_shared_manifest \
      "$workdir/inventory.json" \
      "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      "$loopback_dkg_summary" \
      "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      "$shared_manifest" \
      "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_shared_manifest to reject non-routable dkg endpoints\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_requires_signer_ufvk() {
  local workdir shared_manifest dkg_summary_no_ufvk
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.contracts.owallet_ua)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary_no_ufvk="$workdir/dkg-summary.no-ufvk.json"
  jq 'del(.ufvk)' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary_no_ufvk"

  shared_manifest="$workdir/shared-manifest.json"
  if (
    production_render_shared_manifest \
      "$workdir/inventory.json" \
      "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      "$dkg_summary_no_ufvk" \
      "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      "$shared_manifest" \
      "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_shared_manifest to require a signer UFVK\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_shared_manifest_uses_completion_fallback_for_signer_ufvk() {
  local workdir shared_manifest dkg_summary_no_ufvk dkg_completion bridge_summary_no_ua
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.contracts.owallet_ua)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary_no_ufvk="$workdir/dkg-summary.no-ufvk.json"
  jq 'del(.ufvk)' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary_no_ufvk"
  bridge_summary_no_ua="$workdir/bridge-summary.no-ua.json"
  jq 'del(.owallet_ua) | del(.juno_shielded_address)' "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" >"$bridge_summary_no_ua"
  dkg_completion="$workdir/dkg-completion.json"
  cat >"$dkg_completion" <<'EOF'
{
  "network": "testnet",
  "ufvk": "uview1completionfallback",
  "juno_shielded_address": "u1completionfallback"
}
EOF

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$bridge_summary_no_ua" \
    "$dkg_summary_no_ufvk" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir" \
    "$dkg_completion"

  assert_eq "$(jq -r '.checkpoint.signer_ufvk' "$shared_manifest")" "uview1completionfallback" "completion ufvk fallback"
  assert_eq "$(jq -r '.contracts.owallet_ua' "$shared_manifest")" "u1completionfallback" "completion juno shielded address fallback"
  rm -rf "$workdir"
}

test_render_operator_stack_env_uses_kms_contract() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cat >>"$workdir/operator-secrets.env" <<'EOF'
JUNO_RPC_BIND=literal:0.0.0.0
JUNO_RPC_ALLOW_IPS=literal:127.0.0.1,10.0.0.5
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  cat >>"$resolved_env" <<'EOF'
BRIDGE_ADDRESS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
BASE_EVENT_SCANNER_BRIDGE_ADDRESS=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "rendered env signer driver"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "rendered env signer kms key id"
  assert_contains "$(cat "$output_env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "rendered env operator address"
  assert_contains "$(cat "$output_env")" "BRIDGE_ADDRESS=0x2222222222222222222222222222222222222222" "rendered env bridge address comes from shared manifest"
  assert_contains "$(cat "$output_env")" "BASE_EVENT_SCANNER_BRIDGE_ADDRESS=0x2222222222222222222222222222222222222222" "rendered env base event scanner bridge address comes from shared manifest"
  assert_not_contains "$(cat "$output_env")" "BRIDGE_ADDRESS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "rendered env ignores stale bridge address from resolved secrets"
  assert_not_contains "$(cat "$output_env")" "BASE_EVENT_SCANNER_BRIDGE_ADDRESS=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "rendered env ignores stale base event scanner bridge address from resolved secrets"
  assert_contains "$(cat "$output_env")" "BASE_EVENT_SCANNER_START_BLOCK=12345" "rendered env base event scanner start block"
  assert_contains "$(cat "$output_env")" "DEPOSIT_RELAYER_BASE_RPC_URL=https://base-sepolia.example.invalid" "rendered env stages the dedicated deposit relayer rpc url"
  assert_contains "$(cat "$output_env")" "AWS_REGION=us-east-1" "rendered env aws region"
  assert_contains "$(cat "$output_env")" "AWS_DEFAULT_REGION=us-east-1" "rendered env aws default region"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_USER=juno" "rendered env juno rpc user"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_PASS=rpcpass" "rendered env juno rpc pass"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_BIND=0.0.0.0" "rendered env juno rpc bind override"
  assert_contains "$(cat "$output_env")" "JUNO_RPC_ALLOW_IPS=127.0.0.1,10.0.0.5" "rendered env juno rpc allowlist override"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "rendered env withdraw coordinator juno rpc url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_SCAN_URL=http://127.0.0.1:8080" "rendered env withdraw coordinator scan url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443" "rendered env withdraw coordinator tss url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem" "rendered env withdraw coordinator tss ca"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.pem" "rendered env withdraw coordinator client cert"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.key" "rendered env withdraw coordinator client key"
  assert_contains "$(cat "$output_env")" "BASE_RELAYER_MIN_READY_BALANCE_WEI=1000000000000000" "rendered env base relayer readiness balance floor"
  assert_contains "$(cat "$output_env")" "BASE_RELAYER_ALLOWED_SELECTORS=0x53a58a48,0xec70b605,0xfe097d57" "rendered env base relayer selector allowlist"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/usr/local/bin/intents-juno-multikey-extend-signer.sh" "rendered env withdraw coordinator extend signer"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "rendered env carries the withdraw extend signer key roster"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000" "rendered env withdraw coordinator juno fee floor"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240" "rendered env withdraw coordinator juno expiry offset"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h" "rendered env withdraw coordinator expiry safety margin"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h" "rendered env withdraw coordinator max expiry extension"
  assert_contains "$(cat "$output_env")" "JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "rendered env uses only the operator-scoped juno txsign signer key"
  assert_not_contains "$(grep '^JUNO_TXSIGN_SIGNER_KEYS=' "$output_env")" "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "rendered env keeps juno txsign scoped to the local operator key"
  assert_contains "$(cat "$output_env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "rendered env withdraw finalizer scan url"
  assert_contains "$(cat "$output_env")" "WITHDRAW_FINALIZER_JUNO_RPC_URL=http://127.0.0.1:18232" "rendered env withdraw finalizer juno rpc url"
  assert_contains "$(cat "$output_env")" "TSS_SIGNER_RUNTIME_MODE=host-process" "rendered env forces host-process signer runtime"
  assert_contains "$(cat "$output_env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "rendered env tss ufvk path"
  assert_contains "$(cat "$output_env")" "TSS_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin" "rendered env tss spendauth signer path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-attested-signer" "rendered env tss nitro signer path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ENCLAVE_EIF_FILE=/var/lib/intents-juno/operator-runtime/enclave/spendauth-signer.eif" "rendered env tss enclave path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ENCLAVE_CID=16" "rendered env tss enclave cid"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ATTESTATION_FILE=/var/lib/intents-juno/operator-runtime/attestation/spendauth-attestation.json" "rendered env tss attestation path"
  assert_contains "$(cat "$output_env")" "TSS_NITRO_ATTESTATION_MAX_AGE_SECONDS=300" "rendered env tss attestation max age"
  assert_contains "$(cat "$output_env")" "TSS_SIGNER_WORK_DIR=/var/lib/intents-juno/tss-signer" "rendered env tss work dir"
  assert_contains "$(cat "$output_env")" "TSS_LISTEN_ADDR=127.0.0.1:9443" "rendered env tss listen addr"
  assert_contains "$(cat "$output_env")" "TSS_TLS_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.pem" "rendered env tss cert path"
  assert_contains "$(cat "$output_env")" "TSS_TLS_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.key" "rendered env tss key path"
  assert_contains "$(cat "$output_env")" "TSS_CLIENT_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem" "rendered env tss client ca"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "rendered env omits private key for kms signer"
  rm -rf "$workdir"
}

test_render_operator_stack_env_adds_base_sepolia_deposit_relayer_fallback() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.contracts.base_rpc_url = "https://sepolia.base.org"' "$workdir/inventory.json" >"$workdir/inventory.tmp"
  mv "$workdir/inventory.tmp" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "DEPOSIT_RELAYER_BASE_RPC_URL=https://sepolia.base.org,https://base-sepolia-rpc.publicnode.com" "rendered env adds the public fallback for Base Sepolia deposit relayer recovery"
  rm -rf "$workdir"
}

test_render_operator_handoffs_refresh_withdraw_change_address_from_shared_manifest() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=literal:u1staleaddress
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.contracts.owallet_ua)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=literal:u1alphaexample" "handoff refreshes withdraw change address"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"
  assert_contains "$(cat "$output_env")" "WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=u1alphaexample" "rendered env uses refreshed withdraw change address"
  rm -rf "$workdir"
}

test_render_operator_handoffs_rejects_local_checkpoint_signer_driver() {
  local workdir shared_manifest dkg_summary_with_key
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  printf '0123456789012345678901234567890123456789012345678901234567890123' >"$workdir/operator.key"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].checkpoint_signer_driver = "local-env"
    | .operators[0].checkpoint_signer_kms_key_id = null
    | .operators[0].operator_address = null
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary_with_key="$workdir/dkg-summary.with-key.json"
  write_dkg_summary_with_operator_key "$dkg_summary_with_key" "$workdir/operator.key"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary_with_key" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  if (production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$dkg_summary_with_key" "$workdir/output" "$workdir" >/dev/null 2>&1); then
    printf 'expected production_render_operator_handoffs to reject checkpoint_signer_driver=local-env in production\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_handoffs_preserves_secure_preview_signer_configuration() {
  local workdir shared_manifest handoff_dir
  workdir="$(mktemp -d)"
  printf 'preview-backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_eq "$(jq -r '.shared_services.kafka.auth.mode' "$shared_manifest")" "aws-msk-iam" "preview shared manifest uses authenticated kafka transport"
  assert_eq "$(jq -r '.checkpoint_signer_driver' "$handoff_dir/operator-deploy.json")" "aws-kms" "preview handoff preserves kms checkpoint signer mode"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$handoff_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "preview handoff preserves kms signer key"
  assert_not_contains "$(cat "$handoff_dir/operator-secrets.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "preview handoff omits local checkpoint signer key material"
  rm -rf "$workdir"
}

test_render_operator_handoffs_derives_withdraw_extend_signer_keys_from_dkg_summary() {
  local workdir shared_manifest handoff_dir dkg_summary
  workdir="$(mktemp -d)"
  printf 'preview-backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/op1.key" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cat >"$workdir/op2.key" <<'EOF'
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  cat >"$workdir/op3.key" <<'EOF'
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  jq '
    .operators[0].operator_key_file = "op1.key"
    | .operators[1].operator_key_file = "op2.key"
    | .operators[2].operator_key_file = "op3.key"
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$dkg_summary" "$workdir/output" "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" "preview handoff derives the full withdraw extend signer roster from dkg operator keys when the source secret omits it"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "preview handoff derives the operator-scoped juno txsign signer key from dkg operator keys when the source secret omits it"
  assert_not_contains "$(grep '^JUNO_TXSIGN_SIGNER_KEYS=' "$handoff_dir/operator-secrets.env")" "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "preview handoff keeps the runtime juno txsign key scoped to the local operator"
  rm -rf "$workdir"
}

test_render_operator_handoffs_provisions_missing_checkpoint_signer_kms_key() {
  local workdir shared_manifest dkg_summary handoff_dir fake_bin fake_log old_provisioner
  workdir="$(mktemp -d)"
  fake_bin="$workdir/fake-checkpoint-kms-provisioner.sh"
  fake_log="$workdir/checkpoint-kms-provisioner.log"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/op1.key" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  cat >"$workdir/op2.key" <<'EOF'
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  cat >"$workdir/op3.key" <<'EOF'
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '(.operators[] | .checkpoint_signer_kms_key_id) = null' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  jq '
    .operators[0].operator_key_file = "op1.key"
    | .operators[1].operator_key_file = "op2.key"
    | .operators[2].operator_key_file = "op3.key"
  ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$dkg_summary"
  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$dkg_summary" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  write_fake_checkpoint_signer_kms_provisioner "$fake_bin" "$fake_log"
  old_provisioner="${PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN:-}"
  export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$fake_bin"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$dkg_summary" "$workdir/output" "$workdir"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$handoff_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/provisioned" "handoff provisions missing checkpoint signer kms key id"
  assert_contains "$(cat "$fake_log")" '--operator-address 0x9999999999999999999999999999999999999999' "provisioner receives operator address"
  assert_contains "$(cat "$fake_log")" '--private-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "provisioner receives operator signer private key"
  assert_not_contains "$(cat "$handoff_dir/operator-secrets.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "handoff still omits local checkpoint signer key material after kms provisioning"

  if [[ -n "$old_provisioner" ]]; then
    export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$old_provisioner"
  else
    unset PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN
  fi
  rm -rf "$workdir"
}

test_resolve_checkpoint_signer_kms_key_id_uses_explicit_arn_without_provisioner() {
  local workdir fake_bin fake_log old_provisioner operator_json resolved
  workdir="$(mktemp -d)"
  fake_bin="$workdir/fake-checkpoint-kms-provisioner.sh"
  fake_log="$workdir/checkpoint-kms-provisioner.log"
  write_fake_checkpoint_signer_kms_provisioner "$fake_bin" "$fake_log"
  old_provisioner="${PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN:-}"
  export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$fake_bin"

  operator_json="$(
    jq -n '{
      operator_id: "0x1111111111111111111111111111111111111111",
      operator_address: "0x9999999999999999999999999999999999999999",
      aws_profile: "op1",
      aws_region: "us-east-1",
      account_id: "021490342184",
      checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555"
    }'
  )"

  resolved="$(production_resolve_checkpoint_signer_kms_key_id "mainnet" "/dev/null" "$operator_json")"
  assert_eq "$resolved" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "explicit checkpoint signer kms arn is returned directly"
  if [[ -f "$fake_log" ]]; then
    printf 'expected explicit checkpoint signer kms arn to bypass provisioner, but saw:\n%s\n' "$(cat "$fake_log")" >&2
    return 1
  fi

  if [[ -n "$old_provisioner" ]]; then
    export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$old_provisioner"
  else
    unset PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN
  fi
  rm -rf "$workdir"
}

test_render_operator_handoffs_derives_owallet_keys_from_signer_ufvk() {
  local workdir shared_manifest handoff_dir fake_bin derived_ivk derived_ovk old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  printf 'JUNO_TXSIGN_SIGNER_KEYS=literal:%s\n' "$(test_default_operator_txsign_key)" >>"$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"

  derived_ivk="0x$(printf 'a%.0s' $(seq 1 128))"
  derived_ovk="0x$(printf 'b%.0s' $(seq 1 64))"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/cargo" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'SP1_DEPOSIT_OWALLET_IVK_HEX=%s\n' '$derived_ivk'
printf 'SP1_WITHDRAW_OWALLET_OVK_HEX=%s\n' '$derived_ovk'
EOF
  chmod +x "$fake_bin/cargo"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  PATH="$old_path"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "DEPOSIT_OWALLET_IVK=literal:$derived_ivk" "handoff injects derived deposit owallet ivk"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "WITHDRAW_OWALLET_OVK=literal:$derived_ovk" "handoff injects derived withdraw owallet ovk"
  rm -rf "$workdir"
}

test_render_operator_handoffs_preserves_explicit_owallet_keys() {
  local workdir shared_manifest handoff_dir fake_bin explicit_ivk explicit_ovk old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  explicit_ivk="0x$(printf '1%.0s' $(seq 1 128))"
  explicit_ovk="0x$(printf '2%.0s' $(seq 1 64))"
  cat >"$workdir/operator-secrets.env" <<EOF
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
DEPOSIT_OWALLET_IVK=literal:$explicit_ivk
WITHDRAW_OWALLET_OVK=literal:$explicit_ovk
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"

  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF
  chmod +x "$fake_bin/cargo"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  PATH="$old_path"

  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "DEPOSIT_OWALLET_IVK=literal:$explicit_ivk" "handoff keeps explicit deposit owallet ivk"
  assert_contains "$(cat "$handoff_dir/operator-secrets.env")" "WITHDRAW_OWALLET_OVK=literal:$explicit_ovk" "handoff keeps explicit withdraw owallet ovk"
  rm -rf "$workdir"
}

test_render_operator_stack_env_rejects_local_checkpoint_signer_driver() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  jq '
    .checkpoint_signer_driver = "local-env"
    | .checkpoint_signer_kms_key_id = null
    | .operator_address = null
  ' "$handoff_dir/operator-deploy.json" >"$handoff_dir/operator-deploy.json.next"
  mv "$handoff_dir/operator-deploy.json.next" "$handoff_dir/operator-deploy.json"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to reject local-env checkpoint signers in production\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_stack_env_preserves_secure_preview_signer_configuration() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'preview-backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "preview env preserves kms checkpoint signer mode"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "preview env carries the checkpoint signer kms key"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "preview env omits local checkpoint signer key material"
  assert_contains "$(cat "$output_env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "preview env still stages the checkpoint package bucket for config hydration"
  assert_contains "$(cat "$output_env")" "JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" "preview env uses authenticated kafka transport"
  rm -rf "$workdir"
}

test_render_operator_stack_env_enables_deposit_scan_from_withdraw_wallet_id() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"

  assert_contains "$(cat "$output_env")" "DEPOSIT_SCAN_ENABLED=true" "rendered env enables deposit scan"
  assert_contains "$(cat "$output_env")" "DEPOSIT_SCAN_JUNO_SCAN_URL=http://127.0.0.1:8080" "rendered env deposit scan url"
  assert_contains "$(cat "$output_env")" "DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=wallet-op1" "rendered env deposit scan wallet id"
  assert_contains "$(cat "$output_env")" "DEPOSIT_SCAN_JUNO_RPC_URL=http://127.0.0.1:18232" "rendered env deposit scan rpc url"
  rm -rf "$workdir"
}

test_render_operator_stack_env_injects_queueauth_secret_from_shared_manifest() {
  local workdir shared_manifest handoff_dir resolved_env output_env tf_json fake_bin old_path
  local queueauth_secret_arn
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  queueauth_secret_arn="arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-kafka-critical-hmac"
  tf_json="$workdir/terraform-output.json"
  jq --arg arn "$queueauth_secret_arn" '.shared_kafka_critical_hmac_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  assert_eq "$(jq -r '.shared_services.kafka.critical_key_id' "$shared_manifest")" "default" "shared manifest includes the default queueauth key id"
  assert_eq "$(jq -r '.shared_services.kafka.critical_hmac_secret_arn' "$shared_manifest")" "$queueauth_secret_arn" "shared manifest includes the queueauth HMAC secret ARN"

  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"

  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_secret_reader "$fake_bin/aws" "$queueauth_secret_arn" "queueauth-test-hmac-key"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"
  PATH="$old_path"

  assert_contains "$(cat "$output_env")" "JUNO_QUEUE_CRITICAL_KEY_ID=default" "rendered env carries the queueauth key id"
  assert_contains "$(cat "$output_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=queueauth-test-hmac-key" "rendered env carries the queueauth HMAC secret"
  rm -rf "$workdir"
}

test_render_operator_stack_env_prefers_inline_ipfs_bearer_token() {
  local workdir shared_manifest handoff_dir resolved_env output_env tf_json fake_bin old_path
  local ipfs_secret_arn
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
CHECKPOINT_IPFS_API_BEARER_TOKEN=literal:inline-ipfs-token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  ipfs_secret_arn="arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-ipfs-api-bearer-token"
  tf_json="$workdir/terraform-output.json"
  jq --arg arn "$ipfs_secret_arn" '.shared_ipfs_api_auth_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"

  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_secret_reader "$fake_bin/aws" "$ipfs_secret_arn" "aws-ipfs-token"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"
  PATH="$old_path"

  assert_contains "$(cat "$output_env")" "CHECKPOINT_IPFS_API_BEARER_TOKEN=inline-ipfs-token" "rendered env prefers inline ipfs bearer token"
  assert_not_contains "$(cat "$output_env")" "CHECKPOINT_IPFS_API_BEARER_TOKEN=aws-ipfs-token" "rendered env ignores shared manifest ipfs secret when inline token is present"
  rm -rf "$workdir"
}

test_render_operator_stack_env_prefers_inline_queueauth_hmac_key() {
  local workdir shared_manifest handoff_dir resolved_env output_env tf_json fake_bin old_path
  local queueauth_secret_arn
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_QUEUE_CRITICAL_HMAC_KEY=literal:inline-queueauth-hmac
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  queueauth_secret_arn="arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-kafka-critical-hmac"
  tf_json="$workdir/terraform-output.json"
  jq --arg arn "$queueauth_secret_arn" '.shared_kafka_critical_hmac_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$tf_json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$tf_json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"

  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_secret_reader "$fake_bin/aws" "$queueauth_secret_arn" "aws-queueauth-hmac"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env"
  PATH="$old_path"

  assert_contains "$(cat "$output_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=inline-queueauth-hmac" "rendered env prefers inline queueauth hmac key"
  assert_not_contains "$(cat "$output_env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=aws-queueauth-hmac" "rendered env ignores shared manifest queueauth secret when inline key is present"
  rm -rf "$workdir"
}

test_render_operator_stack_env_requires_juno_rpc_credentials() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to require JUNO_RPC_USER/JUNO_RPC_PASS\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_stack_env_requires_juno_txsign_signer_keys() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  awk -F= 'index($0, "JUNO_TXSIGN_SIGNER_KEYS=") != 1 { print }' "$handoff_dir/operator-secrets.env" >"$handoff_dir/operator-secrets.env.next"
  mv "$handoff_dir/operator-secrets.env.next" "$handoff_dir/operator-secrets.env"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to require JUNO_TXSIGN_SIGNER_KEYS\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_stack_env_rejects_withdraw_expiry_overrides() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=literal:30h
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to reject withdraw expiry overrides\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_operator_stack_env_rejects_private_key_with_kms_contract() {
  local workdir shared_manifest handoff_dir resolved_env output_env
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
CHECKPOINT_SIGNER_PRIVATE_KEY=literal:0xdeadbeef
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  handoff_dir="$(production_operator_dir "$workdir/output" "0x1111111111111111111111111111111111111111")"
  printf 'CHECKPOINT_SIGNER_PRIVATE_KEY=literal:0xdeadbeef\n' >>"$handoff_dir/operator-secrets.env"

  resolved_env="$workdir/resolved.env"
  output_env="$workdir/operator-stack.env"
  production_resolve_secret_contract "$handoff_dir/operator-secrets.env" "true" "" "" "$resolved_env"
  if (production_render_operator_stack_env "$shared_manifest" "$handoff_dir/operator-deploy.json" "$resolved_env" "$output_env" >/dev/null 2>&1); then
    printf 'expected production_render_operator_stack_env to reject CHECKPOINT_SIGNER_PRIVATE_KEY for aws-kms\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_junocashd_conf_uses_juno_rpc_credentials() {
  local workdir env_file output_conf
  workdir="$(mktemp -d)"
  env_file="$workdir/operator-stack.env"
  output_conf="$workdir/junocashd.conf"

  cat >"$env_file" <<'EOF'
JUNO_RPC_USER=juno
JUNO_RPC_PASS=rpcpass
JUNO_RPC_BIND=0.0.0.0
JUNO_RPC_ALLOW_IPS=127.0.0.1,10.0.0.5
EOF

  production_render_junocashd_conf "$env_file" "$output_conf"

  assert_contains "$(cat "$output_conf")" "rpcbind=0.0.0.0" "junocashd conf rpc bind"
  assert_contains "$(cat "$output_conf")" "rpcallowip=127.0.0.1" "junocashd conf first rpc allow ip"
  assert_contains "$(cat "$output_conf")" "rpcallowip=10.0.0.5" "junocashd conf second rpc allow ip"
  assert_contains "$(cat "$output_conf")" "rpcport=18232" "junocashd conf rpc port"
  assert_contains "$(cat "$output_conf")" "rpcuser=juno" "junocashd conf rpc user"
  assert_contains "$(cat "$output_conf")" "rpcpassword=rpcpass" "junocashd conf rpc password"
  assert_contains "$(cat "$output_conf")" "txunpaidactionlimit=10000" "junocashd conf raises unpaid action limit for shielded transactions"
  rm -rf "$workdir"
}

test_rollout_state_enforces_one_operator_at_a_time() {
  local workdir inventory
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.operators += [{"index":2,"operator_id":"0x6666666666666666666666666666666666666666","aws_profile":"juno","aws_region":"us-east-1","account_id":"021490342184","operator_host":"203.0.113.12","operator_user":"ubuntu","runtime_dir":"/var/lib/intents-juno/operator-runtime","public_dns_label":"op2","public_endpoint":"203.0.113.12","known_hosts_file":"known_hosts","dkg_backup_zip":"dkg-backup.zip","secret_contract_file":"operator-secrets.env"}]' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_write_rollout_state "$workdir/inventory.json" "$workdir/rollout-state.json"
  production_rollout_reserve "$workdir/rollout-state.json" "0x1111111111111111111111111111111111111111"
  if (production_rollout_reserve "$workdir/rollout-state.json" "0x6666666666666666666666666666666666666666") >/dev/null 2>&1; then
    printf 'expected rollout reserve to fail while another operator is in progress\n' >&2
    exit 1
  fi
  production_rollout_complete "$workdir/rollout-state.json" "0x1111111111111111111111111111111111111111" "done" "healthy"
  production_rollout_reserve "$workdir/rollout-state.json" "0x6666666666666666666666666666666666666666"
  assert_eq "$(jq -r '.current_operator_id' "$workdir/rollout-state.json")" "0x6666666666666666666666666666666666666666" "second operator reserved"
  rm -rf "$workdir"
}

test_render_app_handoff_and_envs() {
  local workdir shared_manifest app_manifest resolved_env bridge_env backoffice_env
  local fake_bin old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  assert_file_exists "$app_manifest" "app deploy manifest"
  assert_eq "$(jq -r '.public_scheme' "$app_manifest")" "https" "public scheme"
  assert_eq "$(jq -r '.services.bridge_api.public_url' "$app_manifest")" "https://bridge.alpha.intents-testing.thejunowallet.com" "bridge public url"
  assert_eq "$(jq -r '.services.bridge_api.probe_url' "$app_manifest")" "https://bridge.alpha.intents-testing.thejunowallet.com" "bridge probe url"
  assert_eq "$(jq -r '.services.bridge_api.internal_url' "$app_manifest")" "http://127.0.0.1:8082" "bridge internal url"
  assert_eq "$(jq -r '.services.backoffice.public_url // empty' "$app_manifest")" "" "backoffice public url"
  assert_eq "$(jq -r '.services.backoffice.access.publish_public_dns' "$app_manifest")" "false" "backoffice public publishing suppressed"
  assert_eq "$(jq -r '.services.backoffice.access.mode' "$app_manifest")" "wireguard" "backoffice access mode"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[0]' "$app_manifest")" "10.0.2.50/32" "backoffice wireguard source cidr"
  assert_eq "$(jq -r '.services.backoffice.access.client_config_secret_arn // empty' "$app_manifest")" "" "backoffice wireguard client config secret removed from manifest"
  assert_eq "$(jq -r '.wireguard_role.endpoint_host' "$app_manifest")" "198.51.100.25" "backoffice wireguard endpoint host"
  assert_eq "$(jq -r '.security_group_id' "$app_manifest")" "sg-publicbridge012345678" "security group id"
  assert_eq "$(jq -r '.edge.enabled' "$app_manifest")" "true" "edge enabled"
  assert_eq "$(jq -r '.edge.origin_record_name' "$app_manifest")" "origin.alpha.intents-testing.thejunowallet.com" "edge origin record"
  assert_eq "$(jq -r '.edge.public_lb_dns_name' "$app_manifest")" "bridge-alpha-123456.us-east-1.elb.amazonaws.com" "edge public load balancer dns name"
  assert_eq "$(jq -r '.edge.public_lb_zone_id' "$app_manifest")" "Z35SXDOTRQ7X7K" "edge public load balancer zone id"
  assert_eq "$(jq -r '.edge.origin_endpoint // empty' "$app_manifest")" "" "edge origin endpoint removed from the active app contract"
  assert_eq "$(jq -r '.edge.origin_http_port' "$app_manifest")" "443" "edge origin port"
  assert_eq "$(jq -r '.edge.rate_limit' "$app_manifest")" "2000" "edge rate limit"
  assert_eq "$(jq -r '.edge.alarm_actions[0]' "$app_manifest")" "arn:aws:sns:us-east-1:021490342184:juno-alpha-alerts" "edge alarm actions"
  assert_eq "$(jq -r '.edge.state_path' "$app_manifest")" "$workdir/edge-state/alpha.tfstate" "edge state path is stable per environment"
  assert_contains "$(jq -cr '.operator_addresses' "$app_manifest")" "0x9999999999999999999999999999999999999999" "operator addresses"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  bridge_env="$workdir/bridge-api.env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  production_render_bridge_api_env "$shared_manifest" "$app_manifest" "$resolved_env" "$bridge_env"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"
  PATH="$old_path"

  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_POSTGRES_DSN=postgres://alpha" "bridge env postgres dsn"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_OWALLET_UA=u1alphaexample" "bridge env owallet ua"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_BASE_RPC_URL=https://base-sepolia.example.invalid" "bridge env base rpc url"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_WJUNO_ADDRESS=0x3333333333333333333333333333333333333333" "bridge env wjuno"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_WITHDRAWAL_EXPIRY_WINDOW_SECONDS=86400" "bridge env withdrawal expiry window"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_MIN_DEPOSIT_AMOUNT=201005025" "bridge env min deposit amount"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_DEPOSIT_MIN_CONFIRMATIONS=1" "bridge env deposit confirmation default"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=1" "bridge env withdraw planner confirmation default"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_WITHDRAW_BATCH_CONFIRMATIONS=1" "bridge env withdraw batch confirmation default"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_MIN_WITHDRAW_AMOUNT=200000000" "bridge env min withdraw amount"
  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_FEE_BPS=50" "bridge env fee bps"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_AUTH_SECRET=backoffice-token" "backoffice env auth secret"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_OWALLET_UA=u1alphaexample" "backoffice env mpc address"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_SP1_REQUESTOR_ADDRESS=0x1234567890abcdef1234567890abcdef12345678" "backoffice env prover requestor address"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_SP1_RPC_URL=https://rpc.mainnet.succinct.xyz" "backoffice env sp1 rpc url"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_OPERATOR_ADDRESSES=0x9999999999999999999999999999999999999999" "backoffice env operator addresses"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES=0xd68c28F414B210a6C519D05159014378A5b8Bc0F" "backoffice env relayer signer addresses"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI=1000000000000000" "backoffice env relayer signer balance floor"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_DEPOSIT_MIN_CONFIRMATIONS=1" "backoffice env deposit confirmation default"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=1" "backoffice env withdraw planner confirmation default"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_WITHDRAW_BATCH_CONFIRMATIONS=1" "backoffice env withdraw batch confirmation default"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_OPERATOR_ENDPOINTS=0x9999999999999999999999999999999999999999=203.0.113.11:18443" "backoffice env operator endpoints"
  assert_not_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_URL=http://127.0.0.1:18232" "backoffice env omits unusable loopback juno rpc url"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_URLS=http://203.0.113.11:18232" "backoffice env falls back to operator juno rpc when the explicit url is loopback"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for derived fallback urls"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for derived fallback urls"
  assert_contains "$(cat "$backoffice_env")" "MIN_DEPOSIT_ADMIN_PRIVATE_KEY=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "backoffice env min deposit admin key"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_SERVICE_URLS=bridge-api=http://127.0.0.1:8082/readyz" "backoffice env service urls"
  rm -rf "$workdir"
}

test_render_app_handoff_and_envs_allow_missing_backoffice_juno_rpc_url() {
  local workdir shared_manifest app_manifest resolved_env backoffice_env
  local fake_bin old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq 'del(.app_host.juno_rpc_url) | del(.app_role.juno_rpc_url)' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  assert_eq "$(jq -r '.juno_rpc_url' "$app_manifest")" "null" "app manifest omits juno rpc url"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"
  PATH="$old_path"

  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_URLS=http://203.0.113.11:18232" "backoffice env derives juno rpc fallback urls from operator endpoints"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for derived fallback urls"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for derived fallback urls"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES=0xd68c28F414B210a6C519D05159014378A5b8Bc0F" "backoffice env relayer signer addresses still render without juno rpc"
  rm -rf "$workdir"
}

test_render_app_handoff_emits_base_relayer_signer_addresses_from_inventory() {
  local workdir shared_manifest app_manifest
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .operators[0].base_relayer_address = "0x9565dECCA82442a86F6F36Aa0cD628e557EaD66b"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  assert_eq "$(jq -r '.base_relayer_signer_addresses' "$app_manifest")" "0x9565dECCA82442a86F6F36Aa0cD628e557EaD66b" "app manifest carries relayer signer addresses from operator inventory"
  rm -rf "$workdir"
}

test_render_manifests_allow_external_dns_without_route53_zone() {
  local workdir shared_manifest app_manifest operator_manifest
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "mainnet"
    | .dns.mode = "external"
    | .shared_services.route53_zone_id = null
    | .shared_services.public_zone_name = "junointents.com"
    | .shared_services.public_subdomain = "mainnet.junointents.com"
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
    | .app_host.known_hosts_file = null
    | .app_host.secret_contract_file = null
    | .app_role.known_hosts_file = null
    | .app_role.secret_contract_file = null
    | .app_role.runtime_config_secret_id = "mainnet/app/runtime-config"
    | .app_role.runtime_config_secret_region = "us-east-1"
    | .app_role.public_bridge_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/origin-mainnet"
    | .app_role.public_bridge_additional_certificate_arns = ["arn:aws:acm:us-east-1:021490342184:certificate/bridge-mainnet"]
    | .app_role.internal_backoffice_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/backoffice-mainnet"
    | .wireguard_role.backoffice_hostname = "ops.mainnet.junointents.com"
    | .shared_roles.wireguard.backoffice_hostname = "ops.mainnet.junointents.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"

  app_manifest="$workdir/output/app/app-deploy.json"
  operator_manifest="$workdir/output/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"

  assert_eq "$(jq -r '.dns.mode' "$shared_manifest")" "external" "shared manifest preserves external dns mode"
  assert_eq "$(jq -r '.dns.zone_id // empty' "$shared_manifest")" "" "shared manifest omits route53 zone id for external dns"
  assert_eq "$(jq -r '.dns.zone_name' "$shared_manifest")" "junointents.com" "shared manifest keeps the parent public zone name"
  assert_eq "$(jq -r '.services.bridge_api.record_name' "$app_manifest")" "bridge.mainnet.junointents.com" "app manifest uses the external public bridge hostname"
  assert_eq "$(jq -r '.dns.zone_id // empty' "$app_manifest")" "" "app manifest omits route53 zone id for external dns"
  assert_eq "$(jq -r '.edge.viewer_certificate_arn' "$app_manifest")" "arn:aws:acm:us-east-1:021490342184:certificate/bridge-mainnet" "app manifest carries the existing viewer certificate for external dns"
  assert_eq "$(jq -r '.dns.zone_id // empty' "$operator_manifest")" "" "operator manifest omits route53 zone id for external dns"
  assert_eq "$(jq -r '.dns.record_name' "$operator_manifest")" "op1.mainnet.junointents.com" "operator manifest still computes the public hostname"

  rm -rf "$workdir"
}

test_render_backoffice_env_requires_sp1_requestor_address() {
  local workdir shared_manifest app_manifest resolved_env backoffice_env
  local fake_bin old_path output status
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  jq 'del(.shared_services.proof.requestor_address)' "$shared_manifest" >"$workdir/shared-manifest.next"
  mv "$workdir/shared-manifest.next" "$shared_manifest"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  set +e
  output="$(production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env" 2>&1)"
  status=$?
  set -e
  PATH="$old_path"

  if [[ $status -eq 0 ]]; then
    printf 'expected production_render_backoffice_env to require shared_services.proof.requestor_address\n' >&2
    exit 1
  fi
  assert_contains "$output" "shared manifest is missing shared_services.proof.requestor_address" "backoffice env rejects missing prover requestor address"
  rm -rf "$workdir"
}

test_render_backoffice_env_preserves_non_loopback_juno_rpc_url() {
  local workdir shared_manifest app_manifest resolved_env backoffice_env
  local fake_bin old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.app_host.juno_rpc_url = "https://juno-rpc.example.invalid" | .app_role.juno_rpc_url = "https://juno-rpc.example.invalid"' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"
  PATH="$old_path"

  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_URLS=https://juno-rpc.example.invalid" "backoffice env preserves non-loopback juno rpc url as the preferred fallback entry"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for non-loopback url"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for non-loopback url"
  rm -rf "$workdir"
}

test_render_backoffice_env_uses_private_operator_juno_rpc_fallback() {
  local workdir shared_manifest app_manifest resolved_env backoffice_env
  local fake_bin old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mkdir -p "$workdir/bin"
  cat >"$workdir/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '10.0.0.12\n'
EOF
  chmod +x "$workdir/bin/aws"

  shared_manifest="$workdir/shared-manifest.json"
  old_path="$PATH"
  PATH="$workdir/bin:$PATH"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  PATH="$old_path"
  app_manifest="$workdir/output/app/app-deploy.json"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin-fake"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"
  PATH="$old_path"

  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_URLS=http://10.0.0.12:18232" "backoffice env derives private operator juno rpc fallback"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_USER=juno" "backoffice env keeps juno rpc user for private operator fallback"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_JUNO_RPC_PASS=rpcpass" "backoffice env keeps juno rpc pass for private operator fallback"
  rm -rf "$workdir"
}

test_require_base_relayer_balance_validates_all_configured_keys() {
  local workdir fake_bin old_path output
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

  cat >"$workdir/operator-secrets.resolved.env" <<'EOF'
BASE_RELAYER_PRIVATE_KEYS=0x1111111111111111111111111111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222222222222222222222222222
EOF

  write_fake_cast "$fake_bin/cast" "$workdir/cast.log" "1300000000000000" "1000"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  set +e
  output="$( ( production_require_base_relayer_balance "$workdir/operator-secrets.resolved.env" "https://base-sepolia.example.invalid" "1000000000000000" ) 2>&1 )"
  status=$?
  set -e
  PATH="$old_path"

  if [[ $status -eq 0 ]]; then
    printf 'expected production_require_base_relayer_balance to fail when any configured relayer signer is underfunded\n' >&2
    exit 1
  fi
  assert_contains "$output" "0x2222222222222222222222222222222222222222 balance 1000 wei is below minimum 1000000000000000 wei" "relayer balance check reports the failing signer"
  assert_contains "$(cat "$workdir/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0xd68c28F414B210a6C519D05159014378A5b8Bc0F" "relayer balance check probes the first signer"
  assert_contains "$(cat "$workdir/cast.log")" "balance --rpc-url https://base-sepolia.example.invalid 0x2222222222222222222222222222222222222222" "relayer balance check probes the second signer"

  rm -rf "$workdir"
}

test_render_app_envs_retarget_runtime_postgres_endpoint_from_shared_manifest() {
  local workdir shared_manifest app_manifest resolved_env bridge_env backoffice_env fake_bin old_path
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://operator:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://app:pw@old-preview.cluster.example.internal:5432/intents?sslmode=require
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$shared_manifest" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$workdir/output" "$workdir"
  production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir"
  app_manifest="$workdir/output/app/app-deploy.json"

  resolved_env="$workdir/resolved-app.env"
  production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_manifest")" "true" "" "" "$resolved_env"
  bridge_env="$workdir/bridge-api.env"
  backoffice_env="$workdir/backoffice.env"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_cast "$fake_bin/cast" "$workdir/cast.log"
  production_render_bridge_api_env "$shared_manifest" "$app_manifest" "$resolved_env" "$bridge_env"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_render_backoffice_env "$shared_manifest" "$app_manifest" "$resolved_env" "$backoffice_env"
  PATH="$old_path"

  assert_contains "$(cat "$bridge_env")" "BRIDGE_API_POSTGRES_DSN=postgres://app:pw@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents?sslmode=require" "bridge env retargets postgres dsn to the shared manifest endpoint"
  assert_contains "$(cat "$backoffice_env")" "BACKOFFICE_POSTGRES_DSN=postgres://app:pw@alpha-shared.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432/intents?sslmode=require" "backoffice env retargets postgres dsn to the shared manifest endpoint"
  assert_not_contains "$(cat "$bridge_env")" "old-preview.cluster.example.internal" "bridge env drops stale secret-contract postgres hosts"
  assert_not_contains "$(cat "$backoffice_env")" "old-preview.cluster.example.internal" "backoffice env drops stale secret-contract postgres hosts"
  rm -rf "$workdir"
}

test_render_app_handoff_rejects_non_https_public_scheme() {
  local workdir shared_manifest
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.app_host.public_scheme = "http" | .app_role.public_scheme = "http"' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  if (
    production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_app_handoff to reject non-https public scheme\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_render_app_handoff_requires_loopback_listeners() {
  local workdir shared_manifest
  workdir="$(mktemp -d)"
  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_AUTH_TOKEN=literal:token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/app-known_hosts"
  cat >"$workdir/app-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
APP_BACKOFFICE_AUTH_SECRET=literal:backoffice-token
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.app_host.bridge_api_listen = "0.0.0.0:8082" | .app_role.bridge_api_listen = "0.0.0.0:8082"' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  if (
    production_render_app_handoff "$workdir/inventory.json" "$shared_manifest" "$workdir/output" "$workdir" >/dev/null 2>&1
  ); then
    printf 'expected production_render_app_handoff to reject non-loopback listeners\n' >&2
    exit 1
  fi
  rm -rf "$workdir"
}

test_write_shared_terraform_override_tfvars_accepts_preview_legacy_wireguard_inventory() {
  local workdir override_file fake_bin old_path
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mkdir -p "$workdir/terraform/live-e2e"
  write_live_e2e_tfvars_fixture "$workdir/terraform/live-e2e/terraform.tfvars"
  jq '
    .shared_services.terraform_dir = "deploy/shared/terraform/live-e2e"
    | .shared_postgres_password = "preview-postgres-password"
    | .shared_postgres_db = "preview-intents-db"
    | .shared_services.live_e2e = {
        allowed_ssh_cidr: "92.98.132.70/32",
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10"
      }
    | .app_role.app_instance_profile_name = "juno-live-e2e-preview0316d-instance-profile"
    | .app_host.backoffice_dns_label = ""
    | .app_host.ops_public_dns_label = "ops"
    | .app_role.app_security_group_id = "sg-approle012345678"
    | del(.shared_services.wireguard.public_subnet_id)
    | del(.shared_roles.wireguard.public_subnet_id)
    | del(.shared_roles.wireguard.public_subnet_ids)
    | del(.shared_roles.wireguard.backoffice_private_endpoint)
    | del(.wireguard_role.public_subnet_id)
    | del(.wireguard_role.public_subnet_ids)
    | del(.wireguard_role.backoffice_private_endpoint)
    | .app_host.private_endpoint = ""
    | .app_role.private_endpoint = ""
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/shared-terraform.auto.tfvars.json"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_live_e2e_describer \
    "$fake_bin/aws" \
    --lt \
    "lt-0123456789abcdef0@1=ami-0d130f29f8f555638"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"
  PATH="$old_path"

  assert_eq "$(jq -r '.aws_region' "$override_file")" "us-east-1" "preview override includes live-e2e aws region"
  assert_eq "$(jq -r '.deployment_id' "$override_file")" "preview0316d" "preview override derives live-e2e deployment id from the instance profile"
  assert_eq "$(jq -r '.allowed_ssh_cidr' "$override_file")" "92.98.132.70/32" "preview override preserves live-e2e ssh cidr"
  assert_eq "$(jq -r '.ssh_public_key' "$override_file")" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10" "preview override preserves live-e2e ssh key"
  assert_eq "$(jq -r '.operator_ami_id' "$override_file")" "ami-0d130f29f8f555638" "preview override preserves the live-e2e operator ami"
  assert_eq "$(jq -r '.operator_instance_count' "$override_file")" "1" "preview override keeps the live-e2e operator count aligned with inventory"
  assert_eq "$(jq -r '.shared_proof_service_image' "$override_file")" "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" "preview override includes live-e2e proof image"
  assert_eq "$(jq -r '.shared_sp1_requestor_secret_arn' "$override_file")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-requestor" "preview override includes live-e2e proof requestor secret"
  assert_eq "$(jq -r '.shared_sp1_funder_secret_arn' "$override_file")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-proof-funder" "preview override includes live-e2e proof funder secret"
  assert_eq "$(jq -r '.shared_base_chain_id' "$override_file")" "84532" "preview override includes live-e2e base chain id"
  assert_eq "$(jq -r '.shared_postgres_password' "$override_file")" "preview-postgres-password" "preview override includes live-e2e postgres password"
  assert_eq "$(jq -r '.shared_postgres_db' "$override_file")" "preview-intents-db" "preview override includes live-e2e postgres db name"
  assert_eq "$(jq -r '.shared_wireguard_enabled' "$override_file")" "true" "preview override enables wireguard"
  assert_eq "$(jq -r '.shared_wireguard_backoffice_hostname' "$override_file")" "ops.alpha.intents-testing.thejunowallet.com" "preview override falls back to legacy ops dns label"
  assert_eq "$(jq -r '.operator_client_security_group_ids[0]' "$override_file")" "sg-approle012345678" "preview override forwards the app runtime sg to live-e2e operator ingress"
  assert_eq "$(jq -r '.shared_service_client_security_group_ids[0]' "$override_file")" "sg-approle012345678" "preview override forwards the app runtime sg to live-e2e shared postgres and msk ingress"
  assert_eq "$(jq -r '.shared_ipfs_client_security_group_ids[0]' "$override_file")" "sg-approle012345678" "preview override forwards the app runtime sg to live-e2e ipfs ingress"
  assert_eq "$(jq -r 'has("shared_wireguard_public_subnet_id")' "$override_file")" "false" "preview override omits the live-e2e wireguard subnet when the inventory relies on module defaults"
  assert_eq "$(jq -r 'has("shared_wireguard_public_subnet_ids")' "$override_file")" "false" "preview override does not write the unsupported plural wireguard subnet input"
  assert_eq "$(jq -r 'has("shared_wireguard_backoffice_private_endpoint_ips")' "$override_file")" "false" "preview override does not write the unsupported plural backoffice endpoint input"
  assert_eq "$(jq -r 'has("shared_wireguard_role_ami_id")' "$override_file")" "false" "preview override does not write the unsupported wireguard ami input"
  assert_eq "$(jq -r 'has("shared_wireguard_backoffice_private_endpoint")' "$override_file")" "false" "preview override omits private endpoint when live-e2e can derive runner private ip"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | length' "$override_file")" "0" "preview override writes an empty reusable VPC endpoint list when the VPC has none"
  rm -rf "$workdir"
}

test_write_shared_terraform_override_tfvars_prefers_persisted_live_e2e_operator_ami() {
  local workdir override_file
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mkdir -p "$workdir/terraform/live-e2e"
  write_live_e2e_tfvars_fixture "$workdir/terraform/live-e2e/terraform.tfvars"
  jq '
    .shared_services.terraform_dir = "deploy/shared/terraform/live-e2e"
    | .shared_postgres_password = "preview-postgres-password"
    | .shared_postgres_db = "preview-intents-db"
    | .shared_services.live_e2e = {
        deployment_id: "preview0316d",
        allowed_ssh_cidr: "92.98.132.70/32",
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10",
        operator_ami_id: "ami-0feedfacecafebeef"
      }
    | .app_role.app_instance_profile_name = "juno-live-e2e-preview0316d-instance-profile"
    | .app_role.app_security_group_id = "sg-approle012345678"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/shared-terraform.auto.tfvars.json"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"

  assert_eq "$(jq -r '.operator_ami_id' "$override_file")" "ami-0feedfacecafebeef" "preview override prefers persisted live-e2e operator ami"
  rm -rf "$workdir"
}

test_write_shared_terraform_override_tfvars_resolves_checkpoint_signer_kms_arns_from_aliases() {
  local workdir override_file fake_bin old_path alias_name
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .shared_services.terraform_dir = "deploy/shared/terraform/live-e2e"
    | .shared_postgres_password = "preview-postgres-password"
    | .shared_postgres_db = "preview-intents-db"
    | .shared_services.live_e2e = {
        deployment_id: "preview0316d",
        allowed_ssh_cidr: "92.98.132.70/32",
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10"
      }
    | .app_role.app_instance_profile_name = "juno-live-e2e-preview0316d-instance-profile"
    | .app_role.app_security_group_id = "sg-approle012345678"
    | .operators[0].checkpoint_signer_kms_key_id = null
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  alias_name="alias/intents-juno-preview-checkpoint-signer-$(jq -r '.operators[0].operator_id | ascii_downcase' "$workdir/inventory.json")"
  override_file="$workdir/shared-terraform.auto.tfvars.json"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_live_e2e_describer \
    "$fake_bin/aws" \
    --kms \
    "$alias_name=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" \
    --lt \
    "lt-0123456789abcdef0@1=ami-0d130f29f8f555638"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"
  PATH="$old_path"

  assert_eq "$(jq -r '.allowed_checkpoint_signer_kms_key_arns | length' "$override_file")" "1" "preview override writes one checkpoint signer kms arn from alias discovery"
  assert_eq "$(jq -r '.allowed_checkpoint_signer_kms_key_arns[0]' "$override_file")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "preview override writes the discovered checkpoint signer kms arn"
  rm -rf "$workdir"
}

test_write_shared_terraform_override_tfvars_reuses_existing_live_e2e_vpc_endpoints() {
  local workdir override_file fake_bin old_path
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  mkdir -p "$workdir/terraform/live-e2e"
  write_live_e2e_tfvars_fixture "$workdir/terraform/live-e2e/terraform.tfvars"
  jq '
    .shared_services.terraform_dir = "deploy/shared/terraform/live-e2e"
    | .shared_services.live_e2e = {
        allowed_ssh_cidr: "92.98.132.70/32",
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSRFy2mYiQokwP/vBOs4jMpqBJQ1LXVsa2GsDslAxem root@162.120.18.10"
      }
    | .app_role.app_instance_profile_name = "juno-live-e2e-preview0316d-instance-profile"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/shared-terraform.auto.tfvars.json"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"
  write_fake_aws_live_e2e_describer \
    "$fake_bin/aws" \
    "com.amazonaws.us-east-1.secretsmanager" \
    "com.amazonaws.us-east-1.s3" \
    "com.amazonaws.us-east-1.sts" \
    "com.amazonaws.us-east-1.kms:deleting" \
    "com.amazonaws.us-east-1.unrelated" \
    --lt \
    "lt-0123456789abcdef0@1=ami-0d130f29f8f555638"
  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  production_write_shared_terraform_override_tfvars "$workdir/inventory.json" "$override_file"
  PATH="$old_path"

  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | length' "$override_file")" "3" "preview override records the reusable shared endpoint services returned by aws"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | index("com.amazonaws.us-east-1.secretsmanager") != null' "$override_file")" "true" "preview override keeps the reusable Secrets Manager endpoint"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | index("com.amazonaws.us-east-1.s3") != null' "$override_file")" "true" "preview override keeps the reusable S3 endpoint"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | index("com.amazonaws.us-east-1.sts") != null' "$override_file")" "true" "preview override keeps the reusable STS endpoint"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | index("com.amazonaws.us-east-1.kms") != null' "$override_file")" "false" "preview override ignores endpoints that are not in a reusable state"
  assert_eq "$(jq -r '.shared_existing_vpc_endpoint_services | index("com.amazonaws.us-east-1.unrelated") != null' "$override_file")" "false" "preview override ignores unrelated VPC endpoint services"
  rm -rf "$workdir"
}

test_write_app_terraform_override_tfvars_includes_additional_public_bridge_certificates() {
  local workdir override_file
  workdir="$(mktemp -d)"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .app_role.public_bridge_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/origin-preview"
    | .app_role.public_bridge_additional_certificate_arns = ["arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview"]
    | .app_role.internal_backoffice_certificate_arn = "arn:aws:acm:us-east-1:021490342184:certificate/ops-preview"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  override_file="$workdir/app-terraform.auto.tfvars.json"
  production_write_app_terraform_override_tfvars "$workdir/inventory.json" "$override_file"

  assert_eq "$(jq -r '.public_bridge_certificate_arn' "$override_file")" "arn:aws:acm:us-east-1:021490342184:certificate/origin-preview" "app runtime tfvars use the origin certificate as the default public bridge listener cert"
  assert_eq "$(jq -r '.public_bridge_additional_certificate_arns[0]' "$override_file")" "arn:aws:acm:us-east-1:021490342184:certificate/bridge-preview" "app runtime tfvars preserve the bridge hostname cert as an additional listener certificate"
  rm -rf "$workdir"
}

test_provision_checkpoint_signer_kms_wrapper_runs_from_repo_root() {
  local workdir fakebin log_file output_file expected_repo_root
  workdir="$(mktemp -d)"
  fakebin="$workdir/go"
  log_file="$workdir/go.log"
  output_file="$workdir/output.json"
  expected_repo_root="$REPO_ROOT"

  cat >"$fakebin" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'pwd=%s\n' "\$PWD" >"$log_file"
printf 'args=%s\n' "\$*" >>"$log_file"
printf '{"keyArn":"arn:aws:kms:us-east-1:021490342184:key/test"}\n'
EOF
  chmod +x "$fakebin"

  (
    cd "$workdir"
    PATH="$workdir:$PATH" \
      "$REPO_ROOT/deploy/production/provision-checkpoint-signer-kms.sh" --operator-id op1 >"$output_file"
  )

  assert_contains "$(cat "$log_file")" "pwd=$expected_repo_root" "checkpoint signer kms wrapper runs from repo root"
  assert_contains "$(cat "$log_file")" "args=run ./cmd/provision-checkpoint-signer-kms --operator-id op1" "checkpoint signer kms wrapper uses module-relative go run"
  assert_contains "$(cat "$output_file")" '"keyArn":"arn:aws:kms:us-east-1:021490342184:key/test"' "checkpoint signer kms wrapper preserves command output"
  rm -rf "$workdir"
}

test_production_run_release_binary_executes_directly_on_host_when_runner_not_required() {
  local workdir fake_binary log_file
  workdir="$(mktemp -d)"
  fake_binary="$workdir/fake-release-binary.sh"
  log_file="$workdir/binary.log"

  cat >"$fake_binary" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'binary %s\n' "\$*" >>"$log_file"
EOF
  chmod +x "$fake_binary"

  PRODUCTION_HOST_OS_OVERRIDE=Linux production_run_release_binary "$fake_binary" --hello world

  assert_contains "$(cat "$log_file")" "binary --hello world" "release binary runs directly on linux hosts"
  rm -rf "$workdir"
}

test_production_run_release_binary_uses_docker_runner_when_forced() {
  local workdir fake_binary binary_log fake_docker docker_log path_backup
  workdir="$(mktemp -d)"
  fake_binary="$REPO_ROOT/tmp/test-release-binary.sh"
  binary_log="$workdir/binary.log"
  fake_docker="$workdir/docker"
  docker_log="$workdir/docker.log"
  path_backup="$PATH"

  cat >"$fake_binary" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'binary %s\n' "\$*" >>"$binary_log"
EOF
  chmod +x "$fake_binary"
  write_fake_docker_runner "$fake_docker" "$docker_log"

  PATH="$workdir:$PATH" \
    PRODUCTION_FORCE_RELEASE_BINARY_RUNNER=true \
    production_run_release_binary "$fake_binary" --hello container

  assert_contains "$(cat "$docker_log")" "--platform linux/amd64" "docker runner uses linux amd64 platform"
  assert_contains "$(cat "$docker_log")" "image=docker.io/library/golang:1.24.13-bookworm" "docker runner uses pinned image"
  assert_contains "$(cat "$docker_log")" "-v $REPO_ROOT:$REPO_ROOT" "docker runner mounts the repo root"
  assert_contains "$(cat "$binary_log")" "binary --hello container" "docker runner executes the release binary command"

  rm -f "$fake_binary"
  PATH="$path_backup"
  rm -rf "$workdir"
}

test_production_maybe_use_public_sts_endpoint_sets_global_override_for_private_regional_resolution() {
  unset AWS_ENDPOINT_URL_STS
  export PRODUCTION_TEST_STS_REGIONAL_IPS="10.0.11.214
10.0.10.99"

  production_maybe_use_public_sts_endpoint "us-east-1"

  assert_eq "${AWS_ENDPOINT_URL_STS:-}" "https://sts.amazonaws.com" "private regional sts resolution forces the public global sts endpoint"

  unset PRODUCTION_TEST_STS_REGIONAL_IPS
  unset AWS_ENDPOINT_URL_STS
}

test_production_maybe_use_public_sts_endpoint_preserves_existing_override() {
  export AWS_ENDPOINT_URL_STS="https://custom.example.internal"
  export PRODUCTION_TEST_STS_REGIONAL_IPS="10.0.11.214"

  production_maybe_use_public_sts_endpoint "us-east-1"

  assert_eq "$AWS_ENDPOINT_URL_STS" "https://custom.example.internal" "existing sts endpoint override wins"

  unset PRODUCTION_TEST_STS_REGIONAL_IPS
  unset AWS_ENDPOINT_URL_STS
}

test_production_maybe_use_public_sts_endpoint_skips_public_regional_resolution() {
  unset AWS_ENDPOINT_URL_STS
  export PRODUCTION_TEST_STS_REGIONAL_IPS="54.239.29.1"

  production_maybe_use_public_sts_endpoint "us-east-1"

  assert_eq "${AWS_ENDPOINT_URL_STS:-}" "" "public regional sts resolution does not force the global sts endpoint"

  unset PRODUCTION_TEST_STS_REGIONAL_IPS
}

test_production_ssm_run_shell_command_executes_payload_via_bash() {
  local workdir fake_aws aws_log stdout path_backup
  workdir="$(mktemp -d)"
  fake_aws="$workdir/aws"
  aws_log="$workdir/aws.log"
  path_backup="$PATH"

  cat >"$fake_aws" <<'EOF'
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
  ssm\ send-command\ --instance-ids\ i-1234567890abcdef0\ --document-name\ AWS-RunShellScript\ --parameters\ file://*\ --output\ json)
    parameters_path="${args[7]#file://}"
    jq -r '.commands[0]' "$parameters_path" >"$TEST_AWS_COMMAND_LOG"
    printf '{"Command":{"CommandId":"cmd-123"}}\n'
    ;;
  "ssm get-command-invocation --command-id cmd-123 --instance-id i-1234567890abcdef0 --output json")
    printf '{"Status":"Success","StandardOutputContent":"ok","StandardErrorContent":""}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$fake_aws"

  PATH="$workdir:$PATH"
  export TEST_AWS_LOG="$aws_log"
  export TEST_AWS_COMMAND_LOG="$workdir/command.log"
  stdout="$(production_ssm_run_shell_command "juno" "us-east-1" "i-1234567890abcdef0" $'set -euo pipefail\nprintf "hello\\n"' 1 0)"

  assert_eq "$stdout" "ok" "ssm helper returns command stdout"
  assert_contains "$(cat "$TEST_AWS_COMMAND_LOG")" "base64 -d >\"\$tmp_script\"" "ssm helper stages the payload via base64"
  assert_contains "$(cat "$TEST_AWS_COMMAND_LOG")" "bash \"\$tmp_script\"" "ssm helper executes the staged payload with bash"
  assert_not_contains "$(cat "$TEST_AWS_COMMAND_LOG")" "set -euo pipefail" "ssm helper does not hand raw bash-only syntax to sh"

  unset TEST_AWS_LOG
  unset TEST_AWS_COMMAND_LOG
  PATH="$path_backup"
  rm -rf "$workdir"
}

main() {
  setup_default_checkpoint_signer_kms_provisioner
  trap cleanup_default_checkpoint_signer_kms_provisioner EXIT
  test_resolve_secret_contract_allows_alpha_literals
  test_resolve_secret_contract_rejects_literals_outside_alpha
  test_render_shared_manifest_and_handoffs
  test_render_shared_manifest_prefers_role_outputs_for_shared_proof_and_wireguard
  test_render_shared_manifest_synthesizes_legacy_wireguard_peer_roster_from_client_config_secret
  test_render_shared_manifest_derives_base_event_scanner_start_block_from_transactions
  test_render_shared_manifest_prefers_inventory_owallet_ua
  test_render_shared_manifest_rejects_mismatched_juno_network
  test_render_shared_manifest_rejects_nonroutable_dkg_endpoints
  test_render_shared_manifest_requires_signer_ufvk
  test_render_shared_manifest_uses_completion_fallback_for_signer_ufvk
  test_render_operator_stack_env_uses_kms_contract
  test_render_operator_handoffs_rejects_local_checkpoint_signer_driver
  test_render_operator_handoffs_preserves_secure_preview_signer_configuration
  test_render_operator_handoffs_derives_withdraw_extend_signer_keys_from_dkg_summary
  test_render_operator_handoffs_provisions_missing_checkpoint_signer_kms_key
  test_resolve_checkpoint_signer_kms_key_id_uses_explicit_arn_without_provisioner
  test_render_operator_handoffs_derives_owallet_keys_from_signer_ufvk
  test_render_operator_handoffs_preserves_explicit_owallet_keys
  test_render_operator_handoffs_preserves_dkg_tls_dir
  test_render_operator_stack_env_prefers_operator_checkpoint_blob_storage
  test_render_operator_stack_env_retargets_runtime_values_from_shared_manifest
  test_render_operator_stack_env_rejects_local_checkpoint_signer_driver
  test_render_operator_stack_env_preserves_secure_preview_signer_configuration
  test_render_operator_stack_env_enables_deposit_scan_from_withdraw_wallet_id
  test_render_operator_stack_env_prefers_inline_ipfs_bearer_token
  test_render_operator_stack_env_prefers_inline_queueauth_hmac_key
  test_render_operator_stack_env_adds_base_sepolia_deposit_relayer_fallback
  test_render_operator_stack_env_requires_juno_rpc_credentials
  test_render_operator_stack_env_rejects_withdraw_expiry_overrides
  test_render_operator_stack_env_rejects_private_key_with_kms_contract
  test_render_junocashd_conf_uses_juno_rpc_credentials
  test_rollout_state_enforces_one_operator_at_a_time
  test_render_app_handoff_and_envs
  test_render_app_handoff_and_envs_allow_missing_backoffice_juno_rpc_url
  test_render_manifests_allow_external_dns_without_route53_zone
  test_render_backoffice_env_preserves_non_loopback_juno_rpc_url
  test_render_backoffice_env_uses_private_operator_juno_rpc_fallback
  test_render_app_envs_retarget_runtime_postgres_endpoint_from_shared_manifest
  test_render_app_handoff_prefers_public_operator_endpoints_when_public_endpoints_are_present
  test_render_app_handoff_defaults_operator_ports_by_index_when_dkg_summary_lacks_endpoints
  test_render_app_handoff_rejects_non_https_public_scheme
  test_render_app_handoff_requires_loopback_listeners
  test_write_shared_terraform_override_tfvars_writes_full_production_shared_tfvars
  test_write_shared_terraform_override_tfvars_includes_operator_private_network_cidrs
  test_write_shared_terraform_override_tfvars_accepts_preview_legacy_wireguard_inventory
  test_write_shared_terraform_override_tfvars_prefers_persisted_live_e2e_operator_ami
  test_write_app_terraform_override_tfvars_includes_additional_public_bridge_certificates
  test_provision_checkpoint_signer_kms_wrapper_runs_from_repo_root
  test_production_run_release_binary_executes_directly_on_host_when_runner_not_required
  test_production_run_release_binary_uses_docker_runner_when_forced
  test_production_maybe_use_public_sts_endpoint_sets_global_override_for_private_regional_resolution
  test_production_maybe_use_public_sts_endpoint_preserves_existing_override
  test_production_maybe_use_public_sts_endpoint_skips_public_regional_resolution
  test_production_ssm_run_shell_command_executes_payload_via_bash
}

main "$@"
