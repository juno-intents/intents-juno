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
  if grep -Fq -- "$needle" <<<"$haystack"; then
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

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  local balance_wei="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  printf '0x1111111111111111111111111111111111111111\n'
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  printf '%s\n' "$balance_wei"
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_terraform_binary() {
  local target="$1"
  local log_file="$2"
  local output_fixture="$3"
  local app_output_fixture="${4:-$3}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'terraform %s\n' "\$*" >>"$log_file"
printf 'terraform-cwd %s\n' "\$PWD" >>"$log_file"
printf 'terraform-env AWS_ENDPOINT_URL_STS=%s\n' "\${AWS_ENDPOINT_URL_STS:-}" >>"$log_file"
case "\${1:-}" in
  init|apply)
    for arg in "\$@"; do
      if [[ "\$arg" == -var-file=* ]]; then
        printf 'terraform-var-file %s\n' "\${arg#-var-file=}" >>"$log_file"
        printf 'terraform-var-file-contents %s\n' "\$(tr '\n' ' ' <"\${arg#-var-file=}")" >>"$log_file"
      fi
    done
    exit 0
    ;;
  output)
    [[ "\${2:-}" == "-json" ]] || {
      printf 'unexpected terraform output invocation: %s\n' "\$*" >&2
      exit 1
    }
    case "\$PWD" in
      */app-runtime)
        cat "$app_output_fixture"
        ;;
      *)
        cat "$output_fixture"
        ;;
    esac
    exit 0
    ;;
esac
printf 'unexpected terraform invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_role_runtime_release_resolver() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'resolve-role-runtime-release-inputs %s\n' "\$*" >>"$log_file"
inventory=""
output=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --inventory) inventory="\$2"; shift 2 ;;
    --output) output="\$2"; shift 2 ;;
    --github-repo|--aws-profile|--aws-region) shift 2 ;;
    *) echo "unexpected resolver arg: \$1" >&2; exit 1 ;;
  esac
done
[[ -n "\$inventory" && -n "\$output" ]] || {
  echo "resolver requires --inventory and --output" >&2
  exit 1
}
jq '
  .app_role.app_ami_id = "ami-0resolvedapp1234567"
  | .shared_roles.proof.image_uri = "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:resolved"
  | .shared_roles.proof.image_ecr_repository_arn = "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"
  | .shared_roles.wireguard.ami_id = "ami-0resolvedwireguard1"
  | .wireguard_role.ami_id = "ami-0resolvedwireguard1"
' "\$inventory" >"\$output"
EOF
  chmod +x "$target"
}

write_fake_provision_app_edge_binary() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'provision-app-edge %s\n' "\$*" >>"$log_file"
exit 0
EOF
  chmod +x "$target"
}

write_fake_ready_canary_binary() {
  local target="$1"
  local log_file="$2"
  local label="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$label" "\$*" >>"$log_file"
cat <<'JSON'
{"ready_for_deploy":true}
JSON
EOF
  chmod +x "$target"
}

write_fake_aws_backend_bootstrap() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"
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

write_local_sha256_file() {
  local input="$1"
  local output="$2"
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$input" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$input" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$(basename "$input")" >"$output"
}

write_fake_gh_release_downloader() {
  local target="$1"
  local release_root="$2"
  local log_file="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "release" && "\$2" == "download" ]]; then
  tag="\$3"
  shift 3
  dir=""
  patterns=()
  while [[ \$# -gt 0 ]]; do
    case "\$1" in
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
        printf 'unexpected gh release download arg: %s\n' "\$1" >&2
        exit 1
        ;;
    esac
  done
  [[ -n "\$dir" ]] || {
    printf 'missing --dir\n' >&2
    exit 1
  }
  mkdir -p "\$dir"
  for pattern in "\${patterns[@]}"; do
    cp "$release_root/\$tag/\$pattern" "\$dir/\$pattern"
  done
  exit 0
fi
printf 'unexpected gh invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_bridge_deploy_binary() {
  local target="$1"
  local log_file="$2"
  local bridge_summary_fixture="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'bridge-e2e %s\n' "\$*" >>"$log_file"
if [[ "\${1:-}" == "deploy" ]]; then
  printf 'unexpected subcommand invocation: %s\n' "\$*" >&2
  exit 1
fi
deploy_only="false"
output_path=""
has_dkg_summary="false"
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --deploy-only) deploy_only="true"; shift ;;
    --output) output_path="\$2"; shift 2 ;;
    --dkg-summary) has_dkg_summary="true"; shift 2 ;;
    *) shift ;;
  esac
done
[[ "\$deploy_only" == "true" ]] || {
  printf 'expected --deploy-only flag\n' >&2
  exit 1
}
[[ -n "\$output_path" ]] || {
  printf 'missing --output path\n' >&2
  exit 1
}
[[ "\$has_dkg_summary" == "false" ]] || {
  printf 'unexpected --dkg-summary path\n' >&2
  exit 1
}
cp "$bridge_summary_fixture" "\$output_path"
EOF
  chmod +x "$target"
}

write_fake_production_bridge_deploy_binary() {
  local target="$1"
  local log_file="$2"
  local bridge_summary_fixture="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'bridge-deploy %s\n' "\$*" >>"$log_file"
output_path=""
has_governance_safe="false"
has_pause_guardian="false"
has_deploy_only="false"
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --output) output_path="\$2"; shift 2 ;;
    --governance-safe) has_governance_safe="true"; shift 2 ;;
    --pause-guardian) has_pause_guardian="true"; shift 2 ;;
    --deploy-only) has_deploy_only="true"; shift ;;
    *) shift ;;
  esac
done
[[ "\$has_deploy_only" == "false" ]] || {
  printf 'unexpected --deploy-only flag\n' >&2
  exit 1
}
[[ "\$has_governance_safe" == "true" ]] || {
  printf 'missing --governance-safe\n' >&2
  exit 1
}
[[ "\$has_pause_guardian" == "true" ]] || {
  printf 'missing --pause-guardian\n' >&2
  exit 1
}
[[ -n "\$output_path" ]] || {
  printf 'missing --output path\n' >&2
  exit 1
}
cp "$bridge_summary_fixture" "\$output_path"
EOF
  chmod +x "$target"
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
    --arg app_private_endpoint "10.0.10.21" \
    --arg wireguard_public_subnet_id "subnet-0abc1234def567890" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
      | .operators[0].asg = "juno-op1"
      | .operators[0].launch_template = {"id":"lt-0123456789abcdef0","version":"1"}
      | .app_host.known_hosts_file = $app_kh
      | .app_host.secret_contract_file = $app_secrets
      | .app_host.private_endpoint = $app_private_endpoint
      | .app_host.publish_public_dns = false
      | .shared_services.wireguard.public_subnet_id = $wireguard_public_subnet_id
      | .app_role = {
          host: "203.0.113.21",
          user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/app-runtime",
          public_endpoint: "203.0.113.21",
          private_endpoint: $app_private_endpoint,
          terraform_dir: "deploy/shared/terraform/app-runtime",
          vpc_id: "vpc-0123456789abcdef0",
          public_subnet_ids: ["subnet-0apppublica", "subnet-0apppublicb"],
          private_subnet_ids: ["subnet-0appprivatea", "subnet-0appprivateb"],
          app_ami_id: "ami-0123456789abcdef0",
          ami_release_tag: "app-runtime-ami-v1.2.3-testnet",
          app_instance_profile_name: "juno-app-role",
          public_bridge_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/public-bridge",
          internal_backoffice_certificate_arn: "arn:aws:acm:us-east-1:021490342184:certificate/internal-backoffice",
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
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
      | .shared_roles.proof = {
          requestor_address: "0x1234567890abcdef1234567890abcdef12345678",
          rpc_url: "https://rpc.mainnet.succinct.xyz",
          image_release_tag: "shared-proof-services-image-v1.2.3-testnet",
          image_uri: "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
          image_ecr_repository_arn: "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"
        }
      | .shared_roles.wireguard = {
          public_subnet_id: $wireguard_public_subnet_id,
          public_subnet_ids: [$wireguard_public_subnet_id],
          listen_port: 51820,
          network_cidr: "10.66.0.0/24",
          backoffice_hostname: "ops.alpha.intents-testing.thejunowallet.com",
          backoffice_private_endpoint: $app_private_endpoint,
          source_cidrs: ["10.0.2.50/32"],
          client_config_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-client-config",
          endpoint_host: "198.51.100.25",
          ami_id: "ami-0wireguard1234567",
          publish_public_dns: false
        }
      | .wireguard_role = .shared_roles.wireguard
      | .wireguard_role.ami_release_tag = "wireguard-role-ami-v1.2.3-testnet"
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_deploy_coordinator_generates_handoffs() {
  local workdir output_dir manifest operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  manifest="$output_dir/alpha/shared-manifest.json"
  operator_dir="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111"
  assert_file_exists "$manifest" "shared manifest"
  assert_file_exists "$output_dir/alpha/rollout-state.json" "rollout state"
  assert_file_exists "$operator_dir/operator-deploy.json" "operator manifest"
  assert_file_exists "$output_dir/alpha/app/app-deploy.json" "app manifest"
  assert_eq "$(jq -r '.environment' "$manifest")" "alpha" "manifest environment"
  assert_eq "$(jq -r '.contracts.juno_network' "$manifest")" "testnet" "manifest juno network"
  assert_eq "$(jq -r '.governance.timelock.address' "$manifest")" "0x8888888888888888888888888888888888888888" "timelock address"
  assert_eq "$(jq -r '.dns.record_name' "$operator_dir/operator-deploy.json")" "op1.alpha.intents-testing.thejunowallet.com" "operator dns record"
  assert_eq "$(jq -r '.operator_address' "$operator_dir/operator-deploy.json")" "0x9999999999999999999999999999999999999999" "operator signer address"
  assert_eq "$(jq -r '.checkpoint_signer_driver' "$operator_dir/operator-deploy.json")" "aws-kms" "operator signer driver"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$operator_dir/operator-deploy.json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "operator signer kms key id"
  assert_eq "$(jq -r '.services.bridge_api.public_url' "$output_dir/alpha/app/app-deploy.json")" "https://bridge.alpha.intents-testing.thejunowallet.com" "app manifest bridge url"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[0]' "$output_dir/alpha/app/app-deploy.json")" "10.0.2.50/32" "app manifest wireguard source cidr"
  rm -rf "$workdir"
}

test_deploy_coordinator_prefers_role_outputs_in_shared_and_app_handoffs() {
  local workdir output_dir fake_bin log_dir shared_tf_json app_tf_json
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  shared_tf_json="$workdir/shared-terraform-output.json"
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
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$shared_tf_json"
  app_tf_json="$workdir/app-terraform-output.json"
  jq -n '
    {
      app_role: {
        value: {
          asg: "alpha-app-role",
          launch_template: { id: "lt-app0123456789abcdef", version: "13" },
          public_lb: {
            dns_name: "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678"
          },
          internal_lb: {
            dns_name: "internal-ops-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z2P70J7EXAMPLE",
            security_group_id: "sg-internalops012345678"
          }
        }
      }
    }
  ' >"$app_tf_json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --shared-terraform-output-json "$shared_tf_json" \
    --app-terraform-output-json "$app_tf_json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_eq "$(jq -r '.shared_roles.proof.asg' "$output_dir/alpha/shared-manifest.json")" "alpha-proof-role" "deploy coordinator prefers proof role asg"
  assert_eq "$(jq -r '.wireguard_role.server_key_secret_arn' "$output_dir/alpha/shared-manifest.json")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key" "deploy coordinator renders wireguard server key secret"
  assert_eq "$(jq -r '.app_role.asg' "$output_dir/alpha/app/app-deploy.json")" "alpha-app-role" "deploy coordinator prefers app role asg"
  assert_eq "$(jq -r '.app_role.public_lb.dns_name' "$output_dir/alpha/app/app-deploy.json")" "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com" "deploy coordinator prefers app role public load balancer"
  assert_eq "$(jq -r '.edge.public_lb_dns_name' "$output_dir/alpha/app/app-deploy.json")" "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com" "deploy coordinator renders edge from the public load balancer"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[0]' "$output_dir/alpha/app/app-deploy.json")" "10.0.20.0/24" "deploy coordinator prefers wireguard role source cidrs"
  assert_eq "$(jq -r '.services.backoffice.access.source_cidrs[1]' "$output_dir/alpha/app/app-deploy.json")" "10.0.21.0/24" "deploy coordinator keeps all wireguard role source cidrs"
  rm -rf "$workdir"
}

test_deploy_coordinator_resolves_role_runtime_inputs_and_runs_post_deploy_checks() {
  local workdir output_dir fake_bin log_dir shared_tf_json app_tf_json resolver_log provision_log shared_canary_log app_canary_log
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  resolver_log="$log_dir/resolver.log"
  provision_log="$log_dir/provision.log"
  shared_canary_log="$log_dir/shared-canary.log"
  app_canary_log="$log_dir/app-canary.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  jq '
    .app_role.app_ami_id = ""
    | .shared_roles.proof.image_uri = ""
    | .shared_roles.proof.image_ecr_repository_arn = ""
    | .shared_roles.wireguard.ami_id = ""
    | .wireguard_role.ami_id = ""
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_role_runtime_release_resolver "$fake_bin/resolve-role-runtime-release-inputs.sh" "$resolver_log"
  write_fake_provision_app_edge_binary "$fake_bin/provision-app-edge.sh" "$provision_log"
  write_fake_ready_canary_binary "$fake_bin/canary-shared-services.sh" "$shared_canary_log" "canary-shared-services"
  write_fake_ready_canary_binary "$fake_bin/canary-app-host.sh" "$app_canary_log" "canary-app-host"

  shared_tf_json="$workdir/shared-terraform-output.json"
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
        peer_roster_secret_arns: ["arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-peer-ops-laptop"],
        server_key_secret_arn: "arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-wireguard-server-key"
      }
    }
  ' "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$shared_tf_json"
  app_tf_json="$workdir/app-terraform-output.json"
  jq -n '
    {
      app_role: {
        value: {
          asg: "alpha-app-role",
          launch_template: { id: "lt-app0123456789abcdef", version: "13" },
          public_lb: {
            dns_name: "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678",
            target_group_arn: "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/bridge/1234"
          },
          internal_lb: {
            dns_name: "internal-ops-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z2P70J7EXAMPLE",
            security_group_id: "sg-internalops012345678",
            target_group_arn: "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/backoffice/1234"
          }
        }
      }
    }
  ' >"$app_tf_json"

  PATH="$fake_bin:$PATH" \
  PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN="$fake_bin/resolve-role-runtime-release-inputs.sh" \
  PRODUCTION_PROVISION_APP_EDGE_BIN="$fake_bin/provision-app-edge.sh" \
  PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
  PRODUCTION_CANARY_APP_BIN="$fake_bin/canary-app-host.sh" \
    bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$workdir/inventory.json" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --shared-terraform-output-json "$shared_tf_json" \
      --app-terraform-output-json "$app_tf_json" \
      --skip-terraform-apply \
      --run-post-deploy-checks \
      --output-dir "$output_dir" >/dev/null

  assert_file_exists "$output_dir/alpha/inventory.release-resolved.json" "deploy coordinator writes resolved role runtime inventory"
  assert_eq "$(jq -r '.app_role.app_ami_id' "$output_dir/alpha/inventory.release-resolved.json")" "ami-0resolvedapp1234567" "deploy coordinator resolves app ami id before tfvars"
  assert_eq "$(jq -r '.wireguard_role.ami_id' "$output_dir/alpha/inventory.release-resolved.json")" "ami-0resolvedwireguard1" "deploy coordinator resolves wireguard ami id before tfvars"
  assert_contains "$(cat "$resolver_log")" "--github-repo juno-intents/intents-juno" "deploy coordinator forwards the default github repo to the release resolver"
  assert_contains "$(cat "$provision_log")" "--app-deploy $output_dir/alpha/app/app-deploy.json" "deploy coordinator provisions the app edge from the rendered handoff"
  assert_contains "$(cat "$shared_canary_log")" "--shared-manifest $output_dir/alpha/shared-manifest.json" "deploy coordinator runs the shared canary after rendering the manifest"
  assert_contains "$(cat "$app_canary_log")" "--app-deploy $output_dir/alpha/app/app-deploy.json" "deploy coordinator runs the app canary after rendering the handoff"
  assert_file_exists "$output_dir/alpha/canaries/shared-services.json" "deploy coordinator stores the shared canary output"
  assert_file_exists "$output_dir/alpha/canaries/app.json" "deploy coordinator stores the app canary output"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_dir/alpha/canaries/shared-services.json")" "true" "deploy coordinator requires a passing shared canary"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_dir/alpha/canaries/app.json")" "true" "deploy coordinator requires a passing app canary"
  rm -rf "$workdir"
}

test_deploy_coordinator_supports_run_label() {
  local workdir output_dir run_dir operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" \
    --run-label "run-fixed" >/dev/null

  run_dir="$output_dir/alpha/run-fixed"
  operator_dir="$run_dir/operators/0x1111111111111111111111111111111111111111"
  assert_file_exists "$run_dir/shared-manifest.json" "run label shared manifest"
  assert_file_exists "$run_dir/rollout-state.json" "run label rollout state"
  assert_file_exists "$operator_dir/operator-deploy.json" "run label operator manifest"
  assert_file_exists "$run_dir/app/app-deploy.json" "run label app manifest"
  assert_eq "$(jq -r '.shared_manifest_path' "$operator_dir/operator-deploy.json")" "$run_dir/shared-manifest.json" "run label shared manifest path"
  assert_eq "$(jq -r '.rollout_state_file' "$operator_dir/operator-deploy.json")" "$run_dir/rollout-state.json" "run label rollout state path"
  assert_eq "$(jq -r '.shared_manifest_path' "$run_dir/app/app-deploy.json")" "$run_dir/shared-manifest.json" "run label app shared manifest path"
  assert_eq "$(jq -r '.version' "$run_dir/shared-manifest.json")" "2" "run label shared manifest version"
  assert_eq "$(jq -r '.version' "$run_dir/app/app-deploy.json")" "2" "run label app deploy version"
  assert_eq "$(jq -r '.services.backoffice.access.publish_public_dns' "$run_dir/app/app-deploy.json")" "false" "run label app deploy suppresses public backoffice dns"
  rm -rf "$workdir"
}

test_deploy_coordinator_supports_preview_legacy_wireguard_inventory() {
  local workdir output_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  jq '
    .shared_services.terraform_dir = "deploy/shared/terraform/live-e2e"
    | .app_host.backoffice_dns_label = ""
    | .app_host.ops_public_dns_label = "ops"
    | del(.shared_services.wireguard.public_subnet_id)
    | .app_host.private_endpoint = ""
    | .app_host.publish_public_dns = true
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_eq "$(jq -r '.services.backoffice.record_name // empty' "$output_dir/alpha/app/app-deploy.json")" "" "preview legacy inventory suppresses backoffice record name"
  rm -rf "$workdir"
}

test_deploy_coordinator_materializes_dkg_tls_bundle_when_inventory_omits_it() {
  local workdir output_dir fake_bin log_dir operator_dir dkg_tls_dir cert_purpose san_text
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  dkg_tls_dir="$output_dir/alpha/dkg-tls"
  operator_dir="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111"
  assert_file_exists "$dkg_tls_dir/ca.pem" "generated dkg ca cert"
  assert_file_exists "$dkg_tls_dir/ca.key" "generated dkg ca key"
  assert_file_exists "$dkg_tls_dir/coordinator-client.pem" "generated dkg coordinator client cert"
  assert_file_exists "$dkg_tls_dir/coordinator-client.key" "generated dkg coordinator client key"
  assert_eq "$(jq -r '.dkg_tls_dir' "$operator_dir/operator-deploy.json")" "../../dkg-tls" "operator manifest rewrites dkg tls dir to shared relative path"

  cert_purpose="$(openssl x509 -in "$dkg_tls_dir/coordinator-client.pem" -noout -purpose 2>/dev/null)"
  assert_contains "$cert_purpose" "SSL client : Yes" "generated dkg coordinator client cert supports client auth"
  san_text="$(openssl x509 -in "$dkg_tls_dir/coordinator-client.pem" -noout -ext subjectAltName 2>/dev/null)"
  assert_contains "$san_text" "DNS:coordinator-client" "generated dkg coordinator client cert keeps coordinator SAN"
  rm -rf "$workdir"
}

test_deploy_coordinator_uses_bridge_e2e_deploy_contract() {
  local workdir output_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  cat >"$workdir/deployer.key" <<'EOF'
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_production_bridge_deploy_binary "$fake_bin/bridge-deploy" "$log_dir/bridge.log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --bridge-deploy-binary "$fake_bin/bridge-deploy" \
    --deployer-key-file "$workdir/deployer.key" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_contains "$(cat "$log_dir/bridge.log")" '--contracts-out /Users/ardud/intents-juno/monorepo/contracts/out' "bridge deploy uses repo contracts output"
  assert_contains "$(cat "$log_dir/bridge.log")" '--threshold 2' "bridge deploy forwards dkg threshold"
  assert_contains "$(cat "$log_dir/bridge.log")" '--verifier-address 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B' "bridge deploy forwards verifier address"
  assert_contains "$(cat "$log_dir/bridge.log")" '--deposit-image-id 0x000000000000000000000000000000000000000000000000000000000000aa01' "bridge deploy forwards deposit image id"
  assert_contains "$(cat "$log_dir/bridge.log")" '--withdraw-image-id 0x000000000000000000000000000000000000000000000000000000000000aa02' "bridge deploy forwards withdraw image id"
  assert_contains "$(cat "$log_dir/bridge.log")" '--governance-safe 0x4444444444444444444444444444444444444444' "bridge deploy forwards governance safe"
  assert_contains "$(cat "$log_dir/bridge.log")" '--pause-guardian 0x5555555555555555555555555555555555555555' "bridge deploy forwards pause guardian"
  assert_contains "$(cat "$log_dir/bridge.log")" '--min-deposit-admin-address 0x1111111111111111111111111111111111111111' "bridge deploy forwards min deposit admin address"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x1111111111111111111111111111111111111111' "bridge deploy forwards first operator"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x6666666666666666666666666666666666666666' "bridge deploy forwards second operator"
  assert_contains "$(cat "$log_dir/bridge.log")" '--operator-address 0x7777777777777777777777777777777777777777' "bridge deploy forwards third operator"
  assert_not_contains "$(cat "$log_dir/bridge.log")" '--dkg-summary' "bridge deploy does not pass dkg summary"
  assert_not_contains "$(cat "$log_dir/bridge.log")" '--deploy-only' "production deploy does not pass legacy deploy-only flag"
  assert_file_exists "$output_dir/alpha/bridge-summary.json" "bridge deploy summary"
  rm -rf "$workdir"
}

test_deploy_coordinator_forwards_ephemeral_funder_mode() {
  local workdir output_dir fake_bin log_dir bridge_log
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  bridge_log="$log_dir/bridge.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  cat >"$workdir/funder.key" <<'EOF'
0x59c6995e998f97a5a0044966f09453883f4b8f3359aa4fcf3e4a76fb3f8d5c11
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_production_bridge_deploy_binary "$fake_bin/bridge-deploy" "$bridge_log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --bridge-deploy-binary "$fake_bin/bridge-deploy" \
    --funder-key-file "$workdir/funder.key" \
    --ephemeral-funding-amount-wei 123456789 \
    --sweep-recipient 0x9999999999999999999999999999999999999999 \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_contains "$(cat "$bridge_log")" "--funder-key-file $workdir/funder.key" "bridge deploy forwards funder key file"
  assert_contains "$(cat "$bridge_log")" "--ephemeral-funding-amount-wei 123456789" "bridge deploy forwards ephemeral funding amount"
  assert_contains "$(cat "$bridge_log")" "--sweep-recipient 0x9999999999999999999999999999999999999999" "bridge deploy forwards sweep recipient"
  assert_not_contains "$(cat "$bridge_log")" "--deployer-key-file" "bridge deploy omits direct deployer key in ephemeral mode"
  rm -rf "$workdir"
}

test_deploy_coordinator_rejects_direct_deployer_outside_alpha() {
  local workdir output_dir fake_bin log_dir output
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  cat >"$workdir/deployer.key" <<'EOF'
0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
EOF
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "mainnet"' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"
  write_fake_production_bridge_deploy_binary "$fake_bin/bridge-deploy" "$log_dir/bridge.log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  if output="$(
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$workdir/inventory.json" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --bridge-deploy-binary "$fake_bin/bridge-deploy" \
      --deployer-key-file "$workdir/deployer.key" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir "$output_dir" 2>&1
  )"; then
    printf 'expected deploy-coordinator.sh to reject direct deployer mode outside alpha\n' >&2
    exit 1
  fi

  assert_contains "$output" "--deployer-key-file is not allowed outside alpha; use --funder-key-file with bridge-deploy ephemeral mode" "non-alpha deploys reject direct deployer mode"
  [[ ! -e "$output_dir/mainnet/bridge-summary.json" ]] || {
    printf 'expected no bridge summary when non-alpha direct deployer mode is rejected\n' >&2
    exit 1
  }
  rm -rf "$workdir"
}

test_deploy_coordinator_normalizes_relative_output_paths() {
  local workdir inventory_path operator_dir fake_bin log_dir
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  inventory_path="$workdir/inventory.json"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  (
    cd "$workdir"
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$inventory_path" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir output >/dev/null
  )

  operator_dir="$workdir/output/alpha/operators/0x1111111111111111111111111111111111111111"
  assert_eq "$(jq -r '.shared_manifest_path' "$operator_dir/operator-deploy.json")" "$workdir/output/alpha/shared-manifest.json" "relative output path shared manifest path"
  assert_eq "$(jq -r '.rollout_state_file' "$operator_dir/operator-deploy.json")" "$workdir/output/alpha/rollout-state.json" "relative output path rollout state path"
  assert_eq "$(jq -r '.shared_manifest_path' "$workdir/output/alpha/app/app-deploy.json")" "$workdir/output/alpha/shared-manifest.json" "relative output path app shared manifest path"
  rm -rf "$workdir"
}

test_deploy_coordinator_uses_dkg_completion_for_signer_ufvk() {
  local workdir output_dir dkg_summary_no_ufvk dkg_completion bridge_summary_no_ua manifest fake_bin log_dir
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  "ufvk": "uview1coordinatorfallback",
  "juno_shielded_address": "u1coordinatorfallback"
}
EOF
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$dkg_summary_no_ufvk" \
    --dkg-completion "$dkg_completion" \
    --existing-bridge-summary "$bridge_summary_no_ua" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  manifest="$output_dir/alpha/shared-manifest.json"
  assert_eq "$(jq -r '.checkpoint.signer_ufvk' "$manifest")" "uview1coordinatorfallback" "coordinator signer ufvk fallback"
  assert_eq "$(jq -r '.contracts.owallet_ua' "$manifest")" "u1coordinatorfallback" "coordinator juno shielded address fallback"
  assert_eq "$(jq -r '.owallet_ua' "$output_dir/alpha/bridge-summary.json")" "u1coordinatorfallback" "coordinator bridge summary owallet ua refreshed"
  assert_eq "$(jq -r '.juno_shielded_address' "$output_dir/alpha/bridge-summary.json")" "u1coordinatorfallback" "coordinator bridge summary juno shielded address refreshed"
  rm -rf "$workdir"
}

test_deploy_coordinator_rejects_underfunded_operator_before_render() {
  local workdir output_dir fake_bin log_dir output
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1000"

  if output="$(
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$workdir/inventory.json" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir "$output_dir" 2>&1
  )"; then
    printf 'expected deploy-coordinator.sh to reject underfunded operator relayer\n' >&2
    exit 1
  fi

  assert_contains "$output" "base relayer 0x1111111111111111111111111111111111111111 balance 1000 wei is below minimum 1000000000000000 wei" "underfunded relayer error"
  [[ ! -e "$output_dir/alpha/shared-manifest.json" ]] || {
    printf 'expected no shared manifest when relayer funding preflight fails\n' >&2
    exit 1
  }
  rm -rf "$workdir"
}

test_deploy_coordinator_rejects_legacy_bridge_e2e_binary() {
  local workdir output_dir fake_bin log_dir bridge_log output
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  bridge_log="$log_dir/bridge.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_bridge_deploy_binary "$fake_bin/bridge-e2e" "$bridge_log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  if output="$(
    PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
      --inventory "$workdir/inventory.json" \
      --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
      --bridge-deploy-binary "$fake_bin/bridge-e2e" \
      --deployer-key-file "$workdir/dkg-backup.zip" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-dir "$output_dir" 2>&1
  )"; then
    printf 'expected deploy-coordinator.sh to reject legacy bridge-e2e binary\n' >&2
    exit 1
  fi

  assert_contains "$output" "production bridge deployment requires a bridge-deploy binary, got: bridge-e2e" "legacy bridge-e2e binary rejected"
  [[ ! -e "$output_dir/alpha/bridge-summary.json" ]] || {
    printf 'expected no bridge summary when legacy bridge-e2e binary is rejected\n' >&2
    exit 1
  }
  rm -rf "$workdir"
}

test_deploy_coordinator_invokes_production_bridge_deploy_binary() {
  local workdir output_dir fake_bin log_dir bridge_log
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  bridge_log="$log_dir/bridge.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_production_bridge_deploy_binary "$fake_bin/bridge-deploy" "$bridge_log" "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --bridge-deploy-binary "$fake_bin/bridge-deploy" \
    --deployer-key-file "$workdir/dkg-backup.zip" \
    --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_contains "$(cat "$bridge_log")" "--governance-safe 0x4444444444444444444444444444444444444444" "bridge-deploy receives governance safe"
  assert_contains "$(cat "$bridge_log")" "--pause-guardian 0x5555555555555555555555555555555555555555" "bridge-deploy receives pause guardian"
  assert_contains "$(cat "$bridge_log")" "--min-deposit-admin-address 0x1111111111111111111111111111111111111111" "bridge-deploy receives min deposit admin"
  assert_not_contains "$(cat "$bridge_log")" "--deploy-only" "bridge-deploy does not receive legacy deploy-only flag"
  rm -rf "$workdir"
}

test_deploy_coordinator_bootstraps_terraform_backend_before_init() {
  local workdir output_dir fake_bin log_dir aws_log terraform_log combined_log app_tf_fixture
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  aws_log="$log_dir/aws.log"
  terraform_log="$log_dir/terraform.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  write_fake_aws_backend_bootstrap "$fake_bin/aws" "$aws_log"
  app_tf_fixture="$workdir/app-terraform-output.json"
  jq -n '
    {
      app_role: {
        value: {
          asg: "alpha-app-role",
          launch_template: { id: "lt-app0123456789abcdef", version: "13" },
          public_lb: {
            dns_name: "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678"
          },
          internal_lb: {
            dns_name: "internal-ops-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z2P70J7EXAMPLE",
            security_group_id: "sg-internalops012345678"
          }
        }
      }
    }
  ' >"$app_tf_fixture"
  write_fake_terraform_binary "$fake_bin/terraform" "$terraform_log" "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" "$app_tf_fixture"

  PATH="$fake_bin:$PATH" \
    PRODUCTION_TEST_STS_REGIONAL_IPS=10.0.11.214 \
    bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --output-dir "$output_dir" >/dev/null

  combined_log="$(printf '%s\n%s\n' "$(cat "$aws_log")" "$(cat "$terraform_log")")"
  assert_not_contains "$combined_log" "sts get-caller-identity" "deploy-coordinator derives the terraform backend account id from inventory when available"
  assert_contains "$combined_log" "aws --profile juno --region us-east-1 s3api create-bucket --bucket intents-juno-tfstate-021490342184-us-east-1" "deploy-coordinator creates the terraform state bucket"
  assert_contains "$combined_log" "aws --profile juno --region us-east-1 dynamodb create-table --table-name intents-juno-tfstate-locks-021490342184-us-east-1" "deploy-coordinator creates the terraform lock table"
  assert_contains "$combined_log" "terraform init -input=false -reconfigure -backend-config=bucket=intents-juno-tfstate-021490342184-us-east-1 -backend-config=dynamodb_table=intents-juno-tfstate-locks-021490342184-us-east-1 -backend-config=key=production-shared/alpha.tfstate -backend-config=region=us-east-1" "deploy-coordinator initializes terraform against the bootstrapped backend"
  assert_contains "$combined_log" "terraform apply -auto-approve -input=false -var-file=$output_dir/alpha/shared-terraform.auto.tfvars.json" "deploy-coordinator applies terraform with the generated wireguard override file"
  assert_contains "$combined_log" "terraform init -input=false -reconfigure -backend-config=bucket=intents-juno-tfstate-021490342184-us-east-1 -backend-config=dynamodb_table=intents-juno-tfstate-locks-021490342184-us-east-1 -backend-config=key=app-runtime/alpha.tfstate -backend-config=region=us-east-1" "deploy-coordinator initializes app runtime terraform against the bootstrapped backend"
  assert_contains "$combined_log" "terraform apply -auto-approve -input=false -var-file=$output_dir/alpha/app-terraform.auto.tfvars.json" "deploy-coordinator applies app runtime terraform with the generated role override file"
  assert_contains "$combined_log" "terraform-env AWS_ENDPOINT_URL_STS=https://sts.amazonaws.com" "deploy-coordinator forces public sts when regional sts resolves private"
  assert_file_exists "$output_dir/alpha/shared-terraform.auto.tfvars.json" "deploy-coordinator writes the wireguard override file"
  assert_file_exists "$output_dir/alpha/app-terraform.auto.tfvars.json" "deploy-coordinator writes the app runtime override file"
  assert_eq "$(jq -r '.shared_wireguard_enabled' "$output_dir/alpha/shared-terraform.auto.tfvars.json")" "true" "deploy-coordinator writes a wireguard-enabled override file"
  assert_eq "$(jq -r '.shared_wireguard_public_subnet_ids[0]' "$output_dir/alpha/shared-terraform.auto.tfvars.json")" "subnet-0abc1234def567890" "deploy-coordinator forwards the wireguard public subnet into terraform"
  assert_eq "$(jq -r '.shared_wireguard_backoffice_hostname' "$output_dir/alpha/shared-terraform.auto.tfvars.json")" "ops.alpha.intents-testing.thejunowallet.com" "deploy-coordinator forwards the backoffice hostname into terraform"
  assert_eq "$(jq -r '.deployment_id' "$output_dir/alpha/app-terraform.auto.tfvars.json")" "alpha" "deploy-coordinator writes the app runtime deployment id"
  assert_eq "$(jq -r '.wireguard_cidr_blocks[0]' "$output_dir/alpha/app-terraform.auto.tfvars.json")" "10.0.2.50/32" "deploy-coordinator forwards wireguard source cidrs into the app runtime"
  assert_eq "$(jq -r '.app_ami_id' "$output_dir/alpha/app-terraform.auto.tfvars.json")" "ami-0123456789abcdef0" "deploy-coordinator forwards the app ami into the app runtime"
  assert_line_order "$combined_log" "aws --profile juno --region us-east-1 s3api create-bucket --bucket intents-juno-tfstate-021490342184-us-east-1" "terraform init -input=false -reconfigure -backend-config=bucket=intents-juno-tfstate-021490342184-us-east-1" "deploy-coordinator bootstraps backend storage before terraform init"
  assert_line_order "$combined_log" "terraform init -input=false -reconfigure -backend-config=bucket=intents-juno-tfstate-021490342184-us-east-1 -backend-config=dynamodb_table=intents-juno-tfstate-locks-021490342184-us-east-1 -backend-config=key=production-shared/alpha.tfstate -backend-config=region=us-east-1" "terraform init -input=false -reconfigure -backend-config=bucket=intents-juno-tfstate-021490342184-us-east-1 -backend-config=dynamodb_table=intents-juno-tfstate-locks-021490342184-us-east-1 -backend-config=key=app-runtime/alpha.tfstate -backend-config=region=us-east-1" "deploy-coordinator applies shared terraform before app runtime terraform"
  rm -rf "$workdir"
}

test_deploy_coordinator_resolves_role_runtime_release_inputs_when_inventory_is_unresolved() {
  local workdir output_dir fake_bin log_dir shared_tf_json app_tf_json releases_dir gh_log
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  fake_bin="$workdir/bin"
  log_dir="$workdir/log"
  releases_dir="$workdir/releases"
  gh_log="$log_dir/gh.log"
  mkdir -p "$fake_bin" "$log_dir" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip"
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
  jq '
    .app_role.app_ami_id = ""
    | .shared_roles.proof.image_uri = ""
    | .shared_roles.proof.image_ecr_repository_arn = ""
    | .shared_roles.wireguard.ami_id = ""
    | .wireguard_role.ami_id = ""
  ' "$workdir/inventory.json" >"$workdir/inventory.tmp"
  mv "$workdir/inventory.tmp" "$workdir/inventory.json"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"

  cat >"$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" <<'EOF'
{
  "repo_commit": "1111111111111111111111111111111111111111",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "app_binaries_release_tag": "app-binaries-v1.2.3-testnet",
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0app123456789abcd"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json.sha256"

  cat >"$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" <<'EOF'
{
  "repo_commit": "2222222222222222222222222222222222222222",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
  "regions": {
    "us-east-1": {
      "repository_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services",
      "repository_arn": "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services",
      "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json.sha256"

  cat >"$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" <<'EOF'
{
  "repo_commit": "3333333333333333333333333333333333333333",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0wireguard1234567"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json.sha256"
  write_fake_gh_release_downloader "$fake_bin/gh" "$releases_dir" "$gh_log"

  shared_tf_json="$workdir/shared-terraform-output.json"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" "$shared_tf_json"
  app_tf_json="$workdir/app-terraform-output.json"
  jq -n '
    {
      app_role: {
        value: {
          asg: "alpha-app-role",
          launch_template: { id: "lt-app0123456789abcdef", version: "13" },
          public_lb: {
            dns_name: "bridge-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z35SXDOTRQ7X7K",
            security_group_id: "sg-publicbridge012345678",
            target_group_arn: "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/alpha-bridge/123"
          },
          internal_lb: {
            dns_name: "internal-ops-alpha-role-123456.us-east-1.elb.amazonaws.com",
            zone_id: "Z2P70J7EXAMPLE",
            security_group_id: "sg-internalops012345678",
            target_group_arn: "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/alpha-backoffice/456"
          }
        }
      }
    }
  ' >"$app_tf_json"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-coordinator.sh" \
    --inventory "$workdir/inventory.json" \
    --dkg-summary "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    --shared-terraform-output-json "$shared_tf_json" \
    --app-terraform-output-json "$app_tf_json" \
    --skip-terraform-apply \
    --output-dir "$output_dir" >/dev/null

  assert_file_exists "$output_dir/alpha/inventory.release-resolved.json" "deploy-coordinator writes the release-resolved inventory"
  assert_eq "$(jq -r '.app_role.app_ami_id' "$output_dir/alpha/inventory.release-resolved.json")" "ami-0app123456789abcd" "deploy-coordinator resolves the app runtime ami id"
  assert_eq "$(jq -r '.shared_roles.proof.image_uri' "$output_dir/alpha/inventory.release-resolved.json")" "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef" "deploy-coordinator resolves the shared proof image uri"
  assert_eq "$(jq -r '.wireguard_role.ami_id' "$output_dir/alpha/inventory.release-resolved.json")" "ami-0wireguard1234567" "deploy-coordinator resolves the wireguard ami id"
  assert_contains "$(cat "$gh_log")" "release download app-runtime-ami-v1.2.3-testnet" "deploy-coordinator downloads the app runtime ami manifest"
  assert_contains "$(cat "$gh_log")" "release download shared-proof-services-image-v1.2.3-testnet" "deploy-coordinator downloads the shared proof image manifest"
  assert_contains "$(cat "$gh_log")" "release download wireguard-role-ami-v1.2.3-testnet" "deploy-coordinator downloads the wireguard ami manifest"
  rm -rf "$workdir"
}

main() {
  test_deploy_coordinator_generates_handoffs
  test_deploy_coordinator_prefers_role_outputs_in_shared_and_app_handoffs
  test_deploy_coordinator_resolves_role_runtime_inputs_and_runs_post_deploy_checks
  test_deploy_coordinator_supports_run_label
  test_deploy_coordinator_supports_preview_legacy_wireguard_inventory
  test_deploy_coordinator_materializes_dkg_tls_bundle_when_inventory_omits_it
  test_deploy_coordinator_normalizes_relative_output_paths
  test_deploy_coordinator_uses_dkg_completion_for_signer_ufvk
  test_deploy_coordinator_rejects_underfunded_operator_before_render
  test_deploy_coordinator_rejects_legacy_bridge_e2e_binary
  test_deploy_coordinator_forwards_ephemeral_funder_mode
  test_deploy_coordinator_rejects_direct_deployer_outside_alpha
  test_deploy_coordinator_invokes_production_bridge_deploy_binary
  test_deploy_coordinator_bootstraps_terraform_backend_before_init
  test_deploy_coordinator_resolves_role_runtime_release_inputs_when_inventory_is_unresolved
}

main "$@"
