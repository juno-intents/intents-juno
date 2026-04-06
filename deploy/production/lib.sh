#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"

# shellcheck source=../operators/dkg/common.sh
source "$REPO_ROOT/deploy/operators/dkg/common.sh"

production_json_required() {
  local file="$1"
  local query="$2"
  jq -er "$query" "$file"
}

production_json_optional() {
  local file="$1"
  local query="$2"
  jq -er "$query // empty" "$file" 2>/dev/null || true
}

production_abs_path() {
  local base_dir="$1"
  local path="$2"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
    return 0
  fi
  printf '%s\n' "$base_dir/$path"
}

production_safe_slug() {
  local value="$1"
  value="${value//[^A-Za-z0-9._-]/_}"
  printf '%s\n' "$value"
}

production_operator_dir() {
  local output_dir="$1"
  local operator_id="$2"
  printf '%s/operators/%s\n' "$output_dir" "$(production_safe_slug "$operator_id")"
}

production_app_dir() {
  local output_dir="$1"
  printf '%s/app\n' "$output_dir"
}

production_operator_ids_csv() {
  local dkg_summary="$1"
  jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary"
}

production_threshold() {
  local dkg_summary="$1"
  jq -er '.threshold // .operator_threshold // .operatorThreshold // .max_signers_threshold // empty' "$dkg_summary"
}

production_default_bridge_verifier_address() {
  printf '%s\n' "0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"
}

production_bridge_verifier_address() {
  local inventory="$1"
  local verifier_address
  verifier_address="$(production_json_optional "$inventory" '.contracts.verifier_address | select(type == "string" and length > 0)')"
  if [[ -n "$verifier_address" ]]; then
    printf '%s\n' "$verifier_address"
    return 0
  fi
  production_default_bridge_verifier_address
}

production_secret_keys_json() {
  jq -n '[]'
}

production_tf_output_value() {
  local tf_json="$1"
  local name="$2"
  local required="${3:-true}"
  local value
  value="$(jq -er --arg name "$name" '.[$name].value // empty' "$tf_json" 2>/dev/null || true)"
  if [[ "$required" == "true" && -z "$value" ]]; then
    die "missing required terraform output: $name"
  fi
  printf '%s\n' "$value"
}

production_tf_output_json() {
  local tf_json="$1"
  local name="$2"
  local required="${3:-true}"
  local value
  value="$(jq -cer --arg name "$name" '.[$name].value // empty' "$tf_json" 2>/dev/null || true)"
  if [[ "$required" == "true" && -z "$value" ]]; then
    die "missing required terraform output: $name"
  fi
  if [[ -z "$value" ]]; then
    printf '{}\n'
    return 0
  fi
  printf '%s\n' "$value"
}

production_resolve_s3_bucket_sse_kms_key_id() {
  local aws_profile="$1"
  local aws_region="$2"
  local bucket="$3"
  local encryption_json kms_key_id

  [[ -n "$bucket" ]] || {
    printf '\n'
    return 0
  }
  [[ -n "$aws_profile" && -n "$aws_region" ]] || {
    printf '\n'
    return 0
  }
  have_cmd aws || {
    printf '\n'
    return 0
  }

  encryption_json="$(
    AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api get-bucket-encryption \
      --bucket "$bucket" --output json 2>/dev/null || true
  )"
  [[ -n "$encryption_json" ]] || {
    printf '\n'
    return 0
  }

  kms_key_id="$(
    jq -r '
      [
        .ServerSideEncryptionConfiguration.Rules[]?.ApplyServerSideEncryptionByDefault
        | select(.SSEAlgorithm == "aws:kms")
        | .KMSMasterKeyID
      ][0] // empty
    ' <<<"$encryption_json" 2>/dev/null || true
  )"
  printf '%s\n' "$kms_key_id"
}

production_host_os() {
  if [[ -n "${PRODUCTION_HOST_OS_OVERRIDE:-}" ]]; then
    printf '%s\n' "$PRODUCTION_HOST_OS_OVERRIDE"
    return 0
  fi
  uname -s
}

production_release_binary_runner_image() {
  printf '%s\n' "${PRODUCTION_RELEASE_BINARY_RUNNER_IMAGE:-docker.io/library/golang:1.24.13-bookworm}"
}

production_release_binary_requires_runner() {
  local binary="$1"
  local file_desc=""

  if [[ "${PRODUCTION_FORCE_RELEASE_BINARY_RUNNER:-false}" == "true" ]]; then
    return 0
  fi
  [[ "$(production_host_os)" == "Linux" ]] && return 1
  have_cmd file || return 1
  file_desc="$(file -Lb "$binary" 2>/dev/null || true)"
  [[ "$file_desc" == ELF* ]]
}

production_release_binary_mount_root() {
  local binary="$1"
  local binary_abs

  binary_abs="$(production_abs_path "$(pwd)" "$binary")"
  case "$binary_abs" in
    "$REPO_ROOT"/*)
      printf '%s\n' "$REPO_ROOT"
      ;;
    *)
      die "release binary must live under repo root on non-linux hosts: $binary_abs"
      ;;
  esac
}

production_run_release_binary() {
  local binary="$1"
  shift

  if production_release_binary_requires_runner "$binary"; then
    local mount_root image
    have_cmd docker || die "docker is required to run released linux binaries on $(production_host_os)"
    mount_root="$(production_release_binary_mount_root "$binary")"
    image="$(production_release_binary_runner_image)"
    docker run --rm --platform linux/amd64 \
      --user "$(id -u):$(id -g)" \
      -v "$mount_root:$mount_root" \
      -w "$(pwd)" \
      "$image" /bin/sh -lc 'exec "$@"' sh "$binary" "$@"
    return 0
  fi

  "$binary" "$@"
}

production_inventory_terraform_dir() {
  local inventory="$1"
  local inventory_dir="$2"
  local terraform_dir

  terraform_dir="$(production_json_optional "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  [[ -n "$terraform_dir" ]] || return 1
  production_abs_path "$inventory_dir" "$terraform_dir"
}

production_terraform_backend_bucket_name() {
  local account_id="$1"
  local aws_region="$2"
  [[ "$account_id" =~ ^[0-9]{12}$ ]] || die "invalid aws account id for terraform backend bucket: $account_id"
  [[ -n "$aws_region" ]] || die "aws region is required for terraform backend bucket"
  printf 'intents-juno-tfstate-%s-%s\n' "$account_id" "$aws_region"
}

production_terraform_backend_table_name() {
  local account_id="$1"
  local aws_region="$2"
  [[ "$account_id" =~ ^[0-9]{12}$ ]] || die "invalid aws account id for terraform backend table: $account_id"
  [[ -n "$aws_region" ]] || die "aws region is required for terraform backend table"
  printf 'intents-juno-tfstate-locks-%s-%s\n' "$account_id" "$aws_region"
}

production_terraform_backend_state_key() {
  local environment="$1"
  local terraform_dir="$2"
  local resource_slug
  [[ -n "$environment" ]] || die "environment is required for terraform backend state key"
  [[ -n "$terraform_dir" ]] || die "terraform_dir is required for terraform backend state key"
  resource_slug="$(basename "$terraform_dir")"
  printf '%s/%s.tfstate\n' "$resource_slug" "$(production_safe_slug "$environment")"
}

production_sts_regional_endpoint_ips() {
  local aws_region="$1"

  if [[ -n "${PRODUCTION_TEST_STS_REGIONAL_IPS:-}" ]]; then
    printf '%s\n' "$PRODUCTION_TEST_STS_REGIONAL_IPS"
    return 0
  fi

  have_cmd python3 || return 0
  python3 - "$aws_region" <<'PY'
import socket
import sys

region = sys.argv[1]
host = f"sts.{region}.amazonaws.com"
ips = []
try:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
except OSError:
    infos = []
for info in infos:
    ip = info[4][0]
    if ip not in ips:
        ips.append(ip)
for ip in ips:
    print(ip)
PY
}

production_is_private_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  if [[ "$ip" =~ ^172\.([0-9]+)\. ]]; then
    local second_octet="${BASH_REMATCH[1]}"
    if [[ "$second_octet" =~ ^[0-9]+$ ]] && [[ "$second_octet" -ge 16 && "$second_octet" -le 31 ]]; then
      return 0
    fi
  fi
  return 1
}

production_maybe_use_public_sts_endpoint() {
  local aws_region="$1"
  local regional_ips=""
  local ip

  [[ -n "$aws_region" ]] || return 0
  [[ -n "${AWS_ENDPOINT_URL_STS:-}" ]] && return 0

  case "${PRODUCTION_FORCE_PUBLIC_STS_ENDPOINT:-auto}" in
    true)
      export AWS_ENDPOINT_URL_STS="https://sts.amazonaws.com"
      return 0
      ;;
    false)
      return 0
      ;;
  esac

  regional_ips="$(production_sts_regional_endpoint_ips "$aws_region" || true)"
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    if production_is_private_ipv4 "$ip"; then
      export AWS_ENDPOINT_URL_STS="https://sts.amazonaws.com"
      return 0
    fi
  done <<<"$regional_ips"
}

production_bootstrap_terraform_backend() {
  local aws_profile="$1"
  local aws_region="$2"
  local environment="$3"
  local terraform_dir="$4"
  local account_id_override="${5:-}"
  local account_id bucket_name table_name state_key

  have_cmd aws || die "required command not found: aws"
  [[ -n "$aws_profile" ]] || die "aws profile is required for terraform backend bootstrap"
  [[ -n "$aws_region" ]] || die "aws region is required for terraform backend bootstrap"
  production_maybe_use_public_sts_endpoint "$aws_region"

  account_id="$account_id_override"
  if [[ -z "$account_id" ]]; then
    account_id="$(
      AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" sts get-caller-identity \
        --query 'Account' --output text
    )"
  fi
  [[ "$account_id" =~ ^[0-9]{12}$ ]] || die "failed to resolve a valid aws account id for terraform backend bootstrap"

  bucket_name="$(production_terraform_backend_bucket_name "$account_id" "$aws_region")"
  table_name="$(production_terraform_backend_table_name "$account_id" "$aws_region")"
  state_key="$(production_terraform_backend_state_key "$environment" "$terraform_dir")"

  if ! AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api head-bucket --bucket "$bucket_name" >/dev/null 2>&1; then
    if [[ "$aws_region" == "us-east-1" ]]; then
      AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api create-bucket \
        --bucket "$bucket_name" >/dev/null
    else
      AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api create-bucket \
        --bucket "$bucket_name" \
        --create-bucket-configuration "LocationConstraint=$aws_region" >/dev/null
    fi
  fi

  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api put-bucket-versioning \
    --bucket "$bucket_name" \
    --versioning-configuration Status=Enabled >/dev/null
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api put-bucket-encryption \
    --bucket "$bucket_name" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' >/dev/null
  AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" s3api put-public-access-block \
    --bucket "$bucket_name" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null

  if ! AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" dynamodb describe-table --table-name "$table_name" >/dev/null 2>&1; then
    AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" dynamodb create-table \
      --table-name "$table_name" \
      --attribute-definitions AttributeName=LockID,AttributeType=S \
      --key-schema AttributeName=LockID,KeyType=HASH \
      --billing-mode PAY_PER_REQUEST >/dev/null
  fi

  printf '%s\n%s\n%s\n' "$bucket_name" "$table_name" "$state_key"
}

production_inventory_tfvars_value() {
  local inventory="$1"
  local inventory_dir="$2"
  local key="$3"
  local default_value="${4:-}"
  local terraform_dir tfvars_json tfvars_path value=""

  terraform_dir="$(production_inventory_terraform_dir "$inventory" "$inventory_dir" 2>/dev/null || true)"
  if [[ -n "$terraform_dir" ]]; then
    tfvars_json="$terraform_dir/terraform.tfvars.json"
    tfvars_path="$terraform_dir/terraform.tfvars"

    if [[ -f "$tfvars_json" ]]; then
      value="$(jq -r --arg key "$key" '.[$key] // empty' "$tfvars_json" 2>/dev/null || true)"
    fi
    if [[ -z "$value" && -f "$tfvars_path" ]]; then
      value="$(
        awk -F= -v want="$key" '
          $1 ~ "^[[:space:]]*" want "[[:space:]]*$" {
            value = substr($0, index($0, "=") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            gsub(/^"/, "", value)
            gsub(/"$/, "", value)
            print value
            exit
          }
        ' "$tfvars_path"
      )"
    fi
  fi

  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf '%s\n' "$value"
}

production_inventory_backoffice_dns_label() {
  local inventory="$1"
  local label

  label="$(production_json_optional "$inventory" '
    (.app_role.backoffice_dns_label // .app_host.backoffice_dns_label)
      | select(type == "string" and length > 0)
  ')"
  if [[ -n "$label" ]]; then
    printf '%s\n' "$label"
    return 0
  fi

  production_json_optional "$inventory" '
    (.app_role.ops_public_dns_label // .app_host.ops_public_dns_label)
      | select(type == "string" and length > 0)
  '
}

production_inventory_publish_backoffice_dns() {
  local inventory="$1"
  local publish

  publish="$(
    jq -er '
      if (.app_role? | type == "object") then
        (.app_role.publish_public_dns // false)
      elif (.app_host? | type == "object") then
        (.app_host.publish_public_dns // true)
      else
        false
      end
    ' "$inventory" 2>/dev/null || true
  )"
  [[ "$publish" == "true" ]]
}

production_inventory_app_role_json() {
  local inventory="$1"

  jq -c '
    if (.app_role? | type == "object") then
      .app_role
    elif (.app_host? | type == "object") then
      {
        host: .app_host.host,
        user: .app_host.user,
        runtime_dir: .app_host.runtime_dir,
        public_endpoint: .app_host.public_endpoint,
        private_endpoint: .app_host.private_endpoint,
        aws_profile: .app_host.aws_profile,
        aws_region: .app_host.aws_region,
        account_id: .app_host.account_id,
        security_group_id: .app_host.security_group_id,
        runtime_config_secret_id: .app_host.runtime_config_secret_id,
        runtime_config_secret_region: .app_host.runtime_config_secret_region,
        bridge_public_dns_label: .app_host.bridge_public_dns_label,
        backoffice_dns_label: .app_host.backoffice_dns_label,
        ops_public_dns_label: .app_host.ops_public_dns_label,
        public_scheme: .app_host.public_scheme,
        bridge_api_listen: .app_host.bridge_api_listen,
        backoffice_listen: .app_host.backoffice_listen,
        juno_rpc_url: .app_host.juno_rpc_url,
        service_urls: .app_host.service_urls,
        operator_endpoints: .app_host.operator_endpoints,
        publish_public_dns: true
      }
    else
      {}
    end
  ' "$inventory"
}

production_inventory_wireguard_role_json() {
  local inventory="$1"

  jq -c '
    if (.wireguard_role? | type == "object") then
      .wireguard_role
    elif (.shared_roles.wireguard? | type == "object") then
      .shared_roles.wireguard
    elif (.shared_services.wireguard? | type == "object") then
      {
        public_subnet_id: .shared_services.wireguard.public_subnet_id,
        public_subnet_ids: (if (.shared_services.wireguard.public_subnet_id? | type == "string" and length > 0) then [.shared_services.wireguard.public_subnet_id] else [] end),
        listen_port: .shared_services.wireguard.listen_port,
        network_cidr: .shared_services.wireguard.network_cidr,
        backoffice_hostname: (.shared_services.wireguard.backoffice_hostname // .app_role.backoffice_dns_label // .app_host.backoffice_dns_label // .app_host.ops_public_dns_label),
        backoffice_private_endpoint: (.shared_services.wireguard.backoffice_private_endpoint // .app_role.private_endpoint // .app_host.private_endpoint),
        client_config_secret_arn: .shared_services.wireguard.client_config_secret_arn,
        endpoint_host: .shared_services.wireguard.endpoint_host,
        publish_public_dns: true
      }
    else
      {}
    end
  ' "$inventory"
}

production_inventory_proof_role_json() {
  local inventory="$1"

  jq -c '
    if (.shared_roles.proof? | type == "object") then
      .shared_roles.proof
    elif (.shared_services.proof? | type == "object") then
      .shared_services.proof
    else
      {}
    end
  ' "$inventory"
}

production_inventory_has_v2_roles() {
  local inventory="$1"
  jq -e '
    (.app_role? | type == "object")
    or (.shared_roles? | type == "object")
    or (.wireguard_role? | type == "object")
    or (.operators[]? | has("asg") or has("launch_template") or has("role"))
  ' "$inventory" >/dev/null 2>&1
}

production_aws_existing_shared_vpc_endpoint_services_json() {
  local aws_profile="$1"
  local aws_region="$2"
  local vpc_id="$3"
  local raw_services

  if [[ -z "$vpc_id" ]] || ! command -v aws >/dev/null 2>&1; then
    printf '[]\n'
    return 0
  fi

  if ! raw_services="$(
    aws --profile "$aws_profile" --region "$aws_region" ec2 describe-vpc-endpoints \
      --filters "Name=vpc-id,Values=$vpc_id" \
      --output json 2>/dev/null
  )"; then
    printf '[]\n'
    return 0
  fi

  jq -cn \
    --argjson discovered "$raw_services" \
    --arg region "$aws_region" '
      (
        $discovered
        | if type == "object" then (.VpcEndpoints // []) else . end
        | if type == "array" then . else [] end
        | map(
            if type == "object" then
              select(
                (.State // "") as $state
                | $state == "available"
                  or $state == "pending"
                  or $state == "pendingAcceptance"
                  or $state == "modifying"
              )
              | .ServiceName
            elif type == "string" then
              .
            else
              empty
            end
          )
        | map(select(type == "string"))
      ) as $services
      | [
          "com.amazonaws.\($region).secretsmanager",
          "com.amazonaws.\($region).ecr.api",
          "com.amazonaws.\($region).ecr.dkr",
          "com.amazonaws.\($region).sts",
          "com.amazonaws.\($region).kms",
          "com.amazonaws.\($region).logs",
          "com.amazonaws.\($region).s3"
        ] as $managed
      | [$services[] | select(. as $service | $managed | index($service))] | unique
    '
}

production_inventory_live_e2e_operator_ami_id() {
  local inventory="$1"
  local aws_profile="$2"
  local aws_region="$3"
  local persisted_operator_ami_id launch_template_id launch_template_version lt_json

  persisted_operator_ami_id="$(jq -r '
    .shared_services.live_e2e.operator_ami_id
    // [
      (.operators // [])[].ami_id? // empty
    ][0]
    // empty
  ' "$inventory")"
  if [[ -n "$persisted_operator_ami_id" ]]; then
    printf '%s\n' "$persisted_operator_ami_id"
    return 0
  fi

  launch_template_id="$(jq -r '
    (.operators // [])
    | map(select((.launch_template.id // "") != ""))
    | .[0].launch_template.id // empty
  ' "$inventory")"
  [[ -n "$launch_template_id" ]] || return 0

  launch_template_version="$(jq -r '
    (.operators // [])
    | map(select((.launch_template.id // "") != ""))
    | .[0].launch_template.version // empty
  ' "$inventory")"
  if [[ -z "$launch_template_version" ]]; then
    launch_template_version='$Latest'
  fi

  lt_json="$(
    AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-launch-template-versions \
      --launch-template-id "$launch_template_id" \
      --versions "$launch_template_version" \
      --output json
  )"
  jq -r '.LaunchTemplateVersions[0].LaunchTemplateData.ImageId // empty' <<<"$lt_json"
}

production_write_shared_terraform_override_tfvars() {
  local inventory="$1"
  local output_file="$2"

  if ! jq -e '((.app_host? | type == "object") or (.app_role? | type == "object"))' "$inventory" >/dev/null 2>&1; then
    return 0
  fi

  local env_slug aws_region vpc_id shared_postgres_password shared_postgres_db base_chain_id deposit_image_id withdraw_image_id bridge_guest_release_tag
  local backoffice_hostname app_role_json wireguard_role_json proof_role_json shared_terraform_dir
  local private_subnet_ids_json wireguard_public_subnet_ids_json backoffice_private_endpoint_ips_json wireguard_source_cidrs_json
  local proof_requestor_address proof_requestor_secret_arn proof_funder_secret_arn proof_rpc_url
  local shared_proof_service_image shared_proof_service_image_ecr_repository_arn shared_wireguard_role_ami_id
  local shared_wireguard_listen_port shared_wireguard_network_cidr alarm_actions_json
  local app_security_group_id operator_client_security_group_ids_json shared_service_client_security_group_ids_json
  local operator_private_network_cidr_blocks_json
  local aws_profile shared_existing_vpc_endpoint_services_json
  local live_e2e_json live_e2e_deployment_id live_e2e_allowed_ssh_cidr live_e2e_ssh_public_key
  local app_instance_profile_name operator_instance_count wireguard_public_subnet_id backoffice_private_endpoint
  local allowed_checkpoint_signer_kms_key_arns_json operator_ami_id

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
  shared_terraform_dir="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  app_role_json="$(production_inventory_app_role_json "$inventory")"
  wireguard_role_json="$(production_inventory_wireguard_role_json "$inventory")"
  proof_role_json="$(production_json_optional "$inventory" '.shared_roles.proof // {}')"
  live_e2e_json="$(production_json_optional "$inventory" '.shared_services.live_e2e // {}')"
  vpc_id="$(jq -r '.vpc_id // empty' <<<"$app_role_json")"
  private_subnet_ids_json="$(jq -c '(.private_subnet_ids // []) | if type == "array" then . else [] end' <<<"$app_role_json")"
  shared_postgres_password="$(production_json_optional "$inventory" '.shared_postgres_password')"
  shared_postgres_db="$(production_json_optional "$inventory" '.shared_postgres_db')"
  base_chain_id="$(production_json_required "$inventory" '.contracts.base_chain_id')"
  deposit_image_id="$(production_json_required "$inventory" '.contracts.deposit_image_id | select(type == "string" and length > 0)')"
  withdraw_image_id="$(production_json_required "$inventory" '.contracts.withdraw_image_id | select(type == "string" and length > 0)')"
  bridge_guest_release_tag="$(production_json_optional "$inventory" '.contracts.bridge_guest_release_tag')"
  backoffice_hostname="$(jq -r '(.backoffice_hostname // empty)' <<<"$wireguard_role_json")"
  backoffice_private_endpoint="$(jq -r '.backoffice_private_endpoint // empty' <<<"$wireguard_role_json")"
  wireguard_public_subnet_ids_json="$(
    jq -c '
      if (.public_subnet_ids // [] | type) == "array" and ((.public_subnet_ids // []) | length) > 0 then
        .public_subnet_ids
      elif (.public_subnet_id // "" | type) == "string" and (.public_subnet_id // "") != "" then
        [.public_subnet_id]
      else
        []
      end
    ' <<<"$wireguard_role_json"
  )"
  wireguard_public_subnet_id="$(jq -r '
    if (.public_subnet_id // "" | type) == "string" and (.public_subnet_id // "") != "" then
      .public_subnet_id
    elif (.public_subnet_ids // [] | type) == "array" and ((.public_subnet_ids // []) | length) > 0 then
      .public_subnet_ids[0]
    else
      ""
    end
  ' <<<"$wireguard_role_json")"
  backoffice_private_endpoint_ips_json="$(
    jq -c '
      if (.backoffice_private_endpoint_ips // [] | type) == "array" and ((.backoffice_private_endpoint_ips // []) | length) > 0 then
        .backoffice_private_endpoint_ips
      elif (.backoffice_private_endpoint // "" | type) == "string" and (.backoffice_private_endpoint // "") != "" then
        [.backoffice_private_endpoint]
      else
        []
      end
    ' <<<"$wireguard_role_json"
  )"
  wireguard_source_cidrs_json="$(jq -c '(.source_cidrs // []) | if type == "array" then . else [] end' <<<"$wireguard_role_json")"
  proof_requestor_address="$(jq -r '.requestor_address // empty' <<<"$proof_role_json")"
  proof_requestor_secret_arn="$(jq -r '.requestor_secret_arn // empty' <<<"$proof_role_json")"
  proof_funder_secret_arn="$(jq -r '.funder_secret_arn // empty' <<<"$proof_role_json")"
  proof_rpc_url="$(jq -r '.rpc_url // empty' <<<"$proof_role_json")"
  shared_proof_service_image="$(jq -r '.image_uri // empty' <<<"$proof_role_json")"
  shared_proof_service_image_ecr_repository_arn="$(jq -r '.image_ecr_repository_arn // empty' <<<"$proof_role_json")"
  shared_wireguard_role_ami_id="$(jq -r '.ami_id // empty' <<<"$wireguard_role_json")"
  shared_wireguard_listen_port="$(jq -r '.listen_port // empty' <<<"$wireguard_role_json")"
  shared_wireguard_network_cidr="$(jq -r '.network_cidr // empty' <<<"$wireguard_role_json")"
  alarm_actions_json="$(jq -c '.shared_services.alarm_actions // []' "$inventory")"
  aws_profile="$(jq -r '.aws_profile // "juno"' <<<"$app_role_json")"
  app_security_group_id="$(jq -r '.app_security_group_id // empty' <<<"$app_role_json")"
  app_instance_profile_name="$(jq -r '.app_instance_profile_name // empty' <<<"$app_role_json")"
  live_e2e_deployment_id="$(jq -r '.deployment_id // empty' <<<"$live_e2e_json")"
  if [[ -z "$live_e2e_deployment_id" && "$app_instance_profile_name" == juno-live-e2e-*-instance-profile ]]; then
    live_e2e_deployment_id="${app_instance_profile_name#juno-live-e2e-}"
    live_e2e_deployment_id="${live_e2e_deployment_id%-instance-profile}"
  fi
  live_e2e_allowed_ssh_cidr="$(jq -r '.allowed_ssh_cidr // empty' <<<"$live_e2e_json")"
  live_e2e_ssh_public_key="$(jq -r '.ssh_public_key // empty' <<<"$live_e2e_json")"
  operator_instance_count="$(jq -r '(.operators // []) | length' "$inventory")"
  operator_ami_id=""
  if [[ -n "$app_security_group_id" ]]; then
    shared_service_client_security_group_ids_json="$(jq -cn --arg sg "$app_security_group_id" '[$sg]')"
  else
    shared_service_client_security_group_ids_json='[]'
  fi
  if [[ "$shared_terraform_dir" == "deploy/shared/terraform/live-e2e" && -n "$app_security_group_id" ]]; then
    operator_client_security_group_ids_json="$(jq -cn --arg sg "$app_security_group_id" '[$sg]')"
  else
    operator_client_security_group_ids_json='[]'
  fi
  operator_private_network_cidr_blocks_json="$(jq -c '
    [
      .operators[]?
      | .private_network?.vpc_cidr // empty
      | select(type == "string" and length > 0)
    ]
    | unique
  ' "$inventory")"
  allowed_checkpoint_signer_kms_key_arns_json="$(production_inventory_checkpoint_signer_kms_key_arns_json "$inventory")"
  [[ -n "$shared_proof_service_image" ]] || die "shared_roles.proof.image_uri is required for shared terraform role runtime"
  if [[ "$shared_terraform_dir" == "deploy/shared/terraform/live-e2e" ]]; then
    [[ -n "$backoffice_hostname" ]] || die "wireguard_role.backoffice_hostname is required for live-e2e shared terraform"
    [[ -n "$live_e2e_deployment_id" ]] || die "shared_services.live_e2e.deployment_id is required for live-e2e shared terraform"
    [[ -n "$live_e2e_allowed_ssh_cidr" ]] || die "shared_services.live_e2e.allowed_ssh_cidr is required for live-e2e shared terraform"
    [[ -n "$live_e2e_ssh_public_key" ]] || die "shared_services.live_e2e.ssh_public_key is required for live-e2e shared terraform"
    [[ -n "$proof_requestor_secret_arn" ]] || die "shared_roles.proof.requestor_secret_arn is required for live-e2e shared terraform"
    [[ -n "$proof_funder_secret_arn" ]] || die "shared_roles.proof.funder_secret_arn is required for live-e2e shared terraform"
    [[ -n "$proof_requestor_address" ]] || die "shared_roles.proof.requestor_address is required for live-e2e shared terraform"
    [[ -n "$proof_rpc_url" ]] || die "shared_roles.proof.rpc_url is required for live-e2e shared terraform"
    [[ -n "$shared_postgres_password" ]] || die "shared_postgres_password is required for live-e2e shared terraform"
    [[ -n "$shared_postgres_db" ]] || die "shared_postgres_db is required for live-e2e shared terraform"
    [[ -n "$shared_wireguard_listen_port" ]] || die "wireguard_role.listen_port is required for live-e2e shared terraform"
    [[ -n "$shared_wireguard_network_cidr" ]] || die "wireguard_role.network_cidr is required for live-e2e shared terraform"
    operator_ami_id="$(production_inventory_live_e2e_operator_ami_id "$inventory" "$aws_profile" "$aws_region")"
    [[ -n "$operator_ami_id" ]] || die "operators[].launch_template.id is required to preserve the live-e2e operator ami during shared terraform refresh"
    shared_existing_vpc_endpoint_services_json="$(production_aws_existing_shared_vpc_endpoint_services_json "$aws_profile" "$aws_region" "$vpc_id")"

    jq -n \
      --arg aws_region "$aws_region" \
      --arg deployment_id "$live_e2e_deployment_id" \
      --arg allowed_ssh_cidr "$live_e2e_allowed_ssh_cidr" \
      --arg ssh_public_key "$live_e2e_ssh_public_key" \
      --arg operator_ami_id "$operator_ami_id" \
      --argjson operator_instance_count "$operator_instance_count" \
      --arg shared_postgres_password "$shared_postgres_password" \
      --arg shared_postgres_db "$shared_postgres_db" \
      --arg shared_sp1_requestor_secret_arn "$proof_requestor_secret_arn" \
      --arg shared_sp1_funder_secret_arn "$proof_funder_secret_arn" \
      --arg shared_sp1_requestor_address "$proof_requestor_address" \
      --argjson shared_base_chain_id "$base_chain_id" \
      --arg shared_deposit_image_id "$deposit_image_id" \
      --arg shared_withdraw_image_id "$withdraw_image_id" \
      --arg shared_sp1_rpc_url "$proof_rpc_url" \
      --arg wireguard_public_subnet_id "$wireguard_public_subnet_id" \
      --argjson wireguard_public_subnet_ids "$wireguard_public_subnet_ids_json" \
      --arg backoffice_hostname "$backoffice_hostname" \
      --arg backoffice_private_endpoint "$backoffice_private_endpoint" \
      --argjson backoffice_private_endpoint_ips "$backoffice_private_endpoint_ips_json" \
      --arg shared_proof_service_image "$shared_proof_service_image" \
      --argjson shared_wireguard_listen_port "$shared_wireguard_listen_port" \
      --arg shared_wireguard_network_cidr "$shared_wireguard_network_cidr" \
      --argjson operator_client_security_group_ids "$operator_client_security_group_ids_json" \
      --argjson allowed_checkpoint_signer_kms_key_arns "$allowed_checkpoint_signer_kms_key_arns_json" \
      --argjson shared_service_client_security_group_ids "$shared_service_client_security_group_ids_json" \
      --argjson shared_ipfs_client_security_group_ids "$shared_service_client_security_group_ids_json" \
      --argjson shared_existing_vpc_endpoint_services "$shared_existing_vpc_endpoint_services_json" \
      '{
        aws_region: $aws_region,
        deployment_id: $deployment_id,
        allowed_ssh_cidr: $allowed_ssh_cidr,
        ssh_public_key: $ssh_public_key,
        operator_ami_id: $operator_ami_id,
        operator_instance_count: $operator_instance_count,
        shared_postgres_password: $shared_postgres_password,
        shared_postgres_db: $shared_postgres_db,
        shared_wireguard_enabled: true,
        shared_wireguard_backoffice_hostname: $backoffice_hostname,
        shared_proof_service_image: $shared_proof_service_image,
        shared_sp1_requestor_secret_arn: $shared_sp1_requestor_secret_arn,
        shared_sp1_funder_secret_arn: $shared_sp1_funder_secret_arn,
        shared_sp1_requestor_address: $shared_sp1_requestor_address,
        shared_base_chain_id: $shared_base_chain_id,
        shared_deposit_image_id: $shared_deposit_image_id,
        shared_withdraw_image_id: $shared_withdraw_image_id,
        shared_sp1_rpc_url: $shared_sp1_rpc_url,
        shared_wireguard_listen_port: $shared_wireguard_listen_port,
        shared_wireguard_network_cidr: $shared_wireguard_network_cidr,
        shared_existing_vpc_endpoint_services: $shared_existing_vpc_endpoint_services
      }
      + (if ($operator_client_security_group_ids | length) == 0 then {} else {
        operator_client_security_group_ids: $operator_client_security_group_ids
      } end)
      + (if ($allowed_checkpoint_signer_kms_key_arns | length) == 0 then {} else {
        allowed_checkpoint_signer_kms_key_arns: $allowed_checkpoint_signer_kms_key_arns
      } end)
      + (if ($shared_service_client_security_group_ids | length) == 0 then {} else {
        shared_service_client_security_group_ids: $shared_service_client_security_group_ids
      } end)
      + (if ($shared_ipfs_client_security_group_ids | length) == 0 then {} else {
        shared_ipfs_client_security_group_ids: $shared_ipfs_client_security_group_ids
      } end)
      + (if $wireguard_public_subnet_id == "" then {} else {
        shared_wireguard_public_subnet_id: $wireguard_public_subnet_id
      } end)
      + (if $backoffice_private_endpoint == "" then {} else {
        shared_wireguard_backoffice_private_endpoint: $backoffice_private_endpoint
      } end)' >"$output_file"
    return 0
  fi

  [[ -n "$vpc_id" ]] || die "app_role.vpc_id is required for production shared terraform"
  [[ "$(jq -r 'length' <<<"$private_subnet_ids_json")" -ge 2 ]] || die "app_role.private_subnet_ids must include at least two subnet ids for production shared terraform"
  [[ -n "$shared_postgres_password" ]] || die "shared_postgres_password is required for production shared terraform"
  [[ -n "$proof_requestor_address" ]] || die "shared_roles.proof.requestor_address is required for production shared terraform"
  [[ -n "$proof_requestor_secret_arn" ]] || die "shared_roles.proof.requestor_secret_arn is required for production shared terraform"
  [[ -n "$proof_funder_secret_arn" ]] || die "shared_roles.proof.funder_secret_arn is required for production shared terraform"
  [[ -n "$proof_rpc_url" ]] || die "shared_roles.proof.rpc_url is required for production shared terraform"
  [[ -n "$shared_proof_service_image_ecr_repository_arn" ]] || die "shared_roles.proof.image_ecr_repository_arn is required for shared terraform role runtime"
  if [[ "$env_slug" == "mainnet" ]]; then
    [[ -n "$bridge_guest_release_tag" ]] || die "contracts.bridge_guest_release_tag is required for production shared terraform"
  fi
  jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and length > 0)' <<<"$alarm_actions_json" >/dev/null 2>&1 \
    || die "shared_services.alarm_actions must be a non-empty array for production shared terraform"

  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$env_slug" \
    --arg vpc_id "$vpc_id" \
    --argjson shared_subnet_ids "$private_subnet_ids_json" \
    --arg shared_postgres_password "$shared_postgres_password" \
    --arg shared_sp1_requestor_secret_arn "$proof_requestor_secret_arn" \
    --arg shared_sp1_funder_secret_arn "$proof_funder_secret_arn" \
    --arg shared_sp1_requestor_address "$proof_requestor_address" \
    --arg shared_sp1_rpc_url "$proof_rpc_url" \
    --argjson shared_base_chain_id "$base_chain_id" \
    --arg shared_deposit_image_id "$deposit_image_id" \
    --arg shared_withdraw_image_id "$withdraw_image_id" \
    --arg shared_bridge_guest_release_tag "$bridge_guest_release_tag" \
    --argjson alarm_actions "$alarm_actions_json" \
    --arg shared_proof_service_image "$shared_proof_service_image" \
    --arg shared_proof_service_image_ecr_repository_arn "$shared_proof_service_image_ecr_repository_arn" \
    --argjson shared_service_client_security_group_ids "$shared_service_client_security_group_ids_json" \
    --argjson shared_service_client_cidr_blocks "$operator_private_network_cidr_blocks_json" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      vpc_id: $vpc_id,
      shared_subnet_ids: $shared_subnet_ids,
      shared_postgres_password: $shared_postgres_password,
      shared_sp1_requestor_secret_arn: $shared_sp1_requestor_secret_arn,
      shared_sp1_funder_secret_arn: $shared_sp1_funder_secret_arn,
      shared_sp1_requestor_address: $shared_sp1_requestor_address,
      shared_sp1_rpc_url: $shared_sp1_rpc_url,
      shared_base_chain_id: $shared_base_chain_id,
      shared_deposit_image_id: $shared_deposit_image_id,
      shared_withdraw_image_id: $shared_withdraw_image_id,
      alarm_actions: $alarm_actions,
      shared_wireguard_enabled: false,
      shared_proof_service_image: $shared_proof_service_image,
      shared_proof_service_image_ecr_repository_arn: $shared_proof_service_image_ecr_repository_arn,
      shared_proof_role_min_size: 2,
      shared_proof_role_desired_capacity: 2,
      shared_proof_role_max_size: 4
    }
    + (if $shared_bridge_guest_release_tag == "" then {} else {
      shared_bridge_guest_release_tag: $shared_bridge_guest_release_tag
    } end)
    + (if ($shared_service_client_security_group_ids | length) == 0 then {} else {
      shared_service_client_security_group_ids: $shared_service_client_security_group_ids,
      shared_ipfs_client_security_group_ids: $shared_service_client_security_group_ids
    } end)
    + (if ($shared_service_client_cidr_blocks | length) == 0 then {} else {
      shared_service_client_cidr_blocks: $shared_service_client_cidr_blocks,
      shared_ipfs_client_cidr_blocks: $shared_service_client_cidr_blocks
    } end)' >"$output_file"
}

production_write_app_terraform_override_tfvars() {
  local inventory="$1"
  local output_file="$2"

  if ! jq -e '((.app_host? | type == "object") or (.app_role? | type == "object"))' "$inventory" >/dev/null 2>&1; then
    return 0
  fi

  local env_slug app_role_json
  local aws_region vpc_id public_subnet_ids_json private_subnet_ids_json
  local app_ami_id app_instance_profile_name public_bridge_certificate_arn internal_backoffice_certificate_arn
  local public_bridge_additional_certificate_arns_json
  local alarm_actions_json

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  app_role_json="$(production_inventory_app_role_json "$inventory")"
  aws_region="$(jq -r '.aws_region // empty' <<<"$app_role_json")"
  if [[ -z "$aws_region" ]]; then
    aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
  fi
  vpc_id="$(jq -r '.vpc_id // empty' <<<"$app_role_json")"
  [[ -n "$vpc_id" ]] || die "app_role.vpc_id is required for app runtime terraform"
  public_subnet_ids_json="$(jq -c '(.public_subnet_ids // []) | if type == "array" then . else [] end' <<<"$app_role_json")"
  private_subnet_ids_json="$(jq -c '(.private_subnet_ids // []) | if type == "array" then . else [] end' <<<"$app_role_json")"
  [[ "$(jq -r 'length' <<<"$public_subnet_ids_json")" -ge 2 ]] || die "app_role.public_subnet_ids must include at least two subnet ids"
  [[ "$(jq -r 'length' <<<"$private_subnet_ids_json")" -ge 2 ]] || die "app_role.private_subnet_ids must include at least two subnet ids"
  app_ami_id="$(jq -r '.app_ami_id // empty' <<<"$app_role_json")"
  [[ -n "$app_ami_id" ]] || die "app_role.app_ami_id is required for app runtime terraform"
  app_instance_profile_name="$(jq -r '.app_instance_profile_name // empty' <<<"$app_role_json")"
  [[ -n "$app_instance_profile_name" ]] || die "app_role.app_instance_profile_name is required for app runtime terraform"
  public_bridge_certificate_arn="$(jq -r '.public_bridge_certificate_arn // empty' <<<"$app_role_json")"
  [[ -n "$public_bridge_certificate_arn" ]] || die "app_role.public_bridge_certificate_arn is required for app runtime terraform"
  public_bridge_additional_certificate_arns_json="$(jq -c '
    (.public_bridge_additional_certificate_arns // [])
    | if type == "array" then
        [ .[] | select(type == "string" and length > 0) ]
      else
        []
      end
  ' <<<"$app_role_json")"
  internal_backoffice_certificate_arn="$(jq -r '.internal_backoffice_certificate_arn // empty' <<<"$app_role_json")"
  [[ -n "$internal_backoffice_certificate_arn" ]] || die "app_role.internal_backoffice_certificate_arn is required for app runtime terraform"
  if ! jq -e '.shared_services.alarm_actions | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)' "$inventory" >/dev/null 2>&1; then
    die "shared_services.alarm_actions must be a non-empty array when inventory.app_role or inventory.app_host is present"
  fi
  alarm_actions_json="$(jq -c '.shared_services.alarm_actions' "$inventory")"

  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$env_slug" \
    --arg vpc_id "$vpc_id" \
    --argjson public_subnet_ids "$public_subnet_ids_json" \
    --argjson private_subnet_ids "$private_subnet_ids_json" \
    --arg app_ami_id "$app_ami_id" \
    --arg app_instance_profile_name "$app_instance_profile_name" \
    --arg public_bridge_certificate_arn "$public_bridge_certificate_arn" \
    --argjson public_bridge_additional_certificate_arns "$public_bridge_additional_certificate_arns_json" \
    --arg internal_backoffice_certificate_arn "$internal_backoffice_certificate_arn" \
    --argjson alarm_actions "$alarm_actions_json" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      vpc_id: $vpc_id,
      public_subnet_ids: $public_subnet_ids,
      private_subnet_ids: $private_subnet_ids,
      app_ami_id: $app_ami_id,
      app_instance_profile_name: $app_instance_profile_name,
      public_bridge_certificate_arn: $public_bridge_certificate_arn,
      public_bridge_additional_certificate_arns: $public_bridge_additional_certificate_arns,
      internal_backoffice_certificate_arn: $internal_backoffice_certificate_arn,
      alarm_actions: $alarm_actions
    }' >"$output_file"
}

production_parse_postgres_dsn_field() {
  local dsn="$1"
  local field="$2"
  local rest auth host_db host_port db_query user password db port=""

  [[ "$dsn" == postgres://* ]] || return 1
  rest="${dsn#postgres://}"
  [[ "$rest" == *@*/* ]] || return 1

  auth="${rest%%@*}"
  host_db="${rest#*@}"
  user="${auth%%:*}"
  password="${auth#*:}"
  if [[ "$password" == "$auth" ]]; then
    return 1
  fi

  host_port="${host_db%%/*}"
  db_query="${host_db#*/}"
  db="${db_query%%\?*}"
  if [[ "$host_port" == *:* ]]; then
    port="${host_port##*:}"
  fi

  case "$field" in
    user)
      [[ -n "$user" ]] || return 1
      printf '%s\n' "$user"
      ;;
    password)
      [[ -n "$password" ]] || return 1
      printf '%s\n' "$password"
      ;;
    db)
      [[ -n "$db" ]] || return 1
      printf '%s\n' "$db"
      ;;
    port)
      [[ -n "$port" ]] || return 1
      printf '%s\n' "$port"
      ;;
    *)
      return 1
      ;;
  esac
}

production_current_postgres_dsn() {
  local inventory="$1"
  local inventory_dir="$2"
  local shared_manifest="$3"
  local existing_dsn="$4"
  local endpoint port user password db

  endpoint="$(production_json_optional "$shared_manifest" '.shared_services.postgres.endpoint | select(type == "string" and length > 0)')"
  port="$(production_json_optional "$shared_manifest" '.shared_services.postgres.port')"
  if [[ -z "$endpoint" || -z "$port" ]]; then
    printf '%s\n' "$existing_dsn"
    return 0
  fi

  user="$(production_inventory_tfvars_value "$inventory" "$inventory_dir" shared_postgres_user "")"
  password="$(production_inventory_tfvars_value "$inventory" "$inventory_dir" shared_postgres_password "")"
  db="$(production_inventory_tfvars_value "$inventory" "$inventory_dir" shared_postgres_db "")"

  if [[ -z "$user" ]]; then
    user="$(production_parse_postgres_dsn_field "$existing_dsn" user 2>/dev/null || true)"
  fi
  if [[ -z "$password" ]]; then
    password="$(production_parse_postgres_dsn_field "$existing_dsn" password 2>/dev/null || true)"
  fi
  if [[ -z "$db" ]]; then
    db="$(production_parse_postgres_dsn_field "$existing_dsn" db 2>/dev/null || true)"
  fi

  if [[ -z "$user" || -z "$password" || -z "$db" ]]; then
    printf '%s\n' "$existing_dsn"
    return 0
  fi

  printf 'postgres://%s:%s@%s:%s/%s?sslmode=require\n' "$user" "$password" "$endpoint" "$port" "$db"
}

production_generate_dkg_tls_bundle() {
  local tls_dir="$1"
  local tmp_dir server_ext client_ext

  have_cmd openssl || die "required command not found: openssl"
  mkdir -p "$tls_dir"
  tmp_dir="$(mktemp -d)"
  server_ext="$tmp_dir/server.ext"
  client_ext="$tmp_dir/coordinator-client.ext"

  cat >"$server_ext" <<'EOF'
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

  cat >"$client_ext" <<'EOF'
basicConstraints=CA:FALSE
subjectAltName=DNS:coordinator-client
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/ca.key" \
    -out "$tls_dir/ca.pem" \
    -days 3650 \
    -subj "/CN=Juno DKG Deploy CA" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/server.key" \
    -out "$tmp_dir/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req \
    -in "$tmp_dir/server.csr" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tls_dir/ca.key" \
    -CAcreateserial \
    -out "$tls_dir/server.pem" \
    -days 3650 \
    -sha256 \
    -extfile "$server_ext" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/coordinator-client.key" \
    -out "$tmp_dir/coordinator-client.csr" \
    -subj "/CN=coordinator-client" >/dev/null 2>&1
  openssl x509 -req \
    -in "$tmp_dir/coordinator-client.csr" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tls_dir/ca.key" \
    -CAcreateserial \
    -out "$tls_dir/coordinator-client.pem" \
    -days 3650 \
    -sha256 \
    -extfile "$client_ext" >/dev/null 2>&1

  chmod 0600 \
    "$tls_dir/ca.key" \
    "$tls_dir/server.key" \
    "$tls_dir/coordinator-client.key" || true
  rm -rf "$tmp_dir"
}

production_certificate_sha256_hex() {
  local cert_path="$1"

  have_cmd openssl || die "required command not found: openssl"
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | cut -d= -f2 \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

production_materialize_operator_dkg_backup_zip() {
  die "local dkg backup packaging is disabled; use runtime_material_ref.mode=s3-kms-zip"
}

production_base_relayer_allowed_selectors() {
  printf '0x53a58a48,0xec70b605,0xfe097d57\n'
}

production_rewrite_operator_handoffs_dkg_tls_dir() {
  local output_dir="$1"
  local dkg_tls_dir="$2"
  local manifest rel_path tmp_manifest

  [[ -d "$output_dir/operators" ]] || return 0
  for manifest in "$output_dir"/operators/*/operator-deploy.json; do
    [[ -f "$manifest" ]] || continue
    rel_path="$(python3 - <<'PY' "$dkg_tls_dir" "$(dirname "$manifest")"
import os
import sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))
PY
)"
    tmp_manifest="$(mktemp)"
    jq --arg dkg_tls_dir "$rel_path" '.dkg_tls_dir = $dkg_tls_dir' "$manifest" >"$tmp_manifest"
    mv "$tmp_manifest" "$manifest"
  done
}

production_refresh_operator_secret_contract() {
  die "operator secret contract refresh is disabled; use runtime_config_secret_id on-host hydration"
}

production_refresh_app_secret_contract() {
  die "app secret contract refresh is disabled; use runtime_config_secret_id on-host hydration"
}

production_aws_describe_instance_field() {
  local profile="$1"
  local region="$2"
  local host="$3"
  local query="$4"
  local result=""

  [[ -n "$profile" && -n "$region" ]] || return 0
  have_cmd aws || return 0

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    result="$(AWS_PAGER="" aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=ip-address,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
    if [[ -z "$result" || "$result" == "None" ]]; then
      result="$(AWS_PAGER="" aws --profile "$profile" --region "$region" ec2 describe-instances \
        --filters "Name=private-ip-address,Values=$host" \
        --query "$query" --output text 2>/dev/null || true)"
    fi
  else
    result="$(AWS_PAGER="" aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=dns-name,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
  fi

  if [[ -n "$result" && "$result" != "None" ]]; then
    printf '%s\n' "$result"
  fi
}

production_aws_resolve_private_ip() {
  local profile="$1"
  local region="$2"
  local host="$3"
  local result=""

  result="$(production_aws_describe_instance_field "$profile" "$region" "$host" 'Reservations[].Instances[].PrivateIpAddress')"
  if [[ -n "$result" ]]; then
    printf '%s\n' "$result"
  else
    printf '%s\n' "$host"
  fi
}

production_default_dkg_port_for_index() {
  local operator_index="$1"
  [[ "$operator_index" =~ ^[0-9]+$ ]] || die "invalid operator index for dkg port: $operator_index"
  printf '%s\n' "$((18442 + operator_index))"
}

production_default_dkg_endpoint_for_operator_json() {
  local operator_json="$1"
  local endpoint_host operator_index endpoint_port

  endpoint_host="$(jq -r '.public_endpoint // .operator_host // empty' <<<"$operator_json")"
  operator_index="$(jq -r '.index // empty' <<<"$operator_json")"
  [[ -n "$endpoint_host" ]] || return 1
  [[ -n "$operator_index" ]] || return 1
  endpoint_port="$(production_default_dkg_port_for_index "$operator_index")"
  printf 'https://%s:%s\n' "$endpoint_host" "$endpoint_port"
}

production_default_operator_endpoints_json() {
  local inventory="$1"
  local shared_manifest="${2:-}"
  local operator_count index operator_json endpoint_addr endpoint_host
  local operator_id dkg_endpoint endpoint_port parsed_endpoint operator_index

  operator_count="$(jq -r '.operators | length' "$inventory")"
  for ((index = 0; index < operator_count; index++)); do
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    operator_id="$(jq -r '.operator_id // empty' <<<"$operator_json")"
    operator_index="$(jq -r '.index // empty' <<<"$operator_json")"
    endpoint_addr="$(jq -r '.operator_address // .operator_id // empty' <<<"$operator_json")"
    endpoint_host="$(jq -r '
      if (.private_endpoint // "") != "" then
        .private_endpoint
      elif (.operator_probe_host // "") != "" then
        .operator_probe_host
      else
        (.public_endpoint // .operator_host // "")
      end
    ' <<<"$operator_json")"
    endpoint_port="$(production_default_dkg_port_for_index "$operator_index")"

    if [[ -n "$shared_manifest" && -f "$shared_manifest" && -n "$operator_id" ]]; then
      dkg_endpoint="$(jq -r --arg operator_id "$operator_id" '.operator_roster[] | select(.operator_id == $operator_id) | .dkg_endpoint // empty' "$shared_manifest")"
      if [[ -n "$dkg_endpoint" ]]; then
        parsed_endpoint="$(parse_endpoint_host_port "$dkg_endpoint" 2>/dev/null || true)"
        if [[ -n "$parsed_endpoint" ]]; then
          endpoint_port="${parsed_endpoint##* }"
        fi
      fi
    fi

    [[ -n "$endpoint_addr" && -n "$endpoint_host" ]] || continue
    printf '%s=%s:%s\n' "$endpoint_addr" "$endpoint_host" "$endpoint_port"
  done | jq -R -s 'split("\n") | map(select(length > 0))'
}

production_backoffice_juno_rpc_urls_csv() {
  local app_deploy="$1"
  local explicit_url operator_endpoint endpoint_host_port endpoint_host candidate existing
  local -a urls=()

  explicit_url="$(production_json_optional "$app_deploy" '.juno_rpc_url')"
  if [[ -n "$explicit_url" ]] && ! production_is_loopback_url "$explicit_url"; then
    urls+=("$explicit_url")
  fi

  while IFS= read -r operator_endpoint; do
    [[ -n "$operator_endpoint" ]] || continue
    endpoint_host_port="${operator_endpoint#*=}"
    endpoint_host="$(production_host_from_listen_addr "$endpoint_host_port")"
    candidate="http://${endpoint_host}:18232"
    production_is_loopback_url "$candidate" && continue
    for existing in "${urls[@]}"; do
      if [[ "$existing" == "$candidate" ]]; then
        continue 2
      fi
    done
    urls+=("$candidate")
  done < <(jq -r '.operator_endpoints[]? // empty' "$app_deploy")

  if (( ${#urls[@]} > 0 )); then
    local IFS=,
    printf '%s\n' "${urls[*]}"
  fi
}

production_validate_secret_resolver() {
  local value="$1"
  local allow_local="$2"
  case "$value" in
    literal:*)
      [[ "$allow_local" == "true" ]] || die "literal: resolver is only allowed for alpha"
      ;;
    file:/*)
      [[ "$allow_local" == "true" ]] || die "file: resolver is only allowed for alpha"
      ;;
    aws-sm://*)
      ;;
    aws-ssm:///*)
      ;;
    env:*)
      [[ "$value" =~ ^env:[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid env resolver: $value"
      ;;
    *)
      die "unsupported secret resolver: $value"
      ;;
  esac
}

production_resolve_secret_value() {
  local value="$1"
  local aws_profile="$2"
  local aws_region="$3"

  case "$value" in
    literal:*)
      printf '%s\n' "${value#literal:}"
      ;;
    file:/*)
      local file_path="${value#file:}"
      [[ -f "$file_path" ]] || die "secret file not found: $file_path"
      cat "$file_path"
      ;;
    aws-sm://*)
      AWS_PAGER="" aws ${aws_profile:+--profile "$aws_profile"} ${aws_region:+--region "$aws_region"} \
        secretsmanager get-secret-value \
        --secret-id "${value#aws-sm://}" \
        --query SecretString \
        --output text
      ;;
    aws-ssm:///*)
      AWS_PAGER="" aws ${aws_profile:+--profile "$aws_profile"} ${aws_region:+--region "$aws_region"} \
        ssm get-parameter \
        --name "/${value#aws-ssm:///}" \
        --with-decryption \
        --query Parameter.Value \
        --output text
      ;;
    env:*)
      local env_name="${value#env:}"
      [[ -n "${!env_name:-}" ]] || die "environment variable not set for resolver: $env_name"
      printf '%s\n' "${!env_name}"
      ;;
    *)
      die "unsupported secret resolver: $value"
      ;;
  esac
}

production_resolve_optional_aws_sm_secret() {
  local secret_arn="$1"
  local aws_profile="$2"
  local aws_region="$3"

  secret_arn="$(trim "$secret_arn")"
  if [[ -z "$secret_arn" ]]; then
    return 0
  fi
  production_resolve_secret_value "aws-sm://$secret_arn" "$aws_profile" "$aws_region"
}

production_resolve_secret_contract() {
  die "local secret contract resolution is disabled; use runtime_config_secret_id with host-side hydration"
}

production_env_get_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' "$file"
}

production_env_first_value() {
  local file="$1"
  shift

  local key value
  for key in "$@"; do
    value="$(production_env_get_value "$file" "$key")"
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

production_normalize_ecdsa_private_key() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value//$'\t'/}"
  value="${value// /}"
  value="${value#0x}"
  [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid 32-byte hex private key"
  printf '0x%s\n' "$value"
}

production_normalize_ecdsa_private_key_csv() {
  local csv="$1"
  local IFS=,
  local -a values=()
  local -a normalized=()
  local value

  read -r -a values <<<"$csv"
  (( ${#values[@]} > 0 )) || die "missing ECDSA private key CSV"
  for value in "${values[@]}"; do
    [[ -n "$value" ]] || die "invalid empty ECDSA private key entry"
    normalized+=("$(production_normalize_ecdsa_private_key "$value")")
  done
  (IFS=,; printf '%s\n' "${normalized[*]}")
}

production_secret_contract_upsert_literal() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -F= -v key="$key" '
    index($0, key "=") != 1 { print }
  ' "$file" >"$tmp"
  printf '%s=literal:%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$file"
}

production_secret_contract_delete_key() {
  local file="$1"
  local key="$2"
  local tmp
  tmp="$(mktemp)"
  awk -F= -v key="$key" '
    index($0, key "=") != 1 { print }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

production_effective_owallet_ua() {
  local inventory_owallet_ua="${1:-}"
  local bridge_summary_owallet_ua="${2:-}"
  local summary_owallet_ua="${3:-}"
  local completion_owallet_ua="${4:-}"
  local dkg_owallet_ua=""

  if [[ -n "$summary_owallet_ua" && -n "$completion_owallet_ua" && "$summary_owallet_ua" != "$completion_owallet_ua" ]]; then
    die "dkg summary owallet ua ($summary_owallet_ua) does not match dkg completion owallet ua ($completion_owallet_ua)"
  fi

  if [[ -n "$completion_owallet_ua" ]]; then
    dkg_owallet_ua="$completion_owallet_ua"
  else
    dkg_owallet_ua="$summary_owallet_ua"
  fi

  if [[ -n "$inventory_owallet_ua" && -n "$dkg_owallet_ua" && "$inventory_owallet_ua" != "$dkg_owallet_ua" ]]; then
    die "inventory contracts.owallet_ua ($inventory_owallet_ua) does not match dkg owallet ua ($dkg_owallet_ua)"
  fi

  if [[ -n "$inventory_owallet_ua" ]]; then
    printf '%s\n' "$inventory_owallet_ua"
  elif [[ -n "$dkg_owallet_ua" ]]; then
    printf '%s\n' "$dkg_owallet_ua"
  elif [[ -n "$bridge_summary_owallet_ua" ]]; then
    printf '%s\n' "$bridge_summary_owallet_ua"
  fi
}

production_refresh_bridge_summary_owallet_ua() {
  local bridge_summary="$1"
  local dkg_summary="$2"
  local dkg_completion="${3:-}"
  local bridge_summary_owallet_ua summary_owallet_ua completion_owallet_ua effective_owallet_ua tmp

  bridge_summary_owallet_ua="$(production_json_optional "$bridge_summary" '.owallet_ua // .juno_shielded_address')"
  summary_owallet_ua="$(production_json_optional "$dkg_summary" '.juno_shielded_address // .owallet_ua')"
  completion_owallet_ua=""
  if [[ -n "$dkg_completion" ]]; then
    completion_owallet_ua="$(production_json_optional "$dkg_completion" '.juno_shielded_address // .owallet_ua')"
  fi

  effective_owallet_ua="$(production_effective_owallet_ua "" "$bridge_summary_owallet_ua" "$summary_owallet_ua" "$completion_owallet_ua")"
  [[ -n "$effective_owallet_ua" ]] || return 0

  tmp="$(mktemp)"
  jq \
    --arg owallet_ua "$effective_owallet_ua" \
    '.owallet_ua = $owallet_ua | .juno_shielded_address = $owallet_ua' \
    "$bridge_summary" >"$tmp"
  mv "$tmp" "$bridge_summary"
}

production_dkg_operator_key_file() {
  local dkg_summary="$1"
  local operator_id="$2"
  jq -er --arg operator_id "${operator_id,,}" '
    .operators[]
    | select((.operator_id | ascii_downcase) == $operator_id)
    | .operator_key_file // empty
  ' "$dkg_summary" 2>/dev/null || true
}

production_seed_local_checkpoint_signer_secret() {
  die "local checkpoint signer seeding is disabled; use CHECKPOINT_SIGNER_DRIVER=aws-kms"
}

production_dkg_signer_keys_csv() {
  local dkg_summary="$1"
  local dkg_dir operator_key_file operator_key_hex
  local -a key_hexes=()

  dkg_dir="$(cd "$(dirname "$dkg_summary")" && pwd)"
  while IFS= read -r operator_key_file; do
    [[ -n "$operator_key_file" ]] || return 1
    operator_key_file="$(production_abs_path "$dkg_dir" "$operator_key_file")"
    [[ -f "$operator_key_file" ]] || die "operator key file not found: $operator_key_file"
    operator_key_hex="$(production_normalize_ecdsa_private_key "$(cat "$operator_key_file")")"
    key_hexes+=("$operator_key_hex")
  done < <(jq -r '.operators[] | .operator_key_file // empty' "$dkg_summary")

  (( ${#key_hexes[@]} > 0 )) || return 1
  IFS=,
  printf '%s\n' "${key_hexes[*]}"
}

production_csv_value_at_index() {
  local csv="$1"
  local index="$2"
  local IFS=,
  local -a values=()
  read -r -a values <<<"$csv"
  (( index >= 1 )) || return 1
  (( ${#values[@]} >= index )) || return 1
  printf '%s\n' "${values[$((index - 1))]}"
}

production_dkg_operator_signer_key_hex() {
  local dkg_summary="$1"
  local operator_id="$2"
  local dkg_dir operator_key_file

  operator_key_file="$(production_dkg_operator_key_file "$dkg_summary" "$operator_id")"
  [[ -n "$operator_key_file" ]] || return 1

  dkg_dir="$(cd "$(dirname "$dkg_summary")" && pwd)"
  operator_key_file="$(production_abs_path "$dkg_dir" "$operator_key_file")"
  [[ -f "$operator_key_file" ]] || die "operator key file not found for $operator_id: $operator_key_file"
  production_normalize_ecdsa_private_key "$(cat "$operator_key_file")"
}

production_checkpoint_signer_kms_provisioner_bin() {
  local override="${PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN:-}"
  if [[ -n "$override" ]]; then
    printf '%s\n' "$override"
    return 0
  fi
  printf '%s\n' "$REPO_ROOT/deploy/production/provision-checkpoint-signer-kms.sh"
}

production_operator_checkpoint_signer_kms_alias() {
  local environment="$1"
  local operator_id="$2"
  printf 'alias/intents-juno-%s-checkpoint-signer-%s\n' \
    "$(production_safe_slug "${environment,,}")" \
    "$(production_safe_slug "${operator_id,,}")"
}

production_try_describe_kms_key_arn() {
  local key_id="$1"
  local aws_profile="$2"
  local aws_region="$3"
  local key_arn=""

  [[ -n "$key_id" ]] || return 1
  if [[ "$key_id" =~ ^arn:aws:kms:[^:]+:[0-9]{12}:key/.+$ ]]; then
    printf '%s\n' "$key_id"
    return 0
  fi
  have_cmd aws || return 1

  key_arn="$(
    AWS_PAGER="" aws ${aws_profile:+--profile "$aws_profile"} ${aws_region:+--region "$aws_region"} \
      kms describe-key \
      --key-id "$key_id" \
      --query 'KeyMetadata.Arn' \
      --output text 2>/dev/null || true
  )"
  [[ "$key_arn" =~ ^arn:aws:kms:[^:]+:[0-9]{12}:key/.+$ ]] || return 1
  printf '%s\n' "$key_arn"
}

production_inventory_checkpoint_signer_kms_key_arns_json() {
  local inventory="$1"
  local environment operator_count index
  local operator_json operator_id aws_profile aws_region explicit_key_id alias_name key_arn
  local tmp

  environment="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  operator_count="$(jq -r '(.operators // []) | length' "$inventory")"
  tmp="$(mktemp)"
  for ((index = 0; index < operator_count; index++)); do
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    explicit_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$operator_json")"
    aws_profile="$(jq -r '.aws_profile // empty' <<<"$operator_json")"
    aws_region="$(jq -r '.aws_region // empty' <<<"$operator_json")"
    if [[ -n "$explicit_key_id" ]]; then
      if [[ "$explicit_key_id" =~ ^arn:aws:kms:[^:]+:[0-9]{12}:key/.+$ ]]; then
        key_arn="$explicit_key_id"
      else
        key_arn="$(production_try_describe_kms_key_arn "$explicit_key_id" "$aws_profile" "$aws_region" || true)"
      fi
    else
      operator_id="$(jq -r '.operator_id // empty' <<<"$operator_json")"
      [[ -n "$operator_id" ]] || continue
      alias_name="$(production_operator_checkpoint_signer_kms_alias "$environment" "$operator_id")"
      key_arn="$(production_try_describe_kms_key_arn "$alias_name" "$aws_profile" "$aws_region" || true)"
    fi
    [[ -n "$key_arn" ]] || continue
    printf '%s\n' "$key_arn" >>"$tmp"
  done
  jq -Rcs 'split("\n") | map(select(length > 0)) | unique' "$tmp"
  rm -f "$tmp"
}

production_resolve_checkpoint_signer_kms_key_id() {
  local environment="$1"
  local dkg_summary="$2"
  local operator_json="$3"

  local operator_id operator_address aws_profile aws_region account_id explicit_key_id
  local alias_name operator_key_hex provisioner_bin result_json key_arn
  local -a provision_cmd=()

  operator_id="$(jq -r '.operator_id | select(type == "string" and length > 0)' <<<"$operator_json")"
  operator_address="$(jq -r '.operator_address // .operator_id // empty' <<<"$operator_json")"
  aws_profile="$(jq -r '.aws_profile // empty' <<<"$operator_json")"
  aws_region="$(jq -r '.aws_region // empty' <<<"$operator_json")"
  account_id="$(jq -r '.account_id // empty' <<<"$operator_json")"
  explicit_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$operator_json")"

  [[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "operator $operator_id is missing a valid operator address for checkpoint signer kms"

  if [[ "$explicit_key_id" =~ ^arn:aws:kms:[^:]+:[0-9]{12}:key/.+$ ]]; then
    printf '%s\n' "$explicit_key_id"
    return 0
  fi

  provisioner_bin="$(production_checkpoint_signer_kms_provisioner_bin)"
  [[ -x "$provisioner_bin" ]] || die "checkpoint signer kms provisioner not found or not executable: $provisioner_bin"

  provision_cmd=(
    "$provisioner_bin"
    --operator-id "$operator_id"
    --operator-address "$operator_address"
  )
  if [[ -n "$aws_profile" ]]; then
    provision_cmd+=(--aws-profile "$aws_profile")
  fi
  if [[ -n "$aws_region" ]]; then
    provision_cmd+=(--aws-region "$aws_region")
  fi
  if [[ -n "$account_id" ]]; then
    provision_cmd+=(--account-id "$account_id")
  fi
  if [[ -n "$explicit_key_id" ]]; then
    provision_cmd+=(--key-id "$explicit_key_id")
  else
    alias_name="$(production_operator_checkpoint_signer_kms_alias "$environment" "$operator_id")"
    operator_key_hex="$(production_dkg_operator_signer_key_hex "$dkg_summary" "$operator_id" || true)"
    [[ -n "$operator_key_hex" ]] || die "operator $operator_id is missing operator_key_file; cannot provision checkpoint signer kms key"
    provision_cmd+=(
      --alias-name "$alias_name"
      --private-key "$operator_key_hex"
      --description "intents-juno checkpoint signer for $environment $operator_id"
    )
  fi

  result_json="$(mktemp)"
  if ! "${provision_cmd[@]}" >"$result_json"; then
    rm -f "$result_json"
    die "failed to resolve checkpoint signer kms key for operator $operator_id"
  fi
  key_arn="$(jq -r '.keyArn // empty' "$result_json")"
  rm -f "$result_json"
  [[ "$key_arn" =~ ^arn:aws:kms:[^:]+:[0-9]{12}:key/.+$ ]] || die "invalid checkpoint signer kms key arn for operator $operator_id: $key_arn"
  printf '%s\n' "$key_arn"
}

production_operator_txsign_signer_key() {
  local dkg_summary="$1"
  local operator_id="$2"
  local operator_index="$3"
  local secret_contract_file="${4:-}"
  local aws_profile="${5:-}"
  local aws_region="${6:-}"
  local signer_key existing_keys

  signer_key="$(production_dkg_operator_signer_key_hex "$dkg_summary" "$operator_id" 2>/dev/null || true)"
  if [[ -n "$signer_key" ]]; then
    printf '%s\n' "$signer_key"
    return 0
  fi

  return 1
}

production_require_single_txsign_signer_key() {
  local csv="$1"
  local IFS=,
  local -a values=()

  read -r -a values <<<"$csv"
  (( ${#values[@]} == 1 )) || die "JUNO_TXSIGN_SIGNER_KEYS must contain exactly one operator key in production"
  production_normalize_ecdsa_private_key "${values[0]}"
}

production_normalize_prefixed_hex() {
  local raw_value="$1"
  local expected_nibbles="$2"
  local field_name="$3"
  local normalized
  normalized="$(tr '[:upper:]' '[:lower:]' <<<"${raw_value#0x}")"
  [[ "$normalized" =~ ^[0-9a-f]+$ ]] || die "$field_name must be hex"
  [[ "${#normalized}" -eq "$expected_nibbles" ]] || die "$field_name must be ${expected_nibbles} hex chars"
  printf '0x%s\n' "$normalized"
}

production_derive_owallet_keys_from_ufvk() {
  local signer_ufvk="$1"
  local repo_root derive_manifest output status deposit_ivk withdraw_ovk

  repo_root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
  derive_manifest="${repo_root}/deploy/operators/dkg/e2e/ufvk-derive-keys/Cargo.toml"
  [[ -f "$derive_manifest" ]] || die "ufvk derive manifest not found: $derive_manifest"
  have_cmd cargo || die "cargo is required to derive oWallet keys from signer_ufvk"

  set +e
  output="$(cargo run --quiet --manifest-path "$derive_manifest" -- "$signer_ufvk" 2>&1)"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    die "failed to derive oWallet keys from signer_ufvk"
  fi

  deposit_ivk="$(awk -F= '/^SP1_DEPOSIT_OWALLET_IVK_HEX=/{print $2; exit}' <<<"$output")"
  withdraw_ovk="$(awk -F= '/^SP1_WITHDRAW_OWALLET_OVK_HEX=/{print $2; exit}' <<<"$output")"
  [[ -n "$deposit_ivk" ]] || die "ufvk derive output is missing SP1_DEPOSIT_OWALLET_IVK_HEX"
  [[ -n "$withdraw_ovk" ]] || die "ufvk derive output is missing SP1_WITHDRAW_OWALLET_OVK_HEX"

  deposit_ivk="$(production_normalize_prefixed_hex "$deposit_ivk" 128 "SP1_DEPOSIT_OWALLET_IVK_HEX")"
  withdraw_ovk="$(production_normalize_prefixed_hex "$withdraw_ovk" 64 "SP1_WITHDRAW_OWALLET_OVK_HEX")"
  printf '%s\n%s\n' "$deposit_ivk" "$withdraw_ovk"
}

production_port_from_listen_addr() {
  local listen_addr="$1"
  local port="${listen_addr##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] || die "invalid listen address, expected host:port: $listen_addr"
  printf '%s\n' "$port"
}

production_host_from_listen_addr() {
  local listen_addr="$1"
  local host="${listen_addr%:*}"
  [[ -n "$host" && "$host" != "$listen_addr" ]] || die "invalid listen address, expected host:port: $listen_addr"
  printf '%s\n' "$host"
}

production_require_loopback_listen_addr() {
  local listen_addr="$1"
  local field_name="$2"
  local host
  host="$(production_host_from_listen_addr "$listen_addr")"
  case "$host" in
    127.0.0.1|localhost)
      ;;
    *)
      die "$field_name must bind loopback: $listen_addr"
      ;;
  esac
}

production_is_loopback_url() {
  local url="$1"
  [[ "$url" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:|/|$) ]]
}

production_endpoint_host() {
  local endpoint="$1"
  local host

  host="$(printf '%s\n' "$endpoint" | sed -E 's|^https?://\[?([^]/]+)\]?(:[0-9]+)?$|\1|')"
  [[ -n "$host" && "$host" != "$endpoint" ]] || die "invalid endpoint, expected https://host:port: $endpoint"
  printf '%s\n' "$host"
}

production_is_nonroutable_host() {
  local host="$1"
  case "$host" in
    localhost|127.*|0.0.0.0|::1|'[::1]'|::)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

production_require_routable_dkg_endpoints() {
  local dkg_summary="$1"
  local endpoint host

  while IFS= read -r endpoint; do
    [[ -n "$endpoint" ]] || continue
    host="$(production_endpoint_host "$endpoint")"
    if production_is_nonroutable_host "$host"; then
      die "dkg summary contains a non-routable operator endpoint ($endpoint); rerun DKG with operator-reachable endpoints before production-style deployment"
    fi
  done < <(jq -r '.operators[] | (.endpoint // .grpc_endpoint // empty)' "$dkg_summary")
}

production_public_url() {
  local scheme="$1"
  local host="$2"
  local listen_addr="$3"
  local port
  port="$(production_port_from_listen_addr "$listen_addr")"
  case "$scheme:$port" in
    http:80|https:443)
      printf '%s://%s\n' "$scheme" "$host"
      ;;
    *)
      printf '%s://%s:%s\n' "$scheme" "$host" "$port"
      ;;
  esac
}

production_origin_url() {
  local scheme="$1"
  local host="$2"
  printf '%s://%s\n' "$scheme" "$host"
}

production_is_positive_integer() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 ))
}

production_default_withdraw_coordinator_juno_fee_add_zat() {
  printf '1000000\n'
}

production_default_bridge_fee_bps() {
  printf '50\n'
}

production_default_bridge_relayer_tip_bps() {
  printf '1000\n'
}

production_default_bridge_withdrawal_expiry_window_seconds() {
  printf '86400\n'
}

production_default_bridge_max_expiry_extension_seconds() {
  printf '43200\n'
}

production_compute_min_bridge_withdraw_amount_zat() {
  local fee_add_zat="$1"
  local fee_bps="$2"
  local numerator

  production_is_positive_integer "$fee_add_zat" || die "bridge min withdraw fee add must be a positive integer"
  production_is_positive_integer "$fee_bps" || die "bridge fee bps must be a positive integer"
  (( fee_bps <= 10000 )) || die "bridge fee bps must be <= 10000"

  numerator=$(( fee_add_zat * 10000 + fee_bps - 1 ))
  printf '%s\n' $(( numerator / fee_bps ))
}

production_compute_min_bridge_deposit_amount_zat() {
  local min_withdraw_amount="$1"
  local fee_bps="$2"
  local net_bps numerator

  production_is_positive_integer "$min_withdraw_amount" || die "bridge min withdraw amount must be a positive integer"
  production_is_positive_integer "$fee_bps" || die "bridge fee bps must be a positive integer"
  (( fee_bps <= 10000 )) || die "bridge fee bps must be <= 10000"
  net_bps=$(( 10000 - fee_bps ))
  (( net_bps > 0 )) || die "bridge fee bps leaves no net deposit amount"

  numerator=$(( (min_withdraw_amount - 1) * 10000 ))
  printf '%s\n' $(( numerator / net_bps + 1 ))
}

production_default_bridge_min_withdraw_amount_zat() {
  production_compute_min_bridge_withdraw_amount_zat \
    "$(production_default_withdraw_coordinator_juno_fee_add_zat)" \
    "$(production_default_bridge_fee_bps)"
}

production_default_bridge_min_deposit_amount_zat() {
  production_compute_min_bridge_deposit_amount_zat \
    "$(production_default_bridge_min_withdraw_amount_zat)" \
    "$(production_default_bridge_fee_bps)"
}

production_default_deposit_min_confirmations() {
  local value="${PRODUCTION_DEPLOY_DEPOSIT_MIN_CONFIRMATIONS:-1}"
  production_is_positive_integer "$value" \
    || die "PRODUCTION_DEPLOY_DEPOSIT_MIN_CONFIRMATIONS must be a positive integer"
  printf '%s\n' "$value"
}

production_default_withdraw_planner_min_confirmations() {
  local value="${PRODUCTION_DEPLOY_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"
  production_is_positive_integer "$value" \
    || die "PRODUCTION_DEPLOY_WITHDRAW_PLANNER_MIN_CONFIRMATIONS must be a positive integer"
  printf '%s\n' "$value"
}

production_default_withdraw_batch_confirmations() {
  local value="${PRODUCTION_DEPLOY_WITHDRAW_BATCH_CONFIRMATIONS:-1}"
  production_is_positive_integer "$value" \
    || die "PRODUCTION_DEPLOY_WITHDRAW_BATCH_CONFIRMATIONS must be a positive integer"
  printf '%s\n' "$value"
}

production_required_min_base_relayer_balance_wei() {
  local value="${PRODUCTION_DEPLOY_MIN_BASE_RELAYER_BALANCE_WEI:-1000000000000000}"
  production_is_positive_integer "$value" \
    || die "PRODUCTION_DEPLOY_MIN_BASE_RELAYER_BALANCE_WEI must be a positive integer"
  printf '%s\n' "$value"
}

production_environment_allows_local_secret_resolvers() {
  return 1
}

production_operator_uses_runtime_material_ref() {
  local operator_deploy="$1"
  [[ -f "$operator_deploy" ]] || return 1
  [[ "$(jq -r '.runtime_material_ref.mode // empty' "$operator_deploy")" == "s3-kms-zip" ]]
}

production_runtime_material_ref_field() {
  local operator_deploy="$1"
  local field="$2"
  jq -r --arg field "$field" '.runtime_material_ref[$field] // empty' "$operator_deploy"
}

production_resolve_instance_id_from_host() {
  local aws_profile="$1"
  local aws_region="$2"
  local host="$3"
  local query='Reservations[].Instances[].InstanceId'
  local result=""

  [[ -n "$aws_profile" && -n "$aws_region" ]] || die "aws profile and region are required to resolve an instance id"
  have_cmd aws || die "required command not found: aws"

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    result="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
      --filters "Name=ip-address,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
    if [[ -z "$result" || "$result" == "None" ]]; then
      result="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
        --filters "Name=private-ip-address,Values=$host" \
        --query "$query" --output text 2>/dev/null || true)"
    fi
  else
    result="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ec2 describe-instances \
      --filters "Name=dns-name,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
  fi

  [[ -n "$result" && "$result" != "None" ]] || die "failed to resolve instance id for host: $host"
  printf '%s\n' "$result"
}

production_ssm_run_shell_command() {
  local aws_profile="$1"
  local aws_region="$2"
  local instance_id="$3"
  local command="$4"
  local send_json command_id invocation_json invocation_status stderr stdout parameters_json parameters_file
  local poll_attempts="${5:-30}"
  local poll_interval_seconds="${6:-2}"

  have_cmd aws || die "required command not found: aws"
  have_cmd jq || die "required command not found: jq"

  parameters_json="$(jq -cn --arg command "$command" '{commands: [$command]}')"
  parameters_file="$(mktemp)"
  printf '%s' "$parameters_json" >"$parameters_file"
  send_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --parameters "file://$parameters_file" \
    --output json 2>/dev/null || true)"
  rm -f "$parameters_file"
  [[ -n "$send_json" ]] || return 1
  command_id="$(jq -r '.Command.CommandId // empty' <<<"$send_json")"
  [[ -n "$command_id" ]] || return 1

  for _ in $(seq 1 "$poll_attempts"); do
    invocation_json="$(AWS_PAGER="" aws --profile "$aws_profile" --region "$aws_region" ssm get-command-invocation \
      --command-id "$command_id" \
      --instance-id "$instance_id" \
      --output json 2>/dev/null || true)"
    [[ -n "$invocation_json" ]] || {
      sleep "$poll_interval_seconds"
      continue
    }

    invocation_status="$(jq -r '.Status // empty' <<<"$invocation_json")"
    case "$invocation_status" in
      Success)
        stdout="$(jq -r '.StandardOutputContent // ""' <<<"$invocation_json")"
        printf '%s' "$stdout"
        return 0
        ;;
      Failed|Cancelled|TimedOut|Cancelling)
        stderr="$(jq -r '.StandardErrorContent // ""' <<<"$invocation_json")"
        [[ -n "$stderr" ]] && printf '%s\n' "$stderr" >&2
        return 1
        ;;
      Pending|InProgress|Delayed|"")
        sleep "$poll_interval_seconds"
        ;;
      *)
        sleep "$poll_interval_seconds"
        ;;
    esac
  done

  return 1
}

production_ssm_stage_file() {
  local aws_profile="$1"
  local aws_region="$2"
  local instance_id="$3"
  local source_path="$4"
  local destination_path="$5"
  local mode="${6:-0640}"

  [[ -f "$source_path" ]] || die "stage source file not found: $source_path"
  have_cmd base64 || die "required command not found: base64"

  local encoded command
  encoded="$(base64 <"$source_path" | tr -d '\n')"
  command="$(cat <<EOF
sudo install -d -m 0755 "$(dirname "$destination_path")"
printf '%s' '$encoded' | base64 --decode | sudo tee "$destination_path" >/dev/null
sudo chmod $mode "$destination_path"
EOF
)"
  production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "$command" >/dev/null
}

production_environment_allows_local_checkpoint_signer() {
  return 1
}

production_kafka_auth_mode_for_environment() {
  printf 'aws-msk-iam\n'
}

production_base_relayer_private_keys() {
  local env_file="$1"
  local base_relayer_private_keys
  local -a base_relayer_keys=()
  local key

  base_relayer_private_keys="$(production_env_first_value "$env_file" BASE_RELAYER_PRIVATE_KEYS || true)"
  [[ -n "$base_relayer_private_keys" ]] || die "resolved secret env is missing BASE_RELAYER_PRIVATE_KEYS"

  IFS=',' read -r -a base_relayer_keys <<<"$base_relayer_private_keys"
  [[ "${#base_relayer_keys[@]}" -gt 0 ]] || die "resolved secret env BASE_RELAYER_PRIVATE_KEYS is empty"
  for key in "${base_relayer_keys[@]}"; do
    [[ -n "${key//[[:space:]]/}" ]] || continue
    production_normalize_ecdsa_private_key "$key"
  done
}

production_base_relayer_addresses() {
  local env_file="$1"
  local private_key address

  have_cmd cast || die "cast is required to verify base relayer funding"
  while IFS= read -r private_key; do
    [[ -n "$private_key" ]] || continue
    address="$(cast wallet address --private-key "$private_key" | tr -d '[:space:]')"
    [[ "$address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "failed to derive base relayer address from BASE_RELAYER_PRIVATE_KEYS"
    printf '%s\n' "$address"
  done < <(production_base_relayer_private_keys "$env_file")
}

production_base_relayer_addresses_csv() {
  local env_file="$1"
  local addresses_csv=""
  local address

  while IFS= read -r address; do
    [[ -n "$address" ]] || continue
    if [[ -n "$addresses_csv" ]]; then
      addresses_csv+=","
    fi
    addresses_csv+="$address"
  done < <(production_base_relayer_addresses "$env_file")

  printf '%s\n' "$addresses_csv"
}

production_backoffice_relayer_signer_addresses_csv() {
  local app_deploy="$1"
  local addresses_csv

  addresses_csv="$(production_json_optional "$app_deploy" '.base_relayer_signer_addresses')"
  printf '%s\n' "$addresses_csv"
}

production_base_relayer_balance_snapshot() {
  local env_file="$1"
  local base_rpc_url="$2"
  local address balance_wei

  [[ -n "$base_rpc_url" ]] || die "base rpc url is required to verify base relayer funding"
  while IFS= read -r address; do
    [[ -n "$address" ]] || continue
    balance_wei="$(cast balance --rpc-url "$base_rpc_url" "$address" | tr -d '[:space:]')"
    [[ "$balance_wei" =~ ^[0-9]+$ ]] || die "failed to resolve base relayer balance for $address"
    printf '%s %s\n' "$address" "$balance_wei"
  done < <(production_base_relayer_addresses "$env_file")
}

production_require_base_relayer_balance() {
  local env_file="$1"
  local base_rpc_url="$2"
  local minimum_balance_wei="${3:-}"
  local address balance_wei
  local saw_address="false"

  if [[ -z "$minimum_balance_wei" ]]; then
    minimum_balance_wei="$(production_required_min_base_relayer_balance_wei)"
  fi
  production_is_positive_integer "$minimum_balance_wei" \
    || die "minimum base relayer balance must be a positive integer"
  while read -r address balance_wei; do
    [[ -n "${address:-}" ]] || continue
    saw_address="true"
    if (( balance_wei < minimum_balance_wei )); then
      die "base relayer $address balance $balance_wei wei is below minimum $minimum_balance_wei wei"
    fi
  done < <(production_base_relayer_balance_snapshot "$env_file" "$base_rpc_url")
  [[ "$saw_address" == "true" ]] || die "no base relayer addresses resolved from BASE_RELAYER_PRIVATE_KEYS"
}

production_effective_operator_address() {
  local operator_deploy="$1"
  local operator_address

  operator_address="$(production_json_optional "$operator_deploy" '.operator_address')"
  if [[ -z "$operator_address" ]]; then
    operator_address="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
  fi
  printf '%s\n' "$operator_address"
}

production_require_registered_operator() {
  local shared_manifest="$1"
  local operator_deploy="$2"
  local base_rpc_url operator_registry operator_address is_registered

  have_cmd cast || die "required command not found: cast"

  base_rpc_url="$(production_json_required "$shared_manifest" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
  operator_registry="$(production_json_required "$shared_manifest" '.contracts.operator_registry | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))')"
  operator_address="$(production_effective_operator_address "$operator_deploy")"
  [[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "operator deploy manifest is missing a valid operator address"

  is_registered="$(cast call --rpc-url "$base_rpc_url" "$operator_registry" "isOperator(address)(bool)" "$operator_address" 2>/dev/null | tr -d '[:space:]')"
  case "$is_registered" in
    true|1|0x1)
      ;;
    false|0|0x0)
      die "operator $operator_address is not active in operator registry $operator_registry"
      ;;
    *)
      die "failed to verify operator registry membership for $operator_address against $operator_registry"
      ;;
  esac
}

production_is_tx_hash() {
  local value="$1"
  [[ "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]
}

production_resolve_base_event_scanner_start_block() {
  local bridge_summary="$1"
  local base_rpc_url="$2"
  local explicit_start_block tx_hash block_number max_block

  explicit_start_block="$(production_json_optional "$bridge_summary" '.base_event_scanner_start_block // .contracts.base_event_scanner_start_block // .scanner.start_block')"
  if [[ -n "$explicit_start_block" ]]; then
    production_is_positive_integer "$explicit_start_block" \
      || die "bridge summary base_event_scanner_start_block must be a positive integer"
    printf '%s\n' "$explicit_start_block"
    return 0
  fi

  command -v cast >/dev/null 2>&1 || die "cast is required to derive the base event scanner start block from bridge summary transactions"

  max_block=0
  while IFS= read -r tx_hash; do
    production_is_tx_hash "$tx_hash" || continue
    block_number="$(cast receipt "$tx_hash" blockNumber --rpc-url "$base_rpc_url" | tr -d '[:space:]')"
    production_is_positive_integer "$block_number" \
      || die "failed to resolve a positive block number for bridge summary transaction $tx_hash"
    if (( block_number > max_block )); then
      max_block="$block_number"
    fi
  done < <(jq -r '.transactions // {} | to_entries[]? | .value' "$bridge_summary")

  (( max_block > 0 )) || die "bridge summary is missing base_event_scanner_start_block and usable transaction hashes"
  printf '%s\n' "$max_block"
}

production_deposit_relayer_base_rpc_urls() {
  local shared_manifest="$1"
  local base_rpc_url base_chain_id fallback_url

  base_rpc_url="$(production_json_required "$shared_manifest" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
  base_chain_id="$(production_json_required "$shared_manifest" '.contracts.base_chain_id')"
  fallback_url="https://base-sepolia-rpc.publicnode.com"

  if [[ "$base_chain_id" == "84532" && "$base_rpc_url" == "https://sepolia.base.org" ]]; then
    printf '%s,%s\n' "$base_rpc_url" "$fallback_url"
    return 0
  fi

  printf '%s\n' "$base_rpc_url"
}

production_render_shared_manifest() {
  local inventory="$1"
  local bridge_summary="$2"
  local dkg_summary="$3"
  local tf_json="$4"
  local output_file="$5"
  local inventory_dir="$6"
  local dkg_completion="${7:-}"

  local env_slug juno_network dkg_network base_rpc_url base_chain_id deposit_image_id withdraw_image_id
  local aws_profile aws_region terraform_dir zone_id zone_name public_subdomain ttl_seconds dns_mode
  local postgres_endpoint postgres_port kafka_brokers ipfs_api_url ipfs_api_auth_secret_arn kafka_critical_hmac_secret_arn dkg_bucket dkg_prefix
  local shared_ecs_cluster_arn shared_proof_requestor_service_name shared_proof_funder_service_name
  local shared_sp1_requestor_address shared_sp1_rpc_url
  local bridge_fee_bps bridge_relayer_tip_bps bridge_withdrawal_expiry_window_seconds
  local bridge_max_expiry_extension_seconds bridge_min_deposit_amount bridge_min_withdraw_amount
  local operator_ids_csv threshold operators_json roster_json secret_keys_json governance_json
  local dkg_completion_network signer_ufvk inventory_owallet_ua bridge_summary_owallet_ua
  local summary_owallet_ua completion_owallet_ua effective_owallet_ua base_event_scanner_start_block
  local dkg_kms_key_arn
  local manifest_version proof_role_json wireguard_role_json shared_roles_json
  local tf_proof_role_json tf_wireguard_role_json proof_role_runtime_enabled wireguard_role_runtime_enabled
  local wireguard_source_cidrs_json

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  juno_network="$(production_json_required "$inventory" '.contracts.juno_network | select(type == "string" and length > 0)')"
  dkg_network="$(production_json_required "$dkg_summary" '.network | select(type == "string" and length > 0)')"
  [[ "$juno_network" == "$dkg_network" ]] || die "inventory contracts.juno_network ($juno_network) does not match dkg summary network ($dkg_network)"
  production_require_routable_dkg_endpoints "$dkg_summary"
  if [[ -n "$dkg_completion" ]]; then
    [[ -f "$dkg_completion" ]] || die "dkg completion not found: $dkg_completion"
    dkg_completion_network="$(production_json_optional "$dkg_completion" '.network')"
    if [[ -n "$dkg_completion_network" ]]; then
      [[ "$juno_network" == "$dkg_completion_network" ]] || die "inventory contracts.juno_network ($juno_network) does not match dkg completion network ($dkg_completion_network)"
    fi
  fi
  base_rpc_url="$(production_json_required "$inventory" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
  base_chain_id="$(production_json_required "$inventory" '.contracts.base_chain_id')"
  base_event_scanner_start_block="$(production_resolve_base_event_scanner_start_block "$bridge_summary" "$base_rpc_url")"
  deposit_image_id="$(production_json_optional "$inventory" '.contracts.deposit_image_id')"
  withdraw_image_id="$(production_json_optional "$inventory" '.contracts.withdraw_image_id')"
  aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
  aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
  terraform_dir="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  if production_dns_mode_uses_managed_public_zone "$dns_mode"; then
    zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  else
    zone_id="$(production_json_optional "$inventory" '.shared_services.route53_zone_id')"
  fi
  zone_name="$(production_json_required "$inventory" '.shared_services.public_zone_name | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"

  postgres_endpoint="$(production_tf_output_value "$tf_json" "shared_postgres_endpoint" true)"
  postgres_cluster_arn="$(production_tf_output_value "$tf_json" "shared_postgres_cluster_arn" false)"
  postgres_port="$(production_tf_output_value "$tf_json" "shared_postgres_port" true)"
  kafka_cluster_arn="$(production_tf_output_value "$tf_json" "shared_kafka_cluster_arn" false)"
  kafka_brokers="$(production_tf_output_value "$tf_json" "shared_kafka_bootstrap_brokers" true)"
  shared_ecs_cluster_arn="$(production_tf_output_value "$tf_json" "shared_ecs_cluster_arn" false)"
  shared_proof_requestor_service_name="$(production_tf_output_value "$tf_json" "shared_proof_requestor_service_name" false)"
  shared_proof_funder_service_name="$(production_tf_output_value "$tf_json" "shared_proof_funder_service_name" false)"
  shared_sp1_requestor_address="$(production_tf_output_value "$tf_json" "shared_sp1_requestor_address" false)"
  shared_sp1_rpc_url="$(production_tf_output_value "$tf_json" "shared_sp1_rpc_url" false)"
  ipfs_api_url="$(production_tf_output_value "$tf_json" "shared_ipfs_api_url" true)"
  ipfs_api_auth_secret_arn="$(production_tf_output_value "$tf_json" "shared_ipfs_api_auth_secret_arn" false)"
  kafka_critical_hmac_secret_arn="$(production_tf_output_value "$tf_json" "shared_kafka_critical_hmac_secret_arn" false)"
  ipfs_target_group_arn="$(production_tf_output_value "$tf_json" "shared_ipfs_target_group_arn" false)"
  dkg_bucket="$(production_tf_output_value "$tf_json" "dkg_s3_bucket" false)"
  dkg_prefix="$(production_tf_output_value "$tf_json" "dkg_s3_key_prefix" false)"
  dkg_kms_key_arn="$(production_tf_output_value "$tf_json" "dkg_kms_key_arn" false)"
  bridge_fee_bps="$(production_json_required "$bridge_summary" '.bridge_params.fee_bps // .bridge_fee_params.fee_bps')"
  bridge_relayer_tip_bps="$(production_json_required "$bridge_summary" '.bridge_params.relayer_tip_bps // .bridge_fee_params.relayer_tip_bps')"
  bridge_withdrawal_expiry_window_seconds="$(production_json_required "$bridge_summary" '.bridge_params.withdrawal_expiry_window_seconds')"
  bridge_max_expiry_extension_seconds="$(production_json_required "$bridge_summary" '.bridge_params.max_expiry_extension_seconds')"
  bridge_min_deposit_amount="$(production_json_required "$bridge_summary" '.bridge_params.min_deposit_amount')"
  bridge_min_withdraw_amount="$(production_json_required "$bridge_summary" '.bridge_params.min_withdraw_amount')"

  operator_ids_csv="$(production_operator_ids_csv "$dkg_summary")"
  [[ -n "$operator_ids_csv" ]] || die "dkg summary does not contain operator ids"
  threshold="$(production_threshold "$dkg_summary")"
  tf_proof_role_json="$(production_tf_output_json "$tf_json" "shared_proof_role" false)"
  tf_wireguard_role_json="$(production_tf_output_json "$tf_json" "shared_wireguard_role" false)"
  proof_role_json="$(
    jq -cn \
      --argjson inventory_role "$(production_inventory_proof_role_json "$inventory")" \
      --argjson tf_role "$tf_proof_role_json" \
      --arg requestor_address "$shared_sp1_requestor_address" \
      --arg rpc_url "$shared_sp1_rpc_url" '
        (if ($tf_role | length) > 0 then
          ($inventory_role + $tf_role)
        else
          $inventory_role
        end)
        | if ($requestor_address != "" and ($tf_role | length) == 0) then
            .requestor_address = $requestor_address
          elif (.requestor_address // "") == "" and $requestor_address != "" then
            .requestor_address = $requestor_address
          else
            .
          end
        | if ($rpc_url != "" and ($tf_role | length) == 0) then
            .rpc_url = $rpc_url
          elif (.rpc_url // "") == "" and $rpc_url != "" then
            .rpc_url = $rpc_url
          else
            .
          end
      '
  )"
  wireguard_role_json="$(
    jq -cn \
      --argjson inventory_role "$(production_inventory_wireguard_role_json "$inventory")" \
      --argjson tf_role "$tf_wireguard_role_json" '
        ($inventory_role + $tf_role)
        | .peer_roster_secret_arns = (
            if ((.peer_roster_secret_arns // []) | type) == "array" and ((.peer_roster_secret_arns // []) | length) > 0 then
              .peer_roster_secret_arns
            elif (.client_config_secret_arn // "") != "" then
              [.client_config_secret_arn]
            else
              []
            end
          )
        | .peer_config_secret_arns = (
            if ((.peer_config_secret_arns // {}) | type) == "object" and ((.peer_config_secret_arns // {}) | length) > 0 then
              .peer_config_secret_arns
            elif (.client_config_secret_arn // "") != "" then
              { preview_legacy: .client_config_secret_arn }
            else
              {}
            end
          )
      '
  )"
  proof_role_runtime_enabled="false"
  if jq -e '(.asg // "") != "" or ((.launch_template // {}) | type == "object" and length > 0)' >/dev/null <<<"$proof_role_json"; then
    proof_role_runtime_enabled="true"
  fi
  wireguard_role_runtime_enabled="false"
  if jq -e '
    (.asg // "") != ""
    or ((.launch_template // {}) | type == "object" and length > 0)
    or ((.source_cidrs // []) | type == "array" and length > 0)
  ' >/dev/null <<<"$wireguard_role_json"; then
    wireguard_role_runtime_enabled="true"
  fi
  manifest_version="1"
  if production_inventory_has_v2_roles "$inventory" || [[ "$proof_role_runtime_enabled" == "true" ]] || [[ "$wireguard_role_runtime_enabled" == "true" ]]; then
    manifest_version="2"
  fi
  shared_sp1_requestor_address="$(jq -r '.requestor_address // empty' <<<"$proof_role_json")"
  shared_sp1_rpc_url="$(jq -r '.rpc_url // empty' <<<"$proof_role_json")"
  wireguard_gateway_private_ip="$(jq -r '.gateway_private_ip // empty' <<<"$wireguard_role_json")"
  wireguard_endpoint_host="$(jq -r '.endpoint_host // empty' <<<"$wireguard_role_json")"
  wireguard_listen_port="$(jq -r '.listen_port // empty' <<<"$wireguard_role_json")"
  wireguard_network_cidr="$(jq -r '.network_cidr // empty' <<<"$wireguard_role_json")"
  wireguard_client_address_cidr="$(jq -r '.client_address_cidr // empty' <<<"$wireguard_role_json")"
  wireguard_client_config_secret_arn="$(jq -r '.client_config_secret_arn // empty' <<<"$wireguard_role_json")"
  wireguard_source_cidrs_json="$(jq -c '(.source_cidrs // []) | if type == "array" then . else [] end' <<<"$wireguard_role_json")"
  shared_roles_json="$(jq -cn --argjson proof "$proof_role_json" --argjson wireguard "$wireguard_role_json" '{proof: $proof, wireguard: $wireguard}')"
  operators_json="$(jq -c '[.operators[].operator_id]' "$dkg_summary")"
  roster_json="$(
    jq -c '.operators' "$inventory" | jq -c '
      map({
        index,
        operator_id,
        aws_profile,
        aws_region,
        account_id,
        public_dns_label,
        public_endpoint,
        operator_host
      })
    ' | while IFS= read -r operators_json_line; do
      jq -cn \
        --argjson operators "$operators_json_line" \
        --slurpfile dkg_summary "$dkg_summary" '
          $operators
          | map(
              . as $operator
              | {
                  index: $operator.index,
                  operator_id: $operator.operator_id,
                  aws_profile: $operator.aws_profile,
                  aws_region: $operator.aws_region,
                  account_id: $operator.account_id,
                  public_dns_label: $operator.public_dns_label,
                  dkg_endpoint: (
                    (
                      ($dkg_summary[0].operators // [])
                      | map(select(.operator_id == $operator.operator_id))[0].endpoint
                    ) // (
                      if (($operator.public_endpoint // $operator.operator_host // "") | length) > 0 and ($operator.index != null) then
                        "https://\(($operator.public_endpoint // $operator.operator_host)):\(18442 + ($operator.index | tonumber))"
                      else
                        null
                      end
                    )
                  )
                }
            )
        '
    done
  )"
  secret_keys_json="$(production_secret_keys_json "$inventory" "$inventory_dir")"
  governance_json="$(jq -c '.governance // null' "$bridge_summary")"
  inventory_owallet_ua="$(production_json_optional "$inventory" '.contracts.owallet_ua')"
  bridge_summary_owallet_ua="$(production_json_optional "$bridge_summary" '.owallet_ua // .juno_shielded_address')"
  summary_owallet_ua="$(production_json_optional "$dkg_summary" '.juno_shielded_address // .owallet_ua')"
  completion_owallet_ua=""
  if [[ -n "$dkg_completion" ]]; then
    completion_owallet_ua="$(production_json_optional "$dkg_completion" '.juno_shielded_address // .owallet_ua')"
  fi
  effective_owallet_ua="$(production_effective_owallet_ua "$inventory_owallet_ua" "$bridge_summary_owallet_ua" "$summary_owallet_ua" "$completion_owallet_ua")"
  signer_ufvk="$(production_json_optional "$dkg_summary" '.ufvk')"
  if [[ -z "$signer_ufvk" && -n "$dkg_completion" ]]; then
    signer_ufvk="$(production_json_optional "$dkg_completion" '.ufvk')"
  fi
  [[ -n "$signer_ufvk" ]] || die "dkg summary and completion are missing ufvk"

  jq -n \
    --arg version "$manifest_version" \
    --arg environment "$env_slug" \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg juno_network "$juno_network" \
    --arg aws_profile "$aws_profile" \
    --arg aws_region "$aws_region" \
    --arg terraform_dir "$terraform_dir" \
    --arg zone_id "$zone_id" \
    --arg zone_name "$zone_name" \
    --arg public_subdomain "$public_subdomain" \
    --arg dns_mode "$dns_mode" \
    --arg postgres_endpoint "$postgres_endpoint" \
    --arg postgres_cluster_arn "$postgres_cluster_arn" \
    --arg postgres_port "$postgres_port" \
    --arg kafka_cluster_arn "$kafka_cluster_arn" \
    --arg kafka_brokers "$kafka_brokers" \
    --arg shared_ecs_cluster_arn "$shared_ecs_cluster_arn" \
    --arg shared_proof_requestor_service_name "$shared_proof_requestor_service_name" \
    --arg shared_proof_funder_service_name "$shared_proof_funder_service_name" \
    --arg kafka_auth_mode "$(production_kafka_auth_mode_for_environment "$env_slug")" \
    --arg kafka_auth_aws_region "$aws_region" \
    --arg kafka_critical_key_id "default" \
    --arg kafka_critical_hmac_secret_arn "$kafka_critical_hmac_secret_arn" \
    --arg shared_sp1_requestor_address "$shared_sp1_requestor_address" \
    --arg shared_sp1_rpc_url "$shared_sp1_rpc_url" \
    --arg ipfs_api_url "$ipfs_api_url" \
    --arg ipfs_api_auth_secret_arn "$ipfs_api_auth_secret_arn" \
    --arg ipfs_target_group_arn "$ipfs_target_group_arn" \
    --arg wireguard_gateway_private_ip "$wireguard_gateway_private_ip" \
    --arg wireguard_endpoint_host "$wireguard_endpoint_host" \
    --arg wireguard_listen_port "$wireguard_listen_port" \
    --arg wireguard_network_cidr "$wireguard_network_cidr" \
    --arg wireguard_client_address_cidr "$wireguard_client_address_cidr" \
    --arg wireguard_client_config_secret_arn "$wireguard_client_config_secret_arn" \
    --argjson wireguard_source_cidrs "$wireguard_source_cidrs_json" \
    --arg dkg_bucket "$dkg_bucket" \
    --arg dkg_prefix "$dkg_prefix" \
    --arg dkg_kms_key_arn "$dkg_kms_key_arn" \
    --arg base_rpc_url "$base_rpc_url" \
    --argjson base_chain_id "$base_chain_id" \
    --argjson base_event_scanner_start_block "$base_event_scanner_start_block" \
    --argjson bridge_fee_bps "$bridge_fee_bps" \
    --argjson bridge_relayer_tip_bps "$bridge_relayer_tip_bps" \
    --argjson bridge_withdrawal_expiry_window_seconds "$bridge_withdrawal_expiry_window_seconds" \
    --argjson bridge_max_expiry_extension_seconds "$bridge_max_expiry_extension_seconds" \
    --argjson bridge_min_deposit_amount "$bridge_min_deposit_amount" \
    --argjson bridge_min_withdraw_amount "$bridge_min_withdraw_amount" \
    --arg deposit_image_id "$deposit_image_id" \
    --arg withdraw_image_id "$withdraw_image_id" \
    --arg signer_ufvk "$signer_ufvk" \
    --arg bridge_address "$(production_json_required "$bridge_summary" '.contracts.bridge | select(type == "string" and length > 0)')" \
    --arg wjuno_address "$(production_json_optional "$bridge_summary" '.contracts.wjuno')" \
    --arg operator_registry "$(production_json_optional "$bridge_summary" '.contracts.operator_registry')" \
    --arg fee_distributor "$(production_json_optional "$bridge_summary" '.contracts.fee_distributor')" \
    --arg effective_owallet_ua "$effective_owallet_ua" \
    --argjson ttl_seconds "$ttl_seconds" \
    --argjson checkpoint_threshold "$threshold" \
    --argjson checkpoint_operators "$operators_json" \
    --argjson operator_roster "$roster_json" \
    --argjson secret_reference_names "$secret_keys_json" \
    --argjson governance "$governance_json" \
    --argjson proof_role "$proof_role_json" \
    --argjson wireguard_role "$wireguard_role_json" \
    --argjson shared_roles "$shared_roles_json" \
    --arg proof_role_runtime_enabled "$proof_role_runtime_enabled" \
    '{
      version: $version,
      environment: $environment,
      generated_at: $generated_at,
      shared_services: {
        aws_profile: $aws_profile,
        aws_region: $aws_region,
        terraform_dir: $terraform_dir,
        postgres: {
          endpoint: $postgres_endpoint,
          cluster_arn: (if $postgres_cluster_arn == "" then null else $postgres_cluster_arn end),
          port: ($postgres_port | tonumber)
        },
        kafka: {
          cluster_arn: (if $kafka_cluster_arn == "" then null else $kafka_cluster_arn end),
          bootstrap_brokers: $kafka_brokers,
          tls: true,
          auth: {
            mode: $kafka_auth_mode,
            aws_region: $kafka_auth_aws_region
          },
          critical_key_id: $kafka_critical_key_id,
          critical_hmac_secret_arn: (if $kafka_critical_hmac_secret_arn == "" then null else $kafka_critical_hmac_secret_arn end),
          min_insync_replicas: 2
        },
        ecs: (
          if $shared_ecs_cluster_arn == "" and $shared_proof_requestor_service_name == "" and $shared_proof_funder_service_name == "" then
            null
          else
            {
              cluster_arn: (if $shared_ecs_cluster_arn == "" then null else $shared_ecs_cluster_arn end),
              proof_requestor_service_name: (if $shared_proof_requestor_service_name == "" then null else $shared_proof_requestor_service_name end),
              proof_funder_service_name: (if $shared_proof_funder_service_name == "" then null else $shared_proof_funder_service_name end)
            }
          end
        ),
        proof: {
          requestor_address: (if $shared_sp1_requestor_address == "" then null else $shared_sp1_requestor_address end),
          rpc_url: (if $shared_sp1_rpc_url == "" then null else $shared_sp1_rpc_url end)
        },
        ipfs: {
          api_url: $ipfs_api_url,
          api_auth_secret_arn: (if $ipfs_api_auth_secret_arn == "" then null else $ipfs_api_auth_secret_arn end),
          target_group_arn: (if $ipfs_target_group_arn == "" then null else $ipfs_target_group_arn end)
        },
        artifacts: {
          checkpoint_blob_bucket: (if $dkg_bucket == "" then null else $dkg_bucket end),
          checkpoint_blob_prefix: (if $dkg_prefix == "" then null else $dkg_prefix end),
          checkpoint_blob_sse_kms_key_id: (if $dkg_kms_key_arn == "" then null else $dkg_kms_key_arn end)
        }
      },
      contracts: {
        juno_network: $juno_network,
        base_rpc_url: $base_rpc_url,
        base_chain_id: $base_chain_id,
        base_event_scanner_start_block: $base_event_scanner_start_block,
        bridge: $bridge_address,
        wjuno: (if $wjuno_address == "" then null else $wjuno_address end),
        operator_registry: (if $operator_registry == "" then null else $operator_registry end),
        fee_distributor: (if $fee_distributor == "" then null else $fee_distributor end),
        bridge_params: {
          fee_bps: $bridge_fee_bps,
          relayer_tip_bps: $bridge_relayer_tip_bps,
          withdrawal_expiry_window_seconds: $bridge_withdrawal_expiry_window_seconds,
          max_expiry_extension_seconds: $bridge_max_expiry_extension_seconds,
          min_deposit_amount: $bridge_min_deposit_amount,
          min_withdraw_amount: $bridge_min_withdraw_amount
        },
        deposit_image_id: (if $deposit_image_id == "" then null else $deposit_image_id end),
        withdraw_image_id: (if $withdraw_image_id == "" then null else $withdraw_image_id end),
        owallet_ua: (if $effective_owallet_ua == "" then null else $effective_owallet_ua end)
      },
      shared_roles: $shared_roles,
      wireguard_role: $wireguard_role,
      checkpoint: {
        operators: $checkpoint_operators,
        threshold: $checkpoint_threshold,
        signer_ufvk: $signer_ufvk,
        signature_topic: "checkpoints.signatures.v1",
        package_topic: "checkpoints.packages.v1"
      },
      operator_roster: $operator_roster,
      dns: {
        mode: $dns_mode,
        zone_id: (if $zone_id == "" then null else $zone_id end),
        zone_name: $zone_name,
        public_subdomain: $public_subdomain,
        ttl_seconds: $ttl_seconds
      },
      governance: $governance,
      secret_reference_names: $secret_reference_names
    }' >"$output_file"
}

production_render_app_handoff() {
  local inventory="$1"
  local shared_manifest="$2"
  local output_dir="$3"
  local inventory_dir="$4"
  local app_tf_json="${5:-}"

  if ! jq -e '((.app_host? | type == "object") or (.app_role? | type == "object"))' "$inventory" >/dev/null 2>&1; then
    return 0
  fi

  shared_manifest="$(production_abs_path "$(pwd)" "$shared_manifest")"
  output_dir="$(production_abs_path "$(pwd)" "$output_dir")"

  local env_slug public_subdomain zone_id dns_mode ttl_seconds zone_name
  local app_json app_dir manifest_path app_host app_user runtime_dir
  local public_endpoint aws_profile aws_region account_id security_group_id
  local bridge_dns_label public_scheme bridge_listen_addr backoffice_listen_addr
  local bridge_record_name bridge_public_url backoffice_access_mode backoffice_record_name backoffice_public_url
  local bridge_probe_url="" backoffice_probe_url="" bridge_internal_url="" backoffice_internal_url=""
  local bridge_withdrawal_expiry_window_seconds bridge_min_deposit_amount bridge_min_withdraw_amount bridge_fee_bps
  local juno_rpc_url operator_addresses_json
  local service_urls_json operator_endpoints_json backoffice_wireguard_source_cidrs_json
  local edge_enabled edge_state_path edge_state_dir edge_output_root edge_origin_record_name edge_origin_endpoint
  local edge_public_lb_dns_name edge_public_lb_zone_id
  local edge_origin_http_port edge_rate_limit edge_enable_shield_advanced edge_alarm_actions_json edge_viewer_certificate_arn
  local wireguard_source_cidrs_json backoffice_access_json backoffice_dns_label
  local manifest_version app_role_json proof_role_json wireguard_role_json shared_roles_json tf_app_role_json
  local runtime_config_secret_id runtime_config_secret_region

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  if production_dns_mode_uses_managed_public_zone "$dns_mode"; then
    zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  else
    zone_id="$(production_json_optional "$inventory" '.shared_services.route53_zone_id')"
  fi
  zone_name="$(production_json_required "$inventory" '.shared_services.public_zone_name | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  app_json="$(production_inventory_app_role_json "$inventory")"
  tf_app_role_json='{}'
  if [[ -n "$app_tf_json" ]]; then
    [[ -f "$app_tf_json" ]] || die "app terraform output json not found: $app_tf_json"
    tf_app_role_json="$(production_tf_output_json "$app_tf_json" "app_role" false)"
    app_json="$(
      jq -cn \
        --argjson inventory_role "$app_json" \
        --argjson tf_role "$tf_app_role_json" '
          if ($tf_role | length) > 0 then
            ($inventory_role + $tf_role)
          else
            $inventory_role
          end
        '
    )"
  fi
  manifest_version="3"
  app_role_json="$app_json"
  proof_role_json="$(production_json_optional "$shared_manifest" '.shared_roles.proof // {}')"
  if [[ -z "$proof_role_json" || "$proof_role_json" == "null" ]]; then
    proof_role_json="$(production_inventory_proof_role_json "$inventory")"
  fi
  wireguard_role_json="$(production_json_optional "$shared_manifest" '.wireguard_role // .shared_roles.wireguard // {}')"
  if [[ -z "$wireguard_role_json" || "$wireguard_role_json" == "null" ]]; then
    wireguard_role_json="$(production_inventory_wireguard_role_json "$inventory")"
  fi
  shared_roles_json="$(jq -cn --argjson proof "$proof_role_json" --argjson wireguard "$wireguard_role_json" '{proof: $proof, wireguard: $wireguard}')"

  app_host="$(jq -r '.host // empty' <<<"$app_json")"
  app_user="$(jq -r '.user // "ubuntu"' <<<"$app_json")"
  runtime_dir="$(jq -r '.runtime_dir // "/var/lib/intents-juno/app-runtime"' <<<"$app_json")"
  edge_public_lb_dns_name="$(jq -r '.public_lb.dns_name // empty' <<<"$app_json")"
  edge_public_lb_zone_id="$(jq -r '.public_lb.zone_id // empty' <<<"$app_json")"
  public_endpoint="$(jq -r '.public_lb.dns_name // .public_endpoint // .host // empty' <<<"$app_json")"
  [[ -n "$public_endpoint" || -n "$edge_public_lb_dns_name" ]] || die "app_role.public_endpoint or app_role.public_lb.dns_name is required when inventory.app_role or inventory.app_host is present"
  aws_profile="$(jq -r '.aws_profile // empty' <<<"$app_json")"
  aws_region="$(jq -r '.aws_region // empty' <<<"$app_json")"
  [[ -z "$(jq -r '.known_hosts_file // empty' <<<"$app_json")" ]] || die "app_role must not set known_hosts_file when environment=$env_slug"
  [[ -z "$(jq -r '.secret_contract_file // empty' <<<"$app_json")" ]] || die "app_role must not set secret_contract_file when environment=$env_slug"
  runtime_config_secret_id="$(jq -r '.runtime_config_secret_id // empty' <<<"$app_json")"
  runtime_config_secret_region="$(jq -r '.runtime_config_secret_region // empty' <<<"$app_json")"
  [[ -n "$runtime_config_secret_id" ]] || die "app_role.runtime_config_secret_id is required when inventory.app_role or inventory.app_host is present"
  if [[ -z "$runtime_config_secret_region" ]]; then
    runtime_config_secret_region="$aws_region"
  fi
  [[ -n "$runtime_config_secret_region" ]] || die "app_role.runtime_config_secret_region is required when inventory.app_role or inventory.app_host is present"
  account_id="$(jq -r '.account_id // empty' <<<"$app_json")"
  security_group_id="$(jq -r '.public_lb.security_group_id // .security_group_id // empty' <<<"$app_json")"
  bridge_dns_label="$(jq -r '.bridge_public_dns_label // empty' <<<"$app_json")"
  backoffice_dns_label="$(jq -r '.backoffice_dns_label // empty' <<<"$app_json")"
  [[ -n "$bridge_dns_label" ]] || die "app_role.bridge_public_dns_label is required when inventory.app_role or inventory.app_host is present"
  public_scheme="$(jq -r '.public_scheme // "https"' <<<"$app_json")"
  [[ "$public_scheme" == "https" ]] || die "app_role.public_scheme must be https"
  bridge_listen_addr="$(jq -r '.bridge_api_listen // "0.0.0.0:8082"' <<<"$app_json")"
  backoffice_listen_addr="$(jq -r '.backoffice_listen // "0.0.0.0:8090"' <<<"$app_json")"
  production_require_loopback_listen_addr "$bridge_listen_addr" "app_role.bridge_api_listen"
  production_require_loopback_listen_addr "$backoffice_listen_addr" "app_role.backoffice_listen"
  bridge_withdrawal_expiry_window_seconds="$(production_json_required "$shared_manifest" '.contracts.bridge_params.withdrawal_expiry_window_seconds')"
  bridge_min_deposit_amount="$(production_json_required "$shared_manifest" '.contracts.bridge_params.min_deposit_amount')"
  bridge_min_withdraw_amount="$(production_json_required "$shared_manifest" '.contracts.bridge_params.min_withdraw_amount')"
  bridge_fee_bps="$(production_json_required "$shared_manifest" '.contracts.bridge_params.fee_bps')"
  juno_rpc_url="$(jq -r '.juno_rpc_url // empty' <<<"$app_json")"
  operator_addresses_json="$(jq -c '[.operators[] | (.operator_address // .operator_id)]' "$inventory")"
  service_urls_json="$(jq -c '.service_urls // []' <<<"$app_json")"
  operator_endpoints_json="$(jq -c '.operator_endpoints // []' <<<"$app_json")"
  backoffice_access_json="$(jq -c '.backoffice_access // {}' <<<"$app_json")"
  backoffice_access_mode="$(jq -r '.mode // empty' <<<"$backoffice_access_json")"
  backoffice_record_name="$(jq -r '.public_hostname // empty' <<<"$backoffice_access_json")"
  if ! jq -e '.shared_services.alarm_actions | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)' "$inventory" >/dev/null 2>&1; then
    die "shared_services.alarm_actions must be a non-empty array when inventory.app_role or inventory.app_host is present"
  fi
  edge_alarm_actions_json="$(jq -c '.shared_services.alarm_actions' "$inventory")"
  wireguard_source_cidrs_json='[]'
  backoffice_wireguard_source_cidrs_json='[]'
  if [[ -z "$backoffice_access_mode" ]]; then
    if jq -e '
      ((.wireguard_role.source_cidrs // []) | type == "array" and length > 0)
      or ((.wireguard_role.endpoint_host // "") | type == "string" and length > 0)
    ' "$shared_manifest" >/dev/null 2>&1; then
      backoffice_access_mode="wireguard"
    else
      backoffice_access_mode="cloudflare-access"
    fi
  fi
  if [[ "$backoffice_access_mode" == "wireguard" ]]; then
    wireguard_source_cidrs_json="$(jq -c '
      if ((.wireguard_role.source_cidrs // []) | type == "array" and length > 0) then
        .wireguard_role.source_cidrs
      else
        (.wireguard_role.endpoint_host // "")
        | if test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$") then
            [ . + "/32" ]
          else
            []
          end
      end
    ' "$shared_manifest")"
    [[ "$(jq -r 'length' <<<"$wireguard_source_cidrs_json")" -gt 0 ]] || die "wireguard_role.source_cidrs must not be empty"
    backoffice_wireguard_source_cidrs_json="$wireguard_source_cidrs_json"
  fi
  if [[ "$(jq -r 'length' <<<"$operator_endpoints_json")" == "0" ]]; then
    operator_endpoints_json="$(production_default_operator_endpoints_json "$inventory" "$shared_manifest")"
  fi

  bridge_record_name="${bridge_dns_label}.${public_subdomain}"
  bridge_public_url="$(production_origin_url "$public_scheme" "$bridge_record_name")"
  bridge_internal_url="$(production_public_url "http" "127.0.0.1" "$bridge_listen_addr")"
  backoffice_internal_url="$(production_public_url "http" "127.0.0.1" "$backoffice_listen_addr")"
  bridge_probe_url="$bridge_public_url"
  backoffice_probe_url="$backoffice_internal_url"
  if [[ "$backoffice_access_mode" == "cloudflare-access" ]]; then
    if [[ -z "$backoffice_record_name" && -n "$backoffice_dns_label" ]]; then
      backoffice_record_name="${backoffice_dns_label}.${public_subdomain}"
    fi
    [[ -n "$backoffice_record_name" ]] || die "app_role.backoffice_access.public_hostname or app_role.backoffice_dns_label is required when backoffice_access.mode=cloudflare-access"
    backoffice_public_url="$(production_origin_url "$public_scheme" "$backoffice_record_name")"
  else
    backoffice_record_name=""
    backoffice_public_url=""
  fi
  edge_enabled="true"
  edge_output_root="$(dirname "$output_dir")"
  edge_state_dir="$edge_output_root/edge-state"
  mkdir -p "$edge_state_dir"
  edge_state_path="$edge_state_dir/${env_slug}.tfstate"
  edge_origin_record_name="origin.${public_subdomain}"
  edge_origin_endpoint=""
  if [[ -z "$edge_public_lb_dns_name" ]]; then
    edge_origin_endpoint="$public_endpoint"
  fi
  edge_origin_http_port=443
  edge_rate_limit=2000
  edge_enable_shield_advanced="false"
  edge_viewer_certificate_arn="$(jq -r '.edge_viewer_certificate_arn // .public_bridge_additional_certificate_arns[0] // .public_bridge_certificate_arn // empty' <<<"$app_json")"
  if ! production_dns_mode_uses_managed_public_zone "$dns_mode"; then
    [[ -n "$edge_viewer_certificate_arn" ]] || die "app_role.edge_viewer_certificate_arn or a public bridge certificate is required when dns.mode=$dns_mode"
  fi

  app_dir="$(production_app_dir "$output_dir")"
  mkdir -p "$app_dir"
  manifest_path="$app_dir/app-deploy.json"

  jq -n \
    --arg version "$manifest_version" \
    --arg environment "$env_slug" \
    --arg shared_manifest_path "$shared_manifest" \
    --arg runtime_config_secret_id "$runtime_config_secret_id" \
    --arg runtime_config_secret_region "$runtime_config_secret_region" \
    --arg app_host "$app_host" \
    --arg app_user "$app_user" \
    --arg runtime_dir "$runtime_dir" \
    --arg public_endpoint "$public_endpoint" \
    --arg aws_profile "$aws_profile" \
    --arg aws_region "$aws_region" \
    --arg account_id "$account_id" \
    --arg security_group_id "$security_group_id" \
    --arg juno_rpc_url "$juno_rpc_url" \
    --arg bridge_listen_addr "$bridge_listen_addr" \
    --arg bridge_public_url "$bridge_public_url" \
    --arg bridge_probe_url "$bridge_probe_url" \
    --arg bridge_internal_url "$bridge_internal_url" \
    --arg bridge_record_name "$bridge_record_name" \
    --argjson bridge_withdrawal_expiry_window_seconds "$bridge_withdrawal_expiry_window_seconds" \
    --argjson bridge_min_deposit_amount "$bridge_min_deposit_amount" \
    --argjson bridge_min_withdraw_amount "$bridge_min_withdraw_amount" \
    --argjson bridge_fee_bps "$bridge_fee_bps" \
    --arg backoffice_listen_addr "$backoffice_listen_addr" \
    --arg backoffice_public_url "$backoffice_public_url" \
    --arg backoffice_probe_url "$backoffice_probe_url" \
    --arg backoffice_internal_url "$backoffice_internal_url" \
    --arg backoffice_record_name "$backoffice_record_name" \
    --arg backoffice_access_mode "$backoffice_access_mode" \
    --argjson backoffice_wireguard_source_cidrs "$backoffice_wireguard_source_cidrs_json" \
    --arg public_scheme "$public_scheme" \
    --arg dns_mode "$dns_mode" \
    --arg zone_id "$zone_id" \
    --arg zone_name "$zone_name" \
    --argjson ttl_seconds "$ttl_seconds" \
    --argjson operator_addresses "$operator_addresses_json" \
    --argjson service_urls "$service_urls_json" \
    --argjson operator_endpoints "$operator_endpoints_json" \
    --arg edge_enabled "$edge_enabled" \
    --arg edge_state_path "$edge_state_path" \
    --arg edge_origin_record_name "$edge_origin_record_name" \
    --arg edge_public_lb_dns_name "$edge_public_lb_dns_name" \
    --arg edge_public_lb_zone_id "$edge_public_lb_zone_id" \
    --arg edge_origin_endpoint "$edge_origin_endpoint" \
    --argjson edge_origin_http_port "$edge_origin_http_port" \
    --argjson edge_rate_limit "$edge_rate_limit" \
    --argjson edge_alarm_actions "$edge_alarm_actions_json" \
    --arg edge_enable_shield_advanced "$edge_enable_shield_advanced" \
    --arg edge_viewer_certificate_arn "$edge_viewer_certificate_arn" \
    --argjson app_role "$app_role_json" \
    --argjson proof_role "$proof_role_json" \
    --argjson wireguard_role "$wireguard_role_json" \
    --argjson shared_roles "$shared_roles_json" \
    '{
      version: $version,
      environment: $environment,
      shared_manifest_path: $shared_manifest_path,
      runtime_config_secret_id: $runtime_config_secret_id,
      runtime_config_secret_region: $runtime_config_secret_region,
      app_host: (if $app_host == "" then null else $app_host end),
      app_role: $app_role,
      wireguard_role: $wireguard_role,
      shared_roles: $shared_roles,
      app_user: $app_user,
      runtime_dir: $runtime_dir,
      public_endpoint: (if $public_endpoint == "" then null else $public_endpoint end),
      aws_profile: (if $aws_profile == "" then null else $aws_profile end),
      aws_region: (if $aws_region == "" then null else $aws_region end),
      account_id: (if $account_id == "" then null else $account_id end),
      security_group_id: (if $security_group_id == "" then null else $security_group_id end),
      public_scheme: $public_scheme,
      juno_rpc_url: (if $juno_rpc_url == "" then null else $juno_rpc_url end),
      operator_addresses: $operator_addresses,
      service_urls: $service_urls,
      operator_endpoints: $operator_endpoints,
      services: {
        bridge_api: {
          listen_addr: $bridge_listen_addr,
          public_url: $bridge_public_url,
          probe_url: $bridge_probe_url,
          internal_url: $bridge_internal_url,
          record_name: $bridge_record_name,
          withdrawal_expiry_window_seconds: $bridge_withdrawal_expiry_window_seconds,
          min_deposit_amount: $bridge_min_deposit_amount,
          min_withdraw_amount: $bridge_min_withdraw_amount,
          fee_bps: $bridge_fee_bps
        },
        backoffice: {
          listen_addr: $backoffice_listen_addr,
          public_url: (if $backoffice_public_url == "" then null else $backoffice_public_url end),
          probe_url: $backoffice_probe_url,
          internal_url: $backoffice_internal_url,
          record_name: (if $backoffice_record_name == "" then null else $backoffice_record_name end),
          access: {
            mode: $backoffice_access_mode,
            source_cidrs: (if $backoffice_access_mode == "wireguard" then $backoffice_wireguard_source_cidrs else [] end),
            publish_public_dns: false
          }
        }
      },
      dns: {
        mode: $dns_mode,
        zone_id: (if $zone_id == "" then null else $zone_id end),
        zone_name: $zone_name,
        ttl_seconds: $ttl_seconds
      },
      edge: (
        {
          enabled: ($edge_enabled == "true"),
          state_path: $edge_state_path,
          origin_record_name: $edge_origin_record_name,
          origin_http_port: $edge_origin_http_port,
          rate_limit: $edge_rate_limit,
          alarm_actions: $edge_alarm_actions,
          enable_shield_advanced: ($edge_enable_shield_advanced == "true")
        }
        + (if $edge_public_lb_dns_name == "" then {} else {
          public_lb_dns_name: $edge_public_lb_dns_name
        } end)
        + (if $edge_public_lb_zone_id == "" then {} else {
          public_lb_zone_id: $edge_public_lb_zone_id
        } end)
        + (if $edge_origin_endpoint == "" then {} else {
          origin_endpoint: $edge_origin_endpoint
        } end)
        + (if $edge_viewer_certificate_arn == "" then {} else {
          viewer_certificate_arn: $edge_viewer_certificate_arn
        } end)
      )
    }' >"$manifest_path"
}

production_write_rollout_state() {
  local inventory="$1"
  local output_file="$2"

  mkdir -p "$(dirname "$output_file")"

  jq -n \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --slurpfile inventory "$inventory" '
    {
      version: "1",
      generated_at: $generated_at,
      current_operator_id: null,
      operators: ($inventory[0].operators | map({
        operator_id,
        public_dns_label,
        status: "pending",
        last_updated: $generated_at,
        note: "awaiting rollout"
      }))
    }' >"$output_file"
}

production_render_operator_handoffs() {
  local inventory="$1"
  local shared_manifest="$2"
  local dkg_summary="$3"
  local output_dir="$4"
  local inventory_dir="$5"

  shared_manifest="$(production_abs_path "$(pwd)" "$shared_manifest")"
  output_dir="$(production_abs_path "$(pwd)" "$output_dir")"

  local env_slug public_subdomain zone_id dns_mode ttl_seconds dkg_tls_dir shared_owallet_ua
  local shared_aws_profile shared_aws_region
  local manifest_version withdraw_operator_endpoints_json
  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  if production_dns_mode_uses_managed_public_zone "$dns_mode"; then
    zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  else
    zone_id="$(production_json_optional "$inventory" '.shared_services.route53_zone_id')"
  fi
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  shared_aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
  shared_aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
  dkg_tls_dir="$(jq -r '.dkg_tls_dir // empty' "$inventory")"
  if [[ -n "$dkg_tls_dir" ]]; then
    dkg_tls_dir="$(production_abs_path "$inventory_dir" "$dkg_tls_dir")"
    [[ -d "$dkg_tls_dir" ]] || die "dkg_tls_dir not found: $dkg_tls_dir"
  fi
  manifest_version="3"
  withdraw_operator_endpoints_json="$(production_default_operator_endpoints_json "$inventory" "$shared_manifest")"

  local rollout_state="$output_dir/rollout-state.json"
  production_write_rollout_state "$inventory" "$rollout_state"

  local operator_count index
  operator_count="$(jq -r '.operators | length' "$inventory")"
  for ((index = 0; index < operator_count; index++)); do
    local operator_json operator_id handoff_dir manifest_path public_dns_name public_endpoint
    local checkpoint_signer_driver checkpoint_signer_kms_key_id operator_address operator_index
    local checkpoint_blob_bucket checkpoint_blob_prefix checkpoint_blob_sse_kms_key_id
    local operator_aws_profile operator_aws_region runtime_config_secret_id runtime_config_secret_region
    local runtime_material_mode runtime_material_bucket runtime_material_key runtime_material_region runtime_material_kms_key_id
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    operator_id="$(jq -r '.operator_id' <<<"$operator_json")"
    operator_index="$(jq -r '.index' <<<"$operator_json")"
    handoff_dir="$(production_operator_dir "$output_dir" "$operator_id")"
    mkdir -p "$handoff_dir"

    public_endpoint="$(jq -r '.public_endpoint // .operator_host // empty' <<<"$operator_json")"
    public_dns_name="$(jq -r --arg subdomain "$public_subdomain" '.public_dns_label + "." + $subdomain' <<<"$operator_json")"
    local operator_role_json
    operator_role_json="$(jq -c '{
      asg: (.asg // .launch_template.asg // .role // null),
      launch_template: (.launch_template // null),
      public_dns_label: (.public_dns_label // null),
      public_endpoint: (.public_endpoint // .operator_host // null),
      operator_host: (.operator_host // null),
      operator_user: (.operator_user // "ubuntu"),
      runtime_dir: (.runtime_dir // "/var/lib/intents-juno/operator-runtime"),
      publish_public_dns: (.publish_public_dns // true)
    }' <<<"$operator_json")"
    checkpoint_signer_driver="$(jq -r '.checkpoint_signer_driver // "aws-kms"' <<<"$operator_json")"
    checkpoint_signer_kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$operator_json")"
    checkpoint_blob_bucket="$(jq -r '.checkpoint_blob_bucket // empty' <<<"$operator_json")"
    checkpoint_blob_prefix="$(jq -r '.checkpoint_blob_prefix // empty' <<<"$operator_json")"
    checkpoint_blob_sse_kms_key_id="$(jq -r '.checkpoint_blob_sse_kms_key_id // empty' <<<"$operator_json")"
    operator_aws_profile="$(jq -r '.aws_profile // empty' <<<"$operator_json")"
    operator_aws_region="$(jq -r '.aws_region // empty' <<<"$operator_json")"
    operator_address="$(jq -r '.operator_address // empty' <<<"$operator_json")"
    [[ -z "$(jq -r '.known_hosts_file // empty' <<<"$operator_json")" ]] || die "operator $operator_id must not set known_hosts_file when environment=$env_slug"
    [[ -z "$(jq -r '.dkg_backup_zip // empty' <<<"$operator_json")" ]] || die "operator $operator_id must not set dkg_backup_zip when environment=$env_slug"
    [[ -z "$(jq -r '.secret_contract_file // empty' <<<"$operator_json")" ]] || die "operator $operator_id must not set secret_contract_file when environment=$env_slug"
    runtime_config_secret_id="$(jq -r '.runtime_config_secret_id // empty' <<<"$operator_json")"
    runtime_config_secret_region="$(jq -r '.runtime_config_secret_region // empty' <<<"$operator_json")"
    runtime_material_mode="$(jq -r '.runtime_material_ref.mode // empty' <<<"$operator_json")"
    runtime_material_bucket="$(jq -r '.runtime_material_ref.bucket // empty' <<<"$operator_json")"
    runtime_material_key="$(jq -r '.runtime_material_ref.key // empty' <<<"$operator_json")"
    runtime_material_region="$(jq -r '.runtime_material_ref.region // empty' <<<"$operator_json")"
    runtime_material_kms_key_id="$(jq -r '.runtime_material_ref.kms_key_id // empty' <<<"$operator_json")"
    manifest_path="$handoff_dir/operator-deploy.json"

    case "$checkpoint_signer_driver" in
      aws-kms)
        checkpoint_signer_kms_key_id="$(production_resolve_checkpoint_signer_kms_key_id "$env_slug" "$dkg_summary" "$operator_json")"
        ;;
      *)
        die "operator $operator_id must use checkpoint_signer_driver=aws-kms (got: $checkpoint_signer_driver)"
        ;;
    esac

    if [[ -z "$checkpoint_blob_bucket" ]]; then
      checkpoint_blob_bucket="$(jq -r '.shared_services.artifacts.checkpoint_blob_bucket // empty' "$shared_manifest")"
    fi
    if [[ -z "$checkpoint_blob_prefix" ]]; then
      checkpoint_blob_prefix="$(jq -r '.shared_services.artifacts.checkpoint_blob_prefix // empty' "$shared_manifest")"
    fi
    if [[ -z "$checkpoint_blob_sse_kms_key_id" ]]; then
      checkpoint_blob_sse_kms_key_id="$(jq -r '.shared_services.artifacts.checkpoint_blob_sse_kms_key_id // empty' "$shared_manifest")"
    fi
    if [[ -z "$checkpoint_blob_sse_kms_key_id" && -n "$checkpoint_blob_bucket" ]]; then
      checkpoint_blob_sse_kms_key_id="$(
        production_resolve_s3_bucket_sse_kms_key_id \
          "${operator_aws_profile:-$shared_aws_profile}" \
          "${operator_aws_region:-$shared_aws_region}" \
          "$checkpoint_blob_bucket"
      )"
    fi

    [[ "$runtime_material_mode" == "s3-kms-zip" ]] || die "operator $operator_id must set runtime_material_ref.mode=s3-kms-zip when environment=$env_slug"
    [[ -n "$runtime_material_bucket" ]] || die "operator $operator_id runtime_material_ref.bucket is required"
    [[ -n "$runtime_material_key" ]] || die "operator $operator_id runtime_material_ref.key is required"
    [[ -n "$runtime_material_region" ]] || die "operator $operator_id runtime_material_ref.region is required"
    [[ -n "$runtime_material_kms_key_id" ]] || die "operator $operator_id runtime_material_ref.kms_key_id is required"
    [[ -n "$runtime_config_secret_id" ]] || die "operator $operator_id runtime_config_secret_id is required"
    if [[ -z "$runtime_config_secret_region" ]]; then
      runtime_config_secret_region="${operator_aws_region:-$shared_aws_region}"
    fi
    [[ -n "$runtime_config_secret_region" ]] || die "operator $operator_id runtime_config_secret_region is required"

    jq -n \
      --arg version "$manifest_version" \
      --arg environment "$env_slug" \
      --arg shared_manifest_path "$shared_manifest" \
      --arg rollout_state_file "$rollout_state" \
      --arg checkpoint_signer_driver "$checkpoint_signer_driver" \
      --arg checkpoint_signer_kms_key_id "$checkpoint_signer_kms_key_id" \
      --arg checkpoint_blob_bucket "$checkpoint_blob_bucket" \
      --arg checkpoint_blob_prefix "$checkpoint_blob_prefix" \
      --arg checkpoint_blob_sse_kms_key_id "$checkpoint_blob_sse_kms_key_id" \
      --arg operator_address "$operator_address" \
      --arg runtime_material_mode "$runtime_material_mode" \
      --arg runtime_material_bucket "$runtime_material_bucket" \
      --arg runtime_material_key "$runtime_material_key" \
      --arg runtime_material_region "$runtime_material_region" \
      --arg runtime_material_kms_key_id "$runtime_material_kms_key_id" \
      --arg runtime_config_secret_id "$runtime_config_secret_id" \
      --arg runtime_config_secret_region "$runtime_config_secret_region" \
      --arg dkg_tls_dir "$dkg_tls_dir" \
      --arg public_dns_name "$public_dns_name" \
      --arg public_endpoint "$public_endpoint" \
      --arg zone_id "$zone_id" \
      --arg dns_mode "$dns_mode" \
      --argjson ttl_seconds "$ttl_seconds" \
      --argjson withdraw_operator_endpoints "$withdraw_operator_endpoints_json" \
      --argjson operator "$operator_json" \
      --argjson operator_role "$operator_role_json" \
      '{
        version: $version,
        environment: $environment,
        shared_manifest_path: $shared_manifest_path,
        rollout_state_file: $rollout_state_file,
        operator_id: $operator.operator_id,
        operator_role: $operator_role,
        operator_address: (if $operator_address == "" then null else $operator_address end),
        checkpoint_signer_driver: $checkpoint_signer_driver,
        checkpoint_signer_kms_key_id: (if $checkpoint_signer_kms_key_id == "" then null else $checkpoint_signer_kms_key_id end),
        checkpoint_blob_bucket: (if $checkpoint_blob_bucket == "" then null else $checkpoint_blob_bucket end),
        checkpoint_blob_prefix: (if $checkpoint_blob_prefix == "" then null else $checkpoint_blob_prefix end),
        checkpoint_blob_sse_kms_key_id: (if $checkpoint_blob_sse_kms_key_id == "" then null else $checkpoint_blob_sse_kms_key_id end),
        operator_index: $operator.index,
        aws_profile: $operator.aws_profile,
        aws_region: $operator.aws_region,
        account_id: $operator.account_id,
        operator_host: ($operator.operator_host // ""),
        operator_user: ($operator.operator_user // "ubuntu"),
        runtime_dir: ($operator.runtime_dir // "/var/lib/intents-juno/operator-runtime"),
        runtime_material_ref: (
          if $runtime_material_mode == "" then null else {
            mode: $runtime_material_mode,
            bucket: $runtime_material_bucket,
            key: $runtime_material_key,
            region: $runtime_material_region,
            kms_key_id: $runtime_material_kms_key_id
          } end
        ),
        runtime_config_secret_id: (if $runtime_config_secret_id == "" then null else $runtime_config_secret_id end),
        runtime_config_secret_region: (if $runtime_config_secret_region == "" then null else $runtime_config_secret_region end),
        dkg_tls_dir: (if $dkg_tls_dir == "" then null else $dkg_tls_dir end),
        withdraw_operator_endpoints: $withdraw_operator_endpoints,
        public_endpoint: (if $public_endpoint == "" then null else $public_endpoint end),
        dns: {
          mode: $dns_mode,
          zone_id: (if $zone_id == "" then null else $zone_id end),
          record_name: $public_dns_name,
          ttl_seconds: $ttl_seconds
        }
      }' >"$manifest_path"
  done
}

production_render_operator_stack_env() {
  local shared_manifest="$1"
  local operator_deploy="$2"
  local resolved_secret_env="$3"
  local output_file="$4"

  local checkpoint_operators signer_driver signer_kms_key_id operator_address aws_region environment
  local deposit_scan_wallet_id base_event_scanner_start_block withdraw_juno_fee_add_zat
  local withdraw_operator_endpoints owallet_ua signer_ufvk
  local juno_rpc_bind juno_rpc_allow_ips
  local min_base_relayer_balance_wei
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations
  local deposit_relayer_base_rpc_url
  local kafka_critical_key_id runtime_config_secret_id
  local deposit_owallet_ivk withdraw_owallet_ovk
  local -a derived_owallet_keys=()
  deposit_scan_wallet_id=""
  kafka_critical_key_id=""
  min_base_relayer_balance_wei="$(production_required_min_base_relayer_balance_wei)"
  withdraw_juno_fee_add_zat="$(production_default_withdraw_coordinator_juno_fee_add_zat)"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"
  juno_rpc_bind="127.0.0.1"
  juno_rpc_allow_ips="127.0.0.1"
  environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
  withdraw_operator_endpoints="$(jq -r '.withdraw_operator_endpoints // [] | join(",")' "$operator_deploy")"
  runtime_config_secret_id="$(production_json_optional "$operator_deploy" '.runtime_config_secret_id')"
  [[ -n "$runtime_config_secret_id" ]] || die "operator deploy manifest is missing runtime_config_secret_id"
  owallet_ua="$(production_json_required "$shared_manifest" '.contracts.owallet_ua | select(type == "string" and length > 0)')"
  signer_ufvk="$(production_json_required "$shared_manifest" '.checkpoint.signer_ufvk | select(type == "string" and length > 0)')"
  checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
  [[ -n "$checkpoint_operators" ]] || die "shared manifest is missing checkpoint operators"
  kafka_critical_key_id="$(production_json_optional "$shared_manifest" '.shared_services.kafka.critical_key_id')"
  base_event_scanner_start_block="$(jq -r '.contracts.base_event_scanner_start_block // empty' "$shared_manifest")"
  production_is_positive_integer "$base_event_scanner_start_block" \
    || die "shared manifest is missing a positive contracts.base_event_scanner_start_block"
  deposit_relayer_base_rpc_url="$(production_deposit_relayer_base_rpc_urls "$shared_manifest")"
  signer_driver="$(production_json_required "$operator_deploy" '.checkpoint_signer_driver | select(type == "string" and length > 0)')"
  signer_kms_key_id="$(production_json_optional "$operator_deploy" '.checkpoint_signer_kms_key_id')"
  operator_address="$(production_json_optional "$operator_deploy" '.operator_address')"
  aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
  if [[ -z "$operator_address" ]]; then
    operator_address="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
  fi
  [[ -n "$withdraw_operator_endpoints" ]] || die "operator deploy manifest is missing withdraw_operator_endpoints"
  deposit_scan_wallet_id="$(production_env_first_value "$resolved_secret_env" DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID WITHDRAW_COORDINATOR_JUNO_WALLET_ID || true)"
  deposit_owallet_ivk="$(production_env_first_value "$resolved_secret_env" DEPOSIT_OWALLET_IVK || true)"
  withdraw_owallet_ovk="$(production_env_first_value "$resolved_secret_env" WITHDRAW_OWALLET_OVK || true)"
  if [[ -z "$deposit_owallet_ivk" || -z "$withdraw_owallet_ovk" ]]; then
    mapfile -t derived_owallet_keys < <(production_derive_owallet_keys_from_ufvk "$signer_ufvk")
    [[ ${#derived_owallet_keys[@]} -ge 2 ]] || die "failed to derive operator oWallet keys from signer_ufvk"
    if [[ -z "$deposit_owallet_ivk" ]]; then
      deposit_owallet_ivk="${derived_owallet_keys[0]}"
    fi
    if [[ -z "$withdraw_owallet_ovk" ]]; then
      withdraw_owallet_ovk="${derived_owallet_keys[1]}"
    fi
  fi

  case "$signer_driver" in
    aws-kms)
      [[ -n "$signer_kms_key_id" ]] || die "operator deploy manifest is missing checkpoint_signer_kms_key_id for aws-kms signer"
      [[ -n "$aws_region" ]] || die "operator deploy manifest is missing aws_region for aws-kms signer"
      ;;
    *)
      die "operator deploy manifest must use checkpoint_signer_driver=aws-kms (got: $signer_driver)"
      ;;
  esac

  cat >"$output_file" <<EOF
CHECKPOINT_KAFKA_BROKERS=$(jq -r '.shared_services.kafka.bootstrap_brokers' "$shared_manifest")
CHECKPOINT_IPFS_API_URL=$(jq -r '.shared_services.ipfs.api_url' "$shared_manifest")
CHECKPOINT_SIGNER_DRIVER=$signer_driver
CHECKPOINT_OPERATORS=$checkpoint_operators
CHECKPOINT_THRESHOLD=$(jq -r '.checkpoint.threshold' "$shared_manifest")
CHECKPOINT_SIGNATURE_TOPIC=$(jq -r '.checkpoint.signature_topic' "$shared_manifest")
CHECKPOINT_PACKAGE_TOPIC=$(jq -r '.checkpoint.package_topic' "$shared_manifest")
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=$(jq -r '.shared_services.kafka.auth.mode' "$shared_manifest")
JUNO_QUEUE_KAFKA_AWS_REGION=$(jq -r '.shared_services.kafka.auth.aws_region' "$shared_manifest")
OPERATOR_ADDRESS=$operator_address
BASE_CHAIN_ID=$(jq -r '.contracts.base_chain_id' "$shared_manifest")
BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BASE_RELAYER_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
DEPOSIT_RELAYER_BASE_RPC_URL=$deposit_relayer_base_rpc_url
BASE_RELAYER_MIN_READY_BALANCE_WEI=$min_base_relayer_balance_wei
BASE_RELAYER_ALLOWED_SELECTORS=$(production_base_relayer_allowed_selectors)
RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS=$runtime_deposit_min_confirmations
RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=$runtime_withdraw_planner_min_confirmations
RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS=$runtime_withdraw_batch_confirmations
BASE_EVENT_SCANNER_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BASE_EVENT_SCANNER_BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BASE_EVENT_SCANNER_START_BLOCK=$base_event_scanner_start_block
WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232
WITHDRAW_COORDINATOR_JUNO_SCAN_URL=http://127.0.0.1:8080
WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443
WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.key
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/usr/local/bin/intents-juno-multikey-extend-signer.sh
WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240
WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=$withdraw_juno_fee_add_zat
WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h
WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h
WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=$owallet_ua
WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080
WITHDRAW_FINALIZER_JUNO_RPC_URL=http://127.0.0.1:18232
TSS_SIGNER_RUNTIME_MODE=host-process
TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt
TSS_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin
TSS_NITRO_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-attested-signer
TSS_NITRO_ENCLAVE_EIF_FILE=/var/lib/intents-juno/operator-runtime/enclave/spendauth-signer.eif
TSS_NITRO_ENCLAVE_CID=16
TSS_NITRO_ATTESTATION_FILE=/var/lib/intents-juno/operator-runtime/attestation/spendauth-attestation.json
TSS_NITRO_ATTESTATION_MAX_AGE_SECONDS=300
TSS_SIGNER_WORK_DIR=/var/lib/intents-juno/tss-signer
TSS_LISTEN_ADDR=127.0.0.1:9443
TSS_TLS_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.pem
TSS_TLS_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/server.key
TSS_CLIENT_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem
EOF

  if [[ -n "$kafka_critical_key_id" ]]; then
    printf 'JUNO_QUEUE_CRITICAL_KEY_ID=%s\n' "$kafka_critical_key_id" >>"$output_file"
  fi
  if [[ -n "$signer_kms_key_id" ]]; then
    printf 'CHECKPOINT_SIGNER_KMS_KEY_ID=%s\n' "$signer_kms_key_id" >>"$output_file"
  fi
  printf 'WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS=%s\n' "$withdraw_operator_endpoints" >>"$output_file"
  printf 'JUNO_RPC_BIND=%s\n' "$juno_rpc_bind" >>"$output_file"
  printf 'JUNO_RPC_ALLOW_IPS=%s\n' "$juno_rpc_allow_ips" >>"$output_file"
  if [[ -n "$aws_region" ]]; then
    printf 'AWS_REGION=%s\n' "$aws_region" >>"$output_file"
    printf 'AWS_DEFAULT_REGION=%s\n' "$aws_region" >>"$output_file"
  fi

  local checkpoint_blob_bucket checkpoint_blob_prefix checkpoint_blob_sse_kms_key_id deposit_image_id withdraw_image_id
  checkpoint_blob_bucket="$(jq -r '.checkpoint_blob_bucket // empty' "$operator_deploy")"
  checkpoint_blob_prefix="$(jq -r '.checkpoint_blob_prefix // empty' "$operator_deploy")"
  checkpoint_blob_sse_kms_key_id="$(jq -r '.checkpoint_blob_sse_kms_key_id // empty' "$operator_deploy")"
  if [[ -z "$checkpoint_blob_bucket" ]]; then
    checkpoint_blob_bucket="$(jq -r '.shared_services.artifacts.checkpoint_blob_bucket // empty' "$shared_manifest")"
  fi
  if [[ -z "$checkpoint_blob_prefix" ]]; then
    checkpoint_blob_prefix="$(jq -r '.shared_services.artifacts.checkpoint_blob_prefix // empty' "$shared_manifest")"
  fi
  if [[ -z "$checkpoint_blob_sse_kms_key_id" ]]; then
    checkpoint_blob_sse_kms_key_id="$(jq -r '.shared_services.artifacts.checkpoint_blob_sse_kms_key_id // empty' "$shared_manifest")"
  fi
  deposit_image_id="$(jq -r '.contracts.deposit_image_id // empty' "$shared_manifest")"
  withdraw_image_id="$(jq -r '.contracts.withdraw_image_id // empty' "$shared_manifest")"

  if [[ -n "$checkpoint_blob_bucket" ]]; then
    printf 'CHECKPOINT_BLOB_BUCKET=%s\n' "$checkpoint_blob_bucket" >>"$output_file"
    printf 'WITHDRAW_BLOB_BUCKET=%s\n' "$checkpoint_blob_bucket" >>"$output_file"
  fi
  if [[ -n "$checkpoint_blob_prefix" ]]; then
    printf 'CHECKPOINT_BLOB_PREFIX=%s\n' "$checkpoint_blob_prefix" >>"$output_file"
  fi
  if [[ -n "$checkpoint_blob_sse_kms_key_id" ]]; then
    printf 'CHECKPOINT_BLOB_SSE_KMS_KEY_ID=%s\n' "$checkpoint_blob_sse_kms_key_id" >>"$output_file"
  fi
  if [[ -n "$deposit_image_id" ]]; then
    printf 'DEPOSIT_IMAGE_ID=%s\n' "$deposit_image_id" >>"$output_file"
  fi
  if [[ -n "$withdraw_image_id" ]]; then
    printf 'WITHDRAW_IMAGE_ID=%s\n' "$withdraw_image_id" >>"$output_file"
  fi
  if [[ -n "$deposit_scan_wallet_id" ]]; then
    printf 'DEPOSIT_SCAN_ENABLED=true\n' >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_SCAN_URL=http://127.0.0.1:8080\n' >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=%s\n' "$deposit_scan_wallet_id" >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_RPC_URL=http://127.0.0.1:18232\n' >>"$output_file"
  fi
  if [[ -n "$deposit_owallet_ivk" ]]; then
    printf 'DEPOSIT_OWALLET_IVK=%s\n' "$deposit_owallet_ivk" >>"$output_file"
  fi
  if [[ -n "$withdraw_owallet_ovk" ]]; then
    printf 'WITHDRAW_OWALLET_OVK=%s\n' "$withdraw_owallet_ovk" >>"$output_file"
  fi
  :
}

production_render_bridge_api_env() {
  local shared_manifest="$1"
  local app_deploy="$2"
  local resolved_secret_env="$3"
  local output_file="$4"

  local owallet_ua listen_addr withdrawal_expiry_window_seconds min_deposit_amount min_withdraw_amount fee_bps
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations

  owallet_ua="$(production_json_required "$shared_manifest" '.contracts.owallet_ua | select(type == "string" and length > 0)')"
  listen_addr="$(production_json_required "$app_deploy" '.services.bridge_api.listen_addr | select(type == "string" and length > 0)')"
  withdrawal_expiry_window_seconds="$(production_json_optional "$app_deploy" '.services.bridge_api.withdrawal_expiry_window_seconds')"
  min_deposit_amount="$(production_json_optional "$app_deploy" '.services.bridge_api.min_deposit_amount')"
  min_withdraw_amount="$(production_json_optional "$app_deploy" '.services.bridge_api.min_withdraw_amount')"
  fee_bps="$(production_json_optional "$app_deploy" '.services.bridge_api.fee_bps')"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"

  cat >"$output_file" <<EOF
BRIDGE_API_LISTEN_ADDR=$listen_addr
BRIDGE_API_POSTGRES_DSN=
BRIDGE_API_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BRIDGE_API_BASE_CHAIN_ID=$(jq -r '.contracts.base_chain_id' "$shared_manifest")
BRIDGE_API_BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BRIDGE_API_OWALLET_UA=$owallet_ua
BRIDGE_API_WITHDRAWAL_EXPIRY_WINDOW_SECONDS=${withdrawal_expiry_window_seconds:-86400}
BRIDGE_API_MIN_DEPOSIT_AMOUNT=${min_deposit_amount:-0}
BRIDGE_API_DEPOSIT_MIN_CONFIRMATIONS=$runtime_deposit_min_confirmations
BRIDGE_API_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=$runtime_withdraw_planner_min_confirmations
BRIDGE_API_WITHDRAW_BATCH_CONFIRMATIONS=$runtime_withdraw_batch_confirmations
BRIDGE_API_MIN_WITHDRAW_AMOUNT=${min_withdraw_amount:-0}
BRIDGE_API_FEE_BPS=${fee_bps:-0}
EOF

  local wjuno_address
  wjuno_address="$(production_json_optional "$shared_manifest" '.contracts.wjuno')"
  if [[ -n "$wjuno_address" ]]; then
    printf 'BRIDGE_API_WJUNO_ADDRESS=%s\n' "$wjuno_address" >>"$output_file"
  fi
}

production_render_backoffice_env() {
  local shared_manifest="$1"
  local app_deploy="$2"
  local resolved_secret_env="$3"
  local output_file="$4"

  local juno_rpc_url juno_rpc_urls
  local listen_addr operator_addresses service_urls operator_endpoints
  local base_relayer_signer_addresses base_relayer_gas_min_wei
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations
  local sp1_requestor_address sp1_rpc_url render_juno_rpc
  juno_rpc_url="$(production_json_optional "$app_deploy" '.juno_rpc_url')"
  listen_addr="$(production_json_required "$app_deploy" '.services.backoffice.listen_addr | select(type == "string" and length > 0)')"
  operator_addresses="$(jq -r '.operator_addresses | join(",")' "$app_deploy")"
  service_urls="$(jq -r '.service_urls | join(",")' "$app_deploy")"
  operator_endpoints="$(jq -r '.operator_endpoints | join(",")' "$app_deploy")"
  base_relayer_signer_addresses="$(production_backoffice_relayer_signer_addresses_csv "$app_deploy")"
  base_relayer_gas_min_wei="$(production_required_min_base_relayer_balance_wei)"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"
  sp1_requestor_address="$(production_json_optional "$shared_manifest" '.shared_services.proof.requestor_address')"
  sp1_rpc_url="$(production_json_optional "$shared_manifest" '.shared_services.proof.rpc_url')"
  [[ -n "$sp1_requestor_address" ]] || die "shared manifest is missing shared_services.proof.requestor_address"
  render_juno_rpc="false"
  juno_rpc_urls="$(production_backoffice_juno_rpc_urls_csv "$app_deploy" || true)"
  production_json_required "$shared_manifest" '.contracts.wjuno | select(type == "string" and length > 0)' >/dev/null
  production_json_required "$shared_manifest" '.contracts.operator_registry | select(type == "string" and length > 0)' >/dev/null

  cat >"$output_file" <<EOF
BACKOFFICE_LISTEN_ADDR=$listen_addr
BACKOFFICE_POSTGRES_DSN=
BACKOFFICE_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BACKOFFICE_AUTH_SECRET=
BACKOFFICE_BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BACKOFFICE_WJUNO_ADDRESS=$(jq -r '.contracts.wjuno' "$shared_manifest")
BACKOFFICE_OWALLET_UA=$(jq -r '.contracts.owallet_ua' "$shared_manifest")
BACKOFFICE_OPERATOR_REGISTRY_ADDRESS=$(jq -r '.contracts.operator_registry' "$shared_manifest")
BACKOFFICE_OPERATOR_ADDRESSES=$operator_addresses
BACKOFFICE_BASE_RELAYER_SIGNER_ADDRESSES=$base_relayer_signer_addresses
BACKOFFICE_BASE_RELAYER_GAS_MIN_WEI=$base_relayer_gas_min_wei
BACKOFFICE_DEPOSIT_MIN_CONFIRMATIONS=$runtime_deposit_min_confirmations
BACKOFFICE_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=$runtime_withdraw_planner_min_confirmations
BACKOFFICE_WITHDRAW_BATCH_CONFIRMATIONS=$runtime_withdraw_batch_confirmations
BACKOFFICE_KAFKA_BROKERS=$(jq -r '.shared_services.kafka.bootstrap_brokers' "$shared_manifest")
BACKOFFICE_IPFS_API_URL=$(jq -r '.shared_services.ipfs.api_url' "$shared_manifest")
BACKOFFICE_IPFS_API_BEARER_TOKEN=
BACKOFFICE_CLOUDFLARE_TUNNEL_TOKEN=
BACKOFFICE_JUNO_RPC_USER=
BACKOFFICE_JUNO_RPC_PASS=
MIN_DEPOSIT_ADMIN_PRIVATE_KEY=
EOF

  if [[ -n "$sp1_requestor_address" ]]; then
    printf 'BACKOFFICE_SP1_REQUESTOR_ADDRESS=%s\n' "$sp1_requestor_address" >>"$output_file"
  fi
  if [[ -n "$sp1_rpc_url" ]]; then
    printf 'BACKOFFICE_SP1_RPC_URL=%s\n' "$sp1_rpc_url" >>"$output_file"
  fi
  if [[ -n "$juno_rpc_urls" ]]; then
    render_juno_rpc="true"
    printf 'BACKOFFICE_JUNO_RPC_URLS=%s\n' "$juno_rpc_urls" >>"$output_file"
  fi
  local fee_distributor
  fee_distributor="$(production_json_optional "$shared_manifest" '.contracts.fee_distributor')"
  if [[ -n "$fee_distributor" ]]; then
    printf 'BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS=%s\n' "$fee_distributor" >>"$output_file"
  fi
  if [[ -n "$juno_rpc_url" ]]; then
    printf 'BACKOFFICE_JUNO_RPC_URL=%s\n' "$juno_rpc_url" >>"$output_file"
  fi
  if [[ -n "$service_urls" ]]; then
    printf 'BACKOFFICE_SERVICE_URLS=%s\n' "$service_urls" >>"$output_file"
  fi
  if [[ -n "$operator_endpoints" ]]; then
    printf 'BACKOFFICE_OPERATOR_ENDPOINTS=%s\n' "$operator_endpoints" >>"$output_file"
  fi
}

production_render_junocashd_conf() {
  die "runner-side junocashd.conf rendering is disabled; use host-side runtime hydration"
}

production_rollout_reserve() {
  local state_file="$1"
  local operator_id="$2"

  local other_in_progress
  other_in_progress="$(jq -r --arg operator_id "$operator_id" '.operators[] | select(.status == "in_progress" and .operator_id != $operator_id) | .operator_id' "$state_file" | head -n 1)"
  [[ -z "$other_in_progress" ]] || die "rollout already in progress for $other_in_progress"

  local now
  now="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  local tmp_file
  tmp_file="$(mktemp)"
  jq --arg operator_id "$operator_id" --arg now "$now" '
    .current_operator_id = $operator_id
    | .operators |= map(
        if .operator_id == $operator_id then
          .status = "in_progress"
          | .last_updated = $now
          | .note = "rollout in progress"
        else
          .
        end
      )
  ' "$state_file" >"$tmp_file"
  mv "$tmp_file" "$state_file"
}

production_rollout_complete() {
  local state_file="$1"
  local operator_id="$2"
  local status="$3"
  local note="$4"
  local now
  now="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  local tmp_file
  tmp_file="$(mktemp)"
  jq --arg operator_id "$operator_id" --arg status "$status" --arg note "$note" --arg now "$now" '
    .current_operator_id = null
    | .operators |= map(
        if .operator_id == $operator_id then
          .status = $status
          | .last_updated = $now
          | .note = $note
        else
          .
        end
      )
  ' "$state_file" >"$tmp_file"
  mv "$tmp_file" "$state_file"
}

production_publish_dns_record() {
  local aws_profile="$1"
  local aws_region="$2"
  local zone_id="$3"
  local record_name="$4"
  local ttl_seconds="$5"
  local record_value="$6"

  local batch_file record_type
  if [[ "$record_value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    record_type="A"
  else
    record_type="CNAME"
  fi

  local -a aws_args=(aws)
  [[ -n "$aws_profile" ]] && aws_args+=(--profile "$aws_profile")
  [[ -n "$aws_region" ]] && aws_args+=(--region "$aws_region")

  batch_file="$(mktemp)"
  jq -n \
    --arg name "$record_name" \
    --arg value "$record_value" \
    --arg type "$record_type" \
    --argjson ttl "$ttl_seconds" \
    '{
      Changes: [
        {
          Action: "UPSERT",
          ResourceRecordSet: {
            Name: $name,
            Type: $type,
            TTL: $ttl,
            ResourceRecords: [{Value: $value}]
          }
        }
      ]
    }' >"$batch_file"

  AWS_PAGER="" "${aws_args[@]}" \
    route53 change-resource-record-sets \
    --hosted-zone-id "$zone_id" \
    --change-batch "file://$batch_file"
  rm -f "$batch_file"
}

production_dns_mode_uses_managed_public_zone() {
  local dns_mode="${1:-}"
  case "$dns_mode" in
    public-zone|route53)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
