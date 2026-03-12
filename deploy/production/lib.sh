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

production_operator_ids_csv() {
  local dkg_summary="$1"
  jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary"
}

production_threshold() {
  local dkg_summary="$1"
  jq -er '.threshold // .operator_threshold // .operatorThreshold // .max_signers_threshold // empty' "$dkg_summary"
}

production_secret_keys_json() {
  local inventory="$1"
  local inventory_dir="$2"
  jq -n --arg inventory "$inventory" --arg inventory_dir "$inventory_dir" '
    [$inventory] | .[0]
  ' >/dev/null
  jq -r '.operators[].secret_contract_file // empty' "$inventory" \
    | while IFS= read -r rel_path; do
        [[ -n "$rel_path" ]] || continue
        local_path="$(production_abs_path "$inventory_dir" "$rel_path")"
        if [[ -f "$local_path" ]]; then
          awk -F= '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            NF >= 2 { print $1 }
          ' "$local_path"
        fi
      done \
    | LC_ALL=C sort -u \
    | jq -R -s 'split("\n") | map(select(length > 0))'
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

production_resolve_secret_contract() {
  local input_file="$1"
  local allow_local="$2"
  local aws_profile="$3"
  local aws_region="$4"
  local output_file="$5"

  : >"$output_file"

  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    [[ "$raw_line" =~ ^[[:space:]]*# ]] && continue
    [[ "$raw_line" =~ ^[[:space:]]*$ ]] && continue

    local key="${raw_line%%=*}"
    local resolver="${raw_line#*=}"
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "invalid env key in secret contract: $key"
    production_validate_secret_resolver "$resolver" "$allow_local"
    local resolved
    resolved="$(production_resolve_secret_value "$resolver" "$aws_profile" "$aws_region")"
    [[ "$resolved" != *$'\n'* ]] || die "multiline secret values are not supported for $key"
    printf '%s=%s\n' "$key" "$resolved" >>"$output_file"
  done <"$input_file"
}

production_render_shared_manifest() {
  local inventory="$1"
  local bridge_summary="$2"
  local dkg_summary="$3"
  local tf_json="$4"
  local output_file="$5"
  local inventory_dir="$6"

  local env_slug base_rpc_url base_chain_id deposit_image_id withdraw_image_id
  local aws_profile aws_region terraform_dir zone_id zone_name public_subdomain ttl_seconds dns_mode
  local postgres_endpoint postgres_port kafka_brokers ipfs_api_url dkg_bucket dkg_prefix
  local operator_ids_csv threshold operators_json roster_json secret_keys_json governance_json

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  base_rpc_url="$(production_json_required "$inventory" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
  base_chain_id="$(production_json_required "$inventory" '.contracts.base_chain_id')"
  deposit_image_id="$(production_json_optional "$inventory" '.contracts.deposit_image_id')"
  withdraw_image_id="$(production_json_optional "$inventory" '.contracts.withdraw_image_id')"
  aws_profile="$(production_json_required "$inventory" '.shared_services.aws_profile | select(type == "string" and length > 0)')"
  aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
  terraform_dir="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  zone_name="$(production_json_required "$inventory" '.shared_services.public_zone_name | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"

  postgres_endpoint="$(production_tf_output_value "$tf_json" "shared_postgres_endpoint" true)"
  postgres_port="$(production_tf_output_value "$tf_json" "shared_postgres_port" true)"
  kafka_brokers="$(production_tf_output_value "$tf_json" "shared_kafka_bootstrap_brokers" true)"
  ipfs_api_url="$(production_tf_output_value "$tf_json" "shared_ipfs_api_url" true)"
  dkg_bucket="$(production_tf_output_value "$tf_json" "dkg_s3_bucket" false)"
  dkg_prefix="$(production_tf_output_value "$tf_json" "dkg_s3_key_prefix" false)"

  operator_ids_csv="$(production_operator_ids_csv "$dkg_summary")"
  [[ -n "$operator_ids_csv" ]] || die "dkg summary does not contain operator ids"
  threshold="$(production_threshold "$dkg_summary")"
  operators_json="$(jq -c '[.operators[].operator_id]' "$dkg_summary")"
  roster_json="$(jq -c '.operators | map({index, operator_id, aws_profile, aws_region, account_id, public_dns_label})' "$inventory")"
  secret_keys_json="$(production_secret_keys_json "$inventory" "$inventory_dir")"
  governance_json="$(jq -c '.governance // null' "$bridge_summary")"

  jq -n \
    --arg version "1" \
    --arg environment "$env_slug" \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg aws_profile "$aws_profile" \
    --arg aws_region "$aws_region" \
    --arg terraform_dir "$terraform_dir" \
    --arg zone_id "$zone_id" \
    --arg zone_name "$zone_name" \
    --arg public_subdomain "$public_subdomain" \
    --arg dns_mode "$dns_mode" \
    --arg postgres_endpoint "$postgres_endpoint" \
    --arg postgres_port "$postgres_port" \
    --arg kafka_brokers "$kafka_brokers" \
    --arg ipfs_api_url "$ipfs_api_url" \
    --arg dkg_bucket "$dkg_bucket" \
    --arg dkg_prefix "$dkg_prefix" \
    --arg base_rpc_url "$base_rpc_url" \
    --argjson base_chain_id "$base_chain_id" \
    --arg deposit_image_id "$deposit_image_id" \
    --arg withdraw_image_id "$withdraw_image_id" \
    --arg bridge_address "$(production_json_required "$bridge_summary" '.contracts.bridge | select(type == "string" and length > 0)')" \
    --arg wjuno_address "$(production_json_optional "$bridge_summary" '.contracts.wjuno')" \
    --arg operator_registry "$(production_json_optional "$bridge_summary" '.contracts.operator_registry')" \
    --arg fee_distributor "$(production_json_optional "$bridge_summary" '.contracts.fee_distributor')" \
    --arg owallet_ua "$(production_json_optional "$bridge_summary" '.owallet_ua // .juno_shielded_address')" \
    --argjson ttl_seconds "$ttl_seconds" \
    --argjson checkpoint_threshold "$threshold" \
    --argjson checkpoint_operators "$operators_json" \
    --argjson operator_roster "$roster_json" \
    --argjson secret_reference_names "$secret_keys_json" \
    --argjson governance "$governance_json" \
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
          port: ($postgres_port | tonumber)
        },
        kafka: {
          bootstrap_brokers: $kafka_brokers,
          tls: true,
          min_insync_replicas: 2
        },
        ipfs: {
          api_url: $ipfs_api_url
        },
        artifacts: {
          checkpoint_blob_bucket: (if $dkg_bucket == "" then null else $dkg_bucket end),
          checkpoint_blob_prefix: (if $dkg_prefix == "" then null else $dkg_prefix end)
        }
      },
      contracts: {
        base_rpc_url: $base_rpc_url,
        base_chain_id: $base_chain_id,
        bridge: $bridge_address,
        wjuno: (if $wjuno_address == "" then null else $wjuno_address end),
        operator_registry: (if $operator_registry == "" then null else $operator_registry end),
        fee_distributor: (if $fee_distributor == "" then null else $fee_distributor end),
        deposit_image_id: (if $deposit_image_id == "" then null else $deposit_image_id end),
        withdraw_image_id: (if $withdraw_image_id == "" then null else $withdraw_image_id end),
        owallet_ua: (if $owallet_ua == "" then null else $owallet_ua end)
      },
      checkpoint: {
        operators: $checkpoint_operators,
        threshold: $checkpoint_threshold,
        signature_topic: "checkpoints.signatures.v1",
        package_topic: "checkpoints.packages.v1"
      },
      operator_roster: $operator_roster,
      dns: {
        mode: $dns_mode,
        zone_id: $zone_id,
        zone_name: $zone_name,
        public_subdomain: $public_subdomain,
        ttl_seconds: $ttl_seconds
      },
      governance: $governance,
      secret_reference_names: $secret_reference_names
    }' >"$output_file"
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
  local output_dir="$3"
  local inventory_dir="$4"

  shared_manifest="$(production_abs_path "$(pwd)" "$shared_manifest")"
  output_dir="$(production_abs_path "$(pwd)" "$output_dir")"

  local env_slug public_subdomain zone_id dns_mode ttl_seconds
  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"

  local rollout_state="$output_dir/rollout-state.json"
  production_write_rollout_state "$inventory" "$rollout_state"

  local operator_count index
  operator_count="$(jq -r '.operators | length' "$inventory")"
  for ((index = 0; index < operator_count; index++)); do
    local operator_json operator_id handoff_dir known_hosts_src secrets_src backup_zip_src
    local known_hosts_dst secrets_dst manifest_path public_dns_name public_endpoint
    local checkpoint_signer_driver checkpoint_signer_kms_key_id operator_address
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    operator_id="$(jq -r '.operator_id' <<<"$operator_json")"
    handoff_dir="$(production_operator_dir "$output_dir" "$operator_id")"
    mkdir -p "$handoff_dir"

    known_hosts_src="$(jq -r '.known_hosts_file // empty' <<<"$operator_json")"
    secrets_src="$(jq -r '.secret_contract_file // empty' <<<"$operator_json")"
    backup_zip_src="$(jq -r '.dkg_backup_zip // empty' <<<"$operator_json")"
    public_endpoint="$(jq -r '.public_endpoint // .operator_host // empty' <<<"$operator_json")"
    public_dns_name="$(jq -r --arg subdomain "$public_subdomain" '.public_dns_label + "." + $subdomain' <<<"$operator_json")"
    checkpoint_signer_driver="$(jq -r '.checkpoint_signer_driver // "local-env"' <<<"$operator_json")"
    checkpoint_signer_kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$operator_json")"
    operator_address="$(jq -r '.operator_address // empty' <<<"$operator_json")"
    manifest_path="$handoff_dir/operator-deploy.json"

    case "$checkpoint_signer_driver" in
      local-env) ;;
      aws-kms)
        [[ -n "$checkpoint_signer_kms_key_id" ]] || die "operator $operator_id uses checkpoint_signer_driver=aws-kms but checkpoint_signer_kms_key_id is empty"
        ;;
      *)
        die "operator $operator_id has unsupported checkpoint_signer_driver: $checkpoint_signer_driver"
        ;;
    esac

    known_hosts_dst=""
    if [[ -n "$known_hosts_src" ]]; then
      known_hosts_src="$(production_abs_path "$inventory_dir" "$known_hosts_src")"
      [[ -f "$known_hosts_src" ]] || die "known_hosts file not found: $known_hosts_src"
      known_hosts_dst="$handoff_dir/known_hosts"
      cp "$known_hosts_src" "$known_hosts_dst"
    fi

    secrets_dst=""
    if [[ -n "$secrets_src" ]]; then
      secrets_src="$(production_abs_path "$inventory_dir" "$secrets_src")"
      [[ -f "$secrets_src" ]] || die "secret contract file not found: $secrets_src"
      secrets_dst="$handoff_dir/operator-secrets.env"
      cp "$secrets_src" "$secrets_dst"
    fi

    if [[ -n "$backup_zip_src" ]]; then
      backup_zip_src="$(production_abs_path "$inventory_dir" "$backup_zip_src")"
    fi

    jq -n \
      --arg version "1" \
      --arg environment "$env_slug" \
      --arg shared_manifest_path "$shared_manifest" \
      --arg rollout_state_file "$rollout_state" \
      --arg checkpoint_signer_driver "$checkpoint_signer_driver" \
      --arg checkpoint_signer_kms_key_id "$checkpoint_signer_kms_key_id" \
      --arg operator_address "$operator_address" \
      --arg known_hosts_file "$known_hosts_dst" \
      --arg secret_contract_file "$secrets_dst" \
      --arg dkg_backup_zip "$backup_zip_src" \
      --arg public_dns_name "$public_dns_name" \
      --arg public_endpoint "$public_endpoint" \
      --arg zone_id "$zone_id" \
      --arg dns_mode "$dns_mode" \
      --argjson ttl_seconds "$ttl_seconds" \
      --argjson operator "$operator_json" \
      '{
        version: $version,
        environment: $environment,
        shared_manifest_path: $shared_manifest_path,
        rollout_state_file: $rollout_state_file,
        operator_id: $operator.operator_id,
        operator_address: (if $operator_address == "" then null else $operator_address end),
        checkpoint_signer_driver: $checkpoint_signer_driver,
        checkpoint_signer_kms_key_id: (if $checkpoint_signer_kms_key_id == "" then null else $checkpoint_signer_kms_key_id end),
        operator_index: $operator.index,
        aws_profile: $operator.aws_profile,
        aws_region: $operator.aws_region,
        account_id: $operator.account_id,
        operator_host: ($operator.operator_host // ""),
        operator_user: ($operator.operator_user // "ubuntu"),
        runtime_dir: ($operator.runtime_dir // "/var/lib/intents-juno/operator-runtime"),
        dkg_backup_zip: $dkg_backup_zip,
        known_hosts_file: (if $known_hosts_file == "" then null else $known_hosts_file end),
        secret_contract_file: (if $secret_contract_file == "" then null else $secret_contract_file end),
        public_endpoint: (if $public_endpoint == "" then null else $public_endpoint end),
        dns: {
          mode: $dns_mode,
          zone_id: $zone_id,
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

  local checkpoint_operators signer_driver signer_kms_key_id operator_address aws_region
  checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
  [[ -n "$checkpoint_operators" ]] || die "shared manifest is missing checkpoint operators"
  signer_driver="$(production_json_required "$operator_deploy" '.checkpoint_signer_driver | select(type == "string" and length > 0)')"
  signer_kms_key_id="$(production_json_optional "$operator_deploy" '.checkpoint_signer_kms_key_id')"
  operator_address="$(production_json_optional "$operator_deploy" '.operator_address')"
  aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
  if [[ -z "$operator_address" ]]; then
    operator_address="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
  fi

  case "$signer_driver" in
    local-env) ;;
    aws-kms)
      [[ -n "$signer_kms_key_id" ]] || die "operator deploy manifest is missing checkpoint_signer_kms_key_id for aws-kms signer"
      [[ -n "$aws_region" ]] || die "operator deploy manifest is missing aws_region for aws-kms signer"
      if grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY=' "$resolved_secret_env"; then
        die "resolved secret env must not contain CHECKPOINT_SIGNER_PRIVATE_KEY when checkpoint_signer_driver=aws-kms"
      fi
      ;;
    *)
      die "unsupported checkpoint signer driver in operator deploy manifest: $signer_driver"
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
OPERATOR_ADDRESS=$operator_address
BASE_CHAIN_ID=$(jq -r '.contracts.base_chain_id' "$shared_manifest")
BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BASE_RELAYER_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BASE_EVENT_SCANNER_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BASE_EVENT_SCANNER_BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232
WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443
WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=/var/lib/intents-juno/operator-runtime/bundle/tls/coordinator-client.key
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin
WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080
WITHDRAW_FINALIZER_JUNO_RPC_URL=http://127.0.0.1:18232
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

  if [[ -n "$signer_kms_key_id" ]]; then
    printf 'CHECKPOINT_SIGNER_KMS_KEY_ID=%s\n' "$signer_kms_key_id" >>"$output_file"
  fi
  if [[ -n "$aws_region" ]]; then
    printf 'AWS_REGION=%s\n' "$aws_region" >>"$output_file"
    printf 'AWS_DEFAULT_REGION=%s\n' "$aws_region" >>"$output_file"
  fi

  local checkpoint_blob_bucket checkpoint_blob_prefix deposit_image_id withdraw_image_id
  checkpoint_blob_bucket="$(jq -r '.shared_services.artifacts.checkpoint_blob_bucket // empty' "$shared_manifest")"
  checkpoint_blob_prefix="$(jq -r '.shared_services.artifacts.checkpoint_blob_prefix // empty' "$shared_manifest")"
  deposit_image_id="$(jq -r '.contracts.deposit_image_id // empty' "$shared_manifest")"
  withdraw_image_id="$(jq -r '.contracts.withdraw_image_id // empty' "$shared_manifest")"

  if [[ -n "$checkpoint_blob_bucket" ]]; then
    printf 'CHECKPOINT_BLOB_BUCKET=%s\n' "$checkpoint_blob_bucket" >>"$output_file"
  fi
  if [[ -n "$checkpoint_blob_prefix" ]]; then
    printf 'CHECKPOINT_BLOB_PREFIX=%s\n' "$checkpoint_blob_prefix" >>"$output_file"
  fi
  if [[ -n "$deposit_image_id" ]]; then
    printf 'DEPOSIT_IMAGE_ID=%s\n' "$deposit_image_id" >>"$output_file"
  fi
  if [[ -n "$withdraw_image_id" ]]; then
    printf 'WITHDRAW_IMAGE_ID=%s\n' "$withdraw_image_id" >>"$output_file"
  fi

  awk -F= '
    $1 == "CHECKPOINT_SIGNER_DRIVER" { next }
    $1 == "CHECKPOINT_SIGNER_KMS_KEY_ID" { next }
    $1 == "OPERATOR_ADDRESS" { next }
    { print }
  ' "$resolved_secret_env" >>"$output_file"

  local required_env_key
  for required_env_key in CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS; do
    grep -q "^${required_env_key}=" "$output_file" || die "rendered operator env is missing ${required_env_key}"
  done
}

production_render_junocashd_conf() {
  local operator_stack_env="$1"
  local output_file="$2"
  local rpc_user rpc_pass

  [[ -f "$operator_stack_env" ]] || die "operator stack env not found: $operator_stack_env"
  rpc_user="$(
    awk -F= '
      $1 == "JUNO_RPC_USER" {
        print substr($0, index($0, "=") + 1)
        exit
      }
    ' "$operator_stack_env"
  )"
  rpc_pass="$(
    awk -F= '
      $1 == "JUNO_RPC_PASS" {
        print substr($0, index($0, "=") + 1)
        exit
      }
    ' "$operator_stack_env"
  )"
  [[ -n "$rpc_user" ]] || die "operator stack env is missing JUNO_RPC_USER"
  [[ -n "$rpc_pass" ]] || die "operator stack env is missing JUNO_RPC_PASS"

  {
    printf 'testnet=1\n'
    printf 'server=1\n'
    printf 'txindex=1\n'
    printf 'daemon=0\n'
    printf 'listen=1\n'
    printf 'rpcbind=127.0.0.1\n'
    printf 'rpcallowip=127.0.0.1\n'
    printf 'rpcport=18232\n'
    printf 'rpcuser=%s\n' "$rpc_user"
    printf 'rpcpassword=%s\n' "$rpc_pass"
  } >"$output_file"
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
