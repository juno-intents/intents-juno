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

production_inventory_terraform_dir() {
  local inventory="$1"
  local inventory_dir="$2"
  local terraform_dir

  terraform_dir="$(production_json_optional "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
  [[ -n "$terraform_dir" ]] || return 1
  production_abs_path "$inventory_dir" "$terraform_dir"
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
  local backup_zip_src="$1"
  local backup_zip_dst="$2"
  local dkg_tls_dir="${3:-}"
  local tmp_dir tmp_json coordinator_client_fingerprint

  [[ -f "$backup_zip_src" ]] || die "dkg backup zip not found: $backup_zip_src"
  mkdir -p "$(dirname "$backup_zip_dst")"

  if [[ -z "$dkg_tls_dir" ]]; then
    if [[ "$backup_zip_src" != "$backup_zip_dst" ]]; then
      cp "$backup_zip_src" "$backup_zip_dst"
    fi
    return 0
  fi

  [[ -d "$dkg_tls_dir" ]] || die "dkg_tls_dir not found: $dkg_tls_dir"
  for required in ca.pem coordinator-client.pem coordinator-client.key; do
    [[ -f "$dkg_tls_dir/$required" ]] || die "dkg_tls_dir missing required file: $dkg_tls_dir/$required"
  done
  have_cmd unzip || die "required command not found: unzip"
  have_cmd zip || die "required command not found: zip"

  tmp_dir="$(mktemp -d)"
  unzip -q "$backup_zip_src" -d "$tmp_dir" || {
    rm -rf "$tmp_dir"
    die "failed to unpack dkg backup zip: $backup_zip_src"
  }

  [[ -f "$tmp_dir/manifest.json" ]] || {
    rm -rf "$tmp_dir"
    die "dkg backup zip missing manifest.json: $backup_zip_src"
  }
  [[ -f "$tmp_dir/payload/admin-config.json" ]] || {
    rm -rf "$tmp_dir"
    die "dkg backup zip missing payload/admin-config.json: $backup_zip_src"
  }

  mkdir -p "$tmp_dir/payload/tls"
  cp "$dkg_tls_dir/ca.pem" "$tmp_dir/payload/tls/ca.pem"
  cp "$dkg_tls_dir/coordinator-client.pem" "$tmp_dir/payload/tls/coordinator-client.pem"
  cp "$dkg_tls_dir/coordinator-client.key" "$tmp_dir/payload/tls/coordinator-client.key"
  chmod 0600 "$tmp_dir/payload/tls/coordinator-client.key" || true

  coordinator_client_fingerprint="$(production_certificate_sha256_hex "$dkg_tls_dir/coordinator-client.pem")"
  tmp_json="$(mktemp)"
  jq \
    --arg fingerprint "$coordinator_client_fingerprint" \
    '.grpc = ((.grpc // {}) + {
      coordinator_client_cert_sha256: $fingerprint,
      tls_client_cert_pem_path: "./tls/coordinator-client.pem",
      tls_client_key_pem_path: "./tls/coordinator-client.key"
    })' \
    "$tmp_dir/payload/admin-config.json" >"$tmp_json"
  mv "$tmp_json" "$tmp_dir/payload/admin-config.json"

  tmp_json="$(mktemp)"
  jq \
    --arg tls_ca_path "$dkg_tls_dir/ca.pem" \
    --arg coordinator_client_cert_path "$dkg_tls_dir/coordinator-client.pem" \
    --arg coordinator_client_key_path "$dkg_tls_dir/coordinator-client.key" \
    '.includes = ((.includes // {}) + {
      tls_ca_cert: "payload/tls/ca.pem",
      coordinator_client_cert: "payload/tls/coordinator-client.pem",
      coordinator_client_key: "payload/tls/coordinator-client.key"
    })
    | .source_paths = ((.source_paths // {}) + {
      tls_ca_cert: $tls_ca_path,
      coordinator_client_cert: $coordinator_client_cert_path,
      coordinator_client_key: $coordinator_client_key_path
    })' \
    "$tmp_dir/manifest.json" >"$tmp_json"
  mv "$tmp_json" "$tmp_dir/manifest.json"

  rm -f "$backup_zip_dst"
  (
    cd "$tmp_dir"
    zip -qr "$backup_zip_dst" manifest.json payload
  ) || {
    rm -rf "$tmp_dir"
    die "failed to pack normalized dkg backup zip: $backup_zip_dst"
  }

  rm -rf "$tmp_dir"
}

production_base_relayer_allowed_selectors() {
  printf '0x53a58a48,0xec70b605\n'
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
  local inventory="$1"
  local inventory_dir="$2"
  local shared_manifest="$3"
  local operator_json="$4"
  local secret_contract_file="$5"
  local current_dsn existing_dsn checkpoint_blob_bucket

  [[ -f "$secret_contract_file" ]] || return 0

  existing_dsn="$(production_env_first_value "$secret_contract_file" CHECKPOINT_POSTGRES_DSN APP_POSTGRES_DSN || true)"
  existing_dsn="${existing_dsn#literal:}"
  if [[ -n "$existing_dsn" ]]; then
    current_dsn="$(production_current_postgres_dsn "$inventory" "$inventory_dir" "$shared_manifest" "$existing_dsn")"
    production_secret_contract_upsert_literal "$secret_contract_file" CHECKPOINT_POSTGRES_DSN "$current_dsn"
  fi

  checkpoint_blob_bucket="$(jq -r '.checkpoint_blob_bucket // empty' <<<"$operator_json")"
  if [[ -z "$checkpoint_blob_bucket" ]]; then
    checkpoint_blob_bucket="$(jq -r '.shared_services.artifacts.checkpoint_blob_bucket // empty' "$shared_manifest")"
  fi
  if [[ -n "$checkpoint_blob_bucket" ]]; then
    production_secret_contract_upsert_literal "$secret_contract_file" CHECKPOINT_BLOB_BUCKET "$checkpoint_blob_bucket"
    production_secret_contract_upsert_literal "$secret_contract_file" WITHDRAW_BLOB_BUCKET "$checkpoint_blob_bucket"
  fi
}

production_refresh_app_secret_contract() {
  local inventory="$1"
  local inventory_dir="$2"
  local shared_manifest="$3"
  local secret_contract_file="$4"
  local current_dsn existing_dsn updated_any="false"

  [[ -f "$secret_contract_file" ]] || return 0

  existing_dsn="$(production_env_first_value "$secret_contract_file" APP_POSTGRES_DSN CHECKPOINT_POSTGRES_DSN || true)"
  existing_dsn="${existing_dsn#literal:}"
  [[ -n "$existing_dsn" ]] || return 0

  current_dsn="$(production_current_postgres_dsn "$inventory" "$inventory_dir" "$shared_manifest" "$existing_dsn")"
  if grep -q '^APP_POSTGRES_DSN=' "$secret_contract_file"; then
    production_secret_contract_upsert_literal "$secret_contract_file" APP_POSTGRES_DSN "$current_dsn"
    updated_any="true"
  fi
  if grep -q '^CHECKPOINT_POSTGRES_DSN=' "$secret_contract_file"; then
    production_secret_contract_upsert_literal "$secret_contract_file" CHECKPOINT_POSTGRES_DSN "$current_dsn"
    updated_any="true"
  fi
  if [[ "$updated_any" != "true" ]]; then
    production_secret_contract_upsert_literal "$secret_contract_file" APP_POSTGRES_DSN "$current_dsn"
  fi
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
  local operator_count index operator_json endpoint_addr endpoint_host endpoint_profile endpoint_region
  local operator_id dkg_endpoint endpoint_port parsed_endpoint operator_index

  operator_count="$(jq -r '.operators | length' "$inventory")"
  for ((index = 0; index < operator_count; index++)); do
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    operator_id="$(jq -r '.operator_id // empty' <<<"$operator_json")"
    operator_index="$(jq -r '.index // empty' <<<"$operator_json")"
    endpoint_addr="$(jq -r '.operator_address // .operator_id // empty' <<<"$operator_json")"
    endpoint_host="$(jq -r '.private_endpoint // .operator_probe_host // .public_endpoint // .operator_host // empty' <<<"$operator_json")"
    endpoint_profile="$(jq -r '.aws_profile // empty' <<<"$operator_json")"
    endpoint_region="$(jq -r '.aws_region // empty' <<<"$operator_json")"
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
    if [[ -n "$endpoint_profile" && -n "$endpoint_region" ]]; then
      endpoint_host="$(production_aws_resolve_private_ip "$endpoint_profile" "$endpoint_region" "$endpoint_host")"
    fi
    printf '%s=%s:%s\n' "$endpoint_addr" "$endpoint_host" "$endpoint_port"
  done | jq -R -s 'split("\n") | map(select(length > 0))'
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
  local secret_contract_file="$1"
  local dkg_summary="$2"
  local operator_id="$3"

  if grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY=' "$secret_contract_file"; then
    return 0
  fi

  local operator_key_file dkg_dir checkpoint_signer_private_key
  operator_key_file="$(production_dkg_operator_key_file "$dkg_summary" "$operator_id")"
  [[ -n "$operator_key_file" ]] || return 1

  dkg_dir="$(cd "$(dirname "$dkg_summary")" && pwd)"
  operator_key_file="$(production_abs_path "$dkg_dir" "$operator_key_file")"
  [[ -f "$operator_key_file" ]] || die "operator key file not found for $operator_id: $operator_key_file"

  checkpoint_signer_private_key="$(production_normalize_ecdsa_private_key "$(cat "$operator_key_file")")"
  production_secret_contract_upsert_literal "$secret_contract_file" CHECKPOINT_SIGNER_PRIVATE_KEY "$checkpoint_signer_private_key"
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

  [[ -n "$secret_contract_file" && -f "$secret_contract_file" ]] || return 1
  existing_keys="$(production_env_get_value "$secret_contract_file" "JUNO_TXSIGN_SIGNER_KEYS")"
  [[ -n "$existing_keys" ]] || return 1
  case "$existing_keys" in
    literal:*|file:/*|aws-sm://*|aws-ssm:///*|env:*)
      existing_keys="$(production_resolve_secret_value "$existing_keys" "$aws_profile" "$aws_region")"
      ;;
  esac
  signer_key="$(production_csv_value_at_index "$existing_keys" "$operator_index" || true)"
  [[ -n "$signer_key" ]] || return 1
  production_normalize_ecdsa_private_key "$signer_key"
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

production_default_bridge_refund_window_seconds() {
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
  local environment="$1"
  case "$environment" in
    alpha|preview) return 0 ;;
    *) return 1 ;;
  esac
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
  local manifest_dir operators_dir environment allow_local_resolvers tmp_dir addresses_file
  local operator_deploy secret_contract_file aws_profile aws_region resolved_env
  local -a operator_deploys=()
  local addresses_csv

  manifest_dir="$(cd "$(dirname "$app_deploy")" && pwd)"
  operators_dir="$(production_abs_path "$manifest_dir" "../operators")"
  [[ -d "$operators_dir" ]] || die "operator handoff directory not found for app deploy: $operators_dir"

  environment="$(production_json_required "$app_deploy" '.environment | select(type == "string" and length > 0)')"
  allow_local_resolvers="false"
  if production_environment_allows_local_secret_resolvers "$environment"; then
    allow_local_resolvers="true"
  fi

  tmp_dir="$(mktemp -d)"
  addresses_file="$tmp_dir/base-relayer-addresses.txt"

  operator_deploys=("$operators_dir"/*/operator-deploy.json)
  [[ "${#operator_deploys[@]}" -gt 0 && -f "${operator_deploys[0]}" ]] || die "no operator handoff manifests found for app deploy: $app_deploy"

  for operator_deploy in "${operator_deploys[@]}"; do
    [[ -f "$operator_deploy" ]] || continue
    [[ -n "$operator_deploy" ]] || continue
    secret_contract_file="$(production_abs_path "$(dirname "$operator_deploy")" "$(production_json_required "$operator_deploy" '.secret_contract_file | select(type == "string" and length > 0)')")"
    aws_profile="$(production_json_optional "$operator_deploy" '.aws_profile')"
    aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
    resolved_env="$tmp_dir/$(production_safe_slug "$(basename "$(dirname "$operator_deploy")")").resolved.env"
    production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
    production_base_relayer_addresses "$resolved_env" >>"$addresses_file"
  done

  if [[ ! -s "$addresses_file" ]]; then
    rm -rf "$tmp_dir"
    die "no operator handoffs with base relayer signer addresses found for app deploy: $app_deploy"
  fi

  addresses_csv="$(awk 'NF { key = tolower($0); if (!seen[key]++) print $0 }' "$addresses_file" | paste -sd, -)"
  rm -rf "$tmp_dir"
  [[ -n "$addresses_csv" ]] || die "failed to derive base relayer signer addresses for app deploy: $app_deploy"
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
  local postgres_endpoint postgres_port kafka_brokers ipfs_api_url dkg_bucket dkg_prefix
  local ecs_cluster_arn proof_requestor_service_name proof_funder_service_name
  local shared_sp1_requestor_address shared_sp1_rpc_url
  local bridge_fee_bps bridge_relayer_tip_bps bridge_refund_window_seconds
  local bridge_max_expiry_extension_seconds bridge_min_deposit_amount bridge_min_withdraw_amount
  local operator_ids_csv threshold operators_json roster_json secret_keys_json governance_json
  local dkg_completion_network signer_ufvk inventory_owallet_ua bridge_summary_owallet_ua
  local summary_owallet_ua completion_owallet_ua effective_owallet_ua base_event_scanner_start_block
  local dkg_kms_key_arn

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
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  zone_name="$(production_json_required "$inventory" '.shared_services.public_zone_name | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"

  postgres_endpoint="$(production_tf_output_value "$tf_json" "shared_postgres_endpoint" true)"
  postgres_cluster_arn="$(production_tf_output_value "$tf_json" "shared_postgres_cluster_arn" false)"
  postgres_port="$(production_tf_output_value "$tf_json" "shared_postgres_port" true)"
  kafka_cluster_arn="$(production_tf_output_value "$tf_json" "shared_kafka_cluster_arn" false)"
  kafka_brokers="$(production_tf_output_value "$tf_json" "shared_kafka_bootstrap_brokers" true)"
  ecs_cluster_arn="$(production_tf_output_value "$tf_json" "shared_ecs_cluster_arn" false)"
  proof_requestor_service_name="$(production_tf_output_value "$tf_json" "shared_proof_requestor_service_name" false)"
  proof_funder_service_name="$(production_tf_output_value "$tf_json" "shared_proof_funder_service_name" false)"
  shared_sp1_requestor_address="$(production_tf_output_value "$tf_json" "shared_sp1_requestor_address" false)"
  shared_sp1_rpc_url="$(production_tf_output_value "$tf_json" "shared_sp1_rpc_url" false)"
  ipfs_api_url="$(production_tf_output_value "$tf_json" "shared_ipfs_api_url" true)"
  ipfs_target_group_arn="$(production_tf_output_value "$tf_json" "shared_ipfs_target_group_arn" false)"
  dkg_bucket="$(production_tf_output_value "$tf_json" "dkg_s3_bucket" false)"
  dkg_prefix="$(production_tf_output_value "$tf_json" "dkg_s3_key_prefix" false)"
  dkg_kms_key_arn="$(production_tf_output_value "$tf_json" "dkg_kms_key_arn" false)"
  bridge_fee_bps="$(production_json_required "$bridge_summary" '.bridge_params.fee_bps // .bridge_fee_params.fee_bps')"
  bridge_relayer_tip_bps="$(production_json_required "$bridge_summary" '.bridge_params.relayer_tip_bps // .bridge_fee_params.relayer_tip_bps')"
  bridge_refund_window_seconds="$(production_json_required "$bridge_summary" '.bridge_params.refund_window_seconds')"
  bridge_max_expiry_extension_seconds="$(production_json_required "$bridge_summary" '.bridge_params.max_expiry_extension_seconds')"
  bridge_min_deposit_amount="$(production_json_required "$bridge_summary" '.bridge_params.min_deposit_amount')"
  bridge_min_withdraw_amount="$(production_json_required "$bridge_summary" '.bridge_params.min_withdraw_amount')"

  operator_ids_csv="$(production_operator_ids_csv "$dkg_summary")"
  [[ -n "$operator_ids_csv" ]] || die "dkg summary does not contain operator ids"
  threshold="$(production_threshold "$dkg_summary")"
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
    --arg version "1" \
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
    --arg kafka_auth_mode "$(production_kafka_auth_mode_for_environment "$env_slug")" \
    --arg kafka_auth_aws_region "$aws_region" \
    --arg ecs_cluster_arn "$ecs_cluster_arn" \
    --arg proof_requestor_service_name "$proof_requestor_service_name" \
    --arg proof_funder_service_name "$proof_funder_service_name" \
    --arg shared_sp1_requestor_address "$shared_sp1_requestor_address" \
    --arg shared_sp1_rpc_url "$shared_sp1_rpc_url" \
    --arg ipfs_api_url "$ipfs_api_url" \
    --arg ipfs_target_group_arn "$ipfs_target_group_arn" \
    --arg dkg_bucket "$dkg_bucket" \
    --arg dkg_prefix "$dkg_prefix" \
    --arg dkg_kms_key_arn "$dkg_kms_key_arn" \
    --arg base_rpc_url "$base_rpc_url" \
    --argjson base_chain_id "$base_chain_id" \
    --argjson base_event_scanner_start_block "$base_event_scanner_start_block" \
    --argjson bridge_fee_bps "$bridge_fee_bps" \
    --argjson bridge_relayer_tip_bps "$bridge_relayer_tip_bps" \
    --argjson bridge_refund_window_seconds "$bridge_refund_window_seconds" \
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
          min_insync_replicas: 2
        },
        ecs: {
          cluster_arn: (if $ecs_cluster_arn == "" then null else $ecs_cluster_arn end),
          proof_requestor_service_name: (if $proof_requestor_service_name == "" then null else $proof_requestor_service_name end),
          proof_funder_service_name: (if $proof_funder_service_name == "" then null else $proof_funder_service_name end)
        },
        proof: {
          requestor_address: (if $shared_sp1_requestor_address == "" then null else $shared_sp1_requestor_address end),
          rpc_url: (if $shared_sp1_rpc_url == "" then null else $shared_sp1_rpc_url end)
        },
        ipfs: {
          api_url: $ipfs_api_url,
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
          refund_window_seconds: $bridge_refund_window_seconds,
          max_expiry_extension_seconds: $bridge_max_expiry_extension_seconds,
          min_deposit_amount: $bridge_min_deposit_amount,
          min_withdraw_amount: $bridge_min_withdraw_amount
        },
        deposit_image_id: (if $deposit_image_id == "" then null else $deposit_image_id end),
        withdraw_image_id: (if $withdraw_image_id == "" then null else $withdraw_image_id end),
        owallet_ua: (if $effective_owallet_ua == "" then null else $effective_owallet_ua end)
      },
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
        zone_id: $zone_id,
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

  if ! jq -e '.app_host? | type == "object"' "$inventory" >/dev/null 2>&1; then
    return 0
  fi

  shared_manifest="$(production_abs_path "$(pwd)" "$shared_manifest")"
  output_dir="$(production_abs_path "$(pwd)" "$output_dir")"

  local env_slug public_subdomain zone_id dns_mode ttl_seconds
  local app_json app_dir manifest_path known_hosts_src secret_contract_src
  local known_hosts_dst secret_contract_dst app_host app_user runtime_dir
  local public_endpoint aws_profile aws_region account_id security_group_id
  local bridge_dns_label ops_dns_label public_scheme bridge_listen_addr backoffice_listen_addr
  local bridge_record_name ops_record_name bridge_public_url ops_public_url
  local bridge_probe_url ops_probe_url bridge_internal_url ops_internal_url
  local bridge_refund_window_seconds bridge_min_deposit_amount bridge_min_withdraw_amount bridge_fee_bps
  local juno_rpc_url operator_addresses_json
  local service_urls_json operator_endpoints_json
  local edge_enabled edge_state_path edge_origin_record_name edge_origin_endpoint
  local edge_origin_http_port edge_rate_limit edge_enable_shield_advanced

  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  app_json="$(jq -c '.app_host' "$inventory")"

  app_host="$(jq -r '.host // empty' <<<"$app_json")"
  [[ -n "$app_host" ]] || die "app_host.host is required when inventory.app_host is present"
  app_user="$(jq -r '.user // "ubuntu"' <<<"$app_json")"
  runtime_dir="$(jq -r '.runtime_dir // "/var/lib/intents-juno/app-runtime"' <<<"$app_json")"
  public_endpoint="$(jq -r '.public_endpoint // .host // empty' <<<"$app_json")"
  [[ -n "$public_endpoint" ]] || die "app_host.public_endpoint is required when inventory.app_host is present"
  aws_profile="$(jq -r '.aws_profile // empty' <<<"$app_json")"
  aws_region="$(jq -r '.aws_region // empty' <<<"$app_json")"
  account_id="$(jq -r '.account_id // empty' <<<"$app_json")"
  security_group_id="$(jq -r '.security_group_id // empty' <<<"$app_json")"
  bridge_dns_label="$(jq -r '.bridge_public_dns_label // empty' <<<"$app_json")"
  ops_dns_label="$(jq -r '.ops_public_dns_label // empty' <<<"$app_json")"
  [[ -n "$bridge_dns_label" ]] || die "app_host.bridge_public_dns_label is required when inventory.app_host is present"
  [[ -n "$ops_dns_label" ]] || die "app_host.ops_public_dns_label is required when inventory.app_host is present"
  public_scheme="$(jq -r '.public_scheme // "https"' <<<"$app_json")"
  [[ "$public_scheme" == "https" ]] || die "app_host.public_scheme must be https"
  bridge_listen_addr="$(jq -r '.bridge_api_listen // "0.0.0.0:8082"' <<<"$app_json")"
  backoffice_listen_addr="$(jq -r '.backoffice_listen // "0.0.0.0:8090"' <<<"$app_json")"
  production_require_loopback_listen_addr "$bridge_listen_addr" "app_host.bridge_api_listen"
  production_require_loopback_listen_addr "$backoffice_listen_addr" "app_host.backoffice_listen"
  bridge_refund_window_seconds="$(production_json_required "$shared_manifest" '.contracts.bridge_params.refund_window_seconds')"
  bridge_min_deposit_amount="$(production_json_required "$shared_manifest" '.contracts.bridge_params.min_deposit_amount')"
  bridge_min_withdraw_amount="$(production_json_required "$shared_manifest" '.contracts.bridge_params.min_withdraw_amount')"
  bridge_fee_bps="$(production_json_required "$shared_manifest" '.contracts.bridge_params.fee_bps')"
  juno_rpc_url="$(jq -r '.juno_rpc_url // empty' <<<"$app_json")"
  operator_addresses_json="$(jq -c '[.operators[] | (.operator_address // .operator_id)]' "$inventory")"
  service_urls_json="$(jq -c '.service_urls // []' <<<"$app_json")"
  operator_endpoints_json="$(jq -c '.operator_endpoints // []' <<<"$app_json")"
  if [[ "$(jq -r 'length' <<<"$operator_endpoints_json")" == "0" ]]; then
    operator_endpoints_json="$(production_default_operator_endpoints_json "$inventory" "$shared_manifest")"
  fi

  known_hosts_src="$(jq -r '.known_hosts_file // empty' <<<"$app_json")"
  [[ -n "$known_hosts_src" ]] || die "app_host.known_hosts_file is required when inventory.app_host is present"
  known_hosts_src="$(production_abs_path "$inventory_dir" "$known_hosts_src")"
  [[ -f "$known_hosts_src" ]] || die "app known_hosts file not found: $known_hosts_src"

  secret_contract_src="$(jq -r '.secret_contract_file // empty' <<<"$app_json")"
  [[ -n "$secret_contract_src" ]] || die "app_host.secret_contract_file is required when inventory.app_host is present"
  secret_contract_src="$(production_abs_path "$inventory_dir" "$secret_contract_src")"
  [[ -f "$secret_contract_src" ]] || die "app secret contract file not found: $secret_contract_src"

  bridge_record_name="${bridge_dns_label}.${public_subdomain}"
  ops_record_name="${ops_dns_label}.${public_subdomain}"
  bridge_public_url="$(production_origin_url "$public_scheme" "$bridge_record_name")"
  ops_public_url="$(production_origin_url "$public_scheme" "$ops_record_name")"
  bridge_probe_url="$bridge_public_url"
  ops_probe_url="$ops_public_url"
  bridge_internal_url="$(production_public_url "http" "127.0.0.1" "$bridge_listen_addr")"
  ops_internal_url="$(production_public_url "http" "127.0.0.1" "$backoffice_listen_addr")"
  edge_enabled="true"
  edge_state_path=""
  edge_origin_record_name="origin.${public_subdomain}"
  edge_origin_endpoint="$public_endpoint"
  edge_origin_http_port=80
  edge_rate_limit=2000
  edge_enable_shield_advanced="false"

  app_dir="$(production_app_dir "$output_dir")"
  mkdir -p "$app_dir"
  known_hosts_dst="$app_dir/known_hosts"
  secret_contract_dst="$app_dir/app-secrets.env"
  cp "$known_hosts_src" "$known_hosts_dst"
  cp "$secret_contract_src" "$secret_contract_dst"
  production_refresh_app_secret_contract "$inventory" "$inventory_dir" "$shared_manifest" "$secret_contract_dst"
  manifest_path="$app_dir/app-deploy.json"

  jq -n \
    --arg version "1" \
    --arg environment "$env_slug" \
    --arg shared_manifest_path "$shared_manifest" \
    --arg known_hosts_file "$known_hosts_dst" \
    --arg secret_contract_file "$secret_contract_dst" \
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
    --argjson bridge_refund_window_seconds "$bridge_refund_window_seconds" \
    --argjson bridge_min_deposit_amount "$bridge_min_deposit_amount" \
    --argjson bridge_min_withdraw_amount "$bridge_min_withdraw_amount" \
    --argjson bridge_fee_bps "$bridge_fee_bps" \
    --arg backoffice_listen_addr "$backoffice_listen_addr" \
    --arg backoffice_public_url "$ops_public_url" \
    --arg backoffice_probe_url "$ops_probe_url" \
    --arg backoffice_internal_url "$ops_internal_url" \
    --arg backoffice_record_name "$ops_record_name" \
    --arg public_scheme "$public_scheme" \
    --arg dns_mode "$dns_mode" \
    --arg zone_id "$zone_id" \
    --argjson ttl_seconds "$ttl_seconds" \
    --argjson operator_addresses "$operator_addresses_json" \
    --argjson service_urls "$service_urls_json" \
    --argjson operator_endpoints "$operator_endpoints_json" \
    --arg edge_enabled "$edge_enabled" \
    --arg edge_state_path "$app_dir/edge.tfstate" \
    --arg edge_origin_record_name "$edge_origin_record_name" \
    --arg edge_origin_endpoint "$edge_origin_endpoint" \
    --argjson edge_origin_http_port "$edge_origin_http_port" \
    --argjson edge_rate_limit "$edge_rate_limit" \
    --arg edge_enable_shield_advanced "$edge_enable_shield_advanced" \
    '{
      version: $version,
      environment: $environment,
      shared_manifest_path: $shared_manifest_path,
      known_hosts_file: $known_hosts_file,
      secret_contract_file: $secret_contract_file,
      app_host: $app_host,
      app_user: $app_user,
      runtime_dir: $runtime_dir,
      public_endpoint: $public_endpoint,
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
          refund_window_seconds: $bridge_refund_window_seconds,
          min_deposit_amount: $bridge_min_deposit_amount,
          min_withdraw_amount: $bridge_min_withdraw_amount,
          fee_bps: $bridge_fee_bps
        },
        backoffice: {
          listen_addr: $backoffice_listen_addr,
          public_url: $backoffice_public_url,
          probe_url: $backoffice_probe_url,
          internal_url: $backoffice_internal_url,
          record_name: $backoffice_record_name
        }
      },
      dns: {
        mode: $dns_mode,
        zone_id: $zone_id,
        ttl_seconds: $ttl_seconds
      },
      edge: {
        enabled: ($edge_enabled == "true"),
        state_path: $edge_state_path,
        origin_record_name: $edge_origin_record_name,
        origin_endpoint: $edge_origin_endpoint,
        origin_http_port: $edge_origin_http_port,
        rate_limit: $edge_rate_limit,
        enable_shield_advanced: ($edge_enable_shield_advanced == "true")
      }
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
  local signer_ufvk derived_deposit_owallet_ivk derived_withdraw_owallet_ovk
  env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  public_subdomain="$(production_json_required "$inventory" '.shared_services.public_subdomain | select(type == "string" and length > 0)')"
  zone_id="$(production_json_required "$inventory" '.shared_services.route53_zone_id | select(type == "string" and length > 0)')"
  dns_mode="$(production_json_required "$inventory" '.dns.mode | select(type == "string" and length > 0)')"
  ttl_seconds="$(production_json_required "$inventory" '.dns.ttl_seconds')"
  dkg_tls_dir="$(jq -r '.dkg_tls_dir // empty' "$inventory")"
  if [[ -n "$dkg_tls_dir" ]]; then
    dkg_tls_dir="$(production_abs_path "$inventory_dir" "$dkg_tls_dir")"
    [[ -d "$dkg_tls_dir" ]] || die "dkg_tls_dir not found: $dkg_tls_dir"
  fi
  shared_owallet_ua="$(production_json_required "$shared_manifest" '.contracts.owallet_ua | select(type == "string" and length > 0)')"
  signer_ufvk="$(production_json_required "$shared_manifest" '.checkpoint.signer_ufvk | select(type == "string" and length > 0)')"
  derived_deposit_owallet_ivk=""
  derived_withdraw_owallet_ovk=""

  local rollout_state="$output_dir/rollout-state.json"
  production_write_rollout_state "$inventory" "$rollout_state"

  local operator_count index
  operator_count="$(jq -r '.operators | length' "$inventory")"
  for ((index = 0; index < operator_count; index++)); do
    local operator_json operator_id handoff_dir known_hosts_src secrets_src backup_zip_src
    local known_hosts_dst secrets_dst backup_zip_dst manifest_path public_dns_name public_endpoint
    local checkpoint_signer_driver checkpoint_signer_kms_key_id operator_address operator_index operator_txsign_signer_key
    local checkpoint_blob_bucket checkpoint_blob_prefix checkpoint_blob_sse_kms_key_id
    operator_json="$(jq -c ".operators[$index]" "$inventory")"
    operator_id="$(jq -r '.operator_id' <<<"$operator_json")"
    operator_index="$(jq -r '.index' <<<"$operator_json")"
    handoff_dir="$(production_operator_dir "$output_dir" "$operator_id")"
    mkdir -p "$handoff_dir"

    known_hosts_src="$(jq -r '.known_hosts_file // empty' <<<"$operator_json")"
    secrets_src="$(jq -r '.secret_contract_file // empty' <<<"$operator_json")"
    backup_zip_src="$(jq -r '.dkg_backup_zip // empty' <<<"$operator_json")"
    public_endpoint="$(jq -r '.public_endpoint // .operator_host // empty' <<<"$operator_json")"
    public_dns_name="$(jq -r --arg subdomain "$public_subdomain" '.public_dns_label + "." + $subdomain' <<<"$operator_json")"
    checkpoint_signer_driver="$(jq -r '.checkpoint_signer_driver // "aws-kms"' <<<"$operator_json")"
    checkpoint_signer_kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' <<<"$operator_json")"
    checkpoint_blob_bucket="$(jq -r '.checkpoint_blob_bucket // empty' <<<"$operator_json")"
    checkpoint_blob_prefix="$(jq -r '.checkpoint_blob_prefix // empty' <<<"$operator_json")"
    checkpoint_blob_sse_kms_key_id="$(jq -r '.checkpoint_blob_sse_kms_key_id // empty' <<<"$operator_json")"
    operator_address="$(jq -r '.operator_address // empty' <<<"$operator_json")"
    manifest_path="$handoff_dir/operator-deploy.json"

    case "$checkpoint_signer_driver" in
      aws-kms)
        checkpoint_signer_kms_key_id="$(production_resolve_checkpoint_signer_kms_key_id "$env_slug" "$dkg_summary" "$operator_json")"
        ;;
      *)
        die "operator $operator_id must use checkpoint_signer_driver=aws-kms (got: $checkpoint_signer_driver)"
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
      production_refresh_operator_secret_contract "$inventory" "$inventory_dir" "$shared_manifest" "$operator_json" "$secrets_dst"
      if ! grep -q '^DEPOSIT_OWALLET_IVK=' "$secrets_dst" || ! grep -q '^WITHDRAW_OWALLET_OVK=' "$secrets_dst"; then
        local -a derived_owallet_keys
        if [[ -z "$derived_deposit_owallet_ivk" || -z "$derived_withdraw_owallet_ovk" ]]; then
          mapfile -t derived_owallet_keys < <(production_derive_owallet_keys_from_ufvk "$signer_ufvk")
          [[ "${#derived_owallet_keys[@]}" -eq 2 ]] || die "ufvk derive output must contain deposit ivk and withdraw ovk"
          derived_deposit_owallet_ivk="${derived_owallet_keys[0]}"
          derived_withdraw_owallet_ovk="${derived_owallet_keys[1]}"
        fi
        if ! grep -q '^DEPOSIT_OWALLET_IVK=' "$secrets_dst"; then
          production_secret_contract_upsert_literal "$secrets_dst" DEPOSIT_OWALLET_IVK "$derived_deposit_owallet_ivk"
        fi
      if ! grep -q '^WITHDRAW_OWALLET_OVK=' "$secrets_dst"; then
          production_secret_contract_upsert_literal "$secrets_dst" WITHDRAW_OWALLET_OVK "$derived_withdraw_owallet_ovk"
        fi
      fi
      production_secret_contract_upsert_literal "$secrets_dst" WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS "$shared_owallet_ua"
      operator_txsign_signer_key="$(production_operator_txsign_signer_key "$dkg_summary" "$operator_id" "$operator_index" "$secrets_dst" "$(jq -r '.aws_profile // empty' <<<"$operator_json")" "$(jq -r '.aws_region // empty' <<<"$operator_json")" || true)"
      [[ -n "$operator_txsign_signer_key" ]] || die "operator $operator_id is missing an isolated JUNO_TXSIGN_SIGNER_KEYS entry or operator_key_file"
      production_secret_contract_upsert_literal "$secrets_dst" JUNO_TXSIGN_SIGNER_KEYS "$operator_txsign_signer_key"
      production_secret_contract_delete_key "$secrets_dst" CHECKPOINT_SIGNER_PRIVATE_KEY
    fi

    if [[ -n "$backup_zip_src" ]]; then
      backup_zip_src="$(production_abs_path "$inventory_dir" "$backup_zip_src")"
      backup_zip_dst="$handoff_dir/dkg-backup.zip"
      production_materialize_operator_dkg_backup_zip "$backup_zip_src" "$backup_zip_dst" "$dkg_tls_dir"
      backup_zip_src="$backup_zip_dst"
    fi

    jq -n \
      --arg version "1" \
      --arg environment "$env_slug" \
      --arg shared_manifest_path "$shared_manifest" \
      --arg rollout_state_file "$rollout_state" \
      --arg checkpoint_signer_driver "$checkpoint_signer_driver" \
      --arg checkpoint_signer_kms_key_id "$checkpoint_signer_kms_key_id" \
      --arg checkpoint_blob_bucket "$checkpoint_blob_bucket" \
      --arg checkpoint_blob_prefix "$checkpoint_blob_prefix" \
      --arg checkpoint_blob_sse_kms_key_id "$checkpoint_blob_sse_kms_key_id" \
      --arg operator_address "$operator_address" \
      --arg known_hosts_file "$known_hosts_dst" \
      --arg secret_contract_file "$secrets_dst" \
      --arg dkg_backup_zip "$backup_zip_src" \
      --arg dkg_tls_dir "$dkg_tls_dir" \
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
        dkg_backup_zip: $dkg_backup_zip,
        dkg_tls_dir: (if $dkg_tls_dir == "" then null else $dkg_tls_dir end),
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

  local checkpoint_operators signer_driver signer_kms_key_id operator_address aws_region environment
  local deposit_scan_wallet_id base_event_scanner_start_block withdraw_juno_fee_add_zat
  local juno_txsign_signer_keys owallet_ua withdraw_change_address
  local withdraw_expiry_safety_margin withdraw_max_expiry_extension min_base_relayer_balance_wei
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations
  juno_txsign_signer_keys=""
  deposit_scan_wallet_id=""
  min_base_relayer_balance_wei="$(production_required_min_base_relayer_balance_wei)"
  withdraw_juno_fee_add_zat="$(production_default_withdraw_coordinator_juno_fee_add_zat)"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"
  withdraw_expiry_safety_margin="$(production_env_first_value "$resolved_secret_env" WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN || true)"
  withdraw_max_expiry_extension="$(production_env_first_value "$resolved_secret_env" WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION || true)"
  owallet_ua="$(production_json_required "$shared_manifest" '.contracts.owallet_ua | select(type == "string" and length > 0)')"
  checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
  [[ -n "$checkpoint_operators" ]] || die "shared manifest is missing checkpoint operators"
  base_event_scanner_start_block="$(jq -r '.contracts.base_event_scanner_start_block // empty' "$shared_manifest")"
  production_is_positive_integer "$base_event_scanner_start_block" \
    || die "shared manifest is missing a positive contracts.base_event_scanner_start_block"
  environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
  signer_driver="$(production_json_required "$operator_deploy" '.checkpoint_signer_driver | select(type == "string" and length > 0)')"
  signer_kms_key_id="$(production_json_optional "$operator_deploy" '.checkpoint_signer_kms_key_id')"
  operator_address="$(production_json_optional "$operator_deploy" '.operator_address')"
  aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
  if [[ -z "$operator_address" ]]; then
    operator_address="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
  fi
  juno_txsign_signer_keys="$(production_env_first_value "$resolved_secret_env" JUNO_TXSIGN_SIGNER_KEYS || true)"
  [[ -n "$juno_txsign_signer_keys" ]] || die "resolved secret env is missing JUNO_TXSIGN_SIGNER_KEYS for juno-txsign sign-digest"
  juno_txsign_signer_keys="$(production_require_single_txsign_signer_key "$juno_txsign_signer_keys")"
  withdraw_change_address="$(production_env_first_value "$resolved_secret_env" WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS || true)"
  if [[ -n "$withdraw_change_address" && "$withdraw_change_address" != "$owallet_ua" ]]; then
    die "resolved secret env WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS ($withdraw_change_address) does not match shared manifest owallet_ua ($owallet_ua)"
  fi
  if [[ -n "$withdraw_expiry_safety_margin" && "$withdraw_expiry_safety_margin" != "6h" ]]; then
    die "resolved secret env must not override WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN (expected 6h, got $withdraw_expiry_safety_margin)"
  fi
  if [[ -n "$withdraw_max_expiry_extension" && "$withdraw_max_expiry_extension" != "12h" ]]; then
    die "resolved secret env must not override WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION (expected 12h, got $withdraw_max_expiry_extension)"
  fi

  case "$signer_driver" in
    aws-kms)
      [[ -n "$signer_kms_key_id" ]] || die "operator deploy manifest is missing checkpoint_signer_kms_key_id for aws-kms signer"
      [[ -n "$aws_region" ]] || die "operator deploy manifest is missing aws_region for aws-kms signer"
      if grep -q '^CHECKPOINT_SIGNER_PRIVATE_KEY=' "$resolved_secret_env"; then
        die "resolved secret env must not contain CHECKPOINT_SIGNER_PRIVATE_KEY when checkpoint_signer_driver=aws-kms"
      fi
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
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/juno-txsign
WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240
WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=$withdraw_juno_fee_add_zat
WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h
WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h
WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=$owallet_ua
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
  if [[ -n "$juno_txsign_signer_keys" ]]; then
    printf 'JUNO_TXSIGN_SIGNER_KEYS=%s\n' "$juno_txsign_signer_keys" >>"$output_file"
  fi
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
  deposit_scan_wallet_id="$(production_env_first_value "$resolved_secret_env" WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID WITHDRAW_COORDINATOR_JUNO_WALLET_ID || true)"
  if [[ -n "$deposit_scan_wallet_id" ]]; then
    printf 'DEPOSIT_SCAN_ENABLED=true\n' >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_SCAN_URL=http://127.0.0.1:8080\n' >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=%s\n' "$deposit_scan_wallet_id" >>"$output_file"
    printf 'DEPOSIT_SCAN_JUNO_RPC_URL=http://127.0.0.1:18232\n' >>"$output_file"
  fi

  if [[ "$signer_driver" == "aws-kms" ]]; then
    awk -F= '
      NR == FNR {
        if (index($0, "=") > 0) {
          seen[$1] = 1
        }
        next
      }
      $1 == "CHECKPOINT_SIGNER_PRIVATE_KEY" { next }
      !($1 in seen) { print }
    ' "$output_file" "$resolved_secret_env" >>"$output_file"
  else
    awk -F= '
      NR == FNR {
        if (index($0, "=") > 0) {
          seen[$1] = 1
        }
        next
      }
      !($1 in seen) { print }
    ' "$output_file" "$resolved_secret_env" >>"$output_file"
  fi

  local required_env_key
  for required_env_key in CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS; do
    grep -q "^${required_env_key}=" "$output_file" || die "rendered operator env is missing ${required_env_key}"
  done
}

production_render_bridge_api_env() {
  local shared_manifest="$1"
  local app_deploy="$2"
  local resolved_secret_env="$3"
  local output_file="$4"

  local postgres_dsn owallet_ua listen_addr refund_window_seconds min_deposit_amount min_withdraw_amount fee_bps
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations

  postgres_dsn="$(production_env_first_value "$resolved_secret_env" APP_POSTGRES_DSN CHECKPOINT_POSTGRES_DSN || true)"
  [[ -n "$postgres_dsn" ]] || die "resolved secret env is missing APP_POSTGRES_DSN or CHECKPOINT_POSTGRES_DSN"
  owallet_ua="$(production_json_required "$shared_manifest" '.contracts.owallet_ua | select(type == "string" and length > 0)')"
  listen_addr="$(production_json_required "$app_deploy" '.services.bridge_api.listen_addr | select(type == "string" and length > 0)')"
  refund_window_seconds="$(production_json_optional "$app_deploy" '.services.bridge_api.refund_window_seconds')"
  min_deposit_amount="$(production_json_optional "$app_deploy" '.services.bridge_api.min_deposit_amount')"
  min_withdraw_amount="$(production_json_optional "$app_deploy" '.services.bridge_api.min_withdraw_amount')"
  fee_bps="$(production_json_optional "$app_deploy" '.services.bridge_api.fee_bps')"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"

  cat >"$output_file" <<EOF
BRIDGE_API_LISTEN_ADDR=$listen_addr
BRIDGE_API_POSTGRES_DSN=$postgres_dsn
BRIDGE_API_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BRIDGE_API_BASE_CHAIN_ID=$(jq -r '.contracts.base_chain_id' "$shared_manifest")
BRIDGE_API_BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$shared_manifest")
BRIDGE_API_OWALLET_UA=$owallet_ua
BRIDGE_API_REFUND_WINDOW_SECONDS=${refund_window_seconds:-86400}
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

  local postgres_dsn auth_secret juno_rpc_url juno_rpc_user juno_rpc_pass
  local listen_addr operator_addresses service_urls operator_endpoints
  local base_relayer_signer_addresses base_relayer_gas_min_wei
  local runtime_deposit_min_confirmations runtime_withdraw_planner_min_confirmations runtime_withdraw_batch_confirmations
  local min_deposit_admin_private_key sp1_requestor_address sp1_rpc_url render_juno_rpc effective_juno_rpc_url

  postgres_dsn="$(production_env_first_value "$resolved_secret_env" APP_POSTGRES_DSN CHECKPOINT_POSTGRES_DSN || true)"
  [[ -n "$postgres_dsn" ]] || die "resolved secret env is missing APP_POSTGRES_DSN or CHECKPOINT_POSTGRES_DSN"
  auth_secret="$(production_env_first_value "$resolved_secret_env" BACKOFFICE_AUTH_SECRET APP_BACKOFFICE_AUTH_SECRET || true)"
  [[ -n "$auth_secret" ]] || die "resolved secret env is missing BACKOFFICE_AUTH_SECRET or APP_BACKOFFICE_AUTH_SECRET"
  juno_rpc_url="$(production_json_optional "$app_deploy" '.juno_rpc_url')"
  juno_rpc_user="$(production_env_first_value "$resolved_secret_env" JUNO_RPC_USER APP_JUNO_RPC_USER || true)"
  juno_rpc_pass="$(production_env_first_value "$resolved_secret_env" JUNO_RPC_PASS APP_JUNO_RPC_PASS || true)"
  listen_addr="$(production_json_required "$app_deploy" '.services.backoffice.listen_addr | select(type == "string" and length > 0)')"
  operator_addresses="$(jq -r '.operator_addresses | join(",")' "$app_deploy")"
  service_urls="$(jq -r '.service_urls | join(",")' "$app_deploy")"
  operator_endpoints="$(jq -r '.operator_endpoints | join(",")' "$app_deploy")"
  base_relayer_signer_addresses="$(production_backoffice_relayer_signer_addresses_csv "$app_deploy")"
  base_relayer_gas_min_wei="$(production_required_min_base_relayer_balance_wei)"
  runtime_deposit_min_confirmations="$(production_default_deposit_min_confirmations)"
  runtime_withdraw_planner_min_confirmations="$(production_default_withdraw_planner_min_confirmations)"
  runtime_withdraw_batch_confirmations="$(production_default_withdraw_batch_confirmations)"
  min_deposit_admin_private_key="$(production_env_first_value "$resolved_secret_env" MIN_DEPOSIT_ADMIN_PRIVATE_KEY APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY || true)"
  sp1_requestor_address="$(production_json_optional "$shared_manifest" '.shared_services.proof.requestor_address')"
  sp1_rpc_url="$(production_json_optional "$shared_manifest" '.shared_services.proof.rpc_url')"
  render_juno_rpc="false"
  effective_juno_rpc_url="$juno_rpc_url"
  production_json_required "$shared_manifest" '.contracts.wjuno | select(type == "string" and length > 0)' >/dev/null
  production_json_required "$shared_manifest" '.contracts.operator_registry | select(type == "string" and length > 0)' >/dev/null

  cat >"$output_file" <<EOF
BACKOFFICE_LISTEN_ADDR=$listen_addr
BACKOFFICE_POSTGRES_DSN=$postgres_dsn
BACKOFFICE_BASE_RPC_URL=$(jq -r '.contracts.base_rpc_url' "$shared_manifest")
BACKOFFICE_AUTH_SECRET=$auth_secret
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
EOF

  if [[ -n "$sp1_requestor_address" ]]; then
    printf 'BACKOFFICE_SP1_REQUESTOR_ADDRESS=%s\n' "$sp1_requestor_address" >>"$output_file"
  fi
  if [[ -n "$sp1_rpc_url" ]]; then
    printf 'BACKOFFICE_SP1_RPC_URL=%s\n' "$sp1_rpc_url" >>"$output_file"
  fi
  if [[ -n "$effective_juno_rpc_url" && "$effective_juno_rpc_url" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:|/|$) ]]; then
    effective_juno_rpc_url=""
  fi
  if [[ -n "$effective_juno_rpc_url" ]]; then
    render_juno_rpc="true"
    printf 'BACKOFFICE_JUNO_RPC_URL=%s\n' "$effective_juno_rpc_url" >>"$output_file"
  fi
  local fee_distributor
  fee_distributor="$(production_json_optional "$shared_manifest" '.contracts.fee_distributor')"
  if [[ -n "$fee_distributor" ]]; then
    printf 'BACKOFFICE_FEE_DISTRIBUTOR_ADDRESS=%s\n' "$fee_distributor" >>"$output_file"
  fi
  if [[ "$render_juno_rpc" == "true" && -n "$juno_rpc_user" ]]; then
    printf 'BACKOFFICE_JUNO_RPC_USER=%s\n' "$juno_rpc_user" >>"$output_file"
  fi
  if [[ "$render_juno_rpc" == "true" && -n "$juno_rpc_pass" ]]; then
    printf 'BACKOFFICE_JUNO_RPC_PASS=%s\n' "$juno_rpc_pass" >>"$output_file"
  fi
  if [[ -n "$service_urls" ]]; then
    printf 'BACKOFFICE_SERVICE_URLS=%s\n' "$service_urls" >>"$output_file"
  fi
  if [[ -n "$operator_endpoints" ]]; then
    printf 'BACKOFFICE_OPERATOR_ENDPOINTS=%s\n' "$operator_endpoints" >>"$output_file"
  fi
  if [[ -n "$min_deposit_admin_private_key" ]]; then
    printf 'MIN_DEPOSIT_ADMIN_PRIVATE_KEY=%s\n' "$min_deposit_admin_private_key" >>"$output_file"
  fi
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
    printf 'txunpaidactionlimit=10000\n'
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
