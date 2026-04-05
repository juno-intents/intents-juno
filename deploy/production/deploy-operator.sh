#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  deploy-operator.sh [options]

Options:
  --operator-deploy PATH      Operator deploy manifest (required)
  --dkg-tls-dir PATH          Override DKG coordinator TLS dir from manifest
  --force                     Redeploy even when rollout-state already marks this operator done
  --dry-run                   Print actions without mutating remote state
EOF
}

operator_deploy=""
dkg_tls_dir_override=""
force="false"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
    --dkg-tls-dir) dkg_tls_dir_override="$2"; shift 2 ;;
    --force) force="true"; shift ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$operator_deploy" ]] || die "--operator-deploy is required"
[[ -f "$operator_deploy" ]] || die "operator deploy manifest not found: $operator_deploy"

manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
using_runtime_material_ref="false"
if production_operator_uses_runtime_material_ref "$operator_deploy"; then
  using_runtime_material_ref="true"
fi
for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
have_cmd aws || die "required command not found: aws"
[[ "$using_runtime_material_ref" == "true" ]] || die "operator deploy manifest must set runtime_material_ref.mode=s3-kms-zip when environment=$environment"

shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
base_chain_id="$(production_json_required "$shared_manifest_path" '.contracts.base_chain_id')"
base_rpc_url="$(production_json_required "$shared_manifest_path" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
bridge_address="$(production_json_required "$shared_manifest_path" '.contracts.bridge | select(type == "string" and length > 0)')"
peer_manifests_dir="$(cd "$manifest_dir/.." && pwd)"
[[ -d "$peer_manifests_dir" ]] || die "peer operator manifests directory not found: $peer_manifests_dir"

rollout_state_file="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.rollout_state_file | select(type == "string" and length > 0)')")"
[[ -f "$rollout_state_file" ]] || die "rollout state file not found: $rollout_state_file"

operator_id="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
operator_user="$(production_json_required "$operator_deploy" '.operator_user | select(type == "string" and length > 0)')"
runtime_dir="$(production_json_required "$operator_deploy" '.runtime_dir | select(type == "string" and length > 0)')"
aws_profile="$(production_json_optional "$operator_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"
runtime_material_bucket=""
runtime_material_key=""
runtime_material_region=""
runtime_material_kms_key_id=""
runtime_config_secret_id=""
runtime_config_secret_region=""
[[ -n "$aws_profile" ]] || die "operator deploy manifest is missing aws_profile for runtime_material_ref rollout"
[[ -n "$aws_region" ]] || die "operator deploy manifest is missing aws_region for runtime_material_ref rollout"
runtime_material_bucket="$(production_runtime_material_ref_field "$operator_deploy" 'bucket')"
runtime_material_key="$(production_runtime_material_ref_field "$operator_deploy" 'key')"
runtime_material_region="$(production_runtime_material_ref_field "$operator_deploy" 'region')"
runtime_material_kms_key_id="$(production_runtime_material_ref_field "$operator_deploy" 'kms_key_id')"
runtime_config_secret_id="$(production_json_required "$operator_deploy" '.runtime_config_secret_id | select(type == "string" and length > 0)')"
runtime_config_secret_region="$(production_json_optional "$operator_deploy" '.runtime_config_secret_region')"
if [[ -z "$runtime_config_secret_region" ]]; then
  runtime_config_secret_region="${runtime_material_region:-$aws_region}"
fi
[[ -n "$runtime_material_bucket" ]] || die "operator deploy manifest is missing runtime_material_ref.bucket"
[[ -n "$runtime_material_key" ]] || die "operator deploy manifest is missing runtime_material_ref.key"
[[ -n "$runtime_material_region" ]] || die "operator deploy manifest is missing runtime_material_ref.region"
[[ -n "$runtime_material_kms_key_id" ]] || die "operator deploy manifest is missing runtime_material_ref.kms_key_id"
[[ -n "$runtime_config_secret_region" ]] || die "operator deploy manifest is missing runtime_config_secret_region"
dkg_tls_dir="$dkg_tls_dir_override"
if [[ -z "$dkg_tls_dir" ]]; then
  dkg_tls_dir="$(production_json_optional "$operator_deploy" '.dkg_tls_dir')"
fi
if [[ -n "$dkg_tls_dir" ]]; then
  dkg_tls_dir="$(production_abs_path "$manifest_dir" "$dkg_tls_dir")"
  [[ -d "$dkg_tls_dir" ]] || die "dkg tls dir not found: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/ca.pem" ]] || die "dkg tls dir missing ca.pem: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/ca.key" ]] || die "dkg tls dir missing ca.key: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/coordinator-client.pem" ]] || die "dkg tls dir missing coordinator-client.pem: $dkg_tls_dir"
  [[ -f "$dkg_tls_dir/coordinator-client.key" ]] || die "dkg tls dir missing coordinator-client.key: $dkg_tls_dir"
fi

public_endpoint="$(production_json_optional "$operator_deploy" '.public_endpoint')"
dns_mode="$(production_json_optional "$operator_deploy" '.dns.mode')"
dns_zone_id="$(production_json_optional "$operator_deploy" '.dns.zone_id')"
dns_record_name="$(production_json_optional "$operator_deploy" '.dns.record_name')"
dns_ttl="$(production_json_optional "$operator_deploy" '.dns.ttl_seconds')"

current_status="$(jq -r --arg operator_id "$operator_id" '.operators[] | select(.operator_id == $operator_id) | .status' "$rollout_state_file")"
if [[ "$current_status" == "done" ]]; then
  if [[ "$force" == "true" ]]; then
    log "operator $operator_id already marked done in rollout state; forcing redeploy"
  else
    log "operator $operator_id already marked done in rollout state"
    exit 0
  fi
fi

instance_id=""
service_active_retries="${PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES:-20}"
service_active_sleep_seconds="${PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS:-2}"

tmp_dir="$(mktemp -d)"
merged_env="$tmp_dir/operator-stack.env"
config_hydrator_stage="$tmp_dir/intents-juno-config-hydrator.sh"
operator_stack_hydrator_env="$tmp_dir/operator-stack-hydrator.env"
signer_ufvk_file="$tmp_dir/ufvk.txt"
dkg_peer_hosts_file="$tmp_dir/dkg-peer-hosts.json"
run_operator_rollout_stage="$tmp_dir/run-operator-rollout.sh"
generated_base_relayer_tls_files=()
generated_dkg_server_tls_files=()
staged_dkg_tls_files=()
staged_wrapper_scripts=()
success="false"
reserved="false"

env_has_key() {
  local file="$1"
  local key="$2"
  grep -q "^${key}=" "$file"
}

env_get_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' "$file"
}

set_env_value_local() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    { print }
    END {
      if (updated == 0) {
        print key "=" value
      }
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

delete_env_key_local() {
  local file="$1"
  local key="$2"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" 'index($0, key "=") != 1 { print }' "$file" >"$tmp"
  mv "$tmp" "$file"
}

extract_build_runbook_block() {
  local source_file="$1"
  local start_marker="$2"
  local end_marker="$3"
  local output_file="$4"

  awk -v start_marker="$start_marker" -v end_marker="$end_marker" '
    index($0, start_marker) > 0 {
      capture = 1
      next
    }
    capture && $0 == end_marker {
      exit
    }
    capture {
      print
    }
  ' "$source_file" >"$output_file"

  [[ -s "$output_file" ]] || die "failed to extract embedded block from $source_file"
}

append_unique_san_entry() {
  local entry="$1"
  shift
  local existing
  for existing in "$@"; do
    [[ "$existing" == "$entry" ]] && return 0
  done
  printf '%s\n' "$entry"
}

append_host_san_entries() {
  local host="$1"
  [[ -n "$host" ]] || return 0
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf 'IP:%s\n' "$host"
  else
    printf 'DNS:%s\n' "$host"
  fi
}

aws_resolve_private_ip() {
  local profile="$1"
  local region="$2"
  local host="$3"
  local query='Reservations[].Instances[].PrivateIpAddress'
  local result=""

  if ! have_cmd aws; then
    printf '%s\n' "$host"
    return 0
  fi

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=ip-address,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
    if [[ -z "$result" || "$result" == "None" ]]; then
      result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
        --filters "Name=private-ip-address,Values=$host" \
        --query "$query" --output text 2>/dev/null || true)"
    fi
  else
    result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=dns-name,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
  fi

  if [[ -n "$result" && "$result" != "None" ]]; then
    printf '%s\n' "$result"
  else
    printf '%s\n' "$host"
  fi
}

aws_describe_instance_field() {
  local profile="$1"
  local region="$2"
  local host="$3"
  local query="$4"
  local result=""

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=ip-address,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
    if [[ -z "$result" || "$result" == "None" ]]; then
      result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
        --filters "Name=private-ip-address,Values=$host" \
        --query "$query" --output text 2>/dev/null || true)"
    fi
  else
    result="$(aws --profile "$profile" --region "$region" ec2 describe-instances \
      --filters "Name=dns-name,Values=$host" \
      --query "$query" --output text 2>/dev/null || true)"
  fi

  if [[ -n "$result" && "$result" != "None" ]]; then
    printf '%s\n' "$result"
  fi
}

resolve_dkg_peer_host_from_manifest() {
  local manifest="$1"
  local private_host host profile region
  private_host="$(jq -r '(.private_endpoint // .operator_probe_host) // empty' "$manifest")"
  if [[ -n "$private_host" ]]; then
    printf '%s\n' "$private_host"
    return 0
  fi
  host="$(jq -r '(.operator_host // .public_endpoint) // empty' "$manifest")"
  [[ -n "$host" ]] || die "peer operator manifest missing operator_host/public_endpoint: $manifest"
  profile="$(jq -r '.aws_profile // empty' "$manifest")"
  region="$(jq -r '.aws_region // empty' "$manifest")"
  if [[ -n "$profile" && -n "$region" ]]; then
    aws_resolve_private_ip "$profile" "$region" "$host"
    return 0
  fi
  printf '%s\n' "$host"
}

ensure_operator_grpc_mesh_ingress() {
  local profile="$1"
  local region="$2"
  local host="$3"
  local group_ids group_id

  [[ -n "$profile" && -n "$region" ]] || return 0
  have_cmd aws || return 0

  group_ids="$(aws_describe_instance_field "$profile" "$region" "$host" 'Reservations[].Instances[].SecurityGroups[].GroupId')"
  [[ -n "$group_ids" ]] || return 0

  for group_id in $group_ids; do
    aws --profile "$profile" --region "$region" ec2 authorize-security-group-ingress \
      --group-id "$group_id" \
      --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":18443,\"ToPort\":18447,\"UserIdGroupPairs\":[{\"GroupId\":\"$group_id\",\"Description\":\"Operator distributed DKG peer traffic\"}]}]" \
      >/dev/null 2>&1 || true
  done
}

generate_dkg_server_tls() {
  local tls_dir="$1"
  local resolved_host="$2"
  local original_host="$3"
  local public_host="$4"
  local out_cert="$5"
  local out_key="$6"
  local tmp_cert_dir="$tmp_dir/dkg-server-tls"
  local csr_path="$tmp_cert_dir/server.csr"
  local ext_path="$tmp_cert_dir/server.ext"
  local serial_path="$tmp_cert_dir/ca.srl"
  local -a san_entries=()
  local candidate

  [[ -d "$tls_dir" ]] || die "dkg tls dir not found: $tls_dir"
  [[ -f "$tls_dir/ca.pem" ]] || die "dkg tls dir missing ca.pem: $tls_dir"
  [[ -f "$tls_dir/ca.key" ]] || die "dkg tls dir missing ca.key: $tls_dir"
  have_cmd openssl || die "required command not found: openssl"

  mkdir -p "$tmp_cert_dir"
  san_entries=("DNS:localhost" "IP:127.0.0.1")
  for candidate in "$resolved_host" "$original_host" "$public_host"; do
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      if ! printf '%s\n' "${san_entries[@]}" | grep -Fxq "$entry"; then
        san_entries+=("$entry")
      fi
    done < <(append_host_san_entries "$candidate")
  done

  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage = digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage = serverAuth\n'
    printf 'subjectAltName='
    local first="true"
    for entry in "${san_entries[@]}"; do
      if [[ "$first" == "true" ]]; then
        printf '%s' "$entry"
        first="false"
      else
        printf ',%s' "$entry"
      fi
    done
    printf '\n'
  } >"$ext_path"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$out_key" \
    -out "$csr_path" \
    -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req \
    -in "$csr_path" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tls_dir/ca.key" \
    -CAserial "$serial_path" \
    -CAcreateserial \
    -out "$out_cert" \
    -days 365 \
    -sha256 \
    -extfile "$ext_path" >/dev/null 2>&1
  chmod 0600 "$out_key"
}

wait_for_remote_service_active() {
  local svc="$1"
  local status=""
  local attempt
  for ((attempt = 1; attempt <= service_active_retries; attempt++)); do
    status="$(production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "sudo systemctl is-active $svc 2>/dev/null || echo inactive" 2>/dev/null || printf 'inactive')"
    status="${status//$'\r'/}"
    status="${status//$'\n'/}"
    if [[ "$status" == "active" ]]; then
      return 0
    fi
    if (( attempt < service_active_retries )); then
      sleep "$service_active_sleep_seconds"
    fi
  done
  die "service $svc did not become active on $operator_host (last status: ${status:-unknown})"
}

remote_juno_scan_post() {
  local scan_url="$1"
  local path="$2"
  local payload="$3"
  local bearer_token="$4"
  local payload_b64
  local bearer_token_b64
  local remote_cmd
  payload_b64="$(printf '%s' "$payload" | base64 | tr -d '\n')"
  bearer_token_b64="$(printf '%s' "$bearer_token" | base64 | tr -d '\n')"
  remote_cmd="$(cat <<EOF
set -euo pipefail
scan_url="$scan_url"
path="$path"
payload_b64="$payload_b64"
bearer_token_b64="$bearer_token_b64"

if payload="\$(printf '%s' "\$payload_b64" | base64 --decode 2>/dev/null)"; then
  :
else
  payload="\$(printf '%s' "\$payload_b64" | base64 -D)"
fi
if [[ -n "\$bearer_token_b64" ]]; then
  if bearer_token="\$(printf '%s' "\$bearer_token_b64" | base64 --decode 2>/dev/null)"; then
    :
  else
    bearer_token="\$(printf '%s' "\$bearer_token_b64" | base64 -D)"
  fi
else
  bearer_token=""
fi

curl_headers=()
if [[ -n "\$bearer_token" ]]; then
  curl_headers=(-H "Authorization: Bearer \$bearer_token")
fi

curl -fsS -X POST "\${curl_headers[@]}" -H "Content-Type: application/json" --data "\$payload" "\${scan_url%/}\${path}"
EOF
)"
  production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "$remote_cmd" >/dev/null
}

remote_juno_scan_get() {
  local scan_url="$1"
  local path="$2"
  local bearer_token="$3"
  local bearer_token_b64
  local remote_cmd
  bearer_token_b64="$(printf '%s' "$bearer_token" | base64 | tr -d '\n')"
  remote_cmd="$(cat <<EOF
set -euo pipefail
scan_url="$scan_url"
path="$path"
bearer_token_b64="$bearer_token_b64"

if [[ -n "\$bearer_token_b64" ]]; then
  if bearer_token="\$(printf '%s' "\$bearer_token_b64" | base64 --decode 2>/dev/null)"; then
    :
  else
    bearer_token="\$(printf '%s' "\$bearer_token_b64" | base64 -D)"
  fi
else
  bearer_token=""
fi

curl_headers=()
if [[ -n "\$bearer_token" ]]; then
  curl_headers=(-H "Authorization: Bearer \$bearer_token")
fi

curl -fsS "\${curl_headers[@]}" "\${scan_url%/}\${path}"
EOF
)"
  production_ssm_run_shell_command "$aws_profile" "$aws_region" "$instance_id" "$remote_cmd"
}

wait_for_remote_juno_scan_tip() {
  local scan_url="$1"
  local bearer_token="$2"
  local attempt health_response
  for ((attempt = 1; attempt <= service_active_retries; attempt++)); do
    health_response="$(remote_juno_scan_get "$scan_url" "/v1/health" "$bearer_token" 2>/dev/null || true)"
    if [[ -n "$health_response" ]] && jq -e '.status == "ok" and ((.scanned_height | type) == "number")' >/dev/null <<<"$health_response"; then
      return 0
    fi
    if (( attempt < service_active_retries )); then
      sleep "$service_active_sleep_seconds"
    fi
  done
  die "juno-scan did not report a scanned tip on $operator_host"
}

start_remote_scan_wallet_backfill() {
  local scan_url="$1"
  local bearer_token="$2"

  wait_for_remote_juno_scan_tip "$scan_url" "$bearer_token"
  production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "sudo systemctl reset-failed juno-scan-backfill.service || true && sudo systemctl start --no-block juno-scan-backfill.service" >/dev/null
}

derive_base_relayer_allowlist() {
  local shared_manifest="$1"
  jq -r '
    [
      .contracts.bridge,
      .contracts.wjuno,
      .contracts.operator_registry,
      .contracts.fee_distributor
    ]
    | map(select(type == "string" and test("^0x[0-9a-fA-F]{40}$")))
    | unique
    | join(",")
  ' "$shared_manifest"
}

derive_base_relayer_selector_allowlist() {
  printf '0x53a58a48,0xec70b605,0xfe097d57\n'
}

derive_base_relayer_url() {
  local listen_addr="$1"
  local scheme="$2"
  if [[ "$listen_addr" == :* ]]; then
    printf '%s://127.0.0.1%s\n' "$scheme" "$listen_addr"
    return 0
  fi
  printf '%s://%s\n' "$scheme" "$listen_addr"
}

decode_base64_to_file() {
  local value="$1"
  local output_file="$2"
  if printf '%s' "$value" | base64 --decode >"$output_file" 2>/dev/null; then
    return 0
  fi
  printf '%s' "$value" | base64 -D >"$output_file"
}

prepare_base_relayer_env() {
  local shared_manifest="$1"
  local env_file="$2"
  local staging_dir="$3"
  local cert_b64 key_b64 cert_file key_file listen_addr scheme allowlist selector_allowlist

  if ! env_has_key "$env_file" "BASE_RELAYER_LISTEN_ADDR"; then
    set_env_value_local "$env_file" "BASE_RELAYER_LISTEN_ADDR" "127.0.0.1:18081"
  fi
  listen_addr="$(env_get_value "$env_file" "BASE_RELAYER_LISTEN_ADDR")"
  if [[ -z "$listen_addr" ]]; then
    listen_addr="127.0.0.1:18081"
    set_env_value_local "$env_file" "BASE_RELAYER_LISTEN_ADDR" "$listen_addr"
  fi

  if ! env_has_key "$env_file" "BASE_RELAYER_ALLOWED_CONTRACTS"; then
    allowlist="$(derive_base_relayer_allowlist "$shared_manifest")"
    if [[ -n "$allowlist" ]]; then
      set_env_value_local "$env_file" "BASE_RELAYER_ALLOWED_CONTRACTS" "$allowlist"
    fi
  fi
  if ! env_has_key "$env_file" "BASE_RELAYER_ALLOWED_SELECTORS"; then
    selector_allowlist="$(derive_base_relayer_selector_allowlist)"
    if [[ -n "$selector_allowlist" ]]; then
      set_env_value_local "$env_file" "BASE_RELAYER_ALLOWED_SELECTORS" "$selector_allowlist"
    fi
  fi
  if ! env_has_key "$env_file" "BASE_RELAYER_RATE_LIMIT_PER_SECOND"; then
    set_env_value_local "$env_file" "BASE_RELAYER_RATE_LIMIT_PER_SECOND" "20"
  fi
  if ! env_has_key "$env_file" "BASE_RELAYER_RATE_LIMIT_BURST"; then
    set_env_value_local "$env_file" "BASE_RELAYER_RATE_LIMIT_BURST" "40"
  fi
  if ! env_has_key "$env_file" "BASE_RELAYER_RATE_LIMIT_MAX_TRACKED_CLIENTS"; then
    set_env_value_local "$env_file" "BASE_RELAYER_RATE_LIMIT_MAX_TRACKED_CLIENTS" "10000"
  fi

  cert_b64="$(env_get_value "$env_file" "BASE_RELAYER_TLS_CERT_PEM_B64")"
  key_b64="$(env_get_value "$env_file" "BASE_RELAYER_TLS_KEY_PEM_B64")"
  if [[ -n "$cert_b64" || -n "$key_b64" ]]; then
    [[ -n "$cert_b64" && -n "$key_b64" ]] || die "BASE_RELAYER_TLS_CERT_PEM_B64 and BASE_RELAYER_TLS_KEY_PEM_B64 must be set together"
    cert_file="$staging_dir/base-relayer-server.pem"
    key_file="$staging_dir/base-relayer-server.key"
    decode_base64_to_file "$cert_b64" "$cert_file"
    decode_base64_to_file "$key_b64" "$key_file"
    chmod 0600 "$key_file"
    generated_base_relayer_tls_files=("$cert_file" "$key_file")
    set_env_value_local "$env_file" "BASE_RELAYER_TLS_CERT_FILE" "/etc/intents-juno/base-relayer/server.pem"
    set_env_value_local "$env_file" "BASE_RELAYER_TLS_KEY_FILE" "/etc/intents-juno/base-relayer/server.key"
    delete_env_key_local "$env_file" "BASE_RELAYER_TLS_CERT_PEM_B64"
    delete_env_key_local "$env_file" "BASE_RELAYER_TLS_KEY_PEM_B64"
  fi

  cert_file="$(env_get_value "$env_file" "BASE_RELAYER_TLS_CERT_FILE")"
  key_file="$(env_get_value "$env_file" "BASE_RELAYER_TLS_KEY_FILE")"
  if [[ -n "$cert_file" || -n "$key_file" ]]; then
    [[ -n "$cert_file" && -n "$key_file" ]] || die "BASE_RELAYER_TLS_CERT_FILE and BASE_RELAYER_TLS_KEY_FILE must be set together"
    scheme="https"
  else
    scheme="http"
  fi

  if ! env_has_key "$env_file" "BASE_RELAYER_URL"; then
    set_env_value_local "$env_file" "BASE_RELAYER_URL" "$(derive_base_relayer_url "$listen_addr" "$scheme")"
  fi
}

cleanup() {
  if [[ "$dry_run" != "true" && "$reserved" == "true" && "$success" != "true" ]]; then
    production_rollout_complete "$rollout_state_file" "$operator_id" "failed" "remote deployment failed"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

: >"$tmp_dir/operator-secrets.resolved.env"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
production_render_operator_stack_env "$shared_manifest_path" "$operator_deploy" "$resolved_secret_env" "$merged_env"
if env_has_key "$merged_env" "CHECKPOINT_SIGNER_PRIVATE_KEY"; then
  die "deploy-operator rendered CHECKPOINT_SIGNER_PRIVATE_KEY; plaintext operator key configuration is dev/test-only"
fi
cat >"$operator_stack_hydrator_env" <<EOF
OPERATOR_STACK_CONFIG_JSON_PATH=/etc/intents-juno/operator-stack-config.json
OPERATOR_STACK_CONFIG_SECRET_ID=$runtime_config_secret_id
OPERATOR_STACK_CONFIG_SECRET_REGION=$runtime_config_secret_region
EOF
extract_build_runbook_block \
  "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh" \
  "cat > /tmp/intents-juno-config-hydrator.sh <<'EOF_CONFIG_HYDRATOR'" \
  "EOF_CONFIG_HYDRATOR" \
  "$config_hydrator_stage"
for wrapper_name in \
  intents-juno-checkpoint-signer.sh \
  intents-juno-checkpoint-aggregator.sh \
  intents-juno-deposit-relayer.sh \
  intents-juno-multikey-extend-signer.sh \
  intents-juno-withdraw-coordinator.sh \
  intents-juno-withdraw-finalizer.sh \
  intents-juno-base-event-scanner.sh; do
  wrapper_stage="$tmp_dir/$wrapper_name"
  case "$wrapper_name" in
    intents-juno-checkpoint-signer.sh)
      wrapper_start="cat > /tmp/intents-juno-checkpoint-signer.sh <<'EOF_SIGNER'"
      wrapper_end="EOF_SIGNER"
      ;;
    intents-juno-checkpoint-aggregator.sh)
      wrapper_start="cat > /tmp/intents-juno-checkpoint-aggregator.sh <<'EOF_AGG'"
      wrapper_end="EOF_AGG"
      ;;
    intents-juno-deposit-relayer.sh)
      wrapper_start="cat > /tmp/intents-juno-deposit-relayer.sh <<'EOF_DEPOSIT_RELAYER'"
      wrapper_end="EOF_DEPOSIT_RELAYER"
      ;;
    intents-juno-multikey-extend-signer.sh)
      wrapper_start="cat > /tmp/intents-juno-multikey-extend-signer.sh <<'EOF_WITHDRAW_EXTEND_SIGNER'"
      wrapper_end="EOF_WITHDRAW_EXTEND_SIGNER"
      ;;
    intents-juno-withdraw-coordinator.sh)
      wrapper_start="cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'"
      wrapper_end="EOF_WITHDRAW_COORDINATOR"
      ;;
    intents-juno-withdraw-finalizer.sh)
      wrapper_start="cat > /tmp/intents-juno-withdraw-finalizer.sh <<'EOF_WITHDRAW_FINALIZER'"
      wrapper_end="EOF_WITHDRAW_FINALIZER"
      ;;
    intents-juno-base-event-scanner.sh)
      wrapper_start="cat > /tmp/intents-juno-base-event-scanner.sh <<'EOF_BASE_EVENT_SCANNER'"
      wrapper_end="EOF_BASE_EVENT_SCANNER"
      ;;
  esac
  extract_build_runbook_block \
    "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh" \
    "$wrapper_start" \
    "$wrapper_end" \
    "$wrapper_stage"
  chmod 0755 "$wrapper_stage"
  staged_wrapper_scripts+=("$wrapper_stage")
done
case "$environment" in
  mainnet)
    sed -i.bak 's/__BOOTSTRAP_JUNOCASHD_TESTNET_LINE__//g' "$config_hydrator_stage"
    ;;
  *)
    sed -i.bak 's/__BOOTSTRAP_JUNOCASHD_TESTNET_LINE__/testnet=1/g' "$config_hydrator_stage"
    ;;
esac
rm -f "$config_hydrator_stage.bak"
chmod 0755 "$config_hydrator_stage"
prepare_base_relayer_env "$shared_manifest_path" "$merged_env" "$tmp_dir"
printf '%s\n' "$(production_json_required "$shared_manifest_path" '.checkpoint.signer_ufvk | select(type == "string" and length > 0)')" >"$signer_ufvk_file"
mapfile -t peer_operator_manifests < <(find "$peer_manifests_dir" -mindepth 2 -maxdepth 2 -name operator-deploy.json -print | sort)
(( ${#peer_operator_manifests[@]} > 0 )) || die "no peer operator manifests found under $peer_manifests_dir"
peer_hosts_jsonl="$tmp_dir/dkg-peer-hosts.jsonl"
: >"$peer_hosts_jsonl"
for peer_manifest in "${peer_operator_manifests[@]}"; do
  peer_operator_id="$(jq -r '.operator_id // empty' "$peer_manifest")"
  [[ -n "$peer_operator_id" ]] || die "peer operator manifest missing operator_id: $peer_manifest"
  peer_host="$(resolve_dkg_peer_host_from_manifest "$peer_manifest")"
  jq -n \
    --arg operator_id "$peer_operator_id" \
    --arg host "$peer_host" \
    '{operator_id: $operator_id, host: $host}' >>"$peer_hosts_jsonl"
done
jq -s 'sort_by(.operator_id)' "$peer_hosts_jsonl" >"$dkg_peer_hosts_file"
resolved_withdraw_tss_server_name="$(jq -r --arg operator_id "$operator_id" '.[] | select(.operator_id == $operator_id) | .host // empty' "$dkg_peer_hosts_file")"
if [[ -n "$resolved_withdraw_tss_server_name" ]]; then
  set_env_value_local "$merged_env" "WITHDRAW_COORDINATOR_TSS_SERVER_NAME" "$resolved_withdraw_tss_server_name"
fi
set_env_value_local "$merged_env" "JUNO_SCAN_BACKFILL_FROM_HEIGHT" "${PRODUCTION_DEPLOY_SCAN_BACKFILL_FROM_HEIGHT:-0}"
cp "$SCRIPT_DIR/run-operator-rollout.sh" "$run_operator_rollout_stage"
chmod 0755 "$run_operator_rollout_stage"

if [[ -n "$dkg_tls_dir" ]]; then
  resolved_operator_host="$(jq -r --arg operator_id "$operator_id" '.[] | select(.operator_id == $operator_id) | .host' "$dkg_peer_hosts_file")"
  [[ -n "$resolved_operator_host" && "$resolved_operator_host" != "null" ]] || die "missing resolved dkg peer host for operator_id $operator_id"
  dkg_server_cert_file="$tmp_dir/dkg-server.pem"
  dkg_server_key_file="$tmp_dir/dkg-server.key"
  generate_dkg_server_tls "$dkg_tls_dir" "$resolved_operator_host" "$operator_host" "$public_endpoint" "$dkg_server_cert_file" "$dkg_server_key_file"
  generated_dkg_server_tls_files=("$dkg_server_cert_file" "$dkg_server_key_file")
  staged_dkg_tls_files=(
    "$dkg_tls_dir/ca.pem"
    "$dkg_tls_dir/coordinator-client.pem"
    "$dkg_tls_dir/coordinator-client.key"
  )
fi

remote_stage_dir="/tmp/intents-juno-deploy-$(production_safe_slug "$operator_id")"
files_to_copy=(
  "$merged_env"
  "$config_hydrator_stage"
  "$operator_stack_hydrator_env"
  "$signer_ufvk_file"
  "$dkg_peer_hosts_file"
  "$shared_manifest_path"
  "$operator_deploy"
  "$run_operator_rollout_stage"
  "$REPO_ROOT/deploy/operators/dkg/backup-package.sh"
  "$REPO_ROOT/deploy/operators/dkg/common.sh"
)
for tls_file in "${generated_base_relayer_tls_files[@]}"; do
  files_to_copy+=("$tls_file")
done
for tls_file in "${generated_dkg_server_tls_files[@]}"; do
  files_to_copy+=("$tls_file")
done
for tls_file in "${staged_dkg_tls_files[@]}"; do
  files_to_copy+=("$tls_file")
done
for wrapper_stage in "${staged_wrapper_scripts[@]}"; do
  files_to_copy+=("$wrapper_stage")
done

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would deploy operator $operator_id via ssm/$operator_host"
else
  production_require_registered_operator "$shared_manifest_path" "$operator_deploy"
  ensure_operator_grpc_mesh_ingress "$aws_profile" "$aws_region" "$operator_host"
  production_rollout_reserve "$rollout_state_file" "$operator_id"
  reserved="true"
  instance_id="$(production_resolve_instance_id_from_host "$aws_profile" "$aws_region" "$operator_host")"
  production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "sudo rm -rf '$remote_stage_dir' && sudo install -d -m 0755 '$remote_stage_dir'" >/dev/null \
    || die "failed to create remote stage dir over ssm: $remote_stage_dir"
  for source_path in "${files_to_copy[@]}"; do
    file_mode="0640"
    case "$(basename "$source_path")" in
      *.sh)
        file_mode="0755"
        ;;
      *.key|ufvk.txt|operator-stack-hydrator.env)
        file_mode="0600"
        ;;
    esac
    production_ssm_stage_file "$aws_profile" "$aws_region" "$instance_id" "$source_path" "$remote_stage_dir/$(basename "$source_path")" "$file_mode"
  done
  production_ssm_run_shell_command \
    "$aws_profile" "$aws_region" "$instance_id" \
    "sudo bash -lc 'set -euo pipefail; cleanup(){ rm -rf \"$remote_stage_dir\"; }; trap cleanup EXIT; bash \"$remote_stage_dir/run-operator-rollout.sh\" --stage-dir \"$remote_stage_dir\" --runtime-dir \"$runtime_dir\"'" >/dev/null \
    || die "remote rollout failed over ssm for operator $operator_id"


  for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
    wait_for_remote_service_active "$svc"
  done
fi

if [[ "$dry_run" != "true" ]]; then
  scan_wallet_id="$(production_env_first_value "$merged_env" DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID WITHDRAW_COORDINATOR_JUNO_WALLET_ID || true)"
  scan_url="$(production_env_first_value "$merged_env" DEPOSIT_SCAN_JUNO_SCAN_URL WITHDRAW_FINALIZER_JUNO_SCAN_URL WITHDRAW_COORDINATOR_JUNO_SCAN_URL || true)"
  scan_bearer_token="$(production_env_first_value "$merged_env" JUNO_SCAN_BEARER_TOKEN || true)"
  if [[ -n "$scan_wallet_id" ]]; then
    [[ -n "$scan_url" ]] || die "rendered operator env is missing juno-scan URL for wallet $scan_wallet_id"
    start_remote_scan_wallet_backfill "$scan_url" "$scan_bearer_token"
  fi
fi

if production_dns_mode_uses_managed_public_zone "$dns_mode" && [[ -n "$dns_zone_id" && -n "$dns_record_name" && -n "$public_endpoint" ]]; then
  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would publish $dns_record_name -> $public_endpoint"
  else
    production_publish_dns_record "$aws_profile" "$aws_region" "$dns_zone_id" "$dns_record_name" "${dns_ttl:-60}" "$public_endpoint"
  fi
fi

if [[ "$dry_run" == "true" ]]; then
  success="true"
  log "[DRY RUN] operator deploy validated: $operator_id"
else
  production_rollout_complete "$rollout_state_file" "$operator_id" "done" "healthy"
  success="true"
  log "operator deployed: $operator_id"
fi
