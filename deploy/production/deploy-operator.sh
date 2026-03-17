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
  --known-hosts PATH          Override known_hosts path from manifest
  --secret-contract-file PATH Override operator-secrets.env path from manifest
  --force                     Redeploy even when rollout-state already marks this operator done
  --dry-run                   Print actions without mutating remote state
EOF
}

operator_deploy=""
dkg_tls_dir_override=""
known_hosts_override=""
secret_contract_override=""
force="false"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
    --dkg-tls-dir) dkg_tls_dir_override="$2"; shift 2 ;;
    --known-hosts) known_hosts_override="$2"; shift 2 ;;
    --secret-contract-file) secret_contract_override="$2"; shift 2 ;;
    --force) force="true"; shift ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$operator_deploy" ]] || die "--operator-deploy is required"
[[ -f "$operator_deploy" ]] || die "operator deploy manifest not found: $operator_deploy"
for cmd in jq ssh scp; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$environment"; then
  allow_local_resolvers="true"
fi

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
dkg_backup_zip="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.dkg_backup_zip | select(type == "string" and length > 0)')")"
[[ -f "$dkg_backup_zip" ]] || die "dkg backup zip not found: $dkg_backup_zip"
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

known_hosts_file="$known_hosts_override"
if [[ -z "$known_hosts_file" ]]; then
  known_hosts_file="$(production_json_required "$operator_deploy" '.known_hosts_file | select(type == "string" and length > 0)')"
fi
known_hosts_file="$(production_abs_path "$manifest_dir" "$known_hosts_file")"
[[ -f "$known_hosts_file" ]] || die "known_hosts file not found: $known_hosts_file"

secret_contract_file="$secret_contract_override"
if [[ -z "$secret_contract_file" ]]; then
  secret_contract_file="$(production_json_required "$operator_deploy" '.secret_contract_file | select(type == "string" and length > 0)')"
fi
secret_contract_file="$(production_abs_path "$manifest_dir" "$secret_contract_file")"
[[ -f "$secret_contract_file" ]] || die "secret contract file not found: $secret_contract_file"

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

ssh_target="${operator_user}@${operator_host}"
SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
SCP_OPTS=("${SSH_OPTS[@]}")
service_active_retries="${PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES:-20}"
service_active_sleep_seconds="${PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS:-2}"

tmp_dir="$(mktemp -d)"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
merged_env="$tmp_dir/operator-stack.env"
junocashd_conf="$tmp_dir/junocashd.conf"
config_hydrator_stage="$tmp_dir/intents-juno-config-hydrator.sh"
signer_ufvk_file="$tmp_dir/ufvk.txt"
dkg_peer_hosts_file="$tmp_dir/dkg-peer-hosts.json"
generated_base_relayer_tls_files=()
generated_dkg_server_tls_files=()
staged_dkg_tls_files=()
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
  local host profile region
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
    status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
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
  payload_b64="$(printf '%s' "$payload" | base64 | tr -d '\n')"
  bearer_token_b64="$(printf '%s' "$bearer_token" | base64 | tr -d '\n')"
  ssh "${SSH_OPTS[@]}" "$ssh_target" bash -s -- "$scan_url" "$path" "$payload_b64" "$bearer_token_b64" <<'REMOTE_EOF'
set -euo pipefail
scan_url="$1"
path="$2"
payload_b64="${3-}"
bearer_token_b64="${4-}"

if payload="$(printf '%s' "$payload_b64" | base64 --decode 2>/dev/null)"; then
  :
else
  payload="$(printf '%s' "$payload_b64" | base64 -D)"
fi
if [[ -n "$bearer_token_b64" ]]; then
  if bearer_token="$(printf '%s' "$bearer_token_b64" | base64 --decode 2>/dev/null)"; then
    :
  else
    bearer_token="$(printf '%s' "$bearer_token_b64" | base64 -D)"
  fi
else
  bearer_token=""
fi

curl_headers=()
if [[ -n "$bearer_token" ]]; then
  curl_headers=(-H "Authorization: Bearer $bearer_token")
fi

curl -fsS -X POST "${curl_headers[@]}" -H "Content-Type: application/json" --data "$payload" "${scan_url%/}${path}"
REMOTE_EOF
}

remote_juno_scan_get() {
  local scan_url="$1"
  local path="$2"
  local bearer_token="$3"
  local bearer_token_b64
  bearer_token_b64="$(printf '%s' "$bearer_token" | base64 | tr -d '\n')"
  ssh "${SSH_OPTS[@]}" "$ssh_target" bash -s -- "$scan_url" "$path" "$bearer_token_b64" <<'REMOTE_EOF'
set -euo pipefail
scan_url="$1"
path="$2"
bearer_token_b64="${3-}"

if [[ -n "$bearer_token_b64" ]]; then
  if bearer_token="$(printf '%s' "$bearer_token_b64" | base64 --decode 2>/dev/null)"; then
    :
  else
    bearer_token="$(printf '%s' "$bearer_token_b64" | base64 -D)"
  fi
else
  bearer_token=""
fi

curl_headers=()
if [[ -n "$bearer_token" ]]; then
  curl_headers=(-H "Authorization: Bearer $bearer_token")
fi

curl -fsS "${curl_headers[@]}" "${scan_url%/}${path}"
REMOTE_EOF
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

sync_remote_scan_wallet() {
  local scan_url="$1"
  local wallet_id="$2"
  local signer_ufvk="$3"
  local bearer_token="$4"
  local wallet_payload backfill_payload backfill_response next_height to_height

  wallet_payload="$(jq -cn --arg wallet_id "$wallet_id" --arg ufvk "$signer_ufvk" '{wallet_id: $wallet_id, ufvk: $ufvk}')"
  remote_juno_scan_post "$scan_url" "/v1/wallets" "$wallet_payload" "$bearer_token" >/dev/null

  wait_for_remote_juno_scan_tip "$scan_url" "$bearer_token"

  next_height=0
  while :; do
    backfill_payload="$(jq -cn --argjson from_height "$next_height" --argjson batch_size 10000 '{from_height: $from_height, batch_size: $batch_size}')"
    backfill_response="$(remote_juno_scan_post "$scan_url" "/v1/wallets/${wallet_id}/backfill" "$backfill_payload" "$bearer_token")"
    to_height="$(jq -er '.to_height' <<<"$backfill_response")"
    next_height="$(jq -er '.next_height' <<<"$backfill_response")"
    if (( next_height > to_height )); then
      break
    fi
  done
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

production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_secret_env"
production_render_operator_stack_env "$shared_manifest_path" "$operator_deploy" "$resolved_secret_env" "$merged_env"
production_render_junocashd_conf "$merged_env" "$junocashd_conf"
extract_build_runbook_block \
  "$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh" \
  "cat > /tmp/intents-juno-config-hydrator.sh <<'EOF_CONFIG_HYDRATOR'" \
  "EOF_CONFIG_HYDRATOR" \
  "$config_hydrator_stage"
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
  "$dkg_backup_zip"
  "$merged_env"
  "$junocashd_conf"
  "$config_hydrator_stage"
  "$signer_ufvk_file"
  "$dkg_peer_hosts_file"
  "$shared_manifest_path"
  "$operator_deploy"
  "$REPO_ROOT/deploy/operators/dkg/backup-package.sh"
  "$REPO_ROOT/deploy/operators/dkg/common.sh"
  "$REPO_ROOT/deploy/operators/dkg/operator-export-kms.sh"
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

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would deploy operator $operator_id via $ssh_target"
else
  production_require_base_relayer_balance "$resolved_secret_env" "$base_rpc_url"
  production_require_registered_operator "$shared_manifest_path" "$operator_deploy"
  ensure_operator_grpc_mesh_ingress "$aws_profile" "$aws_region" "$operator_host"
  production_rollout_reserve "$rollout_state_file" "$operator_id"
  reserved="true"
  ssh "${SSH_OPTS[@]}" "$ssh_target" "rm -rf '$remote_stage_dir' && mkdir -p '$remote_stage_dir'"
  for source_path in "${files_to_copy[@]}"; do
    scp "${SCP_OPTS[@]}" "$source_path" "$ssh_target:$remote_stage_dir/$(basename "$source_path")"
  done

  ssh "${SSH_OPTS[@]}" "$ssh_target" bash -s -- "$remote_stage_dir" "$runtime_dir" "$base_chain_id" "$bridge_address" <<'REMOTE_EOF'
set -euo pipefail

remote_stage_dir="$1"
runtime_dir="$2"
base_chain_id="$3"
bridge_address="$4"

if ! getent group intents-juno >/dev/null 2>&1; then
  sudo groupadd --system intents-juno
fi
if ! id -u intents-juno >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir /var/lib/intents-juno --shell /usr/sbin/nologin --gid intents-juno intents-juno
fi

sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno || true
sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno/base-relayer || true
sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir" || true

if [[ -f "$remote_stage_dir/base-relayer-server.pem" ]]; then
  sudo install -m 0640 "$remote_stage_dir/base-relayer-server.pem" /etc/intents-juno/base-relayer/server.pem
fi
if [[ -f "$remote_stage_dir/base-relayer-server.key" ]]; then
  sudo install -m 0640 "$remote_stage_dir/base-relayer-server.key" /etc/intents-juno/base-relayer/server.key
fi

if sudo test -f /etc/intents-juno/operator-stack.env; then
  sudo sed -i '/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d' /etc/intents-juno/operator-stack.env
fi
sudo rm -f /etc/intents-juno/checkpoint-signer.key
sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/operator-stack.env" /etc/intents-juno/operator-stack.env
sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/junocashd.conf" /etc/intents-juno/junocashd.conf
sudo install -m 0640 "$remote_stage_dir/shared-manifest.json" /etc/intents-juno/shared-manifest.json
sudo install -m 0640 "$remote_stage_dir/operator-deploy.json" /etc/intents-juno/operator-deploy.json
sudo install -m 0600 "$remote_stage_dir/$(basename "$remote_stage_dir").zip" /tmp/intents-juno-dkg-backup.zip 2>/dev/null || true
sudo cp "$remote_stage_dir/dkg-backup.zip" /tmp/intents-juno-dkg-backup.zip
sudo bash "$remote_stage_dir/backup-package.sh" restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force
sudo rm -f /tmp/intents-juno-dkg-backup.zip
if [[ -f "$remote_stage_dir/dkg-server.pem" ]]; then
  sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/dkg-server.pem" "$runtime_dir/bundle/tls/server.pem"
fi
if [[ -f "$remote_stage_dir/dkg-server.key" ]]; then
  sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/dkg-server.key" "$runtime_dir/bundle/tls/server.key"
fi
if [[ -f "$remote_stage_dir/ca.pem" ]]; then
  sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/ca.pem" "$runtime_dir/bundle/tls/ca.pem"
fi
if [[ -f "$remote_stage_dir/coordinator-client.pem" ]]; then
  sudo install -m 0640 -o root -g intents-juno "$remote_stage_dir/coordinator-client.pem" "$runtime_dir/bundle/tls/coordinator-client.pem"
fi
if [[ -f "$remote_stage_dir/coordinator-client.key" ]]; then
  sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/coordinator-client.key" "$runtime_dir/bundle/tls/coordinator-client.key"
fi
dkg_peer_hosts_file="$remote_stage_dir/dkg-peer-hosts.json"
if [[ -f "$dkg_peer_hosts_file" ]]; then
  admin_config_path="$runtime_dir/bundle/admin-config.json"
  dkg_roster_tmp="$(mktemp)"
  dkg_roster_hash_tmp="$(mktemp)"
  sudo cat "$admin_config_path" | jq --slurpfile peer_hosts "$dkg_peer_hosts_file" '
    .roster.operators |= map(
      . as $op
      | (($peer_hosts[0][] | select(.operator_id == $op.operator_id))
        // error("missing distributed dkg peer host for operator_id " + ($op.operator_id | tostring))) as $peer
      | .grpc_endpoint = (
          ($op.grpc_endpoint | capture("^(?<scheme>https?)://(?<host>[^:/]+)(?::(?<port>[0-9]+))?$")) as $endpoint
          | "\($endpoint.scheme)://\($peer.host):\($endpoint.port)"
        )
    )
  ' >"$dkg_roster_tmp"
  jq -c '
    .roster |
    {
      roster_version: .roster_version,
      operators: (
        .operators
        | map({
            operator_id: (.operator_id | tostring | gsub("^\\s+|\\s+$"; "")),
            grpc_endpoint: (
              if .grpc_endpoint == null then null
              else (.grpc_endpoint | tostring | gsub("^\\s+|\\s+$"; ""))
              end
            ),
            age_recipient: (
              if .age_recipient == null then null
              else (.age_recipient | tostring | gsub("^\\s+|\\s+$"; ""))
              end
            )
          })
        | sort_by(.operator_id)
        | map(with_entries(select(.value != null)))
      ),
      coordinator_age_recipient: (
        if .coordinator_age_recipient == null then null
        else (.coordinator_age_recipient | tostring | gsub("^\\s+|\\s+$"; ""))
        end
      )
    }
    | with_entries(select(.value != null))
  ' "$dkg_roster_tmp" >"$dkg_roster_hash_tmp"
  dkg_roster_canonical="$(cat "$dkg_roster_hash_tmp")"
  if command -v sha256sum >/dev/null 2>&1; then
    dkg_roster_hash="$(printf '%s' "$dkg_roster_canonical" | sha256sum | awk '{print $1}')"
  else
    dkg_roster_hash="$(printf '%s' "$dkg_roster_canonical" | shasum -a 256 | awk '{print $1}')"
  fi
  jq --arg roster_hash "$dkg_roster_hash" '.roster_hash_hex = $roster_hash' "$dkg_roster_tmp" >"${dkg_roster_tmp}.final"
  sudo install -m 0640 -o intents-juno -g intents-juno "${dkg_roster_tmp}.final" "$admin_config_path"
  rm -f "$dkg_roster_tmp" "${dkg_roster_tmp}.final" "$dkg_roster_hash_tmp"
fi
if [[ -f "$runtime_dir/bundle/tls/coordinator-client.pem" ]]; then
  admin_config_path="$runtime_dir/bundle/admin-config.json"
  coordinator_client_fingerprint_tmp="$(mktemp)"
  coordinator_client_fingerprint="$(openssl x509 -in "$runtime_dir/bundle/tls/coordinator-client.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
  jq --arg fingerprint "$coordinator_client_fingerprint" \
     --arg cert "./tls/coordinator-client.pem" \
     --arg key "./tls/coordinator-client.key" '
    .grpc = ((.grpc // {}) + {
      coordinator_client_cert_sha256: $fingerprint,
      tls_client_cert_pem_path: $cert,
      tls_client_key_pem_path: $key
    })
  ' "$admin_config_path" >"$coordinator_client_fingerprint_tmp"
  sudo install -m 0640 -o intents-juno -g intents-juno "$coordinator_client_fingerprint_tmp" "$admin_config_path"
  rm -f "$coordinator_client_fingerprint_tmp"
fi
sudo jq -er '
  (.grpc.coordinator_client_cert_sha256 // "" | tostring | length) > 0
' "$runtime_dir/bundle/admin-config.json" >/dev/null || {
  echo "operator runtime admin config missing coordinator client fingerprint: $runtime_dir/bundle/admin-config.json" >&2
  exit 1
}
sudo jq -er '
  .grpc.tls_client_cert_pem_path == "./tls/coordinator-client.pem"
  and .grpc.tls_client_key_pem_path == "./tls/coordinator-client.key"
' "$runtime_dir/bundle/admin-config.json" >/dev/null || {
  echo "operator runtime admin config missing coordinator client tls paths: $runtime_dir/bundle/admin-config.json" >&2
  exit 1
}

env_get_value_remote() {
  local key="$1"
  sudo awk -F= -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' /etc/intents-juno/operator-stack.env
}

case "$(env_get_value_remote "JUNO_DEV_MODE")" in
  1|true|TRUE|yes|YES|on|ON)
    coord_client_cert="$(env_get_value_remote "WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE")"
    coord_client_key="$(env_get_value_remote "WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE")"
    coord_client_ca="$(env_get_value_remote "TSS_CLIENT_CA_FILE")"
    [[ -n "$coord_client_cert" ]] || {
      echo "operator runtime is missing WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    [[ -n "$coord_client_key" ]] || {
      echo "operator runtime is missing WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    sudo test -s "$coord_client_cert" || {
      echo "operator runtime is missing coordinator client cert: $coord_client_cert" >&2
      exit 1
    }
    sudo test -s "$coord_client_key" || {
      echo "operator runtime is missing coordinator client key: $coord_client_key" >&2
      exit 1
    }
    sudo openssl x509 -in "$coord_client_cert" -noout -purpose 2>/dev/null | grep -Fq 'SSL client : Yes' || {
      echo "operator runtime coordinator client cert is not valid for TLS client auth: $coord_client_cert" >&2
      exit 1
    }
    if [[ -n "$coord_client_ca" ]] && sudo test -s "$coord_client_ca"; then
      sudo openssl verify -CAfile "$coord_client_ca" "$coord_client_cert" >/dev/null 2>&1 || {
        echo "operator runtime coordinator client cert does not verify against CA: $coord_client_cert" >&2
        exit 1
      }
    fi
    ;;
esac

# shellcheck source=/dev/null
source "$remote_stage_dir/common.sh"
dkg_release_tag="${JUNO_DKG_RELEASE_TAG:-$JUNO_DKG_VERSION_DEFAULT}"
dkg_stage_dir="$(mktemp -d)"
dkg_admin_downloaded="$(ensure_dkg_binary "dkg-admin" "$dkg_release_tag" "$dkg_stage_dir")"
juno_txsign_downloaded="$(ensure_juno_txsign_binary "$JUNO_TXSIGN_VERSION_DEFAULT" "$dkg_stage_dir")"
sudo install -d -m 0755 -o intents-juno -g intents-juno "$runtime_dir/bin"
sudo install -m 0755 "$dkg_admin_downloaded" "$runtime_dir/bin/dkg-admin"
sudo install -m 0755 "$juno_txsign_downloaded" "$runtime_dir/bin/juno-txsign"
rm -rf "$dkg_stage_dir"
dkg_admin_runtime_bin="$runtime_dir/bin/dkg-admin"
juno_txsign_runtime_bin="$runtime_dir/bin/juno-txsign"
sudo chown -R intents-juno:intents-juno "$runtime_dir"
source "$remote_stage_dir/common.sh"
CHECKPOINT_SIGNER_KMS_KEY_ID="$(env_get_value_remote "CHECKPOINT_SIGNER_KMS_KEY_ID")"
CHECKPOINT_BLOB_BUCKET="$(env_get_value_remote "CHECKPOINT_BLOB_BUCKET")"
CHECKPOINT_BLOB_PREFIX="$(env_get_value_remote "CHECKPOINT_BLOB_PREFIX")"
CHECKPOINT_BLOB_SSE_KMS_KEY_ID="$(env_get_value_remote "CHECKPOINT_BLOB_SSE_KMS_KEY_ID")"
CHECKPOINT_SIGNER_DRIVER_REMOTE="$(printf '%s' "$(env_get_value_remote "CHECKPOINT_SIGNER_DRIVER")" | tr '[:upper:]' '[:lower:]')"
AWS_REGION="$(env_get_value_remote "AWS_REGION")"
if [[ -z "$AWS_REGION" ]]; then
  AWS_REGION="$(env_get_value_remote "AWS_DEFAULT_REGION")"
fi
case "$CHECKPOINT_SIGNER_DRIVER_REMOTE" in
  aws-kms)
    [[ -n "$CHECKPOINT_SIGNER_KMS_KEY_ID" ]] || {
      echo "operator runtime is missing CHECKPOINT_SIGNER_KMS_KEY_ID in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    [[ -n "$CHECKPOINT_BLOB_BUCKET" ]] || {
      echo "operator runtime is missing CHECKPOINT_BLOB_BUCKET in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    [[ -n "$CHECKPOINT_BLOB_SSE_KMS_KEY_ID" ]] || {
      echo "operator runtime is missing CHECKPOINT_BLOB_SSE_KMS_KEY_ID in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    [[ -n "$AWS_REGION" ]] || {
      echo "operator runtime is missing AWS_REGION or AWS_DEFAULT_REGION in /etc/intents-juno/operator-stack.env" >&2
      exit 1
    }
    sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir/exports"
    ensure_command aws
    sudo -u intents-juno bash "$remote_stage_dir/operator-export-kms.sh" export \
      --workdir "$runtime_dir" \
      --release-tag "$dkg_release_tag" \
      --kms-key-id "${CHECKPOINT_BLOB_SSE_KMS_KEY_ID}" \
      --s3-bucket "${CHECKPOINT_BLOB_BUCKET}" \
      --s3-key-prefix "${CHECKPOINT_BLOB_PREFIX:-dkg/keypackages}" \
      --s3-sse-kms-key-id "${CHECKPOINT_BLOB_SSE_KMS_KEY_ID}" \
      --aws-region "${AWS_REGION}"
    latest_kms_receipt="$(sudo bash -lc 'ls -1t "$1"/exports/kms-export-receipt-*.json 2>/dev/null | head -n1' _ "$runtime_dir")"
    [[ -n "$latest_kms_receipt" ]] || {
      echo "operator runtime did not produce a kms export receipt under $runtime_dir/exports" >&2
      exit 1
    }
    sudo ln -sfn "$latest_kms_receipt" "$runtime_dir/exports/kms-export-receipt.json"
    ;;
  *)
    echo "operator runtime must set CHECKPOINT_SIGNER_DRIVER=aws-kms in /etc/intents-juno/operator-stack.env" >&2
    exit 1
    ;;
esac
if sudo test -e /var/lib/intents-juno/juno-scan.db; then
  sudo systemctl stop juno-scan || true
  sudo bash -lc 'chown -R intents-juno:intents-juno /var/lib/intents-juno/juno-scan.db'
fi
sudo test -x "$dkg_admin_runtime_bin" || {
  echo "restored runtime is missing dkg-admin binary: $dkg_admin_runtime_bin" >&2
  exit 1
}
sudo test -x "$juno_txsign_runtime_bin" || {
  echo "restored runtime is missing juno-txsign binary: $juno_txsign_runtime_bin" >&2
  exit 1
}
juno_txsign_help="$(sudo "$juno_txsign_runtime_bin" --help 2>&1 || true)"
grep -qE '(^|[[:space:]])sign-digest([[:space:]]|$)' <<<"$juno_txsign_help" || {
  echo "restored runtime juno-txsign binary does not support sign-digest: $juno_txsign_runtime_bin" >&2
  exit 1
}

checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"
checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"
dkg_admin_serve_script="/usr/local/bin/intents-juno-dkg-admin-serve.sh"
spendauth_signer_script="/usr/local/bin/intents-juno-spendauth-signer.sh"
deposit_relayer_script="/usr/local/bin/intents-juno-deposit-relayer.sh"
withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"
base_event_scanner_script="/usr/local/bin/intents-juno-base-event-scanner.sh"

signer_tmp="$(mktemp)"
cat >"$signer_tmp" <<'EOF_SIGNER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
set -a
source /etc/intents-juno/operator-stack.env
set +a
export_optional_env_vars() {
  local name
  for name in "$@"; do
    if [[ "${!name+x}" == "x" ]]; then
      export "$name"
    fi
  done
}
export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS
[[ -n "${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_SIGNATURE_TOPIC:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_SIGNATURE_TOPIC in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_CHAIN_ID:-}" ]] || {
  echo "checkpoint-signer requires BASE_CHAIN_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BRIDGE_ADDRESS:-}" ]] || {
  echo "checkpoint-signer requires BRIDGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${OPERATOR_ADDRESS:-}" ]] || {
  echo "checkpoint-signer requires OPERATOR_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_THRESHOLD:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_THRESHOLD in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
if [[ "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=require"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-ca"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-full"* ]]; then
  echo "checkpoint-signer requires CHECKPOINT_POSTGRES_DSN with sslmode=require (or verify-ca/verify-full)" >&2
  exit 1
fi
kafka_tls_value="${JUNO_QUEUE_KAFKA_TLS:-true}"
case "${kafka_tls_value,,}" in
  1|true|yes|on)
    export JUNO_QUEUE_KAFKA_TLS=true
    ;;
  *)
    echo "checkpoint-signer requires JUNO_QUEUE_KAFKA_TLS=true for kafka TLS transport" >&2
    exit 1
    ;;
esac
kafka_auth_mode="$(printf '%s' "${JUNO_QUEUE_KAFKA_AUTH_MODE:-}" | tr '[:upper:]' '[:lower:]')"
case "$kafka_auth_mode" in
  aws-msk-iam)
    export JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
    if [[ -z "${JUNO_QUEUE_KAFKA_AWS_REGION:-}" ]]; then
      if [[ -n "${AWS_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_REGION}"
      elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_DEFAULT_REGION}"
      else
        echo "checkpoint-signer requires JUNO_QUEUE_KAFKA_AWS_REGION (or AWS_REGION/AWS_DEFAULT_REGION) for aws-msk-iam" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "checkpoint-signer requires JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" >&2
    exit 1
    ;;
esac
signer_driver="$(printf '%s' "${CHECKPOINT_SIGNER_DRIVER:-}" | tr '[:upper:]' '[:lower:]')"
checkpoint_signer_lease_name="${CHECKPOINT_SIGNER_LEASE_NAME:-checkpoint-signer-${OPERATOR_ADDRESS}}"
checkpoint_signer_help="$(/usr/local/bin/checkpoint-signer --help 2>&1 || true)"
checkpoint_signer_supports_signer_driver=false
if grep -q -- '-signer-driver ' <<<"$checkpoint_signer_help"; then
  checkpoint_signer_supports_signer_driver=true
fi
case "${signer_driver}" in
  aws-kms)
    [[ -n "${CHECKPOINT_SIGNER_KMS_KEY_ID:-}" ]] || {
      echo "checkpoint-signer requires CHECKPOINT_SIGNER_KMS_KEY_ID in /etc/intents-juno/operator-stack.env when CHECKPOINT_SIGNER_DRIVER=aws-kms" >&2
      exit 1
    }
    [[ "$checkpoint_signer_supports_signer_driver" == true ]] || {
      echo "checkpoint-signer binary does not support CHECKPOINT_SIGNER_DRIVER=aws-kms; upgrade the operator binary" >&2
      exit 1
    }
    signer_args=(
      --signer-driver "${signer_driver}"
      --kms-key-id "${CHECKPOINT_SIGNER_KMS_KEY_ID}"
    )
    ;;
  *)
    echo "checkpoint-signer requires CHECKPOINT_SIGNER_DRIVER=aws-kms in /etc/intents-juno/operator-stack.env" >&2
    exit 1
    ;;
esac
exec /usr/local/bin/checkpoint-signer \
  --juno-rpc-url http://127.0.0.1:18232 \
  "${signer_args[@]}" \
  --base-chain-id "${BASE_CHAIN_ID}" \
  --bridge-address "${BRIDGE_ADDRESS}" \
  --confirmations 1 \
  --poll-interval 15s \
  --owner-id "$(hostname -s)" \
  --lease-name "${checkpoint_signer_lease_name}" \
  --postgres-dsn "$CHECKPOINT_POSTGRES_DSN" \
  --lease-driver postgres \
  --queue-driver kafka \
  --queue-brokers "$CHECKPOINT_KAFKA_BROKERS" \
  --queue-output-topic "$CHECKPOINT_SIGNATURE_TOPIC" \
  --health-port "${CHECKPOINT_SIGNER_HEALTH_PORT:-18301}"
EOF_SIGNER_WRAPPER
sudo install -m 0755 "$signer_tmp" "$checkpoint_signer_script"
rm -f "$signer_tmp"
if ! grep -q -- '--base-chain-id "${BASE_CHAIN_ID}"' "$checkpoint_aggregator_script"; then
  sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_aggregator_script"
fi
if ! grep -q -- '--bridge-address "${BRIDGE_ADDRESS}"' "$checkpoint_aggregator_script"; then
  sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_aggregator_script"
fi
dkg_admin_tmp="$(mktemp)"
cat >"$dkg_admin_tmp" <<'EOF_DKG_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
admin_config="${DKG_ADMIN_CONFIG_FILE:-/var/lib/intents-juno/operator-runtime/bundle/admin-config.json}"
[[ -s "$admin_config" ]] || {
  echo "dkg-admin serve requires admin-config.json: $admin_config" >&2
  exit 1
}
admin_config_dir="$(dirname "$admin_config")"
cd "$admin_config_dir"
exec /var/lib/intents-juno/operator-runtime/bin/dkg-admin --config "$admin_config" serve
EOF_DKG_WRAPPER
sudo install -m 0755 "$dkg_admin_tmp" "$dkg_admin_serve_script"
rm -f "$dkg_admin_tmp"

if [[ "$(printf '%s' "$(env_get_value_remote "TSS_SIGNER_RUNTIME_MODE")" | tr '[:upper:]' '[:lower:]')" == "host-process" ]]; then
  spendauth_tmp="$(mktemp)"
  cat >"$spendauth_tmp" <<'EOF_SPENDAUTH_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env

dev_mode_enabled() {
  case "${JUNO_DEV_MODE:-false}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

runtime_mode="$(printf '%s' "${TSS_SIGNER_RUNTIME_MODE:-nitro-enclave}" | tr '[:upper:]' '[:lower:]')"
case "$runtime_mode" in
  host-process)
    if ! dev_mode_enabled; then
      echo "tss-host host-process mode requires JUNO_DEV_MODE=true" >&2
      exit 1
    fi
    [[ -x "${TSS_SPENDAUTH_SIGNER_BIN:-}" ]] || {
      echo "tss-host host-process mode requires TSS_SPENDAUTH_SIGNER_BIN executable: ${TSS_SPENDAUTH_SIGNER_BIN:-unset}" >&2
      exit 1
    }
    admin_config="${DKG_ADMIN_CONFIG_FILE:-/var/lib/intents-juno/operator-runtime/bundle/admin-config.json}"
    [[ -s "$admin_config" ]] || {
      echo "tss-host host-process mode requires DKG_ADMIN_CONFIG_FILE: $admin_config" >&2
      exit 1
    }
    if [[ "$(id -u)" -eq 0 ]]; then
      exec sudo -u intents-juno "$0" "$@"
    fi
    admin_config_dir="$(dirname "$admin_config")"
    cd "$admin_config_dir"
    exec "${TSS_SPENDAUTH_SIGNER_BIN}" --config "$admin_config" "$@"
    ;;
  *)
    echo "unsupported TSS_SIGNER_RUNTIME_MODE for host-process spendauth patch: ${TSS_SIGNER_RUNTIME_MODE:-unset}" >&2
    exit 1
    ;;
esac
EOF_SPENDAUTH_WRAPPER
  sudo install -m 0755 "$spendauth_tmp" "$spendauth_signer_script"
  rm -f "$spendauth_tmp"
fi

deposit_relayer_tmp="$(mktemp)"
cat >"$deposit_relayer_tmp" <<'EOF_DEPOSIT_RELAYER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
export_optional_env_vars() {
  local name
  for name in "$@"; do
    if [[ "${!name+x}" == "x" ]]; then
      export "$name"
    fi
  done
}
export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS
[[ -n "${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "deposit-relayer requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "deposit-relayer requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_OPERATORS:-}" ]] || {
  echo "deposit-relayer requires CHECKPOINT_OPERATORS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_THRESHOLD:-}" ]] || {
  echo "deposit-relayer requires CHECKPOINT_THRESHOLD in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_CHAIN_ID:-}" ]] || {
  echo "deposit-relayer requires BASE_CHAIN_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BRIDGE_ADDRESS:-}" ]] || {
  echo "deposit-relayer requires BRIDGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${DEPOSIT_IMAGE_ID:-}" ]] || {
  echo "deposit-relayer requires DEPOSIT_IMAGE_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_URL:-}" ]] || {
  echo "deposit-relayer requires BASE_RELAYER_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_AUTH_TOKEN:-}" ]] || {
  echo "deposit-relayer requires BASE_RELAYER_AUTH_TOKEN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
if [[ "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=require"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-ca"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-full"* ]]; then
  echo "deposit-relayer requires CHECKPOINT_POSTGRES_DSN with sslmode=require (or verify-ca/verify-full)" >&2
  exit 1
fi
kafka_tls_value="${JUNO_QUEUE_KAFKA_TLS:-true}"
case "${kafka_tls_value,,}" in
  1|true|yes|on)
    export JUNO_QUEUE_KAFKA_TLS=true
    ;;
  *)
    echo "deposit-relayer requires JUNO_QUEUE_KAFKA_TLS=true for kafka TLS transport" >&2
    exit 1
    ;;
esac
kafka_auth_mode="$(printf '%s' "${JUNO_QUEUE_KAFKA_AUTH_MODE:-}" | tr '[:upper:]' '[:lower:]')"
case "$kafka_auth_mode" in
  aws-msk-iam)
    export JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
    if [[ -z "${JUNO_QUEUE_KAFKA_AWS_REGION:-}" ]]; then
      if [[ -n "${AWS_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_REGION}"
      elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_DEFAULT_REGION}"
      else
        echo "deposit-relayer requires JUNO_QUEUE_KAFKA_AWS_REGION (or AWS_REGION/AWS_DEFAULT_REGION) for aws-msk-iam" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "deposit-relayer requires JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" >&2
    exit 1
    ;;
esac
export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN

deposit_owner="${DEPOSIT_RELAYER_OWNER:-$(hostname -s)-deposit-relayer}"
deposit_max_items="${DEPOSIT_RELAYER_MAX_ITEMS:-1}"
deposit_queue_group="${DEPOSIT_RELAYER_QUEUE_GROUP:-deposit-relayer}"
deposit_queue_topics="${DEPOSIT_RELAYER_QUEUE_TOPICS:-deposits.event.v2,checkpoints.packages.v1}"
deposit_proof_response_group="${DEPOSIT_RELAYER_PROOF_RESPONSE_GROUP:-$(hostname -s)-deposit-relayer-proof}"
deposit_base_rpc_url="${BASE_RPC_URL:-${BASE_RELAYER_RPC_URL:-${BASE_EVENT_SCANNER_BASE_RPC_URL:-}}}"
[[ -n "${deposit_base_rpc_url}" ]] || {
  echo "deposit-relayer requires BASE_RPC_URL, BASE_RELAYER_RPC_URL, or BASE_EVENT_SCANNER_BASE_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
deposit_juno_rpc_url="${DEPOSIT_SCAN_JUNO_RPC_URL:-${WITHDRAW_COORDINATOR_JUNO_RPC_URL:-}}"
[[ -n "${deposit_juno_rpc_url}" ]] || {
  echo "deposit-relayer requires DEPOSIT_SCAN_JUNO_RPC_URL or WITHDRAW_COORDINATOR_JUNO_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}

args=(
  --postgres-dsn "${CHECKPOINT_POSTGRES_DSN}"
  --store-driver postgres
  --base-chain-id "${BASE_CHAIN_ID}"
  --bridge-address "${BRIDGE_ADDRESS}"
  --operators "${CHECKPOINT_OPERATORS}"
  --operator-threshold "${CHECKPOINT_THRESHOLD}"
  --deposit-image-id "${DEPOSIT_IMAGE_ID}"
  --base-relayer-url "${BASE_RELAYER_URL}"
  --base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN
  --base-rpc-url "${deposit_base_rpc_url}"
  --juno-rpc-url "${deposit_juno_rpc_url}"
  --max-items "${deposit_max_items}"
  --owner "${deposit_owner}"
  --proof-driver queue
  --proof-request-topic "${PROOF_REQUEST_TOPIC:-proof.requests.v1}"
  --proof-result-topic "${PROOF_RESULT_TOPIC:-proof.fulfillments.v1}"
  --proof-failure-topic "${PROOF_FAILURE_TOPIC:-proof.failures.v1}"
  --proof-response-group "${deposit_proof_response_group}"
  --queue-driver kafka
  --queue-brokers "${CHECKPOINT_KAFKA_BROKERS}"
  --queue-group "${deposit_queue_group}"
  --queue-topics "${deposit_queue_topics}"
  --deposit-min-confirmations "${RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS:-1}"
  --withdraw-planner-min-confirmations "${RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"
  --withdraw-batch-confirmations "${RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS:-1}"
  --health-port "${DEPOSIT_RELAYER_HEALTH_PORT:-18303}"
)
if [[ -n "${DEPOSIT_OWALLET_IVK:-}" ]]; then
  args+=(--owallet-ivk "${DEPOSIT_OWALLET_IVK}")
fi
if [[ "${DEPOSIT_SCAN_ENABLED:-false}" == "true" ]]; then
  [[ -n "${DEPOSIT_SCAN_JUNO_SCAN_URL:-}" ]] || {
    echo "deposit-relayer scanner requires DEPOSIT_SCAN_JUNO_SCAN_URL in /etc/intents-juno/operator-stack.env" >&2
    exit 1
  }
  [[ -n "${DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID:-}" ]] || {
    echo "deposit-relayer scanner requires DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID in /etc/intents-juno/operator-stack.env" >&2
    exit 1
  }
  [[ -n "${DEPOSIT_SCAN_JUNO_RPC_URL:-}" ]] || {
    echo "deposit-relayer scanner requires DEPOSIT_SCAN_JUNO_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
    exit 1
  }
  args+=(
    --scan-enabled
    --juno-scan-url "${DEPOSIT_SCAN_JUNO_SCAN_URL}"
    --juno-scan-wallet-id "${DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID}"
    --juno-scan-bearer-env "${DEPOSIT_SCAN_JUNO_SCAN_BEARER_ENV:-JUNO_SCAN_BEARER_TOKEN}"
    --juno-rpc-user-env "${DEPOSIT_SCAN_JUNO_RPC_USER_ENV:-JUNO_RPC_USER}"
    --juno-rpc-pass-env "${DEPOSIT_SCAN_JUNO_RPC_PASS_ENV:-JUNO_RPC_PASS}"
    --scan-poll-interval "${DEPOSIT_SCAN_POLL_INTERVAL:-15s}"
  )
fi

exec /usr/local/bin/deposit-relayer "${args[@]}"
EOF_DEPOSIT_RELAYER_WRAPPER
sudo install -m 0755 "$deposit_relayer_tmp" "$deposit_relayer_script"
rm -f "$deposit_relayer_tmp"

withdraw_tmp="$(mktemp)"
cat >"$withdraw_tmp" <<'EOF_WITHDRAW_COORDINATOR_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
export_optional_env_vars() {
  local name
  for name in "$@"; do
    if [[ "${!name+x}" == "x" ]]; then
      export "$name"
    fi
  done
}
export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS

dev_mode_enabled() {
  case "${JUNO_DEV_MODE:-false}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

[[ -n "${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "withdraw-coordinator requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "withdraw-coordinator requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_CHAIN_ID:-}" ]] || {
  echo "withdraw-coordinator requires BASE_CHAIN_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BRIDGE_ADDRESS:-}" ]] || {
  echo "withdraw-coordinator requires BRIDGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_URL:-}" ]] || {
  echo "withdraw-coordinator requires BASE_RELAYER_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_AUTH_TOKEN:-}" ]] || {
  echo "withdraw-coordinator requires BASE_RELAYER_AUTH_TOKEN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_COORDINATOR_JUNO_WALLET_ID:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_JUNO_WALLET_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_COORDINATOR_JUNO_RPC_URL:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_JUNO_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_COORDINATOR_JUNO_SCAN_URL:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_JUNO_SCAN_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${JUNO_RPC_USER:-}" ]] || {
  echo "withdraw-coordinator requires JUNO_RPC_USER in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${JUNO_RPC_PASS:-}" ]] || {
  echo "withdraw-coordinator requires JUNO_RPC_PASS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_COORDINATOR_TSS_URL:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_TSS_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ "${WITHDRAW_COORDINATOR_TSS_URL}" == https://* ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_TSS_URL to use https://" >&2
  exit 1
}
[[ -s "${WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE to reference a readable PEM file" >&2
  exit 1
}
if ! dev_mode_enabled; then
  [[ -s "${WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE:-}" ]] || {
    echo "withdraw-coordinator production mode requires WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE to reference a readable PEM file" >&2
    exit 1
  }
  [[ -s "${WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE:-}" ]] || {
    echo "withdraw-coordinator production mode requires WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE to reference a readable PEM file" >&2
    exit 1
  }
fi
[[ -n "${WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -x "${WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN}" ]] || {
  echo "withdraw-coordinator requires executable WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN: ${WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN}" >&2
  exit 1
}
[[ -n "${WITHDRAW_BLOB_BUCKET:-}" ]] || {
  echo "withdraw-coordinator requires WITHDRAW_BLOB_BUCKET in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
if [[ "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=require"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-ca"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-full"* ]]; then
  echo "withdraw-coordinator requires CHECKPOINT_POSTGRES_DSN with sslmode=require (or verify-ca/verify-full)" >&2
  exit 1
fi
kafka_tls_value="${JUNO_QUEUE_KAFKA_TLS:-true}"
case "${kafka_tls_value,,}" in
  1|true|yes|on)
    export JUNO_QUEUE_KAFKA_TLS=true
    ;;
  *)
    echo "withdraw-coordinator requires JUNO_QUEUE_KAFKA_TLS=true for kafka TLS transport" >&2
    exit 1
    ;;
esac
kafka_auth_mode="$(printf '%s' "${JUNO_QUEUE_KAFKA_AUTH_MODE:-}" | tr '[:upper:]' '[:lower:]')"
case "$kafka_auth_mode" in
  aws-msk-iam)
    export JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
    if [[ -z "${JUNO_QUEUE_KAFKA_AWS_REGION:-}" ]]; then
      if [[ -n "${AWS_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_REGION}"
      elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_DEFAULT_REGION}"
      else
        echo "withdraw-coordinator requires JUNO_QUEUE_KAFKA_AWS_REGION (or AWS_REGION/AWS_DEFAULT_REGION) for aws-msk-iam" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "withdraw-coordinator requires JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" >&2
    exit 1
    ;;
esac
txbuild_bin="${WITHDRAW_COORDINATOR_TXBUILD_BIN:-juno-txbuild}"
command -v "${txbuild_bin}" >/dev/null 2>&1 || {
  echo "withdraw-coordinator requires WITHDRAW_COORDINATOR_TXBUILD_BIN to resolve an executable (current: ${txbuild_bin})" >&2
  exit 1
}
tss_server_name_args=()
if [[ -n "${WITHDRAW_COORDINATOR_TSS_SERVER_NAME:-}" ]]; then
  tss_server_name_args=(--tss-server-name "${WITHDRAW_COORDINATOR_TSS_SERVER_NAME}")
fi
export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN JUNO_TXSIGN_SIGNER_KEYS

withdraw_coord_owner="${WITHDRAW_COORDINATOR_OWNER:-$(hostname -s)-withdraw-coordinator}"
withdraw_coord_queue_group="${WITHDRAW_COORDINATOR_QUEUE_GROUP:-withdraw-coordinator}"
withdraw_coord_queue_topics="${WITHDRAW_COORDINATOR_QUEUE_TOPIC:-withdrawals.requested.v2}"

exec /usr/local/bin/withdraw-coordinator \
  --postgres-dsn-env "${WITHDRAW_COORDINATOR_POSTGRES_DSN_ENV:-CHECKPOINT_POSTGRES_DSN}" \
  --owner "${withdraw_coord_owner}" \
  --claim-ttl "${WITHDRAW_COORDINATOR_CLAIM_TTL:-5m}" \
  --queue-driver kafka \
  --queue-brokers "${CHECKPOINT_KAFKA_BROKERS}" \
  --queue-group "${withdraw_coord_queue_group}" \
  --queue-topics "${withdraw_coord_queue_topics}" \
  --juno-txbuild-bin "${txbuild_bin}" \
  --juno-scan-url "${WITHDRAW_COORDINATOR_JUNO_SCAN_URL}" \
  --juno-scan-bearer-env JUNO_SCAN_BEARER_TOKEN \
  --juno-rpc-url "${WITHDRAW_COORDINATOR_JUNO_RPC_URL}" \
  --juno-rpc-user-env JUNO_RPC_USER \
  --juno-rpc-pass-env JUNO_RPC_PASS \
  --juno-wallet-id "${WITHDRAW_COORDINATOR_JUNO_WALLET_ID}" \
  --juno-change-address "${WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS}" \
  --deposit-min-confirmations "${RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS:-1}" \
  --juno-minconf "${RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}" \
  --juno-expiry-offset "${WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET:-240}" \
  --juno-confirmations "${RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS:-1}" \
  --juno-fee-add-zat "${WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT:-1000000}" \
  --tss-url "${WITHDRAW_COORDINATOR_TSS_URL}" \
  --tss-server-ca-file "${WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE}" \
  "${tss_server_name_args[@]}" \
  --tss-client-cert-file "${WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE}" \
  --tss-client-key-file "${WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE}" \
  --tss-timeout 120s \
  --base-chain-id "${BASE_CHAIN_ID}" \
  --bridge-address "${BRIDGE_ADDRESS}" \
  --base-relayer-url "${BASE_RELAYER_URL}" \
  --base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN \
  --extend-signer-bin "${WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN}" \
  --expiry-safety-margin "${WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN:-6h}" \
  --max-expiry-extension "${WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION:-12h}" \
  --blob-driver s3 \
  --blob-bucket "${WITHDRAW_BLOB_BUCKET}" \
  --blob-prefix "${WITHDRAW_BLOB_PREFIX:-withdraw-live}" \
  --health-port "${WITHDRAW_COORDINATOR_HEALTH_PORT:-18304}"
EOF_WITHDRAW_COORDINATOR_WRAPPER
sudo install -m 0755 "$withdraw_tmp" "$withdraw_coordinator_script"
rm -f "$withdraw_tmp"

withdraw_finalizer_script="/usr/local/bin/intents-juno-withdraw-finalizer.sh"
withdraw_finalizer_tmp="$(mktemp)"
cat >"$withdraw_finalizer_tmp" <<'EOF_WITHDRAW_FINALIZER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
export_optional_env_vars() {
  local name
  for name in "$@"; do
    if [[ "${!name+x}" == "x" ]]; then
      export "$name"
    fi
  done
}
export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS
[[ -n "${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "withdraw-finalizer requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "withdraw-finalizer requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_OPERATORS:-}" ]] || {
  echo "withdraw-finalizer requires CHECKPOINT_OPERATORS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_THRESHOLD:-}" ]] || {
  echo "withdraw-finalizer requires CHECKPOINT_THRESHOLD in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_CHAIN_ID:-}" ]] || {
  echo "withdraw-finalizer requires BASE_CHAIN_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BRIDGE_ADDRESS:-}" ]] || {
  echo "withdraw-finalizer requires BRIDGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_IMAGE_ID:-}" ]] || {
  echo "withdraw-finalizer requires WITHDRAW_IMAGE_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_URL:-}" ]] || {
  echo "withdraw-finalizer requires BASE_RELAYER_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_RELAYER_AUTH_TOKEN:-}" ]] || {
  echo "withdraw-finalizer requires BASE_RELAYER_AUTH_TOKEN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_BLOB_BUCKET:-}" ]] || {
  echo "withdraw-finalizer requires WITHDRAW_BLOB_BUCKET in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_FINALIZER_JUNO_SCAN_URL:-}" ]] || {
  echo "withdraw-finalizer requires WITHDRAW_FINALIZER_JUNO_SCAN_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID:-}" ]] || {
  echo "withdraw-finalizer requires WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${WITHDRAW_FINALIZER_JUNO_RPC_URL:-}" ]] || {
  echo "withdraw-finalizer requires WITHDRAW_FINALIZER_JUNO_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${JUNO_RPC_USER:-}" ]] || {
  echo "withdraw-finalizer requires JUNO_RPC_USER in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${JUNO_RPC_PASS:-}" ]] || {
  echo "withdraw-finalizer requires JUNO_RPC_PASS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
if [[ "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=require"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-ca"* && "${CHECKPOINT_POSTGRES_DSN}" != *"sslmode=verify-full"* ]]; then
  echo "withdraw-finalizer requires CHECKPOINT_POSTGRES_DSN with sslmode=require (or verify-ca/verify-full)" >&2
  exit 1
fi
kafka_tls_value="${JUNO_QUEUE_KAFKA_TLS:-true}"
case "${kafka_tls_value,,}" in
  1|true|yes|on)
    export JUNO_QUEUE_KAFKA_TLS=true
    ;;
  *)
    echo "withdraw-finalizer requires JUNO_QUEUE_KAFKA_TLS=true for kafka TLS transport" >&2
    exit 1
    ;;
esac
kafka_auth_mode="$(printf '%s' "${JUNO_QUEUE_KAFKA_AUTH_MODE:-}" | tr '[:upper:]' '[:lower:]')"
case "$kafka_auth_mode" in
  aws-msk-iam)
    export JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
    if [[ -z "${JUNO_QUEUE_KAFKA_AWS_REGION:-}" ]]; then
      if [[ -n "${AWS_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_REGION}"
      elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_DEFAULT_REGION}"
      else
        echo "withdraw-finalizer requires JUNO_QUEUE_KAFKA_AWS_REGION (or AWS_REGION/AWS_DEFAULT_REGION) for aws-msk-iam" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "withdraw-finalizer requires JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" >&2
    exit 1
    ;;
esac
export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN

withdraw_finalizer_owner="${WITHDRAW_FINALIZER_OWNER:-$(hostname -s)-withdraw-finalizer}"
withdraw_finalizer_queue_group="${WITHDRAW_FINALIZER_QUEUE_GROUP:-withdraw-finalizer}"
withdraw_finalizer_queue_topics="${WITHDRAW_FINALIZER_QUEUE_TOPICS:-checkpoints.packages.v1}"
withdraw_finalizer_proof_response_group="${WITHDRAW_FINALIZER_PROOF_RESPONSE_GROUP:-$(hostname -s)-withdraw-finalizer-proof}"

args=(
  --postgres-dsn "${CHECKPOINT_POSTGRES_DSN}"
  --base-chain-id "${BASE_CHAIN_ID}"
  --bridge-address "${BRIDGE_ADDRESS}"
  --operators "${CHECKPOINT_OPERATORS}"
  --operator-threshold "${CHECKPOINT_THRESHOLD}"
  --withdraw-image-id "${WITHDRAW_IMAGE_ID}"
  --withdraw-witness-extractor-enabled
  --juno-scan-url "${WITHDRAW_FINALIZER_JUNO_SCAN_URL}"
  --juno-scan-wallet-id "${WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID}"
  --juno-scan-bearer-env JUNO_SCAN_BEARER_TOKEN
  --juno-rpc-url "${WITHDRAW_FINALIZER_JUNO_RPC_URL}"
  --juno-rpc-user-env JUNO_RPC_USER
  --juno-rpc-pass-env JUNO_RPC_PASS
  --base-relayer-url "${BASE_RELAYER_URL}"
  --base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN
  --owner "${withdraw_finalizer_owner}"
  --proof-driver queue
  --proof-request-topic "${PROOF_REQUEST_TOPIC:-proof.requests.v1}"
  --proof-result-topic "${PROOF_RESULT_TOPIC:-proof.fulfillments.v1}"
  --proof-failure-topic "${PROOF_FAILURE_TOPIC:-proof.failures.v1}"
  --proof-response-group "${withdraw_finalizer_proof_response_group}"
  --queue-driver kafka
  --queue-brokers "${CHECKPOINT_KAFKA_BROKERS}"
  --queue-group "${withdraw_finalizer_queue_group}"
  --queue-topics "${withdraw_finalizer_queue_topics}"
  --blob-driver s3
  --blob-bucket "${WITHDRAW_BLOB_BUCKET}"
  --blob-prefix "${WITHDRAW_BLOB_PREFIX:-withdraw-live}"
  --health-port "${WITHDRAW_FINALIZER_HEALTH_PORT:-18305}"
)
if [[ -n "${WITHDRAW_OWALLET_OVK:-}" ]]; then
  args+=(--owallet-ovk "${WITHDRAW_OWALLET_OVK}")
fi

exec /usr/local/bin/withdraw-finalizer "${args[@]}"
EOF_WITHDRAW_FINALIZER_WRAPPER
sudo install -m 0755 "$withdraw_finalizer_tmp" "$withdraw_finalizer_script"
rm -f "$withdraw_finalizer_tmp"

base_event_scanner_tmp="$(mktemp)"
cat >"$base_event_scanner_tmp" <<'EOF_BASE_EVENT_SCANNER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
export_optional_env_vars() {
  local name
  for name in "$@"; do
    if [[ "${!name+x}" == "x" ]]; then
      export "$name"
    fi
  done
}
export_optional_env_vars JUNO_QUEUE_KAFKA_AWS_REGION AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS
[[ -n "${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "base-event-scanner requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_EVENT_SCANNER_BASE_RPC_URL:-}" ]] || {
  echo "base-event-scanner requires BASE_EVENT_SCANNER_BASE_RPC_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_EVENT_SCANNER_BRIDGE_ADDRESS:-}" ]] || {
  echo "base-event-scanner requires BASE_EVENT_SCANNER_BRIDGE_ADDRESS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "base-event-scanner requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "${BASE_EVENT_SCANNER_START_BLOCK:-}" ]] || {
  echo "base-event-scanner requires BASE_EVENT_SCANNER_START_BLOCK in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}

args=(
  --base-rpc-url "${BASE_EVENT_SCANNER_BASE_RPC_URL}"
  --bridge-address "${BASE_EVENT_SCANNER_BRIDGE_ADDRESS}"
  --postgres-dsn "${CHECKPOINT_POSTGRES_DSN}"
  --start-block "${BASE_EVENT_SCANNER_START_BLOCK}"
  --poll-interval "${BASE_EVENT_SCANNER_POLL_INTERVAL:-3s}"
  --queue-driver kafka
  --queue-brokers "${CHECKPOINT_KAFKA_BROKERS}"
  --withdraw-event-topic "${BASE_EVENT_SCANNER_WITHDRAW_EVENT_TOPIC:-withdrawals.requested.v2}"
  --health-port "${BASE_EVENT_SCANNER_HEALTH_PORT:-18306}"
)

case "${JUNO_QUEUE_KAFKA_TLS:-}" in
  true|1|yes) export JUNO_QUEUE_KAFKA_TLS="true" ;;
esac
case "$(printf '%s' "${JUNO_QUEUE_KAFKA_AUTH_MODE:-}" | tr '[:upper:]' '[:lower:]')" in
  aws-msk-iam)
    export JUNO_QUEUE_KAFKA_AUTH_MODE="aws-msk-iam"
    if [[ -z "${JUNO_QUEUE_KAFKA_AWS_REGION:-}" ]]; then
      if [[ -n "${AWS_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_REGION}"
      elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
        export JUNO_QUEUE_KAFKA_AWS_REGION="${AWS_DEFAULT_REGION}"
      else
        echo "base-event-scanner requires JUNO_QUEUE_KAFKA_AWS_REGION (or AWS_REGION/AWS_DEFAULT_REGION) for aws-msk-iam" >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "base-event-scanner requires JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" >&2
    exit 1
    ;;
esac

exec /usr/local/bin/base-event-scanner "${args[@]}"
EOF_BASE_EVENT_SCANNER_WRAPPER
sudo install -m 0755 "$base_event_scanner_tmp" "$base_event_scanner_script"
rm -f "$base_event_scanner_tmp"

config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"
sudo install -m 0755 "$remote_stage_dir/intents-juno-config-hydrator.sh" "$config_hydrator_script"

sudo systemctl daemon-reload
sudo systemctl restart intents-juno-config-hydrator.service
sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"
sudo pkill -f '/usr/local/bin/intents-juno-dkg-admin-serve.sh' || true
sudo pkill -f 'dkg-admin .* serve' || true
for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
  sudo systemctl reset-failed "$svc" || true
  sudo systemctl restart "$svc"
done
REMOTE_EOF

  for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
    wait_for_remote_service_active "$svc"
  done
fi

if [[ "$dry_run" != "true" ]]; then
  scan_wallet_id="$(production_env_first_value "$merged_env" DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID WITHDRAW_COORDINATOR_JUNO_WALLET_ID || true)"
  scan_url="$(production_env_first_value "$merged_env" DEPOSIT_SCAN_JUNO_SCAN_URL WITHDRAW_FINALIZER_JUNO_SCAN_URL || true)"
  scan_bearer_token="$(production_env_first_value "$merged_env" JUNO_SCAN_BEARER_TOKEN || true)"
  if [[ -n "$scan_wallet_id" ]]; then
    [[ -n "$scan_url" ]] || die "rendered operator env is missing juno-scan URL for wallet $scan_wallet_id"
    sync_remote_scan_wallet "$scan_url" "$scan_wallet_id" "$(tr -d '\r\n' < "$signer_ufvk_file")" "$scan_bearer_token"
  fi
fi

if [[ "$dns_mode" == "public-zone" && -n "$dns_zone_id" && -n "$dns_record_name" && -n "$public_endpoint" ]]; then
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
