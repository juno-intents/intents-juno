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
  --known-hosts PATH          Override known_hosts path from manifest
  --secret-contract-file PATH Override operator-secrets.env path from manifest
  --force                     Redeploy even when rollout-state already marks this operator done
  --dry-run                   Print actions without mutating remote state
EOF
}

operator_deploy=""
known_hosts_override=""
secret_contract_override=""
force="false"
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
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
[[ "$environment" == "alpha" ]] && allow_local_resolvers="true"

shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
base_chain_id="$(production_json_required "$shared_manifest_path" '.contracts.base_chain_id')"
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
signer_ufvk_file="$tmp_dir/ufvk.txt"
dkg_peer_hosts_file="$tmp_dir/dkg-peer-hosts.json"
generated_base_relayer_tls_files=()
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
  local cert_b64 key_b64 cert_file key_file listen_addr scheme allowlist

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
  if [[ "$reserved" == "true" && "$success" != "true" ]]; then
    production_rollout_complete "$rollout_state_file" "$operator_id" "failed" "remote deployment failed"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_secret_env"
production_render_operator_stack_env "$shared_manifest_path" "$operator_deploy" "$resolved_secret_env" "$merged_env"
production_render_junocashd_conf "$merged_env" "$junocashd_conf"
prepare_base_relayer_env "$shared_manifest_path" "$merged_env" "$tmp_dir"
printf '%s\n' "$(production_json_required "$shared_manifest_path" '.checkpoint.signer_ufvk | select(type == "string" and length > 0)')" >"$signer_ufvk_file"
mapfile -t peer_operator_manifests < <(find "$peer_manifests_dir" -mindepth 2 -maxdepth 2 -name operator-deploy.json -print | sort)
(( ${#peer_operator_manifests[@]} > 0 )) || die "no peer operator manifests found under $peer_manifests_dir"
jq -s '
  map({
    operator_id: (.operator_id // error("peer operator manifest missing operator_id")),
    host: (
      (.operator_host // .public_endpoint)
      // error("peer operator manifest missing operator_host/public_endpoint")
    )
  })
  | sort_by(.operator_id)
' "${peer_operator_manifests[@]}" >"$dkg_peer_hosts_file"

production_rollout_reserve "$rollout_state_file" "$operator_id"
reserved="true"

remote_stage_dir="/tmp/intents-juno-deploy-$(production_safe_slug "$operator_id")"
files_to_copy=(
  "$dkg_backup_zip"
  "$merged_env"
  "$junocashd_conf"
  "$signer_ufvk_file"
  "$dkg_peer_hosts_file"
  "$shared_manifest_path"
  "$operator_deploy"
  "$REPO_ROOT/deploy/operators/dkg/backup-package.sh"
  "$REPO_ROOT/deploy/operators/dkg/common.sh"
)
for tls_file in "${generated_base_relayer_tls_files[@]}"; do
  files_to_copy+=("$tls_file")
done

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would deploy operator $operator_id via $ssh_target"
else
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
dkg_peer_hosts_file="$remote_stage_dir/dkg-peer-hosts.json"
if [[ -f "$dkg_peer_hosts_file" ]]; then
  admin_config_path="$runtime_dir/bundle/admin-config.json"
  dkg_roster_tmp="$(mktemp)"
  dkg_roster_hash_tmp="$(mktemp)"
  jq --slurpfile peer_hosts "$dkg_peer_hosts_file" '
    .roster.operators |= map(
      . as $op
      | (($peer_hosts[0][] | select(.operator_id == $op.operator_id))
        // error("missing distributed dkg peer host for operator_id " + ($op.operator_id | tostring))) as $peer
      | .grpc_endpoint = (
          ($op.grpc_endpoint | capture("^(?<scheme>https?)://(?<host>[^:/]+)(?::(?<port>[0-9]+))?$")) as $endpoint
          | "\($endpoint.scheme)://\($peer.host):\($endpoint.port)"
        )
    )
  ' "$admin_config_path" >"$dkg_roster_tmp"
  jq -c '
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
  if command -v sha256sum >/dev/null 2>&1; then
    dkg_roster_hash="$(sha256sum "$dkg_roster_hash_tmp" | awk '{print $1}')"
  else
    dkg_roster_hash="$(shasum -a 256 "$dkg_roster_hash_tmp" | awk '{print $1}')"
  fi
  jq --arg roster_hash "$dkg_roster_hash" '.roster_hash_hex = $roster_hash' "$dkg_roster_tmp" >"${dkg_roster_tmp}.final"
  sudo install -m 0640 -o intents-juno -g intents-juno "${dkg_roster_tmp}.final" "$admin_config_path"
  rm -f "$dkg_roster_tmp" "${dkg_roster_tmp}.final" "$dkg_roster_hash_tmp"
fi

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
sudo install -d -m 0755 -o intents-juno -g intents-juno "$runtime_dir/bin"
sudo install -m 0755 "$dkg_admin_downloaded" "$runtime_dir/bin/dkg-admin"
rm -rf "$dkg_stage_dir"
dkg_admin_runtime_bin="$runtime_dir/bin/dkg-admin"
sudo chown -R intents-juno:intents-juno "$runtime_dir"
if sudo test -e /var/lib/intents-juno/juno-scan.db; then
  sudo systemctl stop juno-scan || true
  sudo bash -lc 'chown -R intents-juno:intents-juno /var/lib/intents-juno/juno-scan.db'
fi
sudo test -x "$dkg_admin_runtime_bin" || {
  echo "restored runtime is missing dkg-admin binary: $dkg_admin_runtime_bin" >&2
  exit 1
}

checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"
checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"
dkg_admin_serve_script="/usr/local/bin/intents-juno-dkg-admin-serve.sh"
spendauth_signer_script="/usr/local/bin/intents-juno-spendauth-signer.sh"
withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"
base_event_scanner_script="/usr/local/bin/intents-juno-base-event-scanner.sh"
[[ -f "$checkpoint_signer_script" ]] || {
  echo "checkpoint signer wrapper is missing: $checkpoint_signer_script" >&2
  exit 1
}
[[ -f "$checkpoint_aggregator_script" ]] || {
  echo "checkpoint aggregator wrapper is missing: $checkpoint_aggregator_script" >&2
  exit 1
}
[[ -f "$dkg_admin_serve_script" ]] || {
  echo "dkg-admin wrapper is missing: $dkg_admin_serve_script" >&2
  exit 1
}
[[ -f "$spendauth_signer_script" ]] || {
  echo "spendauth signer wrapper is missing: $spendauth_signer_script" >&2
  exit 1
}
[[ -f "$withdraw_coordinator_script" ]] || {
  echo "withdraw-coordinator wrapper is missing: $withdraw_coordinator_script" >&2
  exit 1
}
[[ -f "$base_event_scanner_script" ]] || {
  echo "base-event-scanner wrapper is missing: $base_event_scanner_script" >&2
  exit 1
}

signer_tmp="$(mktemp)"
cat >"$signer_tmp" <<'EOF_SIGNER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
set -a
source /etc/intents-juno/operator-stack.env
set +a
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
signer_driver="$(printf '%s' "${CHECKPOINT_SIGNER_DRIVER:-local-env}" | tr '[:upper:]' '[:lower:]')"
checkpoint_signer_lease_name="${CHECKPOINT_SIGNER_LEASE_NAME:-checkpoint-signer-${OPERATOR_ADDRESS}}"
checkpoint_signer_help="$(/usr/local/bin/checkpoint-signer --help 2>&1 || true)"
checkpoint_signer_supports_signer_driver=false
if grep -q -- '-signer-driver ' <<<"$checkpoint_signer_help"; then
  checkpoint_signer_supports_signer_driver=true
fi
case "${signer_driver}" in
  ""|local-env)
    signer_driver="local-env"
    if [[ "$checkpoint_signer_supports_signer_driver" == true ]]; then
      signer_args=(--signer-driver "${signer_driver}")
    else
      signer_args=()
    fi
    ;;
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
    echo "checkpoint-signer requires CHECKPOINT_SIGNER_DRIVER to be local-env or aws-kms in /etc/intents-juno/operator-stack.env" >&2
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

if grep -Fq 'export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "$withdraw_coordinator_script" && \
  ! grep -Fq 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "$withdraw_coordinator_script"; then
  sudo sed -i 's|^export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS$|export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS|' "$withdraw_coordinator_script"
fi

base_event_scanner_tmp="$(mktemp)"
cat >"$base_event_scanner_tmp" <<'EOF_BASE_EVENT_SCANNER_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
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
  --withdraw-event-topic "${BASE_EVENT_SCANNER_WITHDRAW_EVENT_TOPIC:-withdrawals.requested.v1}"
  --health-port "${BASE_EVENT_SCANNER_HEALTH_PORT:-18306}"
)

case "${JUNO_QUEUE_KAFKA_TLS:-}" in
  true|1|yes) export JUNO_QUEUE_KAFKA_TLS="true" ;;
esac

exec /usr/local/bin/base-event-scanner "${args[@]}"
EOF_BASE_EVENT_SCANNER_WRAPPER
sudo install -m 0755 "$base_event_scanner_tmp" "$base_event_scanner_script"
rm -f "$base_event_scanner_tmp"

config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"
if [[ -f "$config_hydrator_script" ]] && {
  grep -Fq 'install -m 0600 "$tmp" "$file"' "$config_hydrator_script" ||
  grep -Fq 'install -m 0640 -o root -g intents-juno "$tmp_env" "$stack_env_file"' "$config_hydrator_script"
}; then
  hydrator_tmp="$(mktemp)"
  awk '
    $0 == "  install -m 0600 \"$tmp\" \"$file\"" {
      print "  cat \"$tmp\" > \"$file\""
      print "  chmod 0640 \"$file\""
      next
    }
    $0 == "install -m 0640 -o root -g intents-juno \"$tmp_env\" \"$stack_env_file\"" {
      print "cat \"$tmp_env\" > \"$stack_env_file\""
      print "chmod 0640 \"$stack_env_file\""
      next
    }
    { print }
  ' "$config_hydrator_script" >"$hydrator_tmp"
  sudo install -m 0755 "$hydrator_tmp" "$config_hydrator_script"
  rm -f "$hydrator_tmp"
fi

sudo systemctl daemon-reload
sudo systemctl restart intents-juno-config-hydrator.service
sudo install -m 0600 -o intents-juno -g intents-juno "$remote_stage_dir/ufvk.txt" "$runtime_dir/ufvk.txt"
for svc in junocashd juno-scan checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
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

production_rollout_complete "$rollout_state_file" "$operator_id" "done" "healthy"
success="true"
log "operator deployed: $operator_id"
