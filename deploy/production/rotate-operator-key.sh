#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

operator_deploy=""
known_hosts_override=""
secret_contract_override=""
output_dir=""
dry_run="false"

rotation_services=(
  checkpoint-signer
  checkpoint-aggregator
  dkg-admin-serve
  tss-host
  base-relayer
  deposit-relayer
  withdraw-coordinator
  withdraw-finalizer
  base-event-scanner
)

usage() {
  cat <<'EOF'
Usage:
  rotate-operator-key.sh --operator-deploy PATH [options]

Options:
  --operator-deploy PATH      Operator deploy manifest (required)
  --known-hosts PATH          Override known_hosts path from manifest
  --secret-contract-file PATH Override operator-secrets.env path from manifest
  --output-dir DIR            Evidence output directory
  --dry-run                   Render evidence without mutating remote state
EOF
}

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

remote_env_value() {
  local key="$1"
  ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo awk -F= '/^${key}=/{print substr(\$0, index(\$0, \"=\") + 1); exit}' /etc/intents-juno/operator-stack.env" 2>/dev/null || true
}

capture_remote_operator_evidence() {
  local target="$1"
  local signer_driver signer_kms_key_id operator_address services_json status svc

  signer_driver="$(remote_env_value "CHECKPOINT_SIGNER_DRIVER")"
  signer_kms_key_id="$(remote_env_value "CHECKPOINT_SIGNER_KMS_KEY_ID")"
  operator_address="$(remote_env_value "OPERATOR_ADDRESS")"
  services_json='{}'
  for svc in "${rotation_services[@]}"; do
    status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo inactive)"
    services_json="$(jq --arg svc "$svc" --arg status "$status" '. + {($svc): $status}' <<<"$services_json")"
  done

  jq -n \
    --arg version "1" \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg operator_id "$operator_id" \
    --arg operator_host "$operator_host" \
    --arg driver "$signer_driver" \
    --arg kms_key_id "$signer_kms_key_id" \
    --arg operator_address "$operator_address" \
    --argjson services "$services_json" \
    '{
      version: $version,
      generated_at: $generated_at,
      operator_id: $operator_id,
      operator_host: $operator_host,
      signer: {
        driver: $driver,
        kms_key_id: (if $kms_key_id == "" then null else $kms_key_id end),
        operator_address: (if $operator_address == "" then null else $operator_address end)
      },
      services: $services
    }' >"$target"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
    --known-hosts) known_hosts_override="$2"; shift 2 ;;
    --secret-contract-file) secret_contract_override="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$operator_deploy" ]] || die "--operator-deploy is required"
[[ -f "$operator_deploy" ]] || die "operator deploy manifest not found: $operator_deploy"
for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  for cmd in ssh scp; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
environment="$(production_json_required "$operator_deploy" '.environment | select(type == "string" and length > 0)')"
allow_local_resolvers="false"
[[ "$environment" == "alpha" ]] && allow_local_resolvers="true"

shared_manifest_path="$(production_abs_path "$manifest_dir" "$(production_json_required "$operator_deploy" '.shared_manifest_path | select(type == "string" and length > 0)')")"
[[ -f "$shared_manifest_path" ]] || die "shared manifest not found: $shared_manifest_path"
operator_id="$(production_json_required "$operator_deploy" '.operator_id | select(type == "string" and length > 0)')"
operator_host="$(production_json_required "$operator_deploy" '.operator_host | select(type == "string" and length > 0)')"
operator_user="$(production_json_required "$operator_deploy" '.operator_user | select(type == "string" and length > 0)')"
aws_profile="$(production_json_optional "$operator_deploy" '.aws_profile')"
aws_region="$(production_json_optional "$operator_deploy" '.aws_region')"

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

if [[ -z "$output_dir" ]]; then
  output_dir="$manifest_dir/rotation-evidence/$(date -u +'%Y%m%dT%H%M%SZ')"
fi
mkdir -p "$output_dir"

ssh_target="${operator_user}@${operator_host}"
SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
SCP_OPTS=("${SSH_OPTS[@]}")

tmp_dir="$(mktemp -d)"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
merged_env="$tmp_dir/operator-stack.env"
junocashd_conf="$tmp_dir/junocashd.conf"
config_hydrator_stage="$tmp_dir/intents-juno-config-hydrator.sh"
generated_base_relayer_tls_files=()

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_secret_env"
production_render_operator_stack_env "$shared_manifest_path" "$operator_deploy" "$resolved_secret_env" "$merged_env"
production_render_junocashd_conf "$merged_env" "$junocashd_conf"
extract_build_runbook_block \
  "$SCRIPT_DIR/../shared/runbooks/build-operator-stack-ami.sh" \
  "cat > /tmp/intents-juno-config-hydrator.sh <<'EOF_CONFIG_HYDRATOR'" \
  "EOF_CONFIG_HYDRATOR" \
  "$config_hydrator_stage"
chmod 0755 "$config_hydrator_stage"
prepare_base_relayer_env "$shared_manifest_path" "$merged_env" "$tmp_dir"

if [[ "$dry_run" == "true" ]]; then
  jq -n \
    --arg version "1" \
    --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg operator_id "$operator_id" \
    --arg operator_host "$operator_host" \
    '{
      version: $version,
      generated_at: $generated_at,
      operator_id: $operator_id,
      operator_host: $operator_host,
      signer: {
        driver: "dry-run",
        kms_key_id: null,
        operator_address: null
      },
      services: {}
    }' >"$output_dir/pre.json"
  cp "$output_dir/pre.json" "$output_dir/post.json"
  log "[DRY RUN] rendered rotation evidence in $output_dir"
  exit 0
fi

capture_remote_operator_evidence "$output_dir/pre.json"

remote_stage_dir="/tmp/intents-juno-rotate-$(production_safe_slug "$operator_id")"
files_to_copy=("$merged_env" "$junocashd_conf" "$config_hydrator_stage")
for tls_file in "${generated_base_relayer_tls_files[@]}"; do
  files_to_copy+=("$tls_file")
done

ssh "${SSH_OPTS[@]}" "$ssh_target" "rm -rf '$remote_stage_dir' && mkdir -p '$remote_stage_dir'"
for source_path in "${files_to_copy[@]}"; do
  scp "${SCP_OPTS[@]}" "$source_path" "$ssh_target:$remote_stage_dir/$(basename "$source_path")"
done

ssh "${SSH_OPTS[@]}" "$ssh_target" bash -s -- "$remote_stage_dir" <<'REMOTE_EOF'
set -euo pipefail

remote_stage_dir="$1"

sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno || true
sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno/base-relayer || true

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
config_hydrator_script="/usr/local/bin/intents-juno-config-hydrator.sh"
sudo install -m 0755 "$remote_stage_dir/intents-juno-config-hydrator.sh" "$config_hydrator_script"
sudo systemctl restart intents-juno-config-hydrator.service
for svc in checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
  sudo systemctl restart "$svc"
done
REMOTE_EOF

for svc in "${rotation_services[@]}"; do
  status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo inactive)"
  [[ "$status" == "active" ]] || die "service $svc is not active on $operator_host"
done

capture_remote_operator_evidence "$output_dir/post.json"
log "operator key rotation staged for $operator_id; evidence written to $output_dir"
