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

tmp_dir="$(mktemp -d)"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
merged_env="$tmp_dir/operator-stack.env"
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
production_render_operator_stack_env "$shared_manifest_path" "$resolved_secret_env" "$merged_env"
prepare_base_relayer_env "$shared_manifest_path" "$merged_env" "$tmp_dir"

production_rollout_reserve "$rollout_state_file" "$operator_id"
reserved="true"

remote_stage_dir="/tmp/intents-juno-deploy-$(production_safe_slug "$operator_id")"
files_to_copy=(
  "$dkg_backup_zip"
  "$merged_env"
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

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  sudo awk -v key="$key" -v value="$value" '
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
  sudo install -m 0640 -o root -g intents-juno "$tmp" "$file"
  rm -f "$tmp"
}

sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno || true
sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno/base-relayer || true
sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir" || true

if [[ -f "$remote_stage_dir/base-relayer-server.pem" ]]; then
  sudo install -m 0640 "$remote_stage_dir/base-relayer-server.pem" /etc/intents-juno/base-relayer/server.pem
fi
if [[ -f "$remote_stage_dir/base-relayer-server.key" ]]; then
  sudo install -m 0640 "$remote_stage_dir/base-relayer-server.key" /etc/intents-juno/base-relayer/server.key
fi

while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  key="${line%%=*}"
  value="${line#*=}"
  set_env_value /etc/intents-juno/operator-stack.env "$key" "$value"
done <"$remote_stage_dir/operator-stack.env"

sudo install -m 0640 "$remote_stage_dir/shared-manifest.json" /etc/intents-juno/shared-manifest.json
sudo install -m 0640 "$remote_stage_dir/operator-deploy.json" /etc/intents-juno/operator-deploy.json
sudo install -m 0600 "$remote_stage_dir/$(basename "$remote_stage_dir").zip" /tmp/intents-juno-dkg-backup.zip 2>/dev/null || true
sudo cp "$remote_stage_dir/dkg-backup.zip" /tmp/intents-juno-dkg-backup.zip
sudo bash "$remote_stage_dir/backup-package.sh" restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir" --force
sudo rm -f /tmp/intents-juno-dkg-backup.zip
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
if [[ -e /var/lib/intents-juno/juno-scan.db ]]; then
  sudo chown -R intents-juno:intents-juno /var/lib/intents-juno/juno-scan.db
fi
sudo test -x "$dkg_admin_runtime_bin" || {
  echo "restored runtime is missing dkg-admin binary: $dkg_admin_runtime_bin" >&2
  exit 1
}

checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"
checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"
dkg_admin_serve_script="/usr/local/bin/intents-juno-dkg-admin-serve.sh"
withdraw_coordinator_script="/usr/local/bin/intents-juno-withdraw-coordinator.sh"
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
[[ -f "$withdraw_coordinator_script" ]] || {
  echo "withdraw-coordinator wrapper is missing: $withdraw_coordinator_script" >&2
  exit 1
}

if ! grep -q -- '--base-chain-id "${BASE_CHAIN_ID}"' "$checkpoint_signer_script"; then
  sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_signer_script"
fi
if ! grep -q -- '--bridge-address "${BRIDGE_ADDRESS}"' "$checkpoint_signer_script"; then
  sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_signer_script"
fi
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

if grep -Fq 'export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "$withdraw_coordinator_script" && \
  ! grep -Fq 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "$withdraw_coordinator_script"; then
  sudo sed -i 's|^export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS$|export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS|' "$withdraw_coordinator_script"
fi

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

for svc in checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
  sudo systemctl restart "$svc"
done
REMOTE_EOF

  for svc in checkpoint-signer checkpoint-aggregator dkg-admin-serve tss-host base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer base-event-scanner; do
    status="$(ssh "${SSH_OPTS[@]}" "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
    [[ "$status" == "active" ]] || die "service $svc is not active on $operator_host"
  done
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
