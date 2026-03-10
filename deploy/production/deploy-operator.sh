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
  --dry-run                   Print actions without mutating remote state
EOF
}

operator_deploy=""
known_hosts_override=""
secret_contract_override=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-deploy) operator_deploy="$2"; shift 2 ;;
    --known-hosts) known_hosts_override="$2"; shift 2 ;;
    --secret-contract-file) secret_contract_override="$2"; shift 2 ;;
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
  log "operator $operator_id already marked done in rollout state"
  exit 0
fi

ssh_target="${operator_user}@${operator_host}"
SSH_OPTS=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts_file" -o ConnectTimeout=10)
SCP_OPTS=("${SSH_OPTS[@]}")

tmp_dir="$(mktemp -d)"
resolved_secret_env="$tmp_dir/operator-secrets.resolved.env"
merged_env="$tmp_dir/operator-stack.env"
success="false"
reserved="false"

cleanup() {
  if [[ "$reserved" == "true" && "$success" != "true" ]]; then
    production_rollout_complete "$rollout_state_file" "$operator_id" "failed" "remote deployment failed"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_secret_env"
production_render_operator_stack_env "$shared_manifest_path" "$resolved_secret_env" "$merged_env"

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

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would deploy operator $operator_id via $ssh_target"
else
  ssh "${SSH_OPTS[@]}" "$ssh_target" "rm -rf '$remote_stage_dir' && mkdir -p '$remote_stage_dir'"
  for source_path in "${files_to_copy[@]}"; do
    scp "${SCP_OPTS[@]}" "$source_path" "$ssh_target:$remote_stage_dir/$(basename "$source_path")"
  done

  ssh "${SSH_OPTS[@]}" "$ssh_target" bash -s -- "$remote_stage_dir" "$runtime_dir" <<'REMOTE_EOF'
set -euo pipefail

remote_stage_dir="$1"
runtime_dir="$2"

set_env_value() {
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
  sudo install -m 0640 "$tmp" "$file"
  rm -f "$tmp"
}

sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno || true
sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir" || true

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
sudo bash "$remote_stage_dir/backup-package.sh" restore --package /tmp/intents-juno-dkg-backup.zip --workdir "$runtime_dir"
sudo rm -f /tmp/intents-juno-dkg-backup.zip

sudo systemctl restart intents-juno-config-hydrator.service
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
