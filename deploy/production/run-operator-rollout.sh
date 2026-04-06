#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run-operator-rollout.sh --stage-dir PATH --runtime-dir PATH
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'run-operator-rollout: %s\n' "$*" >&2
}

stage_dir=""
runtime_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage-dir)
      stage_dir="$2"
      shift 2
      ;;
    --runtime-dir)
      runtime_dir="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$stage_dir" ]] || die "--stage-dir is required"
[[ -d "$stage_dir" ]] || die "stage dir not found: $stage_dir"
[[ -n "$runtime_dir" ]] || die "--runtime-dir is required"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

for cmd in jq sudo systemctl; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

operator_stack_env="$stage_dir/operator-stack.env"
operator_stack_hydrator_env="$stage_dir/operator-stack-hydrator.env"
junocashd_conf="$stage_dir/junocashd.conf"
shared_manifest_path="$stage_dir/shared-manifest.json"
operator_deploy="$stage_dir/operator-deploy.json"
backup_package_script="$stage_dir/backup-package.sh"
dkg_common_stage="$stage_dir/common.sh"
config_hydrator_stage="$stage_dir/intents-juno-config-hydrator.sh"
signer_ufvk_file="$stage_dir/ufvk.txt"
dkg_peer_hosts_file="$stage_dir/dkg-peer-hosts.json"

[[ -f "$operator_stack_env" ]] || die "missing stage file: $operator_stack_env"
[[ -f "$shared_manifest_path" ]] || die "missing stage file: $shared_manifest_path"
[[ -f "$operator_deploy" ]] || die "missing stage file: $operator_deploy"
[[ -f "$backup_package_script" ]] || die "missing stage file: $backup_package_script"
[[ -f "$dkg_common_stage" ]] || die "missing stage file: $dkg_common_stage"

restore_package_path=""
cleanup_restore_package="false"

cleanup() {
  if [[ "$cleanup_restore_package" == "true" && -n "$restore_package_path" ]]; then
    rm -f "$restore_package_path" 2>/dev/null || true
  fi
}
trap cleanup EXIT

ensure_service_user() {
  if ! getent group intents-juno >/dev/null 2>&1; then
    sudo groupadd --system intents-juno
  fi
  if ! id -u intents-juno >/dev/null 2>&1; then
    sudo useradd --system --create-home --home-dir /var/lib/intents-juno --shell /usr/sbin/nologin --gid intents-juno intents-juno
  fi

  sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno
  sudo install -d -m 0750 -o root -g intents-juno /etc/intents-juno/base-relayer
  sudo install -d -m 0750 -o intents-juno -g intents-juno "$runtime_dir"
}

stage_optional_tls_files() {
  if [[ -f "$stage_dir/base-relayer-server.pem" ]]; then
    sudo install -m 0640 "$stage_dir/base-relayer-server.pem" /etc/intents-juno/base-relayer/server.pem
  fi
  if [[ -f "$stage_dir/base-relayer-server.key" ]]; then
    sudo install -m 0640 "$stage_dir/base-relayer-server.key" /etc/intents-juno/base-relayer/server.key
  fi
  if [[ -f "$stage_dir/dkg-server.pem" ]]; then
    sudo install -m 0640 -o root -g intents-juno "$stage_dir/dkg-server.pem" "$runtime_dir/bundle/tls/server.pem"
  fi
  if [[ -f "$stage_dir/dkg-server.key" ]]; then
    sudo install -m 0600 -o intents-juno -g intents-juno "$stage_dir/dkg-server.key" "$runtime_dir/bundle/tls/server.key"
  fi
  if [[ -f "$stage_dir/ca.pem" ]]; then
    sudo install -m 0640 -o root -g intents-juno "$stage_dir/ca.pem" "$runtime_dir/bundle/tls/ca.pem"
  fi
  if [[ -f "$stage_dir/coordinator-client.pem" ]]; then
    sudo install -m 0640 -o root -g intents-juno "$stage_dir/coordinator-client.pem" "$runtime_dir/bundle/tls/coordinator-client.pem"
  fi
  if [[ -f "$stage_dir/coordinator-client.key" ]]; then
    sudo install -m 0600 -o intents-juno -g intents-juno "$stage_dir/coordinator-client.key" "$runtime_dir/bundle/tls/coordinator-client.key"
  fi
}

install_stage_files() {
  if sudo test -f /etc/intents-juno/operator-stack.env; then
    sudo sed -i '/^CHECKPOINT_SIGNER_PRIVATE_KEY=/d' /etc/intents-juno/operator-stack.env
  fi
  sudo rm -f /etc/intents-juno/checkpoint-signer.key
  sudo install -m 0640 -o root -g intents-juno "$operator_stack_env" /etc/intents-juno/operator-stack.env
  if [[ -f "$operator_stack_hydrator_env" ]]; then
    sudo install -m 0600 "$operator_stack_hydrator_env" /etc/intents-juno/operator-stack-hydrator.env
  fi
  if [[ -f "$junocashd_conf" ]]; then
    sudo install -m 0640 -o root -g intents-juno "$junocashd_conf" /etc/intents-juno/junocashd.conf
  fi
  sudo install -m 0640 "$shared_manifest_path" /etc/intents-juno/shared-manifest.json
  sudo install -m 0640 "$operator_deploy" /etc/intents-juno/operator-deploy.json
  if [[ -f "$config_hydrator_stage" ]]; then
    sudo install -m 0755 "$config_hydrator_stage" /usr/local/bin/intents-juno-config-hydrator.sh
  fi
  for wrapper_name in \
    intents-juno-checkpoint-signer.sh \
    intents-juno-checkpoint-aggregator.sh \
    intents-juno-deposit-relayer.sh \
    intents-juno-multikey-extend-signer.sh \
    intents-juno-withdraw-coordinator.sh \
    intents-juno-withdraw-finalizer.sh \
    intents-juno-base-event-scanner.sh; do
    if [[ -f "$stage_dir/$wrapper_name" ]]; then
      sudo install -m 0755 "$stage_dir/$wrapper_name" "/usr/local/bin/$wrapper_name"
    fi
  done
}

fetch_restore_package() {
  local runtime_material_mode runtime_material_bucket runtime_material_key runtime_material_region

  runtime_material_mode="$(jq -r '.runtime_material_ref.mode // empty' "$operator_deploy")"
  [[ "$runtime_material_mode" == "s3-kms-zip" ]] || die "operator deploy manifest must set runtime_material_ref.mode=s3-kms-zip"
  have_cmd aws || die "required command not found: aws"
  runtime_material_bucket="$(jq -r '.runtime_material_ref.bucket // empty' "$operator_deploy")"
  runtime_material_key="$(jq -r '.runtime_material_ref.key // empty' "$operator_deploy")"
  runtime_material_region="$(jq -r '.runtime_material_ref.region // empty' "$operator_deploy")"
  [[ -n "$runtime_material_bucket" ]] || die "runtime_material_ref.bucket is required"
  [[ -n "$runtime_material_key" ]] || die "runtime_material_ref.key is required"
  [[ -n "$runtime_material_region" ]] || die "runtime_material_ref.region is required"
  restore_package_path="$stage_dir/runtime-material.zip"
  AWS_PAGER="" aws --region "$runtime_material_region" s3 cp "s3://${runtime_material_bucket}/${runtime_material_key}" "$restore_package_path" >/dev/null
  cleanup_restore_package="true"
}

restore_runtime() {
  sudo bash "$backup_package_script" restore --package "$restore_package_path" --workdir "$runtime_dir" --force
  sudo chown -R intents-juno:intents-juno "$runtime_dir"
}

ensure_runtime_dkg_admin_binary() {
  local dkg_stage_dir dkg_admin_downloaded
  if sudo test -x "$runtime_dir/bin/dkg-admin"; then
    return 0
  fi

  # Some older runtime-material bundles omitted payload/bin/dkg-admin. Repair
  # them from the published dkg-admin release rather than requiring a re-export.
  # shellcheck disable=SC1090
  source "$dkg_common_stage"

  dkg_stage_dir="$(mktemp -d)"
  export JUNO_DKG_DISABLE_SOURCE_BUILD="true"
  dkg_admin_downloaded="$(ensure_dkg_binary "dkg-admin" "${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}" "$dkg_stage_dir")"
  sudo install -d -m 0755 "$runtime_dir/bin"
  sudo install -m 0755 "$dkg_admin_downloaded" "$runtime_dir/bin/dkg-admin"
  sudo chown intents-juno:intents-juno "$runtime_dir/bin/dkg-admin"
  rm -rf "$dkg_stage_dir"
}

compute_dkg_roster_hash_hex() {
  local roster_json="$1"
  local canonical

  canonical="$(printf '%s' "$roster_json" | jq -c '
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
  ')"
  printf '%s' "$canonical" | sha256sum | awk '{print $1}'
}

rewrite_dkg_roster() {
  local admin_config_path dkg_roster_tmp dkg_roster_hash_tmp dkg_roster_canonical
  [[ -f "$dkg_peer_hosts_file" ]] || return 0

  admin_config_path="$runtime_dir/bundle/admin-config.json"
  [[ -f "$admin_config_path" ]] || die "missing admin config after restore: $admin_config_path"

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
  dkg_roster_canonical="$(jq -c '.roster' "$dkg_roster_tmp")"
  compute_dkg_roster_hash_hex "$dkg_roster_canonical" >"$dkg_roster_hash_tmp"
  jq --arg roster_hash "$(cat "$dkg_roster_hash_tmp")" '.roster_hash_hex = $roster_hash' "$dkg_roster_tmp" >"${dkg_roster_tmp}.next"
  mv "${dkg_roster_tmp}.next" "$dkg_roster_tmp"
  sudo install -m 0640 -o intents-juno -g intents-juno "$dkg_roster_tmp" "$admin_config_path"
  rm -f "$dkg_roster_tmp" "$dkg_roster_hash_tmp"
}

hydrate_and_restart() {
  local services=(
    junocashd
    juno-scan
    juno-scan-backfill
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
  if [[ -f "$signer_ufvk_file" ]]; then
    sudo install -m 0600 -o intents-juno -g intents-juno "$signer_ufvk_file" "$runtime_dir/ufvk.txt"
  fi

  sudo systemctl daemon-reload
  if systemctl list-unit-files intents-juno-config-hydrator.service >/dev/null 2>&1; then
    sudo systemctl enable intents-juno-config-hydrator.service >/dev/null || true
    sudo systemctl restart intents-juno-config-hydrator.service
  else
    sudo /usr/local/bin/intents-juno-config-hydrator.sh
  fi

  for svc in "${services[@]}"; do
    sudo systemctl reset-failed "$svc" || true
    sudo systemctl restart "$svc"
  done
}

ensure_service_user
install_stage_files
fetch_restore_package
restore_runtime
ensure_runtime_dkg_admin_binary
stage_optional_tls_files
rewrite_dkg_roster
hydrate_and_restart
log "rollout complete"
