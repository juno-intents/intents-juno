#!/usr/bin/env bash
# shellcheck shell=bash
#
# deploy-operator.sh — Deploy an operator node for the Juno Bridge.
#
# Sets up an EC2 instance with systemd services for:
#   - checkpoint-signer
#   - checkpoint-aggregator
#   - tss-host
#
# Usage:
#   deploy-operator.sh [options]
#
# Options:
#   --shared-config PATH      Path to shared-config.json from coordinator (required)
#   --dkg-backup PATH         Path to DKG backup archive (required)
#   --operator-host HOST      SSH-accessible operator host (required)
#   --operator-user USER      SSH user (default: ubuntu)
#   --binary-dir DIR          Directory containing operator binaries (required)
#   --runtime-dir DIR         Operator runtime directory on host (default: /var/lib/intents-juno/operator-runtime)
#   --aws-profile PROFILE     AWS CLI profile (default: juno)
#   --dry-run                 Print actions without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../operators/dkg/common.sh
source "$REPO_ROOT/deploy/operators/dkg/common.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
shared_config=""
dkg_backup=""
operator_host=""
operator_user="ubuntu"
binary_dir=""
runtime_dir="/var/lib/intents-juno/operator-runtime"
aws_profile="juno"
dry_run="false"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-config)   shared_config="$2"; shift 2 ;;
    --dkg-backup)      dkg_backup="$2"; shift 2 ;;
    --operator-host)   operator_host="$2"; shift 2 ;;
    --operator-user)   operator_user="$2"; shift 2 ;;
    --binary-dir)      binary_dir="$2"; shift 2 ;;
    --runtime-dir)     runtime_dir="$2"; shift 2 ;;
    --aws-profile)     aws_profile="$2"; shift 2 ;;
    --dry-run)         dry_run="true"; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
[[ -n "$shared_config" ]]  || die "--shared-config is required"
[[ -f "$shared_config" ]]  || die "shared-config not found: $shared_config"
[[ -n "$dkg_backup" ]]     || die "--dkg-backup is required"
[[ -f "$dkg_backup" ]]     || die "dkg-backup not found: $dkg_backup"
[[ -n "$operator_host" ]]  || die "--operator-host is required"
[[ -n "$binary_dir" ]]     || die "--binary-dir is required"
[[ -d "$binary_dir" ]]     || die "binary-dir not found: $binary_dir"

for cmd in ssh scp jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

ssh_target="${operator_user}@${operator_host}"
ssh_opts="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

# ── Step 1: Restore DKG keys ─────────────────────────────────────────────────
log "Step 1: Uploading DKG backup to $operator_host"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would upload DKG backup and restore"
else
  scp $ssh_opts "$dkg_backup" "${ssh_target}:/tmp/dkg-backup.tar.gz"
  # shellcheck disable=SC2029
  ssh $ssh_opts "$ssh_target" bash -s <<'RESTORE_EOF'
set -euo pipefail
sudo mkdir -p /var/lib/intents-juno/operator-runtime
cd /var/lib/intents-juno/operator-runtime
sudo tar xzf /tmp/dkg-backup.tar.gz
sudo rm -f /tmp/dkg-backup.tar.gz
echo "DKG keys restored"
RESTORE_EOF
  log "DKG keys restored on $operator_host"
fi

# ── Step 2: Upload binaries ──────────────────────────────────────────────────
log "Step 2: Uploading operator binaries"
binaries=(checkpoint-signer checkpoint-aggregator tss-host)

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would upload binaries: ${binaries[*]}"
else
  for bin in "${binaries[@]}"; do
    if [[ -f "$binary_dir/$bin" ]]; then
      scp $ssh_opts "$binary_dir/$bin" "${ssh_target}:/tmp/$bin"
      ssh $ssh_opts "$ssh_target" "sudo mv /tmp/$bin /usr/local/bin/$bin && sudo chmod +x /usr/local/bin/$bin"
      log "  uploaded: $bin"
    else
      warn "binary not found: $binary_dir/$bin (skipping)"
    fi
  done
fi

# ── Step 3: Upload shared config ─────────────────────────────────────────────
log "Step 3: Uploading shared configuration"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would upload shared-config.json"
else
  scp $ssh_opts "$shared_config" "${ssh_target}:/tmp/shared-config.json"
  ssh $ssh_opts "$ssh_target" "sudo mv /tmp/shared-config.json ${runtime_dir}/shared-config.json"
  log "Shared config uploaded"
fi

# ── Step 4: Install systemd services ─────────────────────────────────────────
log "Step 4: Configuring systemd services"

postgres_dsn="$(jq -r '.postgres_dsn // empty' "$shared_config")"
kafka_brokers="$(jq -r '.kafka_brokers // empty' "$shared_config")"
ipfs_api_url="$(jq -r '.ipfs_api_url // empty' "$shared_config")"
bridge_address="$(jq -r '.contracts.bridge // empty' "$shared_config")"

generate_service() {
  local name="$1"
  local exec_start="$2"

  cat <<EOF
[Unit]
Description=Juno Bridge $name
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
ExecStart=$exec_start
Restart=always
RestartSec=5
LimitNOFILE=65535
Environment=JUNO_QUEUE_KAFKA_TLS=true

[Install]
WantedBy=multi-user.target
EOF
}

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would install systemd services"
else
  # Create checkpoint-signer service
  generate_service "checkpoint-signer" \
    "/usr/local/bin/checkpoint-signer --runtime-dir ${runtime_dir} --postgres-dsn '${postgres_dsn}' --kafka-brokers '${kafka_brokers}' --ipfs-api-url '${ipfs_api_url}'" \
    | ssh $ssh_opts "$ssh_target" "sudo tee /etc/systemd/system/checkpoint-signer.service > /dev/null"

  # Create checkpoint-aggregator service
  generate_service "checkpoint-aggregator" \
    "/usr/local/bin/checkpoint-aggregator --runtime-dir ${runtime_dir} --postgres-dsn '${postgres_dsn}' --kafka-brokers '${kafka_brokers}' --ipfs-api-url '${ipfs_api_url}'" \
    | ssh $ssh_opts "$ssh_target" "sudo tee /etc/systemd/system/checkpoint-aggregator.service > /dev/null"

  # Create tss-host service
  generate_service "tss-host" \
    "/usr/local/bin/tss-host --runtime-dir ${runtime_dir} --postgres-dsn '${postgres_dsn}' --kafka-brokers '${kafka_brokers}'" \
    | ssh $ssh_opts "$ssh_target" "sudo tee /etc/systemd/system/tss-host.service > /dev/null"

  # Reload and start services
  ssh $ssh_opts "$ssh_target" bash -s <<'SYSTEMD_EOF'
set -euo pipefail
sudo systemctl daemon-reload
for svc in checkpoint-signer checkpoint-aggregator tss-host; do
  sudo systemctl enable "$svc"
  sudo systemctl restart "$svc"
  echo "Started: $svc"
done
SYSTEMD_EOF
  log "Systemd services installed and started"
fi

# ── Step 5: Verify health ────────────────────────────────────────────────────
log "Step 5: Verifying operator health"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would check health endpoints"
else
  sleep 5
  for svc in checkpoint-signer checkpoint-aggregator tss-host; do
    status="$(ssh $ssh_opts "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
    if [[ "$status" == "active" ]]; then
      log "  $svc: active"
    else
      warn "  $svc: $status"
    fi
  done
fi

log ""
log "=== Operator deployment complete ==="
log "Host: $operator_host"
log "Runtime: $runtime_dir"
log "Services: checkpoint-signer, checkpoint-aggregator, tss-host"
