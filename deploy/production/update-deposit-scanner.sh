#!/usr/bin/env bash
# shellcheck shell=bash
#
# update-deposit-scanner.sh — Enable/update deposit auto-scanner on a running operator.
#
# Updates DEPOSIT_SCAN_* env vars in /etc/intents-juno/operator-stack.env
# and restarts deposit-relayer.service.
#
# Usage:
#   update-deposit-scanner.sh [options]
#
# Options:
#   --operator-host HOST       SSH-accessible operator host (required)
#   --operator-user USER       SSH user (default: ubuntu)
#   --juno-scan-url URL        juno-scan base URL (required)
#   --juno-scan-wallet-id ID   juno-scan wallet ID (required)
#   --juno-rpc-url URL         junocashd JSON-RPC URL (required)
#   --poll-interval DUR        scanner poll interval (default: 15s)
#   --dry-run                  Print actions without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../operators/dkg/common.sh
source "$REPO_ROOT/deploy/operators/dkg/common.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
operator_host=""
operator_user="ubuntu"
juno_scan_url=""
juno_scan_wallet_id=""
juno_rpc_url=""
poll_interval="15s"
dry_run="false"

env_file="/etc/intents-juno/operator-stack.env"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-host)       operator_host="$2"; shift 2 ;;
    --operator-user)       operator_user="$2"; shift 2 ;;
    --juno-scan-url)       juno_scan_url="$2"; shift 2 ;;
    --juno-scan-wallet-id) juno_scan_wallet_id="$2"; shift 2 ;;
    --juno-rpc-url)        juno_rpc_url="$2"; shift 2 ;;
    --poll-interval)       poll_interval="$2"; shift 2 ;;
    --dry-run)             dry_run="true"; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
[[ -n "$operator_host" ]] || die "--operator-host is required"
[[ -n "$juno_scan_url" ]] || die "--juno-scan-url is required"
[[ -n "$juno_scan_wallet_id" ]] || die "--juno-scan-wallet-id is required"
[[ -n "$juno_rpc_url" ]] || die "--juno-rpc-url is required"

for cmd in ssh; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

ssh_target="${operator_user}@${operator_host}"
ssh_opts="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

# ── Helper: set_env_on_host ───────────────────────────────────────────────────
# Updates or appends KEY=VALUE in the remote env file.
set_env_on_host() {
  local key="$1" value="$2"
  # shellcheck disable=SC2087
  ssh $ssh_opts "$ssh_target" bash -s <<REMOTE_EOF
set -euo pipefail
file="$env_file"
key="$key"
value="$value"
if grep -q "^\${key}=" "\$file" 2>/dev/null; then
  sudo sed -i "s|^\${key}=.*|\${key}=\${value}|" "\$file"
else
  echo "\${key}=\${value}" | sudo tee -a "\$file" >/dev/null
fi
REMOTE_EOF
}

# ── Step 1: Backup env file ──────────────────────────────────────────────────
log "Step 1: Backing up $env_file on $operator_host"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would backup $env_file"
else
  ssh $ssh_opts "$ssh_target" "sudo cp $env_file ${env_file}.bak.\$(date +%Y%m%d%H%M%S)"
  log "  backup created"
fi

# ── Step 2: Update DEPOSIT_SCAN_* vars ───────────────────────────────────────
log "Step 2: Updating scanner env vars"

declare -A scan_vars=(
  [DEPOSIT_SCAN_ENABLED]="true"
  [DEPOSIT_SCAN_JUNO_SCAN_URL]="$juno_scan_url"
  [DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID]="$juno_scan_wallet_id"
  [DEPOSIT_SCAN_JUNO_RPC_URL]="$juno_rpc_url"
  [DEPOSIT_SCAN_POLL_INTERVAL]="$poll_interval"
)

for key in DEPOSIT_SCAN_ENABLED DEPOSIT_SCAN_JUNO_SCAN_URL DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID DEPOSIT_SCAN_JUNO_RPC_URL DEPOSIT_SCAN_POLL_INTERVAL; do
  value="${scan_vars[$key]}"
  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would set $key=$value"
  else
    set_env_on_host "$key" "$value"
    log "  set $key=$value"
  fi
done

# ── Step 3: Remove deposits.event.v1 from queue topics if present ────────────
log "Step 3: Cleaning queue topics"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would remove deposits.event.v1 from DEPOSIT_RELAYER_QUEUE_TOPICS if present"
else
  # shellcheck disable=SC2087
  ssh $ssh_opts "$ssh_target" bash -s <<'REMOTE_TOPICS_EOF'
set -euo pipefail
file="/etc/intents-juno/operator-stack.env"
current="$(grep '^DEPOSIT_RELAYER_QUEUE_TOPICS=' "$file" | head -1 | cut -d= -f2-)"
if [[ "$current" == *"deposits.event.v1"* ]]; then
  cleaned="$(echo "$current" | sed 's/,*deposits\.event\.v1,*//' | sed 's/^,//;s/,$//')"
  [[ -n "$cleaned" ]] || cleaned="checkpoints.packages.v1"
  sudo sed -i "s|^DEPOSIT_RELAYER_QUEUE_TOPICS=.*|DEPOSIT_RELAYER_QUEUE_TOPICS=${cleaned}|" "$file"
  echo "removed deposits.event.v1, topics now: $cleaned"
else
  echo "deposits.event.v1 not present, no change needed"
fi
REMOTE_TOPICS_EOF
fi

# ── Step 4: Restart deposit-relayer ──────────────────────────────────────────
log "Step 4: Restarting deposit-relayer.service"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would restart deposit-relayer.service"
else
  ssh $ssh_opts "$ssh_target" "sudo systemctl restart deposit-relayer.service"
  log "  restarted deposit-relayer.service"
fi

# ── Step 5: Verify service is active ─────────────────────────────────────────
log "Step 5: Verifying deposit-relayer.service"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would verify deposit-relayer.service after 5s"
else
  sleep 5
  if ssh $ssh_opts "$ssh_target" "systemctl is-active deposit-relayer.service" | grep -q '^active$'; then
    log "  deposit-relayer.service is active"
  else
    warn "deposit-relayer.service is NOT active — check logs with: ssh $ssh_target journalctl -u deposit-relayer.service -n 50"
  fi
fi

log "Done."
