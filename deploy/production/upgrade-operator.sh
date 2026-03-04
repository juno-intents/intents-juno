#!/usr/bin/env bash
# shellcheck shell=bash
#
# upgrade-operator.sh — Upgrade operator binaries on an existing node.
#
# Stops services, replaces binaries, restarts, and verifies health.
#
# Usage:
#   upgrade-operator.sh [options]
#
# Options:
#   --operator-host HOST      SSH-accessible operator host (required)
#   --operator-user USER      SSH user (default: ubuntu)
#   --binary-dir DIR          Directory containing new operator binaries (required)
#   --release-url URL         GitHub release URL to download binaries from (alternative to --binary-dir)
#   --dry-run                 Print actions without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../operators/dkg/common.sh
source "$REPO_ROOT/deploy/operators/dkg/common.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
operator_host=""
operator_user="ubuntu"
binary_dir=""
release_url=""
dry_run="false"

services=(checkpoint-signer checkpoint-aggregator tss-host)

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-host)   operator_host="$2"; shift 2 ;;
    --operator-user)   operator_user="$2"; shift 2 ;;
    --binary-dir)      binary_dir="$2"; shift 2 ;;
    --release-url)     release_url="$2"; shift 2 ;;
    --dry-run)         dry_run="true"; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
[[ -n "$operator_host" ]] || die "--operator-host is required"
if [[ -z "$binary_dir" && -z "$release_url" ]]; then
  die "one of --binary-dir or --release-url is required"
fi
if [[ -n "$binary_dir" && ! -d "$binary_dir" ]]; then
  die "binary-dir not found: $binary_dir"
fi

for cmd in ssh scp; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

ssh_target="${operator_user}@${operator_host}"
ssh_opts="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

# ── Step 1: Stop services ────────────────────────────────────────────────────
log "Step 1: Stopping services on $operator_host"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would stop: ${services[*]}"
else
  for svc in "${services[@]}"; do
    ssh $ssh_opts "$ssh_target" "sudo systemctl stop $svc 2>/dev/null || true"
    log "  stopped: $svc"
  done
fi

# ── Step 2: Upload new binaries ──────────────────────────────────────────────
log "Step 2: Uploading new binaries"
if [[ -n "$release_url" && -z "$binary_dir" ]]; then
  # Download from GitHub release
  binary_dir="$(mktemp -d)"
  trap 'rm -rf "$binary_dir"' EXIT

  log "Downloading binaries from $release_url"
  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would download from $release_url"
  else
    for bin in "${services[@]}"; do
      curl -fsSL "${release_url}/${bin}" -o "${binary_dir}/${bin}" || warn "failed to download $bin"
      chmod +x "${binary_dir}/${bin}" 2>/dev/null || true
    done
  fi
fi

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would upload binaries: ${services[*]}"
else
  for bin in "${services[@]}"; do
    if [[ -f "$binary_dir/$bin" ]]; then
      scp $ssh_opts "$binary_dir/$bin" "${ssh_target}:/tmp/$bin"
      ssh $ssh_opts "$ssh_target" "sudo mv /tmp/$bin /usr/local/bin/$bin && sudo chmod +x /usr/local/bin/$bin"
      log "  uploaded: $bin"
    else
      warn "binary not found: $binary_dir/$bin (skipping)"
    fi
  done
fi

# ── Step 3: Restart services ─────────────────────────────────────────────────
log "Step 3: Restarting services"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would restart: ${services[*]}"
else
  ssh $ssh_opts "$ssh_target" "sudo systemctl daemon-reload"
  for svc in "${services[@]}"; do
    ssh $ssh_opts "$ssh_target" "sudo systemctl start $svc"
    log "  started: $svc"
  done
fi

# ── Step 4: Verify health ────────────────────────────────────────────────────
log "Step 4: Verifying services"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would check service status"
else
  sleep 5
  all_healthy="true"
  for svc in "${services[@]}"; do
    status="$(ssh $ssh_opts "$ssh_target" "sudo systemctl is-active $svc" 2>/dev/null || echo "inactive")"
    if [[ "$status" == "active" ]]; then
      log "  $svc: active"
    else
      warn "  $svc: $status"
      all_healthy="false"
    fi
  done

  if [[ "$all_healthy" == "true" ]]; then
    log "All services healthy after upgrade"
  else
    warn "Some services are not healthy — check logs on $operator_host"
  fi
fi

log ""
log "=== Operator upgrade complete ==="
log "Host: $operator_host"
