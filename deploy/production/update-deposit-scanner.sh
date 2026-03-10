#!/usr/bin/env bash
# shellcheck shell=bash
#
# update-deposit-scanner.sh — Update deposit scanner settings with strict host validation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

operator_host=""
operator_user="ubuntu"
operator_port="22"
known_hosts_file=""
ssh_private_key=""
operator_deploy=""
juno_scan_url=""
juno_scan_wallet_id=""
juno_rpc_url=""
poll_interval="15s"
dry_run="false"

env_file="/etc/intents-juno/operator-stack.env"

usage() {
  cat <<'EOF'
Usage:
  update-deposit-scanner.sh [options]

Options:
  --operator-deploy PATH
  --operator-host HOST
  --operator-user USER
  --operator-port PORT
  --known-hosts PATH
  --ssh-private-key PATH
  --juno-scan-url URL
  --juno-scan-wallet-id ID
  --juno-rpc-url URL
  --poll-interval DUR
  --dry-run
EOF
}

build_ssh_opts() {
  SSH_OPTS=(
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$known_hosts_file"
    -o GlobalKnownHostsFile=/dev/null
    -o ConnectTimeout=10
  )
  if [[ -n "$ssh_private_key" ]]; then
    [[ -f "$ssh_private_key" ]] || die "ssh private key not found: $ssh_private_key"
    SSH_OPTS=(-i "$ssh_private_key" "${SSH_OPTS[@]}")
  fi
}

set_env_on_host() {
  local key="$1"
  local value="$2"
  ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" bash -s -- "$env_file" "$key" "$value" <<'REMOTE_EOF'
set -euo pipefail
file="$1"
key="$2"
value="$3"
tmp="$(mktemp)"
sudo awk -v key="$key" -v value="$value" '
  BEGIN {
    updated = 0
  }
  index($0, key "=") == 1 {
    print key "=" value
    updated = 1
    next
  }
  {
    print
  }
  END {
    if (updated == 0) {
      print key "=" value
    }
  }
' "$file" >"$tmp"
sudo install -m 0640 "$tmp" "$file"
rm -f "$tmp"
REMOTE_EOF
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --operator-deploy)
        operator_deploy="$2"
        shift 2
        ;;
      --operator-host)
        operator_host="$2"
        shift 2
        ;;
      --operator-user)
        operator_user="$2"
        shift 2
        ;;
      --operator-port)
        operator_port="$2"
        shift 2
        ;;
      --known-hosts)
        known_hosts_file="$2"
        shift 2
        ;;
      --ssh-private-key)
        ssh_private_key="$2"
        shift 2
        ;;
      --juno-scan-url)
        juno_scan_url="$2"
        shift 2
        ;;
      --juno-scan-wallet-id)
        juno_scan_wallet_id="$2"
        shift 2
        ;;
      --juno-rpc-url)
        juno_rpc_url="$2"
        shift 2
        ;;
      --poll-interval)
        poll_interval="$2"
        shift 2
        ;;
      --dry-run)
        dry_run="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done

  if [[ -n "$operator_deploy" ]]; then
    [[ -f "$operator_deploy" ]] || die "operator deploy manifest not found: $operator_deploy"
    local manifest_dir
    manifest_dir="$(cd "$(dirname "$operator_deploy")" && pwd)"
    operator_host="$(jq -er '.operator_host | select(type == "string" and length > 0)' "$operator_deploy")"
    operator_user="$(jq -er '.operator_user | select(type == "string" and length > 0)' "$operator_deploy")"
    known_hosts_file="${known_hosts_file:-$(jq -er '.known_hosts_file | select(type == "string" and length > 0)' "$operator_deploy")}"
    if [[ "$known_hosts_file" != /* ]]; then
      known_hosts_file="$manifest_dir/$known_hosts_file"
    fi
  fi

  [[ -n "$operator_host" ]] || die "--operator-host is required"
  [[ -n "$known_hosts_file" ]] || die "--known-hosts is required"
  [[ -f "$known_hosts_file" ]] || die "known-hosts file not found: $known_hosts_file"
  [[ -n "$juno_scan_url" ]] || die "--juno-scan-url is required"
  [[ -n "$juno_scan_wallet_id" ]] || die "--juno-scan-wallet-id is required"
  [[ -n "$juno_rpc_url" ]] || die "--juno-rpc-url is required"

  have_cmd ssh || die "required command not found: ssh"
  build_ssh_opts "$known_hosts_file" "$ssh_private_key"

  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would update deposit scanner env vars on $operator_host"
    exit 0
  fi

  set_env_on_host DEPOSIT_SCAN_ENABLED true
  set_env_on_host DEPOSIT_SCAN_JUNO_SCAN_URL "$juno_scan_url"
  set_env_on_host DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID "$juno_scan_wallet_id"
  set_env_on_host DEPOSIT_SCAN_JUNO_RPC_URL "$juno_rpc_url"
  set_env_on_host DEPOSIT_SCAN_POLL_INTERVAL "$poll_interval"

  ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" \
    "sudo systemctl restart deposit-relayer.service && sudo systemctl is-active --quiet deposit-relayer.service"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
