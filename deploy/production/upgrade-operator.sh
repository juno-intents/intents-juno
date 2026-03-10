#!/usr/bin/env bash
# shellcheck shell=bash
#
# upgrade-operator.sh — Upgrade operator binaries with strict host validation.

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
binary_dir=""
release_url=""
dry_run="false"

services=(checkpoint-signer checkpoint-aggregator tss-host)

usage() {
  cat <<'EOF'
Usage:
  upgrade-operator.sh [options]

Options:
  --operator-deploy PATH
  --operator-host HOST
  --operator-user USER
  --operator-port PORT
  --known-hosts PATH
  --ssh-private-key PATH
  --binary-dir DIR
  --release-url URL
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
      --binary-dir)
        binary_dir="$2"
        shift 2
        ;;
      --release-url)
        release_url="$2"
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
  if [[ -z "$binary_dir" && -z "$release_url" ]]; then
    die "one of --binary-dir or --release-url is required"
  fi
  if [[ -n "$binary_dir" ]]; then
    [[ -d "$binary_dir" ]] || die "binary dir not found: $binary_dir"
  fi

  for cmd in ssh scp curl; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  build_ssh_opts "$known_hosts_file" "$ssh_private_key"

  if [[ -n "$release_url" && -z "$binary_dir" ]]; then
    binary_dir="$(mktemp -d)"
    trap 'rm -rf "$binary_dir"' EXIT
    for bin in "${services[@]}"; do
      curl -fsSL "${release_url}/${bin}" -o "${binary_dir}/${bin}"
      chmod 0755 "${binary_dir}/${bin}"
    done
  fi

  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would stop, upload, and restart: ${services[*]}"
    exit 0
  fi

  for svc in "${services[@]}"; do
    ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" "sudo systemctl stop $svc 2>/dev/null || true"
  done

  for bin in "${services[@]}"; do
    [[ -f "$binary_dir/$bin" ]] || die "binary not found: $binary_dir/$bin"
    scp "${SSH_OPTS[@]}" -P "$operator_port" "$binary_dir/$bin" "$operator_user@$operator_host:/tmp/$bin"
    ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" "sudo mv /tmp/$bin /usr/local/bin/$bin && sudo chmod 0755 /usr/local/bin/$bin"
  done

  ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" "sudo systemctl daemon-reload"
  for svc in "${services[@]}"; do
    ssh "${SSH_OPTS[@]}" -p "$operator_port" "$operator_user@$operator_host" "sudo systemctl restart $svc && sudo systemctl is-active --quiet $svc"
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
