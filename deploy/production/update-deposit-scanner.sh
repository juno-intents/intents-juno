#!/usr/bin/env bash
# shellcheck shell=bash
#
# update-deposit-scanner.sh — Update deposit scanner settings through SSM.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

operator_host=""
instance_id=""
aws_profile=""
aws_region=""
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
  --instance-id ID
  --aws-profile PROFILE
  --aws-region REGION
  --juno-scan-url URL
  --juno-scan-wallet-id ID
  --juno-rpc-url URL
  --poll-interval DUR
  --dry-run
EOF
}

shell_quote() {
  printf '%q' "$1"
}

build_remote_command() {
  local quoted_env_file quoted_scan_url quoted_wallet_id quoted_rpc_url quoted_poll_interval

  quoted_env_file="$(shell_quote "$env_file")"
  quoted_scan_url="$(shell_quote "$juno_scan_url")"
  quoted_wallet_id="$(shell_quote "$juno_scan_wallet_id")"
  quoted_rpc_url="$(shell_quote "$juno_rpc_url")"
  quoted_poll_interval="$(shell_quote "$poll_interval")"

  cat <<EOF
set -euo pipefail
file=$quoted_env_file

set_env() {
  local key="\$1"
  local value="\$2"
  local tmp

  tmp="\$(mktemp)"
  awk -v key="\$key" -v value="\$value" '
    BEGIN { updated = 0 }
    index(\$0, key "=") == 1 {
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
  ' "\$file" >"\$tmp"
  cat "\$tmp" >"\$file"
  chmod 0640 "\$file"
  rm -f "\$tmp"
}

set_env DEPOSIT_SCAN_ENABLED true
set_env DEPOSIT_SCAN_JUNO_SCAN_URL $quoted_scan_url
set_env DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID $quoted_wallet_id
set_env DEPOSIT_SCAN_JUNO_RPC_URL $quoted_rpc_url
set_env DEPOSIT_SCAN_POLL_INTERVAL $quoted_poll_interval

systemctl restart deposit-relayer.service
systemctl is-active --quiet deposit-relayer.service
EOF
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
      --instance-id)
        instance_id="$2"
        shift 2
        ;;
      --aws-profile)
        aws_profile="$2"
        shift 2
        ;;
      --aws-region)
        aws_region="$2"
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
    operator_host="${operator_host:-$(jq -er '.operator_host | select(type == "string" and length > 0)' "$operator_deploy")}"
    aws_profile="${aws_profile:-$(jq -er '.aws_profile | select(type == "string" and length > 0)' "$operator_deploy")}"
    aws_region="${aws_region:-$(jq -er '.aws_region | select(type == "string" and length > 0)' "$operator_deploy")}"
  fi

  [[ -n "$aws_profile" ]] || die "--aws-profile is required"
  [[ -n "$aws_region" ]] || die "--aws-region is required"
  [[ -n "$juno_scan_url" ]] || die "--juno-scan-url is required"
  [[ -n "$juno_scan_wallet_id" ]] || die "--juno-scan-wallet-id is required"
  [[ -n "$juno_rpc_url" ]] || die "--juno-rpc-url is required"

  if [[ -z "$instance_id" ]]; then
    [[ -n "$operator_host" ]] || die "--operator-host or --instance-id is required"
    instance_id="$(production_resolve_instance_id_from_host "$aws_profile" "$aws_region" "$operator_host")"
  fi

  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would update deposit scanner env vars on $instance_id"
    exit 0
  fi

  production_ssm_run_shell_command \
    "$aws_profile" \
    "$aws_region" \
    "$instance_id" \
    "$(build_remote_command)" >/dev/null
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
