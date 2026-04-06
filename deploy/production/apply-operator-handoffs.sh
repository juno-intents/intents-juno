#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  apply-operator-handoffs.sh --handoff-dir PATH
EOF
}

handoff_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --handoff-dir)
      handoff_dir="$2"
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

[[ -n "$handoff_dir" ]] || die "--handoff-dir is required"
handoff_dir="$(production_abs_path "$(pwd)" "$handoff_dir")"
[[ -d "$handoff_dir" ]] || die "handoff dir not found: $handoff_dir"

shared_manifest="$handoff_dir/shared-manifest.json"
operators_dir="$handoff_dir/operators"
app_deploy="$handoff_dir/app/app-deploy.json"

[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"
[[ -d "$operators_dir" ]] || die "operators dir not found: $operators_dir"

entries_tmp="$(mktemp)"
cleanup() {
  rm -f "$entries_tmp"
}
trap cleanup EXIT

find "$operators_dir" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r operator_dir; do
  manifest="$operator_dir/operator-deploy.json"
  handoff="$operator_dir/operator-handoff.json"
  [[ -f "$manifest" ]] || die "operator deploy manifest not found: $manifest"
  [[ -f "$handoff" ]] || die "operator handoff file not found: $handoff"

  manifest_operator_id="$(jq -r '.operator_id // empty' "$manifest")"
  handoff_operator_id="$(jq -r '.operator_id // empty' "$handoff")"
  [[ -n "$manifest_operator_id" && "$manifest_operator_id" == "$handoff_operator_id" ]] \
    || die "operator handoff id does not match manifest in $operator_dir"

  merged_tmp="$(mktemp)"
  jq -s '
    .[0] as $manifest
    | .[1] as $handoff
    | $manifest
    | .operator_address = $handoff.operator_address
    | .checkpoint_signer_kms_key_id = $handoff.checkpoint_signer_kms_key_id
    | .runtime_material_ref = $handoff.runtime_material_ref
    | .runtime_config_secret_id = $handoff.runtime_config_secret_id
    | .runtime_config_secret_region = $handoff.runtime_config_secret_region
    | .base_relayer_address = ($handoff.base_relayer_address // .base_relayer_address)
    | .withdraw_coordinator_juno_wallet_id = ($handoff.withdraw_coordinator_juno_wallet_id // .withdraw_coordinator_juno_wallet_id)
    | .withdraw_finalizer_juno_scan_wallet_id = ($handoff.withdraw_finalizer_juno_scan_wallet_id // .withdraw_finalizer_juno_scan_wallet_id)
    | .deposit_scan_juno_scan_wallet_id = (
        $handoff.deposit_scan_juno_scan_wallet_id
        // $handoff.withdraw_finalizer_juno_scan_wallet_id
        // $handoff.withdraw_coordinator_juno_wallet_id
        // .deposit_scan_juno_scan_wallet_id
      )
  ' "$manifest" "$handoff" >"$merged_tmp"
  mv "$merged_tmp" "$manifest"

  operator_address="$(jq -r '.operator_address // empty' "$manifest")"
  operator_index="$(jq -r '.operator_index // .index // empty' "$manifest")"
  operator_host="$(jq -r '.public_endpoint // .operator_host // empty' "$manifest")"
  [[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "invalid operator address after merge: $manifest"
  [[ -n "$operator_host" ]] || die "operator host is required to derive withdraw operator endpoints: $manifest"
  [[ -n "$operator_index" ]] || die "operator index is required to derive withdraw operator endpoints: $manifest"
  operator_port="$(production_default_dkg_port_for_index "$operator_index")"
  jq -n \
    --arg operator_id "$manifest_operator_id" \
    --arg operator_address "$operator_address" \
    --argjson operator_index "$operator_index" \
    --arg endpoint "$operator_address=$operator_host:$operator_port" \
    '{
      operator_id: $operator_id,
      operator_address: $operator_address,
      operator_index: $operator_index,
      endpoint: $endpoint
    }' >>"$entries_tmp"
  printf '\n' >>"$entries_tmp"
done

entries_json="$(jq -s 'sort_by(.operator_index)' "$entries_tmp")"
operator_addresses_json="$(jq -c 'map(.operator_address)' <<<"$entries_json")"
operator_endpoints_json="$(jq -c 'map(.endpoint)' <<<"$entries_json")"

find "$operators_dir" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r operator_dir; do
  manifest="$operator_dir/operator-deploy.json"
  manifest_tmp="$(mktemp)"
  jq --argjson withdraw_operator_endpoints "$operator_endpoints_json" \
    '.withdraw_operator_endpoints = $withdraw_operator_endpoints' \
    "$manifest" >"$manifest_tmp"
  mv "$manifest_tmp" "$manifest"
done

shared_manifest_tmp="$(mktemp)"
jq --argjson operator_addresses "$operator_addresses_json" \
  '.checkpoint.operators = $operator_addresses' \
  "$shared_manifest" >"$shared_manifest_tmp"
mv "$shared_manifest_tmp" "$shared_manifest"

if [[ -f "$app_deploy" ]]; then
  app_deploy_tmp="$(mktemp)"
  jq \
    --argjson operator_addresses "$operator_addresses_json" \
    --argjson operator_endpoints "$operator_endpoints_json" \
    '.operator_addresses = $operator_addresses | .operator_endpoints = $operator_endpoints' \
    "$app_deploy" >"$app_deploy_tmp"
  mv "$app_deploy_tmp" "$app_deploy"
fi
