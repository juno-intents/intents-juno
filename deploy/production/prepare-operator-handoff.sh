#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  prepare-operator-handoff.sh [options]

Options:
  --workdir PATH   folder containing dkg-backup.zip and handoff-setup.json (default: current directory)
  --output PATH    output path for operator-handoff.json (default: <workdir>/operator-handoff.json)
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'prepare-operator-handoff: %s\n' "$*" >&2
}

workdir="$(pwd)"
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir)
      workdir="$2"
      shift 2
      ;;
    --output)
      output_path="$2"
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

workdir="$(cd "$workdir" && pwd)"
[[ -d "$workdir" ]] || die "workdir not found: $workdir"

runtime_package="$workdir/dkg-backup.zip"
setup_json="$workdir/handoff-setup.json"
if [[ -z "$output_path" ]]; then
  output_path="$workdir/operator-handoff.json"
fi

[[ -f "$runtime_package" ]] || die "missing $runtime_package"
[[ -f "$setup_json" ]] || die "missing $setup_json"

for cmd in aws jq unzip cast openssl; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

jq -e 'type == "object"' "$setup_json" >/dev/null 2>&1 \
  || die "handoff-setup.json must contain a JSON object"

aws_profile="$(jq -r '.aws_profile // empty' "$setup_json")"
aws_region="$(jq -r '.aws_region // empty' "$setup_json")"
runtime_material_bucket="$(jq -r '.runtime_material.bucket // empty' "$setup_json")"
runtime_material_key="$(jq -r '.runtime_material.key // empty' "$setup_json")"
runtime_material_kms_key_id="$(jq -r '.runtime_material.kms_key_id // empty' "$setup_json")"
runtime_config_secret_id="$(jq -r '.runtime_config_secret.id // empty' "$setup_json")"
runtime_config_secret_region="$(jq -r '.runtime_config_secret.region // empty' "$setup_json")"
runtime_config_secret_kms_key_id="$(jq -r '.runtime_config_secret.kms_key_id // empty' "$setup_json")"
checkpoint_signer_kms_key_id="$(jq -r '.checkpoint_signer.kms_key_id // empty' "$setup_json")"
checkpoint_signer_alias_name="$(jq -r '.checkpoint_signer.alias_name // empty' "$setup_json")"
access_user_name="$(jq -r '.access.user_name // empty' "$setup_json")"
access_policy_name="$(jq -r '.access.policy_name // .access.user_name // empty' "$setup_json")"

[[ -n "$aws_region" ]] || die "handoff-setup.json is missing aws_region"
[[ -n "$runtime_material_bucket" ]] || die "handoff-setup.json is missing runtime_material.bucket"
[[ -n "$runtime_material_key" ]] || die "handoff-setup.json is missing runtime_material.key"
[[ -n "$runtime_material_kms_key_id" ]] || die "handoff-setup.json is missing runtime_material.kms_key_id"
[[ -n "$runtime_config_secret_id" ]] || die "handoff-setup.json is missing runtime_config_secret.id"
if [[ -z "$runtime_config_secret_region" ]]; then
  runtime_config_secret_region="$aws_region"
fi
[[ -n "$checkpoint_signer_kms_key_id" || -n "$checkpoint_signer_alias_name" ]] \
  || die "handoff-setup.json must set checkpoint_signer.kms_key_id or checkpoint_signer.alias_name"
[[ -n "$access_user_name" ]] || die "handoff-setup.json is missing access.user_name"

aws_cmd() {
  local -a args=()
  if [[ -n "$aws_profile" ]]; then
    args+=(--profile "$aws_profile")
  fi
  AWS_PAGER="" aws "${args[@]}" "$@"
}

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

admin_config_json="$tmp_dir/admin-config.json"
unzip -p "$runtime_package" payload/admin-config.json >"$admin_config_json" \
  || die "dkg-backup.zip is missing payload/admin-config.json"
operator_id="$(jq -r '.operator_id // empty' "$admin_config_json")"
[[ "$operator_id" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "backup package admin-config.json is missing a valid operator_id"

generate_hex() {
  local byte_count="$1"
  openssl rand -hex "$byte_count" | tr -d '\n'
}

operator_private_key="${PRODUCTION_PREPARE_OPERATOR_HANDOFF_PRIVATE_KEY:-}"
if [[ -z "$operator_private_key" ]]; then
  operator_private_key="0x$(generate_hex 32)"
fi
operator_private_key="0x${operator_private_key#0x}"
[[ "$operator_private_key" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "generated operator private key is not 32-byte hex"

operator_address="$(cast wallet address --private-key "$operator_private_key" 2>/dev/null | tr -d '[:space:]')"
[[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "failed to derive operator address from generated private key"

base_relayer_auth_token="${PRODUCTION_PREPARE_OPERATOR_HANDOFF_BASE_RELAYER_AUTH_TOKEN:-}"
if [[ -z "$base_relayer_auth_token" ]]; then
  base_relayer_auth_token="brat-$(generate_hex 16)"
fi
juno_rpc_user="${PRODUCTION_PREPARE_OPERATOR_HANDOFF_JUNO_RPC_USER:-}"
if [[ -z "$juno_rpc_user" ]]; then
  juno_rpc_user="juno-$(generate_hex 6)"
fi
juno_rpc_pass="${PRODUCTION_PREPARE_OPERATOR_HANDOFF_JUNO_RPC_PASS:-}"
if [[ -z "$juno_rpc_pass" ]]; then
  juno_rpc_pass="rpc-$(generate_hex 16)"
fi

runtime_config_json="$tmp_dir/runtime-config.json"
jq -n \
  --slurpfile setup "$setup_json" \
  --arg base_relayer_auth_token "$base_relayer_auth_token" \
  --arg juno_rpc_user "$juno_rpc_user" \
  --arg juno_rpc_pass "$juno_rpc_pass" \
  --arg operator_private_key "$operator_private_key" \
  '
    (($setup[0].runtime_config // {}) | if type == "object" then . else error("runtime_config must be an object") end)
    + {
        BASE_RELAYER_AUTH_TOKEN: $base_relayer_auth_token,
        JUNO_RPC_USER: $juno_rpc_user,
        JUNO_RPC_PASS: $juno_rpc_pass,
        JUNO_TXSIGN_SIGNER_KEYS: $operator_private_key
      }
  ' >"$runtime_config_json"

private_key_file="$tmp_dir/operator-signer.key"
printf '%s\n' "$operator_private_key" >"$private_key_file"

runtime_manifest_json="$tmp_dir/runtime-manifest.json"
prepare_args=(
  --runtime-package "$runtime_package"
  --runtime-config-json "$runtime_config_json"
  --runtime-material-bucket "$runtime_material_bucket"
  --runtime-material-key "$runtime_material_key"
  --runtime-material-region "$aws_region"
  --runtime-material-kms-key-id "$runtime_material_kms_key_id"
  --runtime-config-secret-id "$runtime_config_secret_id"
  --runtime-config-secret-region "$runtime_config_secret_region"
  --operator-id "$operator_id"
  --operator-address "$operator_address"
  --output "$runtime_manifest_json"
)
if [[ -n "$aws_profile" ]]; then
  prepare_args+=(--aws-profile "$aws_profile")
fi
if [[ -n "$runtime_config_secret_kms_key_id" ]]; then
  prepare_args+=(--runtime-config-secret-kms-key-id "$runtime_config_secret_kms_key_id")
fi
if [[ -n "$checkpoint_signer_kms_key_id" ]]; then
  prepare_args+=(--checkpoint-signer-kms-key-id "$checkpoint_signer_kms_key_id")
else
  prepare_args+=(--checkpoint-signer-alias-name "$checkpoint_signer_alias_name")
  prepare_args+=(--checkpoint-signer-private-key-file "$private_key_file")
fi

bash "$SCRIPT_DIR/prepare-runtime-materials.sh" "${prepare_args[@]}"
checkpoint_signer_kms_key_id="$(jq -r '.checkpoint_signer_kms_key_id // empty' "$runtime_manifest_json")"
[[ -n "$checkpoint_signer_kms_key_id" ]] || die "runtime material setup returned no checkpoint signer kms key id"

access_inline_policy_json="$(jq -c '.access.inline_policy_document // empty' "$setup_json")"
access_managed_policy_arns_json="$(jq -c '.access.managed_policy_arns // []' "$setup_json")"
if ! aws_cmd --region "$aws_region" iam get-user --user-name "$access_user_name" >/dev/null 2>&1; then
  aws_cmd --region "$aws_region" iam create-user --user-name "$access_user_name" >/dev/null
fi
if [[ -n "$access_inline_policy_json" && "$access_inline_policy_json" != "null" ]]; then
  aws_cmd --region "$aws_region" iam put-user-policy \
    --user-name "$access_user_name" \
    --policy-name "$access_policy_name" \
    --policy-document "$access_inline_policy_json" >/dev/null
fi
while IFS= read -r managed_policy_arn; do
  [[ -n "$managed_policy_arn" ]] || continue
  aws_cmd --region "$aws_region" iam attach-user-policy \
    --user-name "$access_user_name" \
    --policy-arn "$managed_policy_arn" >/dev/null
done < <(jq -r '.[]? // empty' <<<"$access_managed_policy_arns_json")

access_key_json="$(
  aws_cmd --region "$aws_region" iam create-access-key --user-name "$access_user_name"
)"
access_key_id="$(jq -r '.AccessKey.AccessKeyId // empty' <<<"$access_key_json")"
secret_access_key="$(jq -r '.AccessKey.SecretAccessKey // empty' <<<"$access_key_json")"
[[ -n "$access_key_id" && -n "$secret_access_key" ]] || die "iam create-access-key returned empty credentials"

jq -n \
  --arg operator_id "$operator_id" \
  --arg operator_address "$operator_address" \
  --arg aws_region "$aws_region" \
  --arg access_user_name "$access_user_name" \
  --arg access_key_id "$access_key_id" \
  --arg secret_access_key "$secret_access_key" \
  --slurpfile runtime_manifest "$runtime_manifest_json" \
  '{
    operator_id: $operator_id,
    operator_address: $operator_address,
    aws_region: $aws_region,
    checkpoint_signer_kms_key_id: $runtime_manifest[0].checkpoint_signer_kms_key_id,
    runtime_material_ref: $runtime_manifest[0].runtime_material_ref,
    runtime_config_secret_id: $runtime_manifest[0].runtime_config_secret_id,
    runtime_config_secret_region: $runtime_manifest[0].runtime_config_secret_region,
    access: {
      user_name: $access_user_name,
      access_key_id: $access_key_id,
      secret_access_key: $secret_access_key
    }
  }' >"$output_path"

log "wrote operator handoff to $output_path"
