#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  prepare-operator-handoff.sh [options]

Options:
  --workdir PATH       folder containing dkg-backup.zip and handoff-setup.json (default: current directory)
  --output PATH        output path for operator-handoff.json (default: <workdir>/operator-handoff.json)
  --aws-profile NAME   override handoff-setup.json aws_profile for this run
  --no-aws-profile     ignore handoff-setup.json aws_profile for this run
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
aws_profile_override=""
aws_profile_override_set=0
disable_aws_profile=0

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
    --aws-profile)
      aws_profile_override="$2"
      aws_profile_override_set=1
      shift 2
      ;;
    --no-aws-profile)
      disable_aws_profile=1
      shift
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

if [[ $aws_profile_override_set -eq 1 && $disable_aws_profile -eq 1 ]]; then
  die "--aws-profile and --no-aws-profile cannot be used together"
fi

for cmd in aws jq unzip cast openssl; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

jq -e 'type == "object"' "$setup_json" >/dev/null 2>&1 \
  || die "handoff-setup.json must contain a JSON object"

aws_profile="$(jq -r '.aws_profile // empty' "$setup_json")"
if [[ $disable_aws_profile -eq 1 ]]; then
  aws_profile=""
elif [[ $aws_profile_override_set -eq 1 ]]; then
  aws_profile="$aws_profile_override"
fi
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

validate_rollout_policy_document() {
  local policy_document_json="$1"
  local label="$2"
  local validation

  validation="$(
    jq -cer '
      def listify:
        if . == null then []
        elif type == "array" then .
        elif type == "string" then [.]
        else error("policy Action/Resource entries must be strings or arrays")
        end;
      def action_list($stmt): ($stmt.Action // null) | listify | map(ascii_downcase);
      def not_action_list($stmt): ($stmt.NotAction // null) | listify | map(ascii_downcase);
      def resource_list($stmt): ($stmt.Resource // null) | listify | map(tostring);
      def has_forbidden_action($stmt):
        action_list($stmt) | any(.[]; . == "*"
          or . == "secretsmanager:*"
          or . == "secretsmanager:getsecretvalue"
          or . == "kms:*"
          or . == "kms:decrypt"
          or . == "s3:*"
          or . == "s3:getobject"
          or . == "ssm:*"
          or . == "ssm:startsession");
      def has_wildcard_secret_resource($stmt):
        (action_list($stmt) | any(.[]; startswith("secretsmanager:")))
        and (resource_list($stmt) | any(.[]; . == "*"));
      (.Statement // []) as $raw_statements
      | ($raw_statements | if type == "array" then . else [.] end) as $statements
      | [
          $statements[]
          | select(
              (not_action_list(.) | length) > 0
              or has_forbidden_action(.)
              or has_wildcard_secret_resource(.)
            )
        ] as $violations
      | if ($violations | length) > 0 then
          error("forbidden rollout policy permission detected")
        else
          "ok"
        end
    ' <<<"$policy_document_json" 2>/dev/null || true
  )"

  [[ "$validation" == "ok" ]] || die "$label includes forbidden rollout permissions"
}

validate_managed_rollout_policy() {
  local policy_arn="$1"
  local policy_json version_id policy_version_json policy_document_json

  policy_json="$(aws_cmd --region "$aws_region" iam get-policy --policy-arn "$policy_arn")" \
    || die "failed to describe managed policy: $policy_arn"
  version_id="$(jq -r '.Policy.DefaultVersionId // empty' <<<"$policy_json")"
  [[ -n "$version_id" ]] || die "managed policy is missing DefaultVersionId: $policy_arn"
  policy_version_json="$(aws_cmd --region "$aws_region" iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id")" \
    || die "failed to read managed policy version: $policy_arn:$version_id"
  policy_document_json="$(jq -c '.PolicyVersion.Document | if type == "string" then fromjson else . end' <<<"$policy_version_json")" \
    || die "managed policy document is not valid JSON: $policy_arn"
  validate_rollout_policy_document "$policy_document_json" "managed policy $policy_arn"
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
operator_network="$(jq -r '.network // empty' "$admin_config_json")"

generate_hex() {
  local byte_count="$1"
  openssl rand -hex "$byte_count" | tr -d '\n'
}

operator_private_key="0x$(generate_hex 32)"
operator_private_key="0x${operator_private_key#0x}"
[[ "$operator_private_key" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "generated operator private key is not 32-byte hex"

operator_address="$(cast wallet address --private-key "$operator_private_key" 2>/dev/null | tr -d '[:space:]')"
[[ "$operator_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "failed to derive operator address from generated private key"

base_relayer_private_key="0x$(generate_hex 32)"
base_relayer_private_key="0x${base_relayer_private_key#0x}"
[[ "$base_relayer_private_key" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "generated base relayer private key is not 32-byte hex"

base_relayer_address="$(cast wallet address --private-key "$base_relayer_private_key" 2>/dev/null | tr -d '[:space:]')"
[[ "$base_relayer_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "failed to derive base relayer address from generated private key"

tss_auth_token="tss-$(generate_hex 16)"
short_operator_id="$(printf '%s' "${operator_id#0x}" | tr 'A-F' 'a-f' | cut -c1-12)"
wallet_id="wallet-${short_operator_id}"
if [[ -n "$operator_network" ]]; then
  wallet_id="wallet-${operator_network}-${short_operator_id}"
fi

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
  --arg base_relayer_private_key "$base_relayer_private_key" \
  --arg juno_rpc_user "$juno_rpc_user" \
  --arg juno_rpc_pass "$juno_rpc_pass" \
  --arg operator_private_key "$operator_private_key" \
  --arg tss_auth_token "$tss_auth_token" \
  --arg wallet_id "$wallet_id" \
  '
    (($setup[0].runtime_config // {}) | if type == "object" then . else error("runtime_config must be an object") end)
    + {
        BASE_RELAYER_AUTH_TOKEN: $base_relayer_auth_token,
        BASE_RELAYER_PRIVATE_KEYS: $base_relayer_private_key,
        JUNO_RPC_USER: $juno_rpc_user,
        JUNO_RPC_PASS: $juno_rpc_pass,
        JUNO_TXSIGN_SIGNER_KEYS: $operator_private_key,
        TSS_AUTH_TOKEN: $tss_auth_token,
        WITHDRAW_COORDINATOR_JUNO_WALLET_ID: $wallet_id,
        WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID: $wallet_id
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
if [[ -n "$access_inline_policy_json" && "$access_inline_policy_json" != "null" ]]; then
  validate_rollout_policy_document "$access_inline_policy_json" "access.inline_policy_document"
fi
while IFS= read -r managed_policy_arn; do
  [[ -n "$managed_policy_arn" ]] || continue
  validate_managed_rollout_policy "$managed_policy_arn"
done < <(jq -r '.[]? // empty' <<<"$access_managed_policy_arns_json")
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
  --arg base_relayer_address "$base_relayer_address" \
  --arg aws_region "$aws_region" \
  --arg access_user_name "$access_user_name" \
  --arg access_key_id "$access_key_id" \
  --arg secret_access_key "$secret_access_key" \
  --arg withdraw_coordinator_juno_wallet_id "$wallet_id" \
  --arg withdraw_finalizer_juno_scan_wallet_id "$wallet_id" \
  --slurpfile runtime_manifest "$runtime_manifest_json" \
  '{
    operator_id: $operator_id,
    operator_address: $operator_address,
    base_relayer_address: $base_relayer_address,
    aws_region: $aws_region,
    checkpoint_signer_kms_key_id: $runtime_manifest[0].checkpoint_signer_kms_key_id,
    runtime_material_ref: $runtime_manifest[0].runtime_material_ref,
    runtime_config_secret_id: $runtime_manifest[0].runtime_config_secret_id,
    runtime_config_secret_region: $runtime_manifest[0].runtime_config_secret_region,
    withdraw_coordinator_juno_wallet_id: $withdraw_coordinator_juno_wallet_id,
    withdraw_finalizer_juno_scan_wallet_id: $withdraw_finalizer_juno_scan_wallet_id,
    access: {
      user_name: $access_user_name,
      access_key_id: $access_key_id,
      secret_access_key: $secret_access_key
    }
  }' >"$output_path"

log "wrote operator handoff to $output_path"
