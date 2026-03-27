#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_prepare_operator_handoff_aws() {
  local target="$1"
  local log_file="$2"
  local secret_payload_file="$3"
  local policy_payload_file="$4"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"

extract_arg() {
  local key="\$1"
  shift
  local args=( "\$@" )
  local i
  for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[\$i]}" == "\$key" && \$((i + 1)) -lt \${#args[@]} ]]; then
      printf '%s\n' "\${args[\$((i + 1))]}"
      return 0
    fi
  done
  return 1
}

case "\$*" in
  *"s3 cp"* )
    ;;
  *"secretsmanager describe-secret"* )
    exit 255
    ;;
  *"secretsmanager create-secret"* )
    extract_arg --secret-string "\$@" >"$secret_payload_file"
    printf '{"ARN":"arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet-op1-runtime-config"}\n'
    ;;
  *"iam get-user"* )
    exit 255
    ;;
  *"iam create-user"* )
    printf '{"User":{"Arn":"arn:aws:iam::021490342184:user/mainnet-op1-runtime-access"}}\n'
    ;;
  *"iam put-user-policy"* )
    extract_arg --policy-document "\$@" >"$policy_payload_file"
    printf '{}\n'
    ;;
  *"iam create-access-key"* )
    printf '{"AccessKey":{"AccessKeyId":"AKIAEXAMPLE123","SecretAccessKey":"secret-example-456"}}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

write_fake_prepare_operator_handoff_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "wallet" && "$2" == "address" ]]; then
  printf '0x9999999999999999999999999999999999999999\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "$*" >&2
exit 1
EOF
  chmod 0755 "$target"
}

write_fake_prepare_operator_handoff_provisioner() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"keyArn":"arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555"}'
EOF
  chmod 0755 "$target"
}

test_prepare_operator_handoff_discovers_inputs_and_emits_handoff() {
  local tmp fake_bin aws_log secret_payload policy_payload provisioner output_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"
  secret_payload="$tmp/runtime-secret.json"
  policy_payload="$tmp/access-policy.json"
  provisioner="$tmp/fake-provision-checkpoint-signer-kms"
  output_json="$tmp/operator-handoff.json"
  mkdir -p "$fake_bin"

  write_test_dkg_backup_zip "$tmp/dkg-backup.zip"
  cat >"$tmp/handoff-setup.json" <<'JSON'
{
  "aws_profile": "operator-op1",
  "aws_region": "us-east-1",
  "runtime_material": {
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op1/runtime-material.zip",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
  },
  "runtime_config_secret": {
    "id": "mainnet/op1/runtime-config",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/22222222-3333-4444-5555-666666666666"
  },
  "checkpoint_signer": {
    "alias_name": "alias/mainnet-op1-checkpoint-signer"
  },
  "access": {
    "user_name": "mainnet-op1-runtime-access",
    "policy_name": "mainnet-op1-runtime-access",
    "inline_policy_document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "secretsmanager:PutSecretValue"
          ],
          "Resource": "arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet/op1/runtime-config"
        }
      ]
    }
  },
  "runtime_config": {
    "CHECKPOINT_POSTGRES_DSN": "postgres://checkpoint.example.internal:5432/juno?sslmode=require",
    "WITHDRAW_COORDINATOR_JUNO_WALLET_ID": "wallet-op1",
    "WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID": "wallet-op1"
  }
}
JSON

  write_fake_prepare_operator_handoff_aws "$fake_bin/aws" "$aws_log" "$secret_payload" "$policy_payload"
  write_fake_prepare_operator_handoff_cast "$fake_bin/cast"
  write_fake_prepare_operator_handoff_provisioner "$provisioner"

  (
    cd "$tmp"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_PREPARE_RUNTIME_MATERIALS_CHECKPOINT_SIGNER_BIN="$provisioner" \
    PRODUCTION_PREPARE_OPERATOR_HANDOFF_BASE_RELAYER_AUTH_TOKEN="base-relayer-token-op1" \
    PRODUCTION_PREPARE_OPERATOR_HANDOFF_JUNO_RPC_USER="juno-op1" \
    PRODUCTION_PREPARE_OPERATOR_HANDOFF_JUNO_RPC_PASS="rpc-pass-op1" \
    bash "$REPO_ROOT/deploy/production/prepare-operator-handoff.sh"
  )

  assert_file_exists "$tmp/operator-handoff.json" "operator handoff output"
  assert_eq "$(jq -r '.operator_id' "$output_json")" "0x1111111111111111111111111111111111111111" "handoff returns operator id from backup package"
  assert_eq "$(jq -r '.operator_address' "$output_json")" "0x9999999999999999999999999999999999999999" "handoff returns the derived operator address"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$output_json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "handoff returns the checkpoint signer kms key id"
  assert_eq "$(jq -r '.runtime_material_ref.mode' "$output_json")" "s3-kms-zip" "handoff returns the runtime material mode"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$output_json")" "mainnet/op1/runtime-config" "handoff returns the runtime config secret id"
  assert_eq "$(jq -r '.access.user_name' "$output_json")" "mainnet-op1-runtime-access" "handoff returns the access identity name"
  assert_eq "$(jq -r '.access.access_key_id' "$output_json")" "AKIAEXAMPLE123" "handoff returns the access key id"
  assert_eq "$(jq -r '.access.secret_access_key' "$output_json")" "secret-example-456" "handoff returns the secret access key"

  assert_contains "$(cat "$aws_log")" "s3 cp" "handoff uploads the runtime package"
  assert_contains "$(cat "$aws_log")" "iam create-user --user-name mainnet-op1-runtime-access" "handoff creates the access identity"
  assert_contains "$(cat "$aws_log")" "iam put-user-policy --user-name mainnet-op1-runtime-access --policy-name mainnet-op1-runtime-access" "handoff installs the inline access policy"
  if ! [[ "$(jq -r '.JUNO_TXSIGN_SIGNER_KEYS' "$secret_payload")" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    printf 'expected handoff to generate a single 32-byte operator key\n' >&2
    exit 1
  fi
  assert_eq "$(jq -r '.BASE_RELAYER_AUTH_TOKEN' "$secret_payload")" "base-relayer-token-op1" "handoff stores the generated base relayer auth token"
  assert_eq "$(jq -r '.JUNO_RPC_USER' "$secret_payload")" "juno-op1" "handoff stores the generated juno rpc user"
  assert_eq "$(jq -r '.JUNO_RPC_PASS' "$secret_payload")" "rpc-pass-op1" "handoff stores the generated juno rpc password"
  assert_eq "$(jq -r '.WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS // empty' "$secret_payload")" "" "handoff does not store the legacy withdraw extend signer key roster"
  assert_eq "$(jq -r '.Statement[0].Action[0]' "$policy_payload")" "secretsmanager:PutSecretValue" "handoff applies the configured inline policy"
  assert_eq "$(jq -r '.Statement[0].Resource' "$policy_payload")" "arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet/op1/runtime-config" "handoff scopes the inline policy to the runtime config secret"

  rm -rf "$tmp"
}

test_prepare_operator_handoff_rejects_forbidden_policy_permissions() {
  local tmp fake_bin aws_log secret_payload policy_payload provisioner output
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  aws_log="$tmp/aws.log"
  secret_payload="$tmp/runtime-secret.json"
  policy_payload="$tmp/access-policy.json"
  provisioner="$tmp/fake-provision-checkpoint-signer-kms"
  mkdir -p "$fake_bin"

  write_test_dkg_backup_zip "$tmp/dkg-backup.zip"
  cat >"$tmp/handoff-setup.json" <<'JSON'
{
  "aws_profile": "operator-op1",
  "aws_region": "us-east-1",
  "runtime_material": {
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op1/runtime-material.zip",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
  },
  "runtime_config_secret": {
    "id": "mainnet/op1/runtime-config",
    "region": "us-east-1"
  },
  "checkpoint_signer": {
    "alias_name": "alias/mainnet-op1-checkpoint-signer"
  },
  "access": {
    "user_name": "mainnet-op1-runtime-access",
    "policy_name": "mainnet-op1-runtime-access",
    "inline_policy_document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "ssm:StartSession"
          ],
          "Resource": "*"
        }
      ]
    }
  },
  "runtime_config": {
    "CHECKPOINT_POSTGRES_DSN": "postgres://checkpoint.example.internal:5432/juno?sslmode=require"
  }
}
JSON

  write_fake_prepare_operator_handoff_aws "$fake_bin/aws" "$aws_log" "$secret_payload" "$policy_payload"
  write_fake_prepare_operator_handoff_cast "$fake_bin/cast"
  write_fake_prepare_operator_handoff_provisioner "$provisioner"

  set +e
  output="$(
    cd "$tmp" && \
      PATH="$fake_bin:$PATH" \
      PRODUCTION_PREPARE_RUNTIME_MATERIALS_CHECKPOINT_SIGNER_BIN="$provisioner" \
      bash "$REPO_ROOT/deploy/production/prepare-operator-handoff.sh" 2>&1
  )"
  status=$?
  set -e

  if [[ $status -eq 0 ]]; then
    printf 'expected handoff to reject forbidden rollout permissions\n' >&2
    exit 1
  fi
  assert_contains "$output" "forbidden rollout permissions" "handoff rejects interactive or read-capable rollout policies"

  rm -rf "$tmp"
}

main() {
  test_prepare_operator_handoff_discovers_inputs_and_emits_handoff
  test_prepare_operator_handoff_rejects_forbidden_policy_permissions
}

main "$@"
