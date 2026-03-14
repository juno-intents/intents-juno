#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg base_dir "$workdir/operators" \
    '
      .operators = [
        {
          index: 1,
          operator_id: "0x1111111111111111111111111111111111111111",
          operator_address: "0x9999999999999999999999999999999999999999",
          checkpoint_signer_driver: "aws-kms",
          checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555",
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          operator_host: "203.0.113.11",
          operator_user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/operator-runtime",
          public_dns_label: "op1",
          public_endpoint: "203.0.113.11",
          known_hosts_file: ($base_dir + "/op1/known_hosts"),
          dkg_backup_zip: ($base_dir + "/op1/dkg-backup.zip"),
          secret_contract_file: ($base_dir + "/op1/operator-secrets.env")
        },
        {
          index: 2,
          operator_id: "0x6666666666666666666666666666666666666666",
          operator_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          checkpoint_signer_driver: "aws-kms",
          checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/66666666-2222-3333-4444-555555555555",
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          operator_host: "203.0.113.12",
          operator_user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/operator-runtime",
          public_dns_label: "op2",
          public_endpoint: "203.0.113.12",
          known_hosts_file: ($base_dir + "/op2/known_hosts"),
          dkg_backup_zip: ($base_dir + "/op2/dkg-backup.zip"),
          secret_contract_file: ($base_dir + "/op2/operator-secrets.env")
        },
        {
          index: 3,
          operator_id: "0x7777777777777777777777777777777777777777",
          operator_address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          checkpoint_signer_driver: "aws-kms",
          checkpoint_signer_kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/77777777-2222-3333-4444-555555555555",
          aws_profile: "juno",
          aws_region: "us-east-1",
          account_id: "021490342184",
          operator_host: "203.0.113.13",
          operator_user: "ubuntu",
          runtime_dir: "/var/lib/intents-juno/operator-runtime",
          public_dns_label: "op3",
          public_endpoint: "203.0.113.13",
          known_hosts_file: ($base_dir + "/op3/known_hosts"),
          dkg_backup_zip: ($base_dir + "/op3/dkg-backup.zip"),
          secret_contract_file: ($base_dir + "/op3/operator-secrets.env")
        }
      ]
      | .app_host = null
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_operator_inputs() {
  local workdir="$1"
  local op
  for op in op1 op2 op3; do
    mkdir -p "$workdir/operators/$op"
    printf 'backup-%s' "$op" >"$workdir/operators/$op/dkg-backup.zip"
    cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/operators/$op/known_hosts"
    cat >"$workdir/operators/$op/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
CHECKPOINT_SIGNER_PRIVATE_KEY=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_PRIVATE_KEYS=literal:0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BASE_RELAYER_AUTH_TOKEN=literal:token
EOF
    append_default_owallet_proof_keys "$workdir/operators/$op/operator-secrets.env"
  done
}

write_dkg_summary_fixture() {
  local target="$1"
  local workdir="$2"

  printf '0x1111111111111111111111111111111111111111111111111111111111111111' >"$workdir/operators/op1/operator-key.hex"
  printf '0x2222222222222222222222222222222222222222222222222222222222222222' >"$workdir/operators/op2/operator-key.hex"
  printf '0x3333333333333333333333333333333333333333333333333333333333333333' >"$workdir/operators/op3/operator-key.hex"

  jq -n \
    --arg op1_key "$workdir/operators/op1/operator-key.hex" \
    --arg op2_key "$workdir/operators/op2/operator-key.hex" \
    --arg op3_key "$workdir/operators/op3/operator-key.hex" \
    '{
      network: "testnet",
      threshold: 3,
      ufvk: "uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
      operators: [
        {
          index: 1,
          operator_id: "0x1111111111111111111111111111111111111111",
          operator_key_file: $op1_key
        },
        {
          index: 2,
          operator_id: "0x6666666666666666666666666666666666666666",
          operator_key_file: $op2_key
        },
        {
          index: 3,
          operator_id: "0x7777777777777777777777777777777777777777",
          operator_key_file: $op3_key
        }
      ]
    }' >"$target"
}

write_fake_tools() {
  local bin_dir="$1"
  local log_file="$2"
  mkdir -p "$bin_dir"

  cat >"$bin_dir/deploy-operator.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'deploy-operator %s\n' "\$*" >>"$log_file"
manifest=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --operator-deploy) manifest="\$2"; shift 2 ;;
    --dry-run) shift ;;
    *) shift ;;
  esac
done
[[ -n "\$manifest" ]] || exit 1
state_file="\$(jq -r '.rollout_state_file' "\$manifest")"
operator_id="\$(jq -r '.operator_id' "\$manifest")"
tmp_file="\$(mktemp)"
jq --arg operator_id "\$operator_id" '
  .current_operator_id = null
  | .operators |= map(
      if .operator_id == \$operator_id then
        .status = "done"
        | .note = "healthy"
      else
        .
      end
    )
' "\$state_file" >"\$tmp_file"
mv "\$tmp_file" "\$state_file"
EOF

  cat >"$bin_dir/canary-shared-services.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'canary-shared %s\n' "\$*" >>"$log_file"
cat <<'JSON'
{"ready_for_deploy":true,"checks":{"postgres":{"status":"passed"}}}
JSON
EOF

  cat >"$bin_dir/canary-operator-boot.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'canary-operator %s\n' "\$*" >>"$log_file"
manifest=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --operator-deploy) manifest="\$2"; shift 2 ;;
    --dry-run) shift ;;
    *) shift ;;
  esac
done
operator_id="\$(jq -r '.operator_id' "\$manifest")"
cat <<JSON
{"ready_for_deploy":true,"operator_id":"\$operator_id","checks":{"systemd":{"status":"passed"}}}
JSON
EOF

  cat >"$bin_dir/deploy-coordinator-should-not-run.sh" <<EOF
#!/usr/bin/env bash
printf 'deploy-coordinator-should-not-run %s\n' "\$*" >>"$log_file"
exit 99
EOF

  cat >"$bin_dir/cast" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  printf '0x1111111111111111111111111111111111111111\n'
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  printf '300000000000000\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF

  chmod 0755 \
    "$bin_dir/cast" \
    "$bin_dir/deploy-operator.sh" \
    "$bin_dir/canary-shared-services.sh" \
    "$bin_dir/canary-operator-boot.sh" \
    "$bin_dir/deploy-coordinator-should-not-run.sh"
}

test_rehearse_rollout_creates_timestamped_run_and_resumes() {
  local workdir inventory dkg_summary log_file fake_bin output_root run_dir
  workdir="$(mktemp -d)"
  inventory="$workdir/inventory.json"
  dkg_summary="$workdir/dkg-summary.json"
  log_file="$workdir/rehearsal.log"
  fake_bin="$workdir/bin"
  output_root="$workdir/rehearsal"

  write_operator_inputs "$workdir"
  write_inventory_fixture "$inventory" "$workdir"
  write_dkg_summary_fixture "$dkg_summary" "$workdir"
  write_fake_tools "$fake_bin" "$log_file"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_DEPLOY_OPERATOR_BIN="$fake_bin/deploy-operator.sh" \
    PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
    PRODUCTION_CANARY_OPERATOR_BIN="$fake_bin/canary-operator-boot.sh" \
    bash deploy/production/rehearse-rollout.sh \
      --inventory "$inventory" \
      --dkg-summary "$dkg_summary" \
      --existing-bridge-summary "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
      --terraform-output-json "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
      --skip-terraform-apply \
      --output-root "$output_root" \
      --run-id "run-fixed" \
      --pause-after-operator-count 2 >/dev/null
  )

  run_dir="$output_root/alpha/run-fixed"
  assert_file_exists "$run_dir/deployment-inventory.json" "inventory snapshot"
  assert_file_exists "$run_dir/bridge-summary.json" "bridge summary"
  assert_file_exists "$run_dir/shared-manifest.json" "shared manifest"
  assert_file_exists "$run_dir/terraform-output.json" "terraform output"
  assert_file_exists "$run_dir/rollout-state.json" "rollout state"
  assert_file_exists "$run_dir/canaries/shared-services.json" "shared canary"
  assert_file_exists "$run_dir/canaries/0x1111111111111111111111111111111111111111.json" "op1 canary"
  assert_file_exists "$run_dir/canaries/0x6666666666666666666666666666666666666666.json" "op2 canary"
  assert_file_exists "$run_dir/summary.md" "summary"
  assert_eq "$(jq '[.operators[] | select(.status == "done")] | length' "$run_dir/rollout-state.json")" "2" "two operators done before resume"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    PRODUCTION_DEPLOY_COORDINATOR_BIN="$fake_bin/deploy-coordinator-should-not-run.sh" \
    PRODUCTION_DEPLOY_OPERATOR_BIN="$fake_bin/deploy-operator.sh" \
    PRODUCTION_CANARY_SHARED_BIN="$fake_bin/canary-shared-services.sh" \
    PRODUCTION_CANARY_OPERATOR_BIN="$fake_bin/canary-operator-boot.sh" \
    bash deploy/production/rehearse-rollout.sh \
      --resume-run-dir "$run_dir" >/dev/null
  )

  assert_eq "$(jq '[.operators[] | select(.status == "done")] | length' "$run_dir/rollout-state.json")" "3" "all operators done after resume"
  assert_file_exists "$run_dir/canaries/0x7777777777777777777777777777777777777777.json" "op3 canary after resume"
  assert_contains "$(cat "$run_dir/summary.md")" "Run dir: \`$run_dir\`" "summary includes run dir"
  assert_contains "$(cat "$log_file")" "deploy-operator --operator-deploy $run_dir/operators/0x1111111111111111111111111111111111111111/operator-deploy.json" "first operator deploy logged"
  assert_contains "$(cat "$log_file")" "deploy-operator --operator-deploy $run_dir/operators/0x7777777777777777777777777777777777777777/operator-deploy.json" "resume operator deploy logged"

  rm -rf "$workdir"
}

main() {
  test_rehearse_rollout_creates_timestamped_run_and_resumes
}

main "$@"
