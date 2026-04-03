#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_live_inventory_fixture() {
  local target="$1"
  jq '
    .environment = "mainnet"
    | .dkg_tls_dir = ""
    | .operators[0].known_hosts_file = null
    | .operators[0].dkg_backup_zip = null
    | .operators[0].secret_contract_file = null
    | .operators[0].runtime_material_ref = {
        mode: "s3-kms-zip",
        bucket: "mainnet-runtime-materials",
        key: "operators/op1/runtime-material.zip",
        region: "us-east-1",
        kms_key_id: "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
      }
    | .operators[0].runtime_config_secret_id = "mainnet/op1/runtime-config"
    | .operators[0].runtime_config_secret_region = "us-east-1"
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_fake_cast() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "call" && "$5" == "isOperator(address)(bool)" ]]; then
  printf 'true\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "$*" >&2
exit 1
EOF
  chmod 0755 "$target"
}

write_fake_live_aws() {
  local target="$1"
  local log_dir="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"

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
  *"ec2 describe-instances"*"--query Reservations[].Instances[].InstanceId"* )
    printf 'i-op001\n'
    ;;
  *"ec2 describe-instances"*"--query Reservations[].Instances[].SecurityGroups[].GroupId"* )
    printf 'sg-op001\n'
    ;;
  *"ec2 authorize-security-group-ingress"* )
    ;;
  *"route53 change-resource-record-sets"* )
    printf '{"ChangeInfo":{"Status":"INSYNC"}}\n'
    ;;
  *"ssm send-command"* )
    params="\$(extract_arg --parameters "\$@" || true)"
    command_text="\$(jq -r '.commands[0] // empty' <<<"\$params" 2>/dev/null || true)"
    if [[ -n "\$command_text" ]]; then
      printf '%s\n' "\$command_text" >>"$log_dir/commands.log"
    else
      printf '%s\n' "\$params" >>"$log_dir/commands.log"
    fi
    counter_file="$log_dir/command-counter"
    counter=0
    if [[ -f "\$counter_file" ]]; then
      counter="\$(cat "\$counter_file")"
    fi
    counter=\$((counter + 1))
    printf '%s' "\$counter" >"\$counter_file"
    jq -cn --arg command_id "cmd-\$counter" '{Command: {CommandId: \$command_id}}'
    ;;
  *"ssm get-command-invocation"* )
    jq -cn --arg stdout "$(printf 'active\n')" '{Status: "Success", StandardOutputContent: \$stdout, StandardErrorContent: ""}'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

test_deploy_operator_uses_ssm_runtime_refs_for_live_rollout() {
  local workdir fake_bin log_dir manifest state_file shared_manifest output_dir
  local operator_id ssh_log scp_log

  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  output_dir="$workdir/output"
  operator_id="0x1111111111111111111111111111111111111111"
  ssh_log="$log_dir/ssh.log"
  scp_log="$log_dir/scp.log"
  mkdir -p "$fake_bin" "$log_dir"

  write_live_inventory_fixture "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs \
    "$workdir/inventory.json" \
    "$shared_manifest" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$output_dir" \
    "$workdir"

  manifest="$(production_operator_dir "$output_dir" "$operator_id")/operator-deploy.json"
  state_file="$output_dir/rollout-state.json"

  write_fake_live_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast"
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$ssh_log"
exit 1
EOF
  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$scp_log"
exit 1
EOF
  chmod 0755 "$fake_bin/ssh" "$fake_bin/scp"

  PATH="$fake_bin:$PATH" \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES=1 \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS=0 \
  bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/aws.log")" "ssm send-command --instance-ids i-op001" "live deploy stages files over ssm"
  assert_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress --group-id sg-op001" "live deploy refreshes grpc mesh ingress"
  assert_contains "$(cat "$log_dir/commands.log")" "run-operator-rollout.sh" "live deploy runs the host rollout entrypoint over ssm"
  assert_contains "$(cat "$log_dir/commands.log")" "operator-stack-hydrator.env" "live deploy stages the runtime config hydrator env"
  assert_contains "$(cat "$log_dir/commands.log")" "systemctl is-active checkpoint-signer" "live deploy waits for operator services over ssm"
  assert_not_contains "$(cat "$log_dir/commands.log")" "dkg-backup.zip" "live deploy does not stage local runtime packages"
  assert_not_contains "$(cat "$log_dir/commands.log")" "operator-secrets.env" "live deploy does not stage local secret contracts"
  assert_not_contains "$(cat "$log_dir/commands.log")" "known_hosts" "live deploy does not require ssh trust roots"
  assert_eq "$(jq -r --arg operator_id "$operator_id" '.operators[] | select(.operator_id == $operator_id) | .status' "$state_file")" "done" "live deploy marks rollout complete"
  if [[ -f "$ssh_log" ]]; then
    printf 'expected no ssh usage in the live deploy path\n' >&2
    exit 1
  fi
  if [[ -f "$scp_log" ]]; then
    printf 'expected no scp usage in the live deploy path\n' >&2
    exit 1
  fi

  rm -rf "$workdir"
}

test_deploy_operator_skips_route53_for_external_dns_mode() {
  local workdir fake_bin log_dir manifest state_file shared_manifest output_dir
  local operator_id

  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  log_dir="$workdir/logs"
  output_dir="$workdir/output"
  operator_id="0x1111111111111111111111111111111111111111"
  mkdir -p "$fake_bin" "$log_dir"

  write_live_inventory_fixture "$workdir/inventory.json"
  jq '.dns.mode = "external" | .shared_services.route53_zone_id = null' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  shared_manifest="$workdir/shared-manifest.json"
  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$shared_manifest" \
    "$workdir"
  production_render_operator_handoffs \
    "$workdir/inventory.json" \
    "$shared_manifest" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$output_dir" \
    "$workdir"

  manifest="$(production_operator_dir "$output_dir" "$operator_id")/operator-deploy.json"
  state_file="$output_dir/rollout-state.json"

  write_fake_live_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast"
  cat >"$fake_bin/ssh" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  cat >"$fake_bin/scp" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod 0755 "$fake_bin/ssh" "$fake_bin/scp"

  PATH="$fake_bin:$PATH" \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES=1 \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS=0 \
  bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_not_contains "$(cat "$log_dir/aws.log")" "route53 change-resource-record-sets" "external dns operator deploy skips route53 publishing"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "external dns rollout still completes"

  rm -rf "$workdir"
}

main() {
  test_deploy_operator_uses_ssm_runtime_refs_for_live_rollout
  test_deploy_operator_skips_route53_for_external_dns_mode
}

main "$@"
