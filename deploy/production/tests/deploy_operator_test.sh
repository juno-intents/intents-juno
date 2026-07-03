#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

export PRODUCTION_TEST_ALLOW_LOCAL_SECRET_CONTRACTS=true

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

assert_no_ssm_cat_operator_stack_env() {
  local log_file="$1"
  local msg="$2"

  [[ -f "$log_file" ]] || return 0
  if awk '/sudo cat/ && /operator-stack[.]env/ { found = 1 } END { exit found ? 0 : 1 }' "$log_file"; then
    printf 'assert_no_ssm_cat_operator_stack_env failed: %s\n' "$msg" >&2
    exit 1
  fi
}

assert_line_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"
  local first_line second_line
  first_line="$(awk -v needle="$first" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  second_line="$(awk -v needle="$second" 'index($0, needle) { print NR; exit }' <<<"$haystack")"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'assert_line_order failed: %s: first=%q second=%q first_line=%q second_line=%q\n' "$msg" "$first" "$second" "$first_line" "$second_line" >&2
    exit 1
  fi
}

write_fake_cast() {
  local target="$1"
  local log_file="$2"
  local balance_wei="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
printf 'cast %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "wallet" && "\$2" == "address" ]]; then
  printf '0x1111111111111111111111111111111111111111\n'
  exit 0
fi
if [[ "\$1" == "balance" ]]; then
  printf '%s\n' "$balance_wei"
  exit 0
fi
if [[ "\$1" == "call" && "\$5" == "isOperator(address)(bool)" ]]; then
  printf 'true\n'
  exit 0
fi
printf 'unexpected cast invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_aws_secret_reader() {
  local target="$1"
  local expected_secret_arn="$2"
  local secret_value="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"
args=( "\$@" )
for ((i=0; i<\${#args[@]}; i++)); do
  if [[ "\${args[\$i]}" == "secretsmanager" && \$((i + 1)) -lt \${#args[@]} && "\${args[\$((i + 1))]}" == "get-secret-value" ]]; then
    secret_arn=""
    for ((j=0; j<\${#args[@]}; j++)); do
      if [[ "\${args[\$j]}" == "--secret-id" && \$((j + 1)) -lt \${#args[@]} ]]; then
        secret_arn="\${args[\$((j + 1))]}"
        break
      fi
    done
    [[ "\$secret_arn" == "$expected_secret_arn" ]] || {
      printf 'unexpected secret id: %s\n' "\$secret_arn" >&2
      exit 1
    }
    printf '%s\n' "$secret_value"
    exit 0
  fi
done
exit 0
EOF
  chmod +x "$target"
}

write_fake_ssm_aws() {
  local target="$1"
  local log_dir="$2"
  local instance_id="${3:-i-op001}"
  local private_ip="${4:-10.0.0.11}"
  local expected_secret_arn="${5:-}"
  local secret_value="${6:-}"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
log_dir="$log_dir"
instance_id="$instance_id"
private_ip="$private_ip"
expected_secret_arn="$expected_secret_arn"
secret_value="$secret_value"
mkdir -p "\$log_dir/ssm"
printf 'aws %s\n' "\$*" >>"\$log_dir/aws.log"

arg_after() {
  local want="\$1"
  shift
  local args=( "\$@" )
  for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[\$i]}" == "\$want" && \$((i + 1)) -lt \${#args[@]} ]]; then
      printf '%s\n' "\${args[\$((i + 1))]}"
      return 0
    fi
  done
  return 1
}

decode_ssm_command() {
  local wrapped="\$1"
  awk '
    /__INTENTS_JUNO_SSM_COMMAND__/ && !seen {
      seen = 1
      next
    }
    /^__INTENTS_JUNO_SSM_COMMAND__\$/ && seen {
      exit
    }
    seen {
      print
    }
  ' <<<"\$wrapped" | base64 --decode
}

record_staged_file() {
  local command="\$1"
  local payload_line payload destination prefix dest_prefix chunk
  local stage_b64="\$log_dir/ssm/stage-current.b64"

  if [[ "\$command" == *"sudo install -m 0600 /dev/null"* ]]; then
    rm -f "\$stage_b64"
  fi
  if [[ "\$command" == *"<<'__INTENTS_JUNO_SSM_STAGE_CHUNK__'"* ]]; then
    chunk="\$(awk '
      /<<'\''__INTENTS_JUNO_SSM_STAGE_CHUNK__'\''/ {
        in_chunk = 1
        next
      }
      /^__INTENTS_JUNO_SSM_STAGE_CHUNK__\$/ && in_chunk {
        in_chunk = 0
        next
      }
      in_chunk {
        printf "%s", \$0
      }
    ' <<<"\$command")"
    printf '%s' "\$chunk" >>"\$stage_b64"
    return 0
  fi
  if [[ "\$command" == *"sudo base64 --decode"* && "\$command" == *"sudo mv"* && -f "\$stage_b64" ]]; then
    destination="\$(awk '/^sudo mv / { print \$NF }' <<<"\$command" | tail -1)"
    destination="\${destination//\\\\/}"
    [[ -n "\$destination" ]] || return 0
    base64 --decode <"\$stage_b64" >"\$log_dir/\$(basename "\$destination")"
    rm -f "\$stage_b64"
    return 0
  fi

  payload_line="\$(grep -F " | base64 --decode | sudo tee " <<<"\$command" || true)"
  [[ -n "\$payload_line" ]] || return 0
  prefix="printf '%s' '"
  dest_prefix=' | base64 --decode | sudo tee "'
  payload="\${payload_line#"\$prefix"}"
  payload="\${payload%%"' | base64 --decode"*}"
  destination="\${payload_line#*"\$dest_prefix"}"
  destination="\${destination%%\\"*}"
  [[ -n "\$payload" && -n "\$destination" ]] || return 0
  printf '%s' "\$payload" | base64 --decode >"\$log_dir/\$(basename "\$destination")"
}

args=( "\$@" )
if [[ "\${args[*]}" == *"secretsmanager get-secret-value"* ]]; then
  secret_arn="\$(arg_after --secret-id "\${args[@]}" || true)"
  if [[ -n "\$expected_secret_arn" && "\$secret_arn" != "\$expected_secret_arn" ]]; then
    printf 'unexpected secret id: %s\n' "\$secret_arn" >&2
    exit 1
  fi
  printf '%s\n' "\$secret_value"
  exit 0
fi

if [[ "\${args[*]}" == *"ec2 describe-instances"* ]]; then
  query="\$(arg_after --query "\${args[@]}" || true)"
  case "\${args[*]}" in
    *'Name=ip-address,Values=10.9.0.222'* ) printf 'None\n' ;;
    *'Name=ip-address,Values=10.9.0.233'* ) printf 'None\n' ;;
    *'Name=private-ip-address,Values=10.9.0.222'* ) printf 'None\n' ;;
    *'Name=private-ip-address,Values=10.9.0.233'* ) printf 'None\n' ;;
    *'Name=private-ip-address,Values=10.9.0.44'* ) printf '10.9.0.44\n' ;;
    *'Name=tag:Operator,Values=op2'* ) printf '10.9.1.22\n' ;;
    *'Name=tag:Operator,Values=op3'* ) printf '10.9.1.33\n' ;;
    *'Name=tag:Operator,Values=op4'* ) printf '10.9.1.44\n' ;;
    * )
      if [[ "\$query" == *"InstanceId"* ]]; then
        printf '%s\n' "\$instance_id"
      elif [[ "\$query" == *"SecurityGroups"* ]]; then
        printf 'sg-op001\n'
      elif [[ "\$query" == *"PrivateIpAddress"* ]]; then
        printf '%s\n' "\$private_ip"
      else
        printf '%s\n' "\$private_ip"
      fi
      ;;
  esac
  exit 0
fi

if [[ "\${args[*]}" == *"ec2 authorize-security-group-ingress"* ]]; then
  exit 0
fi

if [[ "\${args[*]}" == *"route53 change-resource-record-sets"* ]]; then
  exit 0
fi

if [[ "\${args[*]}" == *"ssm send-command"* ]]; then
  params_ref="\$(arg_after --parameters "\${args[@]}")"
  params_file="\${params_ref#file://}"
  wrapped_command="\$(jq -r '.commands[0]' "\$params_file")"
  command="\$(decode_ssm_command "\$wrapped_command")"
  printf '%s\n---\n' "\$command" >>"\$log_dir/ssm.commands"
  record_staged_file "\$command"

  counter_file="\$log_dir/ssm/counter"
  count=0
  [[ -f "\$counter_file" ]] && count="\$(cat "\$counter_file")"
  count=\$((count + 1))
  printf '%s' "\$count" >"\$counter_file"
  command_id="cmd-\$count"
  stdout=""
  status="Success"
  stderr=""
  if [[ "\$command" == *"sudo systemctl is-active juno-scan"* && -n "\${PRODUCTION_TEST_JUNO_SCAN_INACTIVE_ATTEMPTS:-}" ]]; then
    scan_counter_file="\$log_dir/ssm/juno-scan.counter"
    scan_count=0
    [[ -f "\$scan_counter_file" ]] && scan_count="\$(cat "\$scan_counter_file")"
    scan_count=\$((scan_count + 1))
    printf '%s' "\$scan_count" >"\$scan_counter_file"
    if (( scan_count <= PRODUCTION_TEST_JUNO_SCAN_INACTIVE_ATTEMPTS )); then
      stdout="inactive"
    else
      stdout="active"
    fi
  elif [[ "\$command" == *"systemctl is-active"* ]]; then
    stdout="active"
  elif [[ "\$command" == *"/v1/health"* ]]; then
    stdout='{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
  elif [[ "\$command" == *"sudo cat"* && "\$command" == *"deploy-stage-manifest.json"* ]]; then
    stdout="\$(cat "\$log_dir/deploy-stage-manifest.json" 2>/dev/null || true)"
  elif [[ "\$command" == *"sudo cat"* && "\$command" == *"operator-stack.env"* ]]; then
    status="Failed"
    stderr="operator-stack.env must not be returned through SSM stdout"
  fi
  if [[ -n "\${PRODUCTION_TEST_FAIL_REMOTE_STAGE:-}" && "\$command" == *"sudo install -d -m 0700"* ]]; then
    status="Failed"
    stderr="stage failed"
  fi
  if [[ -n "\${PRODUCTION_TEST_UNMANIFESTED_STAGE_FILE:-}" && "\$command" == *"find . -mindepth 1 -maxdepth 1 -type f"* ]]; then
    status="Failed"
    stderr="prepared deploy stage directory file set mismatch"
  fi
  printf '%s' "\$stdout" >"\$log_dir/ssm/\$command_id.stdout"
  printf '%s' "\$status" >"\$log_dir/ssm/\$command_id.status"
  printf '%s' "\$stderr" >"\$log_dir/ssm/\$command_id.stderr"
  jq -n --arg id "\$command_id" '{Command:{CommandId:\$id}}'
  exit 0
fi

if [[ "\${args[*]}" == *"ssm get-command-invocation"* ]]; then
  command_id="\$(arg_after --command-id "\${args[@]}")"
  stdout="\$(cat "\$log_dir/ssm/\$command_id.stdout" 2>/dev/null || true)"
  status="\$(cat "\$log_dir/ssm/\$command_id.status" 2>/dev/null || printf 'Success')"
  stderr="\$(cat "\$log_dir/ssm/\$command_id.stderr" 2>/dev/null || true)"
  jq -n --arg status "\$status" --arg stdout "\$stdout" --arg stderr "\$stderr" '{Status:\$status,StandardOutputContent:\$stdout,StandardErrorContent:\$stderr}'
  exit 0
fi

exit 0
EOF
  chmod +x "$target"
}

write_inventory_fixture() {
  local target="$1"
  local workdir="$2"
  jq \
    --arg kh "$workdir/known_hosts" \
    --arg backup "$workdir/dkg-backup.zip" \
    --arg secrets "$workdir/operator-secrets.env" \
    '
      .operators[0].known_hosts_file = $kh
      | .operators[0].dkg_backup_zip = $backup
      | .operators[0].secret_contract_file = $secrets
    ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_dkg_summary_with_operator_key() {
  local target="$1"
  local operator_key_file="$2"
  jq \
    --arg operator_key_file "$operator_key_file" \
    '
      .operators[0].operator_key_file = $operator_key_file
    ' "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" >"$target"
}

test_deploy_operator_stages_live_juno_scan_artifacts() {
  local script_text
  script_text="$(cat "$REPO_ROOT/deploy/production/deploy-operator.sh")"

  assert_contains "$script_text" 'intents-juno-juno-scan.sh' "deploy-operator stages the live juno-scan wrapper"
  assert_contains "$script_text" 'intents-juno-juno-scan-backfill.sh' "deploy-operator stages the live juno-scan backfill wrapper"
  assert_contains "$script_text" 'juno-scan.service' "deploy-operator stages the juno-scan unit"
  assert_contains "$script_text" 'juno-scan-backfill.service' "deploy-operator stages the juno-scan backfill unit"
  assert_contains "$script_text" 'render_live_juno_scan_wrapper() {' "deploy-operator renders the staged juno-scan wrapper before rollout"
  assert_contains "$script_text" 'script="${script//__BOOTSTRAP_JUNO_SCAN_UA_HRP__/$juno_scan_ua_hrp}"' "deploy-operator resolves the staged juno-scan hrp placeholder"
  assert_contains "$script_text" 'script="${script//\\\$/\$}"' "deploy-operator unescapes staged juno-scan runtime env references"
}

test_deploy_operator_enforces_known_hosts_and_updates_rollout() {
  local workdir output_dir manifest shared_manifest log_dir fake_bin state_file terraform_output queueauth_secret_arn
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "production" | .operators[0].known_hosts_file = null' "$workdir/inventory.json" >"$workdir/inventory.tmp.json"
  mv "$workdir/inventory.tmp.json" "$workdir/inventory.json"
  jq '
    .operators[0].checkpoint_blob_bucket = "alpha-op1-dkg-keypackages"
    | .operators[0].checkpoint_blob_prefix = "operators/op1/checkpoint-packages"
    | .operators[0].checkpoint_blob_sse_kms_key_id = "arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  queueauth_secret_arn="arn:aws:secretsmanager:us-east-1:021490342184:secret:alpha-kafka-critical-hmac"
  terraform_output="$workdir/terraform-output.json"
  jq --arg arn "$queueauth_secret_arn" '.shared_kafka_critical_hmac_secret_arn = {value: $arn}' \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" >"$terraform_output"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$terraform_output" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  shared_manifest="$workdir/shared-manifest.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir" "i-op001" "10.0.0.11" "$queueauth_secret_arn" "queueauth-test-hmac-key"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/aws.log")" "ssm send-command --instance-ids i-op001" "deploy stages over ssm"
  assert_contains "$(cat "$log_dir/ssm.commands")" "ufvk.txt" "ufvk file copied"
  assert_contains "$(cat "$log_dir/ssm.commands")" "intents-juno-config-hydrator.sh" "config hydrator copied"
  assert_contains "$(cat "$log_dir/ssm.commands")" "dkg-peer-hosts.json" "distributed dkg peer host map copied"
  assert_contains "$(cat "$log_dir/ssm.commands")" "backup-package.sh" "backup package helper staged"
  assert_contains "$(cat "$log_dir/ssm.commands")" "common.sh" "dkg common helper staged"
  assert_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh" "operator rollout script staged"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "fetch_restore_package" "remote rollout fetches runtime material"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'aws --region "$runtime_material_region" s3 cp' "remote rollout restores from S3 runtime material"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo bash "$backup_package_script" restore --package "$restore_package_path" --workdir "$runtime_dir" --force' "remote rollout restores runtime material through backup-package"
  assert_line_order "$(cat "$log_dir/run-operator-rollout.sh")" "fetch_restore_package" "restore_runtime" "remote rollout fetches runtime material before restore"
  assert_line_order "$(cat "$log_dir/run-operator-rollout.sh")" "restore_runtime" "hydrate_and_restart" "remote rollout restores runtime before service restarts"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$signer_ufvk_file" "$runtime_dir/ufvk.txt"' "remote rollout stages signer ufvk file"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo systemctl reset-failed "$svc" || true' "remote rollout clears systemd start limits before restart"
  assert_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active junocashd" "deploy verifies junocashd after restarting it"
  assert_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active juno-scan" "deploy verifies juno-scan after restarting it"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "kms signer driver staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "kms signer key id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_SSE_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/bbbbbbbb-cccc-dddd-eeee-ffffffffffff" "checkpoint blob sse kms key id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "OPERATOR_ADDRESS=0x9999999999999999999999999999999999999999" "operator address staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232" "withdraw coordinator rpc url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000" "withdraw coordinator juno fee floor staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240" "withdraw coordinator juno expiry offset staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h" "withdraw coordinator expiry safety margin staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h" "withdraw coordinator max expiry extension staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=/usr/local/bin/intents-juno-multikey-extend-signer.sh" "withdraw coordinator extend signer staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_QUEUE_CRITICAL_KEY_ID=default" "queueauth key id staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_QUEUE_CRITICAL_HMAC_KEY=queueauth-test-hmac-key" "queueauth HMAC key staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_SCAN_BACKFILL_FROM_HEIGHT=0" "scanner backfill floor staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080" "withdraw finalizer scan url staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_EVENT_SCANNER_START_BLOCK=12345" "base event scanner start block staged"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "DEPOSIT_RELAYER_BASE_RPC_URL=https://base-sepolia.example.invalid" "deposit relayer rpc url staged independently"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'intents-juno-juno-scan-backfill.sh' "remote rollout stages the scanner backfill wrapper"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0644 "$stage_dir/juno-scan-backfill.service" /etc/systemd/system/juno-scan-backfill.service' "remote rollout installs the scanner backfill service unit"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo systemctl restart "$svc"' "remote rollout restarts staged services"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "/v1/wallets/wallet-op1/backfill" "deploy no longer blocks on synchronous wallet backfill over ssh"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt" "tss ufvk path staged"
  assert_contains "$(cat "$log_dir/ufvk.txt")" "uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" "ufvk value staged"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "kms operator env omits private key"
  assert_contains "$(cat "$log_dir/cast.log")" "call --rpc-url https://base-sepolia.example.invalid 0x4444444444444444444444444444444444444444 isOperator(address)(bool) 0x9999999999999999999999999999999999999999" "deploy validates operator registry membership before rollout"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_ALLOWED_CONTRACTS=0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333,0x4444444444444444444444444444444444444444,0x5555555555555555555555555555555555555555" "allowlist injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_ALLOWED_SELECTORS=0x53a58a48,0xec70b605,0xfe097d57" "selector allowlist injected"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_PER_SECOND=20" "rate limit refill default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_BURST=40" "rate limit burst default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_RATE_LIMIT_MAX_TRACKED_CLIENTS=10000" "rate limit capacity default"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_URL=http://127.0.0.1:18081" "base relayer url"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "operator env uses operator-owned checkpoint bucket"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_PREFIX=operators/op1/checkpoint-packages" "operator env uses operator-owned checkpoint prefix"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-dkg-keypackages" "operator env omits shared checkpoint bucket when operator bucket is configured"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_respects_scan_backfill_from_height_override() {
  local workdir output_dir manifest log_dir fake_bin
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "production" | .operators[0].known_hosts_file = null' "$workdir/inventory.json" >"$workdir/inventory.tmp.json"
  mv "$workdir/inventory.tmp.json" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":118298,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":100000,"to_height":118298,"scanned_from":100000,"scanned_to":109999,"next_height":118299,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PRODUCTION_DEPLOY_SCAN_BACKFILL_FROM_HEIGHT=100000 PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-operator.sh" --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_SCAN_BACKFILL_FROM_HEIGHT=100000" "deploy stages the configured scanner backfill start height"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "/v1/wallets/wallet-op1/backfill" "deploy does not issue synchronous wallet backfill requests when a custom floor is configured"
  rm -rf "$workdir"
}

test_deploy_operator_stages_distributed_dkg_server_tls() {
  local workdir output_dir manifest shared_manifest log_dir fake_bin state_file cert_b64 key_b64 san_text
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin" "$workdir/dkg-tls"

  write_test_dkg_tls_dir "$workdir/source-dkg-tls"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip" "$workdir/source-dkg-tls"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  write_test_dkg_tls_dir "$workdir/dkg-tls"
  rm -f "$workdir/dkg-tls/server.pem" "$workdir/dkg-tls/server.key"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  shared_manifest="$workdir/shared-manifest.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "dkg-server.pem" "deploy copies generated dkg server cert"
  assert_contains "$(cat "$log_dir/ssm.commands")" "dkg-server.key" "deploy copies generated dkg server key"
  assert_contains "$(cat "$log_dir/ssm.commands")" "coordinator-client.pem" "deploy copies dkg coordinator client cert"
  assert_contains "$(cat "$log_dir/ssm.commands")" "coordinator-client.key" "deploy copies dkg coordinator client key"
  assert_contains "$(cat "$log_dir/ssm.commands")" "ca.pem" "deploy copies dkg ca"
  assert_contains "$(cat "$log_dir/aws.log")" "describe-instances" "deploy resolves peer hosts through aws"
  assert_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress" "deploy ensures operator grpc mesh ingress"
  assert_contains "$(cat "$log_dir/aws.log")" '"FromPort":8443' "deploy ensures operator dkg admin mesh ingress"
  assert_contains "$(cat "$log_dir/dkg-peer-hosts.json")" "10.0.0.11" "deploy writes resolved peer hosts"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_TSS_SERVER_NAME=10.0.0.11" "deploy stages tss server name override from resolved private host"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0640 -o root -g intents-juno "$stage_dir/ca.pem" "$runtime_dir/bundle/tls/ca.pem"' "remote deploy installs shared dkg ca"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0640 -o root -g intents-juno "$stage_dir/coordinator-client.pem" "$runtime_dir/bundle/tls/coordinator-client.pem"' "remote deploy installs shared dkg coordinator client cert"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$stage_dir/coordinator-client.key" "$runtime_dir/bundle/tls/coordinator-client.key"' "remote deploy installs shared dkg coordinator client key"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "coordinator_client_cert_sha256" "remote deploy refreshes dkg coordinator client fingerprint"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "tls_client_cert_pem_path" "remote deploy patches dkg admin config with tls client cert path"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "tls_client_key_pem_path" "remote deploy patches dkg admin config with tls client key path"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "operator runtime admin config missing coordinator client tls paths" "remote deploy verifies final dkg admin client tls paths"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" "operator runtime admin config missing coordinator client fingerprint" "remote deploy verifies final dkg admin client fingerprint"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0640 -o root -g intents-juno "$stage_dir/dkg-server.pem" "$runtime_dir/bundle/tls/server.pem"' "remote deploy installs generated dkg server cert"
  assert_contains "$(cat "$log_dir/run-operator-rollout.sh")" 'sudo install -m 0600 -o intents-juno -g intents-juno "$stage_dir/dkg-server.key" "$runtime_dir/bundle/tls/server.key"' "remote deploy installs generated dkg server key"
  san_text="$(openssl x509 -in "$log_dir/dkg-server.pem" -noout -ext subjectAltName 2>/dev/null)"
  assert_contains "$san_text" "DNS:localhost" "generated cert preserves localhost san"
  assert_contains "$san_text" "IP Address:10.0.0.11" "generated cert includes resolved peer host"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_prefers_manifest_private_endpoints_for_dkg_peer_hosts() {
  local workdir output_dir manifest state_file log_dir fake_bin cert_b64 key_b64
  local peer_manifest_one peer_manifest_two dkg_peer_hosts
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "production" | .operators[0].known_hosts_file = null' "$workdir/inventory.json" >"$workdir/inventory.tmp.json"
  mv "$workdir/inventory.tmp.json" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/mainnet" "$workdir"

  manifest="$output_dir/mainnet/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/mainnet/rollout-state.json"
  peer_manifest_one="$output_dir/mainnet/operators/0x2222222222222222222222222222222222222222/operator-deploy.json"
  peer_manifest_two="$output_dir/mainnet/operators/0x3333333333333333333333333333333333333333/operator-deploy.json"
  mkdir -p "$(dirname "$peer_manifest_one")" "$(dirname "$peer_manifest_two")"
  jq -n '{
    operator_id: "0x2222222222222222222222222222222222222222",
    operator_host: "203.0.113.22",
    public_endpoint: "203.0.113.22",
    private_endpoint: "10.9.0.22",
    operator_probe_host: "10.9.0.22",
    aws_profile: "juno",
    aws_region: "us-east-1"
  }' >"$peer_manifest_one"
  jq -n '{
    operator_id: "0x3333333333333333333333333333333333333333",
    operator_host: "203.0.113.33",
    public_endpoint: "203.0.113.33",
    private_endpoint: "10.9.0.33",
    operator_probe_host: "10.9.0.33",
    aws_profile: "juno",
    aws_region: "us-east-1"
  }' >"$peer_manifest_two"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  dkg_peer_hosts="$(cat "$log_dir/dkg-peer-hosts.json")"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x2222222222222222222222222222222222222222") | .host' <<<"$dkg_peer_hosts")" "10.9.0.22" "deploy uses manifest private endpoint for peer one"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x3333333333333333333333333333333333333333") | .host' <<<"$dkg_peer_hosts")" "10.9.0.33" "deploy uses manifest private endpoint for peer two"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .host' <<<"$dkg_peer_hosts")" "10.0.0.11" "deploy still resolves the current operator host for local tls identity"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_TSS_SERVER_NAME=10.0.0.11" "deploy still resolves the current operator host for local tls identity"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_prefers_confirmed_private_operator_host_over_tag_fallback() {
  local workdir output_dir manifest state_file log_dir fake_bin cert_b64 key_b64
  local dkg_peer_hosts
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "production" | .operators[0].known_hosts_file = null' "$workdir/inventory.json" >"$workdir/inventory.tmp.json"
  mv "$workdir/inventory.tmp.json" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/mainnet" "$workdir"

  manifest="$output_dir/mainnet/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/mainnet/rollout-state.json"
  jq '
    .operator_host = "10.9.0.44"
    | .public_endpoint = "198.51.100.44"
    | .private_endpoint = null
    | .operator_probe_host = null
    | .aws_profile = "mainnet-op4"
    | .aws_region = "us-east-1"
    | .operator_role.operator_host = "10.9.0.44"
    | .operator_role.public_endpoint = "198.51.100.44"
  ' "$manifest" >"$manifest.tmp"
  mv "$manifest.tmp" "$manifest"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir" "i-op004" "10.9.0.44"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  dkg_peer_hosts="$(cat "$log_dir/dkg-peer-hosts.json")"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .host' <<<"$dkg_peer_hosts")" "10.9.0.44" "deploy keeps confirmed explicit private operator host for local tls identity"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "WITHDRAW_COORDINATOR_TSS_SERVER_NAME=10.9.0.44" "deploy stages tss server name from confirmed explicit private operator host"
  assert_not_contains "$(cat "$log_dir/aws.log")" 'Name=tag:Operator,Values=op4' "deploy does not use ambiguous tag fallback after confirming explicit private operator host"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_resolves_stale_peer_hosts_by_operator_profile_tag() {
  local workdir output_dir manifest state_file log_dir fake_bin cert_b64 key_b64
  local peer_manifest_one peer_manifest_two dkg_peer_hosts
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '.environment = "production" | .operators[0].known_hosts_file = null' "$workdir/inventory.json" >"$workdir/inventory.tmp.json"
  mv "$workdir/inventory.tmp.json" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/mainnet" "$workdir"

  manifest="$output_dir/mainnet/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/mainnet/rollout-state.json"
  peer_manifest_one="$output_dir/mainnet/operators/0x2222222222222222222222222222222222222222/operator-deploy.json"
  peer_manifest_two="$output_dir/mainnet/operators/0x3333333333333333333333333333333333333333/operator-deploy.json"
  mkdir -p "$(dirname "$peer_manifest_one")" "$(dirname "$peer_manifest_two")"
  jq -n '{
    operator_id: "0x2222222222222222222222222222222222222222",
    operator_host: "10.9.0.222",
    public_endpoint: "198.51.100.22",
    aws_profile: "mainnet-op2",
    aws_region: "us-east-2"
  }' >"$peer_manifest_one"
  jq -n '{
    operator_id: "0x3333333333333333333333333333333333333333",
    operator_host: "10.9.0.233",
    public_endpoint: "198.51.100.33",
    aws_profile: "mainnet-op3",
    aws_region: "eu-west-1"
  }' >"$peer_manifest_two"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir" "i-op001" "10.0.0.10"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  dkg_peer_hosts="$(cat "$log_dir/dkg-peer-hosts.json")"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x2222222222222222222222222222222222222222") | .host' <<<"$dkg_peer_hosts")" "10.9.1.22" "deploy resolves stale peer one through operator tag lookup"
  assert_eq "$(jq -r '.[] | select(.operator_id=="0x3333333333333333333333333333333333333333") | .host' <<<"$dkg_peer_hosts")" "10.9.1.33" "deploy resolves stale peer two through operator tag lookup"
  assert_contains "$(cat "$log_dir/aws.log")" 'Name=tag:Operator,Values=op2' "deploy falls back to operator tag lookup for peer one"
  assert_contains "$(cat "$log_dir/aws.log")" 'Name=tag:Operator,Values=op3' "deploy falls back to operator tag lookup for peer two"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  rm -rf "$workdir"
}

test_deploy_operator_dry_run_does_not_mutate_rollout_or_remote_state() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
cat >>"$log_dir/run-operator-rollout.sh" || true
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --dry-run >/dev/null

  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "dry-run leaves rollout state pending"
  if [[ -e "$log_dir/ssm.commands" ]]; then
    printf 'expected dry-run to avoid scp but saw:\n%s\n' "$(cat "$log_dir/ssm.commands")" >&2
    exit 1
  fi
  if [[ -e "$log_dir/ssm.commands" ]]; then
    printf 'expected dry-run to avoid ssh but saw:\n%s\n' "$(cat "$log_dir/ssm.commands")" >&2
    exit 1
  fi
  if [[ -e "$log_dir/aws.log" ]]; then
    assert_not_contains "$(cat "$log_dir/aws.log")" "authorize-security-group-ingress" "dry-run avoids mutating security groups"
  fi

  rm -rf "$workdir"
}

test_deploy_operator_prepare_only_stages_without_rollout() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "sudo install -d -m 0700" "prepare-only creates a private remote stage directory"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "sudo install -d -m 0755 /tmp/intents-juno-deploy" "prepare-only keeps the remote deploy stage directory private"
  assert_contains "$(cat "$log_dir/ssm.commands")" "operator-stack.env" "prepare-only stages rendered operator env"
  assert_contains "$(cat "$log_dir/ssm.commands")" "deploy-stage-manifest.json" "prepare-only stages the package manifest last"
  assert_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh" "prepare-only stages the remote rollout script"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "prepare-only does not apply the staged rollout"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active checkpoint-signer" "prepare-only does not wait on restarted services"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "prepare-only leaves rollout status pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_runs_without_restaging() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  rm -f "$log_dir/ssm.commands"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "sudo cat" "apply-prepared reads the prepared stage manifest"
  assert_contains "$(cat "$log_dir/ssm.commands")" "deploy-stage-manifest.json" "apply-prepared validates the prepared package manifest"
  assert_contains "$(cat "$log_dir/ssm.commands")" 'env_file="$remote_stage_dir/operator-stack.env"' "apply-prepared uses the prepared operator env remotely"
  assert_contains "$(cat "$log_dir/ssm.commands")" 'stat -c '\''%a'\'' "$stage_dir"' "apply-prepared verifies the remote stage directory mode"
  assert_contains "$(cat "$log_dir/ssm.commands")" 'stat -c '\''%a'\'' "$path"' "apply-prepared verifies staged file modes"
  assert_contains "$(cat "$log_dir/ssm.commands")" "sha256sum -c" "apply-prepared verifies staged file checksums before rollout"
  assert_contains "$(cat "$log_dir/ssm.commands")" "trap cleanup EXIT" "apply-prepared cleans up the staged package after rollout"
  assert_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "apply-prepared points at the staged remote rollout"
  assert_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active checkpoint-signer" "apply-prepared waits on restarted services"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "sudo install -d -m 0700" "apply-prepared does not recreate the remote stage directory"
  assert_no_ssm_cat_operator_stack_env "$log_dir/ssm.commands" "apply-prepared does not read the full prepared env over ssm"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "operator-stack.env.b64" "apply-prepared does not restage operator-stack.env"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "apply-prepared completes rollout status"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_dry_run_verifies_without_rollout() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  rm -f "$log_dir/ssm.commands"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared \
    --dry-run >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "deploy-stage-manifest.json" "apply-prepared dry-run validates the prepared package manifest"
  assert_contains "$(cat "$log_dir/ssm.commands")" "sha256sum -c" "apply-prepared dry-run verifies staged file checksums"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "apply-prepared dry-run does not run the staged remote rollout"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active checkpoint-signer" "apply-prepared dry-run does not wait on services"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "apply-prepared dry-run leaves rollout pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_rejects_stale_manifest() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  jq '.deposit_relayer_release_tag = "app-binaries-drifted"' "$manifest" >"$manifest.tmp"
  mv "$manifest.tmp" "$manifest"
  rm -f "$log_dir/ssm.commands"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null 2>&1; then
    printf 'expected apply-prepared to reject a stale prepared package\n' >&2
    exit 1
  fi
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "stale apply-prepared fails before remote rollout"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "stale apply-prepared leaves rollout pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_rejects_extra_manifest_path() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  jq '.files += [{path:"junocashd.conf",mode:"0640",sha256:"0000000000000000000000000000000000000000000000000000000000000000"}]' "$log_dir/deploy-stage-manifest.json" >"$log_dir/deploy-stage-manifest.next"
  mv "$log_dir/deploy-stage-manifest.next" "$log_dir/deploy-stage-manifest.json"
  rm -f "$log_dir/ssm.commands"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null 2>&1; then
    printf 'expected apply-prepared to reject an unexpected stage manifest path\n' >&2
    exit 1
  fi

  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "extra stage manifest path fails before remote rollout"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "extra stage manifest path leaves rollout pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_accepts_dkg_tls_package() {
  local workdir output_dir log_dir fake_bin manifest state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  write_test_dkg_tls_dir "$workdir/dkg-tls"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip" "$workdir/dkg-tls"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null

  assert_file_exists "$log_dir/dkg-server.pem" "prepare-only stages generated dkg server cert"
  assert_file_exists "$log_dir/dkg-server.key" "prepare-only stages generated dkg server key"
  assert_contains "$(cat "$log_dir/deploy-stage-manifest.json")" "dkg-server.pem" "stage manifest records generated dkg server cert"
  assert_contains "$(cat "$log_dir/deploy-stage-manifest.json")" "dkg-server.key" "stage manifest records generated dkg server key"
  mv "$workdir/dkg-tls" "$workdir/dkg-tls.removed"
  rm -f "$log_dir/ssm.commands"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "deploy-stage-manifest.json" "apply-prepared validates the prepared dkg package manifest"
  assert_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "apply-prepared rolls out the prepared dkg package"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "dkg tls dir not found" "apply-prepared uses prepared dkg tls material instead of local tls files"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "apply-prepared dkg package completes rollout"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_rejects_missing_dkg_tls_artifact() {
  local workdir output_dir log_dir fake_bin manifest state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  write_test_dkg_tls_dir "$workdir/dkg-tls"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip" "$workdir/dkg-tls"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  jq '(.files) |= map(select(.path != "dkg-server.pem"))' "$log_dir/deploy-stage-manifest.json" >"$log_dir/deploy-stage-manifest.next"
  mv "$log_dir/deploy-stage-manifest.next" "$log_dir/deploy-stage-manifest.json"
  rm -f "$log_dir/ssm.commands"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null 2>&1; then
    printf 'expected apply-prepared to reject a prepared package missing DKG TLS artifacts\n' >&2
    exit 1
  fi

  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "missing dkg tls artifact fails before remote rollout"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "missing dkg tls artifact leaves rollout pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_rejects_unmanifested_stage_file() {
  local workdir output_dir log_dir fake_bin manifest state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  write_test_dkg_tls_dir "$workdir/dkg-tls"
  write_test_dkg_backup_zip "$workdir/dkg-backup.zip" "$workdir/dkg-tls"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq --arg dkg_tls_dir "$workdir/dkg-tls" '.dkg_tls_dir = $dkg_tls_dir' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --prepare-only >/dev/null
  rm -f "$log_dir/ssm.commands"

  if PRODUCTION_TEST_UNMANIFESTED_STAGE_FILE=true PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
      --operator-deploy "$manifest" \
      --apply-prepared >/dev/null 2>&1; then
    printf 'expected apply-prepared to reject unmanifested staged files\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$log_dir/ssm.commands")" "find . -mindepth 1 -maxdepth 1 -type f" "apply-prepared compares actual remote stage files against manifest"
  assert_not_contains "$(cat "$log_dir/ssm.commands")" "run-operator-rollout.sh\" --stage-dir" "unmanifested stage file fails before remote rollout"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "pending" "unmanifested stage file leaves rollout pending"

  rm -rf "$workdir"
}

test_deploy_operator_apply_prepared_done_state_requires_force() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  jq '(.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111")).status = "done"' "$state_file" >"$state_file.tmp"
  mv "$state_file.tmp" "$state_file"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  chmod +x "$fake_bin/aws"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --apply-prepared >/dev/null 2>&1; then
    printf 'expected apply-prepared to require --force when rollout state is done\n' >&2
    exit 1
  fi
  if [[ -e "$log_dir/ssm.commands" ]]; then
    printf 'expected apply-prepared done-state failure before SSM but saw:\n%s\n' "$(cat "$log_dir/ssm.commands")" >&2
    exit 1
  fi

  rm -rf "$workdir"
}

test_deploy_operator_full_deploy_marks_failed_when_staging_fails() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/aws" "$fake_bin/cast"

  if PRODUCTION_TEST_FAIL_REMOTE_STAGE=true PATH="$fake_bin:$PATH" \
    bash "$REPO_ROOT/deploy/production/deploy-operator.sh" --operator-deploy "$manifest" >/dev/null 2>&1; then
    printf 'expected full deploy to fail when remote staging fails\n' >&2
    exit 1
  fi

  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "failed" "full deploy staging failure marks rollout failed"

  rm -rf "$workdir"
}

test_deploy_operator_stages_base_relayer_ready_balance_floor() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=literal:wallet-op1
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=literal:wallet-op1
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "rollout status"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "BASE_RELAYER_MIN_READY_BALANCE_WEI=1000000000000000" "operator env stages base relayer readiness balance floor"
  assert_not_contains "$(cat "$log_dir/cast.log")" "balance --rpc-url" "deploy leaves base relayer readiness enforcement to the base-relayer wrapper"

  rm -rf "$workdir"
}

test_deploy_operator_force_reruns_done_operator() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"
  jq '(.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111")).status = "done"' "$state_file" >"$state_file.tmp"
  mv "$state_file.tmp" "$state_file"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
fi
cat >>"$log_dir/run-operator-rollout.sh" || true
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" \
    --force >/dev/null

  assert_contains "$(cat "$log_dir/ssm.commands")" "operator-deploy.json" "force rerun still stages manifest files"
  assert_contains "$(cat "$log_dir/ssm.commands")" "systemctl is-active checkpoint-signer" "force rerun still verifies restarted services"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "force rerun preserves done rollout status after redeploy"
  rm -rf "$workdir"
}

test_deploy_operator_retries_transient_service_checks() {
  local workdir output_dir log_dir fake_bin manifest state_file cert_b64 key_b64
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'backup' >"$workdir/dkg-backup.zip"
  cert_b64="$(printf 'test-cert' | base64 | tr -d '\n')"
  key_b64="$(printf 'test-key' | base64 | tr -d '\n')"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=literal:postgres://alpha
BASE_RELAYER_PRIVATE_KEYS=literal:0x1111111111111111111111111111111111111111111111111111111111111111
BASE_RELAYER_AUTH_TOKEN=env:TEST_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=literal:juno
JUNO_RPC_PASS=literal:rpcpass
JUNO_TXSIGN_SIGNER_KEYS=literal:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_CERT_PEM_B64=literal:%s\n' "$cert_b64" >>"$workdir/operator-secrets.env"
  printf 'BASE_RELAYER_TLS_KEY_PEM_B64=literal:%s\n' "$key_b64" >>"$workdir/operator-secrets.env"
  export TEST_BASE_RELAYER_AUTH_TOKEN="token"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/alpha" "$workdir"

  manifest="$output_dir/alpha/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/alpha/rollout-state.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
if [[ "\$*" == *"systemctl is-active juno-scan"* ]]; then
  counter_file="$log_dir/juno-scan.counter"
  count=0
  if [[ -f "\$counter_file" ]]; then
    count="\$(cat "\$counter_file")"
  fi
  count=\$((count + 1))
  printf '%s' "\$count" >"\$counter_file"
  if (( count < 3 )); then
    printf 'inactive\n'
    exit 0
  fi
  printf 'active\n'
  exit 0
fi
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
  exit 0
fi
cat >>"$log_dir/run-operator-rollout.sh" || true
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PRODUCTION_DEPLOY_SERVICE_ACTIVE_RETRIES=5 \
  PRODUCTION_DEPLOY_SERVICE_ACTIVE_SLEEP_SECONDS=0.01 \
  PRODUCTION_TEST_JUNO_SCAN_INACTIVE_ATTEMPTS=2 \
  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  if [[ "$(grep -c 'systemctl is-active juno-scan' "$log_dir/ssm.commands")" -lt 3 ]]; then
    printf 'expected deploy-operator.sh to retry juno-scan readiness\n' >&2
    exit 1
  fi
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "transient service retries still complete rollout"
  rm -rf "$workdir"
}

test_deploy_operator_preserves_secure_preview_signer_configuration() {
  local workdir output_dir manifest log_dir fake_bin state_file
  workdir="$(mktemp -d)"
  output_dir="$workdir/output"
  log_dir="$workdir/logs"
  fake_bin="$workdir/bin"
  mkdir -p "$log_dir" "$fake_bin"

  printf 'preview-backup' >"$workdir/dkg-backup.zip"
  export TEST_PREVIEW_CHECKPOINT_POSTGRES_DSN="postgres://preview?sslmode=require"
  export TEST_PREVIEW_BASE_RELAYER_KEYS="0x1111111111111111111111111111111111111111111111111111111111111111"
  export TEST_PREVIEW_BASE_RELAYER_AUTH_TOKEN="preview-token"
  export TEST_PREVIEW_JUNO_RPC_USER="juno"
  export TEST_PREVIEW_JUNO_RPC_PASS="rpcpass"
  export TEST_PREVIEW_WALLET_ID="wallet-op1"
  export TEST_PREVIEW_JUNO_TXSIGN_SIGNER_KEYS="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  cat >"$workdir/operator-secrets.env" <<'EOF'
CHECKPOINT_POSTGRES_DSN=env:TEST_PREVIEW_CHECKPOINT_POSTGRES_DSN
BASE_RELAYER_PRIVATE_KEYS=env:TEST_PREVIEW_BASE_RELAYER_KEYS
BASE_RELAYER_AUTH_TOKEN=env:TEST_PREVIEW_BASE_RELAYER_AUTH_TOKEN
JUNO_RPC_USER=env:TEST_PREVIEW_JUNO_RPC_USER
JUNO_RPC_PASS=env:TEST_PREVIEW_JUNO_RPC_PASS
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=env:TEST_PREVIEW_WALLET_ID
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=env:TEST_PREVIEW_WALLET_ID
JUNO_TXSIGN_SIGNER_KEYS=env:TEST_PREVIEW_JUNO_TXSIGN_SIGNER_KEYS
EOF
  append_default_owallet_proof_keys "$workdir/operator-secrets.env"
  cp "$REPO_ROOT/deploy/production/tests/fixtures/known_hosts" "$workdir/known_hosts"
  write_inventory_fixture "$workdir/inventory.json" "$workdir"
  jq '
    .environment = "preview"
    | .shared_services.public_subdomain = "preview.intents-testing.thejunowallet.com"
  ' "$workdir/inventory.json" >"$workdir/inventory.next"
  mv "$workdir/inventory.next" "$workdir/inventory.json"

  production_render_shared_manifest \
    "$workdir/inventory.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/bridge-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" \
    "$REPO_ROOT/deploy/production/tests/fixtures/terraform-output.json" \
    "$workdir/shared-manifest.json" \
    "$workdir"
  production_render_operator_handoffs "$workdir/inventory.json" "$workdir/shared-manifest.json" "$REPO_ROOT/deploy/production/tests/fixtures/dkg-summary.json" "$output_dir/preview" "$workdir"

  manifest="$output_dir/preview/operators/0x1111111111111111111111111111111111111111/operator-deploy.json"
  state_file="$output_dir/preview/rollout-state.json"

  cat >"$fake_bin/scp" <<EOF
#!/usr/bin/env bash
printf 'scp %s\n' "\$*" >>"$log_dir/ssm.commands"
for arg in "\$@"; do
  if [[ -f "\$arg" ]]; then
    cp "\$arg" "$log_dir/\$(basename "\$arg")"
  fi
done
exit 0
EOF
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$log_dir/ssm.commands"
stdin_file="$log_dir/ssh.stdin.capture"
cat >"\$stdin_file" || true
cat "\$stdin_file" >>"$log_dir/run-operator-rollout.sh"
if [[ "\$*" == *"systemctl is-active"* ]]; then
  printf 'active\n'
elif [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":5000,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":0,"to_height":5000,"scanned_from":0,"scanned_to":5000,"next_height":5001,"inserted_notes":1,"inserted_events":2}'
fi
exit 0
EOF
  write_fake_ssm_aws "$fake_bin/aws" "$log_dir"
  write_fake_cast "$fake_bin/cast" "$log_dir/cast.log" "1300000000000000"
  chmod +x "$fake_bin/scp" "$fake_bin/ssh" "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/deploy-operator.sh" \
    --operator-deploy "$manifest" >/dev/null

  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_DRIVER=aws-kms" "preview operator env stages kms checkpoint signer mode"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "preview operator env stages the checkpoint signer kms key"
  assert_not_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_SIGNER_PRIVATE_KEY=" "preview operator env omits local checkpoint signer key material"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "CHECKPOINT_BLOB_BUCKET=alpha-op1-dkg-keypackages" "preview operator env stages the checkpoint package bucket required by config hydration"
  assert_contains "$(cat "$log_dir/operator-stack.env")" "JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam" "preview operator env stages kafka auth iam"
  assert_eq "$(jq -r '.operators[] | select(.operator_id=="0x1111111111111111111111111111111111111111") | .status' "$state_file")" "done" "preview secure signer rollout succeeds"
  rm -rf "$workdir"
}

main() {
  test_deploy_operator_stages_live_juno_scan_artifacts
  test_deploy_operator_enforces_known_hosts_and_updates_rollout
  test_deploy_operator_respects_scan_backfill_from_height_override
  test_deploy_operator_stages_distributed_dkg_server_tls
  test_deploy_operator_prefers_manifest_private_endpoints_for_dkg_peer_hosts
  test_deploy_operator_prefers_confirmed_private_operator_host_over_tag_fallback
  test_deploy_operator_resolves_stale_peer_hosts_by_operator_profile_tag
  test_deploy_operator_dry_run_does_not_mutate_rollout_or_remote_state
  test_deploy_operator_prepare_only_stages_without_rollout
  test_deploy_operator_apply_prepared_runs_without_restaging
  test_deploy_operator_apply_prepared_dry_run_verifies_without_rollout
  test_deploy_operator_apply_prepared_rejects_stale_manifest
  test_deploy_operator_apply_prepared_rejects_extra_manifest_path
  test_deploy_operator_apply_prepared_accepts_dkg_tls_package
  test_deploy_operator_apply_prepared_rejects_missing_dkg_tls_artifact
  test_deploy_operator_apply_prepared_rejects_unmanifested_stage_file
  test_deploy_operator_apply_prepared_done_state_requires_force
  test_deploy_operator_full_deploy_marks_failed_when_staging_fails
  test_deploy_operator_stages_base_relayer_ready_balance_floor
  test_deploy_operator_force_reruns_done_operator
  test_deploy_operator_retries_transient_service_checks
  test_deploy_operator_preserves_secure_preview_signer_configuration
}

main "$@"
