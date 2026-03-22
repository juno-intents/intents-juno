#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if grep -Fq -- "$needle" <<<"$haystack"; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_provision_app_edge_fixture() {
  local target="$1"
  local state_path="$2"
  cat >"$target" <<JSON
{
  "environment": "preview",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "security_group_id": "",
  "dns": {
    "zone_id": "Z01169511CVMQJAD7T3TJ"
  },
  "services": {
    "bridge_api": {
      "record_name": "bridge.preview.intents-testing.thejunowallet.com"
    }
  },
  "edge": {
    "enabled": true,
    "origin_record_name": "origin.preview.intents-testing.thejunowallet.com",
    "public_lb_dns_name": "juno-app-runtime-preview-bridge-1076285917.us-east-1.elb.amazonaws.com",
    "origin_http_port": 443,
    "rate_limit": 2000,
    "alarm_actions": [
      "arn:aws:sns:us-east-1:021490342184:preview-app-edge"
    ],
    "state_path": "$state_path",
    "enable_shield_advanced": false
  }
}
JSON
}

write_fake_provision_app_edge_terraform() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'terraform %s\n' "$*" >>"$TEST_TERRAFORM_LOG"
args=( "$@" )
while [[ ${#args[@]} -gt 0 ]]; do
  case "${args[0]}" in
    -chdir=*)
      args=( "${args[@]:1}" )
      ;;
    *)
      break
      ;;
  esac
done
case "${args[0]:-}" in
  init|apply)
    exit 0
    ;;
  state)
    [[ "${args[1]:-}" == "list" ]] || {
      printf 'unexpected terraform state invocation: %s\n' "$*" >&2
      exit 1
    }
    if [[ -n "${TEST_TERRAFORM_STATE_LIST:-}" ]]; then
      printf '%s\n' "$TEST_TERRAFORM_STATE_LIST"
    fi
    exit 0
    ;;
  import)
    exit 0
    ;;
esac
printf 'unexpected terraform invocation: %s\n' "$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_fake_provision_app_edge_aws() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >>"$TEST_AWS_LOG"
args=( "$@" )
while [[ ${#args[@]} -gt 0 ]]; do
  case "${args[0]}" in
    --profile|--region)
      args=( "${args[@]:2}" )
      ;;
    *)
      break
      ;;
  esac
done
case "${args[*]}" in
  "wafv2 list-web-acls --scope CLOUDFRONT --output json")
    if [[ -n "${TEST_WAF_LIST_JSON_FILE:-}" ]]; then
      cat "$TEST_WAF_LIST_JSON_FILE"
    else
      printf '%s\n' '{"WebACLs":[]}'
    fi
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "$target"
}

test_provision_app_edge_imports_existing_waf_when_state_is_missing_it() {
  local tmp fake_bin app_deploy state_path terraform_log aws_log waf_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  app_deploy="$tmp/app-deploy.json"
  state_path="$tmp/edge-state/preview.tfstate"
  terraform_log="$tmp/terraform.log"
  aws_log="$tmp/aws.log"
  waf_json="$tmp/waf-list.json"

  mkdir -p "$fake_bin" "$(dirname "$state_path")"
  : >"$state_path"
  : >"$terraform_log"
  : >"$aws_log"
  cat >"$waf_json" <<'JSON'
{"WebACLs":[{"Name":"juno-app-edge-preview-waf","Id":"282bcc63-cbc2-49b1-811b-7c242b8817f0","ARN":"arn:aws:wafv2:us-east-1:021490342184:global/webacl/juno-app-edge-preview-waf/282bcc63-cbc2-49b1-811b-7c242b8817f0"}]}
JSON
  write_provision_app_edge_fixture "$app_deploy" "$state_path"
  write_fake_provision_app_edge_terraform "$fake_bin/terraform"
  write_fake_provision_app_edge_aws "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    TEST_TERRAFORM_LOG="$terraform_log" \
      TEST_AWS_LOG="$aws_log" \
      TEST_WAF_LIST_JSON_FILE="$waf_json" \
      PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/provision-app-edge.sh" \
        --app-deploy "$app_deploy"
  )

  assert_contains "$(cat "$terraform_log")" "state list -state=$state_path" "provision checks the existing edge state before importing preview globals"
  assert_contains "$(cat "$aws_log")" "wafv2 list-web-acls --scope CLOUDFRONT --output json" "provision queries existing global WAFs when the edge state lacks the preview ACL"
  assert_contains "$(cat "$terraform_log")" "import -input=false -state=$state_path" "provision imports the existing preview WAF into state before apply"
  assert_contains "$(cat "$terraform_log")" "aws_wafv2_web_acl.app 282bcc63-cbc2-49b1-811b-7c242b8817f0/juno-app-edge-preview-waf/CLOUDFRONT" "provision uses the provider import id format for the preview WAF"
  assert_contains "$(cat "$terraform_log")" "apply -input=false -auto-approve -state=$state_path" "provision still runs terraform apply after adopting the preview WAF"

  rm -rf "$tmp"
}

test_provision_app_edge_skips_waf_lookup_when_state_already_tracks_it() {
  local tmp fake_bin app_deploy state_path terraform_log aws_log
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  app_deploy="$tmp/app-deploy.json"
  state_path="$tmp/edge-state/preview.tfstate"
  terraform_log="$tmp/terraform.log"
  aws_log="$tmp/aws.log"

  mkdir -p "$fake_bin" "$(dirname "$state_path")"
  : >"$state_path"
  : >"$terraform_log"
  : >"$aws_log"
  write_provision_app_edge_fixture "$app_deploy" "$state_path"
  write_fake_provision_app_edge_terraform "$fake_bin/terraform"
  write_fake_provision_app_edge_aws "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    TEST_TERRAFORM_LOG="$terraform_log" \
      TEST_AWS_LOG="$aws_log" \
      TEST_TERRAFORM_STATE_LIST='aws_wafv2_web_acl.app' \
      PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/provision-app-edge.sh" \
        --app-deploy "$app_deploy"
  )

  assert_contains "$(cat "$terraform_log")" "state list -state=$state_path" "provision checks the current edge state before deciding whether to adopt the preview WAF"
  assert_not_contains "$(cat "$terraform_log")" "import -input=false" "provision skips WAF imports when state already tracks the preview ACL"
  assert_not_contains "$(cat "$aws_log")" "wafv2 list-web-acls --scope CLOUDFRONT --output json" "provision skips the WAF lookup when state already contains the preview ACL"
  assert_contains "$(cat "$terraform_log")" "apply -input=false -auto-approve -state=$state_path" "provision still applies edge changes when the preview WAF is already in state"

  rm -rf "$tmp"
}

main() {
  test_provision_app_edge_imports_existing_waf_when_state_is_missing_it
  test_provision_app_edge_skips_waf_lookup_when_state_already_tracks_it
}

main "$@"
