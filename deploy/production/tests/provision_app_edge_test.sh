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
    "mode": "public-zone",
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

write_external_provision_app_edge_fixture() {
  local target="$1"
  local state_path="$2"
  cat >"$target" <<JSON
{
  "environment": "mainnet",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "security_group_id": "",
  "dns": {
    "mode": "external"
  },
  "services": {
    "bridge_api": {
      "record_name": "bridge.mainnet.junointents.com"
    }
  },
  "edge": {
    "enabled": true,
    "origin_record_name": "origin.mainnet.junointents.com",
    "public_lb_dns_name": "juno-app-runtime-mainnet-bridge-1076285917.us-east-1.elb.amazonaws.com",
    "origin_http_port": 443,
    "rate_limit": 2000,
    "alarm_actions": [
      "arn:aws:sns:us-east-1:021490342184:mainnet-app-edge"
    ],
    "state_path": "$state_path",
    "enable_shield_advanced": false,
    "viewer_certificate_arn": "arn:aws:acm:us-east-1:021490342184:certificate/bridge-mainnet"
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
    for arg in "${args[@]}"; do
      case "$arg" in
        -var-file=*)
          tfvars_path="${arg#-var-file=}"
          printf 'tfvars %s\n' "$tfvars_path" >>"$TEST_TERRAFORM_LOG"
          cat "$tfvars_path" >>"$TEST_TERRAFORM_LOG"
          printf '\n' >>"$TEST_TERRAFORM_LOG"
          ;;
      esac
    done
    exit 0
    ;;
  output)
    printf '%s\n' "${TEST_TERRAFORM_OUTPUT_JSON:-{\"bridge_distribution_domain_name\":{\"value\":\"d111111abcdef8.cloudfront.net\"}}}"
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
  "cloudfront list-distributions --output json")
    if [[ -n "${TEST_CLOUDFRONT_LIST_JSON_FILE:-}" ]]; then
      cat "$TEST_CLOUDFRONT_LIST_JSON_FILE"
    else
      printf '%s\n' '{"DistributionList":{"Items":[]}}'
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

test_provision_app_edge_imports_existing_edge_resources_when_state_is_missing_them() {
  local tmp fake_bin app_deploy state_path terraform_log aws_log waf_json cloudfront_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  app_deploy="$tmp/app-deploy.json"
  state_path="$tmp/edge-state/preview.tfstate"
  terraform_log="$tmp/terraform.log"
  aws_log="$tmp/aws.log"
  waf_json="$tmp/waf-list.json"
  cloudfront_json="$tmp/cloudfront-list.json"

  mkdir -p "$fake_bin" "$(dirname "$state_path")"
  : >"$state_path"
  : >"$terraform_log"
  : >"$aws_log"
  cat >"$waf_json" <<'JSON'
{"WebACLs":[{"Name":"juno-app-edge-preview-waf","Id":"282bcc63-cbc2-49b1-811b-7c242b8817f0","ARN":"arn:aws:wafv2:us-east-1:021490342184:global/webacl/juno-app-edge-preview-waf/282bcc63-cbc2-49b1-811b-7c242b8817f0"}]}
JSON
  cat >"$cloudfront_json" <<'JSON'
{"DistributionList":{"Items":[{"Id":"EKLE2YOSENG5F","ARN":"arn:aws:cloudfront::021490342184:distribution/EKLE2YOSENG5F","Aliases":{"Items":["bridge.preview.intents-testing.thejunowallet.com"]}}]}}
JSON
  write_provision_app_edge_fixture "$app_deploy" "$state_path"
  write_fake_provision_app_edge_terraform "$fake_bin/terraform"
  write_fake_provision_app_edge_aws "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    TEST_TERRAFORM_LOG="$terraform_log" \
      TEST_AWS_LOG="$aws_log" \
      TEST_WAF_LIST_JSON_FILE="$waf_json" \
      TEST_CLOUDFRONT_LIST_JSON_FILE="$cloudfront_json" \
      PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/provision-app-edge.sh" \
        --app-deploy "$app_deploy"
  )

  assert_contains "$(cat "$terraform_log")" "state list -state=$state_path" "provision checks the existing edge state before importing preview globals"
  assert_contains "$(cat "$aws_log")" "wafv2 list-web-acls --scope CLOUDFRONT --output json" "provision queries existing global WAFs when the edge state lacks the preview ACL"
  assert_contains "$(cat "$aws_log")" "cloudfront list-distributions --output json" "provision queries existing CloudFront distributions when the edge state lacks the preview bridge"
  assert_contains "$(cat "$terraform_log")" "import -input=false -state=$state_path" "provision imports the existing preview WAF into state before apply"
  assert_contains "$(cat "$terraform_log")" "aws_wafv2_web_acl.app 282bcc63-cbc2-49b1-811b-7c242b8817f0/juno-app-edge-preview-waf/CLOUDFRONT" "provision uses the provider import id format for the preview WAF"
  assert_contains "$(cat "$terraform_log")" "aws_cloudfront_distribution.bridge EKLE2YOSENG5F" "provision imports the existing preview bridge distribution into state before apply"
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
      TEST_TERRAFORM_STATE_LIST=$'aws_wafv2_web_acl.app\naws_cloudfront_distribution.bridge' \
      PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/provision-app-edge.sh" \
        --app-deploy "$app_deploy"
  )

  assert_contains "$(cat "$terraform_log")" "state list -state=$state_path" "provision checks the current edge state before deciding whether to adopt the preview WAF"
  assert_not_contains "$(cat "$terraform_log")" "import -input=false" "provision skips WAF imports when state already tracks the preview ACL"
  assert_not_contains "$(cat "$aws_log")" "wafv2 list-web-acls --scope CLOUDFRONT --output json" "provision skips the WAF lookup when state already contains the preview ACL"
  assert_not_contains "$(cat "$aws_log")" "cloudfront list-distributions --output json" "provision skips the CloudFront lookup when state already contains the preview bridge"
  assert_contains "$(cat "$terraform_log")" "apply -input=false -auto-approve -state=$state_path" "provision still applies edge changes when the preview WAF is already in state"

  rm -rf "$tmp"
}

test_provision_app_edge_supports_external_dns_with_existing_viewer_certificate() {
  local tmp fake_bin app_deploy state_path terraform_log aws_log dns_receipt
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  app_deploy="$tmp/app-deploy.json"
  state_path="$tmp/edge-state/mainnet.tfstate"
  terraform_log="$tmp/terraform.log"
  aws_log="$tmp/aws.log"
  dns_receipt="$tmp/edge-dns.json"

  mkdir -p "$fake_bin" "$(dirname "$state_path")"
  : >"$state_path"
  : >"$terraform_log"
  : >"$aws_log"
  write_external_provision_app_edge_fixture "$app_deploy" "$state_path"
  write_fake_provision_app_edge_terraform "$fake_bin/terraform"
  write_fake_provision_app_edge_aws "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    TEST_TERRAFORM_LOG="$terraform_log" \
      TEST_AWS_LOG="$aws_log" \
      TEST_TERRAFORM_OUTPUT_JSON='{"bridge_distribution_domain_name":{"value":"d111111abcdef8.cloudfront.net"}}' \
      PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/provision-app-edge.sh" \
        --app-deploy "$app_deploy"
  )

  assert_contains "$(cat "$terraform_log")" '"manage_dns_records": false' "external dns disables terraform-managed dns records"
  assert_contains "$(cat "$terraform_log")" '"viewer_certificate_arn": "arn:aws:acm:us-east-1:021490342184:certificate/bridge-mainnet"' "external dns passes the provided viewer certificate"
  assert_not_contains "$(cat "$aws_log")" "route53" "external dns never touches route53"
  assert_file_exists "$dns_receipt" "external dns receipt"
  assert_eq "$(jq -r '.records[0].name' "$dns_receipt")" "origin.mainnet.junointents.com" "dns receipt captures the origin record name"
  assert_eq "$(jq -r '.records[0].value' "$dns_receipt")" "juno-app-runtime-mainnet-bridge-1076285917.us-east-1.elb.amazonaws.com" "dns receipt points the origin record at the app load balancer"
  assert_eq "$(jq -r '.records[1].name' "$dns_receipt")" "bridge.mainnet.junointents.com" "dns receipt captures the public bridge hostname"
  assert_eq "$(jq -r '.records[1].value' "$dns_receipt")" "d111111abcdef8.cloudfront.net" "dns receipt points the public bridge hostname at cloudfront"

  rm -rf "$tmp"
}

main() {
  test_provision_app_edge_imports_existing_edge_resources_when_state_is_missing_them
  test_provision_app_edge_skips_waf_lookup_when_state_already_tracks_it
  test_provision_app_edge_supports_external_dns_with_existing_viewer_certificate
}

main "$@"
