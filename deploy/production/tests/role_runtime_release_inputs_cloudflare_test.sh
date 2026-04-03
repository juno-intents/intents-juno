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

write_cloudflare_release_inventory_fixture() {
  local target="$1"
  jq '
    .environment = "mainnet"
    | .shared_services.public_zone_name = "junointents.com"
    | .shared_services.public_subdomain = "junointents.com"
    | .contracts.juno_network = "mainnet"
    | .app_role.ami_release_tag = "app-runtime-ami-v2026.04.03-r1-mainnet"
    | .app_role.app_ami_id = ""
    | .shared_roles.proof.image_release_tag = "shared-proof-services-image-v2026.04.03-r1-mainnet"
    | .shared_roles.proof.image_uri = ""
    | .shared_roles.proof.image_ecr_repository_arn = ""
    | .app_role.backoffice_access = {
        mode: "cloudflare-access",
        public_hostname: "ops.junointents.com"
      }
    | del(.shared_services.wireguard)
    | del(.shared_roles.wireguard)
    | del(.wireguard_role)
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

write_fake_role_runtime_cloudflare_gh() {
  local target="$1"
  local releases_dir="$2"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$TEST_GH_LOG"
args=( "$@" )
if [[ "${args[0]:-}" != "release" || "${args[1]:-}" != "download" ]]; then
  printf 'unexpected gh invocation: %s\n' "$*" >&2
  exit 1
fi
tag="${args[2]}"
dir=""
patterns=()
for ((i=3; i<${#args[@]}; i++)); do
  case "${args[$i]}" in
    --dir)
      dir="${args[$((i + 1))]}"
      i=$((i + 1))
      ;;
    --pattern)
      patterns+=("${args[$((i + 1))]}")
      i=$((i + 1))
      ;;
  esac
done
mkdir -p "$dir"
for pattern in "${patterns[@]}"; do
  cp "$TEST_RELEASES_DIR/$tag/$pattern" "$dir/$pattern"
done
EOF
  chmod +x "$target"
}

test_role_runtime_release_inputs_do_not_require_wireguard_release_for_cloudflare_backoffice() {
  local workdir releases_dir fake_bin gh_log inventory output_inventory
  workdir="$(mktemp -d)"
  releases_dir="$workdir/releases"
  fake_bin="$workdir/bin"
  gh_log="$workdir/gh.log"
  inventory="$workdir/inventory.json"
  output_inventory="$workdir/output.json"

  mkdir -p "$fake_bin" \
    "$releases_dir/app-runtime-ami-v2026.04.03-r1-mainnet" \
    "$releases_dir/shared-proof-services-image-v2026.04.03-r1-mainnet"
  : >"$gh_log"

  cat >"$releases_dir/app-runtime-ami-v2026.04.03-r1-mainnet/app-runtime-ami-manifest.json" <<'JSON'
{"regions":{"us-east-1":{"ami_id":"ami-0432b4571770fa599"}}}
JSON
  sha256sum "$releases_dir/app-runtime-ami-v2026.04.03-r1-mainnet/app-runtime-ami-manifest.json" \
    | awk '{print $1 "  app-runtime-ami-manifest.json"}' >"$releases_dir/app-runtime-ami-v2026.04.03-r1-mainnet/app-runtime-ami-manifest.json.sha256"

  cat >"$releases_dir/shared-proof-services-image-v2026.04.03-r1-mainnet/shared-proof-services-image-manifest.json" <<'JSON'
{"regions":{"us-east-1":{"image_uri":"021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef","repository_arn":"arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services"}}}
JSON
  sha256sum "$releases_dir/shared-proof-services-image-v2026.04.03-r1-mainnet/shared-proof-services-image-manifest.json" \
    | awk '{print $1 "  shared-proof-services-image-manifest.json"}' >"$releases_dir/shared-proof-services-image-v2026.04.03-r1-mainnet/shared-proof-services-image-manifest.json.sha256"

  write_cloudflare_release_inventory_fixture "$inventory"
  write_fake_role_runtime_cloudflare_gh "$fake_bin/gh" "$releases_dir"

  (
    cd "$REPO_ROOT"
    TEST_RELEASES_DIR="$releases_dir" TEST_GH_LOG="$gh_log" PATH="$fake_bin:$PATH" \
      bash "$REPO_ROOT/deploy/production/resolve-role-runtime-release-inputs.sh" \
        --inventory "$inventory" \
        --output "$output_inventory"
  )

  assert_eq "$(jq -r '.app_role.app_ami_id' "$output_inventory")" "ami-0432b4571770fa599" "resolver patches the app runtime ami id"
  assert_eq "$(jq -r '.shared_roles.proof.image_uri' "$output_inventory")" "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef" "resolver patches the proof image uri"
  assert_eq "$(jq -r 'has("wireguard_role")' "$output_inventory")" "false" "resolver keeps wireguard absent for cloudflare backoffice inventories"
  assert_not_contains "$(cat "$gh_log")" "wireguard-role-ami" "resolver does not fetch a wireguard ami when cloudflare backoffice is used"
  rm -rf "$workdir"
}

main() {
  test_role_runtime_release_inputs_do_not_require_wireguard_release_for_cloudflare_backoffice
  printf 'role_runtime_release_inputs_cloudflare_test: PASS\n'
}

main "$@"
