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

write_local_sha256_file() {
  local input="$1"
  local output="$2"
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$input" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$input" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$(basename "$input")" >"$output"
}

write_fake_gh() {
  local target="$1"
  local release_root="$2"
  local log_file="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "\$*" >>"$log_file"
if [[ "\$1" == "release" && "\$2" == "download" ]]; then
  tag="\$3"
  shift 3
  dir=""
  patterns=()
  while [[ \$# -gt 0 ]]; do
    case "\$1" in
      --repo)
        shift 2
        ;;
      --pattern)
        patterns+=("\$2")
        shift 2
        ;;
      --dir)
        dir="\$2"
        shift 2
        ;;
      --clobber)
        shift
        ;;
      *)
        echo "unexpected gh release download arg: \$1" >&2
        exit 1
        ;;
    esac
  done
  [[ -n "\$dir" ]] || {
    echo "missing --dir" >&2
    exit 1
  }
  mkdir -p "\$dir"
  for pattern in "\${patterns[@]}"; do
    cp "$release_root/\$tag/\$pattern" "\$dir/\$pattern"
  done
  exit 0
fi
echo "unexpected gh invocation: \$*" >&2
exit 1
EOF
  chmod +x "$target"
}

write_inventory_fixture() {
  local target="$1"
  jq '
    .environment = "alpha"
    | .contracts.juno_network = "testnet"
    | .shared_services.aws_region = "us-east-1"
    | .app_role.ami_release_tag = "app-runtime-ami-v1.2.3-testnet"
    | .app_role.app_ami_id = ""
    | .shared_roles.proof.image_release_tag = "shared-proof-services-image-v1.2.3-testnet"
    | .shared_roles.proof.image_uri = ""
    | .shared_roles.proof.image_ecr_repository_arn = ""
    | .shared_roles.wireguard.ami_release_tag = "wireguard-role-ami-v1.2.3-testnet"
    | .shared_roles.wireguard.ami_id = ""
    | .wireguard_role.ami_release_tag = "wireguard-role-ami-v1.2.3-testnet"
    | .wireguard_role.ami_id = ""
  ' "$REPO_ROOT/deploy/production/schema/deployment-inventory.example.json" >"$target"
}

test_resolve_role_runtime_release_inputs_patches_inventory() {
  local workdir fake_bin releases_dir output_inventory inventory
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  releases_dir="$workdir/releases"
  mkdir -p "$fake_bin" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet"

  inventory="$workdir/inventory.json"
  output_inventory="$workdir/inventory.resolved.json"
  write_inventory_fixture "$inventory"

  cat >"$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" <<'EOF'
{
  "repo_commit": "1111111111111111111111111111111111111111",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "app_binaries_release_tag": "app-binaries-v1.2.3-testnet",
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0app123456789abcd"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json.sha256"

  cat >"$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" <<'EOF'
{
  "repo_commit": "2222222222222222222222222222222222222222",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
  "regions": {
    "us-east-1": {
      "repository_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services",
      "repository_arn": "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services",
      "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json.sha256"

  cat >"$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" <<'EOF'
{
  "repo_commit": "3333333333333333333333333333333333333333",
  "built_at_utc": "2026-03-20T00:00:00Z",
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0wireguard1234567"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json.sha256"

  write_fake_gh "$fake_bin/gh" "$releases_dir" "$workdir/gh.log"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/resolve-role-runtime-release-inputs.sh" \
    --inventory "$inventory" \
    --output "$output_inventory" \
    --github-repo juno-intents/intents-juno

  assert_eq "$(jq -r '.app_role.app_ami_id' "$output_inventory")" "ami-0app123456789abcd" "release resolver patches app ami id"
  assert_eq "$(jq -r '.shared_roles.proof.image_uri' "$output_inventory")" "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef" "release resolver patches proof image uri"
  assert_eq "$(jq -r '.shared_roles.proof.image_ecr_repository_arn' "$output_inventory")" "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services" "release resolver patches proof repository arn"
  assert_eq "$(jq -r '.wireguard_role.ami_id' "$output_inventory")" "ami-0wireguard1234567" "release resolver patches wireguard ami id"
  assert_eq "$(jq -r '.shared_roles.wireguard.ami_id' "$output_inventory")" "ami-0wireguard1234567" "release resolver mirrors wireguard ami id into shared role contract"
  assert_contains "$(cat "$workdir/gh.log")" "release download app-runtime-ami-v1.2.3-testnet" "release resolver downloads the app runtime ami manifest"
  assert_contains "$(cat "$workdir/gh.log")" "release download shared-proof-services-image-v1.2.3-testnet" "release resolver downloads the proof image manifest"
  assert_contains "$(cat "$workdir/gh.log")" "release download wireguard-role-ami-v1.2.3-testnet" "release resolver downloads the wireguard ami manifest"
  rm -rf "$workdir"
}

test_resolve_role_runtime_release_inputs_rejects_latest_tags() {
  local workdir fake_bin output inventory stderr
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  mkdir -p "$fake_bin"

  inventory="$workdir/inventory.json"
  output="$workdir/inventory.resolved.json"
  stderr="$workdir/stderr.log"
  write_inventory_fixture "$inventory"
  jq '
    .app_role.ami_release_tag = "app-runtime-ami-latest"
  ' "$inventory" >"$inventory.tmp"
  mv "$inventory.tmp" "$inventory"

  cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh should not be invoked when latest tags are rejected" >&2
exit 1
EOF
  chmod +x "$fake_bin/gh"

  if PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/resolve-role-runtime-release-inputs.sh" \
    --inventory "$inventory" \
    --output "$output" \
    --github-repo juno-intents/intents-juno >"$workdir/stdout.log" 2>"$stderr"; then
    printf 'expected release resolver to reject latest tags\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "must not use latest tags" "release resolver rejects latest tags"
  assert_not_contains "$(cat "$stderr")" "gh should not be invoked" "release resolver fails before gh download"
  rm -rf "$workdir"
}

test_resolve_role_runtime_release_inputs_derives_ecr_repository_arn_from_manifest_uri() {
  local workdir fake_bin releases_dir output_inventory inventory aws_log
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  releases_dir="$workdir/releases"
  aws_log="$workdir/aws.log"
  mkdir -p "$fake_bin" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet"

  inventory="$workdir/inventory.json"
  output_inventory="$workdir/inventory.resolved.json"
  write_inventory_fixture "$inventory"

  cat >"$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" <<'EOF'
{
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0app123456789abcd"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json" \
    "$releases_dir/app-runtime-ami-v1.2.3-testnet/app-runtime-ami-manifest.json.sha256"

  cat >"$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" <<'EOF'
{
  "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef",
  "regions": {
    "us-east-1": {
      "repository_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services",
      "image_uri": "021490342184.dkr.ecr.us-east-1.amazonaws.com/intents-juno-proof-services@sha256:abcdef"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json" \
    "$releases_dir/shared-proof-services-image-v1.2.3-testnet/shared-proof-services-image-manifest.json.sha256"

  cat >"$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" <<'EOF'
{
  "regions": {
    "us-east-1": {
      "ami_id": "ami-0wireguard1234567"
    }
  }
}
EOF
  write_local_sha256_file \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json" \
    "$releases_dir/wireguard-role-ami-v1.2.3-testnet/wireguard-role-ami-manifest.json.sha256"

  write_fake_gh "$fake_bin/gh" "$releases_dir" "$workdir/gh.log"

  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$aws_log"
echo "unexpected aws invocation: \$*" >&2
exit 1
EOF
  chmod +x "$fake_bin/aws"

  PATH="$fake_bin:$PATH" bash "$REPO_ROOT/deploy/production/resolve-role-runtime-release-inputs.sh" \
    --inventory "$inventory" \
    --output "$output_inventory" \
    --github-repo juno-intents/intents-juno

  assert_eq "$(jq -r '.shared_roles.proof.image_ecr_repository_arn' "$output_inventory")" "arn:aws:ecr:us-east-1:021490342184:repository/intents-juno-proof-services" "release resolver derives proof repository arn from repository uri"
  if [[ -f "$aws_log" ]]; then
    assert_not_contains "$(cat "$aws_log")" "ecr describe-repositories" "release resolver does not call AWS when repository uri is present"
  fi
  rm -rf "$workdir"
}

main() {
  test_resolve_role_runtime_release_inputs_patches_inventory
  test_resolve_role_runtime_release_inputs_rejects_latest_tags
  test_resolve_role_runtime_release_inputs_derives_ecr_repository_arn_from_manifest_uri
}

main "$@"
