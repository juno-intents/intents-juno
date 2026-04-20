#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

RUNBOOK_PATH="$REPO_ROOT/deploy/shared/runbooks/copy-operator-ami.sh"

test_copy_operator_ami_replicates_to_unique_target_regions() {
  local workdir manifest_out aws_log
  workdir="$(mktemp -d)"
  aws_log="$workdir/aws.log"

  cat >"$workdir/source-manifest.json" <<'JSON'
{
  "manifest_version": 1,
  "generated_at": "2026-04-20T10:00:00Z",
  "image": {
    "name": "intents-juno-operator-stack-h226327-20260420T100000Z",
    "description": "Operator stack AMI synced to junocashd block 226327"
  },
  "regions": {
    "us-west-2": {
      "ami_id": "ami-sourcewest2"
    }
  },
  "junocashd": {
    "release_tag": "v0.9.10",
    "synced_block_height": 226327,
    "synced_block_hash": "0000000000000000000000000000000000000000000000000000000000000001"
  }
}
JSON

  mkdir -p "$workdir/bin"
  cat >"$workdir/bin/aws" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >>"$aws_log"
if [[ "\$1 \$2" == "ec2 copy-image" ]]; then
  region=""
  while [[ \$# -gt 0 ]]; do
    case "\$1" in
      --region)
        region="\$2"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  case "\$region" in
    us-east-2) printf 'ami-copy-east2\n' ;;
    eu-west-1) printf 'ami-copy-euw1\n' ;;
    *) printf 'unexpected region %s\n' "\$region" >&2; exit 1 ;;
  esac
  exit 0
fi
if [[ "\$1 \$2 \$3" == "ec2 wait image-available" ]]; then
  exit 0
fi
if [[ "\$1 \$2" == "ec2 create-tags" ]]; then
  exit 0
fi
printf 'unexpected aws invocation: %s\n' "\$*" >&2
exit 1
EOF
  chmod 0755 "$workdir/bin/aws"

  manifest_out="$workdir/merged-manifest.json"
  PATH="$workdir/bin:$PATH" \
    "$RUNBOOK_PATH" replicate \
      --manifest-in "$workdir/source-manifest.json" \
      --manifest-out "$manifest_out" \
      --source-region us-west-2 \
      --target-regions "us-west-2,us-east-2,eu-west-1,us-east-2"

  assert_eq "$(jq -r '.regions["us-west-2"].ami_id' "$manifest_out")" "ami-sourcewest2" "replication preserves the source region ami id"
  assert_eq "$(jq -r '.regions["us-east-2"].ami_id' "$manifest_out")" "ami-copy-east2" "replication records the copied ami id for us-east-2"
  assert_eq "$(jq -r '.regions["eu-west-1"].ami_id' "$manifest_out")" "ami-copy-euw1" "replication records the copied ami id for eu-west-1"
  assert_eq "$(jq -r '.regions | keys | length' "$manifest_out")" "3" "replication emits one manifest entry per unique region"
  assert_contains "$(cat "$aws_log")" "ec2 copy-image --region us-east-2 --source-region us-west-2 --source-image-id ami-sourcewest2" "replication copies the ami into us-east-2"
  assert_contains "$(cat "$aws_log")" "ec2 copy-image --region eu-west-1 --source-region us-west-2 --source-image-id ami-sourcewest2" "replication copies the ami into eu-west-1"

  rm -rf "$workdir"
}

test_copy_operator_ami_passthrough_when_no_target_regions_requested() {
  local workdir manifest_out
  workdir="$(mktemp -d)"

  cat >"$workdir/source-manifest.json" <<'JSON'
{
  "manifest_version": 1,
  "generated_at": "2026-04-20T10:00:00Z",
  "image": {
    "name": "intents-juno-operator-stack-h226327-20260420T100000Z",
    "description": "Operator stack AMI synced to junocashd block 226327"
  },
  "regions": {
    "us-west-2": {
      "ami_id": "ami-sourcewest2"
    }
  }
}
JSON

  manifest_out="$workdir/merged-manifest.json"
  "$RUNBOOK_PATH" replicate \
    --manifest-in "$workdir/source-manifest.json" \
    --manifest-out "$manifest_out" \
    --source-region us-west-2 \
    --target-regions ""

  assert_eq "$(jq -r '.regions["us-west-2"].ami_id' "$manifest_out")" "ami-sourcewest2" "passthrough preserves the source ami id"
  assert_eq "$(jq -r '.regions | keys | length' "$manifest_out")" "1" "passthrough keeps the single-region manifest unchanged"

  rm -rf "$workdir"
}

main() {
  test_copy_operator_ami_replicates_to_unique_target_regions
  test_copy_operator_ami_passthrough_when_no_target_regions_requested
}

main "$@"
