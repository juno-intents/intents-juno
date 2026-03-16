#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

test_shared_services_canary_checks_postgres_kafka_and_ipfs() {
  local tmp manifest fake_bin log_file output_json
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_file="$tmp/calls.log"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin"

  cat >"$manifest" <<'JSON'
{
  "environment": "alpha",
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "postgres": {
      "endpoint": "postgres.alpha.internal",
      "port": 5432,
      "cluster_arn": "arn:aws:rds:us-east-1:021490342184:cluster:alpha-shared"
    },
    "kafka": {
      "bootstrap_brokers": "broker-1.alpha.internal:9098,broker-2.alpha.internal:9098",
      "auth": {
        "mode": "aws-msk-iam",
        "aws_region": "us-east-1"
      },
      "cluster_arn": "arn:aws:kafka:us-east-1:021490342184:cluster/alpha-shared/11111111-2222-3333-4444-555555555555-1"
    },
    "ipfs": {
      "api_url": "https://ipfs.alpha.internal",
      "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/alpha-ipfs-api/1111111111111111"
    },
    "artifacts": {
      "checkpoint_blob_bucket": "alpha-dkg-keypackages",
      "object_lock_required": true
    }
  }
}
JSON

  cat >"$fake_bin/pg_isready" <<EOF
#!/usr/bin/env bash
printf 'pg_isready %s\n' "\$*" >>"$log_file"
exit 0
EOF
  cat >"$fake_bin/nc" <<EOF
#!/usr/bin/env bash
printf 'nc %s\n' "\$*" >>"$log_file"
exit 0
EOF
  cat >"$fake_bin/curl" <<EOF
#!/usr/bin/env bash
printf 'curl %s\n' "\$*" >>"$log_file"
printf '{"Version":"0.25.0"}\n'
exit 0
EOF
  cat >"$fake_bin/aws" <<EOF
#!/usr/bin/env bash
printf 'aws %s\n' "\$*" >>"$log_file"
case "\$*" in
  *"sts get-caller-identity"*)
    printf '{"Account":"021490342184"}\n'
    ;;
  *"rds describe-db-clusters"*)
    printf '{"DBClusters":[{"Status":"available","AvailabilityZones":["us-east-1a","us-east-1b"]}]}\n'
    ;;
  *"kafka describe-cluster-v2"*)
    printf '{"ClusterInfo":{"State":"ACTIVE","Provisioned":{"BrokerNodeGroupInfo":{"ClientSubnets":["subnet-a","subnet-b"]}}}}\n'
    ;;
  *"elbv2 describe-target-health"*)
    printf '{"TargetHealthDescriptions":[{"TargetHealth":{"State":"healthy"}},{"TargetHealth":{"State":"healthy"}}]}\n'
    ;;
  *"s3api head-bucket"*)
    ;;
  *"s3api get-bucket-versioning"*)
    printf 'Enabled\n'
    ;;
  *"s3api get-object-lock-configuration"*)
    printf 'Enabled\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
exit 0
EOF
  chmod 0755 "$fake_bin/pg_isready" "$fake_bin/nc" "$fake_bin/curl" "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services.sh \
      --shared-manifest "$manifest" >"$output_json"
  )

  assert_contains "$(cat "$log_file")" "pg_isready -h postgres.alpha.internal -p 5432" "postgres canary check"
  assert_contains "$(cat "$log_file")" "nc -z broker-1.alpha.internal 9098" "first kafka broker canary check"
  assert_contains "$(cat "$log_file")" "nc -z broker-2.alpha.internal 9098" "second kafka broker canary check"
  assert_contains "$(cat "$log_file")" "curl -fsS -X POST https://ipfs.alpha.internal/api/v0/version" "ipfs canary check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 sts get-caller-identity" "aws auth check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 rds describe-db-clusters --db-cluster-identifier arn:aws:rds:us-east-1:021490342184:cluster:alpha-shared --output json" "postgres cluster health check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 kafka describe-cluster-v2 --cluster-arn arn:aws:kafka:us-east-1:021490342184:cluster/alpha-shared/11111111-2222-3333-4444-555555555555-1 --output json" "kafka cluster health check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:us-east-1:021490342184:targetgroup/alpha-ipfs-api/1111111111111111 --output json" "ipfs target health check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 s3api head-bucket --bucket alpha-dkg-keypackages" "artifact bucket reachability check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 s3api get-bucket-versioning --bucket alpha-dkg-keypackages --query Status --output text" "artifact bucket versioning check"
  assert_contains "$(cat "$log_file")" "aws --profile juno --region us-east-1 s3api get-object-lock-configuration --bucket alpha-dkg-keypackages --query ObjectLockConfiguration.ObjectLockEnabled --output text" "artifact bucket object lock check"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "shared canary ready flag"
  assert_eq "$(jq -r '.checks.aws_auth.status' "$output_json")" "passed" "shared canary aws auth status"
  assert_eq "$(jq -r '.checks.postgres.status' "$output_json")" "passed" "shared canary postgres status"
  assert_eq "$(jq -r '.checks.kafka.status' "$output_json")" "passed" "shared canary kafka status"
  assert_eq "$(jq -r '.checks.ipfs.status' "$output_json")" "passed" "shared canary ipfs status"
  assert_eq "$(jq -r '.checks.artifacts.status' "$output_json")" "passed" "shared canary artifacts status"

  rm -rf "$tmp"
}

test_shared_services_canary_rejects_non_iam_kafka_auth() {
  local tmp manifest fake_bin output_json
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin"

  cat >"$manifest" <<'JSON'
{
  "environment": "alpha",
  "shared_services": {
    "postgres": {
      "endpoint": "postgres.alpha.internal",
      "port": 5432
    },
    "kafka": {
      "bootstrap_brokers": "broker-1.alpha.internal:9094",
      "auth": {
        "mode": "tls",
        "aws_region": "us-east-1"
      }
    },
    "ipfs": {
      "api_url": "https://ipfs.alpha.internal"
    }
  }
}
JSON

  cat >"$fake_bin/pg_isready" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/nc" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$fake_bin/pg_isready" "$fake_bin/nc" "$fake_bin/curl"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services.sh \
      --shared-manifest "$manifest" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "shared canary ready flag rejects non-iam kafka auth"
  assert_eq "$(jq -r '.checks.kafka.status' "$output_json")" "failed" "shared canary kafka auth status"
  assert_contains "$(jq -r '.checks.kafka.detail' "$output_json")" "aws-msk-iam" "shared canary kafka auth detail"

  rm -rf "$tmp"
}

test_shared_services_canary_requires_preview_iam_kafka_auth() {
  local tmp manifest fake_bin output_json
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin"

  cat >"$manifest" <<'JSON'
{
  "environment": "preview",
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1",
    "postgres": {
      "endpoint": "postgres.preview.internal",
      "port": 5432
    },
    "kafka": {
      "bootstrap_brokers": "broker-1.preview.internal:9098",
      "auth": {
        "mode": "aws-msk-iam",
        "aws_region": "us-east-1"
      }
    },
    "ipfs": {
      "api_url": "https://ipfs.preview.internal"
    }
  }
}
JSON

  cat >"$fake_bin/pg_isready" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/nc" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "--profile" ]]; then
  shift 2
fi
if [[ "$1" == "--region" ]]; then
  shift 2
fi
if [[ "$1" == "sts" && "$2" == "get-caller-identity" ]]; then
  printf '%s\n' '{"Account":"021490342184"}'
  exit 0
fi
exit 0
EOF
  chmod 0755 "$fake_bin/pg_isready" "$fake_bin/nc" "$fake_bin/curl" "$fake_bin/aws"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services.sh \
      --shared-manifest "$manifest" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "preview shared canary accepts kafka auth iam"
  assert_eq "$(jq -r '.checks.kafka.status' "$output_json")" "passed" "preview shared canary kafka status"
  assert_contains "$(jq -r '.checks.kafka.detail' "$output_json")" "aws-msk-iam" "preview shared canary reports kafka iam transport"

  rm -rf "$tmp"
}

main() {
  test_shared_services_canary_checks_postgres_kafka_and_ipfs
  test_shared_services_canary_rejects_non_iam_kafka_auth
  test_shared_services_canary_requires_preview_iam_kafka_auth
}

main "$@"
