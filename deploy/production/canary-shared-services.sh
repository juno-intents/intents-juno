#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  canary-shared-services.sh --shared-manifest <path> [--dry-run]

Checks:
  - Postgres reachability via pg_isready
  - Kafka broker TCP reachability via nc
  - IPFS API reachability via curl

Output:
  JSON summary to stdout suitable for gating deployment
EOF
}

shared_manifest=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shared-manifest)
      shared_manifest="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$shared_manifest" ]] || die "--shared-manifest is required"
[[ -f "$shared_manifest" ]] || die "shared manifest not found: $shared_manifest"

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done
if [[ "$dry_run" != "true" ]]; then
  for cmd in pg_isready nc curl; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
fi

postgres_endpoint="$(production_json_required "$shared_manifest" '.shared_services.postgres.endpoint | select(type == "string" and length > 0)')"
postgres_port="$(production_json_required "$shared_manifest" '.shared_services.postgres.port')"
kafka_brokers="$(production_json_required "$shared_manifest" '.shared_services.kafka.bootstrap_brokers | select(type == "string" and length > 0)')"
ipfs_api_url="$(production_json_required "$shared_manifest" '.shared_services.ipfs.api_url | select(type == "string" and length > 0)')"
ipfs_api_url="${ipfs_api_url%/}"

postgres_status="passed"
kafka_status="passed"
ipfs_status="passed"
postgres_detail="reachable"
kafka_detail="all brokers reachable"
ipfs_detail="api reachable"

if [[ "$dry_run" == "true" ]]; then
  postgres_status="skipped"
  kafka_status="skipped"
  ipfs_status="skipped"
  postgres_detail="dry run"
  kafka_detail="dry run"
  ipfs_detail="dry run"
else
  if ! pg_isready -h "$postgres_endpoint" -p "$postgres_port" >/dev/null 2>&1; then
    postgres_status="failed"
    postgres_detail="pg_isready failed"
  fi

  IFS=',' read -r -a broker_array <<<"$kafka_brokers"
  for broker in "${broker_array[@]}"; do
    broker="$(trim "$broker")"
    [[ -n "$broker" ]] || continue
    broker_host="${broker%:*}"
    broker_port="${broker##*:}"
    if ! nc -z "$broker_host" "$broker_port" >/dev/null 2>&1; then
      kafka_status="failed"
      kafka_detail="broker unreachable: $broker"
      break
    fi
  done

  if ! curl -fsS "${ipfs_api_url}/api/v0/version" >/dev/null 2>&1; then
    ipfs_status="failed"
    ipfs_detail="ipfs api unreachable"
  fi
fi

ready_for_deploy="true"
for status in "$postgres_status" "$kafka_status" "$ipfs_status"; do
  if [[ "$status" != "passed" && "$status" != "skipped" ]]; then
    ready_for_deploy="false"
  fi
done
if [[ "$dry_run" == "true" ]]; then
  ready_for_deploy="false"
fi

jq -n \
  --arg version "1" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg manifest "$shared_manifest" \
  --arg postgres_status "$postgres_status" \
  --arg postgres_detail "$postgres_detail" \
  --arg kafka_status "$kafka_status" \
  --arg kafka_detail "$kafka_detail" \
  --arg ipfs_status "$ipfs_status" \
  --arg ipfs_detail "$ipfs_detail" \
  --argjson ready_for_deploy "$ready_for_deploy" \
  '{
    version: $version,
    generated_at: $generated_at,
    shared_manifest: $manifest,
    ready_for_deploy: $ready_for_deploy,
    checks: {
      postgres: {
        status: $postgres_status,
        detail: $postgres_detail
      },
      kafka: {
        status: $kafka_status,
        detail: $kafka_detail
      },
      ipfs: {
        status: $ipfs_status,
        detail: $ipfs_detail
      }
    }
  }'
