#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_contains_line() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if ! printf '%s\n' "$haystack" | grep -Fx "$needle" >/dev/null 2>&1; then
    printf 'assert_contains_line failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

test_backup_package_contains_required_files() {
  local tmp runtime workdir output
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  workdir="$tmp/ceremony-workdir"
  output="$tmp/operator-backup.zip"

  mkdir -p "$runtime/bundle" "$tmp/backup" "$tmp/exports" "$workdir/reports"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 2,
  "max_signers": 3,
  "network": "mainnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {"roster_version":1, "operators":[]}
}
JSON

  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$tmp/backup/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$tmp/exports/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$tmp/exports/keypackage-backup.json.KeyImportReceipt.json"
  printf '{"report_version":1}\n' >"$workdir/reports/test-completiton.json"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --completion-report "$workdir/reports/test-completiton.json" \
      --output "$output"
  )

  local listing
  listing="$(unzip -Z1 "$output")"
  assert_contains_line "$listing" "manifest.json" "backup zip manifest"
  assert_contains_line "$listing" "payload/age-identity.txt" "backup zip age identity"
  assert_contains_line "$listing" "payload/keypackage-backup.json" "backup zip age blob"
  assert_contains_line "$listing" "payload/keypackage-backup.json.KeyImportReceipt.json" "backup zip age receipt"
  assert_contains_line "$listing" "payload/admin-config.json" "backup zip admin config"
  assert_contains_line "$listing" "payload/test-completiton.json" "backup zip completion report"

  rm -rf "$tmp"
}

main() {
  test_backup_package_contains_required_files
}

main "$@"
