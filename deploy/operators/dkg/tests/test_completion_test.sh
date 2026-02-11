#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

test_completion_outputs_ufvk_and_address() {
  local tmp workdir
  tmp="$(mktemp -d)"
  workdir="$tmp/workdir"
  mkdir -p "$workdir/reports" "$workdir/out"

  cat >"$workdir/reports/online-run.json" <<'JSON'
{
  "report_version": 1,
  "ceremony_hash": "abcd1234",
  "success": true,
  "operator_reports": [
    {
      "operator_id": "0x1111111111111111111111111111111111111111",
      "identifier": 1,
      "phase_timings_ms": {
        "smoke_standard_commit": 10,
        "smoke_standard_share": 11,
        "smoke_randomized_commit": 12,
        "smoke_randomized_share": 13
      },
      "phase_retries": {},
      "phase_error_codes": {}
    }
  ]
}
JSON

  cat >"$workdir/out/KeysetManifest.json" <<'JSON'
{
  "manifest_version": 1,
  "network": "mainnet",
  "threshold": 3,
  "max_signers": 5,
  "ufvk": "uview1test",
  "owallet_ua": "u1testshielded",
  "public_key_package_hash": "pkghash",
  "transcript_hash": "trhash"
}
JSON

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/test-completiton.sh run \
      --workdir "$workdir" \
      --skip-resume \
      --output "$workdir/reports/test-completiton.json"
  )

  local ufvk ua sig
  ufvk="$(jq -r '.ufvk' "$workdir/reports/test-completiton.json")"
  ua="$(jq -r '.juno_shielded_address' "$workdir/reports/test-completiton.json")"
  sig="$(jq -r '.test_signature.status' "$workdir/reports/test-completiton.json")"
  assert_eq "$ufvk" "uview1test" "ufvk output"
  assert_eq "$ua" "u1testshielded" "shielded address output"
  assert_eq "$sig" "passed" "test signature status"

  rm -rf "$tmp"
}

test_completion_fails_when_smoke_phase_missing() {
  local tmp workdir
  tmp="$(mktemp -d)"
  workdir="$tmp/workdir"
  mkdir -p "$workdir/reports" "$workdir/out"

  cat >"$workdir/reports/online-run.json" <<'JSON'
{
  "report_version": 1,
  "ceremony_hash": "abcd1234",
  "success": true,
  "operator_reports": [
    {
      "operator_id": "0x1111111111111111111111111111111111111111",
      "identifier": 1,
      "phase_timings_ms": {
        "smoke_standard_commit": 10
      },
      "phase_retries": {},
      "phase_error_codes": {}
    }
  ]
}
JSON

  cat >"$workdir/out/KeysetManifest.json" <<'JSON'
{
  "manifest_version": 1,
  "network": "mainnet",
  "threshold": 3,
  "max_signers": 5,
  "ufvk": "uview1test",
  "owallet_ua": "u1testshielded",
  "public_key_package_hash": "pkghash",
  "transcript_hash": "trhash"
}
JSON

  if (
    cd "$REPO_ROOT"
    deploy/operators/dkg/test-completiton.sh run \
      --workdir "$workdir" \
      --skip-resume \
      --output "$workdir/reports/test-completiton.json" >/dev/null 2>&1
  ); then
    printf 'expected completion check to fail when smoke phases are missing\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

main() {
  test_completion_outputs_ufvk_and_address
  test_completion_fails_when_smoke_phase_missing
}

main "$@"
