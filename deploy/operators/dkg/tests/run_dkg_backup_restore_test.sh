#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/../e2e/run-dkg-backup-restore.sh"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

test_run_dkg_backup_restore_can_render_handoffs_after_local_restore() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "--inventory <path>" "usage documents inventory handoff option"
  assert_contains "$script_text" "--handoff-output-dir <path>" "usage documents handoff output option"
  assert_contains "$script_text" "--shared-manifest-path <p>" "usage documents shared-manifest handoff option"
  assert_contains "$script_text" "--rollout-state-file <p>" "usage documents rollout-state handoff option"
  assert_contains "$script_text" "deploy/operators/dkg/render-handoff.sh" "script invokes render-handoff after restore flow"
  assert_contains "$script_text" '--shared-manifest-path "$shared_manifest_path"' "script forwards shared-manifest path into render-handoff"
  assert_contains "$script_text" '--rollout-state-file "$rollout_state_file"' "script forwards rollout-state path into render-handoff"
  assert_contains "$script_text" "--validate" "script validates rendered handoff bundles immediately"
}

main() {
  test_run_dkg_backup_restore_can_render_handoffs_after_local_restore
}

main "$@"
