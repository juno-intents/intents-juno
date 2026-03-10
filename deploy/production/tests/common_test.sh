#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_file_exists() {
  local path="$1"
  local msg="$2"
  if [[ ! -f "$path" ]]; then
    printf 'assert_file_exists failed: %s: %s\n' "$msg" "$path" >&2
    exit 1
  fi
}
