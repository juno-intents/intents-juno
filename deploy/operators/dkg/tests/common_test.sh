#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

test_normalize_eth_address() {
  local got
  got="$(normalize_eth_address "0x52908400098527886E0F7030069857D2E4169EE7")"
  assert_eq "$got" "0x52908400098527886e0f7030069857d2e4169ee7" "normalize_eth_address"

  if normalize_eth_address "0x1234" >/dev/null 2>&1; then
    printf 'expected invalid address to fail\n' >&2
    exit 1
  fi
}

test_parse_endpoint_host_port() {
  local host port
  read -r host port <<<"$(parse_endpoint_host_port "https://node.tailnet.ts.net:8443")"
  assert_eq "$host" "node.tailnet.ts.net" "endpoint host"
  assert_eq "$port" "8443" "endpoint port"

  if parse_endpoint_host_port "http://node.tailnet.ts.net:8443" >/dev/null 2>&1; then
    printf 'expected non-https endpoint to fail\n' >&2
    exit 1
  fi
  if parse_endpoint_host_port "https://node.tailnet.ts.net" >/dev/null 2>&1; then
    printf 'expected missing port endpoint to fail\n' >&2
    exit 1
  fi
}

test_safe_slug() {
  local got
  got="$(safe_slug "0xabc:def/ghi")"
  assert_eq "$got" "0xabc_def_ghi" "safe_slug"
}

test_build_export_s3_key() {
  local got

  got="$(build_export_s3_key "dkg/keypackages" "cer-123" "0xabc" "7")"
  assert_eq "$got" "dkg/keypackages/cer-123/operator_7_0xabc.json" "s3 key basic"

  got="$(build_export_s3_key "/dkg/keypackages/" "cer-123" "0xabc" "7")"
  assert_eq "$got" "dkg/keypackages/cer-123/operator_7_0xabc.json" "s3 key trims slashes"

  got="$(build_export_s3_key "" "cer-123" "0xabc" "7")"
  assert_eq "$got" "cer-123/operator_7_0xabc.json" "s3 key empty prefix"
}

test_repair_executable_file() {
  local tmp
  tmp="$(mktemp)"
  printf '#!/usr/bin/env bash\necho ok\n' >"$tmp"
  chmod 0644 "$tmp"
  repair_executable_file "$tmp"
  if [[ ! -x "$tmp" ]]; then
    printf 'expected repair_executable_file to set +x\n' >&2
    exit 1
  fi
  rm -f "$tmp"
}

test_remove_macos_quarantine_calls_xattr() {
  local tmp target marker
  tmp="$(mktemp -d)"
  target="$tmp/target"
  marker="$tmp/xattr.args"
  mkdir -p "$target"
  cat >"$tmp/xattr" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$marker"
EOF
  chmod 0755 "$tmp/xattr"

  (
    PATH="$tmp:$PATH"
    export JUNO_DKG_OS_OVERRIDE="darwin"
    remove_macos_quarantine "$target"
  )

  if [[ ! -f "$marker" ]]; then
    printf 'expected xattr to be invoked\n' >&2
    exit 1
  fi
  local got
  got="$(cat "$marker")"
  assert_eq "$got" "-dr com.apple.quarantine $target" "xattr invocation"
  rm -rf "$tmp"
}

test_require_tailscale_active_allows_insecure_override() {
  local tmp_bin
  tmp_bin="$(mktemp -d)"

  if ! (
    unset JUNO_DKG_ALLOW_INSECURE_NETWORK
    PATH="$tmp_bin:$PATH"
    require_tailscale_active >/dev/null 2>&1
  ); then
    :
  else
    printf 'expected require_tailscale_active to fail without tailscale when override is unset\n' >&2
    exit 1
  fi

  (
    export JUNO_DKG_ALLOW_INSECURE_NETWORK="1"
    PATH="$tmp_bin:$PATH"
    require_tailscale_active >/dev/null
  )

  rm -rf "$tmp_bin"
}

main() {
  test_normalize_eth_address
  test_parse_endpoint_host_port
  test_safe_slug
  test_build_export_s3_key
  test_repair_executable_file
  test_remove_macos_quarantine_calls_xattr
  test_require_tailscale_active_allows_insecure_override
}

main "$@"
