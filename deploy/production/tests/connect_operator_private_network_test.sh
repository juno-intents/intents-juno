#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_operator_network_aws() {
  local target="$1"
  local log_file="$2"
  local state_dir="$3"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"
state_dir="$state_dir"
pcx_file="\$state_dir/pcx-id"
accepted_file="\$state_dir/pcx-accepted"
active_file="\$state_dir/pcx-active"
accept_attempts_file="\$state_dir/accept-attempts"

case "\$*" in
  *"us-east-1 sts get-caller-identity"*)
    printf '054422645452\n'
    ;;
  *"us-west-2 sts get-caller-identity"*)
    printf '054422645452\n'
    ;;
  *"us-west-2 ec2 describe-vpcs --filters Name=is-default,Values=true"*)
    printf 'vpc-op1west2\n'
    ;;
  *"us-east-1 ec2 describe-vpcs --vpc-ids vpc-sharedmainnet"* )
    printf '10.64.0.0/16\n'
    ;;
  *"us-west-2 ec2 describe-vpcs --vpc-ids vpc-op1west2"* )
    printf '10.80.0.0/16\n'
    ;;
  *"us-west-2 ec2 describe-subnets --filters Name=vpc-id,Values=vpc-op1west2 Name=default-for-az,Values=true"* )
    printf 'subnet-op1a\tsubnet-op1b\n'
    ;;
  *"us-west-2 ec2 describe-route-tables --filters Name=vpc-id,Values=vpc-op1west2"* )
    printf 'rtb-op1a\trtb-op1b\n'
    ;;
  *"us-east-1 ec2 describe-route-tables --filters Name=vpc-id,Values=vpc-sharedmainnet"* )
    printf 'rtb-shareda\trtb-sharedb\n'
    ;;
  *"describe-vpc-peering-connections"* )
    if [[ -f "\$pcx_file" ]]; then
      if [[ "\$*" == *"--query VpcPeeringConnections[0].VpcPeeringConnectionId"* ]]; then
        cat "\$pcx_file"
      else
        if [[ -f "\$accepted_file" && ! -f "\$active_file" ]]; then
          : >"\$active_file"
          printf 'pending-acceptance\n'
        else
          printf 'active\n'
        fi
      fi
    else
      if [[ "\$*" == *"--query VpcPeeringConnections[0].VpcPeeringConnectionId"* ]]; then
        printf 'None\n'
      else
        printf 'None\n'
      fi
    fi
    ;;
  *"create-vpc-peering-connection"* )
    printf 'pcx-op1shared\n' >"\$pcx_file"
    printf 'pcx-op1shared\n'
    ;;
  *"accept-vpc-peering-connection"* )
    attempts=0
    if [[ -f "\$accept_attempts_file" ]]; then
      attempts="\$(cat "\$accept_attempts_file")"
    fi
    attempts="\$((attempts + 1))"
    printf '%s' "\$attempts" >"\$accept_attempts_file"
    if [[ "\$attempts" == "1" ]]; then
      printf 'An error occurred (InvalidVpcPeeringConnectionID.NotFound) when calling the AcceptVpcPeeringConnection operation: not visible yet\n' >&2
      exit 254
    fi
    : >"\$accepted_file"
    printf '{}\n'
    ;;
  *"modify-vpc-peering-connection-options"* )
    if [[ ! -f "\$active_file" ]]; then
      printf 'peering not active yet\n' >&2
      exit 254
    fi
    printf '{}\n'
    ;;
  *"create-route"* )
    printf '{}\n'
    ;;
  *"replace-route"* )
    printf '{}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

test_connect_operator_private_network_creates_peering_routes_and_patches_inventory() {
  local tmp fake_bin log_file state_dir inventory output_inventory receipt
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  log_file="$tmp/aws.log"
  state_dir="$tmp/state"
  inventory="$tmp/inventory.json"
  output_inventory="$tmp/inventory.next.json"
  receipt="$tmp/receipt.json"
  mkdir -p "$fake_bin" "$state_dir"

  cat >"$inventory" <<'JSON'
{
  "environment": "mainnet",
  "shared_services": {
    "aws_profile": "juno",
    "aws_region": "us-east-1"
  },
  "app_role": {
    "vpc_id": "vpc-sharedmainnet"
  },
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "aws_profile": "mainnet-op1",
      "aws_region": "us-west-2",
      "account_id": "",
      "operator_host": ""
    }
  ]
}
JSON

  write_fake_operator_network_aws "$fake_bin/aws" "$log_file" "$state_dir"

  PATH="$fake_bin:$PATH" \
  bash "$REPO_ROOT/deploy/production/connect-operator-private-network.sh" \
    --inventory "$inventory" \
    --operator-id "0x1111111111111111111111111111111111111111" \
    --output-inventory "$output_inventory" \
    --receipt "$receipt"

  assert_contains "$(cat "$log_file")" "us-west-2 ec2 create-vpc-peering-connection --vpc-id vpc-op1west2 --peer-vpc-id vpc-sharedmainnet --peer-owner-id 054422645452 --peer-region us-east-1" "network connect creates the cross-region peering request from the operator region"
  assert_contains "$(cat "$log_file")" "us-east-1 ec2 accept-vpc-peering-connection --vpc-peering-connection-id pcx-op1shared" "network connect accepts the peering in the shared region"
  assert_contains "$(cat "$log_file")" "us-west-2 ec2 modify-vpc-peering-connection-options --vpc-peering-connection-id pcx-op1shared --requester-peering-connection-options AllowDnsResolutionFromRemoteVpc=true" "network connect enables requester-side DNS resolution over peering"
  assert_contains "$(cat "$log_file")" "us-east-1 ec2 modify-vpc-peering-connection-options --vpc-peering-connection-id pcx-op1shared --accepter-peering-connection-options AllowDnsResolutionFromRemoteVpc=true" "network connect enables accepter-side DNS resolution over peering"
  assert_contains "$(cat "$log_file")" "us-west-2 ec2 create-route --route-table-id rtb-op1a --destination-cidr-block 10.64.0.0/16 --vpc-peering-connection-id pcx-op1shared" "network connect adds the shared VPC route to operator route tables"
  assert_contains "$(cat "$log_file")" "us-east-1 ec2 create-route --route-table-id rtb-shareda --destination-cidr-block 10.80.0.0/16 --vpc-peering-connection-id pcx-op1shared" "network connect adds the operator VPC route to shared route tables"
  assert_eq "$(jq -r '.operators[0].account_id' "$output_inventory")" "054422645452" "network connect patches the operator account id"
  assert_eq "$(jq -r '.operators[0].private_network.vpc_id' "$output_inventory")" "vpc-op1west2" "network connect patches the operator VPC id"
  assert_eq "$(jq -r '.operators[0].private_network.vpc_cidr' "$output_inventory")" "10.80.0.0/16" "network connect patches the operator VPC CIDR"
  assert_eq "$(jq -r '.operators[0].private_network.subnet_ids[1]' "$output_inventory")" "subnet-op1b" "network connect patches the operator subnet list"
  assert_eq "$(jq -r '.operators[0].private_network.route_table_ids[1]' "$output_inventory")" "rtb-op1b" "network connect patches the operator route table list"
  assert_eq "$(jq -r '.operators[0].private_network.shared_vpc_id' "$output_inventory")" "vpc-sharedmainnet" "network connect records the shared VPC id"
  assert_eq "$(jq -r '.vpc_peering_connection_id' "$receipt")" "pcx-op1shared" "network connect writes a receipt with the peering id"

  rm -rf "$tmp"
}

main() {
  test_connect_operator_private_network_creates_peering_routes_and_patches_inventory
}

main "$@"
