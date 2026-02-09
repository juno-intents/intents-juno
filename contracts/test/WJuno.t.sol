// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {WJuno} from "../src/WJuno.sol";

contract WJunoTest is Test {
    WJuno private token;

    address private owner = address(this);
    address private bridge = makeAddr("bridge");

    function setUp() public {
        token = new WJuno(owner);
    }

    function test_decimals_is8() public view {
        assertEq(token.decimals(), 8);
    }

    function test_setBridge_onlyOwner() public {
        vm.prank(makeAddr("notOwner"));
        vm.expectRevert();
        token.setBridge(bridge);
    }

    function test_setBridge_once() public {
        token.setBridge(bridge);

        vm.expectRevert(WJuno.BridgeAlreadySet.selector);
        token.setBridge(makeAddr("bridge2"));
    }

    function test_mintBurn_onlyBridge() public {
        token.setBridge(bridge);

        address alice = makeAddr("alice");

        vm.expectRevert(WJuno.NotBridge.selector);
        token.mint(alice, 1);

        vm.prank(bridge);
        token.mint(alice, 10);
        assertEq(token.balanceOf(alice), 10);

        vm.expectRevert(WJuno.NotBridge.selector);
        token.burn(alice, 1);

        vm.prank(bridge);
        token.burn(alice, 3);
        assertEq(token.balanceOf(alice), 7);
    }

    function test_permit_allowsTransferFrom() public {
        token.setBridge(bridge);

        uint256 ownerPk = 0xA11CE;
        address alice = vm.addr(ownerPk);
        address bob = makeAddr("bob");

        vm.prank(bridge);
        token.mint(alice, 100);

        uint256 value = 25;
        uint256 deadline = block.timestamp + 1 days;

        bytes32 permitTypehash =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 structHash = keccak256(abi.encode(permitTypehash, alice, bob, value, token.nonces(alice), deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        token.permit(alice, bob, value, deadline, v, r, s);

        vm.prank(bob);
        token.transferFrom(alice, bob, value);

        assertEq(token.balanceOf(alice), 75);
        assertEq(token.balanceOf(bob), 25);
    }
}

