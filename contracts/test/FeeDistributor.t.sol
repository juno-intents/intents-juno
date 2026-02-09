// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {FeeDistributor} from "../src/FeeDistributor.sol";
import {OperatorRegistry} from "../src/OperatorRegistry.sol";
import {WJuno} from "../src/WJuno.sol";

contract FeeDistributorTest is Test {
    WJuno private token;
    OperatorRegistry private registry;
    FeeDistributor private distributor;

    address private owner = address(this);
    address private bridge = makeAddr("bridge");

    uint256 private op1Pk = 0xBEEF01;
    uint256 private op2Pk = 0xBEEF02;
    address private op1;
    address private op2;
    address private op1Fee = makeAddr("op1Fee");
    address private op2Fee = makeAddr("op2Fee");

    function setUp() public {
        op1 = vm.addr(op1Pk);
        op2 = vm.addr(op2Pk);

        token = new WJuno(owner);
        token.setBridge(bridge);

        registry = new OperatorRegistry(owner);
        distributor = new FeeDistributor(owner, token, address(registry));
        distributor.setBridge(bridge);

        registry.setFeeDistributor(address(distributor));

        registry.setOperator(op1, op1Fee, 1, true);
        registry.setOperator(op2, op2Fee, 3, true);
    }

    function test_depositAndClaim_splitsByWeight() public {
        // Mint + account 400 fees.
        vm.startPrank(bridge);
        token.mint(address(distributor), 400);
        distributor.depositFees(400);
        vm.stopPrank();

        assertEq(distributor.pendingReward(op1), 100);
        assertEq(distributor.pendingReward(op2), 300);

        distributor.claim(op1);
        assertEq(token.balanceOf(op1Fee), 100);

        distributor.claim(op2);
        assertEq(token.balanceOf(op2Fee), 300);

        // Claiming again is a no-op.
        distributor.claim(op1);
        distributor.claim(op2);
        assertEq(token.balanceOf(op1Fee), 100);
        assertEq(token.balanceOf(op2Fee), 300);
    }

    function test_depositFees_onlyBridge() public {
        vm.expectRevert();
        distributor.depositFees(1);
    }

    function test_depositFees_revertsWhenNoWeight() public {
        // Remove both operators (weight -> 0).
        registry.setOperator(op1, op1Fee, 0, false);
        registry.setOperator(op2, op2Fee, 0, false);

        vm.startPrank(bridge);
        token.mint(address(distributor), 1);
        vm.expectRevert(FeeDistributor.NoOperators.selector);
        distributor.depositFees(1);
        vm.stopPrank();
    }

    function test_operatorUpdate_harvestsPendingToNewRecipient() public {
        vm.startPrank(bridge);
        token.mint(address(distributor), 400);
        distributor.depositFees(400);
        vm.stopPrank();

        address newRecipient = makeAddr("op2FeeNew");
        // Update operator fee recipient; should harvest to the new recipient.
        registry.setOperator(op2, newRecipient, 3, true);

        assertEq(token.balanceOf(newRecipient), 300);
        assertEq(distributor.pendingReward(op2), 0);
    }
}
