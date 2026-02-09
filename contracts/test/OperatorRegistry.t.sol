// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {OperatorRegistry} from "../src/OperatorRegistry.sol";

contract OperatorRegistryTest is Test {
    OperatorRegistry private registry;

    address private owner = address(this);
    address private other = makeAddr("other");

    function setUp() public {
        registry = new OperatorRegistry(owner);
    }

    function test_setOperator_onlyOwner() public {
        vm.prank(other);
        vm.expectRevert();
        registry.setOperator(makeAddr("op"), makeAddr("fee"), 1, true);
    }

    function test_threshold_mustBeWithinActiveCount() public {
        address op1 = makeAddr("op1");
        address op2 = makeAddr("op2");

        registry.setOperator(op1, makeAddr("fee1"), 1, true);
        registry.setOperator(op2, makeAddr("fee2"), 1, true);

        registry.setThreshold(2);
        assertEq(registry.threshold(), 2);

        vm.expectRevert(OperatorRegistry.InvalidThreshold.selector);
        registry.setThreshold(3);
    }
}

