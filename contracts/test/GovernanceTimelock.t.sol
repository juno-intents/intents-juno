// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {Bridge} from "../src/Bridge.sol";
import {FeeDistributor} from "../src/FeeDistributor.sol";
import {OperatorRegistry} from "../src/OperatorRegistry.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {WJuno} from "../src/WJuno.sol";

contract GovernanceTimelockVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

contract GovernanceTimelockTest is Test {
    bytes32 private constant DEPOSIT_IMAGE_ID = bytes32(uint256(0xD001));
    bytes32 private constant WITHDRAW_IMAGE_ID = bytes32(uint256(0xD002));

    WJuno private token;
    OperatorRegistry private registry;
    FeeDistributor private distributor;
    GovernanceTimelockVerifier private verifier;
    Bridge private bridge;
    TimelockController private timelock;

    address private proposer = makeAddr("proposer");
    address private executor = makeAddr("executor");
    address private admin = makeAddr("admin");

    function setUp() public {
        // OZ reserves timestamp=1 as the "done" sentinel, so zero-delay operations must start later.
        vm.warp(2);

        verifier = new GovernanceTimelockVerifier();
        token = new WJuno(address(this));
        registry = new OperatorRegistry(address(this));
        distributor = new FeeDistributor(address(this), token, address(registry));
        registry.setFeeDistributor(address(distributor));

        address operator = makeAddr("operator");
        registry.setOperator(operator, operator, 1, true);
        registry.setThreshold(1);

        bridge = new Bridge(
            address(this),
            token,
            distributor,
            registry,
            verifier,
            DEPOSIT_IMAGE_ID,
            WITHDRAW_IMAGE_ID,
            50,
            1000,
            1 days,
            12 hours,
            0,
            0
        );

        token.setBridge(address(bridge));
        distributor.setBridge(address(bridge));

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        timelock = new TimelockController(0, proposers, executors, admin);
    }

    function test_timelock_acceptsOwnership_and_controlsBridgePointers() public {
        token.transferOwnership(address(timelock));
        distributor.transferOwnership(address(timelock));
        registry.transferOwnership(address(timelock));
        bridge.transferOwnership(address(timelock));

        _scheduleAndExecute(address(token), abi.encodeWithSignature("acceptOwnership()"), "accept-token");
        _scheduleAndExecute(address(distributor), abi.encodeWithSignature("acceptOwnership()"), "accept-fee");
        _scheduleAndExecute(address(registry), abi.encodeWithSignature("acceptOwnership()"), "accept-registry");
        _scheduleAndExecute(address(bridge), abi.encodeWithSignature("acceptOwnership()"), "accept-bridge");

        assertEq(token.owner(), address(timelock));
        assertEq(distributor.owner(), address(timelock));
        assertEq(registry.owner(), address(timelock));
        assertEq(bridge.owner(), address(timelock));

        address newBridge = makeAddr("newBridge");
        _scheduleAndExecute(address(token), abi.encodeCall(WJuno.setBridge, (newBridge)), "update-wjuno-bridge");
        _scheduleAndExecute(
            address(distributor), abi.encodeCall(FeeDistributor.setBridge, (newBridge)), "update-fee-bridge"
        );
        _scheduleAndExecute(address(bridge), abi.encodeCall(Bridge.pause, ()), "pause-bridge");

        assertEq(token.bridge(), newBridge);
        assertEq(distributor.bridge(), newBridge);
        assertTrue(bridge.paused());
    }

    function _scheduleAndExecute(address target, bytes memory data, string memory saltLabel) private {
        bytes32 salt = keccak256(bytes(saltLabel));
        vm.prank(proposer);
        timelock.schedule(target, 0, data, bytes32(0), salt, 0);

        vm.warp(block.timestamp + 1);
        vm.prank(executor);
        timelock.execute(target, 0, data, bytes32(0), salt);
    }
}
