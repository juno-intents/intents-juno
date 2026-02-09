// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Bridge} from "../src/Bridge.sol";
import {FeeDistributor} from "../src/FeeDistributor.sol";
import {OperatorRegistry} from "../src/OperatorRegistry.sol";
import {IRiscZeroVerifierRouter} from "../src/interfaces/IRiscZeroVerifierRouter.sol";
import {WJuno} from "../src/WJuno.sol";

contract MockVerifierRouter is IRiscZeroVerifierRouter {
    bool public ok = true;
    bytes32 public expectedImageId;
    bytes32 public expectedJournalHash;

    function setExpected(bytes32 imageId, bytes32 journalHash, bool ok_) external {
        expectedImageId = imageId;
        expectedJournalHash = journalHash;
        ok = ok_;
    }

    function verify(bytes calldata, bytes32 imageId, bytes calldata journal) external view returns (bool) {
        if (!ok) return false;
        if (expectedImageId != bytes32(0) && expectedImageId != imageId) return false;
        if (expectedJournalHash != bytes32(0) && expectedJournalHash != keccak256(journal)) return false;
        return true;
    }
}

contract BridgeTest is Test {
    WJuno private token;
    OperatorRegistry private registry;
    FeeDistributor private distributor;
    MockVerifierRouter private verifier;
    Bridge private bridge;

    address private owner = address(this);
    address private relayer = makeAddr("relayer");

    uint256[5] private opPks = [uint256(0xA0), uint256(0xA1), uint256(0xA2), uint256(0xA3), uint256(0xA4)];

    bytes32 private constant DEPOSIT_IMAGE_ID = bytes32(uint256(0xD001));
    bytes32 private constant WITHDRAW_IMAGE_ID = bytes32(uint256(0xD002));

    uint96 private constant FEE_BPS = 50; // 0.50%
    uint96 private constant TIP_BPS = 1000; // 10% of fee
    uint64 private constant REFUND_WINDOW = 1 days;
    uint64 private constant MAX_EXTEND = 12 hours;

    function setUp() public {
        verifier = new MockVerifierRouter();

        token = new WJuno(owner);

        registry = new OperatorRegistry(owner);
        distributor = new FeeDistributor(owner, token, address(registry));
        registry.setFeeDistributor(address(distributor));

        // Operator set: 5 operators, threshold 3.
        for (uint256 i = 0; i < opPks.length; i++) {
            address op = vm.addr(opPks[i]);
            registry.setOperator(op, makeAddr(string.concat("fee", vm.toString(i))), 1, true);
        }
        registry.setThreshold(3);

        bridge = new Bridge(
            owner,
            token,
            distributor,
            registry,
            verifier,
            DEPOSIT_IMAGE_ID,
            WITHDRAW_IMAGE_ID,
            FEE_BPS,
            TIP_BPS,
            REFUND_WINDOW,
            MAX_EXTEND
        );

        token.setBridge(address(bridge));
        distributor.setBridge(address(bridge));
    }

    function test_mintBatch_mintsNetAndFees_andIsIdempotent() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        bytes32 depositId = keccak256("deposit-1");
        uint256 amount = 100_000;
        items[0] = Bridge.MintItem({depositId: depositId, recipient: makeAddr("alice"), amount: amount});

        bytes memory journal = abi.encode(items);
        verifier.setExpected(DEPOSIT_IMAGE_ID, keccak256(journal), true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"01", journal);

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        assertEq(token.balanceOf(items[0].recipient), net);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(relayer), tip);
        assertTrue(bridge.depositUsed(depositId));

        // Replaying the same depositId is a skip/no-op.
        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"02", journal);
        assertEq(token.balanceOf(items[0].recipient), net);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(relayer), tip);
    }

    function test_requestWithdraw_andRefund() public {
        address alice = makeAddr("alice");
        uint256 amount = 50_000;

        // Fund alice.
        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, bytes("uaddr1..."));
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(address(bridge)), amount);

        vm.expectRevert(Bridge.WithdrawNotExpired.selector);
        bridge.refund(wid);

        vm.warp(block.timestamp + REFUND_WINDOW + 1);
        bridge.refund(wid);

        assertEq(token.balanceOf(alice), amount);
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    function test_finalizeWithdrawBatch_burnsAndDistributesFees_andIdempotent() public {
        address alice = makeAddr("alice");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, bytes("uaddr1..."));
        vm.stopPrank();

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](1);
        items[0] = Bridge.FinalizeItem({withdrawalId: wid, netAmount: net});
        bytes memory journal = abi.encode(items);

        verifier.setExpected(WITHDRAW_IMAGE_ID, keccak256(journal), true);

        Bridge.Checkpoint memory cp = _checkpoint();
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        uint256 supplyBefore = token.totalSupply();

        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, sigs, hex"03", journal);

        // Fees moved to relayer + distributor; net burned.
        assertEq(token.balanceOf(relayer), tip);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(address(bridge)), 0);
        assertEq(token.totalSupply(), supplyBefore - net);

        // Idempotent replay: no changes.
        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, sigs, hex"04", journal);

        assertEq(token.balanceOf(relayer), tip);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    function test_extendWithdrawExpiryBatch_requiresQuorumSig_andUpdatesExpiry() public {
        address alice = makeAddr("alice");
        uint256 amount = 10_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, bytes("uaddr1..."));
        vm.stopPrank();

        (, , uint64 oldExpiry,,,,) = bridge.getWithdrawal(wid);
        uint64 newExpiry = oldExpiry + 6 hours;

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = wid;

        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory sigs = _sortedSigs(bridge.extendWithdrawDigest(idsHash, newExpiry), _firstN(3));

        bridge.extendWithdrawExpiryBatch(ids, newExpiry, sigs);

        (, , uint64 updatedExpiry,,,,) = bridge.getWithdrawal(wid);
        assertEq(updatedExpiry, newExpiry);
    }

    function test_mintBatch_revertsWithInsufficientSignatures() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: keccak256("d"), recipient: makeAddr("alice"), amount: 1});
        bytes memory journal = abi.encode(items);
        verifier.setExpected(DEPOSIT_IMAGE_ID, keccak256(journal), true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(2));

        vm.expectRevert(Bridge.InsufficientSignatures.selector);
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_mintBatch_revertsIfThresholdUnset() public {
        MockVerifierRouter v = new MockVerifierRouter();

        WJuno t = new WJuno(owner);
        OperatorRegistry r = new OperatorRegistry(owner);
        FeeDistributor d = new FeeDistributor(owner, t, address(r));
        r.setFeeDistributor(address(d));

        // Add operators but do not set threshold.
        for (uint256 i = 0; i < opPks.length; i++) {
            r.setOperator(vm.addr(opPks[i]), makeAddr(string.concat("fee", vm.toString(i))), 1, true);
        }

        Bridge b = new Bridge(
            owner,
            t,
            d,
            r,
            v,
            DEPOSIT_IMAGE_ID,
            WITHDRAW_IMAGE_ID,
            FEE_BPS,
            TIP_BPS,
            REFUND_WINDOW,
            MAX_EXTEND
        );
        t.setBridge(address(b));
        d.setBridge(address(b));

        Bridge.Checkpoint memory cp = Bridge.Checkpoint({
            height: 1,
            blockHash: keccak256("bh"),
            finalOrchardRoot: keccak256("root"),
            baseChainId: block.chainid,
            bridgeContract: address(b)
        });

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: keccak256("d"), recipient: makeAddr("alice"), amount: 1});
        bytes memory journal = abi.encode(items);
        v.setExpected(DEPOSIT_IMAGE_ID, keccak256(journal), true);

        vm.expectRevert(Bridge.OperatorThresholdUnset.selector);
        b.mintBatch(cp, new bytes[](0), hex"01", journal);
    }

    function _checkpoint() private view returns (Bridge.Checkpoint memory) {
        return Bridge.Checkpoint({
            height: 123,
            blockHash: keccak256("bh"),
            finalOrchardRoot: keccak256("root"),
            baseChainId: block.chainid,
            bridgeContract: address(bridge)
        });
    }

    function _firstN(uint256 n) private view returns (uint256[] memory pks) {
        pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) pks[i] = opPks[i];
    }

    function _sortedSigs(bytes32 digest, uint256[] memory pks) private returns (bytes[] memory sigs) {
        uint256 n = pks.length;
        address[] memory signers = new address[](n);
        sigs = new bytes[](n);

        for (uint256 i = 0; i < n; i++) {
            signers[i] = vm.addr(pks[i]);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            sigs[i] = abi.encodePacked(r, s, v);
        }

        // Sort by signer address ascending (Bridge enforces this to ensure uniqueness without a bitmap).
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (signers[j] < signers[i]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (sigs[i], sigs[j]) = (sigs[j], sigs[i]);
                }
            }
        }
    }
}
