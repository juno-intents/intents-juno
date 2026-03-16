// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Bridge} from "../src/Bridge.sol";
import {FeeDistributor} from "../src/FeeDistributor.sol";
import {OperatorRegistry} from "../src/OperatorRegistry.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {WJuno} from "../src/WJuno.sol";

contract MockVerifierRouter is ISP1Verifier {
    bool public ok = true;
    bytes32 public expectedProgramVKey;
    bytes32 public expectedPublicValuesHash;

    error VerifyFailed();

    function setExpected(bytes32 programVKey, bytes calldata publicValues, bool ok_) external {
        expectedProgramVKey = programVKey;
        expectedPublicValuesHash = keccak256(publicValues);
        ok = ok_;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata) external view {
        if (!ok) revert VerifyFailed();
        if (expectedProgramVKey != bytes32(0) && expectedProgramVKey != programVKey) revert VerifyFailed();
        if (expectedPublicValuesHash != bytes32(0) && expectedPublicValuesHash != keccak256(publicValues)) {
            revert VerifyFailed();
        }
    }
}

contract MockStringVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {
        revert("string verifier failure");
    }
}

contract MockPanicVerifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {
        uint256 zero = 0;
        uint256 value = 1 / zero;
        value;
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
    address private minDepositAdmin = makeAddr("minDepositAdmin");
    address private pauseGuardian = makeAddr("pauseGuardian");

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
            MAX_EXTEND,
            0,
            0
        );

        token.setBridge(address(bridge));
        distributor.setBridge(address(bridge));
    }

    function test_constructor_revertsOnZeroImageId() public {
        vm.expectRevert(Bridge.ZeroImageId.selector);
        new Bridge(
            owner,
            token,
            distributor,
            registry,
            verifier,
            bytes32(0),
            WITHDRAW_IMAGE_ID,
            FEE_BPS,
            TIP_BPS,
            REFUND_WINDOW,
            MAX_EXTEND,
            0,
            0
        );

        vm.expectRevert(Bridge.ZeroImageId.selector);
        new Bridge(
            owner,
            token,
            distributor,
            registry,
            verifier,
            DEPOSIT_IMAGE_ID,
            bytes32(0),
            FEE_BPS,
            TIP_BPS,
            REFUND_WINDOW,
            MAX_EXTEND,
            0,
            0
        );
    }

    function test_setImageIds_revertsOnZeroImageId() public {
        vm.expectRevert(Bridge.ZeroImageId.selector);
        bridge.setImageIds(bytes32(0), WITHDRAW_IMAGE_ID);

        vm.expectRevert(Bridge.ZeroImageId.selector);
        bridge.setImageIds(DEPOSIT_IMAGE_ID, bytes32(0));
    }

    function test_minDepositAdmin_canUpdateOnlyMinDepositAmount() public {
        bridge.setMinDepositAdmin(minDepositAdmin);

        vm.prank(minDepositAdmin);
        bridge.setMinDepositAmount(123_456);

        assertEq(bridge.minDepositAmount(), 123_456);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, minDepositAdmin));
        vm.prank(minDepositAdmin);
        bridge.setVerifier(verifier);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, minDepositAdmin));
        vm.prank(minDepositAdmin);
        bridge.setParams(FEE_BPS, TIP_BPS, REFUND_WINDOW, MAX_EXTEND, 999, 111);
    }

    function test_owner_retainsFullParamControlAlongsideMinDepositAdmin() public {
        bridge.setMinDepositAdmin(minDepositAdmin);

        bridge.setMinDepositAmount(777);
        assertEq(bridge.minDepositAmount(), 777);

        bridge.setParams(75, 1200, 2 days, 18 hours, 888, 999);

        assertEq(bridge.feeBps(), 75);
        assertEq(bridge.relayerTipBps(), 1200);
        assertEq(bridge.refundWindowSeconds(), 2 days);
        assertEq(bridge.maxExpiryExtensionSeconds(), 18 hours);
        assertEq(bridge.minDepositAmount(), 888);
        assertEq(bridge.minWithdrawAmount(), 999);
        assertEq(bridge.minDepositAdmin(), minDepositAdmin);
    }

    function test_pauseGuardian_canPause_butOnlyOwnerCanUnpause() public {
        bridge.setPauseGuardian(pauseGuardian);

        vm.prank(pauseGuardian);
        bridge.pause();
        assertTrue(bridge.paused());

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, pauseGuardian));
        vm.prank(pauseGuardian);
        bridge.unpause();

        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_pauseGuardian_cannotSetAdminRoles() public {
        bridge.setPauseGuardian(pauseGuardian);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, pauseGuardian));
        vm.prank(pauseGuardian);
        bridge.setMinDepositAdmin(minDepositAdmin);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, pauseGuardian));
        vm.prank(pauseGuardian);
        bridge.setPauseGuardian(address(0xBEEF));
    }

    function test_mintBatch_mintsNetAndFees_andIsIdempotent() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        bytes32 depositId = keccak256("deposit-1");
        uint256 amount = 100_000;
        items[0] = Bridge.MintItem({depositId: depositId, recipient: makeAddr("alice"), amount: amount});

        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);

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

    function test_mintBatch_belowMinDepositDoesNotBurnDepositId() public {
        bridge.setMinDepositAmount(100_000);

        Bridge.Checkpoint memory cp = _checkpoint();
        bytes32 depositId = keccak256("deposit-below-min");
        address recipient = makeAddr("alice");
        uint256 amount = 99_999;

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: depositId, recipient: recipient, amount: amount});

        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"01", journal);

        assertEq(token.balanceOf(recipient), 0);
        assertFalse(bridge.depositUsed(depositId));

        bridge.setMinDepositAmount(amount);

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"02", journal);

        assertEq(token.balanceOf(recipient), net);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(relayer), tip);
        assertTrue(bridge.depositUsed(depositId));
    }

    function test_requestWithdraw_andRefund() public {
        address alice = makeAddr("alice");
        uint256 amount = 50_000;

        // Fund alice.
        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes memory ua = bytes("uaddr1...");
        bytes32 wid = bridge.requestWithdraw(amount, ua);
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

    function test_refund_allowed_whilePaused_afterExpiry() public {
        address alice = makeAddr("alice");
        uint256 amount = 50_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, bytes("uaddr1..."));
        vm.stopPrank();

        bridge.pause();
        vm.warp(block.timestamp + REFUND_WINDOW + 1);
        bridge.refund(wid);

        assertEq(token.balanceOf(alice), amount);
    }

    function test_markWithdrawPaidBatch_blocksRefund_andAllowsLateFinalize() public {
        address alice = makeAddr("alice");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        bytes memory ua = bytes("uaddr1...");
        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = wid;
        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory paidSigs = _sortedSigs(bridge.markWithdrawPaidDigest(idsHash), _firstN(3));

        bridge.markWithdrawPaidBatch(ids, paidSigs);
        assertTrue(bridge.withdrawalPaid(wid));

        vm.warp(block.timestamp + REFUND_WINDOW + 1);

        vm.expectRevert(Bridge.WithdrawalPaid.selector);
        bridge.refund(wid);

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        Bridge.Checkpoint memory cp = _checkpoint();
        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](1);
        items[0] = Bridge.FinalizeItem({withdrawalId: wid, recipientUAHash: keccak256(ua), netAmount: net});
        bytes memory journal = abi.encode(
            Bridge.WithdrawJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: items
            })
        );
        verifier.setExpected(WITHDRAW_IMAGE_ID, journal, true);

        bytes[] memory checkpointSigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, checkpointSigs, hex"05", journal);

        assertEq(token.balanceOf(relayer), tip);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    function test_markWithdrawPaidBatch_requiresQuorumSignatures() public {
        address alice = makeAddr("alice");
        uint256 amount = 10_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, bytes("uaddr1..."));
        vm.stopPrank();

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = wid;
        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory sigs = _sortedSigs(bridge.markWithdrawPaidDigest(idsHash), _firstN(2));

        vm.expectRevert(Bridge.InsufficientSignatures.selector);
        bridge.markWithdrawPaidBatch(ids, sigs);
    }

    function test_finalizeWithdrawBatch_burnsAndDistributesFees_andIdempotent() public {
        address alice = makeAddr("alice");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes memory ua = bytes("uaddr1...");
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](1);
        items[0] = Bridge.FinalizeItem({withdrawalId: wid, recipientUAHash: keccak256(ua), netAmount: net});
        Bridge.WithdrawJournal memory wj = Bridge.WithdrawJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(wj);

        verifier.setExpected(WITHDRAW_IMAGE_ID, journal, true);

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

    function test_finalizeWithdrawBatch_skipsRefundedItemsAndFinalizesRemaining() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);
        vm.prank(address(bridge));
        token.mint(bob, amount);

        bytes memory uaAlice = bytes("uaddr1-alice");
        bytes memory uaBob = bytes("uaddr1-bob");

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 widAlice = bridge.requestWithdraw(amount, uaAlice);
        vm.stopPrank();

        vm.startPrank(bob);
        token.approve(address(bridge), amount);
        bytes32 widBob = bridge.requestWithdraw(amount, uaBob);
        vm.stopPrank();

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = widAlice;
        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory paidSigs = _sortedSigs(bridge.markWithdrawPaidDigest(idsHash), _firstN(3));
        bridge.markWithdrawPaidBatch(ids, paidSigs);

        vm.warp(block.timestamp + REFUND_WINDOW + 1);
        bridge.refund(widBob);

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 tip = (fee * TIP_BPS) / 10_000;
        uint256 feeToDist = fee - tip;
        uint256 net = amount - fee;

        Bridge.Checkpoint memory cp = _checkpoint();
        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](2);
        items[0] = Bridge.FinalizeItem({withdrawalId: widAlice, recipientUAHash: keccak256(uaAlice), netAmount: net});
        items[1] = Bridge.FinalizeItem({withdrawalId: widBob, recipientUAHash: keccak256(uaBob), netAmount: net});
        bytes memory journal = abi.encode(
            Bridge.WithdrawJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: items
            })
        );
        verifier.setExpected(WITHDRAW_IMAGE_ID, journal, true);

        bytes[] memory checkpointSigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, checkpointSigs, hex"06", journal);

        assertEq(token.balanceOf(relayer), tip);
        assertEq(token.balanceOf(address(distributor)), feeToDist);
        assertEq(token.balanceOf(address(bridge)), 0);

        (,,,, bool finalizedAlice,,) = bridge.getWithdrawal(widAlice);
        (,,,, bool finalizedBob, bool refundedBob,) = bridge.getWithdrawal(widBob);
        assertTrue(finalizedAlice);
        assertFalse(finalizedBob);
        assertTrue(refundedBob);
    }

    function test_mintBatch_allowsDistinctBatchesAtSameCheckpoint() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        Bridge.MintItem[] memory itemsA = new Bridge.MintItem[](1);
        itemsA[0] = Bridge.MintItem({
            depositId: keccak256("deposit-same-cp-a"),
            recipient: makeAddr("alice"),
            amount: 100_000
        });
        bytes memory journalA = abi.encode(
            Bridge.DepositJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: itemsA
            })
        );
        verifier.setExpected(DEPOSIT_IMAGE_ID, journalA, true);
        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"0a", journalA);

        Bridge.MintItem[] memory itemsB = new Bridge.MintItem[](1);
        itemsB[0] = Bridge.MintItem({
            depositId: keccak256("deposit-same-cp-b"),
            recipient: makeAddr("bob"),
            amount: 100_000
        });
        bytes memory journalB = abi.encode(
            Bridge.DepositJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: itemsB
            })
        );
        verifier.setExpected(DEPOSIT_IMAGE_ID, journalB, true);
        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"0b", journalB);

        assertTrue(bridge.depositUsed(itemsA[0].depositId));
        assertTrue(bridge.depositUsed(itemsB[0].depositId));
    }

    function test_mintBatch_revertsOnCheckpointHeightRegression() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        bytes memory journal = _depositJournal(cp, 1);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);
        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"0c", journal);

        Bridge.Checkpoint memory stale = Bridge.Checkpoint({
            height: cp.height - 1,
            blockHash: bytes32(uint256(0x1234)),
            finalOrchardRoot: bytes32(uint256(0x5678)),
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract
        });
        bytes memory staleJournal = _depositJournal(stale, 1);
        verifier.setExpected(DEPOSIT_IMAGE_ID, staleJournal, true);
        bytes[] memory staleSigs = _sortedSigs(bridge.checkpointDigest(stale), _firstN(3));

        vm.expectRevert(abi.encodeWithSelector(Bridge.CheckpointHeightRegression.selector, stale.height, cp.height));
        vm.prank(relayer);
        bridge.mintBatch(stale, staleSigs, hex"0d", staleJournal);
    }

    function test_mintBatch_revertsOnConflictingCheckpointAtSameHeight() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        bytes memory journal = _depositJournal(cp, 1);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);
        vm.prank(relayer);
        bridge.mintBatch(cp, sigs, hex"0e", journal);

        Bridge.Checkpoint memory conflicting = Bridge.Checkpoint({
            height: cp.height,
            blockHash: bytes32(uint256(0xabc123)),
            finalOrchardRoot: bytes32(uint256(0xdef456)),
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract
        });
        bytes memory conflictingJournal = _depositJournal(conflicting, 1);
        verifier.setExpected(DEPOSIT_IMAGE_ID, conflictingJournal, true);
        bytes[] memory conflictingSigs = _sortedSigs(bridge.checkpointDigest(conflicting), _firstN(3));

        vm.expectRevert(
            abi.encodeWithSelector(
                Bridge.CheckpointConflict.selector, conflicting.height, conflicting.blockHash, conflicting.finalOrchardRoot
            )
        );
        vm.prank(relayer);
        bridge.mintBatch(conflicting, conflictingSigs, hex"0f", conflictingJournal);
    }

    function test_mintBatch_revertsOnTooManyItems() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        uint256 itemCount = bridge.MAX_BATCH_SIZE() + 1;
        bytes memory journal = _depositJournal(cp, itemCount);
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(abi.encodeWithSelector(Bridge.InvalidBatchSize.selector, itemCount, bridge.MAX_BATCH_SIZE()));
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_finalizeWithdrawBatch_revertsOnTooManyItems() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        uint256 itemCount = bridge.MAX_BATCH_SIZE() + 1;
        bytes memory journal = _withdrawJournal(cp, itemCount);
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(abi.encodeWithSelector(Bridge.InvalidBatchSize.selector, itemCount, bridge.MAX_BATCH_SIZE()));
        bridge.finalizeWithdrawBatch(cp, sigs, hex"01", journal);
    }

    function test_finalizeWithdrawBatch_revertsOnRecipientHashMismatch() public {
        address alice = makeAddr("alice");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        bytes memory ua = bytes("uaddr1...");
        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 net = amount - fee;

        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](1);
        items[0] = Bridge.FinalizeItem({withdrawalId: wid, recipientUAHash: keccak256("wrong-ua"), netAmount: net});
        Bridge.WithdrawJournal memory wj = Bridge.WithdrawJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(wj);

        verifier.setExpected(WITHDRAW_IMAGE_ID, journal, true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(Bridge.WithdrawalRecipientMismatch.selector);
        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, sigs, hex"03", journal);
    }

    function test_extendWithdrawExpiryBatch_requiresQuorumSig_andUpdatesExpiry() public {
        address alice = makeAddr("alice");
        uint256 amount = 10_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes memory ua = bytes("uaddr1...");
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        (,, uint64 oldExpiry,,,,) = bridge.getWithdrawal(wid);
        uint64 newExpiry = oldExpiry + 6 hours;

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = wid;

        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory sigs = _sortedSigs(bridge.extendWithdrawDigest(idsHash, newExpiry), _firstN(3));

        bridge.extendWithdrawExpiryBatch(ids, newExpiry, sigs);

        (,, uint64 updatedExpiry,,,,) = bridge.getWithdrawal(wid);
        assertEq(updatedExpiry, newExpiry);
    }

    function test_extendWithdrawExpiryBatch_revertsOnEmptyIds() public {
        bytes32[] memory ids = new bytes32[](0);
        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert(Bridge.InvalidExtendBatch.selector);
        bridge.extendWithdrawExpiryBatch(ids, uint64(block.timestamp + 1), sigs);
    }

    function test_extendWithdrawExpiryBatch_revertsOnTooManyIds() public {
        uint256 max = bridge.MAX_EXTEND_BATCH();
        bytes32[] memory ids = new bytes32[](max + 1);
        for (uint256 i = 0; i < ids.length; i++) {
            ids[i] = bytes32(i + 1);
        }

        vm.expectRevert(Bridge.InvalidExtendBatch.selector);
        bridge.extendWithdrawExpiryBatch(ids, uint64(block.timestamp + 1 days), new bytes[](0));
    }

    function test_extendWithdrawExpiryBatch_revertsWhenNewExpiryNotInFuture() public {
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = keccak256("wid");

        vm.expectRevert(Bridge.InvalidExtendBatch.selector);
        bridge.extendWithdrawExpiryBatch(ids, uint64(block.timestamp), new bytes[](0));
    }

    function test_extendWithdrawExpiryBatch_revertsOnUnsortedIds() public {
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = bytes32(uint256(2));
        ids[1] = bytes32(uint256(1));

        vm.expectRevert(Bridge.SignaturesNotSortedOrUnique.selector);
        bridge.extendWithdrawExpiryBatch(ids, uint64(block.timestamp + 1 days), new bytes[](0));
    }

    function test_extendWithdrawExpiryBatch_revertsOnExpiryExtensionTooLarge() public {
        address alice = makeAddr("alice");
        uint256 amount = 10_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes memory ua = bytes("uaddr1...");
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        (,, uint64 oldExpiry,,,,) = bridge.getWithdrawal(wid);
        uint64 newExpiry = oldExpiry + MAX_EXTEND + uint64(1);

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = wid;

        bytes32 idsHash = keccak256(abi.encodePacked(ids));
        bytes[] memory sigs = _sortedSigs(bridge.extendWithdrawDigest(idsHash, newExpiry), _firstN(3));

        vm.expectRevert(Bridge.ExpiryExtensionTooLarge.selector);
        bridge.extendWithdrawExpiryBatch(ids, newExpiry, sigs);
    }

    function test_mintBatch_revertsWithInsufficientSignatures() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: keccak256("d"), recipient: makeAddr("alice"), amount: 1});
        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(2));

        vm.expectRevert(Bridge.InsufficientSignatures.selector);
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_mintBatch_revertsOnJournalCheckpointMismatch() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: keccak256("d"), recipient: makeAddr("alice"), amount: 1});

        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: keccak256("wrong-root"),
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(Bridge.BadJournalDomain.selector);
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_finalizeWithdrawBatch_revertsOnJournalCheckpointMismatch() public {
        address alice = makeAddr("alice");
        uint256 amount = 100_000;

        vm.prank(address(bridge));
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bytes memory ua = bytes("uaddr1...");
        bytes32 wid = bridge.requestWithdraw(amount, ua);
        vm.stopPrank();

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 net = amount - fee;

        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](1);
        items[0] = Bridge.FinalizeItem({withdrawalId: wid, recipientUAHash: keccak256(ua), netAmount: net});

        Bridge.WithdrawJournal memory wj = Bridge.WithdrawJournal({
            finalOrchardRoot: keccak256("wrong-root"),
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(wj);
        verifier.setExpected(WITHDRAW_IMAGE_ID, journal, true);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(Bridge.BadJournalDomain.selector);
        vm.prank(relayer);
        bridge.finalizeWithdrawBatch(cp, sigs, hex"01", journal);
    }

    function test_mintBatch_surfacesVerifierRevertData() public {
        Bridge.Checkpoint memory cp = _checkpoint();

        Bridge.MintItem[] memory items = new Bridge.MintItem[](1);
        items[0] = Bridge.MintItem({depositId: keccak256("verify-fail"), recipient: makeAddr("alice"), amount: 1});
        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        verifier.setExpected(DEPOSIT_IMAGE_ID, journal, false);

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(
            abi.encodeWithSelector(
                Bridge.VerifierReverted.selector, abi.encodeWithSelector(MockVerifierRouter.VerifyFailed.selector)
            )
        );
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_mintBatch_surfacesVerifierStringError() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        bytes memory journal = _depositJournal(cp, 1);
        bridge.setVerifier(new MockStringVerifier());

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(
            abi.encodeWithSelector(Bridge.VerifierStringError.selector, "string verifier failure")
        );
        bridge.mintBatch(cp, sigs, hex"01", journal);
    }

    function test_mintBatch_surfacesVerifierPanic() public {
        Bridge.Checkpoint memory cp = _checkpoint();
        bytes memory journal = _depositJournal(cp, 1);
        bridge.setVerifier(new MockPanicVerifier());

        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        vm.expectRevert(abi.encodeWithSelector(Bridge.VerifierPanic.selector, uint256(0x12)));
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
            owner, t, d, r, v, DEPOSIT_IMAGE_ID, WITHDRAW_IMAGE_ID, FEE_BPS, TIP_BPS, REFUND_WINDOW, MAX_EXTEND, 0, 0
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
        Bridge.DepositJournal memory dj = Bridge.DepositJournal({
            finalOrchardRoot: cp.finalOrchardRoot,
            baseChainId: cp.baseChainId,
            bridgeContract: cp.bridgeContract,
            items: items
        });
        bytes memory journal = abi.encode(dj);
        v.setExpected(DEPOSIT_IMAGE_ID, journal, true);

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

    function _depositJournal(Bridge.Checkpoint memory cp, uint256 itemCount) private pure returns (bytes memory) {
        Bridge.MintItem[] memory items = new Bridge.MintItem[](itemCount);
        for (uint256 i = 0; i < itemCount; i++) {
            items[i] = Bridge.MintItem({
                depositId: keccak256(abi.encodePacked("deposit", i)),
                recipient: address(uint160(i + 1)),
                amount: i + 1
            });
        }

        return abi.encode(
            Bridge.DepositJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: items
            })
        );
    }

    function _withdrawJournal(Bridge.Checkpoint memory cp, uint256 itemCount) private pure returns (bytes memory) {
        Bridge.FinalizeItem[] memory items = new Bridge.FinalizeItem[](itemCount);
        for (uint256 i = 0; i < itemCount; i++) {
            items[i] = Bridge.FinalizeItem({
                withdrawalId: keccak256(abi.encodePacked("withdrawal", i)),
                recipientUAHash: keccak256(abi.encodePacked("ua", i)),
                netAmount: i + 1
            });
        }

        return abi.encode(
            Bridge.WithdrawJournal({
                finalOrchardRoot: cp.finalOrchardRoot,
                baseChainId: cp.baseChainId,
                bridgeContract: cp.bridgeContract,
                items: items
            })
        );
    }

    function _firstN(uint256 n) private view returns (uint256[] memory pks) {
        pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = opPks[i];
        }
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
