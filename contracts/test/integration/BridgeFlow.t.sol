// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Bridge} from "../../src/Bridge.sol";
import {FeeDistributor} from "../../src/FeeDistributor.sol";
import {OperatorRegistry} from "../../src/OperatorRegistry.sol";
import {IRiscZeroVerifierRouter} from "../../src/interfaces/IRiscZeroVerifierRouter.sol";
import {WJuno} from "../../src/WJuno.sol";

contract AlwaysOkVerifier is IRiscZeroVerifierRouter {
    function verify(bytes calldata, bytes32, bytes32) external pure {}
}

contract BridgeFlowIntegrationTest is Test {
    WJuno private token;
    OperatorRegistry private registry;
    FeeDistributor private distributor;
    AlwaysOkVerifier private verifier;
    Bridge private bridge;

    uint256[5] private opPks = [uint256(0xC0), uint256(0xC1), uint256(0xC2), uint256(0xC3), uint256(0xC4)];

    bytes32 private constant DEPOSIT_IMAGE_ID = bytes32(uint256(0xAA01));
    bytes32 private constant WITHDRAW_IMAGE_ID = bytes32(uint256(0xAA02));

    uint96 private constant FEE_BPS = 50;
    uint96 private constant TIP_BPS = 1000;
    uint64 private constant REFUND_WINDOW = 1 days;
    uint64 private constant MAX_EXTEND = 12 hours;

    function setUp() public {
        verifier = new AlwaysOkVerifier();
        token = new WJuno(address(this));

        registry = new OperatorRegistry(address(this));
        distributor = new FeeDistributor(address(this), token, address(registry));
        registry.setFeeDistributor(address(distributor));

        for (uint256 i = 0; i < opPks.length; i++) {
            address op = vm.addr(opPks[i]);
            registry.setOperator(op, op, 1, true);
        }
        registry.setThreshold(3);

        bridge = new Bridge(
            address(this),
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

    function test_fullFlow_depositMint_thenWithdrawFinalize_thenOperatorClaims() public {
        address alice = makeAddr("alice");
        address relayer = makeAddr("relayer");

        Bridge.Checkpoint memory cp = _checkpoint();
        bytes[] memory sigs = _sortedSigs(bridge.checkpointDigest(cp), _firstN(3));

        // 1) Mint wJUNO on deposit.
        {
            Bridge.MintItem[] memory mints = new Bridge.MintItem[](1);
            mints[0] = Bridge.MintItem({depositId: keccak256("d1"), recipient: alice, amount: 100_000});

            bytes memory depositJournal = abi.encode(
                Bridge.DepositJournal({
                    finalOrchardRoot: cp.finalOrchardRoot,
                    baseChainId: cp.baseChainId,
                    bridgeContract: cp.bridgeContract,
                    items: mints
                })
            );

            vm.prank(relayer);
            bridge.mintBatch(cp, sigs, hex"01", depositJournal);
        }

        // FeeDistributor should have accrued fees; operator 0 can claim.
        address op0 = vm.addr(opPks[0]);
        uint256 pending0 = distributor.pendingReward(op0);
        assertGt(pending0, 0);

        distributor.claim(op0);
        assertEq(token.balanceOf(op0), pending0);

        // 2) Alice requests a withdraw (escrows wJUNO).
        uint256 aliceBal = token.balanceOf(alice);
        vm.startPrank(alice);
        token.approve(address(bridge), aliceBal);
        bytes32 wid = bridge.requestWithdraw(aliceBal, bytes("uaddr1..."));
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(address(bridge)), aliceBal);

        // 3) Operators pay on Juno (off-chain), then finalize on Base with proof journal.
        // Journal contains net amount (net of protocol fee).
        uint256 net = aliceBal - ((aliceBal * FEE_BPS) / 10_000);

        {
            Bridge.FinalizeItem[] memory finals = new Bridge.FinalizeItem[](1);
            finals[0] = Bridge.FinalizeItem({withdrawalId: wid, netAmount: net});

            bytes memory withdrawJournal = abi.encode(
                Bridge.WithdrawJournal({
                    finalOrchardRoot: cp.finalOrchardRoot,
                    baseChainId: cp.baseChainId,
                    bridgeContract: cp.bridgeContract,
                    items: finals
                })
            );

            vm.prank(relayer);
            bridge.finalizeWithdrawBatch(cp, sigs, hex"02", withdrawJournal);
        }

        assertEq(token.balanceOf(address(bridge)), 0);

        // New fees accrued; a different operator can claim.
        address op1 = vm.addr(opPks[1]);
        uint256 pending1 = distributor.pendingReward(op1);
        assertGt(pending1, 0);
        distributor.claim(op1);
        assertEq(token.balanceOf(op1), pending1);
    }

    function _checkpoint() private view returns (Bridge.Checkpoint memory) {
        return Bridge.Checkpoint({
            height: 1,
            blockHash: keccak256("bh"),
            finalOrchardRoot: keccak256("root"),
            baseChainId: block.chainid,
            bridgeContract: address(bridge)
        });
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
