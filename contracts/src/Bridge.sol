// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {FeeDistributor} from "./FeeDistributor.sol";
import {OperatorRegistry} from "./OperatorRegistry.sol";
import {IRiscZeroVerifierRouter} from "./interfaces/IRiscZeroVerifierRouter.sol";
import {WJuno} from "./WJuno.sol";

/// @notice Base-side bridge for minting/burning wJUNO using operator-quorum checkpoints and zk proofs.
contract Bridge is Ownable2Step, Pausable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // -------- Errors --------
    error ZeroAddress();
    error InvalidBps();
    error InvalidWithdrawalRecipient();
    error WithdrawalNotFound();
    error WithdrawalFinalized();
    error WithdrawalRefunded();
    error WithdrawalExpired();
    error WithdrawNotExpired();
    error NetAmountMismatch();
    error InvalidProof();
    error BadCheckpointDomain();
    error InsufficientSignatures();
    error SignaturesNotSortedOrUnique();
    error NotOperator();
    error OperatorThresholdUnset();
    error InvalidExtendBatch();
    error ExpiryExtensionTooLarge();

    // -------- Types --------
    struct Checkpoint {
        uint64 height;
        bytes32 blockHash;
        bytes32 finalOrchardRoot;
        uint256 baseChainId;
        address bridgeContract;
    }

    struct MintItem {
        bytes32 depositId;
        address recipient;
        uint256 amount;
    }

    struct FinalizeItem {
        bytes32 withdrawalId;
        uint256 netAmount;
    }

    struct Withdrawal {
        address requester;
        uint256 amount;
        uint64 expiry;
        uint96 feeBps; // snapshot at request time
        bool finalized;
        bool refunded;
        bytes recipientUA;
    }

    // -------- Constants --------
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_UA_BYTES = 256;
    uint256 public constant MAX_EXTEND_BATCH = 200;

    bytes32 private constant CHECKPOINT_TYPEHASH = keccak256(
        "Checkpoint(uint64 height,bytes32 blockHash,bytes32 finalOrchardRoot,uint256 baseChainId,address bridgeContract)"
    );
    bytes32 private constant EXTEND_TYPEHASH = keccak256(
        "ExtendWithdrawExpiry(bytes32 withdrawalIdsHash,uint64 newExpiry,uint256 baseChainId,address bridgeContract)"
    );

    // -------- State --------
    WJuno public immutable wjuno;
    FeeDistributor public immutable feeDistributor;
    OperatorRegistry public immutable operatorRegistry;
    IRiscZeroVerifierRouter public verifier;

    bytes32 public depositImageId;
    bytes32 public withdrawImageId;

    uint96 public feeBps;
    uint96 public relayerTipBps; // portion of fee (in bps) paid to msg.sender
    uint64 public refundWindowSeconds;
    uint64 public maxExpiryExtensionSeconds;

    uint256 public withdrawNonce;

    mapping(bytes32 => bool) public depositUsed;
    mapping(bytes32 => Withdrawal) private _withdrawals;

    // -------- Events --------
    event ParamsUpdated(uint96 feeBps, uint96 relayerTipBps, uint64 refundWindowSeconds, uint64 maxExpiryExtensionSeconds);
    event VerifierUpdated(address indexed verifier);
    event ImageIdsUpdated(bytes32 depositImageId, bytes32 withdrawImageId);

    event Minted(bytes32 indexed depositId, address indexed recipient, uint256 amount, uint256 fee, uint256 relayerTip);
    event DepositSkipped(bytes32 indexed depositId);

    event WithdrawRequested(
        bytes32 indexed withdrawalId,
        address indexed requester,
        uint256 amount,
        bytes recipientUA,
        uint64 expiry,
        uint96 feeBps
    );
    event WithdrawFinalized(bytes32 indexed withdrawalId, uint256 netAmount, uint256 fee, uint256 relayerTip);
    event WithdrawFinalizedSkipped(bytes32 indexed withdrawalId);
    event WithdrawRefunded(bytes32 indexed withdrawalId);
    event WithdrawExpiryExtended(bytes32 indexed withdrawalId, uint64 oldExpiry, uint64 newExpiry);

    constructor(
        address initialOwner,
        WJuno wjuno_,
        FeeDistributor feeDistributor_,
        OperatorRegistry operatorRegistry_,
        IRiscZeroVerifierRouter verifier_,
        bytes32 depositImageId_,
        bytes32 withdrawImageId_,
        uint96 feeBps_,
        uint96 relayerTipBps_,
        uint64 refundWindowSeconds_,
        uint64 maxExpiryExtensionSeconds_
    ) Ownable(initialOwner) EIP712("WJUNO Bridge", "1") {
        if (
            address(wjuno_) == address(0) || address(feeDistributor_) == address(0)
                || address(operatorRegistry_) == address(0) || address(verifier_) == address(0)
        ) revert ZeroAddress();

        if (feeBps_ > BPS_DENOMINATOR || relayerTipBps_ > BPS_DENOMINATOR) revert InvalidBps();
        if (refundWindowSeconds_ == 0 || maxExpiryExtensionSeconds_ == 0) revert InvalidExtendBatch();

        wjuno = wjuno_;
        feeDistributor = feeDistributor_;
        operatorRegistry = operatorRegistry_;
        verifier = verifier_;

        depositImageId = depositImageId_;
        withdrawImageId = withdrawImageId_;

        feeBps = feeBps_;
        relayerTipBps = relayerTipBps_;
        refundWindowSeconds = refundWindowSeconds_;
        maxExpiryExtensionSeconds = maxExpiryExtensionSeconds_;

        emit ParamsUpdated(feeBps_, relayerTipBps_, refundWindowSeconds_, maxExpiryExtensionSeconds_);
        emit VerifierUpdated(address(verifier_));
        emit ImageIdsUpdated(depositImageId_, withdrawImageId_);
    }

    // -------- Admin --------
    function setParams(
        uint96 newFeeBps,
        uint96 newRelayerTipBps,
        uint64 newRefundWindowSeconds,
        uint64 newMaxExpiryExtensionSeconds
    ) external onlyOwner {
        if (newFeeBps > BPS_DENOMINATOR || newRelayerTipBps > BPS_DENOMINATOR) revert InvalidBps();
        if (newRefundWindowSeconds == 0 || newMaxExpiryExtensionSeconds == 0) revert InvalidExtendBatch();

        feeBps = newFeeBps;
        relayerTipBps = newRelayerTipBps;
        refundWindowSeconds = newRefundWindowSeconds;
        maxExpiryExtensionSeconds = newMaxExpiryExtensionSeconds;

        emit ParamsUpdated(newFeeBps, newRelayerTipBps, newRefundWindowSeconds, newMaxExpiryExtensionSeconds);
    }

    function setVerifier(IRiscZeroVerifierRouter newVerifier) external onlyOwner {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        verifier = newVerifier;
        emit VerifierUpdated(address(newVerifier));
    }

    function setImageIds(bytes32 newDepositImageId, bytes32 newWithdrawImageId) external onlyOwner {
        depositImageId = newDepositImageId;
        withdrawImageId = newWithdrawImageId;
        emit ImageIdsUpdated(newDepositImageId, newWithdrawImageId);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // -------- EIP-712 digests (for off-chain signing) --------
    function checkpointDigest(Checkpoint calldata checkpoint) public view returns (bytes32) {
        if (checkpoint.baseChainId != block.chainid || checkpoint.bridgeContract != address(this)) revert BadCheckpointDomain();
        bytes32 structHash = keccak256(
            abi.encode(
                CHECKPOINT_TYPEHASH,
                checkpoint.height,
                checkpoint.blockHash,
                checkpoint.finalOrchardRoot,
                checkpoint.baseChainId,
                checkpoint.bridgeContract
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function extendWithdrawDigest(bytes32 withdrawalIdsHash, uint64 newExpiry) public view returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(EXTEND_TYPEHASH, withdrawalIdsHash, newExpiry, block.chainid, address(this)));
        return _hashTypedDataV4(structHash);
    }

    // -------- Core --------
    function mintBatch(Checkpoint calldata checkpoint, bytes[] calldata operatorSigs, bytes calldata seal, bytes calldata journal)
        external
        whenNotPaused
        nonReentrant
    {
        _verifyCheckpointSigs(checkpoint, operatorSigs);
        _verifySeal(seal, depositImageId, journal);

        MintItem[] memory items = abi.decode(journal, (MintItem[]));

        uint96 fbps = feeBps;
        uint96 tipBps = relayerTipBps;

        for (uint256 i = 0; i < items.length; i++) {
            MintItem memory it = items[i];

            if (depositUsed[it.depositId]) {
                emit DepositSkipped(it.depositId);
                continue;
            }

            depositUsed[it.depositId] = true;

            // Skip invalid items to keep batches resilient (but prevent replays by marking used).
            if (it.recipient == address(0) || it.amount == 0) {
                emit DepositSkipped(it.depositId);
                continue;
            }

            (uint256 fee, uint256 tip, uint256 net) = _computeFeeAndNet(it.amount, fbps, tipBps);

            if (net != 0) wjuno.mint(it.recipient, net);

            uint256 feeToDistributor = fee - tip;
            if (feeToDistributor != 0) {
                wjuno.mint(address(feeDistributor), feeToDistributor);
                feeDistributor.depositFees(feeToDistributor);
            }
            if (tip != 0) wjuno.mint(msg.sender, tip);

            emit Minted(it.depositId, it.recipient, it.amount, fee, tip);
        }
    }

    function requestWithdraw(uint256 amount, bytes calldata junoRecipientUA)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 withdrawalId)
    {
        if (amount == 0) revert InvalidExtendBatch();
        if (junoRecipientUA.length == 0 || junoRecipientUA.length > MAX_UA_BYTES) revert InvalidWithdrawalRecipient();

        IERC20(address(wjuno)).safeTransferFrom(msg.sender, address(this), amount);

        uint64 expiry = uint64(block.timestamp + refundWindowSeconds);
        uint96 fbps = feeBps;

        withdrawNonce += 1;
        withdrawalId = keccak256(abi.encode(bytes32("WJUNO_WITHDRAW_V1"), block.chainid, address(this), withdrawNonce, msg.sender, amount, keccak256(junoRecipientUA)));

        Withdrawal storage w = _withdrawals[withdrawalId];
        w.requester = msg.sender;
        w.amount = amount;
        w.expiry = expiry;
        w.feeBps = fbps;
        w.recipientUA = junoRecipientUA;

        emit WithdrawRequested(withdrawalId, msg.sender, amount, junoRecipientUA, expiry, fbps);
    }

    function extendWithdrawExpiryBatch(bytes32[] calldata withdrawalIds, uint64 newExpiry, bytes[] calldata operatorSigs)
        external
        whenNotPaused
        nonReentrant
    {
        uint256 n = withdrawalIds.length;
        if (n == 0 || n > MAX_EXTEND_BATCH) revert InvalidExtendBatch();
        if (newExpiry <= block.timestamp) revert InvalidExtendBatch();

        // Require sorted unique ids (so the signed hash is unambiguous and duplicates are impossible).
        for (uint256 i = 1; i < n; i++) {
            if (withdrawalIds[i] <= withdrawalIds[i - 1]) revert SignaturesNotSortedOrUnique();
        }

        bytes32 idsHash = keccak256(abi.encodePacked(withdrawalIds));
        _verifyOperatorSigs(extendWithdrawDigest(idsHash, newExpiry), operatorSigs);

        for (uint256 i = 0; i < n; i++) {
            Withdrawal storage w = _withdrawals[withdrawalIds[i]];
            if (w.requester == address(0) || w.finalized || w.refunded) continue;
            if (block.timestamp >= w.expiry) continue;

            uint64 oldExpiry = w.expiry;
            if (newExpiry <= oldExpiry) continue;
            if (newExpiry - oldExpiry > maxExpiryExtensionSeconds) revert ExpiryExtensionTooLarge();

            w.expiry = newExpiry;
            emit WithdrawExpiryExtended(withdrawalIds[i], oldExpiry, newExpiry);
        }
    }

    function finalizeWithdrawBatch(
        Checkpoint calldata checkpoint,
        bytes[] calldata operatorSigs,
        bytes calldata seal,
        bytes calldata journal
    ) external whenNotPaused nonReentrant {
        _verifyCheckpointSigs(checkpoint, operatorSigs);
        _verifySeal(seal, withdrawImageId, journal);

        FinalizeItem[] memory items = abi.decode(journal, (FinalizeItem[]));

        uint96 tipBps = relayerTipBps;

        for (uint256 i = 0; i < items.length; i++) {
            FinalizeItem memory it = items[i];
            Withdrawal storage w = _withdrawals[it.withdrawalId];
            if (w.requester == address(0)) revert WithdrawalNotFound();

            if (w.finalized) {
                emit WithdrawFinalizedSkipped(it.withdrawalId);
                continue;
            }
            if (w.refunded) revert WithdrawalRefunded();
            if (block.timestamp >= w.expiry) revert WithdrawalExpired();

            (uint256 fee, uint256 tip, uint256 expectedNet) = _computeFeeAndNet(w.amount, w.feeBps, tipBps);
            if (it.netAmount != expectedNet) revert NetAmountMismatch();

            // Route fees from escrow.
            uint256 feeToDistributor = fee - tip;
            if (tip != 0) IERC20(address(wjuno)).safeTransfer(msg.sender, tip);
            if (feeToDistributor != 0) {
                IERC20(address(wjuno)).safeTransfer(address(feeDistributor), feeToDistributor);
                feeDistributor.depositFees(feeToDistributor);
            }

            // Burn net from escrow (remaining balance after fee routing).
            if (expectedNet != 0) wjuno.burn(address(this), expectedNet);

            w.finalized = true;
            emit WithdrawFinalized(it.withdrawalId, expectedNet, fee, tip);
        }
    }

    function refund(bytes32 withdrawalId) external nonReentrant {
        Withdrawal storage w = _withdrawals[withdrawalId];
        if (w.requester == address(0)) revert WithdrawalNotFound();
        if (w.finalized) revert WithdrawalFinalized();
        if (w.refunded) revert WithdrawalRefunded();
        if (block.timestamp < w.expiry) revert WithdrawNotExpired();

        w.refunded = true;
        IERC20(address(wjuno)).safeTransfer(w.requester, w.amount);
        emit WithdrawRefunded(withdrawalId);
    }

    // -------- Views --------
    function getWithdrawal(bytes32 withdrawalId)
        external
        view
        returns (
            address requester,
            uint256 amount,
            uint64 expiry,
            uint96 feeBpsAtRequest,
            bool finalized,
            bool refunded,
            bytes memory recipientUA
        )
    {
        Withdrawal storage w = _withdrawals[withdrawalId];
        requester = w.requester;
        amount = w.amount;
        expiry = w.expiry;
        feeBpsAtRequest = w.feeBps;
        finalized = w.finalized;
        refunded = w.refunded;
        recipientUA = w.recipientUA;
    }

    // -------- Internals --------
    function _verifyCheckpointSigs(Checkpoint calldata checkpoint, bytes[] calldata operatorSigs) internal view {
        _verifyOperatorSigs(checkpointDigest(checkpoint), operatorSigs);
    }

    function _verifyOperatorSigs(bytes32 digest, bytes[] calldata operatorSigs) internal view {
        uint256 t = operatorRegistry.threshold();
        if (t == 0) revert OperatorThresholdUnset();
        if (operatorSigs.length < t) revert InsufficientSignatures();

        address prev = address(0);
        for (uint256 i = 0; i < operatorSigs.length; i++) {
            address signer = ECDSA.recover(digest, operatorSigs[i]);
            if (signer <= prev) revert SignaturesNotSortedOrUnique();
            if (!operatorRegistry.isOperator(signer)) revert NotOperator();
            prev = signer;
        }
    }

    function _verifySeal(bytes calldata seal, bytes32 imageId, bytes calldata journal) internal view {
        bool ok = verifier.verify(seal, imageId, journal);
        if (!ok) revert InvalidProof();
    }

    function _computeFeeAndNet(uint256 amount, uint96 fbps, uint96 tipBps)
        internal
        pure
        returns (uint256 fee, uint256 tip, uint256 net)
    {
        fee = (amount * fbps) / BPS_DENOMINATOR;
        tip = (fee * tipBps) / BPS_DENOMINATOR;
        net = amount - fee;
    }
}
