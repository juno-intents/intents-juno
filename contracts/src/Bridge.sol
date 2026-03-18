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
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {WJuno} from "./WJuno.sol";

/// @notice Base-side bridge for minting/burning wJUNO using operator-quorum checkpoints and zk proofs.
contract Bridge is Ownable2Step, Pausable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // -------- Errors --------
    error ZeroAddress();
    error InvalidBps();
    error InvalidWithdrawalRecipient();
    error WithdrawalNotFound();
    error NetAmountMismatch();
    error WithdrawalRecipientMismatch();
    error ZeroImageId();
    error InvalidBatchSize(uint256 size, uint256 maxSize);
    error VerifierStringError(string reason);
    error VerifierPanic(uint256 code);
    error VerifierReverted(bytes reason);
    error BadCheckpointDomain();
    error InsufficientSignatures();
    error SignaturesNotSortedOrUnique();
    error NotOperator();
    error OperatorThresholdUnset();
    error InvalidExtendBatch();
    error ExpiryExtensionTooLarge();
    error BadJournalDomain();
    error BelowMinimumAmount();
    error CheckpointHeightRegression(uint64 receivedHeight, uint64 lastAcceptedHeight);
    error CheckpointConflict(uint64 height, bytes32 blockHash, bytes32 finalOrchardRoot);

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

    // Public journal output of the deposit zkVM. This binds the proof to a
    // specific signed checkpoint domain/root (verified by the contract).
    struct DepositJournal {
        bytes32 finalOrchardRoot;
        uint256 baseChainId;
        address bridgeContract;
        MintItem[] items;
    }

    struct FinalizeItem {
        bytes32 withdrawalId;
        bytes32 recipientUAHash;
        uint256 netAmount;
    }

    // Public journal output of the withdraw zkVM. This binds the proof to a
    // specific signed checkpoint domain/root (verified by the contract).
    struct WithdrawJournal {
        bytes32 finalOrchardRoot;
        uint256 baseChainId;
        address bridgeContract;
        FinalizeItem[] items;
    }

    struct Withdrawal {
        address requester;
        uint256 amount;
        uint64 expiry;
        uint96 feeBps; // snapshot at request time
        bool finalized;
        bytes recipientUA;
    }

    // -------- Constants --------
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_UA_BYTES = 256;
    uint256 public constant MAX_BATCH_SIZE = 200;
    uint256 public constant MAX_EXTEND_BATCH = 200;

    bytes32 private constant CHECKPOINT_TYPEHASH = keccak256(
        "Checkpoint(uint64 height,bytes32 blockHash,bytes32 finalOrchardRoot,uint256 baseChainId,address bridgeContract)"
    );
    bytes32 private constant EXTEND_TYPEHASH = keccak256(
        "ExtendWithdrawExpiry(bytes32 withdrawalIdsHash,uint64 newExpiry,uint256 baseChainId,address bridgeContract)"
    );
    bytes32 private constant MARK_WITHDRAW_PAID_TYPEHASH =
        keccak256("MarkWithdrawPaid(bytes32 withdrawalIdsHash,uint256 baseChainId,address bridgeContract)");

    uint8 private constant WITHDRAW_PAID_SKIP_FINALIZED = 1;
    uint8 private constant WITHDRAW_PAID_SKIP_ALREADY_PAID = 2;
    uint8 private constant WITHDRAW_FINALIZE_SKIP_FINALIZED = 1;
    uint8 private constant WITHDRAW_FINALIZE_SKIP_EXPIRED_UNPAID = 2;

    // -------- State --------
    WJuno public immutable wjuno;
    FeeDistributor public immutable feeDistributor;
    OperatorRegistry public immutable operatorRegistry;
    ISP1Verifier public verifier;

    bytes32 public depositImageId;
    bytes32 public withdrawImageId;

    uint96 public feeBps;
    uint96 public relayerTipBps; // portion of fee (in bps) paid to msg.sender
    uint64 public withdrawalExpiryWindowSeconds;
    uint64 public maxExpiryExtensionSeconds;
    address public pauseGuardian;
    address public minDepositAdmin;
    uint256 public minDepositAmount;
    uint256 public minWithdrawAmount;
    uint64 public lastAcceptedCheckpointHeight;
    bytes32 public lastAcceptedCheckpointBlockHash;
    bytes32 public lastAcceptedCheckpointFinalOrchardRoot;
    bool private checkpointAccepted;

    uint256 public withdrawNonce;

    mapping(bytes32 => bool) public depositUsed;
    mapping(bytes32 => bool) public withdrawalPaid;
    mapping(bytes32 => Withdrawal) private _withdrawals;

    // -------- Events --------
    event ParamsUpdated(
        uint96 feeBps,
        uint96 relayerTipBps,
        uint64 withdrawalExpiryWindowSeconds,
        uint64 maxExpiryExtensionSeconds,
        uint256 minDepositAmount,
        uint256 minWithdrawAmount
    );
    event PauseGuardianUpdated(address indexed pauseGuardian);
    event MinDepositAdminUpdated(address indexed minDepositAdmin);
    event MinDepositAmountUpdated(uint256 minDepositAmount);
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
    event WithdrawFinalizedSkipped(bytes32 indexed withdrawalId, uint8 reason);
    event WithdrawExpiryExtended(bytes32 indexed withdrawalId, uint64 oldExpiry, uint64 newExpiry);
    event WithdrawalPaidRecorded(bytes32 indexed withdrawalId);
    event WithdrawalPaidSkipped(bytes32 indexed withdrawalId, uint8 reason);
    event CheckpointAccepted(uint64 indexed height, bytes32 indexed blockHash, bytes32 indexed finalOrchardRoot);

    constructor(
        address initialOwner,
        WJuno wjuno_,
        FeeDistributor feeDistributor_,
        OperatorRegistry operatorRegistry_,
        ISP1Verifier verifier_,
        bytes32 depositImageId_,
        bytes32 withdrawImageId_,
        uint96 feeBps_,
        uint96 relayerTipBps_,
        uint64 withdrawalExpiryWindowSeconds_,
        uint64 maxExpiryExtensionSeconds_,
        uint256 minDepositAmount_,
        uint256 minWithdrawAmount_
    ) Ownable(initialOwner) EIP712("WJUNO Bridge", "1") {
        if (
            address(wjuno_) == address(0) || address(feeDistributor_) == address(0)
                || address(operatorRegistry_) == address(0) || address(verifier_) == address(0)
        ) revert ZeroAddress();
        if (depositImageId_ == bytes32(0) || withdrawImageId_ == bytes32(0)) revert ZeroImageId();

        if (feeBps_ > BPS_DENOMINATOR || relayerTipBps_ > BPS_DENOMINATOR) revert InvalidBps();
        if (withdrawalExpiryWindowSeconds_ == 0 || maxExpiryExtensionSeconds_ == 0) revert InvalidExtendBatch();

        wjuno = wjuno_;
        feeDistributor = feeDistributor_;
        operatorRegistry = operatorRegistry_;
        verifier = verifier_;

        depositImageId = depositImageId_;
        withdrawImageId = withdrawImageId_;

        feeBps = feeBps_;
        relayerTipBps = relayerTipBps_;
        withdrawalExpiryWindowSeconds = withdrawalExpiryWindowSeconds_;
        maxExpiryExtensionSeconds = maxExpiryExtensionSeconds_;
        minDepositAmount = minDepositAmount_;
        minWithdrawAmount = minWithdrawAmount_;

        emit ParamsUpdated(
            feeBps_,
            relayerTipBps_,
            withdrawalExpiryWindowSeconds_,
            maxExpiryExtensionSeconds_,
            minDepositAmount_,
            minWithdrawAmount_
        );
        emit VerifierUpdated(address(verifier_));
        emit ImageIdsUpdated(depositImageId_, withdrawImageId_);
    }

    // -------- Admin --------
    modifier onlyOwnerOrMinDepositAdmin() {
        if (msg.sender != owner() && msg.sender != minDepositAdmin) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
        _;
    }

    modifier onlyOwnerOrPauseGuardian() {
        if (msg.sender != owner() && msg.sender != pauseGuardian) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
        _;
    }

    function setParams(
        uint96 newFeeBps,
        uint96 newRelayerTipBps,
        uint64 newWithdrawalExpiryWindowSeconds,
        uint64 newMaxExpiryExtensionSeconds,
        uint256 newMinDepositAmount,
        uint256 newMinWithdrawAmount
    ) external onlyOwner {
        if (newFeeBps > BPS_DENOMINATOR || newRelayerTipBps > BPS_DENOMINATOR) {
            revert InvalidBps();
        }
        if (newWithdrawalExpiryWindowSeconds == 0 || newMaxExpiryExtensionSeconds == 0) revert InvalidExtendBatch();

        feeBps = newFeeBps;
        relayerTipBps = newRelayerTipBps;
        withdrawalExpiryWindowSeconds = newWithdrawalExpiryWindowSeconds;
        maxExpiryExtensionSeconds = newMaxExpiryExtensionSeconds;
        minDepositAmount = newMinDepositAmount;
        minWithdrawAmount = newMinWithdrawAmount;

        emit ParamsUpdated(
            newFeeBps,
            newRelayerTipBps,
            newWithdrawalExpiryWindowSeconds,
            newMaxExpiryExtensionSeconds,
            newMinDepositAmount,
            newMinWithdrawAmount
        );
    }

    function setMinDepositAdmin(address newMinDepositAdmin) external onlyOwner {
        minDepositAdmin = newMinDepositAdmin;
        emit MinDepositAdminUpdated(newMinDepositAdmin);
    }

    function setPauseGuardian(address newPauseGuardian) external onlyOwner {
        pauseGuardian = newPauseGuardian;
        emit PauseGuardianUpdated(newPauseGuardian);
    }

    function setMinDepositAmount(uint256 newMinDepositAmount) external onlyOwnerOrMinDepositAdmin {
        minDepositAmount = newMinDepositAmount;
        emit MinDepositAmountUpdated(newMinDepositAmount);
    }

    function setVerifier(ISP1Verifier newVerifier) external onlyOwner {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        verifier = newVerifier;
        emit VerifierUpdated(address(newVerifier));
    }

    function setImageIds(bytes32 newDepositImageId, bytes32 newWithdrawImageId) external onlyOwner {
        if (newDepositImageId == bytes32(0) || newWithdrawImageId == bytes32(0)) revert ZeroImageId();
        depositImageId = newDepositImageId;
        withdrawImageId = newWithdrawImageId;
        emit ImageIdsUpdated(newDepositImageId, newWithdrawImageId);
    }

    function pause() external onlyOwnerOrPauseGuardian {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // -------- EIP-712 digests (for off-chain signing) --------
    function checkpointDigest(Checkpoint calldata checkpoint) public view returns (bytes32) {
        if (checkpoint.baseChainId != block.chainid || checkpoint.bridgeContract != address(this)) {
            revert BadCheckpointDomain();
        }
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

    function markWithdrawPaidDigest(bytes32 withdrawalIdsHash) public view returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(MARK_WITHDRAW_PAID_TYPEHASH, withdrawalIdsHash, block.chainid, address(this)));
        return _hashTypedDataV4(structHash);
    }

    // -------- Core --------
    function mintBatch(
        Checkpoint calldata checkpoint,
        bytes[] calldata operatorSigs,
        bytes calldata seal,
        bytes calldata journal
    ) external whenNotPaused nonReentrant {
        _verifyCheckpointSigs(checkpoint, operatorSigs);
        _validateCheckpointProgress(checkpoint);

        DepositJournal memory dj = abi.decode(journal, (DepositJournal));
        MintItem[] memory items = dj.items;
        uint256 itemsLength = items.length;
        if (itemsLength > MAX_BATCH_SIZE) revert InvalidBatchSize(itemsLength, MAX_BATCH_SIZE);

        _verifySeal(seal, depositImageId, journal);
        if (
            dj.finalOrchardRoot != checkpoint.finalOrchardRoot || dj.baseChainId != checkpoint.baseChainId
                || dj.bridgeContract != checkpoint.bridgeContract
        ) revert BadJournalDomain();

        uint96 fbps = feeBps;
        uint96 tipBps = relayerTipBps;

        for (uint256 i = 0; i < items.length; i++) {
            MintItem memory it = items[i];

            if (depositUsed[it.depositId]) {
                emit DepositSkipped(it.depositId);
                continue;
            }

            // Skip invalid items and leave them replayable so governance can
            // later lower the threshold or operators can correct bad inputs.
            if (it.recipient == address(0) || it.amount == 0 || it.amount < minDepositAmount) {
                emit DepositSkipped(it.depositId);
                continue;
            }

            depositUsed[it.depositId] = true;

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
        _recordCheckpoint(checkpoint);
    }

    function requestWithdraw(uint256 amount, bytes calldata junoRecipientUA)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 withdrawalId)
    {
        if (amount == 0) revert BelowMinimumAmount();
        if (amount < minWithdrawAmount) revert BelowMinimumAmount();
        if (junoRecipientUA.length == 0 || junoRecipientUA.length > MAX_UA_BYTES) revert InvalidWithdrawalRecipient();

        IERC20(address(wjuno)).safeTransferFrom(msg.sender, address(this), amount);

        uint64 expiry = uint64(block.timestamp + withdrawalExpiryWindowSeconds);
        uint96 fbps = feeBps;

        withdrawNonce += 1;
        withdrawalId = keccak256(
            abi.encode(
                bytes32("WJUNO_WITHDRAW_V1"),
                block.chainid,
                address(this),
                withdrawNonce,
                msg.sender,
                amount,
                keccak256(junoRecipientUA)
            )
        );

        Withdrawal storage w = _withdrawals[withdrawalId];
        w.requester = msg.sender;
        w.amount = amount;
        w.expiry = expiry;
        w.feeBps = fbps;
        w.recipientUA = junoRecipientUA;

        emit WithdrawRequested(withdrawalId, msg.sender, amount, junoRecipientUA, expiry, fbps);
    }

    function extendWithdrawExpiryBatch(
        bytes32[] calldata withdrawalIds,
        uint64 newExpiry,
        bytes[] calldata operatorSigs
    ) external whenNotPaused nonReentrant {
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
            if (w.requester == address(0) || w.finalized) continue;
            if (block.timestamp >= w.expiry) continue;

            uint64 oldExpiry = w.expiry;
            if (newExpiry <= oldExpiry) continue;
            if (newExpiry - oldExpiry > maxExpiryExtensionSeconds) revert ExpiryExtensionTooLarge();

            w.expiry = newExpiry;
            emit WithdrawExpiryExtended(withdrawalIds[i], oldExpiry, newExpiry);
        }
    }

    function markWithdrawPaidBatch(bytes32[] calldata withdrawalIds, bytes[] calldata operatorSigs) external {
        uint256 n = withdrawalIds.length;
        if (n == 0 || n > MAX_EXTEND_BATCH) revert InvalidExtendBatch();

        for (uint256 i = 1; i < n; i++) {
            if (withdrawalIds[i] <= withdrawalIds[i - 1]) revert SignaturesNotSortedOrUnique();
        }

        bytes32 idsHash = keccak256(abi.encodePacked(withdrawalIds));
        _verifyOperatorSigs(markWithdrawPaidDigest(idsHash), operatorSigs);

        for (uint256 i = 0; i < n; i++) {
            bytes32 withdrawalId = withdrawalIds[i];
            Withdrawal storage w = _withdrawals[withdrawalId];
            if (w.requester == address(0)) revert WithdrawalNotFound();
            if (w.finalized) {
                emit WithdrawalPaidSkipped(withdrawalId, WITHDRAW_PAID_SKIP_FINALIZED);
                continue;
            }
            if (withdrawalPaid[withdrawalId]) {
                emit WithdrawalPaidSkipped(withdrawalId, WITHDRAW_PAID_SKIP_ALREADY_PAID);
                continue;
            }
            withdrawalPaid[withdrawalId] = true;
            emit WithdrawalPaidRecorded(withdrawalId);
        }
    }

    function finalizeWithdrawBatch(
        Checkpoint calldata checkpoint,
        bytes[] calldata operatorSigs,
        bytes calldata seal,
        bytes calldata journal
    ) external whenNotPaused nonReentrant {
        _verifyCheckpointSigs(checkpoint, operatorSigs);
        _validateCheckpointProgress(checkpoint);

        WithdrawJournal memory wj = abi.decode(journal, (WithdrawJournal));
        FinalizeItem[] memory items = wj.items;
        uint256 itemsLength = items.length;
        if (itemsLength > MAX_BATCH_SIZE) revert InvalidBatchSize(itemsLength, MAX_BATCH_SIZE);

        _verifySeal(seal, withdrawImageId, journal);
        if (
            wj.finalOrchardRoot != checkpoint.finalOrchardRoot || wj.baseChainId != checkpoint.baseChainId
                || wj.bridgeContract != checkpoint.bridgeContract
        ) revert BadJournalDomain();

        uint96 tipBps = relayerTipBps;

        for (uint256 i = 0; i < items.length; i++) {
            FinalizeItem memory it = items[i];
            Withdrawal storage w = _withdrawals[it.withdrawalId];
            if (w.requester == address(0)) revert WithdrawalNotFound();

            if (w.finalized) {
                emit WithdrawFinalizedSkipped(it.withdrawalId, WITHDRAW_FINALIZE_SKIP_FINALIZED);
                continue;
            }
            if (block.timestamp >= w.expiry && !withdrawalPaid[it.withdrawalId]) {
                emit WithdrawFinalizedSkipped(it.withdrawalId, WITHDRAW_FINALIZE_SKIP_EXPIRED_UNPAID);
                continue;
            }

            if (it.recipientUAHash != keccak256(w.recipientUA)) revert WithdrawalRecipientMismatch();

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
        _recordCheckpoint(checkpoint);
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
            bytes memory recipientUA
        )
    {
        Withdrawal storage w = _withdrawals[withdrawalId];
        requester = w.requester;
        amount = w.amount;
        expiry = w.expiry;
        feeBpsAtRequest = w.feeBps;
        finalized = w.finalized;
        recipientUA = w.recipientUA;
    }

    // -------- Internals --------
    function _verifyCheckpointSigs(Checkpoint calldata checkpoint, bytes[] calldata operatorSigs) internal view {
        _verifyOperatorSigs(checkpointDigest(checkpoint), operatorSigs);
    }

    function _validateCheckpointProgress(Checkpoint calldata checkpoint) internal view {
        if (!checkpointAccepted) return;
        if (checkpoint.height < lastAcceptedCheckpointHeight) {
            revert CheckpointHeightRegression(checkpoint.height, lastAcceptedCheckpointHeight);
        }
        if (
            checkpoint.height == lastAcceptedCheckpointHeight
                && (
                    checkpoint.blockHash != lastAcceptedCheckpointBlockHash
                        || checkpoint.finalOrchardRoot != lastAcceptedCheckpointFinalOrchardRoot
                )
        ) {
            revert CheckpointConflict(checkpoint.height, checkpoint.blockHash, checkpoint.finalOrchardRoot);
        }
    }

    function _recordCheckpoint(Checkpoint calldata checkpoint) internal {
        if (!checkpointAccepted || checkpoint.height > lastAcceptedCheckpointHeight) {
            checkpointAccepted = true;
            lastAcceptedCheckpointHeight = checkpoint.height;
            lastAcceptedCheckpointBlockHash = checkpoint.blockHash;
            lastAcceptedCheckpointFinalOrchardRoot = checkpoint.finalOrchardRoot;
            emit CheckpointAccepted(checkpoint.height, checkpoint.blockHash, checkpoint.finalOrchardRoot);
        }
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
        if (imageId == bytes32(0)) revert ZeroImageId();
        try verifier.verifyProof(imageId, journal, seal) {}
        catch Error(string memory reason) {
            revert VerifierStringError(reason);
        }
        catch Panic(uint256 code) {
            revert VerifierPanic(code);
        }
        catch (bytes memory reason) {
            revert VerifierReverted(reason);
        }
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
