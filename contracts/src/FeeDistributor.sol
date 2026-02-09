// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Distributes wJUNO protocol fees to operators using an accumulator model (O(1) per deposit/claim).
/// @dev Operator weights and fee recipients are updated via OperatorRegistry.
contract FeeDistributor is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    error BridgeAlreadySet();
    error NotBridge();
    error NotRegistry();
    error NoOperators();
    error ZeroAddress();

    uint256 internal constant ACC_SCALE = 1e18;

    IERC20 public immutable token;
    address public immutable registry;

    address public bridge;

    uint256 public totalWeight;
    uint256 public accFeePerWeight; // scaled by 1e18

    struct OperatorData {
        address feeRecipient;
        uint96 weight;
        bool active;
        uint256 rewardDebt;
    }

    mapping(address => OperatorData) private _operators;

    event BridgeSet(address indexed bridge);
    event FeesDeposited(uint256 amount, uint256 accFeePerWeight);
    event Claimed(address indexed operator, address indexed recipient, uint256 amount);
    event OperatorUpdated(address indexed operator, address indexed feeRecipient, uint96 weight, bool active);

    constructor(address initialOwner, IERC20 token_, address registry_) Ownable(initialOwner) {
        if (address(token_) == address(0) || registry_ == address(0)) revert ZeroAddress();
        token = token_;
        registry = registry_;
    }

    function setBridge(address newBridge) external onlyOwner {
        if (bridge != address(0)) revert BridgeAlreadySet();
        if (newBridge == address(0)) revert ZeroAddress();
        bridge = newBridge;
        emit BridgeSet(newBridge);
    }

    /// @notice Called by Bridge after fee tokens have been minted/transferred into this contract.
    function depositFees(uint256 amount) external {
        if (msg.sender != bridge) revert NotBridge();
        if (amount == 0) return;

        uint256 tw = totalWeight;
        if (tw == 0) revert NoOperators();

        accFeePerWeight += (amount * ACC_SCALE) / tw;
        emit FeesDeposited(amount, accFeePerWeight);
    }

    /// @notice Returns pending fees for a given operator address.
    function pendingReward(address operator) external view returns (uint256) {
        OperatorData memory op = _operators[operator];
        if (op.weight == 0) return 0;
        uint256 accrued = (uint256(op.weight) * accFeePerWeight) / ACC_SCALE;
        return accrued - op.rewardDebt;
    }

    /// @notice Claims accrued fees for an operator, sending funds to its configured fee recipient.
    /// @dev Callable by anyone; funds always go to the operator's feeRecipient.
    function claim(address operator) external nonReentrant returns (uint256 claimed) {
        OperatorData storage op = _operators[operator];
        uint96 w = op.weight;
        if (w == 0) return 0;

        uint256 accrued = (uint256(w) * accFeePerWeight) / ACC_SCALE;
        claimed = accrued - op.rewardDebt;
        if (claimed == 0) return 0;

        op.rewardDebt = accrued;
        token.safeTransfer(op.feeRecipient, claimed);
        emit Claimed(operator, op.feeRecipient, claimed);
    }

    /// @notice OperatorRegistry hook to update operator weights/recipients.
    /// @dev This function harvests any pending rewards to the *new* fee recipient.
    function onOperatorUpdated(address operator, address feeRecipient, uint96 newWeight, bool active)
        external
        nonReentrant
    {
        if (msg.sender != registry) revert NotRegistry();
        if (operator == address(0) || feeRecipient == address(0)) revert ZeroAddress();

        OperatorData storage op = _operators[operator];

        // Harvest pending rewards before mutating weight/recipient.
        uint96 oldWeight = op.weight;
        if (oldWeight != 0) {
            uint256 accrued = (uint256(oldWeight) * accFeePerWeight) / ACC_SCALE;
            uint256 pending = accrued - op.rewardDebt;
            if (pending != 0) {
                token.safeTransfer(feeRecipient, pending);
                emit Claimed(operator, feeRecipient, pending);
            }
        }

        uint96 effectiveNewWeight = active ? newWeight : 0;

        // Update total weight.
        if (oldWeight != 0 || effectiveNewWeight != 0) {
            totalWeight = totalWeight - oldWeight + effectiveNewWeight;
        }

        op.feeRecipient = feeRecipient;
        op.active = active;
        op.weight = effectiveNewWeight;
        op.rewardDebt = (uint256(effectiveNewWeight) * accFeePerWeight) / ACC_SCALE;

        emit OperatorUpdated(operator, feeRecipient, effectiveNewWeight, active);
    }
}

