// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IFeeDistributorHook {
    function onOperatorUpdated(address operator, address feeRecipient, uint96 weight, bool active) external;
}

/// @notice Operator set for quorum checks + fee distribution configuration.
/// @dev Source of truth for operator membership; also forwards updates to FeeDistributor.
contract OperatorRegistry is Ownable2Step {
    error InvalidThreshold();
    error ZeroAddress();
    error InvalidWeight();

    struct Operator {
        address feeRecipient;
        uint96 weight;
        bool active;
    }

    mapping(address => Operator) private _operators;

    address public feeDistributor;

    uint256 public operatorCount; // active operators
    uint256 public threshold; // signatures required

    event FeeDistributorSet(address indexed feeDistributor);
    event OperatorSet(address indexed operator, address indexed feeRecipient, uint96 weight, bool active);
    event ThresholdSet(uint256 threshold);

    constructor(address initialOwner) Ownable(initialOwner) {}

    function setFeeDistributor(address newFeeDistributor) external onlyOwner {
        if (newFeeDistributor == address(0)) revert ZeroAddress();
        feeDistributor = newFeeDistributor;
        emit FeeDistributorSet(newFeeDistributor);
    }

    function setThreshold(uint256 newThreshold) external onlyOwner {
        if (newThreshold == 0 || newThreshold > operatorCount) revert InvalidThreshold();
        threshold = newThreshold;
        emit ThresholdSet(newThreshold);
    }

    function setOperator(address operator, address feeRecipient, uint96 weight, bool active) external onlyOwner {
        if (operator == address(0) || feeRecipient == address(0)) revert ZeroAddress();
        if (active && weight == 0) revert InvalidWeight();

        Operator storage prev = _operators[operator];
        bool wasActive = prev.active;

        // Update active count.
        if (wasActive && !active) operatorCount -= 1;
        if (!wasActive && active) operatorCount += 1;

        _operators[operator] = Operator({feeRecipient: feeRecipient, weight: weight, active: active});
        emit OperatorSet(operator, feeRecipient, weight, active);

        // Enforce existing threshold (if already set).
        uint256 t = threshold;
        if (t != 0 && t > operatorCount) revert InvalidThreshold();

        // Forward updates to the FeeDistributor.
        address fd = feeDistributor;
        if (fd != address(0)) {
            IFeeDistributorHook(fd).onOperatorUpdated(operator, feeRecipient, weight, active);
        }
    }

    function getOperator(address operator) external view returns (Operator memory) {
        return _operators[operator];
    }

    function isOperator(address operator) external view returns (bool) {
        return _operators[operator].active;
    }
}

