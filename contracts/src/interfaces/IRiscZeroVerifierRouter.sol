// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface for the RISC Zero verifier router used by Boundless proofs.
interface IRiscZeroVerifierRouter {
    /// @dev Reverts on failure.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}
