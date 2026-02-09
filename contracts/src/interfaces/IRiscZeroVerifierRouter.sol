// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface for the RISC Zero verifier router used by Boundless proofs.
interface IRiscZeroVerifierRouter {
    /// @dev Returns true iff `seal` verifies for `imageId` and `journal`.
    function verify(bytes calldata seal, bytes32 imageId, bytes calldata journal) external view returns (bool);
}

