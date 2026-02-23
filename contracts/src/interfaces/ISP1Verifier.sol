// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface for SP1 verifier contracts (e.g. SP1VerifierGateway).
interface ISP1Verifier {
    /// @dev Reverts on verification failure.
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
