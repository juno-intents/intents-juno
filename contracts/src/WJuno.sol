// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @notice Wrapped Juno asset on Base.
/// @dev Minting/burning is restricted to the Bridge contract.
contract WJuno is ERC20, ERC20Permit, Ownable2Step {
    error BridgeAlreadySet();
    error ZeroAddress();
    error NotBridge();

    address public bridge;

    event BridgeSet(address indexed bridge);

    constructor(address initialOwner)
        ERC20("Wrapped Juno", "wJUNO")
        ERC20Permit("Wrapped Juno")
        Ownable(initialOwner)
    {}

    function decimals() public pure override returns (uint8) {
        // Match Junocash base units (1e8) to avoid scaling/rounding issues.
        return 8;
    }

    function setBridge(address newBridge) external onlyOwner {
        if (bridge != address(0)) revert BridgeAlreadySet();
        if (newBridge == address(0)) revert ZeroAddress();
        bridge = newBridge;
        emit BridgeSet(newBridge);
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != bridge) revert NotBridge();
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        if (msg.sender != bridge) revert NotBridge();
        _burn(from, amount);
    }
}
