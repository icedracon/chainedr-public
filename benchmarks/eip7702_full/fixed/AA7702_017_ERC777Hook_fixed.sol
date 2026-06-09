// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: ERC-777 hooks called for ALL addresses
/// @notice AA7702-017 — no EOA/contract distinction in hook logic
interface IERC777 {
    function send(address to, uint256 amount, bytes calldata data) external;
}

contract SecureERC777Distributor {
    mapping(address => uint256) public balances;
    IERC777 public token;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "Reentrancy");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address _token) { token = IERC777(_token); }

    function distribute(address[] calldata recipients, uint256 amount) external nonReentrant {
        for (uint i = 0; i < recipients.length; i++) {
            token.send(recipients[i], amount, "");
            balances[recipients[i]] += amount;
        }
    }
}
