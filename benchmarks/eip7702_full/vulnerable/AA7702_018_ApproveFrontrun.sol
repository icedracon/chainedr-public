// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: approve() frontrun amplified by delegation
/// @notice AA7702-018 — call_boundary bypass
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ApproveTransferFrom {
    IERC20 public token;

    constructor(address _token) { token = IERC20(_token); }

    function setAllowance(address spender, uint256 amount) external {
        // approve without increaseAllowance — race condition
        // Post-7702: delegated EOA can atomically front-run the approval change
        token.approve(spender, amount);
    }

    function pullFunds(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
    }
}
