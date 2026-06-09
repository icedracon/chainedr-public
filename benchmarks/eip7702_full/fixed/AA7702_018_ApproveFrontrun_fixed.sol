// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: uses increaseAllowance instead of raw approve
/// @notice AA7702-018 — prevents approval front-running
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract SafeAllowanceManager {
    mapping(address => mapping(address => uint256)) public allowances;

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowances[msg.sender][spender] += addedValue;
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 current = allowances[msg.sender][spender];
        require(current >= subtractedValue, "Below zero");
        allowances[msg.sender][spender] = current - subtractedValue;
        return true;
    }
}
