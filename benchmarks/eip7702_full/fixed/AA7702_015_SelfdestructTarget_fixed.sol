// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: no selfdestruct — uses withdrawal pattern
/// @notice AA7702-015 — safe delegation target
contract DelegationWithdrawal {
    address public owner;

    constructor() { owner = msg.sender; }

    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call(data);
        require(ok);
    }

    function withdrawETH(address payable recipient, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        require(amount <= address(this).balance, "Insufficient");
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
