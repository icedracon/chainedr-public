// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: callback reentrancy via delegated EOA
/// @notice AA7702-003 — call_boundary bypass
contract CallbackReentrancy {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // Vulnerable: state update AFTER transfer to EOA
        // Pre-7702: safe because EOA has no receive()
        // Post-7702: delegated EOA can reenter via receive()
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
