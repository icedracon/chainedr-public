// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TxOriginGuard {
    function humanOnly() external {
        require(tx.origin == msg.sender, "not eoa");
    }
}