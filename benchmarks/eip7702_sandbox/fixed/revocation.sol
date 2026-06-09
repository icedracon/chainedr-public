// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CrossChainFixed {
    function authorize(address target) external {
        require(block.chainid != 0, "must bind chain");
        _setDelegate(msg.sender, target);
    }
    function _setDelegate(address user, address target) internal {}
}