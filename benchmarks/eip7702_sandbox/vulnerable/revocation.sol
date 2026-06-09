// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CrossChainReplay {
    function authorize(address target, uint chainId) external {
        if (chainId == 0) {
            _setDelegate(msg.sender, target);
        }
    }
    function _setDelegate(address user, address target) internal {}
}