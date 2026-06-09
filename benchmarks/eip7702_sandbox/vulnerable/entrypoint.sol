// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegationGasGrief {
    function processAll(address[] calldata targets) external {
        for (uint i = 0; i < targets.length; ) {
            (bool ok,) = targets[i].call("");
            require(ok);
            unchecked { i++; }
        }
    }
}