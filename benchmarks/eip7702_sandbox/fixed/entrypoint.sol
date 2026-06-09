// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GasFixed {
    uint constant MAX_BATCH = 10;
    function processAll(address[] calldata targets) external {
        require(targets.length <= MAX_BATCH);
        for (uint i = 0; i < targets.length; ) {
            (bool ok,) = targets[i].call{gas: 50000}(""); require(ok);
            unchecked { i++; }
        }
    }
}