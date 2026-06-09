// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegationTarget {
    function executeDelegation(address target, bytes memory data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok);
        return ret;
    }
}