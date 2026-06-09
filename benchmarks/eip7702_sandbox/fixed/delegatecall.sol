// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegationTargetFixed {
    function execute(address target, bytes memory data)
        external returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok);
        return ret;
    }
}