// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ProxyFixed {
    function execute(address target, bytes memory data) external {
        (bool ok,) = target.call(data); require(ok);
    }
}