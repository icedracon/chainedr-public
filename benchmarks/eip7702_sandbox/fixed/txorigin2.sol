// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EntryPointFixed {
    address public entrypoint;
    constructor(address _ep) { entrypoint = _ep; }
    function setEntrypoint(address _ep) external { entrypoint = _ep; }
    function execute() external {
        entrypoint.call("");
    }
}