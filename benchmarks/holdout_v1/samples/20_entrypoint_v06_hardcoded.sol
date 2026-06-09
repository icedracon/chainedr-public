// SPDX-License-Identifier: MIT
// EntryPoint v0.6 hardcoded — breaks for AA users on v0.7+. AA7702-021
// should fire.
pragma solidity ^0.8.20;

interface IEntryPoint {
    function depositTo(address account) external payable;
}

contract LegacyAccount {
    IEntryPoint public constant ENTRY_POINT =
        IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789); // v0.6

    function deposit() external payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }
}
