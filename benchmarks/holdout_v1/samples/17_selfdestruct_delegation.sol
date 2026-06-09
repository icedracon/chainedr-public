// SPDX-License-Identifier: MIT
// SmartAccount delegation target containing a selfdestruct path.
// Under EIP-7702 the SELFDESTRUCT executes in the delegated EOA's
// context — the EOA gets cleared. AA7702-015 should fire.
pragma solidity ^0.8.20;

contract DelegationTargetSelfDestruct {
    address private _admin;

    function shutdown(address payable refundTo) external {
        require(msg.sender == _admin, "not admin");
        selfdestruct(refundTo);
    }
}
